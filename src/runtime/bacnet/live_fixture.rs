//! E03 test-only read transport. Like test_loopback, captures BOTH UDP boundaries,
//! not host-wide pcap. Reuses its packet shape and release guard without changing COV.
//! Extra one-byte receive margin exercises the 1024-byte refusal; no large datagrams.
use super::{
    client::ReadPort,
    fake::Delivery,
    test_loopback::{assert_fixture_port, Packet, PORT_RELEASE_GUARD},
    *,
};
use bacnet_transport::port::{ReceivedNpdu, TransportPort};
use bacnet_types::error::Error as WireError;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot, Notify},
    task::JoinHandle,
};

const CAPTURE_ENTRIES: usize = 128;
const FRAME_BYTES: usize = 4 + MAX_NPDU_BYTES + 1;
const QUEUE: usize = 4;
type WireResult<T> = std::result::Result<T, WireError>;

fn mac(address: SocketAddr) -> [u8; 6] {
    let SocketAddr::V4(address) = address else { panic!("IPv4 fixture") };
    let [a, b, c, d] = address.ip().octets();
    let [hi, lo] = address.port().to_be_bytes();
    [a, b, c, d, hi, lo]
}
fn frame(npdu: &[u8]) -> Vec<u8> {
    assert!(npdu.len() <= MAX_NPDU_BYTES + 1);
    let mut bytes = vec![0x81, 0x0a]; // BVLC Original-Unicast-NPDU, never MBAP.
    bytes.extend_from_slice(&((npdu.len() + 4) as u16).to_be_bytes());
    bytes.extend_from_slice(npdu);
    bytes
}
fn npdu(bytes: &[u8]) -> &[u8] {
    assert!((6..=FRAME_BYTES).contains(&bytes.len()));
    assert_eq!(&bytes[..2], &[0x81, 0x0a]);
    assert_eq!(usize::from(u16::from_be_bytes([bytes[2], bytes[3]])), bytes.len());
    assert_eq!(bytes[4], 1);
    assert!(matches!(bytes[5], 0 | 4), "direct application NPDU only");
    &bytes[4..]
}
#[derive(Default)]
struct Worker {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl Worker {
    async fn join(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.as_mut() {
            task.await.unwrap();
        }
        self.task = None;
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
        // Unwind protection only, NOT successful join/release evidence.
    }
}
struct Shared {
    socket: Mutex<Option<Arc<UdpSocket>>>,
    client: SocketAddr,
    peer: SocketAddr,
    log: Mutex<Vec<Packet>>,
    active: AtomicBool,
    starts: AtomicUsize,
    eofs: AtomicUsize,
    stops: AtomicUsize,
    oversized: AtomicUsize,
    discovery_replies: usize,
}
#[derive(Clone)]
pub(crate) struct Fixture(Arc<Shared>);
impl Fixture {
    fn record(&self, sent: bool, from: SocketAddr, to: SocketAddr, bytes: &[u8]) {
        assert!(bytes.len() <= FRAME_BYTES);
        let mut log = self.0.log.lock().unwrap();
        assert!(log.len() < CAPTURE_ENTRIES, "never truncate capture");
        log.push(Packet { sent, from, to, bytes: bytes.to_vec() });
    }
    pub(crate) fn packets(&self) -> Vec<Packet> {
        self.0.log.lock().unwrap().clone()
    }
    pub(crate) fn requests(&self) -> Vec<Vec<u8>> {
        self.packets()
            .into_iter()
            .filter(|p| !p.sent && p.to == self.0.peer)
            .map(|p| npdu(&p.bytes).to_vec())
            .collect()
    }
    pub(crate) fn endpoints(&self) -> (SocketAddr, SocketAddr) {
        (self.0.client, self.0.peer)
    }
    pub(crate) fn oversized(&self) -> usize {
        self.0.oversized.load(Ordering::SeqCst)
    }
    pub(crate) fn target(&self, realm: &str) -> DirectTarget {
        DirectTarget::parse(realm, &format!("bacnet-ip://{}", self.0.peer)).unwrap()
    }
    pub(super) fn port(&self, plan: &BindingPlan, cancel: Cancellation, deadline: Instant) -> Result<Port> {
        if plan.target.mac() != &mac(self.0.peer) {
            return Err(Error::DeniedDestination);
        }
        if self.0.active.swap(true, Ordering::SeqCst) {
            return Err(Error::Budget);
        }
        Ok(Port {
            fixture: self.clone(),
            socket: self.0.socket.lock().unwrap().as_ref().unwrap().clone(),
            target: plan.target.clone(),
            service: plan.request.service(),
            current: (cancel, deadline),
            delivery: Arc::new(Mutex::new(Delivery::default())),
            received: Arc::new(Notify::new()),
            reader: Worker::default(),
            filter: Worker::default(),
            local: mac(self.0.client),
        })
    }
    pub(crate) async fn refuse_calls(&self, plan: &BindingPlan, calls: &[Vec<u8>]) {
        let port =
            self.port(plan, Cancellation::default(), Instant::now() + Duration::from_secs(30)).unwrap();
        for bytes in calls {
            assert!(port.send_unicast(bytes, plan.target.mac()).await.is_err());
        }
        assert!(port.send_broadcast(&[1, 0, 16, 8]).await.is_err());
        let mut wrong = *plan.target.mac();
        wrong[0] = 192; // Refused BEFORE send; never contact this address.
        assert!(port.send_unicast(&[1, 4, 0, 3, 0, 12], &wrong).await.is_err());
        assert!(self.packets().is_empty());
    }
}
async fn send(socket: &UdpSocket, destination: SocketAddr, bytes: &[u8], fixture: &Fixture) {
    assert_eq!(destination.ip(), Ipv4Addr::LOCALHOST);
    let bytes = frame(bytes);
    assert_eq!(socket.send_to(&bytes, destination).await.unwrap(), bytes.len());
    fixture.record(true, socket.local_addr().unwrap(), destination, &bytes);
}

pub(crate) struct Harness {
    pub(crate) fixture: Fixture,
    worker: Worker,
    _ports: tokio::sync::MutexGuard<'static, ()>,
}
impl Harness {
    pub(crate) async fn new(
        mut respond: impl FnMut(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
        discovery_replies: usize,
    ) -> Self {
        assert!(discovery_replies <= QUEUE);
        let ports = PORT_RELEASE_GUARD.lock().await;
        let client = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let fixture = Fixture(Arc::new(Shared {
            client: client.local_addr().unwrap(),
            peer: peer.local_addr().unwrap(),
            socket: Mutex::new(Some(client)),
            log: Mutex::new(Vec::new()),
            active: AtomicBool::new(false),
            starts: AtomicUsize::new(0),
            eofs: AtomicUsize::new(0),
            stops: AtomicUsize::new(0),
            oversized: AtomicUsize::new(0),
            discovery_replies,
        }));
        let shared = fixture.clone();
        let (stop, mut cancel) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut buf = [0; FRAME_BYTES + 1];
            loop {
                tokio::select! {
                    _ = &mut cancel => break,
                    result = peer.recv_from(&mut buf) => {
                        let (n, from) = result.unwrap();
                        assert_eq!(from, shared.0.client);
                        shared.record(false, from, shared.0.peer, &buf[..n]);
                        let replies = respond(npdu(&buf[..n]));
                        assert!(replies.len() <= QUEUE);
                        for reply in replies { send(&peer, from, &reply, &shared).await; }
                    }
                }
            }
        });
        Self { fixture, worker: Worker { stop: Some(stop), task: Some(task) }, _ports: ports }
    }
    pub(crate) async fn finish(mut self, name: &str, expected: &[Vec<u8>]) {
        self.worker.join().await;
        let f = &self.fixture;
        assert!(!f.0.active.load(Ordering::SeqCst));
        let starts = f.0.starts.load(Ordering::SeqCst);
        assert_eq!(starts, f.0.stops.load(Ordering::SeqCst));
        assert_eq!(starts, f.0.eofs.load(Ordering::SeqCst), "actual receive-channel EOF observed");
        assert_eq!(f.requests(), expected, "exact requests including zero resends");
        let packets = f.packets();
        let sent: Vec<_> = packets.iter().filter(|p| p.sent).collect();
        let received: Vec<_> = packets.iter().filter(|p| !p.sent).collect();
        assert_eq!(sent.len(), received.len());
        let (client, peer) = f.endpoints();
        assert_ne!(client, peer);
        for endpoint in [client, peer] {
            assert_eq!(endpoint.ip(), Ipv4Addr::LOCALHOST);
            assert_fixture_port(endpoint.port());
        }
        for p in &packets {
            assert!((p.from == f.0.client && p.to == f.0.peer) || (p.from == f.0.peer && p.to == f.0.client));
            let bytes = npdu(&p.bytes);
            if p.from == f.0.client {
                assert!(
                    bytes.starts_with(&[1, 0, 16, 8])
                        || (bytes.starts_with(&[1, 4, 0, 3]) && matches!(bytes.get(5), Some(12 | 14)))
                );
            }
            assert_eq!(
                sent.iter().filter(|q| q.from == p.from && q.to == p.to && q.bytes == p.bytes).count(),
                received.iter().filter(|q| q.from == p.from && q.to == p.to && q.bytes == p.bytes).count()
            );
        }
        let socket = f.0.socket.lock().unwrap().take().unwrap();
        assert_eq!(Arc::strong_count(&socket), 1, "all client owners released socket");
        drop(socket);
        let a = rebind(f.0.client).await;
        let b = rebind(f.0.peer).await;
        eprintln!("READ-CAPTURE {name} client={} peer={} requests={} sent={} received={} starts={starts} BVLC/NPDU/services/exact/loopback=PASS stop/join/channel-EOF/rebind=PASS{}",
            f.0.client, f.0.peer, expected.len(), sent.len(), received.len(),
            if packets.is_empty() { " capture-empty=PASS" } else { "" });
        drop((a, b));
    }
}
async fn rebind(address: SocketAddr) -> std::net::UdpSocket {
    let deadline = Instant::now() + Duration::from_secs(5); // Fixture wall margin, not an OS guarantee.
    loop {
        match std::net::UdpSocket::bind(address) {
            Ok(socket) => return socket,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(1)).await
            }
            Err(e) => panic!("release not observed for {address}: {e}"),
        }
    }
}

pub(super) struct Port {
    fixture: Fixture,
    socket: Arc<UdpSocket>,
    target: DirectTarget,
    service: Service,
    current: (Cancellation, Instant),
    delivery: Arc<Mutex<Delivery>>,
    received: Arc<Notify>,
    reader: Worker,
    filter: Worker,
    local: [u8; 6],
}
impl ReadPort for Port {
    fn delivery(&self) -> Arc<Mutex<Delivery>> {
        self.delivery.clone()
    }
}
impl Drop for Port {
    fn drop(&mut self) {
        self.fixture.0.active.store(false, Ordering::SeqCst);
    }
}
impl TransportPort for Port {
    async fn start(&mut self) -> WireResult<mpsc::Receiver<ReceivedNpdu>> {
        let (tx, mut raw) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (out, rx) = mpsc::channel(QUEUE);
        let (stop, mut cancel) = oneshot::channel();
        let socket = self.socket.clone();
        let fixture = self.fixture.clone();
        self.reader = Worker {
            stop: Some(stop),
            task: Some(tokio::spawn(async move {
                let mut buf = [0; FRAME_BYTES + 1];
                loop {
                    tokio::select! {
                        _ = &mut cancel => break,
                        result = socket.recv_from(&mut buf) => {
                            let (n, from) = result.unwrap();
                            assert_eq!(from, fixture.0.peer);
                            fixture.record(false, from, fixture.0.client, &buf[..n]);
                            let bytes = npdu(&buf[..n]).to_vec();
                            tokio::select! {
                                _ = &mut cancel => break,
                                result = tx.send(bytes) => result.unwrap(),
                            }
                        }
                    }
                }
            })),
        };
        let delivery = self.delivery.clone();
        let received = self.received.clone();
        let target = self.target.clone();
        let service = self.service;
        let fixture = self.fixture.clone();
        self.filter.task = Some(tokio::spawn(async move {
            while let Some(bytes) = raw.recv().await {
                let result = if bytes.len() > MAX_NPDU_BYTES {
                    fixture.0.oversized.fetch_add(1, Ordering::SeqCst);
                    Err(Error::Oversized)
                } else if service == Service::DirectedWhoIs {
                    if !bytes.starts_with(&[1, 0, 16, 0]) {
                        Err(Error::InvalidReply)
                    } else {
                        Advertisement::decode(target.clone(), &bytes[4..]).and_then(|ad| {
                            let mut d = delivery.lock().unwrap();
                            if d.advertisements.len() == QUEUE {
                                return Err(Error::Budget);
                            }
                            d.advertisements.push(ad);
                            Ok(())
                        })
                    }
                } else if bytes.starts_with(&[1, 0])
                    && matches!(bytes.get(2), Some(0x30 | 0x50 | 0x60 | 0x70 | 0x71))
                {
                    out.try_send(ReceivedNpdu {
                        npdu: bytes.into(),
                        source_mac: target.mac().as_slice().into(),
                        link_layer_group: false,
                        data_attributes: vec![],
                        reply_tx: None,
                    })
                    .map_err(|_| Error::Budget)
                } else {
                    Err(Error::InvalidReply)
                };
                if let Err(error) = result {
                    delivery.lock().unwrap().error = Some(error);
                }
                received.notify_one();
            }
            fixture.0.eofs.fetch_add(1, Ordering::SeqCst);
        }));
        self.fixture.0.starts.fetch_add(1, Ordering::SeqCst);
        Ok(rx)
    }
    async fn stop(&mut self) -> WireResult<()> {
        self.reader.join().await; // Drops the ONLY raw sender.
        self.filter.join().await; // Drains until actual channel EOF, not UDP "EOF".
        self.fixture.0.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn send_unicast(&self, bytes: &[u8], destination: &[u8]) -> WireResult<()> {
        let service_ok = match self.service {
            Service::ReadProperty => bytes.starts_with(&[1, 4, 0, 3]) && bytes.get(5) == Some(&12),
            Service::ReadPropertyMultiple => bytes.starts_with(&[1, 4, 0, 3]) && bytes.get(5) == Some(&14),
            Service::DirectedWhoIs => bytes.starts_with(&[1, 0, 16, 8]),
        };
        if !service_ok
            || destination != self.target.mac()
            || bytes.len() > MAX_NPDU_BYTES
            || self.current.0.check(self.current.1).is_err()
        {
            return Err(WireError::Encoding("read fixture handoff refused".into()));
        }
        send(&self.socket, self.fixture.0.peer, bytes, &self.fixture).await;
        if self.service == Service::DirectedWhoIs {
            // A finite scripted-peer handshake, NOT a production discovery window.
            // No silence is a successful discovery: the outer absolute deadline
            // fails the run if the independently scripted replies never arrive.
            loop {
                let notified = self.received.notified();
                {
                    let d = self.delivery.lock().unwrap();
                    if d.error.is_some() || d.advertisements.len() == self.fixture.0.discovery_replies {
                        break;
                    }
                }
                notified.await;
            }
        }
        Ok(())
    }
    async fn send_broadcast(&self, _: &[u8]) -> WireResult<()> {
        Err(WireError::Encoding("broadcast forbidden".into()))
    }
    fn local_mac(&self) -> &[u8] {
        &self.local
    }
    fn max_apdu_length(&self) -> u16 {
        480
    }
}

impl crate::runtime::Runtime {
    pub(crate) fn configure_live_reads(
        &mut self,
        profile: Profile,
        fixture: Fixture,
    ) -> crate::runtime::Result<()> {
        self.configure_fake_bacnet(profile, fake::ScriptedPeer::default())?;
        let crate::runtime::plug::Adapter::FakeBacnet(adapter) = &mut self.adapter else { unreachable!() };
        adapter.live = Some(fixture);
        Ok(())
    }
    /// Test-only replay of already live-decoded/synthetic advertisements into the
    /// same quarantine owner. Cannot mutate profile, selection or admitted plans.
    pub(crate) fn retain_live_fixture(&self, raw: &RawEnvelope) -> crate::runtime::Result<()> {
        self.adapter.retain_candidates(raw)
    }
}
pub(crate) fn envelope_bound(raw: &RawEnvelope) -> Result<()> {
    super::check_envelope(raw)
}
