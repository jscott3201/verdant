//! Test-only reusable capture log and UDP/BVLC harness, deliberately COV-agnostic.
//! All binds use 127.0.0.1:0. Independent peer responses belong to the caller.
//! PacketLog captures every send/receive at BOTH socket boundaries; not a pcap
//! or evidence about uninstrumented traffic, physical interfaces, or real peers.
use bacnet_transport::port::{ReceivedNpdu, TransportPort};
use bacnet_types::error::Error;
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

// Fixture bounds only: 512 capture entries, 1024 NPDU bytes, 64 transport slots,
// 64 queued peer commands. Not host/RSS, facility throughput or link-loss limits.
const PACKETS: usize = 512;
const BYTES: usize = 1024;
const QUEUE: usize = 64;
// Guard the complete allocate -> stop/join -> rebind interval. Otherwise a
// concurrent fixture may legitimately acquire a just-released ephemeral port
// before its previous owner verifies release. Test isolation, not admission.
pub(crate) static PORT_RELEASE_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub sent: bool,
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Default)]
pub struct PacketLog(Arc<Mutex<Vec<Packet>>>);
impl PacketLog {
    pub(crate) fn record(&self, sent: bool, from: SocketAddr, to: SocketAddr, bytes: &[u8]) {
        let mut packets = self.0.lock().unwrap();
        assert!(packets.len() < PACKETS, "fixture capture full; never silently truncate");
        assert!(bytes.len() <= BYTES + 4);
        packets.push(Packet { sent, from, to, bytes: bytes.to_vec() });
    }
    pub fn packets(&self) -> Vec<Packet> {
        self.0.lock().unwrap().clone()
    }
    pub fn assert_loopback_only(&self) {
        for p in self.packets() {
            assert_eq!(p.from.ip(), Ipv4Addr::LOCALHOST);
            assert_eq!(p.to.ip(), Ipv4Addr::LOCALHOST);
            assert_ne!(p.from.port(), 0);
            assert_ne!(p.to.port(), 0);
        }
    }
    pub fn assert_directed_only(&self, a: SocketAddr, b: SocketAddr) {
        for p in self.packets() {
            assert!((p.from == a && p.to == b) || (p.from == b && p.to == a), "{p:?}");
            assert!(p.bytes.len() >= 6);
            assert_eq!(p.bytes[4], 1); // NPDU version
            assert_eq!(p.bytes[5] & 0xa8, 0, "no destination/source route or network message");
        }
    }
    pub fn assert_no_broadcast_bbmd_foreign(&self) {
        for p in self.packets() {
            assert_eq!(&p.bytes[..2], &[0x81, 0x0a], "only Original-Unicast-NPDU");
            assert_eq!(u16::from_be_bytes([p.bytes[2], p.bytes[3]]) as usize, p.bytes.len());
        }
    }
    pub fn assert_complete(&self) {
        let packets = self.packets();
        assert!(!packets.is_empty());
        let sent: Vec<_> = packets.iter().filter(|p| p.sent).collect();
        let received: Vec<_> = packets.iter().filter(|p| !p.sent).collect();
        assert_eq!(sent.len(), received.len(), "every captured send must be received");
        for p in sent {
            assert_eq!(
                packets
                    .iter()
                    .filter(|q| q.sent && q.from == p.from && q.to == p.to && q.bytes == p.bytes)
                    .count(),
                received.iter().filter(|q| q.from == p.from && q.to == p.to && q.bytes == p.bytes).count()
            );
        }
    }
    /// TCP is a byte stream: compare complete directional streams, not syscall
    /// or IP-packet counts. The caller captures both transport/socket boundaries.
    /// This is an instrumented fixture audit, NOT host-wide/off-interface pcap.
    pub(crate) fn assert_tcp_complete(&self, client: SocketAddr, peer: SocketAddr) {
        self.assert_loopback_only();
        let packets = self.packets();
        assert!(!packets.is_empty());
        for p in &packets {
            assert!((p.from == client && p.to == peer) || (p.from == peer && p.to == client));
            assert!((49152..=65535).contains(&p.from.port()));
            assert!((49152..=65535).contains(&p.to.port()));
            assert!(![502, 802].contains(&p.from.port()) && ![502, 802].contains(&p.to.port()));
        }
        for (from, to) in [(client, peer), (peer, client)] {
            let stream = |sent| packets.iter().filter(|p| p.sent == sent && p.from == from && p.to == to)
                .flat_map(|p| p.bytes.iter().copied()).collect::<Vec<_>>();
            assert_eq!(stream(true), stream(false), "TCP sent != received: {from} -> {to}");
        }
    }
}
fn mac(addr: SocketAddr) -> [u8; 6] {
    let SocketAddr::V4(a) = addr else {
        panic!("IPv4 fixture");
    };
    let [hi, lo] = a.port().to_be_bytes();
    let [a, b, c, d] = a.ip().octets();
    [a, b, c, d, hi, lo]
}
fn wire(npdu: &[u8]) -> Vec<u8> {
    assert!(npdu.len() <= BYTES);
    let mut bytes = vec![0x81, 0x0a];
    bytes.extend_from_slice(&((npdu.len() + 4) as u16).to_be_bytes());
    bytes.extend_from_slice(npdu);
    bytes
}
fn decode(bytes: &[u8]) -> &[u8] {
    assert!(bytes.len() >= 6 && bytes.len() <= BYTES + 4);
    assert_eq!(&bytes[..2], &[0x81, 0x0a]);
    assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]) as usize, bytes.len());
    &bytes[4..]
}
async fn send(socket: &UdpSocket, peer: SocketAddr, npdu: &[u8], log: &PacketLog) {
    let bytes = wire(npdu);
    assert_eq!(socket.send_to(&bytes, peer).await.unwrap(), bytes.len());
    log.record(true, socket.local_addr().unwrap(), peer, &bytes);
}
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
async fn released(address: SocketAddr) -> std::net::UdpSocket {
    // Fixture wall budget, not immediate OS release or real-time qualification.
    // Under concurrent subprocess/socket activity an initial rebind can report
    // AddrInUse even after our joins. Require an OBSERVED successful bind; never
    // turn elapsed time, an abort request, or a timeout into cleanup evidence.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut waits = 0;
    loop {
        match std::net::UdpSocket::bind(address) {
            Ok(socket) => {
                if waits > 0 {
                    eprintln!("LOOPBACK-RELEASE {address} observed after {waits} waits");
                }
                return socket;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse && std::time::Instant::now() < deadline =>
            {
                waits += 1;
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            Err(error) => panic!("port {address} release NOT observed: {error}"),
        }
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
        // Unwind guard only; NOT counted as a successful stop or join.
    }
}
pub struct LoopbackPort {
    socket: Option<Arc<UdpSocket>>,
    address: SocketAddr,
    peer: SocketAddr,
    mac: [u8; 6],
    log: PacketLog,
    worker: Worker,
    pub stopped: Arc<AtomicUsize>,
}
impl TransportPort for LoopbackPort {
    async fn start(&mut self) -> Result<mpsc::Receiver<ReceivedNpdu>, Error> {
        let socket = self.socket.as_ref().unwrap().clone();
        let log = self.log.clone();
        let local = self.address;
        let peer = self.peer;
        let (tx, rx) = mpsc::channel(QUEUE);
        let (stop, mut cancel) = oneshot::channel();
        self.worker.stop = Some(stop);
        self.worker.task = Some(tokio::spawn(async move {
            let mut buf = [0; BYTES + 5];
            loop {
                tokio::select! {
                    _ = &mut cancel => break,
                    received = socket.recv_from(&mut buf) => {
                        let (n, from) = received.unwrap();
                        log.record(false, from, local, &buf[..n]);
                        assert_eq!(from, peer);
                        let npdu = decode(&buf[..n]);
                        tokio::select! {
                            _ = &mut cancel => break,
                            result = tx.send(ReceivedNpdu { npdu: npdu.to_vec().into(),
                                source_mac: mac(from).as_slice().into(), link_layer_group: false,
                                data_attributes: vec![], reply_tx: None }) => if result.is_err() { break; }
                        }
                    }
                }
            }
        }));
        Ok(rx)
    }
    async fn stop(&mut self) -> Result<(), Error> {
        self.worker.join().await;
        if let Some(socket) = self.socket.take() {
            assert_eq!(Arc::strong_count(&socket), 1, "receive task released socket");
            drop(socket);
            self.stopped.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
    async fn send_unicast(&self, npdu: &[u8], destination: &[u8]) -> Result<(), Error> {
        if destination != mac(self.peer) || npdu.len() > BYTES || npdu.len() < 2 || npdu[1] & 0xa8 != 0 {
            return Err(Error::Encoding("direct loopback only".into()));
        }
        send(self.socket.as_ref().unwrap(), self.peer, npdu, &self.log).await;
        Ok(())
    }
    async fn send_broadcast(&self, _: &[u8]) -> Result<(), Error> {
        Err(Error::Encoding("broadcast forbidden by fixture".into()))
    }
    fn local_mac(&self) -> &[u8] {
        &self.mac
    }
    fn max_apdu_length(&self) -> u16 {
        480
    }
}
pub struct Pair {
    _ports: tokio::sync::MutexGuard<'static, ()>,
    pub subscriber: SocketAddr,
    pub peer: SocketAddr,
    pub log: PacketLog,
    pub client_stopped: Arc<AtomicUsize>,
    pub peer_stopped: Arc<AtomicUsize>,
    commands: mpsc::Sender<Vec<u8>>,
    worker: Worker,
}
impl Pair {
    pub async fn new(handler: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static) -> (Self, LoopbackPort) {
        let ports = PORT_RELEASE_GUARD.lock().await;
        let subscriber_socket =
            Arc::new(UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let peer_socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let subscriber = subscriber_socket.local_addr().unwrap();
        let peer = peer_socket.local_addr().unwrap();
        let log = PacketLog::default();
        let task_log = log.clone();
        let client_stopped = Arc::new(AtomicUsize::new(0));
        let peer_stopped = Arc::new(AtomicUsize::new(0));
        let stopped = peer_stopped.clone();
        let (commands, mut rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (stop, mut cancel) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut buf = [0; BYTES + 5];
            loop {
                tokio::select! {
                    _ = &mut cancel => break,
                    Some(npdu) = rx.recv() => send(&peer_socket, subscriber, &npdu, &task_log).await,
                    received = peer_socket.recv_from(&mut buf) => {
                        let (n, from) = received.unwrap(); assert_eq!(from, subscriber);
                        task_log.record(false, from, peer, &buf[..n]);
                        for response in handler(decode(&buf[..n])) {
                            send(&peer_socket, subscriber, &response, &task_log).await;
                        }
                    }
                }
            }
            stopped.fetch_add(1, Ordering::SeqCst);
        });
        let port = LoopbackPort {
            socket: Some(subscriber_socket),
            address: subscriber,
            peer,
            mac: mac(subscriber),
            log: log.clone(),
            worker: Worker { stop: None, task: None },
            stopped: client_stopped.clone(),
        };
        (
            Self {
                _ports: ports,
                subscriber,
                peer,
                log,
                client_stopped,
                peer_stopped,
                commands,
                worker: Worker { stop: Some(stop), task: Some(task) },
            },
            port,
        )
    }
    pub async fn inject(&self, npdu: Vec<u8>) {
        self.commands.send(npdu).await.unwrap();
    }
    pub async fn finish(mut self, case: &str) {
        self.worker.join().await;
        assert_eq!(self.peer_stopped.load(Ordering::SeqCst), 1);
        assert_eq!(self.client_stopped.load(Ordering::SeqCst), 1);
        self.log.assert_loopback_only();
        self.log.assert_directed_only(self.subscriber, self.peer);
        self.log.assert_no_broadcast_bbmd_foreign();
        self.log.assert_complete();
        let a = released(self.subscriber).await;
        let b = released(self.peer).await;
        eprintln!("COV-CAPTURE {case} subscriber={} peer={} packets={} loopback/direct/no-broadcast-bbmd-foreign=PASS stop/join/rebind=PASS",
            self.subscriber, self.peer, self.log.packets().len());
        drop((a, b));
    }
}
