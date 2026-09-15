//! Test-only loopback WriteProperty harness, HARNESS-ONLY.
//!
//! Two `127.0.0.1:0` UDP binds per run (client + isolated peer), ephemeral
//! and printed by capture; forbids `502`/`802`/`8080`/`47808`. Directed
//! unicast only (NPDU v1, no route/network-msg, `0x81 0x0A` only); no
//! broadcast/BBMD/foreign; no wildcard; no facility; MBAP never BACnet.
//! Captures BOTH boundaries, not host pcap. Mirrors live_fixture/Pair:
//! loopback/directed/no-broadcast/complete, start/stop/EOF/rebind,
//! PORT_GUARD, 5s rebind, strong_count==1. No ordinary-startup socket.

use super::{
    check_frozen_preview, recheck_after_handoff, verify_content, verify_generation, Audit,
    Current, DispatchCancel, DispatchError, Feedback, FrozenRoute, FrozenWrite, Outcome,
    ProtocolResult, PvReadback, SlotReadback, FROZEN_INSTANCE, FROZEN_PRIORITY, FROZEN_PROPERTY,
    FROZEN_SLOT_PROPERTY,
};
use crate::action_journal::Admitted;
use crate::action_preview::Preview;
use bacnet_client::client::{BACnetClient, ClientConfig};
use bacnet_services::{
    read_property::ReadPropertyRequest, write_property::WritePropertyRequest,
};
use bacnet_transport::port::{ReceivedNpdu, TransportPort};
use bacnet_types::{
    enums::{ObjectType, PropertyIdentifier},
    error::Error as WireError,
    primitives::ObjectIdentifier,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{net::UdpSocket, sync::{mpsc, oneshot}, task::JoinHandle};
const CAPTURE_ENTRIES: usize = 128;
const FRAME_BYTES: usize = 4 + 1024 + 1;
const QUEUE: usize = 8;
const HARNESS_APDU_MS: u64 = 1000;
type WireResult<T> = std::result::Result<T, WireError>;

pub(crate) static PORT_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Packet {
    pub sent: bool, pub from: SocketAddr, pub to: SocketAddr, pub bytes: Vec<u8>,
}
#[derive(Clone, Default)]
pub(crate) struct PacketLog(Arc<Mutex<Vec<Packet>>>);
impl PacketLog {
    fn record(&self, sent: bool, from: SocketAddr, to: SocketAddr, bytes: &[u8]) {
        let mut p = self.0.lock().unwrap();
        assert!(p.len() < CAPTURE_ENTRIES, "never truncate capture");
        assert!(bytes.len() <= FRAME_BYTES);
        p.push(Packet { sent, from, to, bytes: bytes.to_vec() });
    }
    pub(crate) fn packets(&self) -> Vec<Packet> {
        self.0.lock().unwrap().clone()
    }
    pub(crate) fn assert_loopback_only(&self) {
        for p in self.packets() {
            assert_eq!(p.from.ip(), Ipv4Addr::LOCALHOST);
            assert_eq!(p.to.ip(), Ipv4Addr::LOCALHOST);
            assert_ne!(p.from.port(), 0);
            assert_ne!(p.to.port(), 0);
        }
    }
    pub(crate) fn assert_directed_only(&self, a: SocketAddr, b: SocketAddr) {
        for p in self.packets() {
            assert!((p.from == a && p.to == b) || (p.from == b && p.to == a), "{p:?}");
            assert!(p.bytes.len() >= 6);
            assert_eq!(p.bytes[4], 1);
            assert_eq!(p.bytes[5] & 0xa8, 0, "no route/network-msg");
        }
    }
    pub(crate) fn assert_no_broadcast_bbmd_foreign(&self) {
        for p in self.packets() {
            assert_eq!(&p.bytes[..2], &[0x81, 0x0a], "only Original-Unicast-NPDU");
            assert_eq!(u16::from_be_bytes([p.bytes[2], p.bytes[3]]) as usize, p.bytes.len());
        }
    }
    pub(crate) fn assert_complete(&self) {
        let packets = self.packets();
        assert!(!packets.is_empty());
        let sent: Vec<_> = packets.iter().filter(|p| p.sent).collect();
        let recv: Vec<_> = packets.iter().filter(|p| !p.sent).collect();
        assert_eq!(sent.len(), recv.len());
        for p in sent {
            assert_eq!(
                packets.iter().filter(|q| q.sent && q.from == p.from && q.to == p.to && q.bytes == p.bytes).count(),
                recv.iter().filter(|q| q.from == p.from && q.to == p.to && q.bytes == p.bytes).count()
            );
        }
    }
}

fn mac_of(addr: SocketAddr) -> [u8; 6] {
    let SocketAddr::V4(v4) = addr else { panic!("IPv4 fixture") };
    let [a, b, c, d] = v4.ip().octets();
    let [hi, lo] = v4.port().to_be_bytes();
    [a, b, c, d, hi, lo]
}
fn frame(npdu: &[u8]) -> Vec<u8> {
    assert!(npdu.len() <= 1025);
    let mut b = vec![0x81, 0x0a];
    b.extend_from_slice(&((npdu.len() + 4) as u16).to_be_bytes());
    b.extend_from_slice(npdu);
    b
}
fn strip(f: &[u8]) -> &[u8] {
    assert!((6..=FRAME_BYTES).contains(&f.len()));
    assert_eq!(&f[..2], &[0x81, 0x0a]);
    assert_eq!(usize::from(u16::from_be_bytes([f[2], f[3]])), f.len());
    assert_eq!(f[4], 1);
    assert!(matches!(f[5], 0 | 4), "direct NPDU only");
    &f[4..]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerMode {
    Confirm,
    DropAfterAccept,
}
#[derive(Debug, Clone)]
pub(crate) struct PeerTable {
    pub slots: [Option<f32>; 16],
    pub relinquish_default: f32,
}
impl Default for PeerTable {
    fn default() -> Self {
        Self { slots: [None; 16], relinquish_default: 20.0 }
    }
}
impl PeerTable {
    pub(crate) fn effective(&self) -> f32 {
        for s in self.slots.iter().flatten() {
            return *s;
        }
        self.relinquish_default
    }
}

struct Shared {
    socket: Mutex<Option<Arc<UdpSocket>>>,
    client: SocketAddr,
    peer: SocketAddr,
    log: PacketLog,
    table: Mutex<PeerTable>,
    mode: PeerMode,
    active: AtomicBool,
    starts: AtomicUsize,
    eofs: AtomicUsize,
    stops: AtomicUsize,
}
#[derive(Clone)]
pub(crate) struct Fixture(Arc<Shared>);
impl Fixture {
    fn record(&self, sent: bool, from: SocketAddr, to: SocketAddr, bytes: &[u8]) {
        self.0.log.record(sent, from, to, bytes);
    }
    pub(crate) fn packets(&self) -> Vec<Packet> {
        self.0.log.packets()
    }
    pub(crate) fn requests(&self) -> Vec<Vec<u8>> {
        self.packets().into_iter().filter(|p| !p.sent && p.to == self.0.peer).map(|p| strip(&p.bytes).to_vec()).collect()
    }
    pub(crate) fn sent_count(&self) -> u32 {
        self.requests().len() as u32
    }
    pub(crate) fn route(&self, realm: &str) -> FrozenRoute {
        FrozenRoute::parse(realm, &format!("bacnet-ip://{}", self.0.peer)).unwrap()
    }
    pub(crate) fn table(&self) -> PeerTable {
        self.0.table.lock().unwrap().clone()
    }
    fn port(&self, route: &FrozenRoute, cancel: DispatchCancel, deadline: Instant) -> std::result::Result<Port, DispatchError> {
        if route.mac() != &mac_of(self.0.peer) {
            return Err(DispatchError::Invalid("frozen route mismatch"));
        }
        if self.0.active.swap(true, Ordering::SeqCst) {
            return Err(DispatchError::Invalid("fixture busy"));
        }
        Ok(Port {
            fixture: self.clone(),
            socket: self.0.socket.lock().unwrap().as_ref().unwrap().clone(),
            target_mac: mac_of(self.0.peer),
            cancel,
            deadline,
            reader: Worker::default(),
            filter: Worker::default(),
            local: mac_of(self.0.client),
        })
    }
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
    }
}

pub(crate) struct Harness {
    pub(crate) fixture: Fixture,
    worker: Worker,
    _ports: tokio::sync::MutexGuard<'static, ()>,
}
impl Harness {
    pub(crate) async fn new(initial: PeerTable, mode: PeerMode) -> Self {
        let ports = PORT_GUARD.lock().await;
        let client = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let peer_addr = peer.local_addr().unwrap();
        for ep in [client_addr, peer_addr] {
            assert_eq!(ep.ip(), Ipv4Addr::LOCALHOST);
            assert!(ep.port() >= 1024);
            assert!(![502, 802, 8080, 47808].contains(&ep.port()));
        }
        assert_ne!(client_addr, peer_addr);
        let fixture = Fixture(Arc::new(Shared {
            client: client_addr,
            peer: peer_addr,
            socket: Mutex::new(Some(client)),
            log: PacketLog::default(),
            table: Mutex::new(initial),
            mode,
            active: AtomicBool::new(false),
            starts: AtomicUsize::new(0),
            eofs: AtomicUsize::new(0),
            stops: AtomicUsize::new(0),
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
                        for reply in handle_request(strip(&buf[..n]), &shared) {
                            let bytes = frame(&reply);
                            assert_eq!(peer.send_to(&bytes, from).await.unwrap(), bytes.len());
                            shared.record(true, shared.0.peer, from, &bytes);
                        }
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
        assert_eq!(starts, f.0.eofs.load(Ordering::SeqCst), "channel EOF observed");
        assert_eq!(f.requests(), expected, "exact requests, zero resends");
        let packets = f.packets();
        let sent: Vec<_> = packets.iter().filter(|p| p.sent).collect();
        let recv: Vec<_> = packets.iter().filter(|p| !p.sent).collect();
        assert_eq!(sent.len(), recv.len());
        let (client, peer) = (f.0.client, f.0.peer);
        assert_ne!(client, peer);
        f.0.log.assert_loopback_only();
        f.0.log.assert_directed_only(client, peer);
        f.0.log.assert_no_broadcast_bbmd_foreign();
        if packets.is_empty() { assert!(expected.is_empty()); } else { f.0.log.assert_complete(); }
        let socket = f.0.socket.lock().unwrap().take().unwrap();
        assert_eq!(Arc::strong_count(&socket), 1, "owners released socket");
        drop(socket);
        let a = rebind(client).await;
        let b = rebind(peer).await;
        eprintln!("DISPATCH-CAPTURE {name} client={} peer={} requests={} sent={} received={} starts={starts} BVLC/NPDU/directed/exact/loopback=PASS stop/join/channel-EOF/rebind=PASS", f.0.client, f.0.peer, expected.len(), sent.len(), recv.len());
        drop((a, b));
    }
}
async fn rebind(address: SocketAddr) -> std::net::UdpSocket {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match std::net::UdpSocket::bind(address) {
            Ok(s) => return s,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(1)).await
            }
            Err(e) => panic!("release not observed for {address}: {e}"),
        }
    }
}

fn real_bytes(value: f32) -> Vec<u8> {
    let mut o = vec![0x44];
    o.extend_from_slice(&value.to_bits().to_be_bytes());
    o
}
fn decode_real(bytes: &[u8]) -> Option<f32> {
    if bytes.len() == 5 && bytes[0] == 0x44 {
        Some(f32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]))
    } else {
        None
    }
}
fn handle_request(npdu: &[u8], shared: &Fixture) -> Vec<Vec<u8>> {
    assert!(npdu.len() >= 6);
    assert_eq!(npdu[0], 1);
    assert_eq!(npdu[1] & 0xa8, 0);
    assert!(npdu.starts_with(&[1, 4, 0, 3]), "unexpected NPDU {npdu:?}");
    let invoke = npdu[4];
    let service = npdu[5];
    if service == 15 {
        let req = WritePropertyRequest::decode(&npdu[6..]).unwrap();
        assert_eq!(req.object_identifier.object_type(), ObjectType::ANALOG_VALUE);
        assert_eq!(req.object_identifier.instance_number(), FROZEN_INSTANCE);
        assert_eq!(req.property_identifier, PropertyIdentifier::PRESENT_VALUE);
        assert_eq!(req.property_array_index, None, "no extra array field");
        assert_eq!(req.priority, Some(FROZEN_PRIORITY), "explicit P8");
        let is_null = req.property_value == vec![0x00];
        let real = decode_real(&req.property_value);
        assert!(is_null || real.is_some(), "NULL-or-Real only");
        if !is_null {
            let v = real.unwrap();
            assert!(v.is_finite());
            assert!((20.0..=24.0).contains(&(v as f64)));
        }
        {
            let mut t = shared.0.table.lock().unwrap();
            if is_null {
                t.slots[(FROZEN_PRIORITY - 1) as usize] = None;
            } else {
                t.slots[(FROZEN_PRIORITY - 1) as usize] = real;
            }
        }
        if shared.0.mode == PeerMode::DropAfterAccept {
            return vec![];
        }
        return vec![vec![1, 0, 0x20, invoke, 15]];
    }
    if service == 12 {
        let req = ReadPropertyRequest::decode(&npdu[6..]).unwrap();
        assert_eq!(req.object_identifier.object_type(), ObjectType::ANALOG_VALUE);
        assert_eq!(req.object_identifier.instance_number(), FROZEN_INSTANCE);
        let table = shared.0.table.lock().unwrap().clone();
        // Manual ComplexACK without BytesMut (closed deps): AV2 object,
        // property, optional slot index, opening 3, Real/NULL, closing 3.
        let mut payload = vec![0x0c, 0x00, 0x80, 0x00, 0x02];
        let value = if req.property_identifier == PropertyIdentifier::PRESENT_VALUE && req.property_array_index.is_none() {
            payload.extend_from_slice(&[0x19, 85, 0x3e]);
            real_bytes(table.effective())
        } else if req.property_identifier.to_raw() == FROZEN_SLOT_PROPERTY && req.property_array_index == Some(u32::from(FROZEN_PRIORITY)) {
            payload.extend_from_slice(&[0x19, 87, 0x29, 8, 0x3e]);
            match table.slots[(FROZEN_PRIORITY - 1) as usize] {
                Some(v) => real_bytes(v),
                None => vec![0x00],
            }
        } else {
            panic!("unexpected read {req:?}");
        };
        payload.extend_from_slice(&value);
        payload.push(0x3f);
        let mut out = vec![1, 0, 0x30, invoke, 12];
        out.extend_from_slice(&payload);
        return vec![out];
    }
    panic!("forbidden service {service}");
}

struct Port {
    fixture: Fixture,
    socket: Arc<UdpSocket>,
    target_mac: [u8; 6],
    cancel: DispatchCancel,
    deadline: Instant,
    reader: Worker,
    filter: Worker,
    local: [u8; 6],
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
                            let bytes = strip(&buf[..n]).to_vec();
                            tokio::select! {
                                _ = &mut cancel => break,
                                result = tx.send(bytes) => result.unwrap(),
                            }
                        }
                    }
                }
            })),
        };
        let fixture2 = self.fixture.clone();
        self.filter.task = Some(tokio::spawn(async move {
            while let Some(bytes) = raw.recv().await {
                if bytes.starts_with(&[1, 0]) && matches!(bytes.get(2), Some(0x20 | 0x30 | 0x50 | 0x60 | 0x70 | 0x71)) {
                    let mac = mac_of(fixture2.0.peer);
                    let _ = out.try_send(ReceivedNpdu {
                        npdu: bytes.into(),
                        source_mac: mac.as_slice().into(),
                        link_layer_group: false,
                        data_attributes: vec![],
                        reply_tx: None,
                    });
                }
            }
            fixture2.0.eofs.fetch_add(1, Ordering::SeqCst);
        }));
        self.fixture.0.starts.fetch_add(1, Ordering::SeqCst);
        Ok(rx)
    }
    async fn stop(&mut self) -> WireResult<()> {
        self.reader.join().await;
        self.filter.join().await;
        self.fixture.0.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn send_unicast(&self, bytes: &[u8], destination: &[u8]) -> WireResult<()> {
        let ok = bytes.starts_with(&[1, 4, 0, 3]) && matches!(bytes.get(5), Some(12 | 15));
        if !ok || destination != self.target_mac || bytes.len() > 1024 || self.cancel.check(self.deadline).is_err() {
            return Err(WireError::Encoding("dispatch handoff refused".into()));
        }
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[1] & 0xa8, 0);
        let framed = frame(bytes);
        assert_eq!(&framed[..2], &[0x81, 0x0a]);
        assert_eq!(self.fixture.0.client.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(self.fixture.0.peer.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(self.socket.send_to(&framed, self.fixture.0.peer).await.unwrap(), framed.len());
        self.fixture.record(true, self.socket.local_addr().unwrap(), self.fixture.0.peer, &framed);
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

fn wire_kind(error: &WireError) -> ProtocolResult {
    match error {
        WireError::Protocol { class, code } => ProtocolResult::RemoteError { class: *class, code: *code },
        WireError::Reject { reason } => ProtocolResult::Reject(*reason),
        WireError::Abort { reason } => ProtocolResult::Abort(*reason),
        WireError::Timeout(_) => ProtocolResult::Timeout,
        WireError::Transport(_) => ProtocolResult::TransportFailure,
        WireError::Encoding(_)
        | WireError::Decoding { .. }
        | WireError::Segmentation(_)
        | WireError::BufferTooShort { .. }
        | WireError::InvalidTag(_)
        | WireError::OutOfRange(_)
        | WireError::RoutedPathTooLong { .. }
        | WireError::RoutedPathCapacityExceeded { .. } => ProtocolResult::InvalidReply,
    }
}
fn is_timeout_abort(error: &WireError) -> bool {
    match error {
        WireError::Abort { reason } => *reason == 10,
        WireError::Timeout(_) => true,
        _ => false,
    }
}
async fn confirmed_write(fixture: &Fixture, write: &FrozenWrite, cancel: &DispatchCancel, deadline: Instant, route: &FrozenRoute) -> std::result::Result<(), WireError> {
    let port = fixture.port(route, cancel.clone(), deadline).map_err(|_| WireError::Encoding("frozen route".into()))?;
    let mut client = BACnetClient::start(
        ClientConfig { apdu_timeout_ms: HARNESS_APDU_MS, apdu_retries: 0, max_apdu_length: 480, segmented_response_accepted: false, ..ClientConfig::default() },
        port,
    )
    .await
    .map_err(|_| WireError::Encoding("client start".into()))?;
    let object = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, FROZEN_INSTANCE).unwrap();
    let property = if write.property() == FROZEN_PROPERTY { PropertyIdentifier::PRESENT_VALUE } else { PropertyIdentifier::from_raw(write.property()) };
    let target = mac_of(fixture.0.peer);
    let result = {
        let fut = client.write_property(&target, object, property, None, write.value().to_vec(), Some(write.priority()));
        tokio::pin!(fut);
        loop {
            tokio::select! {
                r = &mut fut => break r,
                _ = tokio::time::sleep(Duration::from_millis(2)) => {
                    if cancel.check(deadline).is_err() {
                        break Err(WireError::Encoding("dispatch cancelled".into()));
                    }
                }
            }
        }
    };
    client.stop().await.map_err(|_| WireError::Encoding("client stop".into()))?;
    result
}
async fn confirmed_read(fixture: &Fixture, property_raw: u32, array: Option<u32>, cancel: &DispatchCancel, deadline: Instant, route: &FrozenRoute) -> std::result::Result<Vec<u8>, WireError> {
    let port = fixture.port(route, cancel.clone(), deadline).map_err(|_| WireError::Encoding("frozen route".into()))?;
    let mut client = BACnetClient::start(
        ClientConfig { apdu_timeout_ms: HARNESS_APDU_MS, apdu_retries: 0, max_apdu_length: 480, segmented_response_accepted: false, ..ClientConfig::default() },
        port,
    )
    .await
    .map_err(|_| WireError::Encoding("client start".into()))?;
    let object = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, FROZEN_INSTANCE).unwrap();
    let property = if property_raw == FROZEN_PROPERTY { PropertyIdentifier::PRESENT_VALUE } else { PropertyIdentifier::from_raw(property_raw) };
    let target = mac_of(fixture.0.peer);
    let result = {
        let fut = client.read_property(&target, object, property, array);
        tokio::pin!(fut);
        loop {
            tokio::select! {
                r = &mut fut => break r,
                _ = tokio::time::sleep(Duration::from_millis(2)) => {
                    if cancel.check(deadline).is_err() {
                        break Err(WireError::Encoding("dispatch cancelled".into()));
                    }
                }
            }
        }
    };
    client.stop().await.map_err(|_| WireError::Encoding("client stop".into()))?;
    cancel.check(deadline).map_err(|_| WireError::Encoding("dispatch cancelled".into()))?;
    match result {
        Ok(ack) => {
            if ack.object_identifier != object || ack.property_identifier.to_raw() != property_raw || ack.property_array_index != array {
                return Err(WireError::Decoding { offset: 0, message: "mismatched readback".into() });
            }
            Ok(ack.property_value)
        }
        Err(e) => Err(e),
    }
}
fn map_read_error(error: WireError, admitted: &Admitted) -> DispatchError {
    if is_timeout_abort(&error) {
        DispatchError::Unknown {
            operation: admitted.operation().as_str().to_string(),
            attempt: admitted.attempt().as_str().to_string(),
            detail: "uncertain-not-resend: readback lost; reconcile, do not resend".to_string(),
        }
    } else {
        DispatchError::Invalid("readback invalid reply")
    }
}
/// Execute one frozen setpoint dispatch with handoff rechecks and no SQL guard.
pub(crate) async fn execute_setpoint(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    fixture: &Fixture,
    before_send: Option<Arc<dyn Fn() + Send + Sync>>,
    after_write: Option<Arc<dyn Fn() + Send + Sync>>,
) -> std::result::Result<Outcome, DispatchError> {
    check_frozen_preview(preview)?;
    verify_content(admitted, preview, current, route)?;
    if let Some(hook) = before_send {
        hook();
    }
    verify_generation(admitted, current)?;
    cancel.check(deadline)?;
    let write = super::prepare_setpoint(admitted, preview, current, route, cancel, deadline)?;
    assert_eq!(write.object_type(), 2);
    assert_eq!(write.instance(), FROZEN_INSTANCE);
    assert_eq!(write.property(), FROZEN_PROPERTY);
    assert_eq!(write.priority(), FROZEN_PRIORITY);
    assert!(!write.is_release());
    let result = confirmed_write(fixture, &write, cancel, deadline, route).await;
    if let Some(hook) = after_write {
        hook();
    }
    match result {
        Ok(()) => {
            recheck_after_handoff(admitted, current, cancel, deadline)?;
            let slot_wall = SystemTime::now();
            let slot_mono = Instant::now();
            let slot_bytes = confirmed_read(fixture, FROZEN_SLOT_PROPERTY, Some(u32::from(FROZEN_PRIORITY)), cancel, deadline, route).await.map_err(|e| map_read_error(e, admitted))?;
            let pv_wall = SystemTime::now();
            let pv_mono = Instant::now();
            let pv_bytes = confirmed_read(fixture, FROZEN_PROPERTY, None, cancel, deadline, route).await.map_err(|e| map_read_error(e, admitted))?;
            recheck_after_handoff(admitted, current, cancel, deadline)?;
            let audit = Audit::new(fixture.sent_count());
            assert_eq!(audit.effective_retries(), 0);
            assert_eq!(audit.apdu_retries(), 0);
            Ok(Outcome::new(admitted, ProtocolResult::Confirmed, SlotReadback::new(slot_bytes, slot_wall, slot_mono), PvReadback::new(pv_bytes, pv_wall, pv_mono), Feedback::unavailable(), audit))
        }
        Err(e) if is_timeout_abort(&e) => Err(DispatchError::Unknown {
            operation: admitted.operation().as_str().to_string(),
            attempt: admitted.attempt().as_str().to_string(),
            detail: "uncertain-not-resend: response lost after handoff; reconcile, do not resend".to_string(),
        }),
        Err(e) if matches!(e, WireError::Encoding(_)) && cancel.check(deadline).is_err() => Err(cancel.check(deadline).unwrap_err()),
        Err(e) => {
            let protocol = wire_kind(&e);
            recheck_after_handoff(admitted, current, cancel, deadline)?;
            let slot_wall = SystemTime::now();
            let slot_mono = Instant::now();
            let slot_bytes = confirmed_read(fixture, FROZEN_SLOT_PROPERTY, Some(u32::from(FROZEN_PRIORITY)), cancel, deadline, route).await.map_err(|err| map_read_error(err, admitted))?;
            let pv_wall = SystemTime::now();
            let pv_mono = Instant::now();
            let pv_bytes = confirmed_read(fixture, FROZEN_PROPERTY, None, cancel, deadline, route).await.map_err(|err| map_read_error(err, admitted))?;
            let audit = Audit::new(fixture.sent_count());
            Ok(Outcome::new(admitted, protocol, SlotReadback::new(slot_bytes, slot_wall, slot_mono), PvReadback::new(pv_bytes, pv_wall, pv_mono), Feedback::unavailable(), audit))
        }
    }
}
/// Execute one frozen release (NULL at P8); NULL only for admitted releases.
pub(crate) async fn execute_release(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    fixture: &Fixture,
) -> std::result::Result<Outcome, DispatchError> {
    check_frozen_preview(preview)?;
    verify_content(admitted, preview, current, route)?;
    verify_generation(admitted, current)?;
    cancel.check(deadline)?;
    let write = super::prepare_release(admitted, preview, current, route, cancel, deadline)?;
    assert!(write.is_release());
    assert_eq!(write.value(), &[0x00]);
    match confirmed_write(fixture, &write, cancel, deadline, route).await {
        Ok(()) => {
            recheck_after_handoff(admitted, current, cancel, deadline)?;
            let slot_wall = SystemTime::now();
            let slot_mono = Instant::now();
            let slot_bytes = confirmed_read(fixture, FROZEN_SLOT_PROPERTY, Some(u32::from(FROZEN_PRIORITY)), cancel, deadline, route).await.map_err(|e| map_read_error(e, admitted))?;
            let pv_wall = SystemTime::now();
            let pv_mono = Instant::now();
            let pv_bytes = confirmed_read(fixture, FROZEN_PROPERTY, None, cancel, deadline, route).await.map_err(|e| map_read_error(e, admitted))?;
            let audit = Audit::new(fixture.sent_count());
            Ok(Outcome::new(admitted, ProtocolResult::Confirmed, SlotReadback::new(slot_bytes, slot_wall, slot_mono), PvReadback::new(pv_bytes, pv_wall, pv_mono), Feedback::unavailable(), audit))
        }
        Err(e) if is_timeout_abort(&e) => Err(DispatchError::Unknown {
            operation: admitted.operation().as_str().to_string(),
            attempt: admitted.attempt().as_str().to_string(),
            detail: "uncertain-not-resend: release lost; reconcile, do not resend".to_string(),
        }),
        Err(e) if matches!(e, WireError::Encoding(_)) && cancel.check(deadline).is_err() => Err(cancel.check(deadline).unwrap_err()),
        Err(e) => {
            let protocol = wire_kind(&e);
            recheck_after_handoff(admitted, current, cancel, deadline)?;
            let slot_wall = SystemTime::now();
            let slot_mono = Instant::now();
            let slot_bytes = confirmed_read(fixture, FROZEN_SLOT_PROPERTY, Some(u32::from(FROZEN_PRIORITY)), cancel, deadline, route).await.map_err(|err| map_read_error(err, admitted))?;
            let pv_wall = SystemTime::now();
            let pv_mono = Instant::now();
            let pv_bytes = confirmed_read(fixture, FROZEN_PROPERTY, None, cancel, deadline, route).await.map_err(|err| map_read_error(err, admitted))?;
            let audit = Audit::new(fixture.sent_count());
            Ok(Outcome::new(admitted, protocol, SlotReadback::new(slot_bytes, slot_wall, slot_mono), PvReadback::new(pv_bytes, pv_wall, pv_mono), Feedback::unavailable(), audit))
        }
    }
}
