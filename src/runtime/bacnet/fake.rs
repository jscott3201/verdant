//! Socket-free scripted TransportPort. No external transport can be injected.
//! Live loopback peer tests are DEFERRED pending upstream loopback-bind support
//! or a fresh E03 amendment. These bytes never leave process memory.
use super::{model::MAX_NPDU_BYTES, Advertisement, DirectTarget, Error, Result, Service};
use crate::runtime::task::Cancellation;
use bacnet_transport::port::{ReceivedNpdu, TransportPort};
use bacnet_types::error::Error as WireError;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Instant, SystemTime},
};
use tokio::sync::mpsc;

pub const MAX_SCRIPTS: usize = 8;
pub const MAX_REPLIES: usize = 4;
pub const MAX_CAPTURED: usize = 8;
#[derive(Debug, Clone)]
pub struct Reply {
    pub source: DirectTarget,
    pub npdu: Vec<u8>,
}
#[derive(Debug, Clone)]
pub enum Script {
    Replies(Vec<Reply>),
    Silence,
    /// An oversized input descriptor, not an unbounded retained allocation.
    Oversized {
        bytes: usize,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedRequest {
    pub destination: [u8; 6],
    pub npdu: Vec<u8>,
}
#[derive(Debug, Clone, Copy)]
pub(super) struct Receipt {
    pub wall: SystemTime,
    pub monotonic: Instant,
}
#[derive(Default)]
struct State {
    scripts: VecDeque<Script>,
    captured: Vec<EncodedRequest>,
}
struct Shared {
    state: Mutex<State>,
    stop_held: AtomicBool,
    stopping: AtomicUsize,
    stopped: AtomicUsize,
}
#[derive(Clone)]
pub struct ScriptedPeer(Arc<Shared>);
impl Default for ScriptedPeer {
    fn default() -> Self {
        Self(Arc::new(Shared {
            state: Mutex::new(State::default()),
            stop_held: AtomicBool::new(false),
            stopping: AtomicUsize::new(0),
            stopped: AtomicUsize::new(0),
        }))
    }
}
impl ScriptedPeer {
    pub fn push(&self, script: Script) -> Result<()> {
        let script = match script {
            Script::Replies(mut replies) => {
                if replies.len() > MAX_REPLIES
                    || replies.iter().any(|reply| reply.npdu.len() > MAX_NPDU_BYTES)
                {
                    return Err(Error::Oversized);
                }
                // Retain bounded buffers, not caller-supplied excess capacity.
                for reply in &mut replies {
                    reply.npdu = std::mem::take(&mut reply.npdu).into_boxed_slice().into_vec();
                }
                Script::Replies(replies.into_boxed_slice().into_vec())
            }
            Script::Silence => Script::Silence,
            Script::Oversized { bytes } => Script::Oversized { bytes },
        };
        let mut state = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        if state.scripts.len() == MAX_SCRIPTS {
            return Err(Error::Budget);
        }
        state.scripts.push_back(script);
        Ok(())
    }
    pub fn take_requests(&self) -> Result<Vec<EncodedRequest>> {
        Ok(std::mem::take(&mut self.0.state.lock().map_err(|_| Error::Poisoned)?.captured))
    }
    pub fn hold_stop(&self) {
        self.0.stop_held.store(true, Ordering::SeqCst);
    }
    pub fn release_stop(&self) {
        self.0.stop_held.store(false, Ordering::SeqCst);
    }
    pub fn stopping(&self) -> usize {
        self.0.stopping.load(Ordering::SeqCst)
    }
    pub fn stopped(&self) -> usize {
        self.0.stopped.load(Ordering::SeqCst)
    }
}
#[derive(Default)]
pub(super) struct Delivery {
    pub advertisements: Vec<Advertisement>,
    pub error: Option<Error>,
}
pub(super) struct FakePort {
    peer: ScriptedPeer,
    destination: DirectTarget,
    service: Service,
    allowed_sources: Vec<DirectTarget>,
    current: (Cancellation, Instant),
    tx: mpsc::Sender<ReceivedNpdu>,
    rx: Option<mpsc::Receiver<ReceivedNpdu>>,
    pub delivery: Arc<Mutex<Delivery>>,
}
impl FakePort {
    pub fn new(
        peer: ScriptedPeer,
        destination: DirectTarget,
        service: Service,
        allowed_sources: Vec<DirectTarget>,
        current: (Cancellation, Instant),
    ) -> Self {
        let (tx, rx) = mpsc::channel(MAX_REPLIES);
        Self {
            peer,
            destination,
            service,
            allowed_sources,
            current,
            tx,
            rx: Some(rx),
            delivery: Arc::new(Mutex::new(Delivery::default())),
        }
    }
    fn record(&self, npdu: &[u8], mac: &[u8]) -> Result<()> {
        let choice_ok = match self.service {
            Service::ReadProperty => npdu.starts_with(&[1, 4, 0, 3]) && npdu.get(5) == Some(&12),
            Service::ReadPropertyMultiple => npdu.starts_with(&[1, 4, 0, 3]) && npdu.get(5) == Some(&14),
            Service::DirectedWhoIs => npdu.starts_with(&[1, 0, 16, 8]),
        };
        if !choice_ok || mac != self.destination.mac() || npdu.len() > MAX_NPDU_BYTES {
            return Err(Error::DeniedService);
        }
        let script = {
            let mut state = self.peer.0.state.lock().map_err(|_| Error::Poisoned)?;
            if state.captured.len() == MAX_CAPTURED {
                return Err(Error::Budget);
            }
            // Final no-I/O handoff gate, after any startup/encoding/scheduling
            // delay. An expired/canceled request never consumes its script.
            self.current.0.check(self.current.1).map_err(|_| Error::NotCurrent)?;
            state.captured.push(EncodedRequest { destination: *self.destination.mac(), npdu: npdu.to_vec() });
            state.scripts.pop_front().unwrap_or(Script::Silence)
        };
        match script {
            Script::Silence => Ok(()),
            Script::Oversized { bytes } => {
                if bytes > MAX_NPDU_BYTES {
                    Err(Error::Oversized)
                } else {
                    Err(Error::InvalidReply)
                }
            }
            Script::Replies(replies) => {
                for reply in replies {
                    if reply.npdu.len() > MAX_NPDU_BYTES {
                        return Err(Error::Oversized);
                    }
                    if !self.allowed_sources.contains(&reply.source) {
                        return Err(Error::DeniedDestination);
                    }
                    match self.service {
                        Service::DirectedWhoIs => {
                            if !reply.npdu.starts_with(&[1, 0, 16, 0]) {
                                return Err(Error::InvalidReply);
                            }
                            let advertisement = Advertisement::decode(reply.source, &reply.npdu[4..])?;
                            let mut delivery = self.delivery.lock().map_err(|_| Error::Poisoned)?;
                            delivery.advertisements.push(advertisement);
                        }
                        Service::ReadProperty | Service::ReadPropertyMultiple => {
                            // No incoming requests, COV/events, routes, segmentation or
                            // network messages enter the client and provoke auto-responses.
                            if reply.source != self.destination
                                || !reply.npdu.starts_with(&[1, 0])
                                || !matches!(reply.npdu.get(2), Some(0x30 | 0x50 | 0x60 | 0x70 | 0x71))
                            {
                                return Err(Error::InvalidReply);
                            }
                            self.tx
                                .try_send(ReceivedNpdu {
                                    npdu: reply.npdu.into(),
                                    source_mac: reply.source.mac().as_slice().into(),
                                    link_layer_group: false,
                                    data_attributes: Vec::new(),
                                    reply_tx: None,
                                })
                                .map_err(|_| Error::Budget)?;
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn b05_final_fake_handoff_rechecks_deadline_and_cancellation() {
        for expired in [true, false] {
            let peer = ScriptedPeer::default();
            peer.push(Script::Silence).unwrap();
            let target = DirectTarget::parse("realm-a", "bacnet-ip://127.0.0.2:47808").unwrap();
            let cancel = Cancellation::default();
            let deadline = if expired {
                Instant::now()
            } else {
                cancel.cancel();
                Instant::now() + std::time::Duration::from_secs(1)
            };
            let port = FakePort::new(
                peer.clone(),
                target.clone(),
                Service::ReadProperty,
                vec![target.clone()],
                (cancel, deadline),
            );
            let request = [1, 4, 0, 3, 0, 12, 12, 0, 0, 0, 1, 25, 85];
            assert_eq!(port.record(&request, target.mac()), Err(Error::NotCurrent));
            assert!(peer.take_requests().unwrap().is_empty());
            assert_eq!(peer.0.state.lock().unwrap().scripts.len(), 1);
        }
    }
}
impl TransportPort for FakePort {
    async fn start(&mut self) -> std::result::Result<mpsc::Receiver<ReceivedNpdu>, WireError> {
        self.rx.take().ok_or_else(|| WireError::Encoding("fake already started".into()))
    }
    async fn stop(&mut self) -> std::result::Result<(), WireError> {
        self.peer.0.stopping.fetch_add(1, Ordering::SeqCst);
        // Only the test controls this hold. No spawned transport task survives it.
        // Runtime retains the actual job/reservations and reports Unresolved.
        while self.peer.0.stop_held.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        self.peer.0.stopped.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn send_unicast(&self, npdu: &[u8], mac: &[u8]) -> std::result::Result<(), WireError> {
        match self.record(npdu, mac) {
            Ok(()) => Ok(()),
            Err(error) => {
                if let Ok(mut delivery) = self.delivery.lock() {
                    delivery.error = Some(error);
                }
                Err(WireError::Encoding("socket-free adapter refusal".into()))
            }
        }
    }
    async fn send_broadcast(&self, _npdu: &[u8]) -> std::result::Result<(), WireError> {
        Err(WireError::Encoding("broadcast refused".into()))
    }
    fn local_mac(&self) -> &[u8] {
        &[127, 0, 0, 1, 0xba, 0xc0]
    }
    fn max_apdu_length(&self) -> u16 {
        480
    }
}
