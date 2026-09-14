use crate::{
    fixture,
    helpers::{self, Site, KEY},
    runtime::{self, admission::WorkClass, bacnet::*, Runtime, State},
};
use std::time::{Duration, Instant};
pub const TEST_TIMEOUT: Duration = Duration::from_secs(30);
pub fn target(realm: &str, host: u8) -> DirectTarget {
    DirectTarget::parse(realm, &format!("bacnet-ip://127.0.0.{host}:47808")).unwrap()
}
pub fn pv() -> Property {
    Property::new(0, 1, 85, None).unwrap()
}
pub fn status_flags() -> Property {
    Property::new(0, 1, 111, None).unwrap()
}
pub fn profile(request: Request, allowed: Vec<DirectTarget>, services: Vec<Service>) -> Profile {
    Profile::new(
        fixture::scope(),
        vec![BindingPlan::new(
            KEY,
            "sensor-sat-1",
            "mstp://ahu-1",
            "supply-air-temp",
            target("realm-a", 2),
            request,
        )
        .unwrap()],
        allowed,
        services,
    )
    .unwrap()
}
pub fn single() -> Profile {
    profile(Request::read_property(pv()), vec![target("realm-a", 2)], vec![Service::ReadProperty])
}
pub struct Case {
    pub runtime: Runtime,
    pub peer: fake::ScriptedPeer,
    pub site: Site,
    deadline: Instant,
}
impl Case {
    pub fn new(profile: Profile, second: bool) -> Self {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let site = helpers::site(true, second);
        let peer = fake::ScriptedPeer::default();
        let mut runtime = Runtime::inert(&site.scratch.0, fixture::scope()).unwrap();
        runtime.configure_fake_bacnet(profile, peer.clone()).unwrap();
        runtime.begin_start(site.credential.clone()).unwrap();
        while runtime.status().state == State::Starting {
            runtime.poll();
            assert!(Instant::now() < deadline, "B-case startup deadline, NOT a stop/pass");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(runtime.status().state, State::RunningInert, "{:?}", runtime.status());
        Self { runtime, peer, site, deadline }
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn reply(&self, bytes: &[u8]) {
        self.peer
            .push(fake::Script::Replies(vec![fake::Reply {
                source: target("realm-a", 2),
                npdu: bytes.to_vec(),
            }]))
            .unwrap();
    }
    pub fn run(&mut self, class: WorkClass) -> runtime::Result<runtime::RawEnvelope> {
        let id = self.runtime.enqueue(class, KEY, self.deadline).unwrap();
        assert_eq!(self.runtime.dispatch_next().unwrap(), Some(id));
        self.result(id)
    }
    pub fn result(&mut self, id: runtime::WorkId) -> runtime::Result<runtime::RawEnvelope> {
        loop {
            self.runtime.poll();
            if let Some(result) = self.runtime.take_result(id) {
                return result;
            }
            assert!(Instant::now() < self.deadline, "B-case deadline, NOT a stop/pass");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    pub fn wait(&mut self, predicate: impl Fn(&Self) -> bool) {
        while !predicate(self) {
            self.runtime.poll();
            assert!(Instant::now() < self.deadline, "B-case wait deadline, NOT a stop/pass");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    pub fn stop(&mut self) {
        self.peer.release_stop();
        assert_eq!(
            self.runtime.stop(self.deadline.saturating_duration_since(Instant::now())).unwrap(),
            runtime::Drain::Stopped
        );
        self.runtime.discard_candidates().unwrap();
        assert_eq!(self.runtime.status().usage.running, [0; 3]);
        assert_eq!(self.runtime.status().usage.retained, [0; 3]);
        assert!(Instant::now() < self.deadline, "whole B-case exceeded 30s fixture timeout");
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        self.peer.release_stop();
        // Failure cleanup only; never used as passing stop evidence.
        let _ = self.runtime.stop(Duration::from_secs(30));
    }
}
pub fn batch(raw: runtime::RawEnvelope) -> ReadBatch {
    match raw.outcome {
        runtime::RawOutcome::Bacnet(batch) => batch,
        other => panic!("not a read batch: {other:?}"),
    }
}
// Independent literal expectations: BACnet Clause 20 APDU service choices and
// Clause 15.5/15.7/16.10 tags, manually specified; NEVER encoder-derived.
// Direct NPDU: version 1, expecting reply; APDU no segmentation, max APDU=480,
// invoke 0, service 12; analog-input:1, present-value:85.
pub const READ: &[u8] = &[1, 4, 0, 3, 0, 12, 12, 0, 0, 0, 1, 25, 85];
pub const ACK: &[u8] = &[1, 0, 48, 0, 12, 12, 0, 0, 0, 1, 25, 85, 62, 33, 7, 63];
pub const MULTI: &[u8] = &[1, 4, 0, 3, 0, 14, 12, 0, 0, 0, 1, 30, 9, 85, 31, 12, 0, 0, 0, 1, 30, 9, 111, 31];
pub const MULTI_ACK: &[u8] =
    &[1, 0, 48, 0, 14, 12, 0, 0, 0, 1, 30, 41, 85, 78, 33, 7, 79, 41, 111, 94, 145, 2, 145, 32, 95, 31];
pub const WHO: &[u8] = &[1, 0, 16, 8, 9, 42, 25, 42];
pub const IAM: &[u8] = &[1, 0, 16, 0, 196, 2, 0, 0, 42, 34, 1, 224, 145, 3, 33, 7];
