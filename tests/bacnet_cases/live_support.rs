//! Live fixture drivers, not protocol encoders. Original Clause 15.5/15.7/16.10/20
//! expectations in support.rs are reused byte-for-byte and never regenerated.
pub(crate) use crate::bacnet_support::{pv, status_flags, ACK, IAM, MULTI, MULTI_ACK, READ, WHO};
pub(crate) use crate::runtime::{self, admission::WorkClass::*, bacnet::*, RawEnvelope, RawOutcome};
use crate::{
    fixture,
    helpers::{self, Site, KEY},
};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

pub type Exchange = (Vec<u8>, Vec<Vec<u8>>);
pub fn exchange(request: &[u8], response: &[u8]) -> Exchange {
    (request.to_vec(), vec![response.to_vec()])
}
pub fn plan(target: DirectTarget, request: Request, endpoint: &str) -> BindingPlan {
    BindingPlan::new(KEY, "sensor-sat-1", endpoint, "supply-air-temp", target, request).unwrap()
}
pub fn profile(target: DirectTarget, request: Request) -> Profile {
    let service = request.service();
    Profile::new(
        fixture::scope(),
        vec![plan(target.clone(), request, "mstp://ahu-1")],
        vec![target],
        vec![service],
    )
    .unwrap()
}
pub struct Case {
    pub runtime: runtime::Runtime,
    pub wire: live_fixture::Fixture,
    pub target: DirectTarget,
    pub driver: tokio::runtime::Runtime,
    harness: Option<live_fixture::Harness>,
    expected: Vec<Vec<u8>>,
    deadline: Instant,
    site: Site,
}
impl Case {
    pub fn new(request: Request, exchanges: Vec<Exchange>) -> Self {
        Self::custom("realm-a", exchanges, |target| profile(target, request))
    }
    pub fn custom(
        realm: &str,
        exchanges: Vec<Exchange>,
        configure: impl FnOnce(DirectTarget) -> Profile,
    ) -> Self {
        assert!(exchanges.len() <= 8);
        let site = helpers::site(true, false);
        let driver = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let expected = exchanges.iter().map(|e| e.0.clone()).collect();
        let discovery_replies = exchanges.first().filter(|e| e.0 == WHO).map_or(0, |e| e.1.len());
        let mut exchanges: VecDeque<_> = exchanges.into();
        let harness = driver.block_on(live_fixture::Harness::new(
            move |bytes| {
                let (expected, replies) = exchanges.pop_front().expect("unexpected request/resend");
                assert_eq!(bytes, expected, "independent NPDU/APDU/property/range expectation");
                replies
            },
            discovery_replies,
        ));
        // Excludes time waiting for the shared release guard; all acquisition,
        // queueing, result, stop and capture checks share this 30s fixture bound.
        let deadline = Instant::now() + Duration::from_secs(30);
        let wire = harness.fixture.clone();
        let target = wire.target(realm);
        let mut runtime = runtime::Runtime::inert(&site.scratch.0, fixture::scope()).unwrap();
        runtime.configure_live_reads(configure(target.clone()), wire.clone()).unwrap();
        runtime.begin_start(site.credential.clone()).unwrap();
        let mut case =
            Self { runtime, wire, target, driver, harness: Some(harness), expected, deadline, site };
        case.wait(|r, _| r.status().state != runtime::State::Starting);
        assert_eq!(case.runtime.status().state, runtime::State::RunningInert);
        case
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn wait(&mut self, predicate: impl Fn(&runtime::Runtime, &live_fixture::Fixture) -> bool) {
        self.driver.block_on(async {
            while !predicate(&self.runtime, &self.wire) {
                self.runtime.poll();
                assert!(Instant::now() < self.deadline, "live fixture wait expired, NOT stop/pass");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
    }
    pub fn result(&mut self, id: runtime::WorkId) -> runtime::Result<RawEnvelope> {
        self.driver.block_on(async {
            loop {
                self.runtime.poll();
                if let Some(raw) = self.runtime.take_result(id) {
                    return raw;
                }
                assert!(Instant::now() < self.deadline, "live fixture result deadline, NOT stop/pass");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    }
    pub fn run(&mut self, class: runtime::admission::WorkClass) -> runtime::Result<RawEnvelope> {
        let id = self.runtime.enqueue(class, KEY, self.deadline).unwrap();
        assert_eq!(self.runtime.dispatch_next().unwrap(), Some(id));
        self.result(id)
    }
    pub fn finish(mut self, name: &str) {
        self.driver.block_on(async {
            loop {
                match self.runtime.stop(Duration::ZERO).unwrap() {
                    runtime::Drain::Stopped => break,
                    runtime::Drain::Unresolved { .. } => {
                        assert!(Instant::now() < self.deadline, "live owner did not stop");
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
            }
        });
        self.runtime.discard_candidates().unwrap();
        assert_eq!(self.runtime.status().usage.retained, [0; 3]);
        assert_eq!(self.runtime.status().usage.running, [0; 3]);
        assert!(!self.runtime.status().observed_qualification);
        self.driver.block_on(self.harness.take().unwrap().finish(name, &self.expected));
        assert!(Instant::now() < self.deadline);
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        // Failure-only cleanup drives socket tasks while joining the actual jobs.
        // Never substitutes for finish's assertions or reports a pass.
        let deadline = Instant::now() + Duration::from_secs(30);
        self.driver.block_on(async {
            while matches!(self.runtime.stop(Duration::ZERO), Ok(runtime::Drain::Unresolved { .. })) {
                if Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
    }
}
pub fn batch(raw: &RawEnvelope) -> &ReadBatch {
    let RawOutcome::Bacnet(batch) = &raw.outcome else { panic!("not BACnet: {raw:?}") };
    batch
}
