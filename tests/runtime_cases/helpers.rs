use crate::{
    accept, access,
    fixture::{self, Fixture, Scratch},
    runtime::{self, Runtime, State},
    support,
};
use std::{
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

pub const KEY: &str = "sat-binding";
pub fn lifetime() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
pub fn wait(runtime: &mut Runtime, predicate: impl Fn(&Runtime) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !predicate(runtime) {
        runtime.poll();
        assert!(Instant::now() < deadline, "test wait expired, NOT a stop/pass: {:?}", runtime.status());
        std::thread::sleep(Duration::from_millis(2));
    }
}
pub struct Site {
    pub credential: access::Credential,
    pub pending: Option<accept::PendingAcceptance>,
    pub scratch: Scratch,
}
pub fn site(accepted: bool, second: bool) -> Site {
    let mut fixture = Fixture::new();
    let mut pending = None;
    if accepted {
        let (store, sealed) = support::publish(&mut fixture, "runtime-one", "Synthetic SAT");
        let first =
            support::prepare(&mut fixture, &store, &sealed, "runtime-accept-one", accept::AcceptedRevision::INITIAL);
        let first = store.submit(&first, &fixture.seals).unwrap();
        store
            .activate(
                &accept::ActivationRequest::new(
                    fixture::operation("runtime-active-one"),
                    accept::ActiveGeneration::INITIAL,
                    first.request,
                ),
                &fixture.seals,
            )
            .unwrap();
        if second {
            let (store, sealed) = support::publish(&mut fixture, "runtime-two", "Synthetic replacement SAT");
            pending = Some(support::prepare(
                &mut fixture,
                &store,
                &sealed,
                "runtime-accept-two",
                accept::AcceptedRevision::new(1).unwrap(),
            ));
        }
    }
    let Fixture { gate, credentials, registry, native, seals, reference, finding, scratch } = fixture;
    let credential = credentials.publisher.clone();
    drop((gate, credentials, registry, seals, reference, finding));
    drop(native.close());
    // Actual native writer LOCK release, not sleep/retry-open as a success oracle.
    let lock = std::fs::OpenOptions::new().read(true).write(true).open(scratch.native().join("LOCK")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                assert!(Instant::now() < deadline, "fixture owner did not release LOCK");
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("fixture LOCK error: {error}"),
        }
    }
    lock.unlock().unwrap();
    Site { credential, pending, scratch }
}
pub fn start(site: &Site) -> Runtime {
    let mut runtime = Runtime::inert(&site.scratch.0, fixture::scope()).unwrap();
    runtime.begin_start(site.credential.clone()).unwrap();
    wait(&mut runtime, |r| r.status().state != State::Starting);
    assert_eq!(runtime.status().state, State::RunningInert, "{:?}", runtime.status());
    runtime
}
pub fn advance(runtime: &Runtime, site: &Site) {
    let (accepted, seals, _) = runtime.test_stores();
    let record = accepted.submit(site.pending.as_ref().unwrap(), seals).unwrap();
    let request = accept::ActivationRequest::new(
        fixture::operation("runtime-active-two"),
        accept::ActiveGeneration::new(1).unwrap(),
        record.request,
    );
    accepted.activate(&request, seals).unwrap();
}
pub fn result(runtime: &mut Runtime, id: runtime::WorkId) -> runtime::Result<runtime::RawEnvelope> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        runtime.poll();
        if let Some(result) = runtime.take_result(id) {
            return result;
        }
        assert!(Instant::now() < deadline, "no result; not a pass: {:?}", runtime.status());
        std::thread::sleep(Duration::from_millis(2));
    }
}
pub fn stopped(runtime: &mut Runtime) {
    assert_eq!(runtime.stop(Duration::from_secs(30)).unwrap(), runtime::Drain::Stopped);
    assert_eq!(runtime.status().usage.running, [0; 3]);
    assert_eq!(runtime.status().usage.retained, [0; 3]);
}
// Deterministic scheduling barrier; waits have test failure deadlines, not timing
// assumptions about how long native operations usually take.
#[derive(Clone, Default)]
pub struct Latch(Arc<(Mutex<(bool, bool)>, Condvar)>);
impl Latch {
    pub fn hook(&self) -> Arc<dyn Fn() + Send + Sync> {
        let latch = self.clone();
        Arc::new(move || {
            let (lock, cv) = &*latch.0;
            let mut state = lock.lock().unwrap();
            state.0 = true;
            cv.notify_all();
            let (state, timeout) = cv.wait_timeout_while(state, Duration::from_secs(30), |s| !s.1).unwrap();
            assert!(!timeout.timed_out() && state.1, "unreleased test latch");
        })
    }
    pub fn entered(&self) {
        let (lock, cv) = &*self.0;
        let (state, timeout) = cv.wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(30), |s| !s.0).unwrap();
        assert!(!timeout.timed_out() && state.0, "test latch not reached");
    }
    pub fn release(&self) {
        let (lock, cv) = &*self.0;
        lock.lock().unwrap().1 = true;
        cv.notify_all();
    }
}
