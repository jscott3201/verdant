use crate::{
    bacnet_support::*,
    helpers::{self, Latch, KEY},
    runtime::{self, admission::WorkClass::*, bacnet::*, Drain, State},
};
use std::time::{Duration, Instant};

#[test]
fn b05_expired_and_canceled_queued_reads_emit_nothing() {
    let mut case = Case::new(single(), false);
    case.reply(ACK);
    let deadline = Instant::now() + Duration::from_millis(10);
    let id = case.runtime.enqueue(CurrentSensing, KEY, deadline).unwrap();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(case.runtime.dispatch_next().unwrap(), Some(id));
    assert_eq!(case.result(id).unwrap_err().code(), "runtime-deadline");
    let id = case.runtime.enqueue(CurrentSensing, KEY, case.deadline()).unwrap();
    case.runtime.cancel(id).unwrap();
    assert_eq!(case.result(id).unwrap_err().code(), "runtime-cancelled");
    assert!(case.peer.take_requests().unwrap().is_empty());
    assert_eq!(case.peer.stopping(), 0);
    case.stop();
}

#[test]
fn b07_shared_saturation_preserves_mandatory_slots() {
    let mut case = Case::new(single(), false);
    for _ in 0..60 {
        case.runtime.enqueue(OptionalDiscovery, KEY, case.deadline()).unwrap();
    }
    assert!(matches!(
        case.runtime.enqueue(OptionalDiscovery, KEY, case.deadline()),
        Err(runtime::Error::Saturated { class: OptionalDiscovery, running: false })
    ));
    for class in [CurrentSensing, Reconciliation] {
        case.runtime.enqueue(class, KEY, case.deadline()).unwrap();
        case.runtime.enqueue(class, KEY, case.deadline()).unwrap();
        assert!(matches!(
            case.runtime.enqueue(class, KEY, case.deadline()),
            Err(runtime::Error::Saturated { running: false, .. })
        ));
    }
    assert_eq!(case.runtime.status().usage.retained, [2, 2, 60]);
    assert!(case.peer.take_requests().unwrap().is_empty());
    case.stop();
}

#[test]
fn b07_quarantine_uses_same_optional_reservation_family() {
    let mut case = Case::new(
        profile(
            Request::directed_discovery(42).unwrap(),
            vec![target("realm-a", 2)],
            vec![Service::DirectedWhoIs],
        ),
        false,
    );
    let first = case.runtime.enqueue(OptionalDiscovery, KEY, case.deadline()).unwrap();
    for _ in 1..60 {
        case.runtime.enqueue(OptionalDiscovery, KEY, case.deadline()).unwrap();
    }
    case.reply(IAM);
    assert_eq!(case.runtime.dispatch_next().unwrap(), Some(first));
    assert_eq!(case.result(first).unwrap_err().code(), "bacnet-shared-budget");
    assert!(case.runtime.candidates(Instant::now()).unwrap().is_empty());
    assert_eq!(case.runtime.status().usage.retained, [0, 0, 59]);
    case.stop();
}

#[test]
fn b08_stalled_poll_records_misses_without_burst() {
    let start = Instant::now();
    let mut schedule = poll::PollSchedule::new(start, Duration::from_secs(1)).unwrap();
    assert_eq!(schedule.due(start).unwrap(), None);
    assert_eq!(schedule.due(start + Duration::from_millis(999)).unwrap(), None);
    assert_eq!(schedule.due(start + Duration::from_secs(10)).unwrap(), Some(poll::Due { missed: 9 }));
    for _ in 0..100 {
        assert_eq!(schedule.due(start + Duration::from_secs(10)).unwrap(), None);
    }
    assert_eq!(schedule.due(start + Duration::from_secs(11)).unwrap(), Some(poll::Due { missed: 0 }));
    assert!(poll::PollSchedule::new(start, Duration::ZERO).is_err());
}

#[test]
fn b10_cancel_during_read_retains_owner_until_actual_stop_join() {
    let mut case = Case::new(single(), false);
    case.peer.hold_stop();
    let id = case.runtime.enqueue(CurrentSensing, KEY, case.deadline()).unwrap();
    case.runtime.dispatch_next().unwrap();
    // Fake send was actually reached, but no reply was supplied.
    case.wait(|case| !case.peer.take_requests().unwrap().is_empty());
    case.runtime.cancel(id).unwrap();
    case.wait(|case| case.peer.stopping() == 1);
    assert_eq!(case.peer.stopped(), 0);
    assert_eq!(case.runtime.stop(Duration::ZERO).unwrap(), Drain::Unresolved { jobs: 1 });
    assert_eq!(case.runtime.status().usage.retained, [1, 0, 0]);
    assert_eq!(case.runtime.status().usage.running, [1, 0, 0]);
    assert_eq!(
        case.runtime.begin_start(case.site.credential.clone()).unwrap_err().code(),
        "runtime-not-stopped"
    );
    assert!(matches!(
        runtime::Runtime::inert(&case.site.scratch.0, crate::fixture::scope()),
        Err(runtime::Error::OwnerBusy)
    ));
    assert!(case.runtime.take_result(id).is_none());
    case.stop();
    assert_eq!(case.peer.stopped(), 1);
    assert!(case.runtime.take_result(id).is_none());
}

#[test]
fn b02_generation_is_checked_before_fake_handoff() {
    let mut case = Case::new(single(), true);
    case.reply(ACK);
    let latch = Latch::default();
    case.runtime.before_handoff = Some(latch.hook());
    let id = case.runtime.enqueue(CurrentSensing, KEY, case.deadline()).unwrap();
    case.runtime.dispatch_next().unwrap();
    latch.entered();
    helpers::advance(&case.runtime, &case.site);
    latch.release();
    assert_eq!(case.result(id).unwrap_err().code(), "runtime-stale-generation");
    assert!(case.peer.take_requests().unwrap().is_empty());
    assert_eq!(case.runtime.status().state, State::Held);
    case.stop();
}

#[test]
fn b10_superseded_callback_is_not_delivered() {
    let mut case = Case::new(single(), true);
    case.reply(ACK);
    let latch = Latch::default();
    case.runtime.before_callback = Some(latch.hook());
    let id = case.runtime.enqueue(CurrentSensing, KEY, case.deadline()).unwrap();
    case.runtime.dispatch_next().unwrap();
    latch.entered();
    helpers::advance(&case.runtime, &case.site);
    latch.release();
    assert_eq!(case.result(id).unwrap_err().code(), "runtime-stale-generation");
    assert_eq!(case.peer.take_requests().unwrap().len(), 1);
    assert_eq!(case.peer.stopped(), 1);
    case.stop();
}

#[test]
fn b10_public_client_timeout_is_an_outcome_not_a_retry_policy_claim() {
    let mut case = Case::new(single(), false);
    let raw = case.run(CurrentSensing).unwrap();
    // Pinned client requests.rs:452–463 returns local TSM_TIMEOUT (10), not
    // Error::Timeout. Preserve the raw public-client result, do not relabel it.
    assert_eq!(batch(raw).properties[0].outcome, PropertyOutcome::Abort(10));
    assert_eq!(case.peer.take_requests().unwrap().len(), 1);
    assert_eq!(case.peer.stopped(), 1);
    case.stop();
}
