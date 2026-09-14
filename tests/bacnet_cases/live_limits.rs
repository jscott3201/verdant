use crate::{helpers::KEY, live_support::*};
use std::time::{Duration, Instant};

#[test]
fn live_b05_queued_deadline_and_cancellation_are_capture_empty() {
    let mut c = Case::new(Request::read_property(pv()), vec![]);
    let deadline = Instant::now() + Duration::from_secs(1); // Fixture queue margin only.
    let expired = c.runtime.enqueue(CurrentSensing, KEY, deadline).unwrap();
    c.driver.block_on(async { tokio::time::sleep_until(deadline.into()).await });
    assert_eq!(c.runtime.dispatch_next().unwrap(), Some(expired));
    assert_eq!(c.result(expired).unwrap_err().code(), "runtime-deadline");
    let canceled = c.runtime.enqueue(CurrentSensing, KEY, c.deadline()).unwrap();
    c.runtime.cancel(canceled).unwrap();
    assert_eq!(c.result(canceled).unwrap_err().code(), "runtime-cancelled");
    assert!(c.wire.packets().is_empty());
    c.finish("queued-expired-canceled");
}

fn octets(value_bytes: usize) -> Vec<u8> {
    // Independent extended-length application OctetString inside RP-ACK [3].
    // Verdant bounds encoded property bytes, INCLUDING this four-byte tag/length.
    let len = value_bytes - 4;
    let mut out = vec![1, 0, 48, 0, 12, 12, 0, 0, 0, 1, 25, 85, 62, 0x65, 0xfe, (len >> 8) as u8, len as u8];
    out.resize(out.len() + len, 0);
    out.push(63);
    out
}
#[test]
fn live_b06_value_npdu_and_retained_envelope_bounds() {
    for (name, size, oversized_npdu) in [
        ("value-512", 512, false),
        ("value-513", 513, false),
        ("npdu-1024", 1010, false),
        ("npdu-1025", 1011, true),
    ] {
        let response = octets(size);
        assert_eq!(response.len(), size + 14);
        let mut c = Case::new(Request::read_property(pv()), vec![exchange(READ, &response)]);
        let mut raw = c.run(CurrentSensing).unwrap();
        assert_eq!(c.wire.oversized(), usize::from(oversized_npdu), "pre-client NPDU gate");
        if size == 512 {
            assert_eq!(
                batch(&raw).properties[0].outcome,
                PropertyOutcome::Value(response[13..response.len() - 1].to_vec())
            );
            // Live-derived raw-envelope retention boundary, NOT a 65536-byte UDP
            // packet or a claim that the <=8*512 read profile can emit that size.
            let b = batch(&raw);
            let overhead = std::mem::size_of::<RawEnvelope>()
                + raw.endpoint.capacity()
                + raw.property.capacity()
                + raw.scope.as_str().len()
                + raw.binding_key.as_str().len()
                + raw.source.as_str().len()
                + b.target.realm().as_str().len()
                + b.properties.capacity() * std::mem::size_of::<PropertyResult>();
            let RawOutcome::Bacnet(b) = &mut raw.outcome else { unreachable!() };
            b.properties[0].outcome = PropertyOutcome::Value(vec![0; 65536 - overhead]);
            assert!(live_fixture::envelope_bound(&raw).is_ok());
            let RawOutcome::Bacnet(b) = &mut raw.outcome else { unreachable!() };
            b.properties[0].outcome = PropertyOutcome::Value(vec![0; 65537 - overhead]);
            assert_eq!(live_fixture::envelope_bound(&raw), Err(Error::Oversized));
        } else {
            assert_eq!(batch(&raw).properties[0].outcome, PropertyOutcome::Oversized);
        }
        c.finish(name);
    }
}

#[test]
fn live_b07_shared_exhaustion_preserves_mandatory_reserve() {
    let mut c = Case::new(Request::read_property(pv()), vec![exchange(READ, ACK), exchange(READ, ACK)]);
    for _ in 0..60 {
        c.runtime.enqueue(OptionalDiscovery, KEY, c.deadline()).unwrap();
    }
    assert!(matches!(
        c.runtime.enqueue(OptionalDiscovery, KEY, c.deadline()),
        Err(runtime::Error::Saturated { class: OptionalDiscovery, running: false })
    ));
    let mut mandatory = Vec::new();
    let mut extra = Vec::new();
    for class in [CurrentSensing, Reconciliation] {
        mandatory.push(c.runtime.enqueue(class, KEY, c.deadline()).unwrap());
        extra.push(c.runtime.enqueue(class, KEY, c.deadline()).unwrap());
        assert!(matches!(
            c.runtime.enqueue(class, KEY, c.deadline()),
            Err(runtime::Error::Saturated { running: false, .. })
        ));
    }
    assert_eq!(c.runtime.status().usage.retained, [2, 2, 60]);
    assert!(c.wire.packets().is_empty());
    for id in extra {
        c.runtime.cancel(id).unwrap();
        assert_eq!(c.result(id).unwrap_err().code(), "runtime-cancelled");
    }
    for id in mandatory {
        assert_eq!(c.runtime.dispatch_next().unwrap(), Some(id), "mandatory work precedes optional queue");
        assert_eq!(batch(&c.result(id).unwrap()).properties[0].outcome, PropertyOutcome::Value(vec![33, 7]));
    }
    assert_eq!(c.runtime.status().usage.retained, [0, 0, 60]);
    c.finish("shared-exhaustion-mandatory-reads");

    let mut c = Case::new(Request::directed_discovery(42).unwrap(), vec![exchange(WHO, IAM)]);
    let first = c.runtime.enqueue(OptionalDiscovery, KEY, c.deadline()).unwrap();
    for _ in 1..60 {
        c.runtime.enqueue(OptionalDiscovery, KEY, c.deadline()).unwrap();
    }
    assert_eq!(c.runtime.dispatch_next().unwrap(), Some(first));
    assert_eq!(c.result(first).unwrap_err().code(), "bacnet-shared-budget");
    assert!(c.runtime.candidates(Instant::now()).unwrap().is_empty());
    assert_eq!(c.runtime.status().usage.retained, [0, 0, 59]);
    c.finish("live-quarantine-shares-budget");
}

#[test]
fn live_b08_startup_missed_poll_no_burst_or_false_samples() {
    let mut c = Case::new(
        Request::read_property(pv()),
        vec![exchange(READ, ACK), exchange(READ, &[1, 0, 0x60, 0, 9])],
    );
    let start = Instant::now();
    let mut timer = poll::PollSchedule::new(start, Duration::from_secs(1)).unwrap();
    for now in [start, start + Duration::from_millis(999)] {
        assert_eq!(timer.due(now).unwrap(), None);
        assert!(c.wire.packets().is_empty());
    }
    // Explicit scheduler events, not wall-clock/suspend qualification or a new ticker.
    let stalled = start + Duration::from_secs(10);
    assert_eq!(timer.due(stalled).unwrap(), Some(poll::Due { missed: 9 }));
    let current = c.run(CurrentSensing).unwrap();
    assert_eq!(batch(&current).properties[0].outcome, PropertyOutcome::Value(vec![33, 7]));
    for _ in 0..100 {
        assert_eq!(timer.due(stalled).unwrap(), None);
    }
    assert_eq!(c.wire.requests(), [READ]);
    assert_eq!(timer.due(stalled + Duration::from_secs(1)).unwrap(), Some(poll::Due { missed: 0 }));
    let failed = c.run(CurrentSensing).unwrap();
    assert_eq!(batch(&failed).properties[0].outcome, PropertyOutcome::Reject(9));
    assert_ne!(failed.work, current.work);
    assert!(current.source_time.is_none() && failed.source_time.is_none());
    assert_eq!(c.wire.requests().len(), 2, "only two attempts, not eleven invented samples");
    c.finish("poll-startup-stall-no-burst");
}

#[test]
fn live_b10_zero_retry_rp_and_rpm_timeout_and_cancel() {
    assert_eq!((APDU_TIMEOUT_MS, APDU_RETRIES), (6000, 0));
    for (name, request, bytes) in [
        ("rp-timeout", Request::read_property(pv()), READ),
        ("rpm-timeout", Request::read_property_multiple(vec![pv(), status_flags()]).unwrap(), MULTI),
    ] {
        let mut c = Case::new(request, vec![(bytes.to_vec(), vec![])]);
        let raw = c.run(CurrentSensing).unwrap();
        // The real pinned TSM expiry is awaited, not canceled early or converted
        // to success by sleep. Abort(10) is LOCAL, no peer Abort was received.
        assert!(batch(&raw).properties.iter().all(|p| p.outcome == PropertyOutcome::Abort(10)));
        assert_eq!(c.wire.requests(), [bytes]);
        assert_eq!(c.wire.packets().len(), 2, "one sent datagram + one peer receive, no reply/resend");
        c.finish(name);
    }
    let mut c = Case::new(Request::read_property(pv()), vec![(READ.to_vec(), vec![])]);
    let id = c.runtime.enqueue(CurrentSensing, KEY, c.deadline()).unwrap();
    c.runtime.dispatch_next().unwrap();
    c.wait(|_, wire| wire.requests().len() == 1);
    c.runtime.cancel(id).unwrap();
    assert_eq!(c.result(id).unwrap_err().code(), "runtime-cancelled");
    c.finish("rp-canceled-after-emission");
}
