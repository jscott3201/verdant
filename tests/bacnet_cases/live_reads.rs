use crate::{fixture, helpers::KEY, live_support::*};
use std::time::Instant;

#[test]
fn live_b01_b11_read_variants_and_receipt() {
    // Additional independent Clause 15.5/20 literals: AI:1 presentValue; device:42
    // objectList array count/index; BI:2 boolean presentValue. No encoder imports.
    for (name, property, request, response, value) in [
        ("rp-scalar", pv(), READ, ACK, &[0x21, 7][..]),
        (
            "rp-array-count",
            Property::new(8, 42, 76, Some(0)).unwrap(),
            &[1, 4, 0, 3, 0, 12, 12, 2, 0, 0, 42, 25, 76, 41, 0][..],
            &[1, 0, 48, 0, 12, 12, 2, 0, 0, 42, 25, 76, 41, 0, 62, 33, 2, 63][..],
            &[33, 2][..],
        ),
        (
            "rp-array-element",
            Property::new(8, 42, 76, Some(1)).unwrap(),
            &[1, 4, 0, 3, 0, 12, 12, 2, 0, 0, 42, 25, 76, 41, 1][..],
            &[1, 0, 48, 0, 12, 12, 2, 0, 0, 42, 25, 76, 41, 1, 62, 196, 0, 0, 0, 1, 63][..],
            &[196, 0, 0, 0, 1][..],
        ),
        (
            "rp-false",
            Property::new(3, 2, 85, None).unwrap(),
            &[1, 4, 0, 3, 0, 12, 12, 0, 192, 0, 2, 25, 85][..],
            &[1, 0, 48, 0, 12, 12, 0, 192, 0, 2, 25, 85, 62, 16, 63][..],
            &[16][..],
        ),
    ] {
        let mut c = Case::new(Request::read_property(property), vec![exchange(request, response)]);
        let before = Instant::now();
        let raw = c.run(CurrentSensing).unwrap();
        assert_eq!(batch(&raw).target, c.target);
        assert_eq!(
            batch(&raw).properties,
            [PropertyResult { property, outcome: PropertyOutcome::Value(value.to_vec()) }]
        );
        assert_eq!(raw.binding_key.as_str(), KEY);
        assert_eq!(raw.source.as_str(), "sensor-sat-1");
        assert_eq!((raw.accepted_revision.get(), raw.active_generation.get()), (1, 1));
        assert_eq!(raw.receipt_origin, runtime::ReceiptOrigin::BacnetClientReturn);
        assert!(raw.source_time.is_none());
        assert!(raw.receipt_monotonic >= before && raw.receipt_monotonic <= Instant::now());
        assert_eq!(raw.runtime_incarnation, c.runtime.status().incarnation.unwrap());
        assert_eq!(raw.source_generation, c.runtime.status().source_generation.unwrap());
        c.finish(name);
    }
}

#[test]
fn live_b04_rpm_per_property_and_unsupported_outcomes() {
    let mut c = Case::new(
        Request::read_property_multiple(vec![pv(), status_flags()]).unwrap(),
        vec![exchange(MULTI, MULTI_ACK)],
    );
    let raw = c.run(CurrentSensing).unwrap();
    assert_eq!(
        batch(&raw).properties,
        [
            PropertyResult { property: pv(), outcome: PropertyOutcome::Value(vec![33, 7]) },
            PropertyResult {
                property: status_flags(),
                outcome: PropertyOutcome::RemoteError { class: 2, code: 32 }
            },
        ]
    );
    c.finish("rpm-per-property-error");
    let mut c = Case::new(
        Request::read_property_multiple(vec![pv(), status_flags()]).unwrap(),
        vec![exchange(MULTI, &[1, 0, 0x60, 0, 9])],
    );
    let raw = c.run(CurrentSensing).unwrap();
    assert_eq!(
        batch(&raw).properties,
        [
            PropertyResult { property: pv(), outcome: PropertyOutcome::Reject(9) },
            PropertyResult { property: status_flags(), outcome: PropertyOutcome::Reject(9) },
        ]
    );
    c.finish("rpm-unrecognized-service");
    for (name, response, outcome) in [
        (
            "rp-unknown-property",
            &[1, 0, 0x50, 0, 12, 0x91, 2, 0x91, 32][..],
            PropertyOutcome::RemoteError { class: 2, code: 32 },
        ),
        ("rp-unrecognized-service", &[1, 0, 0x60, 0, 9][..], PropertyOutcome::Reject(9)),
        ("rp-remote-abort", &[1, 0, 0x71, 0, 4][..], PropertyOutcome::Abort(4)),
        (
            "rp-mismatched-property",
            &[1, 0, 48, 0, 12, 12, 0, 0, 0, 1, 25, 111, 62, 33, 7, 63][..],
            PropertyOutcome::InvalidReply,
        ),
    ] {
        let mut c = Case::new(Request::read_property(pv()), vec![exchange(READ, response)]);
        assert_eq!(batch(&c.run(CurrentSensing).unwrap()).properties[0].outcome, outcome);
        c.finish(name);
    }
}

#[test]
fn live_b02_b09_destination_service_and_attempted_calls_emit_nothing() {
    for destination in [true, false] {
        let mut c = Case::custom("realm-a", vec![], |target| {
            Profile::new(
                fixture::scope(),
                vec![plan(target.clone(), Request::read_property(pv()), "mstp://ahu-1")],
                if destination { vec![] } else { vec![target] },
                if destination { vec![Service::ReadProperty] } else { vec![] },
            )
            .unwrap()
        });
        assert_eq!(
            c.runtime.enqueue(CurrentSensing, KEY, c.deadline()).unwrap_err().code(),
            if destination { "bacnet-destination-denied" } else { "bacnet-service-denied" }
        );
        assert!(c.wire.packets().is_empty());
        c.finish(if destination { "denied-destination" } else { "denied-service" });
    }
    let c = Case::new(Request::read_property(pv()), vec![]);
    let bound = plan(c.target.clone(), Request::read_property(pv()), "mstp://ahu-1");
    // Attempt at the final private transport gate, not a new public raw-call API.
    // WriteProperty(15), WPM(16), DCC(17), Reinitialize(20), COV(5/28), file(7),
    // global WhoIs, network routing and BVLC management never reach a socket send.
    let mut forbidden: Vec<_> = [15, 16, 17, 20, 5, 28, 7].iter().map(|s| vec![1, 4, 0, 3, 0, *s]).collect();
    forbidden.extend([
        vec![1, 0, 16, 8],
        vec![1, 0x24, 0, 3, 0, 12],
        vec![0x81, 5, 0, 6, 0, 1],
        vec![0x81, 1, 0, 4],
    ]);
    c.driver.block_on(c.wire.refuse_calls(&bound, &forbidden));
    c.finish("forbidden-attempts");
    for source in
        [include_str!("../../src/runtime/bacnet/client.rs"), include_str!("../../src/runtime/bacnet/mod.rs")]
    {
        let source =
            source.lines().filter(|line| !line.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        for call in [
            ".write_property(",
            ".write_property_multiple(",
            ".device_communication_control(",
            ".reinitialize_device(",
            ".register_foreign_device(",
            ".write_bdt(",
            ".read_bdt(",
            ".delete_foreign_device(",
            ".send_broadcast(",
            ".who_is(",
            ".confirmed_request(",
            "Deref",
            "pub fn client(",
            "pub fn transport(",
        ] {
            assert!(!source.contains(call), "forbidden acquisition surface {call}");
        }
    }
}

#[test]
fn live_b03_discovery_realms_conflicts_and_commissioned_freeze() {
    let mut live = Vec::new();
    for realm in ["realm-a", "realm-b"] {
        let mut replies = vec![IAM.to_vec()];
        if realm == "realm-a" {
            // Independently specified conflict: same device:42, maxAPDU=480,
            // no segmentation, different vendor 8 rather than 7.
            replies.push(vec![1, 0, 16, 0, 196, 2, 0, 0, 42, 34, 1, 224, 145, 3, 33, 8]);
        }
        let mut c = Case::custom(realm, vec![(WHO.to_vec(), replies)], |target| {
            profile(target, Request::directed_discovery(42).unwrap())
        });
        let raw = c.run(OptionalDiscovery).unwrap();
        let RawOutcome::Quarantined(ads) = &raw.outcome else { panic!("discovery refused") };
        assert_eq!(ads[0].instance, 42);
        assert_eq!(ads[0].target.realm().as_str(), realm);
        assert_eq!((ads[0].max_apdu, ads[0].segmentation, ads[0].vendor), (480, 3, 7));
        assert_eq!(c.runtime.candidates(Instant::now()).unwrap()[0].conflicted(), realm == "realm-a");
        live.push(raw);
        c.finish(&format!("directed-discovery-{realm}"));
    }
    // Synthetic accepted binding -> explicit frozen direct mapping, NOT a real
    // commissioned BACnet installation. Both pre-advert and post-advert admission
    // go through Runtime::enqueue/dispatch and the same immutable plan snapshot.
    let mut c = Case::new(Request::read_property(pv()), vec![exchange(READ, ACK), exchange(READ, ACK)]);
    let queued = c.runtime.enqueue(CurrentSensing, KEY, c.deadline()).unwrap();
    for raw in &live {
        c.runtime.retain_live_fixture(raw).unwrap();
    }
    let mut synthetic = live[0].clone();
    let RawOutcome::Quarantined(ads) = &mut synthetic.outcome else { unreachable!() };
    ads.truncate(1);
    ads[0].vendor = 99;
    c.runtime.retain_live_fixture(&synthetic).unwrap();
    let candidates = c.runtime.candidates(Instant::now()).unwrap();
    assert_eq!(candidates.len(), 2, "same instance across two realms stays distinct");
    assert_eq!(candidates[0].advertisements.len(), 3);
    assert!(candidates[0].conflicted() && !candidates[1].conflicted());
    assert_eq!(c.runtime.dispatch_next().unwrap(), Some(queued));
    assert_eq!(batch(&c.result(queued).unwrap()).target, c.target);
    assert_eq!(batch(&c.run(CurrentSensing).unwrap()).target, c.target);
    let expired = c.runtime.candidates(Instant::now() + CANDIDATE_TTL).unwrap();
    assert!(expired.iter().all(|candidate| candidate.expired));
    assert!(expired[0].conflicted());
    c.finish("frozen-before-after-live-and-synthetic-adverts");

    // Explicit attempt to promote a discovered endpoint into the selected binding
    // is refused at admission; no retargeted packet or silent acceptance update.
    let RawOutcome::Quarantined(advertisements) = &live[0].outcome else { unreachable!() };
    let [a, b, c, d, hi, lo] = *advertisements[0].target.mac();
    let advertised_endpoint = format!("bacnet-ip://{a}.{b}.{c}.{d}:{}", u16::from_be_bytes([hi, lo]));
    let mut denied = Case::custom("realm-a", vec![], |target| {
        Profile::new(
            fixture::scope(),
            vec![plan(target.clone(), Request::read_property(pv()), &advertised_endpoint)],
            vec![target],
            vec![Service::ReadProperty],
        )
        .unwrap()
    });
    denied.runtime.retain_live_fixture(&live[0]).unwrap();
    assert_eq!(
        denied.runtime.enqueue(CurrentSensing, KEY, denied.deadline()).unwrap_err().code(),
        "bacnet-binding-mismatch"
    );
    denied.finish("advertised-binding-promotion-refused");
}
