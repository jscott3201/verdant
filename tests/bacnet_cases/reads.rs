use crate::{
    bacnet_support::*,
    helpers,
    runtime::{self, admission::WorkClass::*, bacnet::*},
};
use std::time::Instant;

#[test]
fn b01_allowed_direct_read_and_independent_bytes() {
    let mut case = Case::new(single(), false);
    case.reply(ACK);
    let raw = case.run(CurrentSensing).unwrap();
    assert_eq!(raw.binding_key.as_str(), helpers::KEY);
    assert_eq!(raw.source.as_str(), "sensor-sat-1");
    assert_eq!(raw.accepted_revision.get(), 1);
    assert_eq!(raw.active_generation.get(), 1);
    let result = batch(raw);
    assert_eq!(result.target, target("realm-a", 2));
    assert_eq!(
        result.properties,
        vec![PropertyResult { property: pv(), outcome: PropertyOutcome::Value(vec![33, 7]) }]
    );
    assert_eq!(
        case.peer.take_requests().unwrap(),
        vec![fake::EncodedRequest { destination: [127, 0, 0, 2, 186, 192], npdu: READ.to_vec() }]
    );
    assert_eq!(case.peer.stopped(), 1);
    assert_eq!(case.runtime.status().network_calls, 0);
    case.stop();
}

#[test]
fn b02_allowlist_denials_emit_nothing() {
    for (destinations, services, expected) in [
        (vec![], vec![Service::ReadProperty], "bacnet-destination-denied"),
        (vec![target("realm-a", 2)], vec![], "bacnet-service-denied"),
    ] {
        let mut case = Case::new(profile(Request::read_property(pv()), destinations, services), false);
        case.reply(ACK);
        assert_eq!(
            case.runtime.enqueue(CurrentSensing, helpers::KEY, case.deadline()).unwrap_err().code(),
            expected
        );
        assert!(case.peer.take_requests().unwrap().is_empty());
        assert_eq!(case.peer.stopping(), 0);
        assert_eq!(case.runtime.status().usage.retained, [0; 3]);
        case.stop();
    }
    assert_eq!(DirectTarget::parse("realm-a", "bacnet-route://1/2").unwrap_err().code(), "bacnet-invalid");
    for endpoint in [
        "bacnet-ip://0.0.0.0:47808",
        "bacnet-ip://255.255.255.255:47808",
        "bacnet-ip://224.0.0.1:47808",
        "bacnet-ip://localhost:47808",
    ] {
        assert!(DirectTarget::parse("realm-a", endpoint).is_err());
    }
    assert!(Property::new(0, 1, 8, None).is_err());
    assert!(Request::read_property_multiple(vec![pv(); MAX_PROPERTIES + 1]).is_err());
}

#[test]
fn b03_advertisements_are_quarantined_distinct_and_conflicts_inspectable() {
    let destinations = vec![target("realm-a", 2), target("realm-a", 3), target("realm-b", 2)];
    let plan =
        profile(Request::directed_discovery(42).unwrap(), destinations.clone(), vec![Service::DirectedWhoIs]);
    let mut case = Case::new(plan, false);
    case.peer
        .push(fake::Script::Replies(
            destinations
                .iter()
                .map(|target| fake::Reply { source: target.clone(), npdu: IAM.to_vec() })
                .collect(),
        ))
        .unwrap();
    let raw = case.run(OptionalDiscovery).unwrap();
    assert!(matches!(raw.outcome, runtime::RawOutcome::Quarantined(ref ads) if ads.len() == 3));
    let candidates = case.runtime.candidates(Instant::now()).unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].advertisements.len(), 2);
    assert!(candidates[0].conflicted());
    assert!(!candidates[1].conflicted());
    assert!(candidates.iter().all(|entry| !entry.expired));
    assert_eq!(case.runtime.status().usage.retained, [0, 0, 2]);
    case.reply(IAM);
    case.run(OptionalDiscovery).unwrap();
    assert_eq!(case.runtime.candidates(Instant::now()).unwrap().len(), 2);
    let requests = case.peer.take_requests().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.npdu, WHO);
        assert_eq!(request.destination, [127, 0, 0, 2, 186, 192]);
    }
    let expired = case.runtime.candidates(Instant::now() + CANDIDATE_TTL).unwrap();
    assert!(expired.iter().all(|entry| entry.expired));
    assert!(expired[0].conflicted());
    assert!(!case.runtime.status().observed_qualification);
    case.stop();
}

#[test]
fn b04_multi_read_retains_each_property_error() {
    let request = Request::read_property_multiple(vec![pv(), status_flags()]).unwrap();
    let mut case =
        Case::new(profile(request, vec![target("realm-a", 2)], vec![Service::ReadPropertyMultiple]), false);
    case.reply(MULTI_ACK);
    assert_eq!(
        batch(case.run(CurrentSensing).unwrap()).properties,
        vec![
            PropertyResult { property: pv(), outcome: PropertyOutcome::Value(vec![33, 7]) },
            PropertyResult {
                property: status_flags(),
                outcome: PropertyOutcome::RemoteError { class: 2, code: 32 }
            },
        ]
    );
    assert_eq!(case.peer.take_requests().unwrap()[0].npdu, MULTI);
    case.stop();
}

#[test]
fn b06_oversized_input_refuses_before_upstream_and_value_copy_is_bounded() {
    let mut case = Case::new(single(), false);
    case.peer.push(fake::Script::Oversized { bytes: MAX_NPDU_BYTES + 1 }).unwrap();
    assert_eq!(batch(case.run(CurrentSensing).unwrap()).properties[0].outcome, PropertyOutcome::Oversized);
    // Valid application octet-string of 513 bytes, inside NPDU bound but above
    // Verdant's per-property bound. The literal length is independent of codec.
    let mut oversized = vec![1, 0, 48, 0, 12, 12, 0, 0, 0, 1, 25, 85, 62, 0x65, 0xfe, 2, 1];
    oversized.extend(vec![0; 513]);
    oversized.push(63);
    case.reply(&oversized);
    assert_eq!(batch(case.run(CurrentSensing).unwrap()).properties[0].outcome, PropertyOutcome::Oversized);
    case.stop();
}

#[test]
fn b06_oversized_discovery_is_not_an_empty_success() {
    let mut case = Case::new(
        profile(
            Request::directed_discovery(42).unwrap(),
            vec![target("realm-a", 2)],
            vec![Service::DirectedWhoIs],
        ),
        false,
    );
    case.peer.push(fake::Script::Oversized { bytes: MAX_NPDU_BYTES + 1 }).unwrap();
    assert_eq!(case.run(OptionalDiscovery).unwrap_err().code(), "bacnet-oversized");
    assert!(case.runtime.candidates(Instant::now()).unwrap().is_empty());
    case.stop();
}

#[test]
fn b11_receipt_origin_explicit_source_time_absent() {
    let mut case = Case::new(single(), false);
    case.reply(ACK);
    let before = Instant::now();
    let raw = case.run(CurrentSensing).unwrap();
    assert_eq!(raw.receipt_origin, runtime::ReceiptOrigin::BacnetClientReturn);
    assert!(raw.source_time.is_none());
    assert!(raw.receipt_monotonic >= before && raw.receipt_monotonic <= Instant::now());
    assert_eq!(raw.runtime_incarnation, case.runtime.status().incarnation.unwrap());
    assert_eq!(raw.source_generation, case.runtime.status().source_generation.unwrap());
    case.stop();
}
