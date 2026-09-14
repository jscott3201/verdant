use crate::{
    bacnet_support::*,
    runtime::{admission, admission::WorkClass::*, bacnet::*},
};

#[test]
fn b09_only_read_and_directed_discovery_bytes_reach_fake_port() {
    for (request, service, reply, expected, choice, class) in [
        (Request::read_property(pv()), Service::ReadProperty, ACK, READ, 12, CurrentSensing),
        (
            Request::read_property_multiple(vec![pv(), status_flags()]).unwrap(),
            Service::ReadPropertyMultiple,
            MULTI_ACK,
            MULTI,
            14,
            CurrentSensing,
        ),
        (Request::directed_discovery(42).unwrap(), Service::DirectedWhoIs, IAM, WHO, 8, OptionalDiscovery),
    ] {
        let mut case = Case::new(profile(request, vec![target("realm-a", 2)], vec![service]), false);
        case.reply(reply);
        case.run(class).unwrap();
        let encoded = case.peer.take_requests().unwrap();
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0].npdu, expected);
        assert_eq!(encoded[0].destination, [127, 0, 0, 2, 186, 192]);
        let service_offset = if encoded[0].npdu[2] == 16 { 3 } else { 5 };
        assert_eq!(encoded[0].npdu[service_offset], choice);
        case.stop();
    }
    // Supplemental source guard, not a substitute for the above encoded requests
    // or Rust privacy: the client tuple is private and has no extraction/Deref.
    let source = include_str!("../../src/runtime/bacnet/client.rs");
    for forbidden_call in [
        ".write_",
        ".who_is(",
        ".who_has(",
        ".confirmed_request(",
        ".unconfirmed_request(",
        ".subscribe_cov(",
        ".reinitialize_",
        ".create_object(",
        ".delete_object(",
        ".atomic_",
    ] {
        assert!(!source.contains(forbidden_call), "forbidden acquisition call: {forbidden_call}");
    }
    let model = include_str!("../../src/runtime/bacnet/model.rs");
    assert!(model.contains("pub struct Request(Operation)"));
    assert!(source.contains("struct ReadClient(BACnetClient<FakePort>)"));
}

#[test]
fn b12_parent_source_case_evidence_manifest_is_complete_with_live_deferral() {
    let contract = include_str!("../../src/runtime/bacnet/CONTRACT.md");
    let cases =
        [include_str!("reads.rs"), include_str!("lifecycle.rs"), include_str!("manifest.rs")].join("\n");
    for number in 1..=12 {
        assert!(contract.contains(&format!("| B{number:02} |")));
        assert!(cases.contains(&format!("fn b{number:02}_")));
    }
    for path in [
        "tests/runtime_cases/cases.rs",
        "src/runtime/mod.rs",
        "src/runtime/bacnet/client.rs",
        "tests/bacnet_cases/support.rs",
    ] {
        assert!(contract.contains(path));
        assert!(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path).is_file());
    }
    assert!(contract.contains("Live loopback peer tests: DEFERRED"));
    assert!(contract.contains("zero-retry wire semantics: UNVERIFIED"));
    assert_eq!((APDU_TIMEOUT_MS, APDU_RETRIES), (6000, 0));
    assert_eq!(admission::QUEUE_SLOTS, [2, 2, 60]);
    assert_eq!(admission::RUNNING_SLOTS, [1, 1, 2]);
    assert!(TEST_TIMEOUT < admission::MAX_LIFETIME);
    assert_eq!(
        admission::BACNET_FAKE_PAYLOAD_BYTES,
        (fake::MAX_SCRIPTS * fake::MAX_REPLIES + fake::MAX_CAPTURED + 4 * fake::MAX_REPLIES) * MAX_NPDU_BYTES
    );
}
