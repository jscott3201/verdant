//! Live-derived C01/C03–C06/C10, codec and D01–D04/D06 happy-path evidence.
//! Acquisition is PR36 loopback; selection, units, review authority and clock
//! coordinates remain explicit fixtures. C07/C08/C09, D05, D06 injection, D07,
//! D08, ticket races, D10 and byte-budget exhaustion stay synthetic by design.
use crate::{accept, binding, domain, fixture, helpers, live_support::*, observation::*, support::*};
use domain::{
    scope::TrustedScope,
    values::{Diagnostic, Unit, Value},
};
use normalize::{Codec, Refusal, Suitability, TransportResult, UnitProvenance, ValueQuality};
use std::time::Duration;
use time::Freshness;
use window::Retention;

#[test]
fn loopback_context_is_test_only_and_keeps_selection_guards() {
    let h = Driver::new();
    let raw = samples(1).remove(0);
    let context = h.context(&raw, pv());
    assert_eq!(context, BindingContext::synthetic(&h.config, &raw, pv()).unwrap());
    assert_eq!(
        BindingContext::loopback(&h.config, &raw, status_flags())
            .unwrap_err()
            .code(),
        "invalid-input"
    );
    let mut wrong = raw.clone();
    let RawOutcome::Bacnet(batch) = &mut wrong.outcome else {
        unreachable!()
    };
    // Refused before any I/O; this address is never sent to a peer.
    batch.target = DirectTarget::parse("realm-a", "bacnet-ip://192.0.2.1:47808").unwrap();
    assert_eq!(
        BindingContext::loopback(&h.config, &wrong, pv())
            .unwrap_err()
            .code(),
        "invalid-input"
    );
    assert!(
        BindingContext::synthetic(&h.config, &wrong, pv()).is_ok(),
        "existing constructor unchanged"
    );
    for wrong in [
        RawEnvelope {
            scope: TrustedScope::parse("scope-b").unwrap(),
            ..raw.clone()
        },
        RawEnvelope {
            endpoint: "mstp://vav-101".into(),
            ..raw.clone()
        },
        RawEnvelope {
            receipt_origin: runtime::ReceiptOrigin::InertAdapterReturn,
            ..raw.clone()
        },
        RawEnvelope {
            outcome: RawOutcome::NotAttemptedInert,
            ..raw.clone()
        },
    ] {
        assert_eq!(
            BindingContext::loopback(&h.config, &wrong, pv())
                .unwrap_err()
                .code(),
            "invalid-input"
        );
    }
    let mut wrong = raw.clone();
    wrong.active_generation = accept::ActiveGeneration::new(raw.active_generation.get() + 1).unwrap();
    assert_eq!(
        PendingObservation::from_bacnet(
            &wrong,
            context,
            Normalization {
                codec: Codec::Scalar,
                units: unit(),
                receipt_mark: mark(receipt_ms(&raw)),
                ingestion: clock(receipt_ms(&raw)),
            },
            live_policy()
        )
        .unwrap_err()
        .code(),
        "invalid-input"
    );
}

#[test]
fn c01_live_scalars_law1_and_exact_decimal_text_survive_0003() {
    // Independent application-tag/JSON literals, not encoder-generated expectations.
    let cases: &[(&[u8], &str)] = &[
        (&[0x10], r#"{"type":"bool","value":false}"#),
        (&[0x11], r#"{"type":"bool","value":true}"#),
        (&[0x21, 0], r#"{"type":"integer","value":"0"}"#),
        (&[0x31, 255], r#"{"type":"integer","value":"-1"}"#),
        (
            &[0x25, 8, 0, 32, 0, 0, 0, 0, 0, 1],
            r#"{"type":"integer","value":"9007199254740993"}"#,
        ),
        (
            &[0x25, 8, 255, 255, 255, 255, 255, 255, 255, 255],
            r#"{"type":"integer","value":"18446744073709551615"}"#,
        ),
        (&[0x44, 0x41, 0xac, 0, 0], r#"{"type":"decimal","value":"21.5"}"#),
        (
            &[0x55, 8, 0x80, 0, 0, 0, 0, 0, 0, 0],
            r#"{"type":"decimal","value":"-0.0"}"#,
        ),
    ];
    let raws = acquire(
        Request::read_property(pv()),
        cases.iter().map(|(tags, _)| exchange(READ, &ack(tags))).collect(),
        "pr03-c01-scalars",
    );
    let h = Driver::new();
    let w = h.open(None);
    for (raw, (tags, expected)) in raws.iter().zip(cases) {
        assert_eq!(
            batch(raw).properties[0].outcome,
            PropertyOutcome::Value(tags.to_vec())
        );
        let row = h.append(&w, raw, Retention::OptionalHistory);
        assert_eq!(row.decoded().value.to_json(), *expected);
        assert_eq!(row.decoded().quality, ValueQuality::Valid);
        assert_eq!(row.decoded().transport, TransportResult::ValueReturned);
        assert_eq!(row.decoded().suitability, Suitability::SyntheticValueOnly);
        assert_eq!(row.freshness_at_ingestion(), Freshness::Fresh);
    }
    let tags = &[0x75, 6, 0, b'2', b'1', b'.', b'5', b'0'];
    let raw = acquire(
        Request::read_property(pv()),
        vec![exchange(READ, &ack(tags))],
        "pr03-decimal-text",
    )
    .remove(0);
    for (codec, expected, suitability) in [
        (
            Codec::ExactDecimalText,
            r#"{"type":"decimal","value":"21.50"}"#,
            Suitability::SyntheticValueOnly,
        ),
        (
            Codec::Scalar,
            r#"{"type":"text","value":"21.50"}"#,
            Suitability::Refused(Refusal::Unsupported),
        ),
    ] {
        let row = w
            .identify(h.access(), pending(&raw, &h.context(&raw, pv()), codec, unit()))
            .unwrap();
        assert_eq!(row.decoded().value.to_json(), expected);
        assert_eq!(row.decoded().suitability, suitability);
        h.capture(&w, &row, Retention::OptionalHistory, receipt_ms(&raw));
    }
}

#[test]
fn live_policy_is_12_seconds_250ms_not_the_synthetic_policy() {
    let h = Driver::new();
    let raw = samples(1).remove(0);
    let w = h.open(None);
    let row = h.append(&w, &raw, Retention::OptionalHistory);
    let ms = receipt_ms(&raw);
    assert_eq!(row.time().receipt_mark, mark(ms));
    assert_eq!(
        live_policy().assess(row.time(), &clock(ms + 11_999)),
        Freshness::Fresh
    );
    assert_eq!(
        live_policy().assess(row.time(), &clock(ms + 12_000)),
        Freshness::Stale
    );
    let mut skew = clock(ms + 1000);
    skew.monotonic = mark(ms + 750);
    assert_eq!(live_policy().assess(row.time(), &skew), Freshness::Fresh);
    skew.monotonic = mark(ms + 749);
    assert_eq!(live_policy().assess(row.time(), &skew), Freshness::Unknown);
    assert_eq!(
        crate::observation_support::policy().assess(row.time(), &clock(ms + 100)),
        Freshness::Stale
    );
}

#[test]
fn live_codec_quality_missing_and_unit_provenance_are_not_transport_or_authority() {
    let cases: &[(&[u8], ValueQuality, Refusal)] = &[
        (&[0], ValueQuality::Missing, Refusal::Missing),
        (
            &[0x44, 0x7f, 0x80, 0, 0],
            ValueQuality::NonFinite,
            Refusal::NonFinite,
        ),
        (
            &[0x44, 0xff, 0x80, 0, 0],
            ValueQuality::NonFinite,
            Refusal::NonFinite,
        ),
        (
            &[0x44, 0x7f, 0xc0, 0, 1],
            ValueQuality::NonFinite,
            Refusal::NonFinite,
        ),
        (
            &[0x55, 8, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0],
            ValueQuality::NonFinite,
            Refusal::NonFinite,
        ),
        (&[0x21, 0, 0x21, 1], ValueQuality::Invalid, Refusal::Invalid),
        (&[0x72, 0, 255], ValueQuality::Invalid, Refusal::Invalid),
    ];
    let raws = acquire(
        Request::read_property(pv()),
        cases
            .iter()
            .map(|(tags, _, _)| exchange(READ, &ack(tags)))
            .collect(),
        "pr03-codec-quality",
    );
    let h = Driver::new();
    let w = h.open(None);
    for (raw, (tags, quality, refusal)) in raws.iter().zip(cases) {
        assert_eq!(
            batch(raw).properties[0].outcome,
            PropertyOutcome::Value(tags.to_vec())
        );
        let row = h.append(&w, raw, Retention::OptionalHistory);
        assert_eq!(&row.decoded().quality, quality);
        assert_eq!(row.decoded().suitability, Suitability::Refused(*refusal));
        assert_eq!(row.decoded().transport, TransportResult::ValueReturned);
        assert_eq!(row.freshness_at_ingestion(), Freshness::Fresh);
    }
    for (raw, diagnostic) in raws[1..5].iter().zip([
        Diagnostic::PositiveInfinity,
        Diagnostic::NegativeInfinity,
        Diagnostic::NotANumber,
        Diagnostic::PositiveInfinity,
    ]) {
        assert_eq!(h.row(&w, raw).decoded().value, Value::Diagnostic(diagnostic));
    }
    let raw = samples(1).remove(0);
    // Supplied unit provenance on live value bytes: no unit inference from tags
    // and no claim these fixture tokens were observed engineering-units reads.
    for (units, label, suitability) in [
        (
            UnitProvenance::BacnetEngineeringUnits(62),
            "degC",
            Suitability::SyntheticValueOnly,
        ),
        (
            UnitProvenance::BacnetEngineeringUnits(98),
            "percent",
            Suitability::Refused(Refusal::WrongUnit),
        ),
        (
            UnitProvenance::BacnetEngineeringUnits(53),
            "Pa",
            Suitability::Refused(Refusal::WrongUnit),
        ),
        (
            UnitProvenance::BacnetEngineeringUnits(87),
            "L/s",
            Suitability::Refused(Refusal::WrongUnit),
        ),
        (
            UnitProvenance::BacnetEngineeringUnits(999),
            "bacnet-unit:999",
            Suitability::Refused(Refusal::UnknownUnit),
        ),
        (
            UnitProvenance::Absent,
            "unit-not-supplied",
            Suitability::Refused(Refusal::UnknownUnit),
        ),
    ] {
        let row = w
            .identify(
                h.access(),
                pending(&raw, &h.context(&raw, pv()), Codec::Scalar, units.clone()),
            )
            .unwrap();
        assert_eq!(row.decoded().unit, Unit::parse(label).unwrap());
        assert_eq!(row.decoded().unit_provenance, units);
        assert_eq!(row.decoded().suitability, suitability);
        assert_eq!(row.decoded().value, Value::Integer(7));
        h.capture(&w, &row, Retention::OptionalHistory, receipt_ms(&raw));
    }
}

#[test]
fn live_array_count_element_and_rpm_errors_keep_selected_property_and_full_batch() {
    let h = Driver::new();
    let w = h.open(None);
    for (index, request, response, tags) in [
        (
            0,
            &[1, 4, 0, 3, 0, 12, 12, 2, 0, 0, 42, 25, 76, 41, 0][..],
            &[1, 0, 48, 0, 12, 12, 2, 0, 0, 42, 25, 76, 41, 0, 62, 33, 2, 63][..],
            &[33, 2][..],
        ),
        (
            1,
            &[1, 4, 0, 3, 0, 12, 12, 2, 0, 0, 42, 25, 76, 41, 1][..],
            &[
                1, 0, 48, 0, 12, 12, 2, 0, 0, 42, 25, 76, 41, 1, 62, 196, 0, 0, 0, 1, 63,
            ][..],
            &[196, 0, 0, 0, 1][..],
        ),
    ] {
        let property = Property::new(8, 42, 76, Some(index)).unwrap();
        let raw = acquire(
            Request::read_property(property),
            vec![exchange(request, response)],
            "pr03-array",
        )
        .remove(0);
        assert_eq!(
            batch(&raw).properties,
            [PropertyResult {
                property,
                outcome: PropertyOutcome::Value(tags.to_vec())
            }]
        );
        let row = w
            .identify(
                h.access(),
                pending(&raw, &h.context(&raw, property), Codec::Scalar, unit()),
            )
            .unwrap();
        if index == 0 {
            assert_eq!(row.decoded().value, Value::Integer(2));
            assert_eq!(row.decoded().suitability, Suitability::SyntheticValueOnly);
        } else {
            assert!(matches!(row.decoded().quality, ValueQuality::Unknown { .. }));
            assert_eq!(
                row.decoded().suitability,
                Suitability::Refused(Refusal::Unsupported)
            );
        }
        h.capture(&w, &row, Retention::OptionalHistory, receipt_ms(&raw));
    }
    let raw = acquire(
        Request::read_property_multiple(vec![pv(), status_flags()]).unwrap(),
        vec![exchange(MULTI, MULTI_ACK)],
        "pr03-rpm-error",
    )
    .remove(0);
    assert_eq!(
        batch(&raw).properties,
        [
            PropertyResult {
                property: pv(),
                outcome: PropertyOutcome::Value(vec![33, 7])
            },
            PropertyResult {
                property: status_flags(),
                outcome: PropertyOutcome::RemoteError { class: 2, code: 32 }
            },
        ]
    );
    for (property, transport, value) in [
        (pv(), TransportResult::ValueReturned, Value::Integer(7)),
        (
            status_flags(),
            TransportResult::RemoteError { class: 2, code: 32 },
            Value::Missing,
        ),
    ] {
        let row = w
            .identify(
                h.access(),
                pending(&raw, &h.context(&raw, property), Codec::Scalar, unit()),
            )
            .unwrap();
        assert_eq!(
            row.raw().outcome,
            raw.outcome,
            "retain the other property's failure too"
        );
        assert_eq!(row.decoded().transport, transport);
        assert_eq!(row.decoded().value, value);
        if property == status_flags() {
            assert_eq!(
                row.decoded().suitability,
                Suitability::Refused(Refusal::Transport)
            );
        }
        h.capture(&w, &row, Retention::OptionalHistory, receipt_ms(&raw));
    }
}

#[test]
fn live_transport_failures_and_no_response_keep_pr36_local_abort_10() {
    let h = Driver::new();
    let w = h.open(None);
    for (response, outcome, transport) in [
        (
            &[1, 0, 0x50, 0, 12, 0x91, 2, 0x91, 32][..],
            PropertyOutcome::RemoteError { class: 2, code: 32 },
            TransportResult::RemoteError { class: 2, code: 32 },
        ),
        (
            &[1, 0, 0x60, 0, 9][..],
            PropertyOutcome::Reject(9),
            TransportResult::Reject(9),
        ),
        (
            &[1, 0, 0x71, 0, 4][..],
            PropertyOutcome::Abort(4),
            TransportResult::Abort(4),
        ),
        (
            &[1, 0, 48, 0, 12, 12, 0, 0, 0, 1, 25, 111, 62, 33, 7, 63][..],
            PropertyOutcome::InvalidReply,
            TransportResult::InvalidReply,
        ),
    ] {
        let raw = acquire(
            Request::read_property(pv()),
            vec![exchange(READ, response)],
            "pr03-transport",
        )
        .remove(0);
        assert_eq!(batch(&raw).properties[0].outcome, outcome);
        let row = h.append(&w, &raw, Retention::OptionalHistory);
        assert_eq!(row.decoded().transport, transport);
        assert_eq!(row.decoded().value, Value::Missing);
        assert_eq!(row.decoded().quality, ValueQuality::Missing);
        assert_eq!(
            row.decoded().suitability,
            Suitability::Refused(Refusal::Transport)
        );
    }
    assert_eq!((APDU_TIMEOUT_MS, APDU_RETRIES), (6000, 0));
    for (request, bytes) in [
        (Request::read_property(pv()), READ),
        (
            Request::read_property_multiple(vec![pv(), status_flags()]).unwrap(),
            MULTI,
        ),
    ] {
        let mut c = Case::new(request, vec![(bytes.to_vec(), vec![])]);
        let raw = c.run(CurrentSensing).unwrap();
        assert_eq!(c.wire.requests(), [bytes]);
        assert_eq!(
            c.wire.packets().len(),
            2,
            "one sent/received request, no response or resend"
        );
        c.finish("pr03-local-tsm-expiry");
        for property in &batch(&raw).properties {
            // Local pinned TSM expiry, NOT a peer Abort and NOT PropertyOutcome::Timeout.
            assert_eq!(property.outcome, PropertyOutcome::Abort(10));
            let row = w
                .identify(
                    h.access(),
                    pending(&raw, &h.context(&raw, property.property), Codec::Scalar, unit()),
                )
                .unwrap();
            assert_eq!(row.decoded().transport, TransportResult::Abort(10));
            assert_eq!(row.decoded().value, Value::Missing);
            assert_eq!(
                row.decoded().suitability,
                Suitability::Refused(Refusal::Transport)
            );
            h.capture(&w, &row, Retention::OptionalHistory, receipt_ms(&raw));
        }
    }
}

#[test]
fn live_value_and_npdu_limits_preserve_oversized_not_a_normalized_value() {
    let h = Driver::new();
    let w = h.open(None);
    for size in [512usize, 513, 1010, 1011] {
        // Independent extended OctetString tag: encoded value includes 4-byte header.
        let len = size - 4;
        let mut tags = vec![0x65, 0xfe, (len >> 8) as u8, len as u8];
        tags.resize(size, 0);
        let response = ack(&tags);
        assert_eq!(response.len(), size + 14);
        let mut c = Case::new(Request::read_property(pv()), vec![exchange(READ, &response)]);
        let raw = c.run(CurrentSensing).unwrap();
        assert_eq!(c.wire.oversized(), usize::from(size == 1011));
        c.finish("pr03-size-boundary");
        let row = h.append(&w, &raw, Retention::OptionalHistory);
        if size == 512 {
            assert_eq!(batch(&raw).properties[0].outcome, PropertyOutcome::Value(tags));
            assert_eq!(row.decoded().transport, TransportResult::ValueReturned);
            assert!(matches!(row.decoded().quality, ValueQuality::Unknown { .. }));
            assert_eq!(
                row.decoded().suitability,
                Suitability::Refused(Refusal::Unsupported)
            );
        } else {
            assert_eq!(batch(&raw).properties[0].outcome, PropertyOutcome::Oversized);
            assert_eq!(row.decoded().transport, TransportResult::Oversized);
            assert_eq!(row.decoded().value, Value::Missing);
            assert_eq!(
                row.decoded().suitability,
                Suitability::Refused(Refusal::Transport)
            );
        }
    }
}

#[test]
fn c03_c04_c05_d06_live_identity_equal_conflicting_and_saved_receipt_happy_paths() {
    let raws = acquire(
        Request::read_property(pv()),
        vec![
            exchange(READ, ACK),
            exchange(READ, ACK),
            exchange(READ, &ack(&[33, 8])),
        ],
        "pr03-identities",
    );
    assert_ne!(
        raws[0].work, raws[1].work,
        "two real acquisitions, not a cloned sample"
    );
    let h = Driver::new();
    let w = h.open(None);
    w.select_binding(h.access(), &h.context(&raws[0], pv())).unwrap();
    let a = h.row(&w, &raws[0]);
    let ticket = h.capture(&w, &a, Retention::OptionalHistory, receipt_ms(&raws[0]));
    let before = w.checkpoint(h.access()).unwrap();
    w.reconcile_observation(h.access(), &a.clone()).unwrap();
    committed(w.reconcile_capture(h.access(), &ticket).unwrap());
    committed(
        w.submit_capture(h.access(), &ticket, &clock(receipt_ms(&raws[0]) + 1))
            .unwrap(),
    );
    assert_eq!(w.checkpoint(h.access()).unwrap(), before);
    for raw in &raws[1..] {
        let conflict = pending(raw, &h.context(raw, pv()), Codec::Scalar, unit())
            .identify(a.id().clone(), a.incarnation().clone())
            .unwrap();
        assert_eq!(
            w.reconcile_observation(h.access(), &conflict).unwrap_err().code(),
            "identity-conflict"
        );
        h.assert_stored(&w, &a);
        assert_eq!(w.checkpoint(h.access()).unwrap(), before);
    }
    let b = h.append(&w, &raws[1], Retention::OptionalHistory);
    assert_eq!(a.decoded(), b.decoded());
    assert_ne!(a.id(), b.id());
    assert_eq!((a.id().position().seq(), b.id().position().seq()), (0, 1));
    assert_eq!(a.id().position().generation(), b.id().position().generation());
    assert_eq!(w.current(h.access(), &key()).unwrap().unwrap().id, *b.id());
    let saved = ticket.reconciliation_bytes().to_string();
    let checkpoint = w.checkpoint(h.access()).unwrap();
    drop((ticket, w));
    let w = h.open(Some(&checkpoint));
    committed(w.reconcile_saved_capture(h.access(), &saved).unwrap());
    assert_eq!(w.checkpoint(h.access()).unwrap(), checkpoint);
    assert_eq!(w.replay(h.access(), 0, 64).unwrap().records.len(), 2);
    h.assert_stored(&w, &a);
    h.assert_stored(&w, &b);
}

#[test]
fn c06_live_old_binding_activation_and_late_rows_remain_historical() {
    // Use existing accepted/activated fixture APIs so no raw generation or times
    // are rewritten. Only the meaning selection remains an explicit test input.
    let site = helpers::site(true, true);
    let mut c = Case::new(Request::read_property(pv()), vec![exchange(READ, ACK); 4]);
    assert_eq!(c.runtime.stop(Duration::ZERO).unwrap(), runtime::Drain::Stopped);
    c.runtime = runtime::Runtime::inert(&site.scratch.0, fixture::scope()).unwrap();
    c.runtime
        .configure_live_reads(
            profile(c.target.clone(), Request::read_property(pv())),
            c.wire.clone(),
        )
        .unwrap();
    c.runtime.begin_start(site.credential.clone()).unwrap();
    c.wait(|r, _| r.status().state != runtime::State::Starting);
    let old = c.run(CurrentSensing).unwrap();
    let old_later = c.run(CurrentSensing).unwrap();
    helpers::advance(&c.runtime, &site);
    assert_eq!(c.runtime.stop(Duration::ZERO).unwrap(), runtime::Drain::Stopped);
    c.runtime.begin_start(site.credential.clone()).unwrap();
    c.wait(|r, _| r.status().state != runtime::State::Starting);
    let late = c.run(CurrentSensing).unwrap();
    let newest = c.run(CurrentSensing).unwrap();
    assert_eq!((old.accepted_revision.get(), old.active_generation.get()), (1, 1));
    assert_eq!(
        (newest.accepted_revision.get(), newest.active_generation.get()),
        (2, 2)
    );
    assert_ne!(old.runtime_incarnation, newest.runtime_incarnation);
    assert_ne!(old.source_generation, newest.source_generation);
    c.finish("pr03-old-and-new-activation");
    let mut h = Driver::new();
    let w = h.open(None);
    let old_context = h.context(&old, pv());
    w.select_binding(h.access(), &old_context).unwrap();
    let first = h.append(&w, &old, Retention::OptionalHistory);
    let old_config = h.config.clone();
    h.registry
        .record_equipment(
            "vav-101",
            binding::EquipmentKind::Vav,
            fixture::scope(),
            "VAV",
            "mstp://vav-101",
        )
        .unwrap();
    h.config = crate::observation_support::config(&h.gate, &mut h.registry, fixture::scope());
    assert_ne!(h.config.binding_revision(), old_config.binding_revision());
    w.select_binding(h.access(), &h.context(&newest, pv())).unwrap();
    assert!(w.current(h.access(), &key()).unwrap().is_none());
    let current = h.append(&w, &newest, Retention::OptionalHistory);
    h.append(&w, &late, Retention::OptionalHistory); // Delayed delivery, unchanged live receipt.
    let context = BindingContext::loopback(&old_config, &newest, pv()).unwrap();
    let old_revision = w
        .identify(h.access(), pending(&newest, &context, Codec::Scalar, unit()))
        .unwrap();
    h.capture(&w, &old_revision, Retention::OptionalHistory, receipt_ms(&newest));
    let context = BindingContext::loopback(&old_config, &old_later, pv()).unwrap();
    let historical = w
        .identify(h.access(), pending(&old_later, &context, Codec::Scalar, unit()))
        .unwrap();
    h.capture(&w, &historical, Retention::OptionalHistory, receipt_ms(&newest));
    assert_eq!(w.current(h.access(), &key()).unwrap().unwrap().id, *current.id());
    assert_eq!(
        w.select_binding(h.access(), &old_context).unwrap_err().code(),
        "old-binding-selection"
    );
    let checkpoint = w.checkpoint(h.access()).unwrap();
    drop(w);
    let w = h.open(Some(&checkpoint));
    assert_eq!(w.current(h.access(), &key()).unwrap().unwrap().id, *current.id());
    assert_eq!(w.replay(h.access(), 0, 64).unwrap().records.len(), 5);
    for row in [first, old_revision, historical] {
        h.assert_stored(&w, &row);
    }
}
