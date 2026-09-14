use crate::{
    accept, access, bacnet_support, binding, domain, fixture, observation::*, observation_support::*, runtime,
};
use domain::{
    clock::{BootId, MonotonicMark},
    ids::SourceGenerationId,
    scope::TrustedScope,
    values::{Decimal, Unit, Value},
};
use identity::ProducerId;
use index::{Reconciliation, SyntheticReceiver};
use normalize::{Codec, Refusal, Suitability, TransportResult, UnitProvenance, ValueQuality};
use time::{Continuity, Freshness, ObservationTimes};

#[test]
fn c01_zero_false_exact_numbers_and_absent_source_survive_actual_tag_boundary() {
    let mut h = Harness::new();
    // Independent literals: application Boolean false, Unsigned 0, signed -1,
    // 8-byte Unsigned 2^53+1 (not rounded via f64), and REAL 21.5.
    for (bytes, expected) in [
        (&[0x10][..], Value::Bool(false)),
        (&[0x21, 0], Value::Integer(0)),
        (&[0x31, 255], Value::Integer(-1)),
        (
            &[0x25, 8, 0, 32, 0, 0, 0, 0, 0, 1],
            Value::Integer(9_007_199_254_740_993),
        ),
        (
            &[0x44, 0x41, 0xac, 0, 0],
            Value::Decimal(Decimal::parse("21.5").unwrap()),
        ),
    ] {
        let record = h.emit(bytes, 1000);
        assert_eq!(record.decoded().value, expected);
        assert!(matches!(
            record.time().times,
            ObservationTimes::SourceAbsent { .. }
        ));
        assert_eq!(record.time().times.source(), None);
        assert_eq!(record.raw().source_time, None);
        assert_eq!(record.decoded().transport, TransportResult::ValueReturned);
        assert_eq!(record.binding().key(), &key());
    }
    // CharacterString charset 0 + exact lexical "21.50", explicit codec only.
    let raw = bytes(&[0x75, 6, 0, b'2', b'1', b'.', b'5', b'0'], 1000);
    let pending = h.pending(&raw, &h.context, Codec::ExactDecimalText, unit(), 1000);
    let record = h
        .receiver
        .emit(&h.gate, Some(&h.credentials.reviewer), &mut h.producer, pending)
        .unwrap();
    assert_eq!(
        record.decoded().value.to_json(),
        "{\"type\":\"decimal\",\"value\":\"21.50\"}"
    );
    let mut sourced = raw.clone();
    sourced.source_time = Some(wall(990));
    let pending = h.pending(&sourced, &h.context, Codec::ExactDecimalText, unit(), 1000);
    let record = h
        .receiver
        .emit(&h.gate, Some(&h.credentials.reviewer), &mut h.producer, pending)
        .unwrap();
    assert!(matches!(record.time().times, ObservationTimes::SourcePresent(_)));
    assert_eq!(record.time().times.source().unwrap().as_millis(), 990);
    assert_eq!(
        record.time().receipt_origin,
        runtime::ReceiptOrigin::BacnetClientReturn
    );
}

#[test]
fn c02_invalid_nonfinite_unknown_units_retain_evidence_and_refuse_use() {
    let mut h = Harness::new();
    for (payload, quality, refusal) in [
        (&[0x44, 0][..], ValueQuality::Invalid, Refusal::Invalid),
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
    ] {
        let record = h.emit(payload, 1000);
        assert_eq!(record.decoded().quality, quality);
        assert_eq!(record.decoded().suitability, Suitability::Refused(refusal));
        assert_eq!(refusal.code(), "invalid-value");
        assert!(matches!(record.decoded().value, Value::Diagnostic(_)));
        let runtime::RawOutcome::Bacnet(batch) = &record.raw().outcome else {
            panic!("raw");
        };
        assert_eq!(
            batch.properties[0].outcome,
            runtime::bacnet::PropertyOutcome::Value(payload.into())
        );
        let current = h
            .receiver
            .current(
                &h.gate,
                Some(&h.credentials.reviewer),
                &fixture::scope(),
                &key(),
                &clock(1000),
            )
            .unwrap()
            .unwrap();
        assert_eq!(current.freshness, Freshness::Fresh); // transport/quality != freshness
        assert_eq!(current.dependent_value().unwrap_err(), refusal);
    }
    let pending = h.pending(
        &h.raw,
        &h.context,
        Codec::Scalar,
        UnitProvenance::SyntheticBinding(Unit::Unknown("DEGC".into())),
        1000,
    );
    let record = h
        .receiver
        .emit(&h.gate, Some(&h.credentials.reviewer), &mut h.producer, pending)
        .unwrap();
    assert_eq!(record.decoded().unit, Unit::Unknown("DEGC".into()));
    assert_eq!(record.decoded().value, Value::Integer(0));
    assert_eq!(record.decoded().quality, ValueQuality::Valid);
    assert_eq!(
        record.decoded().suitability,
        Suitability::Refused(Refusal::UnknownUnit)
    );
    assert_eq!(Refusal::UnknownUnit.code(), "invalid-input");
}

#[test]
fn c03_new_equal_samples_have_distinct_stable_positions() {
    let mut h = Harness::new();
    let a = h.emit(&[0x10], 1000);
    let b = h.emit(&[0x10], 1000);
    assert_eq!(a.raw(), b.raw());
    assert_eq!(a.decoded(), b.decoded());
    assert_ne!(a.id(), b.id());
    assert_eq!(a.id().position().seq(), 0);
    assert_eq!(b.id().position().seq(), 1);
    assert_eq!(a.id().position().generation(), b.id().position().generation());
    assert_eq!(
        h.receiver
            .history(&h.gate, Some(&h.credentials.reviewer), &fixture::scope(), &key())
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn c04_same_identity_same_complete_content_reconciles_without_new_sample() {
    let mut h = Harness::new();
    let a = h.emit(&[0x21, 0], 1000);
    let checkpoint = h.producer.checkpoint();
    assert_eq!(
        h.receiver
            .reconcile(
                &h.gate,
                Some(&h.credentials.reviewer),
                &fixture::scope(),
                &a.clone()
            )
            .unwrap(),
        Reconciliation::SameContent
    );
    assert_eq!(h.producer.checkpoint(), checkpoint);
    assert_eq!(
        h.receiver
            .history(&h.gate, Some(&h.credentials.reviewer), &fixture::scope(), &key())
            .unwrap()
            .len(),
        1
    );
    let current = h
        .receiver
        .current(
            &h.gate,
            Some(&h.credentials.reviewer),
            &fixture::scope(),
            &key(),
            &clock(1001),
        )
        .unwrap()
        .unwrap();
    assert_eq!(current.observation.id(), a.id());
}

#[test]
fn c05_same_identity_different_content_conflicts_without_overwrite() {
    let mut h = Harness::new();
    let a = h.emit(&[0x21, 0], 1000);
    for raw in [bytes(&[0x21, 1], 1000), bytes(&[0x21, 0], 1001)] {
        let pending = h.pending(&raw, &h.context, Codec::Scalar, unit(), 1001);
        let conflict = pending.identify(a.id().clone(), a.incarnation().clone()).unwrap();
        assert_eq!(
            h.receiver
                .reconcile(
                    &h.gate,
                    Some(&h.credentials.reviewer),
                    &fixture::scope(),
                    &conflict
                )
                .unwrap_err()
                .code(),
            "conflict"
        );
    }
    assert_eq!(
        h.receiver
            .read(&h.gate, Some(&h.credentials.reviewer), &fixture::scope(), a.id())
            .unwrap(),
        Some(&a)
    );
}

#[test]
fn c06_old_binding_revision_and_generation_remain_historical() {
    let mut h = Harness::new();
    let old = h.emit(&[0x21, 1], 1000);
    h.registry
        .record_equipment(
            "vav-101",
            binding::EquipmentKind::Vav,
            fixture::scope(),
            "VAV",
            "mstp://vav-101",
        )
        .unwrap();
    let changed = config(&h.gate, &mut h.registry, fixture::scope());
    assert_ne!(changed.binding_revision(), h.config.binding_revision());
    let mut raw = bytes(&[0x21, 2], 1010);
    raw.accepted_revision = accept::AcceptedRevision::new(h.raw.accepted_revision.get() + 1).unwrap();
    raw.active_generation = accept::ActiveGeneration::new(h.raw.active_generation.get() + 1).unwrap();
    let selected = BindingContext::synthetic(&changed, &raw, bacnet_support::pv()).unwrap();
    h.receiver
        .select_binding(
            &h.gate,
            Some(&h.credentials.reviewer),
            Some(&h.context),
            selected.clone(),
        )
        .unwrap();
    assert!(h
        .receiver
        .current(
            &h.gate,
            Some(&h.credentials.reviewer),
            &fixture::scope(),
            &key(),
            &clock(1010)
        )
        .unwrap()
        .is_none());
    let pending = h.pending(&raw, &selected, Codec::Scalar, unit(), 1010);
    let latest = h
        .receiver
        .emit(&h.gate, Some(&h.credentials.reviewer), &mut h.producer, pending)
        .unwrap();
    // Same active/accepted generation but old binding revision: still historical.
    let old_revision = BindingContext::synthetic(&h.config, &raw, bacnet_support::pv()).unwrap();
    let pending = h.pending(&raw, &old_revision, Codec::Scalar, unit(), 1010);
    h.receiver
        .emit(&h.gate, Some(&h.credentials.reviewer), &mut h.producer, pending)
        .unwrap();
    // Old activation arrives later by receipt time. It must not win either.
    h.emit(&[0x21, 3], 1020);
    let current = h
        .receiver
        .current(
            &h.gate,
            Some(&h.credentials.reviewer),
            &fixture::scope(),
            &key(),
            &clock(1020),
        )
        .unwrap()
        .unwrap();
    assert_eq!(current.observation.id(), latest.id());
    assert_eq!(
        h.receiver
            .read(
                &h.gate,
                Some(&h.credentials.reviewer),
                &fixture::scope(),
                old.id()
            )
            .unwrap(),
        Some(&old)
    );
    assert_eq!(
        h.receiver
            .history(&h.gate, Some(&h.credentials.reviewer), &fixture::scope(), &key())
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        h.receiver
            .select_binding(
                &h.gate,
                Some(&h.credentials.reviewer),
                Some(&selected),
                h.context.clone()
            )
            .unwrap_err()
            .code(),
        "conflict"
    );
}

#[test]
fn c07_intact_receiver_readback_preserves_identity_and_proven_position() {
    let mut h = Harness::new();
    let a = h.emit(&[0x21, 1], 1000);
    let checkpoint = h.producer.checkpoint();
    h.receiver = SyntheticReceiver::reopen(h.receiver.into_image());
    assert_eq!(
        h.receiver
            .read(&h.gate, Some(&h.credentials.reviewer), &fixture::scope(), a.id())
            .unwrap(),
        Some(&a)
    );
    h.producer = h
        .receiver
        .resume(
            &h.gate,
            Some(&h.credentials.reviewer),
            checkpoint.clone(),
            incarnation("process-b"),
        )
        .unwrap();
    assert_eq!(h.producer.checkpoint(), checkpoint);
    let b = h.emit(&[0x21, 1], 1001);
    assert_eq!(a.id().position().generation(), b.id().position().generation());
    assert_eq!(b.id().position().seq(), 1);
    assert_ne!(a.incarnation(), b.incarnation());
    assert_eq!(
        h.receiver
            .reconcile(&h.gate, Some(&h.credentials.reviewer), &fixture::scope(), &a)
            .unwrap(),
        Reconciliation::SameContent
    );
}

#[test]
fn c08_rollback_ambiguity_mints_generation_before_emission_and_fences_old_owner() {
    let mut h = Harness::new();
    let restored = h.producer.checkpoint(); // older counter image
    let a = h.emit(&[0x21, 7], 1000);
    let mut resumed = h
        .receiver
        .resume(
            &h.gate,
            Some(&h.credentials.reviewer),
            restored.clone(),
            incarnation("after-rollback"),
        )
        .unwrap();
    assert_ne!(resumed.checkpoint().generation(), restored.generation());
    assert_eq!(resumed.checkpoint().next_sequence(), 0);
    let pending = h.pending(&h.raw, &h.context, Codec::Scalar, unit(), 1000);
    assert_eq!(
        h.receiver
            .emit(
                &h.gate,
                Some(&h.credentials.reviewer),
                &mut h.producer,
                pending.clone()
            )
            .unwrap_err()
            .code(),
        "conflict"
    );
    let b = h
        .receiver
        .emit(&h.gate, Some(&h.credentials.reviewer), &mut resumed, pending)
        .unwrap();
    assert_eq!(a.id().position().seq(), b.id().position().seq());
    assert_ne!(a.id(), b.id());
    assert_eq!(
        h.receiver
            .reconcile(&h.gate, Some(&h.credentials.reviewer), &fixture::scope(), &a)
            .unwrap(),
        Reconciliation::SameContent
    );
    let mut lost =
        SyntheticReceiver::new(SourceGenerationId::parse("new-independent-receiver").unwrap(), 4).unwrap();
    assert_eq!(
        lost.resume(
            &h.gate,
            Some(&h.credentials.reviewer),
            restored,
            incarnation("unproved")
        )
        .unwrap_err()
        .code(),
        "conflict"
    );
}

#[test]
fn c09_wall_suspend_boot_and_replay_cannot_refresh_stale_data() {
    let mut h = Harness::new();
    let a = h.emit(&[0x21, 7], 1000);
    for now in [clock(1100), clock(1001)] {
        // age == horizon is stale; clock rollback cannot undo it
        let current = h
            .receiver
            .current(
                &h.gate,
                Some(&h.credentials.reviewer),
                &fixture::scope(),
                &key(),
                &now,
            )
            .unwrap()
            .unwrap();
        assert_eq!(current.freshness, Freshness::Stale);
        assert_eq!(current.dependent_value().unwrap_err(), Refusal::NotFresh);
    }
    h.receiver
        .reconcile(&h.gate, Some(&h.credentials.reviewer), &fixture::scope(), &a)
        .unwrap();
    h.receiver = SyntheticReceiver::reopen(h.receiver.into_image());
    assert_eq!(
        h.receiver
            .current(
                &h.gate,
                Some(&h.credentials.reviewer),
                &fixture::scope(),
                &key(),
                &clock(1000)
            )
            .unwrap()
            .unwrap()
            .freshness,
        Freshness::Stale
    );
    let mut suspended = clock(1200);
    suspended.continuity = Continuity::WallOrSuspendAmbiguous;
    let mut other_boot = clock(1200);
    other_boot.monotonic = MonotonicMark::new(BootId::parse("other-boot").unwrap(), 1_200_000_000);
    let mut wall_jump = clock(1200);
    wall_jump.wall = wall(1500);
    let mut backwards = clock(1200);
    backwards.monotonic = mark(1199);
    for now in [suspended, other_boot, wall_jump, backwards] {
        // Each newly emitted record is fresh only before observing ambiguity.
        h.emit(&[0x21, 7], 1200);
        assert_eq!(
            h.receiver
                .current(
                    &h.gate,
                    Some(&h.credentials.reviewer),
                    &fixture::scope(),
                    &key(),
                    &now
                )
                .unwrap()
                .unwrap()
                .freshness,
            Freshness::Unknown
        );
        assert_eq!(
            h.receiver
                .current(
                    &h.gate,
                    Some(&h.credentials.reviewer),
                    &fixture::scope(),
                    &key(),
                    &clock(1200)
                )
                .unwrap()
                .unwrap()
                .freshness,
            Freshness::Unknown
        );
    }
    let evidence = a.time();
    let mut now = clock(1001);
    now.monotonic = MonotonicMark::new(BootId::parse("other-boot").unwrap(), 1_001_000_000);
    assert_eq!(policy().assess(evidence, &now), Freshness::Unknown);
    now = clock(1001);
    now.wall = wall(999);
    assert_eq!(policy().assess(evidence, &now), Freshness::Unknown);
    now.wall = wall(1500); // suspend/wall advance with stalled monotonic mark
    assert_eq!(policy().assess(evidence, &now), Freshness::Unknown);
    let mut raw = bytes(&[0x21, 7], 1200);
    raw.source_time = Some(wall(1000));
    let pending = h.pending(&raw, &h.context, Codec::Scalar, unit(), 1200);
    let backfill = h
        .receiver
        .emit(&h.gate, Some(&h.credentials.reviewer), &mut h.producer, pending)
        .unwrap();
    assert_eq!(backfill.freshness_at_ingestion(), Freshness::Stale);
}

#[test]
fn c10_scope_predicates_and_current_review_gate_prevent_cross_disclosure() {
    let mut h = Harness::new();
    let a = h.emit(&[0x21, 1], 1000);
    let b_scope = TrustedScope::parse("scope-b").unwrap();
    let credential = h
        .gate
        .issue(
            &access::CapabilityName::parse("b-reviewer").unwrap(),
            &b_scope,
            1,
            access::RoleKind::Reviewer,
            &access::KeyId::parse("b-key").unwrap(),
            &access::SyntheticKey::parse("synthetic-b-key").unwrap(),
            &h.credentials.publisher,
            &access::Reason::parse("synthetic scope B").unwrap(),
            &access::DisplayLabel::parse("synthetic B").unwrap(),
        )
        .unwrap();
    let b_config = config(&h.gate, &mut h.registry, b_scope.clone());
    let mut b_raw = bytes(&[0x21, 2], 1000);
    b_raw.scope = b_scope.clone();
    let b_context = BindingContext::synthetic(&b_config, &b_raw, bacnet_support::pv()).unwrap();
    h.receiver
        .select_binding(&h.gate, Some(&credential), None, b_context.clone())
        .unwrap();
    let mut producer = h
        .receiver
        .start(
            &h.gate,
            Some(&credential),
            b_scope.clone(),
            ProducerId::parse("sensor-sat-producer").unwrap(),
            incarnation("b-process"),
        )
        .unwrap();
    let pending = h.pending(&b_raw, &b_context, Codec::Scalar, unit(), 1000);
    let b = h
        .receiver
        .emit(&h.gate, Some(&credential), &mut producer, pending)
        .unwrap();
    for (scope, cred, own, other) in [
        (&fixture::scope(), &h.credentials.reviewer, &a, &b),
        (&b_scope, &credential, &b, &a),
    ] {
        assert_eq!(
            h.receiver.history(&h.gate, Some(cred), scope, &key()).unwrap(),
            vec![own]
        );
        assert!(h
            .receiver
            .read(&h.gate, Some(cred), scope, other.id())
            .unwrap()
            .is_none());
        assert_eq!(
            h.receiver
                .current(&h.gate, Some(cred), scope, &key(), &clock(1000))
                .unwrap()
                .unwrap()
                .observation
                .id(),
            own.id()
        );
        assert_eq!(
            h.receiver
                .reconcile(&h.gate, Some(cred), scope, other)
                .unwrap_err()
                .code(),
            "conflict"
        );
    }
    assert_eq!(
        h.receiver
            .read(&h.gate, Some(&h.credentials.reviewer), &b_scope, b.id())
            .unwrap_err()
            .code(),
        "scope-denied"
    );
    assert_eq!(
        h.receiver
            .read(&h.gate, None, &fixture::scope(), a.id())
            .unwrap_err()
            .code(),
        "anonymous-denied"
    );
    h.gate
        .revoke(
            &h.credentials.reviewer,
            &access::Reason::parse("synthetic revoke").unwrap(),
        )
        .unwrap();
    assert_eq!(
        h.receiver
            .read(&h.gate, Some(&h.credentials.reviewer), &fixture::scope(), a.id())
            .unwrap_err()
            .code(),
        "revoked-credential"
    );
}
