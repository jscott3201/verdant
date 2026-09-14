use crate::{bacnet_support, domain, fixture, observation::*, observation_support::*, runtime};
use domain::{ids::SourceGenerationId, values::Value};
use identity::ProducerId;
use index::SyntheticReceiver;
use normalize::{Codec, Refusal, Suitability, TransportResult, UnitProvenance};
use runtime::bacnet::{PropertyOutcome, PropertyResult};
use time::{Freshness, ObservationTimes};

#[test]
fn raw_batch_reference_keeps_independent_property_error_and_conflict_content() {
    let mut h = Harness::new();
    let mut raw = h.raw.clone();
    let runtime::RawOutcome::Bacnet(batch) = &mut raw.outcome else {
        panic!("batch");
    };
    batch.properties.push(PropertyResult {
        property: bacnet_support::status_flags(),
        outcome: PropertyOutcome::RemoteError { class: 2, code: 32 },
    });
    let pending = h.pending(&raw, &h.context, Codec::Scalar, unit(), 1000);
    let record = h
        .receiver
        .emit(&h.gate, Some(&h.credentials.reviewer), &mut h.producer, pending)
        .unwrap();
    assert_eq!(record.decoded().value, Value::Integer(0));
    assert_eq!(record.raw().outcome, raw.outcome);
    let error_context = BindingContext::synthetic(&h.config, &raw, bacnet_support::status_flags()).unwrap();
    let pending = h.pending(&raw, &error_context, Codec::Scalar, unit(), 1000);
    let error = h
        .receiver
        .emit(&h.gate, Some(&h.credentials.reviewer), &mut h.producer, pending)
        .unwrap();
    assert_eq!(
        error.decoded().transport,
        TransportResult::RemoteError { class: 2, code: 32 }
    );
    assert_eq!(
        error.decoded().suitability,
        Suitability::Refused(Refusal::Transport)
    );
    // Altering an unselected property's evidence also conflicts with the same ID.
    let runtime::RawOutcome::Bacnet(batch) = &mut raw.outcome else {
        panic!("batch");
    };
    batch.properties[1].outcome = PropertyOutcome::Timeout;
    let altered = h
        .pending(&raw, &h.context, Codec::Scalar, unit(), 1000)
        .identify(record.id().clone(), record.incarnation().clone())
        .unwrap();
    assert_eq!(
        h.receiver
            .reconcile(
                &h.gate,
                Some(&h.credentials.reviewer),
                &fixture::scope(),
                &altered
            )
            .unwrap_err()
            .code(),
        "conflict"
    );
}

#[test]
fn raw_joins_and_duplicate_property_are_refused_before_identity_allocation() {
    let h = Harness::new();
    let inputs = || Normalization {
        units: unit(),
        codec: Codec::Scalar,
        receipt_mark: mark(1000),
        ingestion: clock(1000),
    };
    let mut duplicate = h.raw.clone();
    let runtime::RawOutcome::Bacnet(batch) = &mut duplicate.outcome else {
        panic!("batch");
    };
    batch.properties.push(batch.properties[0].clone());
    assert_eq!(
        PendingObservation::from_bacnet(&duplicate, h.context.clone(), inputs(), policy())
            .unwrap_err()
            .code(),
        "invalid-input"
    );
    let mut missing = h.raw.clone();
    let runtime::RawOutcome::Bacnet(batch) = &mut missing.outcome else {
        panic!("batch");
    };
    batch.properties[0].property = bacnet_support::status_flags();
    assert_eq!(
        PendingObservation::from_bacnet(&missing, h.context.clone(), inputs(), policy())
            .unwrap_err()
            .code(),
        "invalid-input"
    );
    let mut wrong_source = h.raw.clone();
    wrong_source.source = domain::ids::InstalledId::parse("vav-101").unwrap();
    assert_eq!(
        PendingObservation::from_bacnet(&wrong_source, h.context.clone(), inputs(), policy())
            .unwrap_err()
            .code(),
        "invalid-input"
    );
    let mut inert = h.raw.clone();
    inert.outcome = runtime::RawOutcome::NotAttemptedInert;
    assert_eq!(
        PendingObservation::from_bacnet(&inert, h.context.clone(), inputs(), policy())
            .unwrap_err()
            .code(),
        "invalid-input"
    );
    assert_eq!(h.producer.checkpoint().next_sequence(), 0);
}

#[test]
fn known_but_wrong_unit_refuses_without_value_or_raw_loss() {
    let mut h = Harness::new();
    let pending = h.pending(
        &h.raw,
        &h.context,
        Codec::Scalar,
        UnitProvenance::BacnetEngineeringUnits(53),
        1000,
    );
    let record = h
        .receiver
        .emit(&h.gate, Some(&h.credentials.reviewer), &mut h.producer, pending)
        .unwrap();
    assert_eq!(record.decoded().unit.as_str(), "Pa");
    assert_eq!(record.decoded().value, Value::Integer(0));
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
    assert_eq!(current.dependent_value().unwrap_err().code(), "wrong-unit");
}

#[test]
fn late_same_binding_data_is_history_and_image_rebuild_keeps_current() {
    let mut h = Harness::new();
    let latest = h.emit(&[0x21, 9], 1010);
    let late = h.emit(&[0x21, 1], 1000);
    h.receiver = SyntheticReceiver::reopen(h.receiver.into_image());
    assert_eq!(
        h.receiver
            .current(
                &h.gate,
                Some(&h.credentials.reviewer),
                &fixture::scope(),
                &key(),
                &clock(1011)
            )
            .unwrap()
            .unwrap()
            .observation
            .id(),
        latest.id()
    );
    assert_eq!(
        h.receiver
            .read(
                &h.gate,
                Some(&h.credentials.reviewer),
                &fixture::scope(),
                late.id()
            )
            .unwrap(),
        Some(&late)
    );
}

#[test]
fn ambiguous_wall_order_is_preserved_without_inventing_source_time() {
    let mut h = Harness::new();
    for source in [None, Some(wall(1200))] {
        let mut raw = h.raw.clone();
        raw.source_time = source;
        let pending = h.pending(&raw, &h.context, Codec::Scalar, unit(), 999);
        let record = h
            .receiver
            .emit(&h.gate, Some(&h.credentials.reviewer), &mut h.producer, pending)
            .unwrap();
        assert!(matches!(
            record.time().times,
            ObservationTimes::WallAmbiguous { .. }
        ));
        assert_eq!(record.raw().source_time, source);
        assert_eq!(
            record.time().times.source().map(|s| s.as_millis()),
            source.map(|_| 1200)
        );
        assert_eq!(record.freshness_at_ingestion(), Freshness::Unknown);
    }
    let evidence = time::TimeEvidence::new(
        None,
        std::time::UNIX_EPOCH - std::time::Duration::from_nanos(1),
        runtime::ReceiptOrigin::BacnetClientReturn,
        mark(0),
        clock(0),
    )
    .unwrap();
    assert_eq!(evidence.times.receipt().as_millis(), -1);
    assert_eq!(evidence.times.source(), None);
}

#[test]
fn fixture_capacity_refuses_without_eviction_or_position_advance() {
    let h = Harness::new();
    let mut receiver =
        SyntheticReceiver::new(SourceGenerationId::parse("capacity-receiver").unwrap(), 1).unwrap();
    let mut producer = receiver
        .start(
            &h.gate,
            Some(&h.credentials.reviewer),
            fixture::scope(),
            ProducerId::parse("bounded").unwrap(),
            incarnation("one"),
        )
        .unwrap();
    let pending = h.pending(&h.raw, &h.context, Codec::Scalar, unit(), 1000);
    let record = receiver
        .emit(
            &h.gate,
            Some(&h.credentials.reviewer),
            &mut producer,
            pending.clone(),
        )
        .unwrap();
    let checkpoint = producer.checkpoint();
    assert_eq!(
        receiver
            .emit(&h.gate, Some(&h.credentials.reviewer), &mut producer, pending)
            .unwrap_err()
            .code(),
        "invalid-input"
    );
    assert_eq!(producer.checkpoint(), checkpoint);
    assert_eq!(
        receiver
            .read(
                &h.gate,
                Some(&h.credentials.reviewer),
                &fixture::scope(),
                record.id()
            )
            .unwrap(),
        Some(&record)
    );
}
