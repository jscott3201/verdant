//! M02-PR05 human action preview, SYNTHETIC-ONLY. No dispatch, no field authority.
#![allow(dead_code)]

#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "../src/storage/mod.rs"]
mod storage;
#[path = "../src/access/mod.rs"]
mod access;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "../src/seal/mod.rs"]
mod seal;
#[path = "../src/accept/mod.rs"]
mod accept;
#[path = "../src/api/mod.rs"]
mod api;
#[path = "../src/binding/mod.rs"]
mod binding;
#[path = "../src/runtime/mod.rs"]
mod runtime;
#[path = "../src/observation/mod.rs"]
mod observation;
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "../src/action_preview/mod.rs"]
mod action_preview;

use access::RoleKind;
use action_preview::{
    AcceptedTarget, AliasSet, EncodedSetpoint, FeedbackPlan, Precondition, Preview, PreviewError,
    Priority, ReleasePlan, SealOrder, TargetObject, Timing,
};
use binding::{BindingStatus, Finding};
use domain::clock::{BootId, MonotonicMark};
use domain::ids::{BindingRevision, InstalledId};
use domain::scope::TrustedScope;
use domain::values::Unit;
use observation::normalize::{Refusal, Suitability};
use observation::time::{ClockReading, Continuity, Freshness, FreshnessPolicy, TimeEvidence};
use std::time::Duration;

fn scope_a() -> TrustedScope {
    TrustedScope::parse("scope-a").expect("frozen scope-a")
}

fn equipment(raw: &str) -> InstalledId {
    InstalledId::parse(raw).expect("frozen equipment")
}

fn binding_rev(value: u32) -> BindingRevision {
    BindingRevision::new(value)
}

fn accepted_rev(value: u32) -> accept::AcceptedRevision {
    accept::AcceptedRevision::new(value).expect("accepted revision")
}

fn unit(raw: &str) -> Unit {
    Unit::parse(raw).expect("unit parses")
}

fn precondition_fresh() -> Precondition {
    // Observed 60s ago; horizon is 300s.
    Precondition::new(
        action_preview::synthetic_time(1_700_000_000_000),
        action_preview::synthetic_time(1_700_000_060_000),
    )
    .expect("fresh precondition")
}

fn seal_ready() -> SealOrder {
    let mut order = SealOrder::new();
    order.check_custody().expect("custody");
    order.decode().expect("decode");
    order.reconstruct().expect("reconstruct");
    order
}

fn permitted() -> Preview {
    Preview::preview(
        scope_a(),
        equipment("ahu-1"),
        binding_rev(7),
        accepted_rev(1),
        BindingStatus::Valid,
        2,
        RoleKind::Publisher,
        Some(8),
        2,
        85,
        None,
        unit("degC"),
        22.0,
        None,
        &["ahu-1-sp"],
        precondition_fresh(),
        &seal_ready(),
        equipment("ahu-1"),
        false,
    )
    .expect("permitted preview")
}

#[test]
fn permitted_human_proposal_is_revision_bound_information() {
    let preview = permitted();
    // Independent literal, never encoder output.
    assert_eq!(
        preview.canonical_bytes(),
        "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish"
    );
    assert_eq!(preview.format(), "verdant-preview-v1");
    assert_eq!(preview.target().scope().as_str(), "scope-a");
    assert_eq!(preview.target().equipment().as_str(), "ahu-1");
    assert_eq!(preview.target().binding_revision().as_u32(), 7);
    assert_eq!(preview.target().accepted_revision().get(), 1);
    assert_eq!(preview.priority().get(), 8);
    assert_eq!(preview.object().object_type(), 2);
    assert_eq!(preview.object().property_id(), 85);
    assert_eq!(preview.object().array_index(), None);
    assert_eq!(preview.unit().as_str(), "degC");
    assert_eq!(preview.encoded().wire_c(), 22.0);
    assert_eq!(
        preview.encoded().mask_note(),
        "priority-8-masks-9-16-masked-by-1-7"
    );
    assert_eq!(preview.timing().duration_secs(), 900);
    assert_eq!(preview.timing().deadline_secs(), 5);
    assert_eq!(preview.timing().apdu_retries(), 0);
    assert_eq!(
        preview.timing().apdu_retries(),
        runtime::bacnet::APDU_RETRIES
    );
    assert_eq!(preview.precondition_age_secs(), 60);
    assert_eq!(preview.feedback().property(), "presentValue");
    assert_eq!(preview.feedback().status(), "unavailable-feedback");
    assert_eq!(preview.feedback().source_time(), None);
    assert!(preview.array().observes_not_owns());
    assert!(!preview.array().is_ownership());
    assert_eq!(preview.array().capability(), "supervisory");
    assert_eq!(preview.release().on_expiry(), "null-relinquish");
    assert!(preview.release().survives_replacement());
    assert!(preview.release().survives_revocation());
    assert!(preview.release().survives_offboarding());
    assert_eq!(preview.release().timeout_policy(), "uncertain-not-resend");
    assert!(!preview.release().allows_resend_after_timeout());
    // Revision-bound information, not a reservation and not dispatch.
    assert!(!preview.is_reservation());
    assert!(!preview.is_dispatch());
    assert!(!preview.is_qualified());
    preview
        .target()
        .require_current(binding_rev(7), accepted_rev(1))
        .expect("current");
}

#[test]
fn assistance_ceiling_refusal() {
    let err = Preview::preview(
        scope_a(),
        equipment("ahu-1"),
        binding_rev(7),
        accepted_rev(1),
        BindingStatus::Valid,
        1,
        RoleKind::Reviewer,
        Some(8),
        2,
        85,
        None,
        unit("degC"),
        22.0,
        None,
        &["ahu-1-sp"],
        precondition_fresh(),
        &seal_ready(),
        equipment("ahu-1"),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "ceiling-exceeded");
    // Publisher role with a reviewer-grade ceiling also refuses.
    let err = Preview::preview(
        scope_a(),
        equipment("ahu-1"),
        binding_rev(7),
        accepted_rev(1),
        BindingStatus::Valid,
        1,
        RoleKind::Publisher,
        Some(8),
        2,
        85,
        None,
        unit("degC"),
        22.0,
        None,
        &["ahu-1-sp"],
        precondition_fresh(),
        &seal_ready(),
        equipment("ahu-1"),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "ceiling-exceeded");
}

#[test]
fn protected_unallocated_and_empty_slot_refusal() {
    // Protected priorities 1-3 are reserved.
    for priority in [1u8, 2, 3] {
        let err = Priority::new(priority)
            .expect("range")
            .check_commissioned()
            .unwrap_err();
        assert_eq!(err.code(), "preview-protected-priority");
    }
    // Commissioned allocation is exactly 8; other slots are unallocated here.
    for priority in [4u8, 7, 9, 16] {
        let err = Priority::new(priority)
            .expect("range")
            .check_commissioned()
            .unwrap_err();
        assert_eq!(err.code(), "preview-unallocated-priority");
    }
    // No empty-slot selection.
    let err = Priority::from_option(None).unwrap_err();
    assert_eq!(err.code(), "preview-invalid");
    // Top-level preview surfaces the same allocation refusals.
    let err = Preview::preview(
        scope_a(),
        equipment("ahu-1"),
        binding_rev(7),
        accepted_rev(1),
        BindingStatus::Valid,
        2,
        RoleKind::Publisher,
        Some(2),
        2,
        85,
        None,
        unit("degC"),
        22.0,
        None,
        &["ahu-1-sp"],
        precondition_fresh(),
        &seal_ready(),
        equipment("ahu-1"),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "preview-protected-priority");
}

#[test]
fn noncommandable_refusal() {
    // Binary Value presentValue is not in this synthetic profile.
    let err = TargetObject::new(5, 85, None)
        .check_commandable()
        .unwrap_err();
    assert_eq!(err.code(), "preview-noncommandable");
    // Analog Value objectName is not a commandable setpoint.
    let err = TargetObject::new(2, 77, None)
        .check_commandable()
        .unwrap_err();
    assert_eq!(err.code(), "preview-noncommandable");
}

#[test]
fn ambiguous_array_refusal() {
    let err = TargetObject::new(2, 85, Some(1))
        .check_commandable()
        .expect("commandable")
        .check_scalar()
        .unwrap_err();
    assert_eq!(err.code(), "preview-ambiguous-array");
    assert!(matches!(
        err,
        PreviewError::AmbiguousArray { index: 1 }
    ));
}

#[test]
fn stale_precondition_refusal() {
    // 600s old exceeds the 300s horizon.
    let stale = Precondition::new(
        action_preview::synthetic_time(1_700_000_000_000),
        action_preview::synthetic_time(1_700_000_600_000),
    )
    .expect("order")
    .check_fresh()
    .unwrap_err();
    assert_eq!(stale.code(), "preview-stale-precondition");
    let err = Preview::preview(
        scope_a(),
        equipment("ahu-1"),
        binding_rev(7),
        accepted_rev(1),
        BindingStatus::Valid,
        2,
        RoleKind::Publisher,
        Some(8),
        2,
        85,
        None,
        unit("degC"),
        22.0,
        None,
        &["ahu-1-sp"],
        Precondition::new(
            action_preview::synthetic_time(1_700_000_000_000),
            action_preview::synthetic_time(1_700_000_600_000),
        )
        .expect("order"),
        &seal_ready(),
        equipment("ahu-1"),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "preview-stale-precondition");
    // D07 freshness assessment that is not Fresh also refuses.
    let boot = BootId::parse("boot-7").expect("boot");
    let mark = MonotonicMark::new(boot.clone(), 1_000);
    let ingestion = ClockReading {
        wall: action_preview::synthetic_time(1_700_000_000_000),
        monotonic: MonotonicMark::new(boot.clone(), 1_000),
        continuity: Continuity::Confirmed,
    };
    let now = ClockReading {
        wall: action_preview::synthetic_time(1_700_001_000_000),
        monotonic: MonotonicMark::new(boot, 1_000_000_000_000),
        continuity: Continuity::Confirmed,
    };
    let evidence = TimeEvidence::new(
        None,
        action_preview::synthetic_time(1_700_000_000_000),
        runtime::ReceiptOrigin::BacnetClientReturn,
        mark,
        ingestion,
    )
    .expect("evidence");
    let policy =
        FreshnessPolicy::new(Duration::from_secs(300), Duration::from_secs(5)).expect("policy");
    let err = action_preview::check_freshness(&policy, &evidence, &now).unwrap_err();
    assert_eq!(err.code(), "preview-stale-precondition");
}

#[test]
fn incorrect_unit_refusal() {
    for presented in [
        "percent",
        "turbo",
        "DEGc",
        "furlongs-per-fortnight",
    ] {
        let err = action_preview::check_unit(&unit(presented)).unwrap_err();
        assert_eq!(err.code(), "wrong-unit");
    }
    // Case-sensitive: DEGc is unknown and still wrong.
    let err = Preview::preview(
        scope_a(),
        equipment("ahu-1"),
        binding_rev(7),
        accepted_rev(1),
        BindingStatus::Valid,
        2,
        RoleKind::Publisher,
        Some(8),
        2,
        85,
        None,
        unit("percent"),
        22.0,
        None,
        &["ahu-1-sp"],
        precondition_fresh(),
        &seal_ready(),
        equipment("ahu-1"),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "wrong-unit");
}

#[test]
fn wire_rounded_out_of_range_refusal() {
    // Requested in range but the decoded wire value leaves the range.
    let err = EncodedSetpoint::from_decoded(22.0, 24.5).unwrap_err();
    assert_eq!(err.code(), "preview-wire-range");
    // Requested outside the range refuses even with an in-range wire claim.
    let err = EncodedSetpoint::from_decoded(19.0, 22.0).unwrap_err();
    assert_eq!(err.code(), "preview-wire-range");
    // Non-finite scalars never become setpoints.
    let err = EncodedSetpoint::new(f64::NAN).unwrap_err();
    assert_eq!(err.code(), "preview-invalid");
}

#[test]
fn duplicate_alias_refusal() {
    let err = AliasSet::new(&["ahu-1-sp", "ahu-1-sp"]).unwrap_err();
    assert_eq!(err.code(), "duplicate-identity");
    let err = Preview::preview(
        scope_a(),
        equipment("ahu-1"),
        binding_rev(7),
        accepted_rev(1),
        BindingStatus::Valid,
        2,
        RoleKind::Publisher,
        Some(8),
        2,
        85,
        None,
        unit("degC"),
        22.0,
        None,
        &["ahu-1-sp", "ahu-1-sp"],
        precondition_fresh(),
        &seal_ready(),
        equipment("ahu-1"),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "duplicate-identity");
}

#[test]
fn unavailable_feedback_is_stated_never_invented() {
    let feedback = FeedbackPlan::pv_readback();
    assert_eq!(feedback.property(), "presentValue");
    assert_eq!(feedback.status(), "unavailable-feedback");
    assert_eq!(feedback.source_time(), None);
    // The permitted preview carries the same unavailable readback.
    assert_eq!(permitted().feedback().status(), "unavailable-feedback");
    assert_eq!(permitted().feedback().source_time(), None);
}

#[test]
fn preview_is_revision_bound_not_reservation_or_dispatch() {
    let preview = permitted();
    preview
        .target()
        .require_current(binding_rev(7), accepted_rev(1))
        .expect("exact revision");
    let err = preview
        .target()
        .require_current(binding_rev(8), accepted_rev(1))
        .unwrap_err();
    assert_eq!(err.code(), "preview-revision-mismatch");
    let err = preview
        .target()
        .require_current(binding_rev(7), accepted_rev(2))
        .unwrap_err();
    assert_eq!(err.code(), "preview-revision-mismatch");
    assert!(!preview.is_reservation());
    assert!(!preview.is_dispatch());
    // Finding join: matching revision passes, replacement revision refuses.
    let binding = binding::ProposedBinding::from_import(
        binding::EndpointAddress::parse("bacnet://ahu-1").expect("endpoint"),
        binding::EndpointClass::Service,
        scope_a(),
        equipment("ahu-1"),
        binding::PropertyName::parse("supply-air-temp").expect("property"),
        scope_a(),
        equipment("sensor-sat-1"),
        unit("degC"),
        None,
        binding::BindingRole::Sense,
        binding::BindingRole::Sense,
        binding::Feedback::Absent,
        BindingStatus::Valid,
    );
    let finding = Finding::for_binding(&binding, binding_rev(7), "fixture-actor");
    AcceptedTarget::new(
        scope_a(),
        equipment("ahu-1"),
        binding_rev(7),
        accepted_rev(1),
    )
    .expect("target")
    .require_finding(&finding)
    .expect("finding joins");
    let err = AcceptedTarget::new(
        scope_a(),
        equipment("ahu-1"),
        binding_rev(8),
        accepted_rev(1),
    )
    .expect("target")
    .require_finding(&finding)
    .unwrap_err();
    assert_eq!(err.code(), "preview-revision-mismatch");
}

#[test]
fn null_release_semantics() {
    let admitted = ReleasePlan::new(equipment("ahu-1"), true);
    assert_eq!(admitted.on_expiry(), "null-relinquish");
    assert_eq!(admitted.null_wire().expect("admitted null"), vec![0x00]);
    let refused = ReleasePlan::new(equipment("ahu-1"), false);
    let err = refused.null_wire().unwrap_err();
    assert_eq!(err.code(), "preview-null-not-admitted");
    // Original-target cleanup survives replacement, revocation and offboarding.
    assert!(admitted.survives_replacement());
    assert!(admitted.survives_revocation());
    assert!(admitted.survives_offboarding());
    // Timeout after handoff is uncertain, never permission to resend.
    assert_eq!(admitted.timeout_policy(), "uncertain-not-resend");
    assert!(!admitted.allows_resend_after_timeout());
}

#[test]
fn s03_consumption_order_preserved() {
    // No availability without the ordered chain.
    let fresh = SealOrder::new();
    assert_eq!(
        fresh.availability().unwrap_err().code(),
        "preview-seal-order"
    );
    assert_eq!(
        fresh.ledger_only().unwrap_err().code(),
        "preview-seal-order"
    );
    // Decode before custody refuses.
    let mut order = SealOrder::new();
    assert_eq!(order.decode().unwrap_err().code(), "preview-seal-order");
    // Reconstruct before decode refuses.
    let mut order = SealOrder::new();
    order.check_custody().expect("custody");
    assert_eq!(
        order.reconstruct().unwrap_err().code(),
        "preview-seal-order"
    );
    // Ordered custody, decode, reconstruct yields availability.
    let mut order = SealOrder::new();
    order.check_custody().expect("custody");
    order.decode().expect("decode");
    order.reconstruct().expect("reconstruct");
    order.availability().expect("available");
    // ledger_status alone remains insufficient even after availability.
    assert_eq!(
        order.ledger_only().unwrap_err().code(),
        "preview-seal-order"
    );
    // Decoding delegates to the real S03 decoder; no independent parser.
    assert_eq!(
        action_preview::decode_profile(&[])
            .unwrap_err()
            .code(),
        "s03-limit"
    );
    assert_eq!(
        action_preview::decode_profile(&["x"])
            .unwrap_err()
            .code(),
        "s03-invalid"
    );
}

#[test]
fn d07_suitability_and_timing_stay_synthetic_only() {
    // SyntheticValueOnly is usable; every refusal stays refused.
    assert!(matches!(
        action_preview::check_suitability(Suitability::SyntheticValueOnly).expect("usable"),
        Suitability::SyntheticValueOnly
    ));
    assert_eq!(
        action_preview::check_suitability(Suitability::Refused(Refusal::WrongUnit))
            .unwrap_err()
            .code(),
        "wrong-unit"
    );
    // Frozen synthetic timing with rate bound.
    let timing = Timing::synthetic();
    assert_eq!(timing.duration_secs(), 900);
    assert_eq!(timing.deadline_secs(), 5);
    assert_eq!(timing.apdu_retries(), 0);
    timing.check_rate(0).expect("within bound");
    assert_eq!(
        timing.check_rate(6).unwrap_err().code(),
        "preview-rate-exceeded"
    );
    // Freshness never becomes qualification.
    assert!(!permitted().is_qualified());
    assert_eq!(
        Freshness::Fresh.retain(Freshness::Stale),
        Freshness::Stale
    );
}
