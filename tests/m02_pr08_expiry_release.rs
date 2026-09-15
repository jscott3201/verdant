//! M02-PR08 normal expiry and exact release, HARNESS-ONLY.
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
#[path = "../src/action_journal/mod.rs"]
mod action_journal;
#[path = "../src/action_dispatch/mod.rs"]
mod action_dispatch;
#[path = "../src/action_expiry/mod.rs"]
mod action_expiry;

use access::RoleKind;
use action_dispatch::{Current, DispatchCancel, DispatchError, FrozenRoute, ProtocolResult};
use action_expiry::{ExpiryHorizon, ExpiryState, PendingRelease};
use action_journal::Journal;
use action_preview::{Precondition, Preview, SealOrder};
use binding::BindingStatus;
use domain::clock::{BootId, MonotonicMark, UnixMillis};
use domain::ids::{BindingRevision, InstalledId, OperationId};
use domain::scope::TrustedScope;
use domain::values::Unit;
use observation::time::{ClockReading, Continuity, Freshness, FreshnessPolicy, TimeEvidence};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use storage::{ConnectionSettings, StoreBounds};

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("verdant-m02-pr08-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).expect("isolated scratch");
        Self(dir)
    }
    fn db(&self) -> std::path::PathBuf {
        self.0.join("store.db")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("cleanup scratch");
    }
}
fn scope_a() -> TrustedScope { TrustedScope::parse("scope-a").expect("frozen scope-a") }
fn equipment(raw: &str) -> InstalledId { InstalledId::parse(raw).expect("frozen equipment") }
fn operation(raw: &str) -> OperationId { OperationId::parse(raw).expect("operation parses") }
fn precondition_fresh() -> Precondition {
    Precondition::new(action_preview::synthetic_time(1_700_000_000_000), action_preview::synthetic_time(1_700_000_060_000)).expect("fresh")
}
fn seal_ready() -> SealOrder {
    let mut o = SealOrder::new();
    o.check_custody().expect("custody"); o.decode().expect("decode"); o.reconstruct().expect("reconstruct"); o
}
fn preview_at(setpoint: f64) -> Preview {
    Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("accepted"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), setpoint, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("ahu-1"), false).expect("permitted preview")
}
fn preview_release(admitted: bool) -> Preview {
    Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("accepted"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), 22.0, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("ahu-1"), admitted).expect("release preview")
}
fn admit_at(scratch: &Scratch, op: &str, preview: &Preview, expected: u32) -> action_journal::Admitted {
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("writer open");
    journal.admit(operation(op), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", preview, expected).expect("admit")
}
fn current_gen(expected: u32) -> Current {
    Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, expected).expect("current")
}
fn deadline_5s() -> Instant { Instant::now() + Duration::from_secs(5) }
fn boot(raw: &str) -> BootId { BootId::parse(raw).expect("boot parses") }
fn mark(raw_boot: &str, nanos: u64) -> MonotonicMark { MonotonicMark::new(boot(raw_boot), nanos) }
fn wall(ms: i64) -> UnixMillis { UnixMillis::new(ms) }
fn reading(wall_ms: i64, boot_raw: &str, nanos: u64, continuity: Continuity) -> ClockReading {
    ClockReading { wall: action_preview::synthetic_time(wall_ms), monotonic: mark(boot_raw, nanos), continuity }
}
fn freshness_policy() -> FreshnessPolicy {
    FreshnessPolicy::new(Duration::from_secs(900), Duration::from_secs(5)).expect("harness policy 900s/5s")
}
fn evidence_at(receipt_ms: i64, boot_raw: &str, nanos: u64) -> TimeEvidence {
    let mark0 = mark(boot_raw, nanos);
    let ingestion = reading(receipt_ms, boot_raw, nanos, Continuity::Confirmed);
    TimeEvidence::new(None, action_preview::synthetic_time(receipt_ms), runtime::ReceiptOrigin::BacnetClientReturn, mark0, ingestion).expect("evidence")
}

#[test]
fn active_expiry_refuses_new_set_allows_cancel_or_null() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    assert_eq!(preview.encoded().wire_bits(), 0x41b00000);
    assert_eq!(preview.timing().duration_secs(), 900);
    assert_eq!(preview.timing().deadline_secs(), 5);
    let admitted = admit_at(&scratch, "exp-active-1", &preview, 0);
    assert_eq!(admitted.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
    let start = mark("boot-7", 0);
    // Active: 899s < 900s duration.
    let now_active = mark("boot-7", 899_000_000_000);
    let active = action_expiry::assess_expiry(&start, &now_active, 900);
    assert_eq!(active, ExpiryState::Active);
    assert!(active.is_active());
    let policy = freshness_policy();
    let evidence = evidence_at(1_700_000_000_000, "boot-7", 0);
    let now_reading = ClockReading { wall: action_preview::synthetic_time(1_700_000_010_000), monotonic: mark("boot-7", 10_000_000_000), continuity: Continuity::Confirmed };
    // Wall age 10s, monotonic elapsed 10s, skew 0 within 5s: Fresh.
    assert_eq!(action_expiry::assess_cleanup(&evidence, &now_reading, policy), Freshness::Fresh);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let write = action_expiry::authorize_set(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &active, Freshness::Fresh).expect("active SET allowed");
    assert_eq!(write.value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    // Expired: elapsed 900s >= 900s duration refuses new SET.
    let now_expired = mark("boot-7", 900_000_000_000);
    let expired = action_expiry::assess_expiry(&start, &now_expired, 900);
    assert_eq!(expired, ExpiryState::Expired { elapsed_secs: 900, duration_secs: 900 });
    assert!(expired.is_expired());
    let err = action_expiry::decide_set_allowed(&expired, Freshness::Fresh).unwrap_err();
    assert_eq!(err.code(), "expiry-expired");
    let err = action_expiry::authorize_set(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &expired, Freshness::Fresh).unwrap_err();
    assert_eq!(err.code(), "expiry-expired");
    // No new SET after expiry, but explicit cancel stays permitted.
    assert!(action_expiry::authorize_cancel(0, 0).is_ok());
    // Admitted NULL release stays permitted after expiry (separate scratch intent).
    let scratch2 = Scratch::new();
    let rel_preview = preview_release(true);
    let rel_admitted = admit_at(&scratch2, "exp-null-1", &rel_preview, 0);
    let rel = action_expiry::authorize_release(&rel_admitted, &rel_preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &expired, Freshness::Fresh).expect("NULL after expiry");
    assert_eq!(rel.value(), &[0x00]);
    assert!(rel.is_release());
    // Checked generation arithmetic refuses overflow instead of wrapping.
    assert_eq!(action_expiry::next_generation(u32::MAX).unwrap_err().code(), "expiry-invalid");
    assert_eq!(action_expiry::next_generation(0).expect("next"), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn masked_expiry_expires_on_own_generation_no_escalation() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let mut initial = PeerTable::default();
    initial.slots[4] = Some(21.0);
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "mask-exp-1", &preview, 0);
    let harness = Harness::new(initial, PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.expect("masked write");
    assert_eq!(outcome.slot().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert_eq!(outcome.pv().value(), &[0x44, 0x41, 0xa8, 0x00, 0x00]);
    assert_eq!(harness.fixture.table().effective(), 21.0);
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 3);
    harness.finish("mask-expiry", &requests).await;
    // Masked intent still expires on its own P8 generation; no escalation to protected 1-3.
    let start = mark("boot-7", 0);
    let expired = action_expiry::assess_expiry(&start, &mark("boot-7", 900_000_000_000), 900);
    assert!(expired.is_expired());
    let route2 = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert_eq!(action_expiry::authorize_set(&admitted, &preview, &current_gen(0), &route2, &DispatchCancel::new(), deadline_5s(), &expired, Freshness::Fresh).unwrap_err().code(), "expiry-expired");
    // Protected priorities stay refused at preview; masking never escalates.
    assert_eq!(action_preview::Priority::new(2).expect("priority 2 parses").check_commissioned().unwrap_err().code(), "preview-protected-priority");
    assert_eq!(preview.priority().get(), 8);
}

#[test]
fn explicit_cancel_unattempted_emits_nothing_duplicate_idempotent() {
    let scratch = Scratch::new();
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let preview = preview_at(22.0);
    let pending = journal.prepare(operation("exp-cancel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("prepare");
    assert_eq!(pending.operation().as_str(), "exp-cancel-1");
    Journal::cancel(pending);
    let count: String = journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count").into_iter().next().expect("row")[0].clone();
    assert_eq!(count, "0");
    assert_eq!(journal.essential_announced(), 0);
    assert_eq!(journal.history_announced(), 0);
    assert_eq!(journal.reconcile(&operation("exp-cancel-1"), &scope_a()).unwrap_err().code(), "admission-not-found");
    // Duplicate cancel of the same unattempted identities also emits nothing.
    let pending2 = journal.prepare(operation("exp-cancel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("prepare again");
    Journal::cancel(pending2);
    let count2: String = journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count").into_iter().next().expect("row")[0].clone();
    assert_eq!(count2, "0");
    assert_eq!(journal.essential_announced(), 0);
    assert_eq!(journal.reconcile(&operation("exp-cancel-1"), &scope_a()).unwrap_err().code(), "admission-not-found");
    assert!(action_expiry::authorize_cancel(0, 0).is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn observed_null_distinct_from_zero_and_inactive() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    assert_eq!(vec![0x00], vec![0x00]);
    assert_ne!(vec![0x00], vec![0x44, 0x00, 0x00, 0x00, 0x00]);
    assert_ne!(vec![0x00], vec![0x91, 0x00]);
    assert_ne!(vec![0x44, 0x00, 0x00, 0x00, 0x00], vec![0x91, 0x00]);
    assert!(action_expiry::is_null_wire(&[0x00]));
    assert!(!action_expiry::is_null_wire(&[0x44, 0x00, 0x00, 0x00, 0x00]));
    assert!(action_expiry::is_real_zero_wire(&[0x44, 0x00, 0x00, 0x00, 0x00]));
    assert!(action_expiry::is_inactive_wire(&[0x91, 0x00]));
    let scratch = Scratch::new();
    let preview = preview_release(true);
    let admitted = admit_at(&scratch, "exp-null-obs-1", &preview, 0);
    let mut initial = PeerTable::default();
    initial.slots[7] = Some(22.0);
    let harness = Harness::new(initial, PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_release(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture).await.expect("release");
    assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
    assert_eq!(outcome.slot().value(), &[0x00]);
    assert_eq!(outcome.pv().value(), &[0x44, 0x41, 0xa0, 0x00, 0x00]);
    assert!(outcome.source_time().is_none());
    assert_eq!(harness.fixture.table().slots[7], None);
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0][5], 15);
    harness.finish("null-observed", &requests).await;
}

#[test]
fn rejected_release_non_admitted_and_wrong_target_generation() {
    let scratch = Scratch::new();
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let denied_preview = preview_release(false);
    let denied = admit_at(&scratch, "exp-rej-1", &denied_preview, 0);
    let err = action_expiry::authorize_release(&denied, &denied_preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh).unwrap_err();
    assert_eq!(err.code(), "dispatch-null-not-admitted");
    // Wrong target equipment refuses before any send.
    let scratch2 = Scratch::new();
    let ok_preview = preview_release(true);
    let ok_admitted = admit_at(&scratch2, "exp-rej-2", &ok_preview, 0);
    let wrong_preview = Preview::preview(scope_a(), equipment("vav-101"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), 22.0, None, &["vav-101-sp"], precondition_fresh(), &seal_ready(), equipment("vav-101"), true).expect("vav preview");
    let err = action_expiry::authorize_release(&ok_admitted, &wrong_preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh).unwrap_err();
    assert_eq!(err.code(), "dispatch-invalid");
    // Wrong generation refuses.
    let stale = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 99).expect("current");
    let err = action_expiry::authorize_release(&ok_admitted, &ok_preview, &stale, &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh).unwrap_err();
    assert_eq!(err.code(), "dispatch-stale-generation");
    match err {
        action_expiry::ExpiryError::Dispatch(DispatchError::StaleGeneration { expected, current }) => {
            assert_eq!(expected, 0); assert_eq!(current, 99);
        }
        other => panic!("wrong variant {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn lost_acknowledgment_persists_unknown_for_reconcile_no_resend() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let scratch = Scratch::new();
    let preview = preview_release(true);
    let admitted = admit_at(&scratch, "exp-lost-1", &preview, 0);
    let pending = PendingRelease::from_admitted(&admitted);
    assert_eq!(pending.operation().as_str(), "exp-lost-1");
    assert_eq!(pending.attempt().as_str(), admitted.attempt().as_str());
    assert_eq!(pending.scope().as_str(), "scope-a");
    assert_eq!(pending.equipment().as_str(), "ahu-1");
    assert_eq!(pending.expected_generation(), 0);
    assert_eq!(pending.target_generation(), 1);
    let harness = Harness::new(PeerTable::default(), PeerMode::DropAfterAccept).await;
    let route = harness.fixture.route("ahu-1");
    let err = action_dispatch::harness::execute_release(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture).await.unwrap_err();
    assert_eq!(err.code(), "dispatch-unknown");
    match &err {
        DispatchError::Unknown { operation, attempt, .. } => {
            assert_eq!(operation, "exp-lost-1");
            assert_eq!(attempt, admitted.attempt().as_str());
        }
        other => panic!("wrong variant {other:?}"),
    }
    assert_eq!(harness.fixture.requests().len(), 1);
    assert_eq!(harness.fixture.sent_count(), 1);
    let requests = harness.fixture.requests();
    harness.finish("lost-release", &requests).await;
    // Pending release persists with original identities for reconcile; no resend.
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let recovered = pending.reconcile_via(&journal).expect("reconcile recovers");
    assert_eq!(recovered.operation().as_str(), "exp-lost-1");
    assert_eq!(recovered.attempt().as_str(), admitted.attempt().as_str());
    assert_eq!(recovered.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
    assert!(recovered.reconciled());
}

#[test]
fn duration_edit_applies_only_to_new_generations() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "exp-dur-1", &preview, 0);
    let horizon = ExpiryHorizon::from_admitted(&admitted, &preview).expect("horizon");
    assert_eq!(horizon.duration_secs(), 900);
    assert_eq!(horizon.deadline_secs(), 5);
    assert_eq!(horizon.expected_generation(), 0);
    assert_eq!(horizon.target_generation(), 1);
    // Synthetic edit for the next generation only; in-flight keeps 900s/5s.
    let edited = horizon.with_edited_duration_for_new_generation(600, 1).expect("edited horizon");
    assert_eq!(edited.duration_secs(), 600);
    assert_eq!(edited.deadline_secs(), 5);
    assert_eq!(edited.expected_generation(), 1);
    assert_eq!(edited.target_generation(), 2);
    assert_eq!(horizon.duration_secs(), 900);
    assert_eq!(horizon.deadline_secs(), 5);
    // Same monotonic now is Active for the in-flight 900s horizon but Expired for the edited 600s horizon.
    let start = mark("boot-7", 0);
    let now_800 = mark("boot-7", 800_000_000_000);
    assert_eq!(action_expiry::assess_expiry(&start, &now_800, horizon.duration_secs()), ExpiryState::Active);
    assert_eq!(action_expiry::assess_expiry(&start, &now_800, edited.duration_secs()), ExpiryState::Expired { elapsed_secs: 800, duration_secs: 600 });
    assert_eq!(horizon.with_edited_duration_for_new_generation(0, 1).unwrap_err().code(), "expiry-invalid");
}

#[test]
fn old_cancel_after_new_generation_refuses_current_unaffected() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let preview2 = preview_at(22.5);
    assert_eq!(preview2.encoded().wire_bits(), 0x41b40000);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    journal.admit(operation("exp-old-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("gen0");
    journal.admit(operation("exp-old-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview2, 1).expect("gen1");
    let err = action_expiry::authorize_cancel(0, 1).unwrap_err();
    assert_eq!(err.code(), "expiry-stale-generation");
    match err {
        action_expiry::ExpiryError::StaleGeneration { expected, current } => {
            assert_eq!(expected, 0); assert_eq!(current, 1);
        }
        other => panic!("wrong variant {other:?}"),
    }
    assert!(action_expiry::authorize_cancel(1, 1).is_ok());
    let current = journal.reconcile(&operation("exp-old-2"), &scope_a()).expect("current unaffected");
    assert_eq!(current.target_generation(), 2);
    assert_eq!(current.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.5000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
}

#[tokio::test(flavor = "current_thread")]
async fn slot_change_blocks_new_handoffs_prior_obligations_stay() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "exp-slot-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.expect("dispatch before change");
    assert_eq!(outcome.binding_revision(), 7);
    assert_eq!(outcome.accepted_revision(), 1);
    assert_eq!(outcome.target_generation(), 1);
    assert_eq!(outcome.equipment(), "ahu-1");
    let requests = harness.fixture.requests();
    harness.finish("slot-prior", &requests).await;
    // Changed slot/binding revision blocks new handoffs until accepted.
    let changed = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(8), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 0).expect("changed");
    let route2 = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let err = action_expiry::authorize_set(&admitted, &preview, &changed, &route2, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh).unwrap_err();
    assert_eq!(err.code(), "dispatch-revision-mismatch");
    // Already-attempted obligation stays attached to the old target.
    assert_eq!(outcome.binding_revision(), 7);
    assert_eq!(outcome.target_generation(), 1);
    assert_eq!(outcome.equipment(), "ahu-1");
    assert_eq!(outcome.slot().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
}

#[test]
fn wall_rollback_and_suspend_resume_refuse_set_allow_cancel_null() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "exp-wall-1", &preview, 0);
    let rel_preview = preview_release(true);
    let rel_admitted = admit_at(&scratch, "exp-wall-null-1", &rel_preview, 1);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let policy = freshness_policy();
    let active = ExpiryState::Active;
    // Wall rollback: receipt 1_700_000_000_000, now 1_699_999_000_000.
    let evidence_roll = evidence_at(1_700_000_000_000, "boot-7", 0);
    let now_roll = ClockReading { wall: action_preview::synthetic_time(1_699_999_000_000), monotonic: mark("boot-7", 5_000_000_000), continuity: Continuity::Confirmed };
    assert_eq!(action_expiry::assess_cleanup(&evidence_roll, &now_roll, policy), Freshness::Unknown);
    assert_eq!(action_expiry::wall_age_millis(wall(1_699_999_000_000), wall(1_700_000_000_000)).unwrap_err().code(), "expiry-indeterminate");
    // Cross-boot: receipt boot-7, now boot-8.
    let evidence_boot = evidence_at(1_700_000_000_000, "boot-7", 0);
    let now_boot = ClockReading { wall: action_preview::synthetic_time(1_700_000_010_000), monotonic: mark("boot-8", 10_000_000_000), continuity: Continuity::Confirmed };
    assert_eq!(action_expiry::assess_cleanup(&evidence_boot, &now_boot, policy), Freshness::Unknown);
    assert_eq!(action_expiry::require_same_boot(&mark("boot-7", 0), &mark("boot-8", 0)).unwrap_err().code(), "expiry-indeterminate");
    // Skew-exceeded: 1s monotonic vs 100s wall with 5s skew bound.
    let evidence_skew = evidence_at(1_700_000_000_000, "boot-7", 0);
    let now_skew = ClockReading { wall: action_preview::synthetic_time(1_700_000_100_000), monotonic: mark("boot-7", 1_000_000_000), continuity: Continuity::Confirmed };
    assert_eq!(action_expiry::assess_cleanup(&evidence_skew, &now_skew, policy), Freshness::Unknown);
    // Suspend-qualified continuity on now.
    let evidence_ok = evidence_at(1_700_000_000_000, "boot-7", 0);
    let now_susp = ClockReading { wall: action_preview::synthetic_time(1_700_000_010_000), monotonic: mark("boot-7", 10_000_000_000), continuity: Continuity::WallOrSuspendAmbiguous };
    assert_eq!(action_expiry::assess_cleanup(&evidence_ok, &now_susp, policy), Freshness::Unknown);
    assert_eq!(action_expiry::require_confirmed(Continuity::WallOrSuspendAmbiguous).unwrap_err().code(), "expiry-indeterminate");
    // All four refuse new SET but allow explicit cancel and admitted-NULL release.
    for freshness in [action_expiry::assess_cleanup(&evidence_roll, &now_roll, policy), action_expiry::assess_cleanup(&evidence_boot, &now_boot, policy), action_expiry::assess_cleanup(&evidence_skew, &now_skew, policy), action_expiry::assess_cleanup(&evidence_ok, &now_susp, policy)] {
        assert_ne!(freshness, Freshness::Fresh);
        let err = action_expiry::authorize_set(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &active, freshness).unwrap_err();
        assert_eq!(err.code(), "expiry-indeterminate");
    }
    let cur1 = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 1).expect("cur1");
    assert!(action_expiry::authorize_cancel(1, 1).is_ok());
    let rel = action_expiry::authorize_release(&rel_admitted, &rel_preview, &cur1, &route, &DispatchCancel::new(), deadline_5s(), &active, Freshness::Unknown).expect("NULL allowed under indeterminate time");
    assert_eq!(rel.value(), &[0x00]);
}

#[tokio::test(flavor = "current_thread")]
async fn earlier_packets_may_take_effect_later_and_release_reveals_other_system() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    // Earlier packet sent before expiry may still take effect later; expiry renews nothing.
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "exp-resid-1", &preview, 0);
    let mut masked = PeerTable::default();
    masked.slots[4] = Some(21.0);
    masked.relinquish_default = 20.0;
    let harness = Harness::new(masked, PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.expect("pre-expiry send");
    assert_eq!(outcome.slot().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert_eq!(outcome.pv().value(), &[0x44, 0x41, 0xa8, 0x00, 0x00]);
    let requests = harness.fixture.requests();
    harness.finish("residual-pre", &requests).await;
    let expired = action_expiry::assess_expiry(&mark("boot-7", 0), &mark("boot-7", 900_000_000_000), 900);
    assert!(expired.is_expired());
    let route2 = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert_eq!(action_expiry::authorize_set(&admitted, &preview, &current_gen(0), &route2, &DispatchCancel::new(), deadline_5s(), &expired, Freshness::Fresh).unwrap_err().code(), "expiry-expired");
    // Release after expiry reveals the other system's command (P5 21.0 over default 20.0), not renewed intent.
    let scratch2 = Scratch::new();
    let rel_preview = preview_release(true);
    let rel_admitted = admit_at(&scratch2, "exp-resid-null-1", &rel_preview, 0);
    let mut table = PeerTable::default();
    table.slots[4] = Some(21.0);
    table.slots[7] = Some(22.0);
    table.relinquish_default = 20.0;
    let harness2 = Harness::new(table, PeerMode::Confirm).await;
    let route3 = harness2.fixture.route("ahu-1");
    let rel_out = action_dispatch::harness::execute_release(&rel_admitted, &rel_preview, &current_gen(0), &route3, &DispatchCancel::new(), deadline_5s(), &harness2.fixture).await.expect("release reveals other");
    assert_eq!(rel_out.slot().value(), &[0x00]);
    assert_eq!(rel_out.pv().value(), &[0x44, 0x41, 0xa8, 0x00, 0x00]);
    assert_eq!(harness2.fixture.table().effective(), 21.0);
    let requests2 = harness2.fixture.requests();
    harness2.finish("residual-reveal", &requests2).await;
}
