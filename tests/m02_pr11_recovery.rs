//! M02-PR11 uncertain effects and restart recovery, HARNESS-ONLY.
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
#[path = "../src/action_recovery/mod.rs"]
mod action_recovery;
#[path = "../src/action_publication/mod.rs"]
mod action_publication;
#[path = "../src/action_custody/mod.rs"]
mod action_custody;
#[path = "../src/action_joined.rs"]
mod action_joined;

use access::RoleKind;
use action_dispatch::{Current, DispatchCancel, DispatchError, FrozenRoute, ProtocolResult};
use action_expiry::{ExpiryState, PendingRelease};
use action_journal::Journal;
use action_preview::{Precondition, Preview, SealOrder};
use action_recovery::decisions::{
    assess_conflicting_request, check_peer_accepted_before_journal, classify_cancellation,
    classify_commit, classify_observation, classify_peer_protocol, decide_set_allowed_from_assessed,
    require_current_generation, require_intact_backup, require_same_record, verify_backup,
    BackupVerdict, CancelVerdict, CommitVerdict, ConflictWait, ObservationVerdict, OrderingVerdict,
    PeerAcceptance, QuiescenceClaim,
};
use binding::BindingStatus;
use domain::clock::{BootId, MonotonicMark, UnixMillis};
use domain::ids::{BindingRevision, InstalledId, OperationId, SourceGenerationId};
use domain::outcomes::RecordIdentity;
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
        let dir = std::env::temp_dir().join(format!("verdant-m02-pr11-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).expect("isolated scratch");
        Self(dir)
    }
    fn db(&self) -> std::path::PathBuf { self.0.join("store.db") }
}
impl Drop for Scratch {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).expect("cleanup scratch"); }
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
fn forced_exit_before_commit_is_rollback_nothing_admitted() {
    use storage::sqlite::faults::{inject, Fault};
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    assert_eq!(preview.encoded().wire_bits(), 0x41b00000);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let pending = journal.prepare(operation("rec-pre-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("prepare");
    inject(&scratch.db(), Fault::BeforeCommit);
    let err = journal.submit(&pending).unwrap_err();
    assert_ne!(err.code(), "admission-unknown");
    assert_ne!(err.code(), "admission-conflict");
    assert_eq!(journal.reconcile(&operation("rec-pre-1"), &scope_a()).unwrap_err().code(), "admission-not-found");
    assert_eq!(journal.essential_announced(), 0);
    assert_eq!(journal.history_announced(), 0);
    let count: String = journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count").into_iter().next().expect("row")[0].clone();
    assert_eq!(count, "0");
    // Pure table: NotCommitted is known rollback, never Unknown.
    let not_committed = storage::sqlite::MutationOutcome::NotCommitted { operation: operation("rec-pre-1"), error: storage::StorageError::SqliteFailure { detail: "injected precommit interruption".to_string() } };
    assert_eq!(classify_commit(&not_committed), CommitVerdict::NotCommitted);
    let conflict = storage::sqlite::MutationOutcome::Conflict { operation: operation("rec-pre-1"), detail: "conflict".to_string() };
    assert_eq!(classify_commit(&conflict), CommitVerdict::ConflictNeedsReconcile);
    // Retry after rollback succeeds as new work with a fresh identity.
    let (mut journal2, _rx2) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let retry = journal2.admit(operation("rec-pre-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("retry as new work");
    assert_eq!(retry.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
}

/// Honesty: no child process is involved here; `LostResponse` fault injection
/// models a lost storage response after commit (UNKNOWN until reconcile).
/// True post-handoff child-process interruption is Slice D (Sec 7), proved in
/// `tests/m02_sliceD_posthandoff_proof.rs`, not here.
#[test]
fn lost_response_after_commit_is_unknown_persists_for_reconcile() {
    use storage::sqlite::faults::{inject, Fault};
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let pending = journal.prepare(operation("rec-post-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("prepare");
    inject(&scratch.db(), Fault::LostResponse);
    let err = journal.submit(&pending).unwrap_err();
    assert_eq!(err.code(), "admission-unknown");
    match &err {
        action_journal::WriterError::Unknown { operation, .. } => assert_eq!(operation.as_str(), "rec-post-1"),
        other => panic!("wrong variant {other:?}"),
    }
    assert_eq!(journal.essential_announced(), 0);
    let recovered = action_recovery::reconcile_journal(&journal, &operation("rec-post-1"), &scope_a()).expect("reconcile recovers");
    assert_eq!(recovered.operation().as_str(), "rec-post-1");
    assert_eq!(recovered.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
    assert!(recovered.reconciled());
    // Pure table: Unknown persists for reconcile, never a silent rollback.
    let unknown = storage::sqlite::MutationOutcome::Unknown { operation: operation("rec-post-1"), detail: "lost response".to_string() };
    assert_eq!(classify_commit(&unknown), CommitVerdict::UnknownNeedsReconcile);
    let committed = storage::sqlite::MutationOutcome::Committed { operation: operation("rec-post-1"), rows: vec![] };
    assert_eq!(classify_commit(&committed), CommitVerdict::Committed);
    // Lost-response row reconciles as committed under its own identity after reopen.
    let (journal2, _rx2) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let again = journal2.reconcile(&operation("rec-post-1"), &scope_a()).expect("reopen recovers");
    assert_eq!(again.payload(), recovered.payload());
    assert!(again.reconciled());
}

#[tokio::test(flavor = "current_thread")]
async fn caller_cancel_needs_join_harness_stop_accounting() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    assert_eq!(classify_cancellation(false, false), CancelVerdict::JoinedStopped);
    assert_eq!(classify_cancellation(true, true), CancelVerdict::JoinedStopped);
    assert_eq!(classify_cancellation(true, false), CancelVerdict::NeedsJoinOrReap);
    // Cancel does not prove the owner stopped: a still-running task needs join.
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = flag.clone();
    let task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        done.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let cancel = DispatchCancel::new();
    cancel.cancel();
    assert!(cancel.check(deadline_5s()).is_err());
    assert_eq!(cancel.check(deadline_5s()).unwrap_err().code(), "dispatch-cancelled");
    assert!(!flag.load(std::sync::atomic::Ordering::SeqCst));
    task.await.expect("join reaps owner");
    assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
    // Harness stop accounting: cancelled handoff consumes no script, no capture.
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "rec-cancel-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let err = action_recovery::authorize_set_via_expiry(&admitted, &preview, &current_gen(0), &route, &cancel, deadline_5s(), &ExpiryState::Active, Freshness::Fresh).unwrap_err();
    assert_eq!(err.code(), "dispatch-cancelled");
    assert_eq!(harness.fixture.sent_count(), 0);
    assert!(harness.fixture.requests().is_empty());
    harness.finish("rec-cancel-stop", &[]).await;
}

#[tokio::test(flavor = "current_thread")]
async fn delayed_old_set_around_null_shown_not_renewed() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let rel_preview = preview_release(true);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    journal.admit(operation("rec-delay-set-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("gen0 SET");
    journal.admit(operation("rec-delay-null-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &rel_preview, 1).expect("gen1 NULL");
    let mut table = PeerTable::default();
    table.slots[4] = Some(21.0);
    table.relinquish_default = 20.0;
    let harness = Harness::new(table, PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let rel_admitted = journal.reconcile(&operation("rec-delay-null-1"), &scope_a()).expect("null intent");
    let rel_out = action_dispatch::harness::execute_release(&rel_admitted, &rel_preview, &Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 1).expect("cur1"), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture).await.expect("release");
    assert_eq!(rel_out.slot().value(), &[0x00]);
    assert_eq!(rel_out.pv().value(), &[0x44, 0x41, 0xa8, 0x00, 0x00]);
    assert_eq!(harness.fixture.table().effective(), 21.0);
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 3);
    harness.finish("rec-delay-residual", &requests).await;
    // Delayed old SET at the pre-NULL generation refuses; residual is shown, not renewed.
    assert_eq!(require_current_generation(0, 2).unwrap_err().code(), "recovery-stale-generation");
    let route2 = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let old_admitted = journal.reconcile(&operation("rec-delay-set-1"), &scope_a()).expect("old intent kept with old ID");
    assert_eq!(old_admitted.target_generation(), 1);
    let current_post_null = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 2).expect("post-NULL current");
    let err = action_recovery::authorize_set_via_expiry(&old_admitted, &preview, &current_post_null, &route2, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh).unwrap_err();
    assert_eq!(err.code(), "dispatch-stale-generation");
}

#[tokio::test(flavor = "current_thread")]
async fn absent_result_unknown_persists_until_reconcile_no_resend() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let scratch = Scratch::new();
    let preview = preview_release(true);
    let admitted = admit_at(&scratch, "rec-absent-1", &preview, 0);
    let pending = PendingRelease::from_admitted(&admitted);
    let harness = Harness::new(PeerTable::default(), PeerMode::DropAfterAccept).await;
    let route = harness.fixture.route("ahu-1");
    let err = action_dispatch::harness::execute_release(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture).await.unwrap_err();
    assert_eq!(err.code(), "dispatch-unknown");
    assert_eq!(harness.fixture.sent_count(), 1);
    assert_eq!(harness.fixture.requests().len(), 1);
    let requests = harness.fixture.requests();
    harness.finish("rec-absent", &requests).await;
    // Unknown persists with identities; reconcile recovers without a resend.
    assert_eq!(action_recovery::peer_acceptance(&ProtocolResult::Timeout), PeerAcceptance::NotAcceptedNeedsReconcile);
    assert_eq!(check_peer_accepted_before_journal(false, true).unwrap_err().code(), "recovery-conflict");
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let recovered = action_recovery::reconcile_pending_release(&pending, &journal).expect("reconcile recovers");
    assert_eq!(recovered.operation().as_str(), "rec-absent-1");
    assert!(recovered.reconciled());
    assert_eq!(recovered.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
    assert_eq!(journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count")[0][0], "1");
}

#[test]
fn clock_discontinuity_refuses_set_allows_cancel_null() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "rec-clock-1", &preview, 0);
    let rel_preview = preview_release(true);
    let rel_admitted = admit_at(&scratch, "rec-clock-null-1", &rel_preview, 1);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let policy = freshness_policy();
    let active = ExpiryState::Active;
    let evidence_roll = evidence_at(1_700_000_000_000, "boot-7", 0);
    let now_roll = reading(1_699_999_000_000, "boot-7", 5_000_000_000, Continuity::Confirmed);
    let evidence_boot = evidence_at(1_700_000_000_000, "boot-7", 0);
    let now_boot = reading(1_700_000_010_000, "boot-8", 10_000_000_000, Continuity::Confirmed);
    let evidence_skew = evidence_at(1_700_000_000_000, "boot-7", 0);
    let now_skew = reading(1_700_000_100_000, "boot-7", 1_000_000_000, Continuity::Confirmed);
    let evidence_ok = evidence_at(1_700_000_000_000, "boot-7", 0);
    let now_susp = reading(1_700_000_010_000, "boot-7", 10_000_000_000, Continuity::WallOrSuspendAmbiguous);
    for (evidence, now) in [(&evidence_roll, &now_roll), (&evidence_boot, &now_boot), (&evidence_skew, &now_skew), (&evidence_ok, &now_susp)] {
        let freshness = action_expiry::assess_cleanup(evidence, now, policy);
        assert_ne!(freshness, Freshness::Fresh);
        assert_eq!(decide_set_allowed_from_assessed(&active, freshness).unwrap_err().code(), "recovery-indeterminate");
        let err = action_recovery::authorize_set_via_expiry(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &active, freshness).unwrap_err();
        assert_eq!(err.code(), "recovery-indeterminate");
    }
    // Cross-boot monotonic alone is indeterminate (Unknown/Stale), never Active.
    assert!(matches!(action_expiry::assess_expiry(&mark("boot-7", 0), &mark("boot-8", 0), 900), ExpiryState::Indeterminate { .. }));
    assert_eq!(action_expiry::require_same_boot(&mark("boot-7", 0), &mark("boot-8", 0)).unwrap_err().code(), "expiry-indeterminate");
    // Explicit cancel and admitted-NULL release stay permitted under indeterminate time.
    assert!(action_recovery::authorize_cancel_via_expiry(1, 1).is_ok());
    let cur1 = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 1).expect("cur1");
    let rel = action_recovery::authorize_release_via_expiry(&rel_admitted, &rel_preview, &cur1, &route, &DispatchCancel::new(), deadline_5s(), &active, Freshness::Unknown).expect("NULL allowed");
    assert_eq!(rel.value(), &[0x00]);
    assert!(rel.is_release());
    assert_eq!(wall(1_699_999_000_000).as_millis(), 1_699_999_000_000);
}

#[tokio::test(flavor = "current_thread")]
async fn inaccessible_peer_timeout_abort_unknown_never_resend() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    assert_eq!(classify_peer_protocol(&ProtocolResult::Timeout), PeerAcceptance::NotAcceptedNeedsReconcile);
    assert_eq!(classify_peer_protocol(&ProtocolResult::Abort(10)), PeerAcceptance::NotAcceptedNeedsReconcile);
    assert_eq!(classify_peer_protocol(&ProtocolResult::Abort(0)), PeerAcceptance::NotAcceptedNeedsReconcile);
    assert_eq!(classify_peer_protocol(&ProtocolResult::TransportFailure), PeerAcceptance::NotAcceptedNeedsReconcile);
    assert_eq!(classify_peer_protocol(&ProtocolResult::InvalidReply), PeerAcceptance::NotAcceptedNeedsReconcile);
    assert_eq!(classify_peer_protocol(&ProtocolResult::Confirmed), PeerAcceptance::Accepted);
    assert_eq!(classify_peer_protocol(&ProtocolResult::Reject(1)), PeerAcceptance::NotAcceptedNeedsReconcile);
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "rec-peer-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::DropAfterAccept).await;
    let route = harness.fixture.route("ahu-1");
    let err = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.unwrap_err();
    assert_eq!(err.code(), "dispatch-unknown");
    match &err {
        DispatchError::Unknown { operation, attempt, .. } => {
            assert_eq!(operation, "rec-peer-1");
            assert_eq!(attempt, admitted.attempt().as_str());
        }
        other => panic!("wrong variant {other:?}"),
    }
    assert_eq!(harness.fixture.sent_count(), 1);
    assert_eq!(harness.fixture.requests().len(), 1);
    let requests = harness.fixture.requests();
    harness.finish("rec-peer-unknown", &requests).await;
    // Never resend: reconcile recovers the same single row without a second send.
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let recovered = action_recovery::reconcile_journal(&journal, &operation("rec-peer-1"), &scope_a()).expect("reconcile");
    assert_eq!(recovered.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
    assert!(recovered.reconciled());
}

#[test]
fn restored_old_journal_refuse_stale_conflict_intact() {
    // Same-ID-different-content refuses as conflict.
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let other = preview_at(22.5);
    assert_eq!(other.encoded().wire_bits(), 0x41b40000);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    journal.admit(operation("rec-backup-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("first");
    let conflict = journal.admit(operation("rec-backup-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &other, 0).unwrap_err();
    assert_eq!(conflict.code(), "admission-conflict");
    // Stale generation refuses; current stays unaffected and nothing replays.
    journal.admit(operation("rec-backup-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &other, 1).expect("gen1");
    let stale = journal.admit(operation("rec-backup-old"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).unwrap_err();
    assert_eq!(stale.code(), "admission-stale-generation");
    match stale {
        action_journal::WriterError::StaleGeneration { expected, current } => {
            assert_eq!(expected, 0); assert_eq!(current, 2);
        }
        other => panic!("wrong variant {other:?}"),
    }
    assert_eq!(journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count")[0][0], "2");
    // Wrong store refuses as conflict via the store receipt identity.
    let other_scratch = Scratch::new();
    let other_store = Journal::open(&other_scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("other open").0;
    let _ = other_store;
    let store_a = journal.store();
    let store_b_scratch = Scratch::new();
    let (store_b, _) = storage::sqlite::SqliteStore::open(&store_b_scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("store b");
    let ticket = store_a.prepare_guarded_batch("1", "SELECT 1; SELECT last_insert_rowid(); SELECT changes();", 8).expect("ticket a");
    match store_b.submit(&ticket) {
        storage::sqlite::MutationOutcome::Conflict { .. } => {}
        other => panic!("expected wrong-store Conflict, got {other:?}"),
    }
    match action_recovery::reconcile_store_ticket(&store_b, &ticket).expect("reconcile wrapper") {
        storage::sqlite::MutationOutcome::Conflict { .. } => {}
        other => panic!("expected Conflict reconcile, got {other:?}"),
    }
    // Intact restore preserves: exact ledger match reconciles with old IDs.
    let current = journal.reconcile(&operation("rec-backup-2"), &scope_a()).expect("current");
    let (reopened, _rx2) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen intact");
    let intact = reopened.reconcile(&operation("rec-backup-2"), &scope_a()).expect("intact");
    assert_eq!(intact.payload(), current.payload());
    assert!(intact.reconciled());
    assert_eq!(action_recovery::verify_backup_against_current(true, &intact, &current).expect("intact"), BackupVerdict::IntactPreserve);
    assert_eq!(verify_backup(true, true, 2, 2), BackupVerdict::IntactPreserve);
    assert_eq!(verify_backup(true, false, 2, 2), BackupVerdict::ConflictSameIdDifferentContent);
    assert_eq!(verify_backup(true, true, 1, 2), BackupVerdict::StaleGenerationRefuse);
    assert_eq!(verify_backup(false, true, 2, 2), BackupVerdict::WrongStoreConflict);
    assert!(require_intact_backup(BackupVerdict::IntactPreserve).is_ok());
    assert_eq!(require_intact_backup(BackupVerdict::StaleGenerationRefuse).unwrap_err().code(), "recovery-conflict");
    // Old obligations keep old IDs: the first row is still generation 1.
    let old = journal.reconcile(&operation("rec-backup-1"), &scope_a()).expect("old kept");
    assert_eq!(old.target_generation(), 1);
    assert_eq!(old.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
}

#[tokio::test(flavor = "current_thread")]
async fn peer_acceptance_before_journal_ordering() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    assert_eq!(check_peer_accepted_before_journal(true, true).expect("peer first"), OrderingVerdict::JournalMayFollowPeer);
    assert_eq!(check_peer_accepted_before_journal(true, false).expect("peer only"), OrderingVerdict::JournalMayFollowPeer);
    assert_eq!(check_peer_accepted_before_journal(false, false).expect("neither"), OrderingVerdict::JournalMustNotPrecedePeer);
    assert_eq!(check_peer_accepted_before_journal(false, true).unwrap_err().code(), "recovery-conflict");
    assert_eq!(action_recovery::require_peer_accepted_before_journal(true, true).expect("wrapper"), OrderingVerdict::JournalMayFollowPeer);
    // Journal admission alone never proves peer acceptance.
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "rec-order-1", &preview, 0);
    assert!(!admitted.reconciled());
    assert!(!admitted.is_dispatch());
    assert_eq!(admitted.journal_format(), "verdant-action-journal-v1");
    // Only a confirmed harness outcome counts as acceptance; then journal may follow.
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.expect("confirmed");
    assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
    assert_eq!(outcome.slot().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert_eq!(outcome.audit().effective_retries(), 0);
    assert!(outcome.source_time().is_none());
    assert_eq!(action_recovery::peer_acceptance(outcome.protocol()), PeerAcceptance::Accepted);
    assert!(check_peer_accepted_before_journal(true, true).is_ok());
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 3);
    harness.finish("rec-order", &requests).await;
}

#[test]
fn later_conflicting_requests_wait_qualified_recovery_no_lease_quiescence() {
    assert_eq!(assess_conflicting_request(false, false, false, QuiescenceClaim::ObservedJoin).expect("wait"), ConflictWait::Wait);
    assert_eq!(assess_conflicting_request(true, false, false, QuiescenceClaim::ObservedJoin).expect("wait"), ConflictWait::Wait);
    assert_eq!(assess_conflicting_request(true, true, false, QuiescenceClaim::ObservedJoin).expect("wait"), ConflictWait::Wait);
    assert_eq!(assess_conflicting_request(true, true, true, QuiescenceClaim::ObservedJoin).expect("qualified"), ConflictWait::QualifiedRecoveryRequired);
    assert_eq!(assess_conflicting_request(true, true, true, QuiescenceClaim::HandleDropped).unwrap_err().code(), "recovery-conflict");
    assert_eq!(assess_conflicting_request(true, true, true, QuiescenceClaim::LeaseExpired).unwrap_err().code(), "recovery-conflict");
    assert_eq!(action_recovery::require_qualified_recovery(true, true, true, QuiescenceClaim::ObservedJoin).expect("wrapper"), ConflictWait::QualifiedRecoveryRequired);
    // Live: a stale later request waits; retained rows never replay as new work.
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let preview2 = preview_at(22.5);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    journal.admit(operation("rec-wait-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("gen0");
    journal.admit(operation("rec-wait-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview2, 1).expect("gen1");
    let before: String = journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count")[0][0].clone();
    assert_eq!(before, "2");
    let stale = journal.admit(operation("rec-wait-late"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).unwrap_err();
    assert_eq!(stale.code(), "admission-stale-generation");
    let after: String = journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count")[0][0].clone();
    assert_eq!(after, "2");
    // Transport ownership + peer state must reconcile first for the conflicting generation.
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let old = journal.reconcile(&operation("rec-wait-1"), &scope_a()).expect("old");
    assert!(action_recovery::require_reconciled_peer_and_transport(&old, &preview, &current_gen(0), &route).is_ok());
    let wrong = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 99).expect("wrong gen");
    assert_eq!(action_recovery::require_reconciled_peer_and_transport(&old, &preview, &wrong, &route).unwrap_err().code(), "dispatch-stale-generation");
}

#[test]
fn subsequent_observations_preserved_by_full_identity_not_slot_value() {
    let gen_a = SourceGenerationId::parse("gen-1").expect("gen-a");
    let gen_b = SourceGenerationId::parse("gen-2").expect("gen-b");
    let old = RecordIdentity::new(gen_a, 41);
    let same_seq_new_gen = RecordIdentity::new(gen_b, 41);
    let same = RecordIdentity::new(SourceGenerationId::parse("gen-1").expect("gen"), 41);
    assert_eq!(classify_observation(&old, &same), ObservationVerdict::SameRecord);
    assert_eq!(classify_observation(&old, &same_seq_new_gen), ObservationVerdict::DifferentRecord);
    assert!(!old.is_same_record(&same_seq_new_gen));
    assert!(old.is_same_record(&same));
    assert!(require_same_record(&old, &same).is_ok());
    assert_eq!(require_same_record(&old, &same_seq_new_gen).unwrap_err().code(), "recovery-conflict");
    assert!(action_recovery::is_same_record(&old, &same));
    assert!(!action_recovery::is_same_record(&old, &same_seq_new_gen));
    assert!(action_recovery::require_same_observation(&old, &same).is_ok());
    // Equal slot values are never ownership proof.
    assert!(!action_recovery::slot_value_proves_ownership());
    assert_eq!(old.to_json(), "{\"generation\":\"gen-1\",\"seq\":\"41\"}");
    // Telemetry generation is separate from field-writer exclusion: a stale
    // producer checkpoint mints a fresh generation before emission (M02-PR03
    // precedent); intact means the exact ledger match.
    let gate_scratch = Scratch::new();
    let (gate, creds) = access::AccessGate::bootstrap(&gate_scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny(), &access::Reason::parse("synthetic PR11 observation").expect("reason")).expect("bootstrap");
    let mut receiver = observation::index::SyntheticReceiver::new(SourceGenerationId::parse("synthetic-receiver-pr11").expect("ns"), 8).expect("receiver");
    let producer = receiver.start(&gate, Some(&creds.reviewer), scope_a(), observation::identity::ProducerId::parse("sensor-sat-1").expect("producer"), observation::identity::ProducerIncarnation::parse("process-a").expect("incarnation")).expect("start");
    let checkpoint = producer.checkpoint();
    let intact = receiver.resume(&gate, Some(&creds.reviewer), checkpoint.clone(), observation::identity::ProducerIncarnation::parse("process-a").expect("incarnation")).expect("intact resume keeps generation");
    assert_eq!(intact.checkpoint().generation().as_str(), checkpoint.generation().as_str());
    assert_eq!(intact.checkpoint().next_sequence(), checkpoint.next_sequence());
    // Rollback mints a fresh generation before emission even if values equal:
    // a checkpoint from a different namespace (same scope/producer, different
    // generation) fences to a new generation with next 0 (M02-PR03 precedent).
    let mut other = observation::index::SyntheticReceiver::new(SourceGenerationId::parse("synthetic-receiver-pr11-other").expect("ns"), 8).expect("other receiver");
    let other_producer = other.start(&gate, Some(&creds.reviewer), scope_a(), observation::identity::ProducerId::parse("sensor-sat-1").expect("producer"), observation::identity::ProducerIncarnation::parse("process-b").expect("incarnation")).expect("other start");
    let stale_checkpoint = other_producer.checkpoint();
    assert_ne!(stale_checkpoint.generation().as_str(), checkpoint.generation().as_str());
    let fenced = receiver.resume(&gate, Some(&creds.reviewer), stale_checkpoint.clone(), observation::identity::ProducerIncarnation::parse("process-b").expect("incarnation")).expect("rollback fences");
    assert_ne!(fenced.checkpoint().generation().as_str(), stale_checkpoint.generation().as_str());
    assert_eq!(fenced.checkpoint().next_sequence(), 0);
    // Unknown scoped identity never reconciles: full identity required.
    assert_eq!(gate_scratch.db().exists(), true);
}

#[test]
fn limits_constrain_profile_delayed_packets_third_party_unbounded() {
    assert_eq!(action_recovery::RECOVERY_FORMAT, "verdant-recovery-v1");
    for phrase in ["delayed-packets-may-take-effect-later", "third-party-writers-outside-transport-ownership-unbounded", "null-release-may-reveal-other-system-command", "one-call-is-not-one-send", "timeout-uncertain-never-resend", "synthetic-budgets-not-host-quotas", "no-power-loss-disk-full-real-time-claim"] {
        assert!(action_recovery::LIMITS.contains(phrase), "{phrase}");
    }
    // One call is not one send by assumption: audit counts effective sends.
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    assert_eq!(preview.timing().duration_secs(), 900);
    assert_eq!(preview.timing().deadline_secs(), 5);
    assert_eq!(preview.timing().apdu_retries(), 0);
    assert_eq!(preview.timing().rate_per_hour(), 6);
    assert_eq!(preview.feedback().status(), "unavailable-feedback");
    assert!(preview.feedback().source_time().is_none());
    assert!(!preview.is_reservation());
    assert!(!preview.is_dispatch());
    assert!(!preview.is_qualified());
    let admitted = admit_at(&scratch, "rec-limits-1", &preview, 0);
    assert_eq!(admitted.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
    // Delayed packets and third-party writers stay outside the bounded profile:
    // expiry refusal renews nothing and release reveals rather than renews.
    let expired = action_expiry::assess_expiry(&mark("boot-7", 0), &mark("boot-7", 900_000_000_000), 900);
    assert!(expired.is_expired());
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert_eq!(action_recovery::authorize_set_via_expiry(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &expired, Freshness::Fresh).unwrap_err().code(), "expiry-expired");
}
