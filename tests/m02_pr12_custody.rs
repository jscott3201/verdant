//! M02-PR12 maintenance, offboarding and current custody, HARNESS-ONLY.
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
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "accept_cases/support.rs"]
mod support;

use access::RoleKind;
use action_custody::{CustodyHold, HoldKind, ScopeHolds};
use action_dispatch::{Current, DispatchCancel, FrozenRoute, ProtocolResult};
use action_expiry::ExpiryState;
use action_journal::Journal;
use action_preview::{Precondition, Preview, SealOrder};
use action_publication::{ImpactGate, OldWriterExclusion};
use binding::BindingStatus;
use domain::ids::{BindingRevision, InstalledId, OperationId, SourceGenerationId};
use domain::outcomes::RecordIdentity;
use domain::scope::TrustedScope;
use domain::values::Unit;
use observation::time::{Continuity, Freshness, FreshnessPolicy};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use storage::{ConnectionSettings, StoreBounds};

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("verdant-m02-pr12-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).expect("isolated scratch");
        Self(dir)
    }
    fn db(&self) -> std::path::PathBuf { self.0.join("store.db") }
}
impl Drop for Scratch {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).expect("cleanup scratch"); }
}
fn scope_a() -> TrustedScope { TrustedScope::parse("scope-a").expect("frozen scope-a") }
fn scope_b() -> TrustedScope { TrustedScope::parse("scope-b").expect("frozen scope-b") }
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
fn journal_count(scratch: &Scratch) -> String {
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count")[0][0].clone()
}
const PAYLOAD_22: &str = "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish";

#[test]
fn scoped_hold_blocks_held_scope_other_proceeds_pending_kept() {
    assert_eq!(action_custody::CUSTODY_FORMAT, "verdant-custody-v1");
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    assert_eq!(preview.canonical_bytes(), PAYLOAD_22);
    let admitted = admit_at(&scratch, "custody-hold-1", &preview, 0);
    assert_eq!(journal_count(&scratch), "1");
    let mut holds = ScopeHolds::new();
    assert!(holds.is_empty());
    holds.hold("scope-a", HoldKind::Active, "synthetic PR12 maintenance").expect("hold scope-a");
    assert!(holds.is_held("scope-a"));
    assert!(!holds.is_held("scope-b"));
    assert_eq!(holds.len(), 1);
    // Held scope blocks new handoffs; other scopes proceed.
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let err = action_custody::authorize_setpoint_via_custody(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).unwrap_err();
    assert_eq!(err.code(), "custody-held");
    assert!(err.to_string().contains("scope-a"));
    assert!(holds.check_not_held("scope-b").is_ok());
    // Pending rows kept, never erased.
    assert_eq!(journal_count(&scratch), "1");
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let kept = action_custody::reconcile_journal_via_custody(&journal, &operation("custody-hold-1"), &scope_a()).expect("pending kept");
    assert_eq!(kept.operation().as_str(), "custody-hold-1");
    assert_eq!(kept.payload(), PAYLOAD_22);
    // Explicit per-scope release restores the held scope; no all-slot reset exists.
    holds.release("scope-a").expect("release");
    assert!(!holds.is_held("scope-a"));
    assert!(action_custody::authorize_setpoint_via_custody(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).is_ok());
    // Frozen profile stays verbatim.
    assert_eq!(preview.timing().duration_secs(), 900);
    assert_eq!(preview.timing().deadline_secs(), 5);
    assert_eq!(preview.timing().apdu_retries(), 0);
    assert_eq!(preview.timing().rate_per_hour(), 6);
    assert_eq!(preview.feedback().status(), "unavailable-feedback");
    assert!(preview.feedback().source_time().is_none());
    assert!(!preview.is_reservation() && !preview.is_dispatch() && !preview.is_qualified());
}

#[test]
fn outstanding_inspection_lists_pending_within_scope_cross_scope_nondisclosure() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let other = preview_at(22.5);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    journal.admit(operation("custody-insp-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("gen0");
    journal.admit(operation("custody-insp-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &other, 1).expect("gen1");
    let listed = action_custody::inspect_outstanding(&journal, &scope_a()).expect("inspect scope-a");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].operation().as_str(), "custody-insp-1");
    assert_eq!(listed[1].operation().as_str(), "custody-insp-2");
    assert_eq!(listed[0].equipment().as_str(), "ahu-1");
    assert_eq!(listed[0].actor(), "publisher-1/scope-a");
    assert_eq!(listed[0].scope().as_str(), "scope-a");
    // Cross-scope nondisclosure: scope-b sees nothing, never scope-a rows.
    let foreign = action_custody::inspect_outstanding(&journal, &scope_b()).expect("inspect scope-b");
    assert!(foreign.is_empty());
    assert_eq!(journal.reconcile(&operation("custody-insp-1"), &scope_b()).unwrap_err().code(), "admission-not-found");
    assert_eq!(journal_count(&scratch), "2");
    // Pure visibility gate is exact equality.
    assert!(action_custody::policy::inspection_visible("scope-a", "scope-a"));
    assert!(!action_custody::policy::inspection_visible("scope-a", "scope-b"));
}

#[tokio::test(flavor = "current_thread")]
async fn revocation_before_handoff_refuses_zero_sends() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let gate_dir = std::env::temp_dir().join(format!("verdant-m02-pr12-gate-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir(&gate_dir).expect("gate scratch");
    let gate_db = gate_dir.join("gate.db");
    let (gate, creds) = access::AccessGate::bootstrap(&gate_db, ConnectionSettings::local_wal_full(), StoreBounds::tiny(), &access::Reason::parse("synthetic PR12 revoke").expect("reason")).expect("bootstrap");
    // Access entry composes ceilings and ActorContext before the handoff.
    gate.enter_review(Some(&creds.publisher), &scope_a()).expect("review enters");
    gate.enter_publish(Some(&creds.publisher), &scope_a()).expect("publish enters");
    let actor = gate.authenticate(Some(&creds.publisher), &scope_a()).expect("actor");
    assert_eq!(actor.capability(), "publisher-1");
    assert_eq!(actor.ceiling().level(), 2);
    assert_eq!(actor.role(), RoleKind::Publisher);
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "custody-revoke-pre-1", &preview, 0);
    gate.revoke(&creds.publisher, &access::Reason::parse("synthetic PR12 offboarding").expect("reason")).expect("revoke");
    assert!(gate.is_revoked(creds.publisher.capability(), creds.publisher.key_id()).expect("read revocation"));
    assert_eq!(gate.revocation_reason(creds.publisher.capability(), creds.publisher.key_id()).expect("reason").expect("some"), "synthetic PR12 offboarding");
    assert_eq!(gate.enter_publish(Some(&creds.publisher), &scope_a()).unwrap_err().code(), "revoked-credential");
    let holds = ScopeHolds::new();
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let err = action_custody::authorize_setpoint_via_custody(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, None, true, &ImpactGate::Preserved).unwrap_err();
    assert_eq!(err.code(), "custody-revoked");
    assert_eq!(harness.fixture.sent_count(), 0);
    assert!(harness.fixture.requests().is_empty());
    harness.finish("custody-revoke-pre", &[]).await;
    // Authorship plus original obligations kept after credentials expire/revoke.
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let kept = journal.reconcile(&operation("custody-revoke-pre-1"), &scope_a()).expect("old kept");
    assert_eq!(kept.actor(), "publisher-1/scope-a");
    assert_eq!(kept.payload(), PAYLOAD_22);
    assert_eq!(journal_count(&scratch), "1");
    std::fs::remove_dir_all(&gate_dir).expect("cleanup");
}

#[tokio::test(flavor = "current_thread")]
async fn revocation_after_handoff_unknown_until_reconcile_never_resend() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let scratch = Scratch::new();
    let preview = preview_release(true);
    let admitted = admit_at(&scratch, "custody-revoke-post-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::DropAfterAccept).await;
    let route = harness.fixture.route("ahu-1");
    let err = action_dispatch::harness::execute_release(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture).await.unwrap_err();
    assert_eq!(err.code(), "dispatch-unknown");
    assert_eq!(harness.fixture.sent_count(), 1);
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 1);
    harness.finish("custody-revoke-post", &requests).await;
    // Post-handoff revocation cannot recall: UNKNOWN until reconcile, never resend.
    assert_eq!(action_custody::require_peer_accepted_before_journal_via_custody(false, true).unwrap_err().code(), "recovery-conflict");
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let pending = action_expiry::PendingRelease::from_admitted(&admitted);
    let recovered = action_custody::reconcile_pending_release_via_custody(&pending, &journal).expect("reconcile");
    assert_eq!(recovered.operation().as_str(), "custody-revoke-post-1");
    assert!(recovered.reconciled());
    assert_eq!(recovered.payload(), PAYLOAD_22);
    // Pending cleanup survives visible in scope.
    let listed = action_custody::inspect_outstanding(&journal, &scope_a()).expect("inspect");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].operation().as_str(), "custody-revoke-post-1");
    assert_eq!(journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count")[0][0], "1");
}

#[test]
fn expired_contractor_transfer_narrow_new_admission() {
    let gate_dir = std::env::temp_dir().join(format!("verdant-m02-pr12-xfer-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir(&gate_dir).expect("gate scratch");
    let gate_db = gate_dir.join("gate.db");
    let (gate, creds) = access::AccessGate::bootstrap(&gate_db, ConnectionSettings::local_wal_full(), StoreBounds::tiny(), &access::Reason::parse("synthetic PR12 transfer").expect("reason")).expect("bootstrap");
    // Active permitted successor issued before offboarding (no broadening here).
    let successor = gate.issue_with_policy(&access::CapabilityName::parse("publisher-2").expect("cap"), &scope_a(), 2, RoleKind::Publisher, &access::KeyId::parse("key-publisher-2").expect("key"), &access::SyntheticKey::parse("synthetic-publisher-2-key").expect("synkey"), &creds.publisher, &access::Reason::parse("synthetic PR12 successor").expect("reason"), &access::DisplayLabel::parse("synthetic").expect("label"), &access::CapabilityPolicy::entry_only(None)).expect("issue successor");
    gate.enter_publish(Some(&successor), &scope_a()).expect("successor permitted");
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let old = journal.admit(operation("custody-xfer-old-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("old gen0");
    assert_eq!(old.actor(), "publisher-1/scope-a");
    assert_eq!(old.payload(), PAYLOAD_22);
    // Offboard the expired contractor; authorship stays on the old row.
    gate.revoke(&creds.publisher, &access::Reason::parse("synthetic PR12 contractor expired").expect("reason")).expect("revoke old");
    assert!(gate.is_revoked(creds.publisher.capability(), creds.publisher.key_id()).expect("revoked"));
    assert!(!gate.is_revoked(successor.capability(), successor.key_id()).expect("successor active"));
    assert_eq!(gate.enter_publish(Some(&creds.publisher), &scope_a()).unwrap_err().code(), "revoked-credential");
    gate.enter_publish(Some(&successor), &scope_a()).expect("successor still permitted");
    let exclusion = OldWriterExclusion::exclude("operator-1/scope-a", "publisher-1/scope-a", "synthetic PR12 transfer narrow").expect("explicit exclusion");
    assert!(exclusion.excludes("publisher-1/scope-a"));
    assert!(!exclusion.excludes("publisher-2/scope-a"));
    let holds = ScopeHolds::new();
    // TRANSFER NARROW: NEW admission by the active role plus old exclusion.
    let moved = action_custody::transfer_narrow_via_new_admission(&mut journal, &old, operation("custody-xfer-new-1"), scope_a(), 2, RoleKind::Publisher, "publisher-2/scope-a", &preview, 1, &holds, Some(&exclusion), true).expect("transfer narrow");
    assert_eq!(moved.operation().as_str(), "custody-xfer-new-1");
    assert_eq!(moved.actor(), "publisher-2/scope-a");
    assert_eq!(moved.payload(), PAYLOAD_22);
    assert_eq!(moved.target_generation(), 2);
    // Old IDs and authorship preserved; old actor excluded; no broadening.
    let kept = journal.reconcile(&operation("custody-xfer-old-1"), &scope_a()).expect("old preserved");
    assert_eq!(kept.operation().as_str(), "custody-xfer-old-1");
    assert_eq!(kept.actor(), "publisher-1/scope-a");
    assert_eq!(kept.payload(), PAYLOAD_22);
    assert_eq!(kept.target_generation(), 1);
    assert_eq!(journal_count(&scratch), "2");
    // Narrowness refusals: same operation, same actor, missing exclusion, unpermitted successor.
    assert_eq!(action_custody::transfer_narrow_via_new_admission(&mut journal, &old, operation("custody-xfer-old-1"), scope_a(), 2, RoleKind::Publisher, "publisher-2/scope-a", &preview, 1, &holds, Some(&exclusion), true).unwrap_err().code(), "custody-transfer");
    assert_eq!(action_custody::transfer_narrow_via_new_admission(&mut journal, &old, operation("custody-xfer-new-9"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 1, &holds, Some(&exclusion), true).unwrap_err().code(), "custody-transfer");
    assert_eq!(action_custody::transfer_narrow_via_new_admission(&mut journal, &old, operation("custody-xfer-new-9"), scope_a(), 2, RoleKind::Publisher, "publisher-2/scope-a", &preview, 1, &holds, None, true).unwrap_err().code(), "custody-transfer");
    assert_eq!(action_custody::transfer_narrow_via_new_admission(&mut journal, &old, operation("custody-xfer-new-9"), scope_a(), 2, RoleKind::Publisher, "publisher-2/scope-a", &preview, 1, &holds, Some(&exclusion), false).unwrap_err().code(), "custody-transfer");
    std::fs::remove_dir_all(&gate_dir).expect("cleanup");
}

#[test]
fn active_and_masked_holds_on_own_generation_no_escalation() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "custody-mask-1", &preview, 0);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    // Active hold on scope-a blocks its own generation; scope-b proceeds.
    let mut holds = ScopeHolds::new();
    holds.hold("scope-a", HoldKind::Active, "synthetic PR12 active maintenance").expect("active hold");
    assert_eq!(holds.check_not_held("scope-a").unwrap_err().code(), "custody-held");
    assert!(holds.check_not_held("scope-b").is_ok());
    assert_eq!(action_custody::authorize_setpoint_via_custody(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).unwrap_err().code(), "custody-held");
    // Masked hold replaces on the same scope: masked intent still held on its own generation.
    holds.hold("scope-a", HoldKind::Masked, "synthetic PR12 masked maintenance").expect("masked hold");
    assert_eq!(holds.check_not_held("scope-a").unwrap_err().code(), "custody-held");
    assert!(holds.check_not_held("scope-b").is_ok());
    assert_eq!(action_custody::authorize_setpoint_via_custody(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).unwrap_err().code(), "custody-held");
    // No escalation: masking never authorizes protected priorities and never widens scope.
    assert_eq!(action_preview::Priority::new(2).expect("priority 2 parses").check_commissioned().unwrap_err().code(), "preview-protected-priority");
    assert_eq!(preview.priority().get(), 8);
    assert_eq!(journal_count(&scratch), "1");
    let hold = CustodyHold::hold("scope-a", HoldKind::Masked, "synthetic PR12 masked").expect("hold value");
    assert!(hold.holds("scope-a"));
    assert!(!hold.holds("scope-b"));
    assert_eq!(hold.kind(), HoldKind::Masked);
}

#[test]
fn canceled_work_idempotent_duplicate_cancel_zero_rows() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let pending = journal.prepare(operation("custody-cancel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("prepare");
    assert_eq!(pending.operation().as_str(), "custody-cancel-1");
    action_custody::cancel_pending(pending);
    let count: String = journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count").into_iter().next().expect("row")[0].clone();
    assert_eq!(count, "0");
    assert_eq!(journal.essential_announced(), 0);
    assert_eq!(journal.history_announced(), 0);
    assert_eq!(action_custody::reconcile_journal_via_custody(&journal, &operation("custody-cancel-1"), &scope_a()).unwrap_err().code(), "admission-not-found");
    // Duplicate cancel of the same unattempted identities also emits nothing.
    let pending2 = journal.prepare(operation("custody-cancel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("prepare again");
    action_custody::cancel_pending(pending2);
    let count2: String = journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count").into_iter().next().expect("row")[0].clone();
    assert_eq!(count2, "0");
    assert_eq!(action_custody::authorize_cancel_via_custody(0, 0).expect("cancel equal"), ());
    assert_eq!(action_custody::authorize_cancel_via_custody(0, 1).unwrap_err().code(), "expiry-stale-generation");
}

#[test]
fn unauthorized_other_person_release_refused() {
    let scratch = Scratch::new();
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let holds = ScopeHolds::new();
    // Non-admitted NULL refuses before any send.
    let denied_preview = preview_release(false);
    let denied = admit_at(&scratch, "custody-rel-deny-1", &denied_preview, 0);
    let err = action_custody::authorize_release_via_custody(&denied, &denied_preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).unwrap_err();
    assert_eq!(err.code(), "dispatch-null-not-admitted");
    // Other-person release refuses on actor equality even for an admitted NULL.
    let scratch2 = Scratch::new();
    let ok_preview = preview_release(true);
    let ok_admitted = admit_at(&scratch2, "custody-rel-ok-1", &ok_preview, 0);
    let other = Current::new("publisher-9/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 0).expect("other actor");
    let err = action_custody::authorize_release_via_custody(&ok_admitted, &ok_preview, &other, &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).unwrap_err();
    assert_eq!(err.code(), "dispatch-invalid");
    // The admitted NULL still authorizes for its own actor only.
    let own = action_custody::authorize_release_via_custody(&ok_admitted, &ok_preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).expect("own release");
    assert_eq!(own.value(), &[0x00]);
    assert!(own.is_release());
    assert!(own.wire_bits().is_none());
}

#[test]
fn ambiguous_slot_ownership_visible_full_identity() {
    let gen_a = SourceGenerationId::parse("gen-1").expect("gen-a");
    let gen_b = SourceGenerationId::parse("gen-2").expect("gen-b");
    let old = RecordIdentity::new(gen_a, 41);
    let same_seq_new_gen = RecordIdentity::new(gen_b, 41);
    let same = RecordIdentity::new(SourceGenerationId::parse("gen-1").expect("gen"), 41);
    assert!(action_custody::is_same_record(&old, &same));
    assert!(!action_custody::is_same_record(&old, &same_seq_new_gen));
    assert!(action_custody::require_same_observation_via_custody(&old, &same).is_ok());
    assert_eq!(action_custody::require_same_observation_via_custody(&old, &same_seq_new_gen).unwrap_err().code(), "recovery-conflict");
    // Equal slot values never prove ownership; ownership stays visible as ambiguous.
    assert!(!action_custody::slot_value_proves_ownership_via_custody());
    assert!(!action_custody::policy::slot_value_proves_ownership());
    assert_eq!(old.to_json(), "{\"generation\":\"gen-1\",\"seq\":\"41\"}");
    // Backup REFUSE STALE keeps old obligations with old IDs.
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let other = preview_at(22.5);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    journal.admit(operation("custody-obs-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("gen0");
    journal.admit(operation("custody-obs-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &other, 1).expect("gen1");
    let cur = journal.reconcile(&operation("custody-obs-2"), &scope_a()).expect("current");
    let stale = journal.reconcile(&operation("custody-obs-1"), &scope_a()).expect("old kept");
    assert!(action_custody::verify_backup_against_current_via_custody(true, &stale, &cur).is_err());
    assert!(action_custody::verify_backup_against_current_via_custody(true, &cur, &cur).is_ok());
}

#[test]
fn constrained_cleanup_limits_and_escalation() {
    assert_eq!(action_custody::CUSTODY_FORMAT, "verdant-custody-v1");
    for phrase in ["delayed-packets-may-take-effect-later", "third-party-writers-outside-transport-ownership-unbounded", "null-release-may-reveal-other-system-command", "one-call-is-not-one-send", "timeout-uncertain-never-resend", "synthetic-budgets-not-host-quotas", "no-power-loss-disk-full-real-time-claim", "custody-scoped-hold-is-evidence-not-physical-lockout"] {
        assert!(action_custody::LIMITS.contains(phrase), "{phrase}");
    }
    // Only the two constrained cleanups exist; all bypasses refuse with escalation.
    assert!(action_custody::authorize_constrained_cleanup("cancel-unattempted").is_ok());
    assert!(action_custody::authorize_constrained_cleanup("admitted-null-release").is_ok());
    for forbidden in ["loto", "emergency-stop", "all-slot-reset", "delete-actor-history", "broad-grant", "notify-bypass", "work-bypass", "mcp-bypass"] {
        let err = action_custody::authorize_constrained_cleanup(forbidden).unwrap_err();
        assert_eq!(err.code(), "custody-constrained");
        assert!(err.to_string().contains("escalate to owner via qualified recovery"), "{forbidden}");
        assert!(err.to_string().contains(forbidden), "{forbidden}");
    }
    // Failures expose limits plus escalation, never promised release.
    let err = action_custody::policy::authorize_constrained_cleanup("all-slot-reset").unwrap_err();
    assert_eq!(err.code(), "custody-constrained");
    // Publication impact, activation currency, alias, and ordering compose without bypass.
    let mut f = fixture::Fixture::new();
    let old = support::config(&mut f, "AHU supply air");
    let cosmetic = support::config(&mut f, "AHU supply air relabeled");
    let diff = cosmetic.impact_from(&old);
    assert!(action_publication::assess_impact(&diff).is_preserved());
    assert!(action_custody::require_aliases_unique_via_custody(&["ahu-1-sp", "vav-101-sp"]).is_ok());
    assert_eq!(action_custody::require_aliases_unique_via_custody(&["ahu-1-sp", "ahu-1-sp"]).unwrap_err().code(), "duplicate-identity");
    assert!(action_custody::require_peer_accepted_before_journal_via_custody(true, true).is_ok());
    assert_eq!(action_custody::require_peer_accepted_before_journal_via_custody(false, true).unwrap_err().code(), "recovery-conflict");
    // Checked generation never wraps.
    assert_eq!(action_custody::policy::next_generation(u32::MAX).unwrap_err().code(), "custody-invalid");
    assert_eq!(action_custody::policy::next_generation(0).expect("next"), 1);
    let _ = FreshnessPolicy::new(Duration::from_secs(900), Duration::from_secs(5)).expect("harness policy 900s/5s");
    let _ = Continuity::Confirmed;
    assert_eq!(action_custody::policy::check_pre_handoff_not_revoked(false, "publisher-1/scope-a").expect("not revoked"), ());
    assert_eq!(action_custody::policy::check_pre_handoff_not_revoked(true, "publisher-1/scope-a").unwrap_err().code(), "custody-revoked");
}
