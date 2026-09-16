//! M02 Slice-B regressions: durable lifecycle, owned 6/hour + 5s wall anchor,
//! durable custody predecessor link, bounded outstanding. SYNTHETIC-ONLY,
//! HARNESS-ONLY.
//!
//! Frozen profile verbatim: BACnet/IP AV `presentValue` on `tiny_site`
//! (`ahu-1`/`vav-101`, `scope-a`); AV2/PV85/P8; `degC` 20-24 tol 0.1;
//! 15min/5s/APDU_RETRIES(0)/6h; PV `unavailable-feedback`, `source_time` None.
//! Secs 4/7 joins stay open; M02-G promotion is HELD (not claimed here).
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
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "accept_cases/support.rs"]
mod support;

use access::RoleKind;
use action_custody::{HoldKind, ScopeHolds};
use action_dispatch::{Current, DispatchCancel, FrozenRoute};
use action_expiry::ExpiryState;
use action_journal::{Journal, LifecycleState};
use action_preview::{Precondition, Preview, SealOrder};
use action_publication::{ImpactGate, OldWriterExclusion};
use binding::BindingStatus;
use domain::ids::{BindingRevision, InstalledId, OperationId};
use domain::scope::TrustedScope;
use domain::values::Unit;
use observation::time::Freshness;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use storage::{ConnectionSettings, StoreBounds};

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("verdant-m02-sliceB-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
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
fn preview_set(setpoint: f64) -> Preview {
    Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), setpoint, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("ahu-1"), false).expect("set preview")
}
fn preview_release() -> Preview {
    Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), 22.0, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("ahu-1"), true).expect("release preview")
}
fn preview_vav_release() -> Preview {
    Preview::preview(scope_a(), equipment("vav-101"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), 22.0, None, &["vav-101-sp"], precondition_fresh(), &seal_ready(), equipment("vav-101"), true).expect("vav release")
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
fn lifecycle_count(scratch: &Scratch) -> String {
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    journal.store().exec_script("SELECT count(*) FROM action_lifecycle;").expect("count")[0][0].clone()
}

#[test]
fn lifecycle_admitted_dispatched_terminal_outstanding_history() {
    let scratch = Scratch::new();
    let preview = preview_set(22.0);
    let admitted = admit_at(&scratch, "sliceB-life-1", &preview, 0);
    assert_eq!(admitted.lifecycle(), LifecycleState::Admitted);
    assert_eq!(lifecycle_count(&scratch), "1");
    // Dispatched before the handoff decision leaves the writer.
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let dispatched = journal.mark_dispatched(&operation("sliceB-life-1"), &scope_a()).expect("dispatched");
    assert_eq!(dispatched.lifecycle(), LifecycleState::Dispatched);
    assert_eq!(dispatched.equipment().as_str(), "ahu-1");
    // Outstanding still contains dispatched (not terminal).
    let listed = action_custody::inspect_outstanding(&journal, &scope_a()).expect("outstanding");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].operation().as_str(), "sliceB-life-1");
    // Terminal on confirmed outcome: absent from outstanding, history readable, no DELETE.
    let terminal = journal.mark_terminal(&operation("sliceB-life-1"), &scope_a()).expect("terminal");
    assert_eq!(terminal.lifecycle(), LifecycleState::Terminal);
    assert!(action_custody::inspect_outstanding(&journal, &scope_a()).expect("empty").is_empty());
    let history = journal.reconcile(&operation("sliceB-life-1"), &scope_a()).expect("history");
    assert_eq!(history.lifecycle(), LifecycleState::Terminal);
    assert_eq!(history.payload(), admitted.payload());
    assert_eq!(journal_count(&scratch), "1");
    assert_eq!(lifecycle_count(&scratch), "1");
    // Terminal is final: further transitions refuse, dispatch consult refuses (no blind resend).
    assert_eq!(journal.transition(&operation("sliceB-life-1"), &scope_a(), LifecycleState::Dispatched).unwrap_err().code(), "admission-conflict");
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert_eq!(action_dispatch::prepare_setpoint(&history, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-invalid");
}

#[test]
fn lifecycle_restart_pre_handoff_reconstructs_without_old_objects() {
    let scratch = Scratch::new();
    let preview = preview_set(22.0);
    let admitted = admit_at(&scratch, "sliceB-pre-1", &preview, 0);
    assert_eq!(admitted.lifecycle(), LifecycleState::Admitted);
    // Child-process restart: drop all Rust objects, reopen from the same file.
    drop(admitted);
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("fresh owner");
    let recovered = journal.reconcile(&operation("sliceB-pre-1"), &scope_a()).expect("reconstruct");
    assert_eq!(recovered.lifecycle(), LifecycleState::Admitted);
    assert_eq!(recovered.equipment().as_str(), "ahu-1");
    assert_eq!(recovered.payload(), preview.canonical_bytes());
    assert_eq!(recovered.predecessor(), None);
    // No blind resend: lifecycle consult still permits admitted (not terminal),
    // but the decision is re-derived from durable rows, not old objects.
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert!(action_dispatch::prepare_setpoint(&recovered, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s()).is_ok());
    // Discoverable cleanup: outstanding still lists the obligation.
    assert_eq!(action_custody::inspect_outstanding(&journal, &scope_a()).expect("outstanding").len(), 1);
}

#[test]
fn lifecycle_restart_post_decision_recovers_via_bounded_scan() {
    let scratch = Scratch::new();
    let preview = preview_set(22.0);
    let other = preview_set(22.5);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    journal.admit(operation("sliceB-scan-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("gen0");
    journal.admit(operation("sliceB-scan-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &other, 1).expect("gen1");
    journal.mark_dispatched(&operation("sliceB-scan-1"), &scope_a()).expect("dispatched");
    drop(journal);
    // Fresh owner recovers via bounded durable scan (LIMIT/OFFSET), not old objects.
    let (journal2, _rx2) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("fresh");
    let page0 = journal2.outstanding_page(&scope_a(), 1, 0).expect("page0");
    let page1 = journal2.outstanding_page(&scope_a(), 1, 1).expect("page1");
    assert_eq!(page0.len(), 1);
    assert_eq!(page1.len(), 1);
    assert_ne!(page0[0].operation().as_str(), page1[0].operation().as_str());
    // Repeated invoke recovers identically (lost wake-up: drop receivers, reconcile).
    let again0 = journal2.outstanding_page(&scope_a(), 1, 0).expect("again");
    assert_eq!(again0[0].operation().as_str(), page0[0].operation().as_str());
    let recovered = journal2.reconcile(&operation("sliceB-scan-1"), &scope_a()).expect("reconcile");
    assert_eq!(recovered.lifecycle(), LifecycleState::Dispatched);
    // Custody bounded consumer agrees with the owner page.
    let listed = action_custody::inspect_outstanding_bounded(&journal2, &scope_a(), 1, 0).expect("bounded");
    assert_eq!(listed.len(), 1);
}

#[test]
fn lifecycle_post_peer_accept_pre_persist_honest_unresolved() {
    let scratch = Scratch::new();
    let preview = preview_set(22.0);
    let admitted = admit_at(&scratch, "sliceB-uncertain-1", &preview, 0);
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    journal.mark_dispatched(&operation("sliceB-uncertain-1"), &scope_a()).expect("dispatched");
    // Post-peer-accept-pre-persist crash: outcome uncertain, persist honest unresolved.
    journal.mark_unresolved(&operation("sliceB-uncertain-1"), &scope_a()).expect("unresolved");
    drop(journal);
    drop(admitted);
    let (fresh, _rx2) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("fresh");
    let recovered = fresh.reconcile(&operation("sliceB-uncertain-1"), &scope_a()).expect("reconstruct");
    assert_eq!(recovered.lifecycle(), LifecycleState::Unresolved);
    assert_eq!(recovered.equipment().as_str(), "ahu-1");
    assert_eq!(recovered.payload(), preview.canonical_bytes());
    // Honest unresolved: not terminal, still outstanding, preserved target, discoverable cleanup.
    assert!(recovered.lifecycle().is_outstanding());
    assert_eq!(action_custody::inspect_outstanding(&fresh, &scope_a()).expect("outstanding").len(), 1);
    let pending = action_expiry::PendingRelease::from_admitted(&recovered);
    let via = pending.reconcile_via(&fresh).expect("pending reconciles without resend");
    assert_eq!(via.operation().as_str(), "sliceB-uncertain-1");
}

#[test]
fn rate_seven_rapid_set_refuses_seventh_via_owner_concurrent() {
    let scratch = Scratch::new();
    // Six SET/hour admit (generations 0..5) on the same scope-equipment wall-hour.
    for (i, op) in ["sliceB-rate-1", "sliceB-rate-2", "sliceB-rate-3", "sliceB-rate-4", "sliceB-rate-5", "sliceB-rate-6"].iter().enumerate() {
        let preview = preview_set(21.0 + (i as f64) * 0.2);
        let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
        journal.admit(operation(op), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, i as u32).expect("SET admits");
    }
    assert_eq!(journal_count(&scratch), "6");
    // Seventh rapid SET refuses through owner accounting, not the pure helper.
    let preview7 = preview_set(22.0);
    let (mut journal7, _rx7) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let err = journal7.admit(operation("sliceB-rate-7"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview7, 6).unwrap_err();
    assert_eq!(err.code(), "admission-rate-exceeded");
    // Pure helper agrees on the bound but the owner is the authority.
    assert_eq!(preview7.timing().check_rate(6).unwrap_err().code(), "preview-rate-exceeded");
    assert!(preview7.timing().check_rate(5).is_ok());
    // Concurrent 7th/8th attempts also refuse via the guarded batch.
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut threads = Vec::new();
    for op in ["sliceB-rate-c1", "sliceB-rate-c2"] {
        let barrier = barrier.clone();
        let db = scratch.db();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            let preview = preview_set(22.0);
            let (mut journal, _rx) = Journal::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("thread open");
            journal.admit(operation(op), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 6).map(|_| "admitted").map_err(|e| e.code().to_string())
        }));
    }
    let mut refused = 0;
    for t in threads {
        let result = t.join().expect("thread");
        assert!(result.is_err(), "concurrent SET beyond quota must refuse");
        assert_eq!(result.unwrap_err(), "admission-rate-exceeded");
        refused += 1;
    }
    assert_eq!(refused, 2);
    assert_eq!(journal_count(&scratch), "6");
    // SET-full queue still admits constrained admitted-null-release (exempt capacity).
    let rel = preview_release();
    let (mut journal_rel, _rxr) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let cleanup = journal_rel.admit(operation("sliceB-rate-rel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &rel, 6).expect("exempt cleanup admits");
    assert_eq!(cleanup.action_kind(), Some(action_journal::ActionKind::Release));
    assert_eq!(journal_count(&scratch), "7");
}

#[test]
fn deadline_wall_delayed_queue_cannot_renew_and_restart_indeterminate() {
    let scratch = Scratch::new();
    let preview = preview_set(22.0);
    let admitted = admit_at(&scratch, "sliceB-deadline-1", &preview, 0);
    let created = admitted.created_secs();
    assert!(created > 0, "durable wall anchor persisted");
    // Delayed queue: wall age 6s >= 5s deadline is expired even with a fresh Instant.
    let wall_expired = action_expiry::assess_deadline_wall(created, created + 6, 5);
    assert_eq!(wall_expired, ExpiryState::Expired { elapsed_secs: 6, duration_secs: 5 });
    let fresh_deadline = Instant::now() + Duration::from_secs(5);
    // Fresh Instant is in the future, but the durable wall still refuses SET.
    assert!(fresh_deadline > Instant::now());
    let err = action_expiry::decide_set_with_wall_anchor(&ExpiryState::Active, Freshness::Fresh, created, created + 6, 5).unwrap_err();
    assert_eq!(err.code(), "expiry-expired");
    // Inside the window still allows SET.
    assert!(action_expiry::decide_set_with_wall_anchor(&ExpiryState::Active, Freshness::Fresh, created, created + 4, 5).is_ok());
    // Restart across expiry + wall rollback is indeterminate: SET refused, admitted NULL permitted.
    let wall_rollback = action_expiry::assess_deadline_wall(created, created - 1, 5);
    assert_eq!(wall_rollback, ExpiryState::Indeterminate { reason: "wall-rollback" });
    let err = action_expiry::decide_set_with_wall_anchor(&ExpiryState::Active, Freshness::Fresh, created, created - 1, 5).unwrap_err();
    assert_eq!(err.code(), "expiry-indeterminate");
    // Cross-boot also indeterminate (monotonic owner, not wall helper).
    let boot_a = domain::clock::BootId::parse("boot-7").expect("boot");
    let boot_b = domain::clock::BootId::parse("boot-8").expect("boot");
    assert_eq!(action_expiry::require_same_boot(&domain::clock::MonotonicMark::new(boot_a, 0), &domain::clock::MonotonicMark::new(boot_b, 0)).unwrap_err().code(), "expiry-indeterminate");
    // Admitted NULL release stays permitted under indeterminate time.
    let rel_preview = preview_release();
    let rel_admitted = admit_at(&scratch, "sliceB-deadline-null-1", &rel_preview, 1);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let cur1 = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 1).expect("cur1");
    let rel = action_expiry::authorize_release_with_wall(&rel_admitted, &rel_preview, &cur1, &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Indeterminate { reason: "wall-rollback" }, Freshness::Unknown, created, created - 1).expect("NULL under indeterminate");
    assert_eq!(rel.value(), &[0x00]);
}

#[test]
fn custody_transfer_durable_link_only_original_cleanup_succeeds() {
    let gate_dir = std::env::temp_dir().join(format!("verdant-m02-sliceB-gate-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir(&gate_dir).expect("gate scratch");
    let gate_db = gate_dir.join("gate.db");
    let (gate, creds) = access::AccessGate::bootstrap(&gate_db, ConnectionSettings::local_wal_full(), StoreBounds::tiny(), &access::Reason::parse("synthetic SliceB transfer").expect("reason")).expect("bootstrap");
    let successor = gate.issue_with_policy(&access::CapabilityName::parse("publisher-2").expect("cap"), &scope_a(), 2, RoleKind::Publisher, &access::KeyId::parse("key-publisher-2").expect("key"), &access::SyntheticKey::parse("synthetic-publisher-2-key").expect("synkey"), &creds.publisher, &access::Reason::parse("synthetic SliceB successor").expect("reason"), &access::DisplayLabel::parse("synthetic").expect("label"), &access::CapabilityPolicy::entry_only(None)).expect("issue successor");
    let scratch = Scratch::new();
    let preview = preview_set(22.0);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let old = journal.admit(operation("sliceB-xfer-old-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("old SET");
    journal.mark_unresolved(&operation("sliceB-xfer-old-1"), &scope_a()).expect("uncertain");
    // Revoke the old actor via the real gate before transfer.
    gate.revoke(&creds.publisher, &access::Reason::parse("synthetic SliceB offboard").expect("reason")).expect("revoke old");
    assert!(gate.is_revoked(creds.publisher.capability(), creds.publisher.key_id()).expect("revoked"));
    assert!(!gate.is_revoked(successor.capability(), successor.key_id()).expect("successor active"));
    let exclusion = OldWriterExclusion::exclude("operator-1/scope-a", "publisher-1/scope-a", "synthetic SliceB transfer narrow").expect("exclusion");
    let holds = ScopeHolds::new();
    // Transfer writes the durable predecessor link in the same batch.
    let moved = action_custody::transfer_narrow_via_new_admission(&mut journal, &old, operation("sliceB-xfer-new-1"), scope_a(), 2, RoleKind::Publisher, "publisher-2/scope-a", &preview, 1, &holds, Some(&exclusion), true).expect("transfer");
    assert_eq!(moved.predecessor().expect("link").as_str(), "sliceB-xfer-old-1");
    assert_eq!(moved.actor(), "publisher-2/scope-a");
    drop(journal);
    drop(old);
    drop(moved);
    // Fresh owner reconstructs both rows from storage without old objects.
    let (mut fresh, _rx2) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("fresh owner");
    let old_kept = fresh.reconcile(&operation("sliceB-xfer-old-1"), &scope_a()).expect("old kept");
    let new_kept = fresh.reconcile(&operation("sliceB-xfer-new-1"), &scope_a()).expect("new kept");
    assert_eq!(old_kept.actor(), "publisher-1/scope-a");
    assert_eq!(new_kept.predecessor().expect("link").as_str(), "sliceB-xfer-old-1");
    // Equivalence refusals: changed equipment/slot/value/revisions need a separate SET.
    let vav_preview = Preview::preview(scope_a(), equipment("vav-101"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), 22.0, None, &["vav-101-sp"], precondition_fresh(), &seal_ready(), equipment("vav-101"), false).expect("vav");
    assert_eq!(action_custody::transfer_narrow_via_new_admission(&mut fresh, &old_kept, operation("sliceB-xfer-bad-1"), scope_a(), 2, RoleKind::Publisher, "publisher-2/scope-a", &vav_preview, 2, &holds, Some(&exclusion), true).unwrap_err().code(), "custody-transfer");
    let changed_value = preview_set(23.0);
    assert_eq!(action_custody::transfer_narrow_via_new_admission(&mut fresh, &old_kept, operation("sliceB-xfer-bad-2"), scope_a(), 2, RoleKind::Publisher, "publisher-2/scope-a", &changed_value, 2, &holds, Some(&exclusion), true).unwrap_err().code(), "custody-transfer");
    // Only permitted original-target cleanup succeeds; replacement hardware refused.
    let rel_preview = preview_release();
    let rel_admitted = fresh.admit(operation("sliceB-xfer-rel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-2/scope-a", &rel_preview, 2).expect("original-target release admits");
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let cur2 = Current::new("publisher-2/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 2).expect("cur2");
    assert!(action_custody::authorize_release_via_custody(&rel_admitted, &rel_preview, &cur2, &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, Some(&exclusion), false, &ImpactGate::Preserved).is_ok());
    let vav_rel = preview_vav_release();
    // Replacement-hardware release admits at its own per-target generation
    // (vav-101 starts at 0, separate from ahu-1).
    let vav_admitted = fresh.admit(operation("sliceB-xfer-rel-vav-1"), scope_a(), 2, RoleKind::Publisher, "publisher-2/scope-a", &vav_rel, 0).expect("vav release admits at its own target");
    let vav_route = FrozenRoute::parse("vav-101", "bacnet-ip://127.0.0.1:20001").expect("vav route");
    let vav_cur = Current::new("publisher-2/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 0).expect("vav cur");
    // Old obligation cannot migrate to replacement hardware: retargeted release refuses.
    let retargeted = Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), 22.0, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("vav-101"), true).expect("retargeted");
    assert_eq!(action_dispatch::prepare_release(&rel_admitted, &retargeted, &cur2, &route, &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-invalid");
    let _ = (vav_admitted, vav_route, vav_cur);
    std::fs::remove_dir_all(&gate_dir).expect("cleanup");
}

#[test]
fn custody_held_returns_blocked_cleanup_outstanding_bounded_nondisclosure() {
    let scratch = Scratch::new();
    let preview = preview_set(22.0);
    let other = preview_set(22.5);
    let rel_preview = preview_release();
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    journal.admit(operation("sliceB-held-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("gen0");
    journal.admit(operation("sliceB-held-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &other, 1).expect("gen1");
    // Original-target release admitted before the hold (gen2) for cleanup proof.
    journal.admit(operation("sliceB-held-rel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &rel_preview, 2).expect("gen2 release");
    let admitted = journal.reconcile(&operation("sliceB-held-1"), &scope_a()).expect("admitted");
    let rel_admitted = journal.reconcile(&operation("sliceB-held-rel-1"), &scope_a()).expect("release admitted");
    let mut holds = ScopeHolds::new();
    holds.hold("scope-a", HoldKind::Active, "synthetic SliceB maintenance").expect("hold");
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    // Held scope blocks new SET with the generic held error.
    let err = action_custody::authorize_setpoint_via_custody(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).unwrap_err();
    assert_eq!(err.code(), "custody-held");
    // Non-original cleanup (SET obligation via release preview) on a held scope
    // returns explicit blocked-cleanup, with the obligation still outstanding.
    let kind_err = action_custody::authorize_release_via_custody(&admitted, &rel_preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).unwrap_err();
    assert_eq!(kind_err.code(), "custody-blocked");
    assert!(kind_err.to_string().contains("blocked-cleanup"));
    assert_eq!(action_custody::inspect_outstanding(&journal, &scope_a()).expect("still outstanding").len(), 3);
    // Original-target admitted-null-release on a held scope is permitted.
    let cur2 = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 2).expect("cur2");
    assert!(action_custody::authorize_release_via_custody(&rel_admitted, &rel_preview, &cur2, &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).is_ok());
    // Bounded page: LIMIT 1 returns one row, OFFSET 1 returns the next.
    let page0 = action_custody::inspect_outstanding_bounded(&journal, &scope_a(), 1, 0).expect("page0");
    let page1 = action_custody::inspect_outstanding_bounded(&journal, &scope_a(), 1, 1).expect("page1");
    assert_eq!(page0.len(), 1);
    assert_eq!(page1.len(), 1);
    assert_ne!(page0[0].operation().as_str(), page1[0].operation().as_str());
    // Cross-scope nondisclosure: scope-b observes nothing.
    assert!(action_custody::inspect_outstanding(&journal, &scope_b()).expect("foreign").is_empty());
    assert!(action_custody::inspect_outstanding_bounded(&journal, &scope_b(), 10, 0).expect("foreign bounded").is_empty());
}

#[test]
fn compat_0004_0005_readable_conservative_defaults_no_backfill() {
    let scratch = Scratch::new();
    let preview = preview_set(22.0);
    let fresh = admit_at(&scratch, "sliceB-compat-new-1", &preview, 0);
    assert!(!fresh.is_legacy());
    assert_eq!(fresh.lifecycle(), LifecycleState::Admitted);
    assert_eq!(fresh.predecessor(), None);
    assert!(fresh.created_secs() > 0);
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    // Simulate an upgraded 0004 row (no identity, no lifecycle): readable, conservative.
    journal.store().exec_script("INSERT INTO action_journal(operation, scope, equipment, binding_revision, accepted_revision, expected_generation, target_generation, payload, deadline_secs, ceiling, actor, attempt, state, created) VALUES ('sliceB-compat-old-1', 'scope-a', 'ahu-1', 7, 1, 1, 2, 'verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish', 5, 2, 'publisher-1/scope-a', 'sliceB-compat-old-1', 'admitted', CAST(strftime('%s','now') AS INTEGER));").expect("legacy insert");
    journal.store().exec_script("INSERT INTO action_targets(scope, equipment, current_generation) VALUES ('scope-a', 'ahu-1', 2) ON CONFLICT(scope, equipment) DO UPDATE SET current_generation=excluded.current_generation;").expect("legacy target");
    let legacy = journal.reconcile(&operation("sliceB-compat-old-1"), &scope_a()).expect("legacy readable");
    assert!(legacy.is_legacy());
    assert_eq!(legacy.lifecycle(), LifecycleState::Admitted);
    assert_eq!(legacy.predecessor(), None);
    assert!(legacy.created_secs() > 0);
    // No backfill: legacy has no lifecycle row.
    let lifecycle_rows: String = journal.store().exec_script("SELECT count(*) FROM action_lifecycle WHERE operation='sliceB-compat-old-1';").expect("count")[0][0].clone();
    assert_eq!(lifecycle_rows, "0");
    // Legacy stale-payload rules preserved for new handoffs.
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let cur1 = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("r"), BindingStatus::Valid, 1).expect("cur1");
    assert_eq!(action_dispatch::prepare_setpoint(&legacy, &preview, &cur1, &route, &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-stale-payload");
    // 0005 row with identity but no lifecycle (delete its lifecycle to simulate): still admitted default.
    journal.store().exec_script("DELETE FROM action_lifecycle WHERE operation='sliceB-compat-new-1';").expect("simulate 0005 without lifecycle");
    let reread = journal.reconcile(&operation("sliceB-compat-new-1"), &scope_a()).expect("0005 readable");
    assert!(!reread.is_legacy());
    assert_eq!(reread.lifecycle(), LifecycleState::Admitted);
    assert_eq!(reread.wire_bits(), Some(0x41b00000));
    // Outstanding contains the 0005 default-admitted row but terminal would not.
    let listed = action_custody::inspect_outstanding(&journal, &scope_a()).expect("outstanding");
    assert!(listed.iter().any(|a| a.operation().as_str() == "sliceB-compat-new-1"));
    assert_eq!(journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count")[0][0], "2");
}
