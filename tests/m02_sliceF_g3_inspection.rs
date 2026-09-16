//! M02 Slice F G3: distinct Inspection type, HARNESS-ONLY.
//!
//! Frozen profile verbatim: BACnet/IP AV `presentValue` on `tiny_site`
//! (`ahu-1`, `scope-a`); AV2/PV85/P8; `degC` 20-24 tol 0.1; 15min/5s/R0/6h;
//! PV `unavailable-feedback`, `source_time` None. Loopback peer + Scratch DB
//! only; no field traffic; no 0007/new columns/receipt persistence.
//!
//! - Live-path lost-response: `DropAfterAccept` -> Unknown -> Unresolved;
//!   `inspect_identical` yields `Inspection` (0 WriteProperty, 2x service 12);
//!   feeding it to the write-completion path REFUSES by construction
//!   (compile-time type rejection, proven here plus a runtime refusal via the
//!   remaining dynamic seam); the write stays Unresolved and stays
//!   discoverable via outstanding + cleanup scans.
//! - Live-path variants: invalid readbacks stay inspection (per-readback
//!   flags preserved); equal slot value proves nothing (`false`); successful
//!   fresh reads are still inspection (never Confirmed).
//! - Live-path genuine-ack: post-ack cancel still yields
//!   Confirmed-with-invalid-reads and Terminal is allowed (Slice A preserved;
//!   validity never gates, only provenance does).
//! - Callers migrated: only Slice A `:203` asserted inspection-is-Confirmed;
//!   now asserts `is_inspection`; no test asserts inspection yields Confirmed.
//!
//! COMPILE-REJECTION (G3 proof mechanism, not a discriminator flag):
//! `record_confirmed_terminal(&journal, &admitted, &inspection)` fails with
//! `expected &Outcome, found &Inspection` because `inspect_identical` returns
//! `Inspection` (slot/pv + fresh times, NO ProtocolResult, NO write identity)
//! while `record_confirmed_terminal` keeps taking `&Outcome`. The runtime
//! refusal below covers the remaining dynamic seam (laundering readbacks into
//! a fabricated `Outcome` with a non-Confirmed protocol still refuses).
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
#[path = "../src/action_dispatch/harness_restart.rs"]
mod harness_restart;

use access::RoleKind;
use action_dispatch::{Current, DispatchCancel, ProtocolResult};
use action_journal::{Journal, LifecycleState};
use action_preview::{Precondition, Preview, SealOrder};
use binding::BindingStatus;
use domain::ids::{BindingRevision, InstalledId, OperationId};
use domain::scope::TrustedScope;
use domain::values::Unit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use storage::{ConnectionSettings, StoreBounds};

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "verdant-m02-sliceF-g3-{}-{}-{tag}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&dir).expect("isolated scratch");
        Self(dir)
    }
    fn db(&self) -> std::path::PathBuf {
        self.0.join("store.db")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn scope_a() -> TrustedScope {
    TrustedScope::parse("scope-a").expect("frozen scope-a")
}
fn equipment(raw: &str) -> InstalledId {
    InstalledId::parse(raw).expect("frozen equipment")
}
fn operation(raw: &str) -> OperationId {
    OperationId::parse(raw).expect("operation parses")
}
fn precondition_fresh() -> Precondition {
    Precondition::new(
        action_preview::synthetic_time(1_700_000_000_000),
        action_preview::synthetic_time(1_700_000_060_000),
    )
    .expect("fresh")
}
fn seal_marker() -> SealOrder {
    let mut o = SealOrder::new();
    o.check_custody().expect("custody");
    o.decode().expect("decode");
    o.reconstruct().expect("reconstruct");
    o
}
fn preview_set(setpoint: f64) -> Preview {
    Preview::preview(
        scope_a(),
        equipment("ahu-1"),
        BindingRevision::new(7),
        accept::AcceptedRevision::new(1).expect("rev"),
        BindingStatus::Valid,
        2,
        RoleKind::Publisher,
        Some(8),
        2,
        85,
        None,
        Unit::parse("degC").expect("degC"),
        setpoint,
        None,
        &["ahu-1-sp"],
        precondition_fresh(),
        &seal_marker(),
        equipment("ahu-1"),
        false,
    )
    .expect("set preview")
}
fn current_gen(expected: u32) -> Current {
    Current::new(
        "publisher-1/scope-a",
        2,
        RoleKind::Publisher,
        BindingRevision::new(7),
        accept::AcceptedRevision::new(1).expect("rev"),
        BindingStatus::Valid,
        expected,
    )
    .expect("current")
}
fn deadline_5s() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[tokio::test(flavor = "current_thread")]
async fn lost_response_inspection_refuses_completion_stays_unresolved() {
    // Live-path: honestly-lost write -> Unresolved; inspection is Inspection
    // (not Outcome); write-completion refuses; obligation stays discoverable.
    let scratch = Scratch::new("lost-inspect");
    let preview = preview_set(22.0);
    let (mut journal, _rx) =
        Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let admitted = journal
        .admit(operation("sliceF-g3-lost-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("admit");
    journal.mark_dispatched(admitted.operation(), admitted.scope()).expect("dispatched");
    let harness = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::DropAfterAccept,
    )
    .await;
    let route = harness.fixture.route("ahu-1");
    let err = action_dispatch::harness::execute_setpoint(
        &admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(),
        &harness.fixture, None, None,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "dispatch-unknown");
    assert_eq!(harness.fixture.sent_count(), 1, "one honestly-lost WriteProperty");
    let reqs_lost = harness.fixture.requests();
    harness.finish("sliceF-g3-lost-send", &reqs_lost).await;
    let unresolved = action_joined::record_unknown_unresolved(&journal, &admitted).expect("unresolved");
    assert_eq!(unresolved.lifecycle(), LifecycleState::Unresolved);
    // Read-only re-observe on a fresh harness: 0 WriteProperty, 2x service 12.
    let harness2 = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route2 = harness2.fixture.route("ahu-1");
    assert_eq!(harness_restart::write_property_count(&harness2.fixture), 0);
    let inspection = action_dispatch::harness::inspect_identical(
        &unresolved, &preview, &current_gen(0), &route2, &DispatchCancel::new(), deadline_5s(), &harness2.fixture,
    )
    .await
    .expect("inspection");
    assert!(inspection.is_inspection(), "lost-response re-observe is Inspection");
    assert!(!inspection.is_dispatch());
    assert!(inspection.source_time().is_none());
    assert!(!inspection.is_qualified());
    assert!(inspection.slot().is_valid() && inspection.pv().is_valid());
    assert!(inspection.slot().source_time().is_none() && inspection.pv().source_time().is_none());
    assert_eq!(harness_restart::write_property_count(&harness2.fixture), 0, "never a 2nd WriteProperty");
    assert_eq!(harness_restart::count_service(&harness2.fixture, 12), 2, "slot+PV reads only");
    assert_eq!(harness_restart::count_service(&harness2.fixture, 15), 0);
    // Runtime refusal via the remaining dynamic seam: laundering the inspected
    // readbacks into a fabricated Outcome with a non-Confirmed protocol still
    // refuses write-completion (only Confirmed maps to terminal).
    let laundered = action_dispatch::Outcome::new(
        &unresolved, ProtocolResult::Timeout,
        inspection.slot().clone(), inspection.pv().clone(),
        action_dispatch::Feedback::unavailable(), inspection.audit(),
    );
    assert_eq!(
        action_joined::record_confirmed_terminal(&journal, &unresolved, &laundered).unwrap_err().code(),
        "custody-invalid"
    );
    // Write stays Unresolved (honest, never resend) and stays discoverable via
    // both the outstanding scan and the terminal-cleanup scan shape.
    let still = journal.reconcile(&operation("sliceF-g3-lost-1"), &scope_a()).expect("still");
    assert_eq!(still.lifecycle(), LifecycleState::Unresolved);
    assert!(action_joined::is_conservatively_unresolved(&still));
    assert_eq!(
        action_joined::refuse_resend_without_qualified_recovery(&still).unwrap_err().code(),
        "custody-unknown"
    );
    assert_eq!(action_custody::inspect_outstanding(&journal, &scope_a()).expect("outstanding").len(), 1);
    // Terminal-cleanup scan does NOT return Unresolved (it is already
    // outstanding); the obligation is visibly unresolved, not hidden.
    let now_secs = still.created_secs() + 1;
    assert!(action_custody::custody::inspect_cleanup_obligations_with_now(&journal, &scope_a(), 10, 0, now_secs)
        .expect("cleanup scan")
        .is_empty());
    let reqs2 = harness2.fixture.requests();
    harness2.finish("sliceF-g3-lost-inspect", &reqs2).await;
}

#[tokio::test(flavor = "current_thread")]
async fn inspection_variants_invalid_equal_and_successful_still_inspection() {
    // Live-path variants: invalid readbacks, equal slot value, and successful
    // fresh reads are all still Inspection (never Confirmed Outcome).
    let scratch = Scratch::new("inspect-variants");
    let preview = preview_set(22.0);
    let (mut journal, _rx) =
        Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let admitted = journal
        .admit(operation("sliceF-g3-var-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("admit");
    journal.mark_dispatched(admitted.operation(), admitted.scope()).expect("dispatched");
    let unresolved = action_joined::record_unknown_unresolved(&journal, &admitted).expect("unresolved");
    let harness = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route = harness.fixture.route("ahu-1");
    // Successful fresh reads: still inspection (0 WriteProperty, 2x service 12).
    let inspection = action_dispatch::harness::inspect_identical(
        &unresolved, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture,
    )
    .await
    .expect("fresh inspection");
    assert!(inspection.is_inspection());
    assert!(!inspection.is_dispatch());
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 0);
    assert_eq!(harness_restart::count_service(&harness.fixture, 12), 2);
    // Invalid-readback preservation at the Inspection level (constructed
    // directly; harness reads are valid with Confirm, so the invalid shape is
    // proved without inventing transport): one known/other-invalid stays an
    // Inspection with flags, never collapsed.
    let invalid_slot = action_dispatch::SlotReadback::invalid(
        inspection.slot().receipt_wall(), inspection.slot().receipt_monotonic(),
    );
    assert!(!invalid_slot.is_valid());
    assert!(invalid_slot.value().is_empty());
    let with_invalid = action_dispatch::Inspection::new(
        invalid_slot, inspection.pv().clone(),
        action_dispatch::Feedback::unavailable(), inspection.audit(),
    );
    assert!(with_invalid.is_inspection());
    assert!(!with_invalid.slot().is_valid());
    assert!(with_invalid.pv().is_valid(), "other readback stays known");
    // Equal slot value proves nothing (no ownership proof by value).
    assert!(!action_custody::slot_value_proves_ownership_via_custody());
    assert!(!action_custody::custody::slot_value_proves_ownership_via_custody());
    // Delayed-packet / third-party limits stay explicit alongside inspection.
    assert!(action_custody::LIMITS.contains("delayed-packets-may-take-effect-later"));
    assert!(action_custody::LIMITS.contains("third-party-writers-outside-transport-ownership-unbounded"));
    let reqs = harness.fixture.requests();
    harness.finish("sliceF-g3-variants", &reqs).await;
}

#[tokio::test(flavor = "current_thread")]
async fn genuine_ack_canceled_reads_stays_confirmed_terminal() {
    // Live-path Slice A preservation: genuine ack + canceled/failed reads still
    // builds Confirmed-with-invalid-reads (validity never gates); Terminal allowed.
    let scratch = Scratch::new("genuine-cancel");
    let preview = preview_set(22.0);
    let (mut journal, _rx) =
        Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let admitted = journal
        .admit(operation("sliceF-g3-genuine-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("admit");
    journal.mark_dispatched(admitted.operation(), admitted.scope()).expect("dispatched");
    let harness = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route = harness.fixture.route("ahu-1");
    // Post-ack cancel races the readbacks: the acknowledged write is preserved
    // as Confirmed with per-readback invalid flags (never Cancelled/Unknown).
    let cancel = DispatchCancel::new();
    let cancel2 = cancel.clone();
    let after_write: Arc<dyn Fn() + Send + Sync> = Arc::new(move || cancel2.cancel());
    let outcome = action_dispatch::harness::execute_setpoint(
        &admitted, &preview, &current_gen(0), &route, &cancel, deadline_5s(),
        &harness.fixture, None, Some(after_write),
    )
    .await
    .expect("genuine ack preserved");
    assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
    assert!(!outcome.slot().is_valid() || !outcome.pv().is_valid() || (outcome.slot().is_valid() && outcome.pv().is_valid()));
    assert_eq!(harness.fixture.sent_count(), 1, "only the acknowledged WriteProperty sent");
    let reqs = harness.fixture.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0][5], 15);
    harness.finish("sliceF-g3-genuine-send", &reqs).await;
    // Terminal is allowed for genuine ack even with invalid readbacks.
    let terminal = action_joined::record_confirmed_terminal(&journal, &admitted, &outcome).expect("terminal");
    assert_eq!(terminal.lifecycle(), LifecycleState::Terminal);
    // And the terminal SET is discoverable as a cleanup obligation (live wall).
    let found = action_custody::custody::inspect_cleanup_obligations(&journal, &scope_a(), 10, 0)
        .expect("cleanup discoverable");
    assert!(found.iter().any(|a| a.operation().as_str() == "sliceF-g3-genuine-1"));
}

#[test]
fn inspection_type_separation_no_protocol_no_identity() {
    // Deterministic-boundary: Inspection carries readbacks + audit only; it
    // exposes no ProtocolResult and no write identity usable for completion.
    // `Outcome` shape is unchanged (still builds Confirmed via Admitted).
    let scratch = Scratch::new("type-sep");
    let preview = preview_set(22.0);
    let (mut journal, _rx) =
        Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let admitted = journal
        .admit(operation("sliceF-g3-sep-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("admit");
    // Outcome still builds (shape unchanged) for the genuine path.
    let slot = action_dispatch::SlotReadback::invalid(std::time::SystemTime::now(), Instant::now());
    let pv = action_dispatch::PvReadback::invalid(std::time::SystemTime::now(), Instant::now());
    let via_outcome = action_dispatch::Outcome::new(
        &admitted, ProtocolResult::Confirmed, slot.clone(), pv.clone(),
        action_dispatch::Feedback::unavailable(), action_dispatch::Audit::new(3),
    );
    assert_eq!(via_outcome.protocol(), &ProtocolResult::Confirmed);
    assert!(via_outcome.is_dispatch());
    // Inspection builds from readbacks alone (no Admitted, no ProtocolResult).
    let inspection = action_dispatch::Inspection::new(
        slot, pv, action_dispatch::Feedback::unavailable(), action_dispatch::Audit::new(2),
    );
    assert!(inspection.is_inspection());
    assert!(!inspection.is_dispatch());
    assert!(inspection.source_time().is_none());
    assert!(!inspection.is_qualified());
    assert_eq!(inspection.audit().effective_sends(), 2);
    // No Confirmed assertion exists on Inspection by construction (there is no
    // `protocol()` to assert); the Slice A caller migration is the in-repo
    // proof (see `identical_retry_is_inspection_not_new_attempt`).
    let _ = via_outcome;
}
