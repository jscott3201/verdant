//! M02 Slice F G2: terminal-SET cleanup-obligation discovery, HARNESS-ONLY.
//!
//! Frozen profile verbatim: BACnet/IP AV `presentValue` on `tiny_site`
//! (`ahu-1`, `scope-a`); AV2/PV85/P8; `degC` 20-24 tol 0.1; 15min/5s/R0/6h;
//! PV `unavailable-feedback`, `source_time` None. Loopback peer + Scratch DB
//! only; no field traffic; no 0007/new columns/receipt persistence.
//!
//! - Deterministic-boundary: `is_cleanup_due` plus `*_with_now` horizon
//!   edges (created+899 due, created+900 expired, rollback not due),
//!   scope-filter, kind-filter, state-filter, LIMIT-clamp.
//! - Live-path: Confirmed SET -> drop ALL objects -> reopen -> live-wall scan
//!   still finds the original-target obligation (terminal SET within horizon)
//!   while `outstanding_page` stays empty; Terminal history unchanged and
//!   reconcile-readable; admitted-NULL with predecessor link authorizes and
//!   executes (resolved or visibly unresolved).
//! - Live-path masked: same with a masked peer table (masking is
//!   presentation-only; identity is bits/kind/target).
//! - Live-path cancel-after-ack: stale cancel for the old generation refuses
//!   exact-equality; cleanup proceeds via NULL release, never a 2nd
//!   WriteProperty for the original op.
//! - Limits: delayed packets may still take effect later; third-party writers
//!   are outside local transport ownership (see `LIMITS`); NULL ack is NOT
//!   quiescence (Terminal history stays readable via reconcile).
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
use action_dispatch::{Current, DispatchCancel, FrozenRoute, ProtocolResult};
use action_journal::{Journal, LifecycleState};
use action_preview::{Precondition, Preview, SealOrder};
use binding::BindingStatus;
use domain::ids::{BindingRevision, InstalledId, OperationId};
use domain::scope::TrustedScope;
use domain::values::Unit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use storage::{ConnectionSettings, StoreBounds};

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "verdant-m02-sliceF-g2-{}-{}-{tag}",
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
fn scope_b() -> TrustedScope {
    TrustedScope::parse("scope-b").expect("scope-b")
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
fn preview_release() -> Preview {
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
        22.0,
        None,
        &["ahu-1-sp"],
        precondition_fresh(),
        &seal_marker(),
        equipment("ahu-1"),
        true,
    )
    .expect("release preview")
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

#[test]
fn cleanup_horizon_deterministic_boundaries() {
    // Deterministic-boundary: pure horizon edges plus filtered scan, no harness.
    use action_journal::lifecycle::{is_cleanup_due, CLEANUP_HORIZON_SECS};
    assert_eq!(CLEANUP_HORIZON_SECS, 900, "15-min horizon");
    assert!(is_cleanup_due(1000, 1899, 900), "created+899 due");
    assert!(!is_cleanup_due(1000, 1900, 900), "created+900 expired");
    assert!(!is_cleanup_due(1000, 999, 900), "rollback not due");
    assert!(!is_cleanup_due(1000, 1000 + 900 + 1, 900), "beyond horizon not due");
    assert!(is_cleanup_due(1000, 1000, 900), "zero elapsed due");
    // Filtered scan with explicit now: terminal SET within horizon only.
    let scratch = Scratch::new("horizon-det");
    let preview = preview_set(22.0);
    let rel_preview = preview_release();
    let (mut journal, _rx) =
        Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny())
            .expect("open");
    let admitted = journal
        .admit(operation("sliceF-g2-h1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("admit SET");
    let created = admitted.created_secs();
    assert!(created > 0);
    journal
        .mark_terminal(admitted.operation(), admitted.scope())
        .expect("terminal");
    // Within horizon (explicit now): found via both owners.
    let due_now = created + 899;
    let found = action_journal::lifecycle::cleanup_obligations_with_now(&journal, &scope_a(), 10, 0, due_now)
        .expect("due scan");
    assert!(found.iter().any(|a| a.operation().as_str() == "sliceF-g2-h1"));
    let via_custody = action_custody::custody::inspect_cleanup_obligations_with_now(&journal, &scope_a(), 10, 0, due_now)
        .expect("custody due");
    assert_eq!(found.len(), via_custody.len());
    // Exact-horizon expiry: excluded.
    let expired_now = created + 900;
    assert!(action_journal::lifecycle::cleanup_obligations_with_now(&journal, &scope_a(), 10, 0, expired_now)
        .expect("expired scan")
        .is_empty());
    // Rollback: excluded.
    assert!(action_journal::lifecycle::cleanup_obligations_with_now(&journal, &scope_a(), 10, 0, created - 1)
        .expect("rollback scan")
        .is_empty());
    // Scope-filtered: scope-b observes nothing (nondisclosure).
    assert!(action_journal::lifecycle::cleanup_obligations_with_now(&journal, &scope_b(), 10, 0, due_now)
        .expect("foreign empty")
        .is_empty());
    assert!(action_custody::custody::inspect_cleanup_obligations_with_now(&journal, &scope_b(), 10, 0, due_now)
        .expect("foreign empty")
        .is_empty());
    // Kind-filter: terminal RELEASE within horizon is not a SET obligation.
    let rel_admitted = journal
        .admit(operation("sliceF-g2-hrel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &rel_preview, 1)
        .expect("admit release");
    journal
        .mark_terminal(rel_admitted.operation(), rel_admitted.scope())
        .expect("release terminal");
    let after_rel = action_custody::custody::inspect_cleanup_obligations_with_now(&journal, &scope_a(), 10, 0, due_now)
        .expect("kind filter");
    assert!(after_rel.iter().any(|a| a.operation().as_str() == "sliceF-g2-h1"));
    assert!(!after_rel.iter().any(|a| a.operation().as_str() == "sliceF-g2-hrel-1"), "release excluded");
    // State-filter: admitted (non-terminal) SET is not returned here.
    journal
        .admit(operation("sliceF-g2-hadmit-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_set(22.5), 2)
        .expect("admitted SET");
    let after_admit = action_custody::custody::inspect_cleanup_obligations_with_now(&journal, &scope_a(), 64, 0, due_now)
        .expect("state filter");
    assert!(!after_admit.iter().any(|a| a.operation().as_str() == "sliceF-g2-hadmit-1"));
    // LIMIT-clamp: limit 1 returns one row; offset pages.
    let page0 = action_custody::custody::inspect_cleanup_obligations_with_now(&journal, &scope_a(), 1, 0, due_now)
        .expect("page0");
    assert_eq!(page0.len(), 1);
    // Terminal history rows unchanged: still Terminal, still reconcile-readable.
    let history = journal.reconcile(&operation("sliceF-g2-h1"), &scope_a()).expect("history");
    assert_eq!(history.lifecycle(), LifecycleState::Terminal);
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_set_cleanup_discoverable_after_drop_live_wall() {
    // Live-path: Confirmed SET -> drop ALL objects -> reopen -> live-wall scan
    // finds the obligation while outstanding stays empty; NULL with predecessor
    // then authorizes and executes (resolved or visibly unresolved).
    let scratch = Scratch::new("drop-live");
    let preview = preview_set(22.0);
    assert_eq!(preview.encoded().wire_bits(), 0x41b00000);
    let db = scratch.db();
    let op = "sliceF-g2-drop-1";
    let created_secs: i64;
    {
        let (mut journal, _rx) =
            Journal::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
        let admitted = journal
            .admit(operation(op), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
            .expect("admit");
        created_secs = admitted.created_secs();
        journal.mark_dispatched(admitted.operation(), admitted.scope()).expect("dispatched");
        let harness = action_dispatch::harness::Harness::new(
            action_dispatch::harness::PeerTable::default(),
            action_dispatch::harness::PeerMode::Confirm,
        )
        .await;
        let route = harness.fixture.route("ahu-1");
        let outcome = action_dispatch::harness::execute_setpoint(
            &admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(),
            &harness.fixture, None, None,
        )
        .await
        .expect("confirmed");
        assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
        assert_eq!(harness.fixture.sent_count(), 3, "write + 2 reads");
        let reqs = harness.fixture.requests();
        harness.finish("sliceF-g2-drop-send", &reqs).await;
        action_joined::record_confirmed_terminal(&journal, &admitted, &outcome).expect("terminal");
        // Drop ALL action objects here (admitted/outcome/journal/harness).
    }
    // Fresh process with no old Rust objects reopens the same DB file.
    let (mut journal2, _rx2) =
        Journal::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    // Outstanding excludes Terminal (the criticized shape Slice D :379-381 pins).
    assert!(action_custody::inspect_outstanding(&journal2, &scope_a()).expect("outstanding").is_empty());
    // Live-wall cleanup scan still finds the original-target obligation.
    let found = action_custody::custody::inspect_cleanup_obligations(&journal2, &scope_a(), 10, 0)
        .expect("live-wall cleanup scan");
    assert!(found.iter().any(|a| a.operation().as_str() == op), "terminal SET within horizon discoverable");
    let row = found.iter().find(|a| a.operation().as_str() == op).expect("row");
    assert_eq!(row.lifecycle(), LifecycleState::Terminal);
    assert_eq!(row.equipment().as_str(), "ahu-1");
    assert_eq!(row.created_secs(), created_secs);
    // Terminal history stays readable via reconcile (NOT quiescence).
    let history = journal2.reconcile(&operation(op), &scope_a()).expect("history");
    assert_eq!(history.lifecycle(), LifecycleState::Terminal);
    // Delayed-packet / third-party limits stay explicit (NULL ack is not proof
    // the field is quiescent; see LIMITS).
    assert!(action_custody::LIMITS.contains("delayed-packets-may-take-effect-later"));
    assert!(action_custody::LIMITS.contains("third-party-writers-outside-transport-ownership-unbounded"));
    // Admitted-NULL cleanup carrying the predecessor link authorizes and sends
    // exactly once (original-target, next generation).
    let rel = preview_release();
    let cleanup = journal2
        .admit_with_predecessor(
            operation("sliceF-g2-drop-rel-1"), scope_a(), 2, RoleKind::Publisher,
            "publisher-1/scope-a", &rel, 1, operation(op),
        )
        .expect("NULL with predecessor");
    assert_eq!(cleanup.predecessor().expect("link").as_str(), op);
    let route2 = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    action_custody::authorize_release_via_custody(
        &cleanup, &rel, &current_gen(1), &route2, &DispatchCancel::new(), deadline_5s(),
        &action_expiry::ExpiryState::Active, observation::time::Freshness::Fresh,
        &action_custody::ScopeHolds::new(), None, false, &action_publication::ImpactGate::Preserved,
    )
    .expect("NULL cleanup authorizes");
    let harness2 = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route_h = harness2.fixture.route("ahu-1");
    let fresh = journal2.reconcile(&operation("sliceF-g2-drop-rel-1"), &scope_a()).expect("fresh NULL");
    let rel_out = action_dispatch::harness::execute_release(
        &fresh, &rel, &current_gen(1), &route_h, &DispatchCancel::new(), deadline_5s(), &harness2.fixture,
    )
    .await
    .expect("NULL sends once");
    assert_eq!(rel_out.protocol(), &ProtocolResult::Confirmed);
    assert_eq!(harness_restart::write_property_count(&harness2.fixture), 1);
    let reqs2 = harness2.fixture.requests();
    harness2.finish("sliceF-g2-drop-cleanup", &reqs2).await;
    // Obligation resolved or visibly unresolved: mark the cleanup Terminal and
    // prove the original Terminal history is still there, unchanged.
    action_joined::record_confirmed_terminal(&journal2, &fresh, &rel_out).expect("cleanup terminal");
    assert_eq!(journal2.reconcile(&operation(op), &scope_a()).expect("orig history").lifecycle(), LifecycleState::Terminal);
}

#[tokio::test(flavor = "current_thread")]
async fn masked_set_cleanup_same_identity() {
    // Live-path masked variant: masking is presentation-only; identity is
    // bits/kind/target, so the same discovery + predecessor path holds.
    let scratch = Scratch::new("masked-live");
    let preview = preview_set(22.0);
    let db = scratch.db();
    let op = "sliceF-g2-mask-1";
    {
        let (mut journal, _rx) =
            Journal::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
        let admitted = journal
            .admit(operation(op), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
            .expect("admit masked SET");
        journal.mark_dispatched(admitted.operation(), admitted.scope()).expect("dispatched");
        let mut table = action_dispatch::harness::PeerTable::default();
        table.slots[4] = Some(21.0);
        let harness = action_dispatch::harness::Harness::new(table, action_dispatch::harness::PeerMode::Confirm).await;
        let route = harness.fixture.route("ahu-1");
        let outcome = action_dispatch::harness::execute_setpoint(
            &admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(),
            &harness.fixture, None, None,
        )
        .await
        .expect("masked write confirmed");
        assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
        let reqs = harness.fixture.requests();
        harness.finish("sliceF-g2-mask-send", &reqs).await;
        action_joined::record_confirmed_terminal(&journal, &admitted, &outcome).expect("terminal");
    }
    let (mut journal2, _rx2) =
        Journal::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let found = action_custody::custody::inspect_cleanup_obligations(&journal2, &scope_a(), 10, 0)
        .expect("masked discoverable");
    assert!(found.iter().any(|a| a.operation().as_str() == op));
    let row = found.iter().find(|a| a.operation().as_str() == op).expect("row");
    assert_eq!(row.wire_bits(), Some(preview.encoded().wire_bits()), "identity is bits, not presentation");
    let rel = preview_release();
    let cleanup = journal2
        .admit_with_predecessor(
            operation("sliceF-g2-mask-rel-1"), scope_a(), 2, RoleKind::Publisher,
            "publisher-1/scope-a", &rel, 1, operation(op),
        )
        .expect("NULL predecessor");
    assert_eq!(cleanup.predecessor().expect("link").as_str(), op);
}

#[tokio::test(flavor = "current_thread")]
async fn cancel_after_ack_stale_refuses_cleanup_via_null() {
    // Live-path cancel-after-ack: stale cancel for the old generation refuses
    // exact-equality; cleanup proceeds via NULL release, never a 2nd WriteProperty.
    let scratch = Scratch::new("cancel-live");
    let preview = preview_set(22.0);
    let db = scratch.db();
    let op = "sliceF-g2-cancel-1";
    {
        let (mut journal, _rx) =
            Journal::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
        let admitted = journal
            .admit(operation(op), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
            .expect("admit");
        journal.mark_dispatched(admitted.operation(), admitted.scope()).expect("dispatched");
        let harness = action_dispatch::harness::Harness::new(
            action_dispatch::harness::PeerTable::default(),
            action_dispatch::harness::PeerMode::Confirm,
        )
        .await;
        let route = harness.fixture.route("ahu-1");
        let outcome = action_dispatch::harness::execute_setpoint(
            &admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(),
            &harness.fixture, None, None,
        )
        .await
        .expect("ack");
        assert_eq!(harness_restart::write_property_count(&harness.fixture), 1);
        let reqs = harness.fixture.requests();
        harness.finish("sliceF-g2-cancel-send", &reqs).await;
        action_joined::record_confirmed_terminal(&journal, &admitted, &outcome).expect("terminal");
    }
    let (mut journal2, _rx2) =
        Journal::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    // Stale cancel for the old generation refuses (exact equality only).
    assert_eq!(
        action_custody::authorize_cancel_via_custody(0, 1).unwrap_err().code(),
        "expiry-stale-generation"
    );
    assert_eq!(
        action_expiry::authorize_cancel(0, 1).unwrap_err().code(),
        "expiry-stale-generation"
    );
    // Cleanup still discoverable and proceeds via NULL release with predecessor.
    let found = action_custody::custody::inspect_cleanup_obligations(&journal2, &scope_a(), 10, 0)
        .expect("discoverable");
    assert!(found.iter().any(|a| a.operation().as_str() == op));
    let rel = preview_release();
    let _cleanup = journal2
        .admit_with_predecessor(
            operation("sliceF-g2-cancel-rel-1"), scope_a(), 2, RoleKind::Publisher,
            "publisher-1/scope-a", &rel, 1, operation(op),
        )
        .expect("NULL predecessor");
    let harness2 = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route_h = harness2.fixture.route("ahu-1");
    let fresh = journal2.reconcile(&operation("sliceF-g2-cancel-rel-1"), &scope_a()).expect("fresh");
    action_dispatch::harness::execute_release(
        &fresh, &rel, &current_gen(1), &route_h, &DispatchCancel::new(), deadline_5s(), &harness2.fixture,
    )
    .await
    .expect("NULL sends once");
    // Exactly one WriteProperty on the cleanup harness; the original op never
    // takes a second WriteProperty (re-observe would be reads only).
    assert_eq!(harness_restart::write_property_count(&harness2.fixture), 1);
    let preview_orig = preview_set(22.0);
    let recovered = journal2.reconcile(&operation(op), &scope_a()).expect("orig");
    let reads_before = harness_restart::count_service(&harness2.fixture, 12);
    let inspection = action_dispatch::harness::inspect_identical(
        &recovered, &preview_orig, &current_gen(0), &route_h, &DispatchCancel::new(), deadline_5s(), &harness2.fixture,
    )
    .await
    .expect("read-only re-observe");
    assert!(inspection.is_inspection());
    assert_eq!(harness_restart::count_service(&harness2.fixture, 12), reads_before + 2);
    assert_eq!(harness_restart::write_property_count(&harness2.fixture), 1, "never a 2nd WriteProperty");
    let reqs2 = harness2.fixture.requests();
    harness2.finish("sliceF-g2-cancel-cleanup", &reqs2).await;
}
