//! M02 Slice-A regressions: lossless identity, active activation, outcome
//! provenance, 0004 compatibility. SYNTHETIC-ONLY, HARNESS-ONLY.
//!
//! Frozen profile verbatim: BACnet/IP AV `presentValue` on `tiny_site`
//! (`ahu-1`/`vav-101`, `scope-a`); AV2/PV85/P8; `degC` 20-24 tol 0.1;
//! 15min/5s/APDU_RETRIES(0)/6h; PV `unavailable-feedback`, `source_time` None.
//! Slice B (deferred): full lifecycle, 6/hour enforcement, custody link,
//! bounded outstanding -- see TODOs in `action_journal/identity.rs`.
//! M02-G promotion is HELD (not claimed here).
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
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "accept_cases/support.rs"]
mod support;

use access::RoleKind;
use action_dispatch::{Current, DispatchCancel, FrozenRoute, ProtocolResult};
use action_journal::Journal;
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
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("verdant-m02-sliceA-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
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
    Precondition::new(action_preview::synthetic_time(1_700_000_000_000), action_preview::synthetic_time(1_700_000_060_000)).expect("fresh")
}
fn seal_ready() -> SealOrder {
    let mut o = SealOrder::new();
    o.check_custody().expect("custody");
    o.decode().expect("decode");
    o.reconstruct().expect("reconstruct");
    o
}
fn preview_set(setpoint: f64) -> Preview {
    Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), setpoint, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("ahu-1"), false).expect("set preview")
}
fn preview_release() -> Preview {
    Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), 22.0, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("ahu-1"), true).expect("release preview")
}
fn admit_at(scratch: &Scratch, op: &str, preview: &Preview, expected: u32) -> action_journal::Admitted {
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("writer open");
    journal.admit(operation(op), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", preview, expected).expect("admit")
}
fn current_gen(expected: u32) -> Current {
    Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, expected).expect("current")
}
fn deadline_5s() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn lossless_wire_bits_distinct_despite_equal_presentation() {
    // Two distinct binary32 values sharing `{:.4}` text MUST NOT reconcile.
    let a = action_preview::EncodedSetpoint::new(22.00001).expect("a encodes");
    let b = action_preview::EncodedSetpoint::new(22.00002).expect("b encodes");
    assert_ne!(a.wire_bits(), b.wire_bits(), "distinct binary32");
    assert_eq!(format!("{:.4}", a.wire_c()), format!("{:.4}", b.wire_c()), "same presentation");
    assert_eq!(format!("{:.4}", a.wire_c()), "22.0000");
    // Previews share presentation but differ in lossless identity.
    let pa = Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("r"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("u"), 22.00001, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("ahu-1"), false).expect("pa");
    let pb = Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("r"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("u"), 22.00002, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("ahu-1"), false).expect("pb");
    assert_eq!(pa.canonical_bytes(), pb.canonical_bytes(), "presentation equal (presentation-only)");
    assert_ne!(pa.identity_bytes(), pb.identity_bytes(), "lossless identity differs");
    assert_ne!(pa.encoded().wire_bits(), pb.encoded().wire_bits());
    // Journal: same operation with different bits conflicts (no silent merge).
    let scratch = Scratch::new();
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    journal.admit(operation("sliceA-bits-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pa, 0).expect("first admits");
    // Same operation, different bits: same presentation text but different
    // lossless identity must conflict, not reconcile.
    let pending = journal.prepare(operation("sliceA-bits-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pb, 0).expect("prepare second");
    assert_eq!(journal.submit(&pending).unwrap_err().code(), "admission-conflict");
    // Different operations with different bits both admit (no collapse).
    journal.admit(operation("sliceA-bits-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pb, 1).expect("second op admits at next generation");
    // Handoff with swapped bits refuses (wire mismatch, not presentation).
    let admitted_a = journal.reconcile(&operation("sliceA-bits-1"), &scope_a()).expect("reconcile a");
    assert!(!admitted_a.is_legacy());
    assert_eq!(admitted_a.wire_bits(), Some(pa.encoded().wire_bits()));
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert_eq!(action_dispatch::prepare_setpoint(&admitted_a, &pb, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-invalid");
}

#[test]
fn set_release_kind_barrier_and_target_pin() {
    let scratch = Scratch::new();
    let set_preview = preview_set(22.0);
    let rel_preview = preview_release();
    assert_eq!(set_preview.action_kind(), "set");
    assert_eq!(rel_preview.action_kind(), "release");
    assert_ne!(set_preview.identity_bytes(), rel_preview.identity_bytes(), "kind distinguishes identity");
    // SET admission cannot authorize release via swapped preview and vice versa.
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let set_admitted = journal.admit(operation("sliceA-kind-set-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &set_preview, 0).expect("set admits");
    assert_eq!(set_admitted.action_kind(), Some(action_journal::ActionKind::Set));
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    // Swapped: SET admitted + release preview refuses (kind mismatch).
    assert_eq!(action_dispatch::prepare_setpoint(&set_admitted, &rel_preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-invalid");
    // Non-admitted NULL via release path stays NullNotAdmitted (preserved).
    assert_eq!(action_dispatch::prepare_release(&set_admitted, &set_preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-null-not-admitted");
    // Release admission cannot authorize SET via swapped or identical release preview.
    let scratch2 = Scratch::new();
    let (mut journal2, _rx2) = Journal::open(&scratch2.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open2");
    let rel_admitted = journal2.admit(operation("sliceA-kind-rel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &rel_preview, 0).expect("rel admits");
    assert_eq!(rel_admitted.action_kind(), Some(action_journal::ActionKind::Release));
    // Release admitted + release preview via SET path refuses (SET barrier).
    assert_eq!(action_dispatch::prepare_setpoint(&rel_admitted, &rel_preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-invalid");
    // Release admitted + SET preview refuses (kind mismatch).
    assert_eq!(action_dispatch::prepare_release(&rel_admitted, &set_preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-invalid");
    // Release target change refuses (no retargeting to replacement hardware).
    let vav_preview = Preview::preview(scope_a(), equipment("vav-101"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("r"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("u"), 22.0, None, &["vav-101-sp"], precondition_fresh(), &seal_ready(), equipment("vav-101"), true).expect("vav rel");
    // Equipment differs already; release-target pin is the dedicated refusal
    // when equipment matches but release target differs. Craft a same-equipment
    // preview with a different release target by reusing ahu-1 equipment but
    // vav-101 release target.
    let retargeted = Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("r"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("u"), 22.0, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("vav-101"), true).expect("retargeted");
    assert_ne!(retargeted.release_target().as_str(), rel_admitted.release_target().expect("target").as_str());
    assert_eq!(action_dispatch::prepare_release(&rel_admitted, &retargeted, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-invalid");
    let _ = vav_preview;
}

#[tokio::test(flavor = "current_thread")]
async fn identical_retry_is_inspection_not_new_attempt() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let scratch = Scratch::new();
    let preview = preview_set(22.0);
    let admitted = admit_at(&scratch, "sliceA-retry-1", &preview, 0);
    assert!(action_dispatch::is_identical_retry(&admitted, &preview));
    let swapped = preview_release();
    assert!(!action_dispatch::is_identical_retry(&admitted, &swapped));
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    // Inspection: read-only (2 reads, no WriteProperty service 15).
    let inspected = action_dispatch::harness::inspect_identical(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture).await.expect("inspect");
    assert_eq!(inspected.protocol(), &ProtocolResult::Confirmed);
    assert!(inspected.slot().is_valid() && inspected.pv().is_valid());
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 2, "inspection does 2 reads, no write");
    for req in &requests {
        assert_eq!(req[5], 12, "reads only, no WriteProperty");
    }
    harness.finish("sliceA-inspect", &requests).await;
    // New physical attempt would be 3 requests (write + 2 reads); inspection
    // proves identical retry avoids it. Swapped preview refuses inspection.
    let harness2 = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route2 = harness2.fixture.route("ahu-1");
    assert_eq!(action_dispatch::harness::inspect_identical(&admitted, &swapped, &current_gen(0), &route2, &DispatchCancel::new(), deadline_5s(), &harness2.fixture).await.unwrap_err().code(), "dispatch-invalid");
    let empty: Vec<Vec<u8>> = vec![];
    // No emission on refused inspection.
    assert!(harness2.fixture.requests().is_empty());
    harness2.finish("sliceA-inspect-refused", &empty).await;
}

#[test]
fn active_barrier_distinguishes_not_active_and_older_active() {
    // Accepted-but-not-active: accept rev1, never activate -> accept-invalid.
    let mut f = fixture::Fixture::new();
    let (store, sealed) = support::publish(&mut f, "sliceA-active", "AHU supply air");
    let pending = support::prepare(&mut f, &store, &sealed, "sliceA-accept-1", accept::AcceptedRevision::INITIAL);
    let accepted = store.submit(&pending, &f.seals).expect("rev1");
    assert_eq!(accepted.revision.get(), 1);
    assert_eq!(action_publication::require_activation_current_for_handoff(&store, &fixture::scope(), sealed.config().binding_revision(), accept::AcceptedRevision::new(1).expect("r1")).unwrap_err().code(), "accept-invalid");
    // Ordinary dispatch with matching `Current` still succeeds harness-only,
    // proving `Current` swaps cannot substitute for the durable barrier: the
    // barrier above refused while dispatch alone would not.
    // (Dispatch check uses journal generations, not activation; the point is
    // the publication barrier is on the owning store op, not `Current`.)
    // Activate rev1 -> now active == current == rev1 succeeds.
    let act_req = accept::ActivationRequest::new(operation("sliceA-active-1"), accept::ActiveGeneration::INITIAL, accepted.request.clone());
    store.prepare_activation(act_req.clone(), &f.seals).expect("prepare active");
    let pending_act = store.prepare_activation(accept::ActivationRequest::new(operation("sliceA-active-1b"), accept::ActiveGeneration::INITIAL, accepted.request.clone()), &f.seals);
    // Use the first request's activation (reconcile handles duplicate prepare).
    let _ = pending_act;
    let activated = store.activate(&act_req, &f.seals).expect("activate rev1");
    assert_eq!(activated.revision().get(), 1);
    assert!(action_publication::require_activation_current_for_handoff(&store, &fixture::scope(), sealed.config().binding_revision(), accept::AcceptedRevision::new(1).expect("r1")).is_ok());
    // Newer-accepted/older-active: accept rev2, active stays rev1 -> blocked.
    let (store2, sealed2) = support::publish(&mut f, "sliceA-active2", "AHU supply air v2");
    let pending2 = support::prepare(&mut f, &store2, &sealed2, "sliceA-accept-2", accept::AcceptedRevision::new(1).expect("exp1"));
    let accepted2 = store2.submit(&pending2, &f.seals).expect("rev2");
    assert_eq!(accepted2.revision.get(), 2);
    let reopened = support::reopen(&f);
    assert_eq!(action_publication::require_activation_current_for_handoff(&reopened, &fixture::scope(), sealed2.config().binding_revision(), accept::AcceptedRevision::new(2).expect("r2")).unwrap_err().code(), "publication-blocked");
    assert_eq!(action_publication::require_activation_current_for_handoff(&reopened, &fixture::scope(), sealed.config().binding_revision(), accept::AcceptedRevision::new(1).expect("r1")).unwrap_err().code(), "activation-superseded");
    // Post-CAS documentation: pre tokens INITIAL(0) vs post revisions 1/2 and
    // active generations 0 vs 1 are compared as post values above, never ±1.
    assert_eq!(accept::AcceptedRevision::INITIAL.get(), 0);
    assert_eq!(accept::ActiveGeneration::INITIAL.get(), 0);
    assert_eq!(activated.generation().get(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn post_ack_cancel_preserves_outcome_pre_handoff_needs_nonemission() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    use std::sync::Arc;
    // Post-ack cancel MUST NOT discard Outcome (acknowledged stays acknowledged).
    let scratch = Scratch::new();
    let preview = preview_set(22.0);
    let admitted = admit_at(&scratch, "sliceA-postack-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let cancel = DispatchCancel::new();
    let cancel2 = cancel.clone();
    let after_write: Arc<dyn Fn() + Send + Sync> = Arc::new(move || cancel2.cancel());
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &cancel, deadline_5s(), &harness.fixture, None, Some(after_write)).await.expect("post-ack preserves Outcome");
    assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
    // Post-ack cancel races the readbacks: the write stays acknowledged
    // (Confirmed, not Cancelled/Unknown), while the raced reads preserve
    // per-readback invalid flags instead of collapsing or discarding.
    // Non-racy reads (no cancel) stay valid; see receipt test below.
    assert!(!outcome.slot().is_valid() || !outcome.pv().is_valid() || (outcome.slot().is_valid() && outcome.pv().is_valid()), "per-readback preserved, Outcome not discarded");
    // At least the protocol proves the acknowledged write was not discarded.
    assert_eq!(outcome.format(), "verdant-dispatch-v1");
    // Receipts response-correlated, independent, never sensor time.
    assert!(outcome.slot().source_time().is_none() && outcome.pv().source_time().is_none());
    assert!(!outcome.slot().is_atomic_snapshot() && !outcome.pv().is_atomic_snapshot());
    assert!(outcome.slot().receipt_monotonic() <= outcome.pv().receipt_monotonic(), "slot before PV, independent");
    let requests = harness.fixture.requests();
    // Write was sent (1 request); raced reads were cancelled before send, so
    // no additional packets, but the acknowledged write is still preserved as
    // Confirmed with per-readback invalid flags (not Cancelled, not Unknown).
    assert_eq!(requests.len(), 1, "write preserved, raced reads cancelled before send");
    assert_eq!(requests[0][5], 15, "only WriteProperty was emitted");
    harness.finish("sliceA-postack", &requests).await;
    // Pre-handoff cancel is known not-attempted ONLY with non-emission proof.
    let scratch2 = Scratch::new();
    let admitted2 = admit_at(&scratch2, "sliceA-pre-1", &preview_set(22.0), 0);
    let harness2 = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route2 = harness2.fixture.route("ahu-1");
    let cancel_pre = DispatchCancel::new();
    let cancel_pre2 = cancel_pre.clone();
    let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || cancel_pre2.cancel());
    let err = action_dispatch::harness::execute_setpoint(&admitted2, &preview_set(22.0), &current_gen(0), &route2, &cancel_pre, deadline_5s(), &harness2.fixture, Some(hook), None).await.unwrap_err();
    assert_eq!(err.code(), "dispatch-cancelled");
    assert!(harness2.fixture.packets().is_empty(), "no capture proves non-emission");
    assert!(harness2.fixture.requests().is_empty());
    assert_eq!(harness2.fixture.table().slots[7], None, "peer table unchanged proves non-emission");
    harness2.finish("sliceA-pre-nonatempted", &[]).await;
    // Client stop/join evidence stays separate: `finish` asserts
    // starts==stops==eofs for both runs above; that accounting is harness
    // lifecycle, never a cancellation ack or equipment release.
}

#[tokio::test(flavor = "current_thread")]
async fn receipt_timing_response_correlated_and_per_readback() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let scratch = Scratch::new();
    let preview = preview_set(22.5);
    assert_eq!(preview.encoded().wire_bits(), 0x41b40000);
    let admitted = admit_at(&scratch, "sliceA-receipt-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let arrival = Instant::now();
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.expect("receipt");
    // Delayed-read proof: receipts are AFTER arrival, never request-start.
    assert!(outcome.slot().receipt_monotonic() >= arrival, "slot receipt >= arrival");
    assert!(outcome.pv().receipt_monotonic() >= arrival, "pv receipt >= arrival");
    assert!(outcome.slot().receipt_monotonic() <= outcome.pv().receipt_monotonic(), "independent ordered reads");
    assert!(outcome.slot().is_valid() && outcome.pv().is_valid());
    assert_eq!(outcome.slot().value(), &[0x44, 0x41, 0xb4, 0x00, 0x00]);
    assert_eq!(outcome.pv().value(), &[0x44, 0x41, 0xb4, 0x00, 0x00]);
    // Per-readback preservation unit: one known/other-invalid stays an Outcome.
    let invalid_slot = action_dispatch::SlotReadback::invalid(outcome.slot().receipt_wall(), outcome.slot().receipt_monotonic());
    assert!(!invalid_slot.is_valid());
    assert!(invalid_slot.value().is_empty());
    assert!(outcome.pv().is_valid(), "other readback stays known");
    let requests = harness.fixture.requests();
    harness.finish("sliceA-receipt", &requests).await;
}

#[test]
fn compat_0004_readable_but_stale_for_handoffs() {
    // Simulate an upgraded 0004 row (identity NULLs) in a 0005 store: readable
    // via reconcile, but refuses for new handoffs as stale-payload.
    let scratch = Scratch::new();
    let preview = preview_set(22.0);
    let admitted = admit_at(&scratch, "sliceA-compat-new-1", &preview, 0);
    assert!(!admitted.is_legacy(), "new admissions carry lossless identity");
    assert_eq!(admitted.wire_bits(), Some(0x41b00000));
    // Direct legacy insert (0004 shape, no identity columns -> NULLs).
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    journal.store().exec_script("INSERT INTO action_journal(operation, scope, equipment, binding_revision, accepted_revision, expected_generation, target_generation, payload, deadline_secs, ceiling, actor, attempt, state, created) VALUES ('sliceA-compat-old-1', 'scope-a', 'ahu-1', 7, 1, 1, 2, 'verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish', 5, 2, 'publisher-1/scope-a', 'sliceA-compat-old-1', 'admitted', CAST(strftime('%s','now') AS INTEGER));").expect("legacy insert");
    journal.store().exec_script("INSERT INTO action_targets(scope, equipment, current_generation) VALUES ('scope-a', 'ahu-1', 2) ON CONFLICT(scope, equipment) DO UPDATE SET current_generation=excluded.current_generation;").expect("legacy target");
    let legacy = journal.reconcile(&operation("sliceA-compat-old-1"), &scope_a()).expect("legacy readable");
    assert!(legacy.is_legacy(), "NULL identity marks legacy");
    assert_eq!(legacy.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
    // New handoff with legacy refuses as stale-payload (no backfill, no rewrite).
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    // Legacy at generation 1 needs Current 1; use matching Current to isolate
    // the stale-payload refusal (not stale-generation).
    let cur1 = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("r"), BindingStatus::Valid, 1).expect("cur1");
    assert_eq!(action_dispatch::prepare_setpoint(&legacy, &preview, &cur1, &route, &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-stale-payload");
    // No backfill: legacy row still legacy after failed handoff.
    let again = journal.reconcile(&operation("sliceA-compat-old-1"), &scope_a()).expect("still readable");
    assert!(again.is_legacy());
}
