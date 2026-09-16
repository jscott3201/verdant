//! M02-PR10 gate journey, HARNESS-ONLY, GREENFIELD, INTEGRATION ONLY.
//!
//! Composes per-feature owner helpers and suites on the frozen profile
//! (AV2/PV85 P8, degC 20-24 tol 0.1, 900s/5s/r0/6h, NULL-only release,
//! `verdant-preview-v1`, unavailable-feedback, PAYLOAD_22, wire 0x41b00000).
//! Every feature ships its own tests; this gate asserts each journey leg and
//! that no denied operation reaches the peer (captures empty on refusals).
//! Companion legs live in `tests/m02_pr10_edges.rs` (same profile/helpers,
//! separate target so each file stays under the 700-line cap).
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
use action_custody::ScopeHolds;
use action_dispatch::{
    harness::{Harness, PeerMode, PeerTable},
    Current, DispatchCancel, DispatchError, ProtocolResult,
};
use action_expiry::ExpiryState;
use action_journal::Journal;
use action_preview::{Precondition, Preview, SealOrder};
use action_publication::ImpactGate;
use binding::BindingStatus;
use domain::clock::{BootId, MonotonicMark};
use domain::ids::{BindingRevision, InstalledId, OperationId, SourceGenerationId};
use domain::outcomes::RecordIdentity;
use domain::scope::TrustedScope;
use domain::values::Unit;
use observation::time::{ClockReading, Continuity, Freshness, FreshnessPolicy, TimeEvidence};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use storage::{ConnectionSettings, StoreBounds};

const PAYLOAD_22: &str = "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish";

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "verdant-m02-pr10-gate-{}-{}",
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
        std::fs::remove_dir_all(&self.0).expect("cleanup scratch");
    }
}
fn scope_a() -> TrustedScope {
    TrustedScope::parse("scope-a").expect("frozen scope-a")
}
fn scope_b() -> TrustedScope {
    TrustedScope::parse("scope-b").expect("frozen scope-b")
}
fn equipment(raw: &str) -> InstalledId {
    InstalledId::parse(raw).expect("frozen equipment")
}
fn operation(raw: &str) -> OperationId {
    OperationId::parse(raw).expect("operation parses")
}
fn accepted_rev(value: u32) -> accept::AcceptedRevision {
    accept::AcceptedRevision::new(value).expect("accepted revision")
}
fn precondition_fresh() -> Precondition {
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
fn preview_at(setpoint: f64) -> Preview {
    Preview::preview(
        scope_a(), equipment("ahu-1"), BindingRevision::new(7), accepted_rev(1),
        BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None,
        Unit::parse("degC").expect("degC"), setpoint, None, &["ahu-1-sp"],
        precondition_fresh(), &seal_ready(), equipment("ahu-1"), false,
    )
    .expect("permitted preview")
}
fn preview_release(admitted: bool) -> Preview {
    Preview::preview(
        scope_a(), equipment("ahu-1"), BindingRevision::new(7), accepted_rev(1),
        BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None,
        Unit::parse("degC").expect("degC"), 22.0, None, &["ahu-1-sp"],
        precondition_fresh(), &seal_ready(), equipment("ahu-1"), admitted,
    )
    .expect("release preview")
}
fn admit_at(scratch: &Scratch, op: &str, preview: &Preview, expected: u32) -> action_journal::Admitted {
    let (mut journal, _rx) = Journal::open(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("writer open");
    journal
        .admit(operation(op), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", preview, expected)
        .expect("admit")
}
fn current_gen(expected: u32) -> Current {
    Current::new(
        "publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7),
        accepted_rev(1), BindingStatus::Valid, expected,
    )
    .expect("current")
}
fn deadline_5s() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn mark(raw_boot: &str, nanos: u64) -> MonotonicMark {
    MonotonicMark::new(BootId::parse(raw_boot).expect("boot"), nanos)
}
fn freshness_policy() -> FreshnessPolicy {
    FreshnessPolicy::new(Duration::from_secs(900), Duration::from_secs(5)).expect("900s/5s")
}
fn evidence_at(receipt_ms: i64, boot_raw: &str, nanos: u64) -> TimeEvidence {
    let mark0 = mark(boot_raw, nanos);
    let ingestion = ClockReading {
        wall: action_preview::synthetic_time(receipt_ms),
        monotonic: mark(boot_raw, nanos),
        continuity: Continuity::Confirmed,
    };
    TimeEvidence::new(
        None, action_preview::synthetic_time(receipt_ms),
        runtime::ReceiptOrigin::BacnetClientReturn, mark0, ingestion,
    )
    .expect("evidence")
}

#[test]
fn frozen_profile_literals_are_verbatim() {
    let preview = preview_at(22.0);
    assert_eq!(preview.canonical_bytes(), PAYLOAD_22);
    assert_eq!(preview.format(), "verdant-preview-v1");
    assert_eq!(preview.encoded().wire_bits(), 0x41b00000);
    assert_eq!(preview.object().object_type(), 2);
    assert_eq!(preview.object().property_id(), 85);
    assert_eq!(preview.priority().get(), 8);
    assert_eq!(preview.unit().as_str(), "degC");
    assert_eq!(preview.timing().duration_secs(), 900);
    assert_eq!(preview.timing().deadline_secs(), 5);
    assert_eq!(preview.timing().apdu_retries(), 0);
    assert_eq!(preview.timing().apdu_retries(), runtime::bacnet::APDU_RETRIES);
    assert_eq!(preview.timing().rate_per_hour(), 6);
    assert_eq!(preview.encoded().mask_note(), "priority-8-masks-9-16-masked-by-1-7");
    assert_eq!(preview.feedback().status(), "unavailable-feedback");
    assert_eq!(preview.feedback().source_time(), None);
    assert_eq!(preview.release().on_expiry(), "null-relinquish");
    assert_eq!(preview.release().timeout_policy(), "uncertain-not-resend");
    assert!(!preview.is_reservation() && !preview.is_dispatch() && !preview.is_qualified());
    println!("M02_PR10_GATE profile=verbatim wire=0x41b00000 payload=PAYLOAD_22");
}

#[tokio::test(flavor = "current_thread")]
async fn allowed_human_action_full_path_on_isolated_peer() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let (mut journal, _rx) = Journal::open(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("open");
    let admitted = journal
        .admit(operation("gate-allow-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("admit");
    assert!(!admitted.reconciled() && !admitted.is_dispatch());
    assert_eq!(admitted.payload(), PAYLOAD_22);
    let current = current_gen(0);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let write = action_publication::authorize_setpoint_via_publication(
        &admitted, &preview, &current, &route, &DispatchCancel::new(), deadline_5s(),
        &ExpiryState::Active, Freshness::Fresh, None, false, &ImpactGate::Preserved,
    )
    .expect("publication authorizes");
    assert_eq!(write.value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert!(!write.is_release());
    action_custody::authorize_setpoint_via_custody(
        &admitted, &preview, &current, &route, &DispatchCancel::new(), deadline_5s(),
        &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved,
    )
    .expect("custody authorizes");
    let outcome = action_dispatch::harness::execute_setpoint(
        &admitted, &preview, &current, &route, &DispatchCancel::new(), deadline_5s(),
        &harness.fixture, None, None,
    )
    .await
    .expect("dispatch");
    assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
    assert_eq!(outcome.slot().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert_eq!(outcome.pv().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert!(outcome.source_time().is_none() && !outcome.is_qualified());
    assert_eq!(outcome.audit().one_call(), 1);
    assert_eq!(outcome.audit().effective_sends(), 3);
    assert_eq!(outcome.audit().effective_retries(), 0);
    assert_eq!(harness.fixture.table().slots[7], Some(22.0));
    action_publication::recheck_after_handoff_via_publication(&admitted, &current, &DispatchCancel::new(), deadline_5s())
        .expect("recheck");
    assert_eq!(
        action_recovery::peer_acceptance(outcome.protocol()),
        action_recovery::PeerAcceptance::Accepted
    );
    action_publication::require_peer_accepted_before_journal_via_publication(true, true).expect("ordered");
    let recovered = action_recovery::reconcile_journal(&journal, &operation("gate-allow-1"), &scope_a())
        .expect("reconcile");
    assert!(recovered.reconciled());
    assert_eq!(recovered.payload(), PAYLOAD_22);
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with(&[1, 4, 0, 3]) && requests[0][5] == 15);
    assert!(requests[1].starts_with(&[1, 4, 0, 3]) && requests[1][5] == 12);
    harness.finish("gate-allowed-full-path", &requests).await;
    println!("M02_PR10_GATE allowed=preview-admit-publish-custody-dispatch-recheck-reconcile sends=3");
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_discovery_binding_read_reconcile() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "gate-discover-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let frozen = harness.fixture.route("ahu-1");
    // Mutable discovery changes underfoot but the frozen route is never retargeted.
    let mut discovery = std::collections::HashMap::new();
    discovery.insert("ahu-1".to_string(), "bacnet-ip://127.0.0.1:9999".to_string());
    discovery.insert("ahu-1".to_string(), "bacnet-ip://192.168.1.10:47808".to_string());
    let outcome = action_dispatch::harness::execute_setpoint(
        &admitted, &preview, &current_gen(0), &frozen, &DispatchCancel::new(), deadline_5s(),
        &harness.fixture, None, None,
    )
    .await
    .expect("frozen wins");
    assert_eq!(outcome.equipment(), "ahu-1");
    // Binding revision-bound: current joins, replacement refuses.
    preview.target().require_current(BindingRevision::new(7), accepted_rev(1)).expect("current");
    assert_eq!(
        preview.target().require_current(BindingRevision::new(8), accepted_rev(1)).unwrap_err().code(),
        "preview-revision-mismatch"
    );
    // Authenticated read: outstanding work listed in scope, never cross-scope.
    let (journal, _rx) = Journal::open(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("reopen");
    let listed = action_custody::inspect_outstanding(&journal, &scope_a()).expect("inspect scope-a");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].operation().as_str(), "gate-discover-1");
    assert_eq!(listed[0].actor(), "publisher-1/scope-a");
    assert!(action_custody::inspect_outstanding(&journal, &scope_b()).expect("inspect scope-b").is_empty());
    let requests = harness.fixture.requests();
    harness.finish("gate-discovery-binding-read", &requests).await;
    println!("M02_PR10_GATE discovery=frozen binding=revision-bound read=scoped-only");
}

#[tokio::test(flavor = "current_thread")]
async fn ceiling_denial_reaches_no_peer() {
    let scratch = Scratch::new();
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    // Protected priorities 1-3 refused at preview; P8 commissioned.
    for priority in [1u8, 2, 3] {
        assert_eq!(
            action_preview::Priority::new(priority).expect("range").check_commissioned().unwrap_err().code(),
            "preview-protected-priority"
        );
    }
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "gate-ceil-1", &preview, 0);
    let reviewer = Current::new(
        "publisher-1/scope-a", 2, RoleKind::Reviewer, BindingRevision::new(7),
        accepted_rev(1), BindingStatus::Valid, 0,
    )
    .expect("reviewer");
    assert_eq!(
        action_dispatch::prepare_setpoint(&admitted, &preview, &reviewer, &route, &DispatchCancel::new(), deadline_5s())
            .unwrap_err()
            .code(),
        "ceiling-exceeded"
    );
    assert!(harness.fixture.requests().is_empty());
    assert_eq!(harness.fixture.sent_count(), 0);
    assert_eq!(harness.fixture.table().slots[7], None);
    harness.finish("gate-ceiling-empty", &[]).await;
    println!("M02_PR10_GATE ceiling=denied captures=empty");
}

#[tokio::test(flavor = "current_thread")]
async fn masking_without_escalation_under_peer_table() {
    let mut high = PeerTable::default();
    high.slots[4] = Some(21.0);
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "gate-mask-1", &preview, 0);
    let harness = Harness::new(high, PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_setpoint(
        &admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(),
        &harness.fixture, None, None,
    )
    .await
    .expect("masked write");
    assert_eq!(outcome.slot().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert_eq!(outcome.pv().value(), &[0x44, 0x41, 0xa8, 0x00, 0x00]);
    assert_eq!(harness.fixture.table().effective(), 21.0);
    let requests = harness.fixture.requests();
    harness.finish("gate-mask-high", &requests).await;
    // Lower priority masked by P8: P8 becomes effective.
    let mut low = PeerTable::default();
    low.slots[11] = Some(23.0);
    let scratch2 = Scratch::new();
    let admitted2 = admit_at(&scratch2, "gate-mask-2", &preview_at(22.0), 0);
    let harness2 = Harness::new(low, PeerMode::Confirm).await;
    let route2 = harness2.fixture.route("ahu-1");
    let outcome2 = action_dispatch::harness::execute_setpoint(
        &admitted2, &preview_at(22.0), &current_gen(0), &route2, &DispatchCancel::new(), deadline_5s(),
        &harness2.fixture, None, None,
    )
    .await
    .expect("effective write");
    assert_eq!(outcome2.pv().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert_eq!(harness2.fixture.table().effective(), 22.0);
    let requests2 = harness2.fixture.requests();
    harness2.finish("gate-mask-low", &requests2).await;
    println!("M02_PR10_GATE masking=p5-masks-p8 p12-masked escalation=never");
}

#[test]
fn conflicting_ids_refuse_with_full_identity() {
    let scratch = Scratch::new();
    let (mut journal, _rx) = Journal::open(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("open");
    journal
        .admit(operation("gate-conf-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.0), 0)
        .expect("first");
    assert_eq!(
        journal
            .admit(operation("gate-conf-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(23.0), 0)
            .unwrap_err()
            .code(),
        "admission-conflict"
    );
    assert_eq!(
        journal
            .admit(operation("gate-conf-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.5), 0)
            .unwrap_err()
            .code(),
        "admission-stale-generation"
    );
    // Full record identity decides sameness; equal slot values never prove ownership.
    let old = RecordIdentity::new(SourceGenerationId::parse("gen-1").expect("gen"), 41);
    assert!(old.is_same_record(&RecordIdentity::new(SourceGenerationId::parse("gen-1").expect("gen"), 41)));
    assert!(!old.is_same_record(&RecordIdentity::new(SourceGenerationId::parse("gen-2").expect("gen"), 41)));
    assert!(!action_recovery::slot_value_proves_ownership());
    assert_eq!(old.to_json(), "{\"generation\":\"gen-1\",\"seq\":\"41\"}");
    let kept = journal.reconcile(&operation("gate-conf-1"), &scope_a()).expect("original retained");
    assert_eq!(kept.payload(), PAYLOAD_22);
    println!("M02_PR10_GATE conflict=refused stale=refused identity=full-record");
}

#[tokio::test(flavor = "current_thread")]
async fn lost_response_unknown_reconciles_without_resend() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "gate-lost-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::DropAfterAccept).await;
    let route = harness.fixture.route("ahu-1");
    let err = action_dispatch::harness::execute_setpoint(
        &admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(),
        &harness.fixture, None, None,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "dispatch-unknown");
    match &err {
        DispatchError::Unknown { operation, attempt, .. } => {
            assert_eq!(operation, "gate-lost-1");
            assert_eq!(attempt, admitted.attempt().as_str());
        }
        other => panic!("wrong variant {other:?}"),
    }
    assert_eq!(harness.fixture.table().slots[7], Some(22.0));
    assert_eq!(harness.fixture.requests().len(), 1);
    let requests = harness.fixture.requests();
    harness.finish("gate-lost-no-resend", &requests).await;
    // UNKNOWN persists; reconcile recovers without a second send.
    let (journal, _rx) = Journal::open(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("reopen");
    let recovered = action_recovery::reconcile_journal(&journal, &operation("gate-lost-1"), &scope_a())
        .expect("reconcile");
    assert!(recovered.reconciled());
    assert_eq!(recovered.payload(), PAYLOAD_22);
    println!("M02_PR10_GATE lost=unknown-persists resend=never sends=1");
}
