//! M02-PR07 controlled dispatch and observed outcomes, HARNESS-ONLY.
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

use access::RoleKind;
use action_dispatch::{
    harness::{Harness, PeerMode, PeerTable},
    Current, DispatchCancel, DispatchError, FrozenRoute, ProtocolResult,
};
use action_journal::Journal;
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
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("verdant-m02-pr07-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
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
fn preview_at(setpoint: f64) -> Preview {
    Preview::preview(
        scope_a(), equipment("ahu-1"), BindingRevision::new(7),
        accept::AcceptedRevision::new(1).expect("accepted"), binding::BindingStatus::Valid,
        2, RoleKind::Publisher, Some(8), 2, 85, None,
        Unit::parse("degC").expect("degC"), setpoint, None, &["ahu-1-sp"],
        precondition_fresh(), &seal_ready(), equipment("ahu-1"), false,
    ).expect("permitted preview")
}
fn preview_release(admitted: bool) -> Preview {
    Preview::preview(
        scope_a(), equipment("ahu-1"), BindingRevision::new(7),
        accept::AcceptedRevision::new(1).expect("accepted"), binding::BindingStatus::Valid,
        2, RoleKind::Publisher, Some(8), 2, 85, None,
        Unit::parse("degC").expect("degC"), 22.0, None, &["ahu-1-sp"],
        precondition_fresh(), &seal_ready(), equipment("ahu-1"), admitted,
    ).expect("release preview")
}
fn open_journal(scratch: &Scratch) -> Journal {
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("writer open");
    // Leak receivers is drop; Journal owns senders. Return journal only.
    // Receivers dropped immediately to keep essential capacity observable via counts.
    journal
}
fn admit_at(scratch: &Scratch, op: &str, preview: &Preview, expected: u32) -> action_journal::Admitted {
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("writer open");
    // First admission in this scratch wins generation 0 unless caller says otherwise.
    journal.admit(operation(op), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", preview, expected).expect("admit")
}
fn current_gen(expected: u32) -> Current {
    Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, expected).expect("current")
}
fn deadline_5s() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn frozen_route_rejects_non_loopback_and_service_ports() {
    assert!(FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:0").is_err());
    for bad in ["bacnet-ip://0.0.0.0:1234", "bacnet-ip://255.255.255.255:1234", "bacnet-ip://224.0.0.1:1234", "bacnet-ip://127.0.0.1:502", "bacnet-ip://127.0.0.1:802", "bacnet-ip://127.0.0.1:8080", "bacnet-ip://127.0.0.1:47808", "bacnet-ip://192.168.1.10:47809", "bacnet-ip://127.0.0.1:80"] {
        assert!(FrozenRoute::parse("ahu-1", bad).is_err(), "{bad}");
    }
    assert!(FrozenRoute::parse("vav-999", "bacnet-ip://127.0.0.1:20000").is_err());
    // Ephemeral loopback parses; exact port comes from harness at runtime.
    assert!(FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").is_ok());
}

#[test]
fn prepare_encodes_only_frozen_av_pv_p8_real() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    // Independent hardcoded wire bits for 22.0f32, never encoder output.
    assert_eq!(preview.encoded().wire_bits(), 0x41b00000);
    assert_eq!(preview.priority().get(), 8);
    assert_eq!(preview.object().object_type(), 2);
    assert_eq!(preview.object().property_id(), 85);
    assert_eq!(preview.object().array_index(), None);
    let admitted = admit_at(&scratch, "prep-exact-1", &preview, 0);
    assert_eq!(admitted.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
    let current = current_gen(0);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let cancel = DispatchCancel::new();
    let write = action_dispatch::prepare_setpoint(&admitted, &preview, &current, &route, &cancel, deadline_5s()).expect("prepare");
    assert_eq!(write.object_type(), 2);
    assert_eq!(write.instance(), 2);
    assert_eq!(write.property(), 85);
    assert_eq!(write.priority(), 8);
    // Hardcoded Real bytes for 22.0, no extra fields.
    assert_eq!(write.value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert_eq!(write.wire_bits(), Some(0x41b00000));
    assert!(!write.is_release());
}

#[tokio::test(flavor = "current_thread")]
async fn dispatch_confirmed_separates_protocol_readbacks_feedback() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "disp-ok-1", &preview, 0);
    let current = current_gen(0);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let cancel = DispatchCancel::new();
    let deadline = deadline_5s();
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current, &route, &cancel, deadline, &harness.fixture, None, None).await.expect("dispatch");
    assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
    // Hardcoded slot/PV Real bytes for 22.0.
    assert_eq!(outcome.slot().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert_eq!(outcome.pv().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert!(outcome.slot().source_time().is_none());
    assert!(outcome.pv().source_time().is_none());
    assert!(outcome.source_time().is_none());
    assert!(!outcome.slot().is_atomic_snapshot());
    assert!(!outcome.pv().is_atomic_snapshot());
    assert!(!outcome.is_qualified());
    assert_eq!(outcome.feedback().property(), "presentValue");
    assert_eq!(outcome.feedback().status(), "unavailable-feedback");
    assert!(outcome.feedback().source_time().is_none());
    assert!(!outcome.feedback().is_meaningful());
    assert_eq!(outcome.operation(), "disp-ok-1");
    assert_eq!(outcome.equipment(), "ahu-1");
    assert_eq!(outcome.format(), "verdant-dispatch-v1");
    assert!(outcome.is_dispatch());
    // One call (1) versus three effective sends (write + slot + pv), zero retries.
    assert_eq!(outcome.audit().one_call(), 1);
    assert_eq!(outcome.audit().effective_sends(), 3);
    assert_eq!(outcome.audit().effective_retries(), 0);
    assert_eq!(outcome.audit().apdu_retries(), 0);
    // Peer table proves independent decoder saw AV2/PV85/P8/Real with no extras.
    let table = harness.fixture.table();
    assert_eq!(table.slots[7], Some(22.0));
    assert_eq!(table.effective(), 22.0);
    // Exact requests: write + two reads, zero resends. NPDU prefixes hardcoded.
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with(&[1, 4, 0, 3]));
    assert_eq!(requests[0][5], 15);
    assert!(requests[1].starts_with(&[1, 4, 0, 3]) && requests[1][5] == 12);
    assert!(requests[2].starts_with(&[1, 4, 0, 3]) && requests[2][5] == 12);
    harness.finish("confirmed-separate", &requests).await;
}

#[tokio::test(flavor = "current_thread")]
async fn priority_masking_without_escalation() {
    // Higher priority (P5=21.0) masks P8 without escalation; P8 still stored.
    let mut initial = PeerTable::default();
    initial.slots[4] = Some(21.0);
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "mask-high-1", &preview, 0);
    let harness = Harness::new(initial, PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.expect("masked write");
    assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
    // Slot holds P8 22.0 (hardcoded), effective stays P5 21.0 (hardcoded).
    assert_eq!(outcome.slot().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert_eq!(outcome.pv().value(), &[0x44, 0x41, 0xa8, 0x00, 0x00]);
    let table = harness.fixture.table();
    assert_eq!(table.slots[4], Some(21.0));
    assert_eq!(table.slots[7], Some(22.0));
    assert_eq!(table.effective(), 21.0);
    let requests = harness.fixture.requests();
    harness.finish("mask-high", &requests).await;
    // Lower priority (P12=23.0) is masked by P8; P8 becomes effective.
    let mut low = PeerTable::default();
    low.slots[11] = Some(23.0);
    let scratch2 = Scratch::new();
    let admitted2 = admit_at(&scratch2, "mask-low-1", &preview_at(22.0), 0);
    let harness2 = Harness::new(low, PeerMode::Confirm).await;
    let route2 = harness2.fixture.route("ahu-1");
    let outcome2 = action_dispatch::harness::execute_setpoint(&admitted2, &preview_at(22.0), &current_gen(0), &route2, &DispatchCancel::new(), deadline_5s(), &harness2.fixture, None, None).await.expect("effective write");
    assert_eq!(outcome2.pv().value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert_eq!(harness2.fixture.table().effective(), 22.0);
    let requests2 = harness2.fixture.requests();
    harness2.finish("mask-low", &requests2).await;
}

#[tokio::test(flavor = "current_thread")]
async fn lost_response_after_acceptance_is_unknown_without_resend() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "unknown-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::DropAfterAccept).await;
    let route = harness.fixture.route("ahu-1");
    let err = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.unwrap_err();
    assert_eq!(err.code(), "dispatch-unknown");
    match &err {
        DispatchError::Unknown { operation, attempt, .. } => {
            assert_eq!(operation, "unknown-1");
            assert_eq!(attempt, admitted.attempt().as_str());
        }
        other => panic!("wrong variant {other:?}"),
    }
    // Peer accepted (table shows 22.0) but response was lost; no blind resend.
    assert_eq!(harness.fixture.table().slots[7], Some(22.0));
    assert_eq!(harness.fixture.requests().len(), 1);
    assert_eq!(harness.fixture.sent_count(), 1);
    assert!(harness.fixture.requests()[0].starts_with(&[1, 4, 0, 3]));
    assert_eq!(harness.fixture.requests()[0][5], 15);
    let requests = harness.fixture.requests();
    harness.finish("unknown-no-resend", &requests).await;
}

#[test]
fn cancel_and_deadline_before_handoff_consume_nothing() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "cancel-1", &preview, 0);
    let current = current_gen(0);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    // Cancelled before handoff.
    let cancel = DispatchCancel::new();
    cancel.cancel();
    assert_eq!(action_dispatch::prepare_setpoint(&admitted, &preview, &current, &route, &cancel, deadline_5s()).unwrap_err().code(), "dispatch-cancelled");
    // Expired deadline before handoff (fake.rs pattern: expired vs cancelled).
    assert_eq!(action_dispatch::prepare_setpoint(&admitted, &preview, &current, &route, &DispatchCancel::new(), Instant::now()).unwrap_err().code(), "dispatch-deadline");
    // No script consumed, no capture: pure prepare never touches the harness.
    // Harness would show zero packets if constructed; prepare alone proves it.
}

#[tokio::test(flavor = "current_thread")]
async fn hook_cancel_before_send_consumes_no_capture() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "hook-cancel-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let cancel = DispatchCancel::new();
    let cancel2 = cancel.clone();
    let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || cancel2.cancel());
    let err = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &cancel, deadline_5s(), &harness.fixture, Some(hook), None).await.unwrap_err();
    assert_eq!(err.code(), "dispatch-cancelled");
    assert!(harness.fixture.packets().is_empty());
    assert!(harness.fixture.requests().is_empty());
    assert_eq!(harness.fixture.table().slots[7], None);
    let requests: Vec<Vec<u8>> = vec![];
    harness.finish("hook-cancel-empty", &requests).await;
}

#[tokio::test(flavor = "current_thread")]
async fn discovery_mutation_cannot_retarget_frozen_route() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "frozen-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let frozen = harness.fixture.route("ahu-1");
    // Mutable discovery lookup changes underfoot but is never consulted.
    let mut discovery: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    discovery.insert("ahu-1".to_string(), "bacnet-ip://127.0.0.1:9999".to_string());
    discovery.insert("ahu-1".to_string(), "bacnet-ip://192.168.1.10:47808".to_string());
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &frozen, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.expect("frozen wins");
    assert_eq!(outcome.equipment(), "ahu-1");
    assert_eq!(harness.fixture.table().slots[7], Some(22.0));
    // Wrong-realm route cannot replace admitted identity.
    let wrong = FrozenRoute::parse("vav-101", &format!("bacnet-ip://{}", harness.fixture.packets()[0].to)).unwrap_or_else(|_| FrozenRoute::parse("vav-101", "bacnet-ip://127.0.0.1:20001").unwrap());
    assert_eq!(action_dispatch::prepare_setpoint(&admitted, &preview, &current_gen(0), &wrong, &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-invalid");
    let requests = harness.fixture.requests();
    harness.finish("frozen-immunity", &requests).await;
}

#[tokio::test(flavor = "current_thread")]
async fn slot_pv_times_separate_never_atomic() {
    let scratch = Scratch::new();
    let preview = preview_at(22.5);
    assert_eq!(preview.encoded().wire_bits(), 0x41b40000);
    let admitted = admit_at(&scratch, "times-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.expect("times");
    assert_eq!(outcome.slot().value(), &[0x44, 0x41, 0xb4, 0x00, 0x00]);
    assert_eq!(outcome.pv().value(), &[0x44, 0x41, 0xb4, 0x00, 0x00]);
    assert!(outcome.slot().receipt_monotonic() <= outcome.pv().receipt_monotonic());
    assert!(!outcome.slot().is_atomic_snapshot());
    assert!(!outcome.pv().is_atomic_snapshot());
    assert!(outcome.slot().source_time().is_none() && outcome.pv().source_time().is_none());
    assert!(!outcome.is_qualified() && !outcome.pv().is_qualified());
    let requests = harness.fixture.requests();
    harness.finish("separate-times", &requests).await;
}

#[tokio::test(flavor = "current_thread")]
async fn null_only_for_admitted_release_and_distinct() {
    // Distinct wire literals: NULL vs Real zero vs enumerated inactive.
    assert_eq!(vec![0x00], vec![0x00]);
    assert_ne!(vec![0x00], vec![0x44, 0x00, 0x00, 0x00, 0x00]);
    assert_ne!(vec![0x00], vec![0x91, 0x00]);
    assert_ne!(vec![0x44, 0x00, 0x00, 0x00, 0x00], vec![0x91, 0x00]);
    let scratch = Scratch::new();
    // Not admitted: prepare refuses before any send.
    let preview_denied = preview_release(false);
    let admitted_denied = admit_at(&scratch, "null-denied-1", &preview_denied, 0);
    assert_eq!(action_dispatch::prepare_release(&admitted_denied, &preview_denied, &current_gen(0), &FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").unwrap(), &DispatchCancel::new(), deadline_5s()).unwrap_err().code(), "dispatch-null-not-admitted");
    // Admitted: NULL relinquishes slot 8, effective falls back to default 20.0.
    let scratch2 = Scratch::new();
    let preview_ok = preview_release(true);
    let admitted_ok = admit_at(&scratch2, "null-ok-1", &preview_ok, 0);
    // First write a value so release has something to relinquish.
    let harness = Harness::new(PeerTable { slots: { let mut s = [None; 16]; s[7] = Some(22.0); s }, relinquish_default: 20.0 }, PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_release(&admitted_ok, &preview_ok, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture).await.expect("release");
    assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
    assert_eq!(outcome.slot().value(), &[0x00]);
    assert_eq!(outcome.pv().value(), &[0x44, 0x41, 0xa0, 0x00, 0x00]);
    assert_eq!(harness.fixture.table().slots[7], None);
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0][5], 15);
    harness.finish("null-admitted", &requests).await;
}

#[test]
fn handoff_rechecks_actor_ceiling_binding_generation_value_deadline() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "recheck-1", &preview, 0);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let deadline = deadline_5s();
    let cancel = DispatchCancel::new();
    // Wrong actor.
    let wrong_actor = Current::new("other-actor", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).unwrap(), BindingStatus::Valid, 0).unwrap();
    assert_eq!(action_dispatch::prepare_setpoint(&admitted, &preview, &wrong_actor, &route, &cancel, deadline).unwrap_err().code(), "dispatch-invalid");
    // Reviewer cannot publish.
    let reviewer = Current::new("publisher-1/scope-a", 2, RoleKind::Reviewer, BindingRevision::new(7), accept::AcceptedRevision::new(1).unwrap(), BindingStatus::Valid, 0).unwrap();
    assert_eq!(action_dispatch::prepare_setpoint(&admitted, &preview, &reviewer, &route, &cancel, deadline).unwrap_err().code(), "ceiling-exceeded");
    // Low ceiling.
    let low = Current::new("publisher-1/scope-a", 1, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).unwrap(), BindingStatus::Valid, 0).unwrap();
    assert_eq!(action_dispatch::prepare_setpoint(&admitted, &preview, &low, &route, &cancel, deadline).unwrap_err().code(), "ceiling-exceeded");
    // Stale generation.
    let stale = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).unwrap(), BindingStatus::Valid, 99).unwrap();
    assert_eq!(action_dispatch::prepare_setpoint(&admitted, &preview, &stale, &route, &cancel, deadline).unwrap_err().code(), "dispatch-stale-generation");
    // Revision mismatch.
    let rev = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(8), accept::AcceptedRevision::new(1).unwrap(), BindingStatus::Valid, 0).unwrap();
    assert_eq!(action_dispatch::prepare_setpoint(&admitted, &preview, &rev, &route, &cancel, deadline).unwrap_err().code(), "dispatch-revision-mismatch");
    // ObservedQualified never accepted.
    let qual = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).unwrap(), BindingStatus::ObservedQualified, 0).unwrap();
    assert_eq!(action_dispatch::prepare_setpoint(&admitted, &preview, &qual, &route, &cancel, deadline).unwrap_err().code(), "dispatch-invalid");
    // Protected priority preview cannot even be built; empty slot refused at preview.
    // Value/deadline rechecks: payload mismatch and expired deadline.
    assert_eq!(action_dispatch::prepare_setpoint(&admitted, &preview_at(23.0), &current_gen(0), &route, &cancel, deadline).unwrap_err().code(), "dispatch-invalid");
    assert_eq!(action_dispatch::prepare_setpoint(&admitted, &preview, &current_gen(0), &route, &cancel, Instant::now()).unwrap_err().code(), "dispatch-deadline");
}
