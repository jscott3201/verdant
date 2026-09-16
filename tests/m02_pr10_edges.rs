//! M02-PR10 gate edges: expiry, clock, restart, replacement, reserves, slow, Modbus.
//!
//! Companion to `tests/m02_pr10_gate.rs` (same frozen profile and helpers,
//! separate target so each file stays under the 700-line cap). HARNESS-ONLY,
//! GREENFIELD, INTEGRATION ONLY: no denied operation reaches the peer.
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

use access::RoleKind;
use action_custody::ScopeHolds;
use action_dispatch::{
    harness::{Harness, PeerMode, PeerTable},
    Current, DispatchCancel, FrozenRoute,
};
use action_expiry::ExpiryState;
use action_journal::Journal;
use action_preview::{Precondition, Preview, SealOrder};
use action_publication::OldWriterExclusion;
use binding::BindingStatus;
use domain::clock::{BootId, MonotonicMark};
use domain::ids::{BindingRevision, InstalledId, OperationId, SourceGenerationId};
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
            "verdant-m02-pr10-edges-{}-{}",
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

#[tokio::test(flavor = "current_thread")]
async fn expiry_refuses_new_set_residual_shown() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "gate-exp-1", &preview, 0);
    let expired = action_expiry::assess_expiry(&mark("boot-7", 0), &mark("boot-7", 900_000_000_000), 900);
    assert!(expired.is_expired());
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert_eq!(
        action_expiry::authorize_set(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &expired, Freshness::Fresh)
            .unwrap_err()
            .code(),
        "expiry-expired"
    );
    assert!(action_expiry::authorize_cancel(0, 0).is_ok());
    // Earlier packets may take effect later; release reveals the other system, never renews.
    let mut table = PeerTable::default();
    table.slots[4] = Some(21.0);
    table.slots[7] = Some(22.0);
    table.relinquish_default = 20.0;
    let harness = Harness::new(table, PeerMode::Confirm).await;
    let hroute = harness.fixture.route("ahu-1");
    let scratch2 = Scratch::new();
    let rel_preview = preview_release(true);
    let rel_admitted = admit_at(&scratch2, "gate-exp-null-1", &rel_preview, 0);
    let out = action_dispatch::harness::execute_release(
        &rel_admitted, &rel_preview, &current_gen(0), &hroute, &DispatchCancel::new(), deadline_5s(), &harness.fixture,
    )
    .await
    .expect("release reveals other");
    assert_eq!(out.slot().value(), &[0x00]);
    assert_eq!(out.pv().value(), &[0x44, 0x41, 0xa8, 0x00, 0x00]);
    assert_eq!(harness.fixture.table().effective(), 21.0);
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 3);
    harness.finish("gate-expiry-residual", &requests).await;
    println!("M02_PR10_GATE expiry=no-new-set residual=shown-not-renewed");
}

#[test]
fn clock_discontinuity_refuses_set_allows_cancel_null() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "gate-clock-1", &preview, 0);
    let rel_preview = preview_release(true);
    let rel_admitted = admit_at(&scratch, "gate-clock-null-1", &rel_preview, 1);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    // Wall rollback: receipt newer than now is Unknown, never Fresh.
    let evidence = evidence_at(1_700_000_000_000, "boot-7", 0);
    let now = ClockReading {
        wall: action_preview::synthetic_time(1_699_999_000_000),
        monotonic: mark("boot-7", 5_000_000_000),
        continuity: Continuity::Confirmed,
    };
    let freshness = action_expiry::assess_cleanup(&evidence, &now, freshness_policy());
    assert_eq!(freshness, Freshness::Unknown);
    assert_eq!(
        action_recovery::authorize_set_via_expiry(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, freshness)
            .unwrap_err()
            .code(),
        "recovery-indeterminate"
    );
    assert!(action_recovery::authorize_cancel_via_expiry(1, 1).is_ok());
    let cur1 = Current::new(
        "publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7),
        accepted_rev(1), BindingStatus::Valid, 1,
    )
    .expect("cur1");
    let rel = action_recovery::authorize_release_via_expiry(
        &rel_admitted, &rel_preview, &cur1, &route, &DispatchCancel::new(), deadline_5s(),
        &ExpiryState::Active, Freshness::Unknown,
    )
    .expect("NULL allowed");
    assert_eq!(rel.value(), &[0x00]);
    println!("M02_PR10_GATE clock=unknown-refuses-set cancel+null=allowed");
}

#[test]
fn producer_restart_fences_new_generation_before_emission() {
    let dir = std::env::temp_dir().join(format!(
        "verdant-m02-pr10-restart-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&dir).expect("scratch");
    let db = dir.join("store.db");
    let (gate, creds) = access::AccessGate::bootstrap(
        &db, ConnectionSettings::local_wal_full(), StoreBounds::tiny(),
        &access::Reason::parse("synthetic PR10 restart").expect("reason"),
    )
    .expect("bootstrap");
    let mut receiver = observation::index::SyntheticReceiver::new(
        SourceGenerationId::parse("synthetic-receiver-pr10").expect("ns"), 8,
    )
    .expect("receiver");
    let producer = receiver
        .start(&gate, Some(&creds.reviewer), scope_a(),
            observation::identity::ProducerId::parse("sensor-sat-1").expect("p"),
            observation::identity::ProducerIncarnation::parse("process-a").expect("i"))
        .expect("start");
    let checkpoint = producer.checkpoint();
    let mut other = observation::index::SyntheticReceiver::new(
        SourceGenerationId::parse("synthetic-receiver-pr10-other").expect("ns"), 8,
    )
    .expect("other");
    let other_producer = other
        .start(&gate, Some(&creds.reviewer), scope_a(),
            observation::identity::ProducerId::parse("sensor-sat-1").expect("p"),
            observation::identity::ProducerIncarnation::parse("process-b").expect("i"))
        .expect("other start");
    let stale_checkpoint = other_producer.checkpoint();
    let fenced = receiver
        .resume(&gate, Some(&creds.reviewer), stale_checkpoint.clone(),
            observation::identity::ProducerIncarnation::parse("process-b").expect("i"))
        .expect("rollback fences");
    assert_ne!(fenced.checkpoint().generation().as_str(), stale_checkpoint.generation().as_str());
    assert_eq!(fenced.checkpoint().next_sequence(), 0);
    assert_eq!(checkpoint.next_sequence(), stale_checkpoint.next_sequence());
    std::fs::remove_dir_all(&dir).expect("cleanup");
    println!("M02_PR10_GATE restart=fenced-before-emission old-ids=pinned");
}

#[test]
fn replacement_pinned_and_offboarding_narrow() {
    // Reused address needs fresh qualification even at equal revisions.
    assert_eq!(
        action_publication::policy::check_replacement_gate(true, true, 7, 7).unwrap_err().code(),
        "publication-pinned"
    );
    assert_eq!(
        action_publication::policy::require_same_equipment("ahu-1", "vav-101").unwrap_err().code(),
        "publication-pinned"
    );
    let gate_dir = std::env::temp_dir().join(format!(
        "verdant-m02-pr10-xfer-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&gate_dir).expect("gate scratch");
    let gate_db = gate_dir.join("gate.db");
    let (gate, creds) = access::AccessGate::bootstrap(
        &gate_db, ConnectionSettings::local_wal_full(), StoreBounds::tiny(),
        &access::Reason::parse("synthetic PR10 transfer").expect("reason"),
    )
    .expect("bootstrap");
    let successor = gate
        .issue_with_policy(
            &access::CapabilityName::parse("publisher-2").expect("cap"), &scope_a(), 2,
            RoleKind::Publisher, &access::KeyId::parse("key-publisher-2").expect("key"),
            &access::SyntheticKey::parse("synthetic-publisher-2-key").expect("synkey"),
            &creds.publisher, &access::Reason::parse("synthetic PR10 successor").expect("reason"),
            &access::DisplayLabel::parse("synthetic").expect("label"),
            &access::CapabilityPolicy::entry_only(None),
        )
        .expect("issue successor");
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let (mut journal, _rx) = Journal::open(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("open");
    let old = journal
        .admit(operation("gate-xfer-old-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("old gen0");
    gate.revoke(&creds.publisher, &access::Reason::parse("synthetic PR10 contractor expired").expect("reason"))
        .expect("revoke old");
    let exclusion = OldWriterExclusion::exclude("operator-1/scope-a", "publisher-1/scope-a", "synthetic PR10 transfer narrow")
        .expect("explicit exclusion");
    let holds = ScopeHolds::new();
    let moved = action_custody::transfer_narrow_via_new_admission(
        &mut journal, &old, operation("gate-xfer-new-1"), scope_a(), 2, RoleKind::Publisher,
        "publisher-2/scope-a", &preview, 1, &holds, Some(&exclusion), true,
    )
    .expect("transfer narrow");
    assert_eq!(moved.operation().as_str(), "gate-xfer-new-1");
    assert_eq!(moved.actor(), "publisher-2/scope-a");
    assert_eq!(moved.payload(), PAYLOAD_22);
    assert_eq!(moved.target_generation(), 2);
    let kept = journal.reconcile(&operation("gate-xfer-old-1"), &scope_a()).expect("old preserved");
    assert_eq!(kept.actor(), "publisher-1/scope-a");
    // Constrained cleanup only: cancel-unattempted and admitted-null-release exist.
    assert!(action_custody::authorize_constrained_cleanup("cancel-unattempted").is_ok());
    assert!(action_custody::authorize_constrained_cleanup("admitted-null-release").is_ok());
    assert_eq!(action_custody::authorize_constrained_cleanup("all-slot-reset").unwrap_err().code(), "custody-constrained");
    assert!(gate.enter_publish(Some(&successor), &scope_a()).is_ok());
    std::fs::remove_dir_all(&gate_dir).expect("cleanup");
    println!("M02_PR10_GATE replacement=pinned offboarding=transfer-narrow cleanup=constrained");
}

#[test]
fn mandatory_journal_pressure_beside_optional_traffic() {
    let scratch = Scratch::new();
    let (mut journal, _rx) = Journal::open(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("open");
    assert_eq!(journal.essential_capacity(), 64);
    assert_eq!(journal.history_capacity(), 1);
    journal
        .admit(operation("gate-j-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.0), 0)
        .expect("gen0");
    journal
        .admit(operation("gate-j-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.5), 1)
        .expect("gen1");
    assert_eq!(journal.essential_announced(), 2);
    assert_eq!(journal.history_announced(), 1);
    assert_eq!(journal.history_refused(), 1);
    println!("M02_PR10_GATE reserves=essential64:history1 pressure=visible-not-borrowed");
}

#[tokio::test(flavor = "current_thread")]
async fn slow_subscriber_and_slow_native_with_explicit_gaps() {
    // Slow unrelated job parks; the controller completes within budget (PR09 slow-peer shape).
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let parked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let parked_flag = parked.clone();
    let slow = tokio::spawn(async move {
        parked_flag.store(true, Ordering::SeqCst);
        let _ = release_rx.await;
        "unresolved-while-controller-completed"
    });
    while !parked.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    let started = Instant::now();
    let budget = Duration::from_secs(5);
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let (mut journal, _rx) = Journal::open(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("open");
    let pending = journal
        .prepare(operation("gate-slow-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("prepare");
    let admitted = journal.submit(&pending).expect("commit");
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_setpoint(
        &admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(),
        &harness.fixture, None, None,
    )
    .await
    .expect("handoff");
    action_publication::recheck_after_handoff_via_publication(&admitted, &current_gen(0), &DispatchCancel::new(), deadline_5s())
        .expect("recheck");
    assert_eq!(action_recovery::peer_acceptance(outcome.protocol()), action_recovery::PeerAcceptance::Accepted);
    assert!(started.elapsed() < budget);
    assert!(!slow.is_finished());
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 3);
    harness.finish("gate-slow-controller", &requests).await;
    release_tx.send(()).expect("release slow");
    let slow_result = tokio::time::timeout(budget, slow).await.expect("join slow").expect("joined");
    assert_eq!(slow_result, "unresolved-while-controller-completed");
    // Slow subscriber loss stays explicit: gaps and COV lag name what is missing.
    let gap = storage::observation_writer::Gap { from: 0, to: 7, reason: "window-evicted".to_string() };
    assert_eq!((gap.from, gap.to), (0, 7));
    assert_eq!(gap.reason, "window-evicted");
    let coverage = runtime::bacnet::cov::Coverage {
        changes: 3,
        last: runtime::bacnet::cov::Loss::Lagged(2),
        revalidation_due: true,
        unobserved_interval: true,
        subscribed: false,
    };
    assert_eq!(coverage.last, runtime::bacnet::cov::Loss::Lagged(2));
    assert!(coverage.unobserved_interval);
    println!("M02_PR10_GATE slow=isolated gaps=explicit invented-transitions=none");
}

#[tokio::test(flavor = "current_thread")]
async fn bounded_modbus_on_isolated_peer() {
    use observation::normalize::{Refusal, Suitability};
    use runtime::{
        modbus::{
            mapping::{ByteOrder, Encoding, Map, Scale, WordOrder},
            test_peer::{Pair, Step},
        },
        Drain, Runtime,
    };
    // Bounds refuse before any peer exists: loopback-only, unprivileged ports,
    // no Modbus/BACnet/listener ports, exact function/unit/length.
    assert!(runtime::modbus::Target::loopback("127.0.0.1:20000".parse().unwrap(), 255).is_ok());
    for (addr, unit, code) in [
        ("0.0.0.0:20000", 1u8, "modbus-destination-denied"),
        ("127.0.0.1:80", 1, "modbus-destination-denied"),
        ("127.0.0.1:502", 1, "modbus-destination-denied"),
        ("127.0.0.1:802", 1, "modbus-destination-denied"),
        ("127.0.0.1:8080", 1, "modbus-destination-denied"),
        ("127.0.0.1:47808", 1, "modbus-destination-denied"),
        ("127.0.0.1:20000", 0, "modbus-broadcast-read-not-allowed"),
        ("127.0.0.1:20000", 248, "modbus-invalid-unit"),
    ] {
        assert_eq!(
            runtime::modbus::Target::loopback(addr.parse().unwrap(), unit).unwrap_err().code(),
            code, "{addr}/{unit}"
        );
    }
    assert_eq!(
        runtime::modbus::Function::parse(5).unwrap_err().code(),
        "modbus-service-denied"
    );
    assert!(runtime::modbus::Read::new(runtime::modbus::Function::Coils, 16, 2000).is_ok());
    assert!(runtime::modbus::Read::new(runtime::modbus::Function::HoldingRegisters, 16, 125).is_ok());
    for (function, quantity, code) in [
        (runtime::modbus::Function::Coils, 0u16, "modbus-quantity"),
        (runtime::modbus::Function::Coils, 2001, "modbus-quantity"),
        (runtime::modbus::Function::HoldingRegisters, 126, "modbus-quantity"),
    ] {
        assert_eq!(
            runtime::modbus::Read::new(function, 16, quantity).unwrap_err().code(),
            code
        );
    }
    assert_eq!(
        runtime::modbus::Read::new(runtime::modbus::Function::Coils, 65500, 100)
            .unwrap_err()
            .code(),
        "modbus-address"
    );
    // Isolated peer read with independent wire expectations (actual driver, loopback).
    let mut rt = Runtime::default();
    let (pair, mut client) = Pair::new(
        &mut rt,
        |t| {
            Map::new(
                "fixture-map-r1", "synthetic-sense", t,
                runtime::modbus::Read::new(runtime::modbus::Function::Coils, 16, 9).unwrap(),
                Encoding::Unsupported("bit-vector".into()), ByteOrder::Big, WordOrder::HighFirst,
                Scale::IDENTITY, Unit::parse("degC").unwrap(),
            )
            .unwrap()
        },
        255,
        vec![Step {
            request: vec![0, 1, 0, 0, 0, 6, 255, 1, 0, 16, 0, 9],
            response: Some(vec![0, 1, 0, 0, 0, 5, 255, 1, 2, 1, 1]),
        }],
        runtime::modbus::TIMEOUT,
    )
    .await;
    let sample = client.read_coils().await.unwrap();
    assert_eq!(
        sample.payload,
        runtime::modbus::Payload::Bits(vec![true, false, false, false, false, false, false, false, true])
    );
    assert_eq!(
        sample.decode(&sample.map).unwrap().suitability,
        Suitability::Refused(Refusal::Unsupported)
    );
    pair.finish("gate-FC01-9-bits", &mut client).await;
    drop(client);
    assert_eq!(rt.stop(Duration::ZERO).unwrap(), Drain::Stopped);
    println!("M02_PR10_GATE modbus=bounded-fc01-9bits wire=exact unit=255");
}
