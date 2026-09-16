//! M02 Slice D post-handoff proof, HARNESS-ONLY. Frozen AV2/PV85/P8 degC
//! 20-24 tol0.1 15min/5s/R0/6h, `unavailable-feedback`, `source_time` None,
//! tiny_site ahu-1/scope-a, loopback peer + Scratch DB only. M02-G HELD.
//! No 0007, no receipt columns, no new dep.
//! - `post_harness_marks` (IN-PROCESS): Terminal on Confirmed, Unresolved on
//!   Unknown/lost, outside harness; Dispatched conservatively unresolved.
//! - `dropped_pending_release` (IN-PROCESS): memory-only drop -> bounded scan
//!   rediscovers, no resend.
//! - `kill_after_accept` (TRUE CHILD): kill after peer accept before marks;
//!   reopen asserts Unresolved, sent==1, no second WriteProperty.
//! - `cancel_after_ack` (TRUE CHILD): cancel after ack + kill; Unresolved.
//! - `receipt_honesty` (IN-PROCESS + TRUE CHILD): delayed receipt>=start;
//!   after restart fresh times never equal pre-kill, valid, source None.
//! Helpers `sliced_child_*` return early when env absent; parents spawn via
//! `current_exe --exact` as TRUE PIDs then `kill()`. Spawn failure skips.
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
use action_expiry::PendingRelease;
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
            "verdant-m02-sliceD-{}-{}-{tag}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&dir).expect("isolated scratch");
        Self(dir)
    }
    fn db(&self) -> std::path::PathBuf {
        self.0.join("store.db")
    }
    fn file(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
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
fn preview_raw(setpoint: f64) -> Preview {
    Preview::preview(
        scope_a(),
        equipment("ahu-1"),
        BindingRevision::new(7),
        accept::AcceptedRevision::new(1).expect("accepted"),
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
    .expect("raw preview")
}
// --- Real S03 seal for joined-path admits (Slice C precedent, no activation store) ---
const BRICK_X: &[u8] = b"@prefix b: <https://brickschema.org/schema/Brick#> .\n@prefix rec: <https://w3id.org/rec#> .\n@prefix owl: <http://www.w3.org/2002/07/owl#> .\n@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\nb:AHU a owl:Class ; rdfs:subClassOf b:Equipment .\nb:Equipment a owl:Class . b:VAV a owl:Class .\nb:Supply_Air_Temperature_Sensor a owl:Class . rec:Room a rdfs:Class .\nb:hasLocation a owl:ObjectProperty . b:feeds a owl:ObjectProperty .\nb:hasPoint a owl:ObjectProperty ; owl:inverseOf b:isPointOf .\nb:isPointOf a owl:ObjectProperty .\n";
const S223_X: &[u8] = b"@prefix s: <http://data.ashrae.org/standard223#> .\n@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\ns:QuantifiableObservableProperty a s:Class . s:observes a rdf:Property .\n";
fn s03_all() -> (semantics::sealed_profile::Profile, Vec<u8>, semantics::matrix::Report, semantics::materialize::Plan) {
    use semantics::ledger::{Fact, Kind};
    use semantics::parse::{Document, Object};
    let mut r = semantics::matrix::Report { rows: Vec::new(), ledger: Vec::new() };
    for (name, bytes) in [(semantics::recipe::BRICK, BRICK_X), (semantics::recipe::S223, S223_X)] {
        let pin = semantics::recipe::artifact(name).unwrap();
        for (s, p, o) in Document::parse(bytes).unwrap().facts() {
            r.rows.push(semantics::matrix::supported(name, s).unwrap());
            r.ledger.push(Fact { artifact: name, sha256: pin.sha256, subject: s.into(), predicate: p.into(), object: o.clone(), kind: Kind::Original, rule: "source-assertion", reason: "synthetic excerpt".into(), provenance: pin.provenance });
        }
    }
    let pin = semantics::recipe::artifact(semantics::recipe::BRICK).unwrap();
    r.ledger.push(Fact { artifact: semantics::recipe::BRICK, sha256: pin.sha256, subject: "https://brickschema.org/schema/Brick#AHU".into(), predicate: "urn:verdant:s01:ancestry-path".into(), object: Object::Iri("https://brickschema.org/schema/Brick#Equipment".into()), kind: Kind::Derived, rule: "explicit-ancestry-path", reason: "synthetic ancestry".into(), provenance: pin.provenance });
    r.rows.sort_by(|a, b| (a.artifact, &a.iri).cmp(&(b.artifact, &b.iri)));
    r.rows.dedup();
    r.ledger.sort_by_cached_key(semantics::ledger::Fact::to_json);
    r.ledger.dedup();
    let site = domain::fixture::tiny_site();
    let row = |iri: &str| r.rows.iter().find(|x| x.iri == iri).unwrap();
    let plan = semantics::materialize::Plan::tiny_site(&r, &[(&site.relationships[0], row("https://brickschema.org/schema/Brick#hasLocation")), (&site.relationships[1], row("https://brickschema.org/schema/Brick#hasLocation")), (&site.relationships[2], row("https://brickschema.org/schema/Brick#hasLocation")), (&site.relationships[3], row("https://brickschema.org/schema/Brick#feeds")), (&site.relationships[5], row("https://brickschema.org/schema/Brick#hasPoint")), (&site.relationships[6], row("https://brickschema.org/schema/Brick#hasPoint")), (&site.relationships[5], row("https://brickschema.org/schema/Brick#isPointOf"))], Some(row("http://data.ashrae.org/standard223#observes")), native::NativeSettings::local().bounds.max_statement_bytes).expect("plan");
    let prof = semantics::sealed_profile::Profile::capture(&r, &plan).expect("profile");
    let mut facts: Vec<_> = r.ledger.iter().map(semantics::ledger::Fact::to_json).collect();
    facts.sort();
    facts.dedup();
    let ledger = facts.concat().into_bytes();
    prof.ledger_status(&ledger).require().expect("roots");
    (prof, ledger, r, plan)
}
fn seal_verified() -> SealOrder {
    let (prof, ledger, r, p) = s03_all();
    let mut o = SealOrder::new();
    o.check_custody_with(&prof, &ledger).expect("custody");
    let pl: Vec<String> = prof.payloads().iter().map(|s| s.to_string()).collect();
    let refs: Vec<&str> = pl.iter().map(String::as_str).collect();
    o.decode_with(&refs).expect("decode");
    o.reconstruct_with(&r, &p).expect("reconstruct");
    assert!(o.is_verified());
    o
}
fn preview_joined(setpoint: f64) -> Preview {
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
        &seal_verified(),
        equipment("ahu-1"),
        false,
    )
    .expect("joined preview")
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
fn child_env(db: &std::path::Path, op: &str, marker: &std::path::Path, capture: &std::path::Path) -> Vec<(String, String)> {
    vec![
        ("VERDANT_SLICED_DB".to_string(), db.to_string_lossy().to_string()),
        ("VERDANT_SLICED_OP".to_string(), op.to_string()),
        ("VERDANT_SLICED_MARKER".to_string(), marker.to_string_lossy().to_string()),
        ("VERDANT_SLICED_CAPTURE".to_string(), capture.to_string_lossy().to_string()),
    ]
}

// --- TRUE CHILD helpers: separate PIDs, killed after peer accept before marks ---
fn child_vars() -> Option<(String, String, String, String)> {
    match (
        std::env::var("VERDANT_SLICED_DB"),
        std::env::var("VERDANT_SLICED_OP"),
        std::env::var("VERDANT_SLICED_MARKER"),
        std::env::var("VERDANT_SLICED_CAPTURE"),
    ) {
        (Ok(a), Ok(b), Ok(c), Ok(d)) => Some((a, b, c, d)),
        _ => None,
    }
}
async fn child_admit(db: &str, op: &str) -> (Preview, action_journal::Admitted) {
    let preview = preview_joined(22.0);
    let (mut journal, _rx) =
        Journal::open(std::path::Path::new(db), ConnectionSettings::local_wal_full(), StoreBounds::tiny())
            .expect("child open");
    let admitted = action_joined::admit_joined(
        &mut journal,
        operation(op),
        scope_a(),
        2,
        RoleKind::Publisher,
        "publisher-1/scope-a",
        &preview,
        0,
    )
    .expect("child admit");
    journal
        .mark_dispatched(admitted.operation(), admitted.scope())
        .expect("child dispatched before send");
    drop(journal);
    let (journal2, _rx2) =
        Journal::open(std::path::Path::new(db), ConnectionSettings::local_wal_full(), StoreBounds::tiny())
            .expect("child reopen");
    let admitted2 = journal2.reconcile(&operation(op), &scope_a()).expect("child reconcile");
    (preview, admitted2)
}

#[tokio::test(flavor = "current_thread")]
async fn sliced_child_confirm_kill() {
    let Some((db, op, marker, capture)) = child_vars() else { return };
    let (preview, admitted2) = child_admit(&db, &op).await;
    let harness = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route = harness.fixture.route("ahu-1");
    let marker_p = std::path::PathBuf::from(&marker);
    let capture_p = std::path::PathBuf::from(&capture);
    let fixture_c = harness.fixture.clone();
    let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        let sent = fixture_c.sent_count();
        let _ = std::fs::write(&capture_p, format!("sent={sent}"));
        let _ = std::fs::write(&marker_p, "accepted");
        std::thread::sleep(Duration::from_secs(30));
    });
    let _ = action_dispatch::harness::execute_setpoint(
        &admitted2,
        &preview,
        &current_gen(0),
        &route,
        &DispatchCancel::new(),
        deadline_5s(),
        &harness.fixture,
        None,
        Some(hook),
    )
    .await;
    std::thread::sleep(Duration::from_secs(30));
}

#[tokio::test(flavor = "current_thread")]
async fn sliced_child_cancel_kill() {
    let Some((db, op, marker, capture)) = child_vars() else { return };
    let (preview, admitted2) = child_admit(&db, &op).await;
    let harness = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route = harness.fixture.route("ahu-1");
    let cancel = DispatchCancel::new();
    let cancel_c = cancel.clone();
    let marker_p = std::path::PathBuf::from(&marker);
    let capture_p = std::path::PathBuf::from(&capture);
    let fixture_c = harness.fixture.clone();
    let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        // Cancel injected after ack (post-ack cancel must not discard the
        // acknowledged write; here we are killed before any mark anyway).
        cancel_c.cancel();
        let sent = fixture_c.sent_count();
        let _ = std::fs::write(&capture_p, format!("sent={sent}"));
        let _ = std::fs::write(&marker_p, "accepted-cancelled");
        std::thread::sleep(Duration::from_secs(30));
    });
    let _ = action_dispatch::harness::execute_setpoint(
        &admitted2,
        &preview,
        &current_gen(0),
        &route,
        &cancel,
        deadline_5s(),
        &harness.fixture,
        None,
        Some(hook),
    )
    .await;
    std::thread::sleep(Duration::from_secs(30));
}

#[tokio::test(flavor = "current_thread")]
async fn post_harness_marks_terminal_on_confirmed_unresolved_on_unknown() {
    let scratch = Scratch::new("marks-confirm");
    let preview = preview_raw(22.0);
    assert_eq!(preview.encoded().wire_bits(), 0x41b00000);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let admitted = journal
        .admit(operation("sliceD-mark-c1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("admit");
    journal.mark_dispatched(admitted.operation(), admitted.scope()).expect("dispatched");
    let harness = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_setpoint(
        &admitted,
        &preview,
        &current_gen(0),
        &route,
        &DispatchCancel::new(),
        deadline_5s(),
        &harness.fixture,
        None,
        None,
    )
    .await
    .expect("confirmed");
    assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
    assert_eq!(harness.fixture.sent_count(), 3);
    let requests = harness.fixture.requests();
    harness.finish("sliceD-marks-confirm", &requests).await;
    let (journal2, _rx2) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let terminal = action_joined::record_confirmed_terminal(&journal2, &admitted, &outcome).expect("terminal");
    assert_eq!(terminal.lifecycle(), LifecycleState::Terminal);
    assert!(action_custody::inspect_outstanding(&journal2, &scope_a()).expect("outstanding").is_empty());
    assert_eq!(
        action_joined::refuse_resend_without_qualified_recovery(&terminal).unwrap_err().code(),
        "custody-conflict"
    );
    let history = journal2.reconcile(&operation("sliceD-mark-c1"), &scope_a()).expect("history");
    assert_eq!(
        action_dispatch::prepare_setpoint(&history, &preview, &current_gen(0), &FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").unwrap(), &DispatchCancel::new(), deadline_5s()).unwrap_err().code(),
        "dispatch-invalid"
    );
    assert_eq!(
        action_joined::record_confirmed_terminal(
            &journal2,
            &admitted,
            &action_dispatch::Outcome::new(&admitted, ProtocolResult::Timeout, outcome.slot().clone(), outcome.pv().clone(), action_dispatch::Feedback::unavailable(), outcome.audit())
        )
        .unwrap_err()
        .code(),
        "custody-invalid"
    );
    let scratch2 = Scratch::new("marks-unknown");
    let (mut journal3, _rx3) = Journal::open(&scratch2.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let admitted2 = journal3
        .admit(operation("sliceD-mark-u1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("admit");
    journal3.mark_dispatched(admitted2.operation(), admitted2.scope()).expect("dispatched");
    assert!(action_joined::is_conservatively_unresolved(
        &journal3.reconcile(&operation("sliceD-mark-u1"), &scope_a()).expect("dispatched read")
    ));
    let harness2 = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::DropAfterAccept,
    )
    .await;
    let route2 = harness2.fixture.route("ahu-1");
    let err = action_dispatch::harness::execute_setpoint(
        &admitted2,
        &preview,
        &current_gen(0),
        &route2,
        &DispatchCancel::new(),
        deadline_5s(),
        &harness2.fixture,
        None,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "dispatch-unknown");
    assert_eq!(harness2.fixture.sent_count(), 1);
    let reqs2 = harness2.fixture.requests();
    harness2.finish("sliceD-marks-unknown", &reqs2).await;
    let (journal4, _rx4) = Journal::open(&scratch2.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let unresolved = action_joined::record_unknown_unresolved(&journal4, &admitted2).expect("unresolved");
    assert_eq!(unresolved.lifecycle(), LifecycleState::Unresolved);
    assert_eq!(action_custody::inspect_outstanding(&journal4, &scope_a()).expect("outstanding").len(), 1);
    assert_eq!(action_joined::refuse_resend_without_qualified_recovery(&unresolved).unwrap_err().code(), "custody-unknown");
    assert!(action_joined::is_conservatively_unresolved(&unresolved));
    assert!(!action_joined::is_conservatively_unresolved(&terminal));
}
#[test]
fn dropped_pending_release_rediscovered_via_bounded_scan_no_resend() {
    let scratch = Scratch::new("pending-drop");
    let preview = preview_raw(22.0);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let admitted = journal
        .admit(operation("sliceD-pending-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("admit");
    let pending = PendingRelease::from_admitted(&admitted);
    assert_eq!(pending.operation().as_str(), "sliceD-pending-1");
    assert_eq!(pending.target_generation(), 1);
    assert_eq!(pending.equipment().as_str(), "ahu-1");
    drop(pending);
    let found = action_expiry::release::rediscover_via_outstanding(&journal, &scope_a(), 10, 0).expect("rediscover");
    assert!(found.iter().any(|a| a.operation().as_str() == "sliceD-pending-1"));
    let via_custody =
        action_custody::custody::rediscover_obligations_via_custody(&journal, &scope_a(), 10, 0).expect("custody rediscover");
    assert_eq!(found.len(), via_custody.len());
    let helper = harness_restart::rediscover_via_outstanding(&journal, &scope_a()).expect("harness helper");
    assert!(helper.iter().any(|a| a.operation().as_str() == "sliceD-pending-1"));
    let rec = journal.reconcile(&operation("sliceD-pending-1"), &scope_a()).expect("reconcile");
    assert_eq!(rec.payload(), preview.canonical_bytes());
    assert_eq!(rec.target_generation(), 1);
    assert_eq!(rec.equipment().as_str(), "ahu-1");
    let outstanding = action_custody::inspect_outstanding(&journal, &scope_a()).expect("outstanding");
    assert!(outstanding.iter().any(|a| a.operation().as_str() == "sliceD-pending-1"));
    assert_eq!(journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count")[0][0], "1");
    let pending2 = PendingRelease::from_admitted(&rec);
    let via = pending2.reconcile_via(&journal).expect("pending reconciles");
    assert_eq!(via.operation().as_str(), "sliceD-pending-1");
}

#[tokio::test(flavor = "current_thread")]
async fn kill_after_accept_before_persist_is_unresolved_no_resend() {
    let scratch = Scratch::new("kill-confirm");
    let db = scratch.db();
    let marker = scratch.file("kill.marker");
    let capture = scratch.file("kill.capture");
    let op = "sliceD-kill-1";
    assert!(!db.exists());
    let envs = child_env(&db, op, &marker, &capture);
    let env_refs: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut child = match harness_restart::spawn_child_test("sliced_child_confirm_kill", &env_refs, &[]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP kill_after_accept: process spawn unavailable: {e}");
            return;
        }
    };
    assert!(
        harness_restart::wait_for_file(&marker, Duration::from_secs(15)),
        "marker timeout: child never accepted; fail, never hang"
    );
    let cap = std::fs::read_to_string(&capture).expect("child capture");
    assert!(cap.contains("sent=1"), "single send observed in child, got {cap}");
    assert!(
        harness_restart::kill_and_reap(&mut child, Duration::from_secs(5)),
        "reap timeout: fail, never infer stop from timeout"
    );
    let (journal, _rx) = Journal::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("fresh open");
    let recovered = journal.reconcile(&operation(op), &scope_a()).expect("reconstruct");
    assert_eq!(recovered.lifecycle(), LifecycleState::Dispatched);
    assert!(action_joined::is_conservatively_unresolved(&recovered));
    assert_eq!(recovered.target_generation(), 1);
    assert_eq!(recovered.equipment().as_str(), "ahu-1");
    assert_eq!(journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count")[0][0], "1");
    let unresolved = action_joined::record_unknown_unresolved(&journal, &recovered).expect("unresolved");
    assert_eq!(unresolved.lifecycle(), LifecycleState::Unresolved);
    let listed = harness_restart::rediscover_via_outstanding(&journal, &scope_a()).expect("rediscover");
    assert!(listed.iter().any(|a| a.operation().as_str() == op));
    assert_eq!(action_joined::refuse_resend_without_qualified_recovery(&unresolved).unwrap_err().code(), "custody-unknown");
    let preview = preview_joined(22.0);
    let harness = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route = harness.fixture.route("ahu-1");
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 0);
    let out = action_dispatch::harness::inspect_identical(
        &recovered,
        &preview,
        &current_gen(0),
        &route,
        &DispatchCancel::new(),
        deadline_5s(),
        &harness.fixture,
    )
    .await
    .expect("read-only re-observe");
    assert!(out.source_time().is_none());
    assert!(out.slot().is_valid() && out.pv().is_valid());
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 0, "no second WriteProperty");
    assert_eq!(harness_restart::count_service(&harness.fixture, 12), 2, "slot+PV reads only");
    let reqs = harness.fixture.requests();
    harness.finish("sliceD-kill-inspect", &reqs).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancel_after_ack_across_restart_is_unresolved_no_second_write() {
    let scratch = Scratch::new("kill-cancel");
    let db = scratch.db();
    let marker = scratch.file("cancel.marker");
    let capture = scratch.file("cancel.capture");
    let op = "sliceD-cancel-1";
    assert!(!db.exists());
    let envs = child_env(&db, op, &marker, &capture);
    let env_refs: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut child = match harness_restart::spawn_child_test("sliced_child_cancel_kill", &env_refs, &[]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP cancel_after_ack: process spawn unavailable: {e}");
            return;
        }
    };
    assert!(
        harness_restart::wait_for_file(&marker, Duration::from_secs(15)),
        "cancel marker timeout"
    );
    let cap = std::fs::read_to_string(&capture).expect("capture");
    assert!(cap.contains("sent=1"), "cancel raced after one send, got {cap}");
    assert!(harness_restart::kill_and_reap(&mut child, Duration::from_secs(5)), "reap timeout");
    let (journal, _rx) =
        Journal::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("fresh open");
    let recovered = journal.reconcile(&operation(op), &scope_a()).expect("reconstruct");
    assert_eq!(recovered.lifecycle(), LifecycleState::Dispatched);
    assert!(action_joined::is_conservatively_unresolved(&recovered));
    let unresolved = action_joined::record_unknown_unresolved(&journal, &recovered).expect("unresolved");
    assert_eq!(unresolved.lifecycle(), LifecycleState::Unresolved);
    // Reconcile recovers identities; no second WriteProperty.
    let rec = action_custody::reconcile_journal_via_custody(&journal, &operation(op), &scope_a()).expect("reconcile");
    assert_eq!(rec.operation().as_str(), op);
    assert_eq!(rec.target_generation(), 1);
    assert_eq!(
        action_joined::refuse_resend_without_qualified_recovery(&unresolved).unwrap_err().code(),
        "custody-unknown"
    );
    // Read-only re-observe only.
    let preview = preview_joined(22.0);
    let harness = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route = harness.fixture.route("ahu-1");
    let out = action_dispatch::harness::inspect_identical(
        &recovered,
        &preview,
        &current_gen(0),
        &route,
        &DispatchCancel::new(),
        deadline_5s(),
        &harness.fixture,
    )
    .await
    .expect("read-only");
    assert!(out.source_time().is_none());
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 0);
    let reqs = harness.fixture.requests();
    assert_eq!(harness_restart::count_service(&harness.fixture, 12), 2);
    harness.finish("sliceD-cancel-inspect", &reqs).await;
}

#[tokio::test(flavor = "current_thread")]
async fn receipt_honesty_delayed_then_fresh_after_restart() {
    // IN-PROCESS delayed proof: receipts AFTER arrival, never request-start.
    let scratch0 = Scratch::new("receipt-pre");
    let preview0 = preview_raw(22.5);
    assert_eq!(preview0.encoded().wire_bits(), 0x41b40000);
    let (mut journal0, _rx0) =
        Journal::open(&scratch0.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let admitted0 = journal0
        .admit(operation("sliceD-receipt-pre-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview0, 0)
        .expect("admit");
    let harness0 = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route0 = harness0.fixture.route("ahu-1");
    let arrival = Instant::now();
    let pre = action_dispatch::harness::execute_setpoint(
        &admitted0,
        &preview0,
        &current_gen(0),
        &route0,
        &DispatchCancel::new(),
        deadline_5s(),
        &harness0.fixture,
        None,
        None,
    )
    .await
    .expect("receipt");
    assert!(pre.slot().receipt_monotonic() >= arrival, "slot receipt >= request_start");
    assert!(pre.pv().receipt_monotonic() >= arrival, "pv receipt >= request_start");
    assert!(pre.slot().receipt_monotonic() <= pre.pv().receipt_monotonic(), "independent ordered reads");
    assert!(pre.slot().is_valid() && pre.pv().is_valid());
    assert!(pre.source_time().is_none() && pre.slot().source_time().is_none() && pre.pv().source_time().is_none());
    let pre_wall = pre.slot().receipt_wall();
    let pre_mono = pre.slot().receipt_monotonic();
    let reqs0 = harness0.fixture.requests();
    harness0.finish("sliceD-receipt-pre", &reqs0).await;
    // TRUE CHILD kill+reopen: fresh times never equal pre-kill, valid, source None.
    let scratch = Scratch::new("receipt-kill");
    let db = scratch.db();
    let marker = scratch.file("receipt.marker");
    let capture = scratch.file("receipt.capture");
    let op = "sliceD-receipt-1";
    let envs = child_env(&db, op, &marker, &capture);
    let env_refs: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut child = match harness_restart::spawn_child_test("sliced_child_confirm_kill", &env_refs, &[]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP receipt_after_restart: spawn unavailable: {e}");
            return;
        }
    };
    assert!(harness_restart::wait_for_file(&marker, Duration::from_secs(15)), "receipt marker timeout");
    assert!(harness_restart::kill_and_reap(&mut child, Duration::from_secs(5)), "reap timeout");
    let (journal, _rx) =
        Journal::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("fresh open");
    let recovered = journal.reconcile(&operation(op), &scope_a()).expect("reconstruct");
    let again = journal.reconcile(&operation(op), &scope_a()).expect("again");
    assert_eq!(recovered, again);
    let dbg = format!("{recovered:?}");
    assert!(!dbg.contains("receipt_wall") && !dbg.contains("receipt_monotonic"), "no receipt fields");
    let unresolved = action_joined::record_unknown_unresolved(&journal, &recovered).expect("unresolved");
    assert_eq!(unresolved.lifecycle(), LifecycleState::Unresolved);
    // Fresh re-observe yields fresh times (never equal pre-kill) with valid + source None.
    let preview = preview_joined(22.0);
    let harness = action_dispatch::harness::Harness::new(
        action_dispatch::harness::PeerTable::default(),
        action_dispatch::harness::PeerMode::Confirm,
    )
    .await;
    let route = harness.fixture.route("ahu-1");
    let fresh_arrival = Instant::now();
    let fresh = action_dispatch::harness::inspect_identical(
        &recovered,
        &preview,
        &current_gen(0),
        &route,
        &DispatchCancel::new(),
        deadline_5s(),
        &harness.fixture,
    )
    .await
    .expect("fresh re-observe");
    assert!(fresh.slot().receipt_monotonic() >= fresh_arrival);
    assert_ne!(fresh.slot().receipt_wall(), pre_wall, "fresh wall never equals pre-kill wall");
    assert!(fresh.slot().receipt_monotonic() > pre_mono, "fresh mono strictly after pre-kill mono");
    assert!(fresh.slot().is_valid() && fresh.pv().is_valid(), "valid re-observed");
    assert!(fresh.source_time().is_none() && fresh.slot().source_time().is_none() && fresh.pv().source_time().is_none());
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 0, "read-only, no second WriteProperty");
    let reqs = harness.fixture.requests();
    harness.finish("sliceD-receipt-fresh", &reqs).await;
}
