//! M02 Slice E: eligibility (G1) + seal (G4) + evidence hardening.
//! SYNTHETIC/HARNESS-ONLY. Frozen AV2/PV85/P8 degC 20-24 tol0.1 15min/5s/R0/6h,
//! `unavailable-feedback`, `source_time` None, tiny_site ahu-1/scope-a,
//! loopback peer + Scratch DB only. M02-G HELD. No 0007, no receipt columns,
//! no new dep. G2/G3 EXCLUDED (Slice F).
//! - A (live-path): first eligible SET/NULL authorizes once (exactly 1
//!   WriteProperty); re-authorize while Dispatched/Unresolved/after-reopen
//!   refuses `custody-unknown` with zero new writes; identical retry stays
//!   read-only `inspect_identical` (2x service 12, 0 new service 15).
//! - B (live-path, no sleeps): admit SET(0) then release(1); old SET with its
//!   original token refuses `dispatch-stale-generation` (0 sends, stays
//!   Admitted); release with token 1 authorizes; after its honestly-lost
//!   outcome (DropAfterAccept peer) a new conflicting SET admission refuses.
//! - C (live-path): held-scope refusal leaves the row Admitted; the same row
//!   authorizes once the hold is lifted (fresh reads).
//! - D (deterministic-boundary + one live-path): `*_with_wall` boundaries
//!   (created+4 Active, created+5 Expired, now<created Indeterminate, NULL
//!   exempt) plus authorize -> shift-created -> execute with FRESH
//!   Instant/Current refusing on the expired durable anchor with zero
//!   capture, and stale-Current still gating.
//! - E (live-path, no transport): seal A verified -> rebind B clears proof
//!   (`!is_verified`, B digest, handoff preview refuses) -> complete B
//!   verifies with B digest -> failed B re-verification stays unverified
//!   with B digest (no A mixing). Stable `s03-*` codes preserved.
//! - F (deterministic): child-spawn mandatoriness branches proved with a
//!   bogus spawn target (never by breaking real spawn).
#![allow(dead_code)]
#[path = "../src/domain/mod.rs"] mod domain;
#[path = "../src/storage/mod.rs"] mod storage;
#[path = "../src/access/mod.rs"] mod access;
#[path = "../src/native/mod.rs"] mod native;
#[path = "../src/seal/mod.rs"] mod seal;
#[path = "../src/accept/mod.rs"] mod accept;
#[path = "../src/api/mod.rs"] mod api;
#[path = "../src/binding/mod.rs"] mod binding;
#[path = "../src/runtime/mod.rs"] mod runtime;
#[path = "../src/observation/mod.rs"] mod observation;
#[path = "../src/semantics/mod.rs"] mod semantics;
#[path = "../src/action_preview/mod.rs"] mod action_preview;
#[path = "../src/action_journal/mod.rs"] mod action_journal;
#[path = "../src/action_dispatch/mod.rs"] mod action_dispatch;
#[path = "../src/action_expiry/mod.rs"] mod action_expiry;
#[path = "../src/action_recovery/mod.rs"] mod action_recovery;
#[path = "../src/action_publication/mod.rs"] mod action_publication;
#[path = "../src/action_custody/mod.rs"] mod action_custody;
#[path = "../src/action_joined.rs"] mod action_joined;
#[path = "../src/action_dispatch/harness_restart.rs"] mod harness_restart;
#[path = "seal_cases/fixture.rs"] mod fixture;
#[path = "accept_cases/support.rs"] mod support;
use access::RoleKind;
use action_custody::{HoldKind, ScopeHolds};
use action_dispatch::harness::{Harness, PeerMode, PeerTable};
use action_dispatch::{Current, DispatchCancel, FrozenRoute};
use action_expiry::ExpiryState;
use action_journal::{Journal, LifecycleState};
use action_preview::{Precondition, Preview, SealOrder};
use action_publication::ImpactGate;
use binding::BindingStatus;
use domain::ids::{BindingRevision, InstalledId, OperationId};
use domain::scope::TrustedScope;
use domain::values::Unit;
use observation::time::Freshness;
use semantics::materialize::Plan;
use semantics::matrix::Report;
use semantics::recipe::{self, BRICK, S223};
use semantics::sealed_profile::Profile;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use storage::{ConnectionSettings, StoreBounds};
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("verdant-m02-sliceE-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).expect("scratch");
        Self(dir)
    }
    fn db(&self) -> std::path::PathBuf { self.0.join("store.db") }
}
impl Drop for Scratch { fn drop(&mut self) { std::fs::remove_dir_all(&self.0).expect("cleanup"); } }
fn scope_a() -> TrustedScope { TrustedScope::parse("scope-a").expect("scope-a") }
fn equipment(raw: &str) -> InstalledId { InstalledId::parse(raw).expect("equip") }
fn operation(raw: &str) -> OperationId { OperationId::parse(raw).expect("op") }
fn fresh_pre() -> Precondition {
    Precondition::new(action_preview::synthetic_time(1_700_000_000_000), action_preview::synthetic_time(1_700_000_060_000)).expect("fresh")
}
fn dl5() -> Instant { Instant::now() + Duration::from_secs(5) }
fn cur(binding: BindingRevision, accepted: accept::AcceptedRevision, gen: u32) -> Current {
    Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, binding, accepted, BindingStatus::Valid, gen).expect("cur")
}
const BRICK_X: &[u8] = b"@prefix b: <https://brickschema.org/schema/Brick#> .\n@prefix rec: <https://w3id.org/rec#> .\n@prefix owl: <http://www.w3.org/2002/07/owl#> .\n@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\nb:AHU a owl:Class ; rdfs:subClassOf b:Equipment .\nb:Equipment a owl:Class . b:VAV a owl:Class .\nb:Supply_Air_Temperature_Sensor a owl:Class . rec:Room a rdfs:Class .\nb:hasLocation a owl:ObjectProperty . b:feeds a owl:ObjectProperty .\nb:hasPoint a owl:ObjectProperty ; owl:inverseOf b:isPointOf .\nb:isPointOf a owl:ObjectProperty .\n";
const S223_X: &[u8] = b"@prefix s: <http://data.ashrae.org/standard223#> .\n@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\ns:QuantifiableObservableProperty a s:Class . s:observes a rdf:Property .\n";
fn s03_report() -> Report {
    use semantics::ledger::{Fact, Kind};
    use semantics::parse::{Document, Object};
    let mut r = Report { rows: Vec::new(), ledger: Vec::new() };
    for (name, bytes) in [(BRICK, BRICK_X), (S223, S223_X)] {
        let pin = recipe::artifact(name).unwrap();
        for (s, p, o) in Document::parse(bytes).unwrap().facts() {
            r.rows.push(semantics::matrix::supported(name, s).unwrap());
            r.ledger.push(Fact { artifact: name, sha256: pin.sha256, subject: s.into(), predicate: p.into(), object: o.clone(), kind: Kind::Original, rule: "source-assertion", reason: "synthetic excerpt".into(), provenance: pin.provenance });
        }
    }
    let pin = recipe::artifact(BRICK).unwrap();
    r.ledger.push(Fact { artifact: BRICK, sha256: pin.sha256, subject: "https://brickschema.org/schema/Brick#AHU".into(), predicate: "urn:verdant:s01:ancestry-path".into(), object: Object::Iri("https://brickschema.org/schema/Brick#Equipment".into()), kind: Kind::Derived, rule: "explicit-ancestry-path", reason: "synthetic ancestry".into(), provenance: pin.provenance });
    r.rows.sort_by(|a, b| (a.artifact, &a.iri).cmp(&(b.artifact, &b.iri)));
    r.rows.dedup();
    r.ledger.sort_by_cached_key(semantics::ledger::Fact::to_json);
    r.ledger.dedup();
    r
}
fn s03_plan(r: &Report) -> Plan {
    let site = domain::fixture::tiny_site();
    let row = |iri: &str| r.rows.iter().find(|x| x.iri == iri).unwrap();
    let loc = row("https://brickschema.org/schema/Brick#hasLocation");
    let pt = row("https://brickschema.org/schema/Brick#hasPoint");
    Plan::tiny_site(r, &[(&site.relationships[0], loc), (&site.relationships[1], loc), (&site.relationships[2], loc), (&site.relationships[3], row("https://brickschema.org/schema/Brick#feeds")), (&site.relationships[5], pt), (&site.relationships[6], pt), (&site.relationships[5], row("https://brickschema.org/schema/Brick#isPointOf"))], Some(row("http://data.ashrae.org/standard223#observes")), native::NativeSettings::local().bounds.max_statement_bytes).expect("plan")
}
fn ledger_bytes_of(r: &Report) -> Vec<u8> {
    let mut facts: Vec<_> = r.ledger.iter().map(semantics::ledger::Fact::to_json).collect();
    facts.sort();
    facts.dedup();
    facts.concat().into_bytes()
}
fn s03_all() -> (Profile, Vec<u8>, Report, Plan) {
    let r = s03_report();
    let p = s03_plan(&r);
    let prof = Profile::capture(&r, &p).expect("profile");
    let ledger = ledger_bytes_of(&r);
    prof.ledger_status(&ledger).require().expect("roots");
    (prof, ledger, r, p)
}
/// Distinct second subject B: same rows/plan as A plus one extra derived
/// ledger fact, so the digest (hence the profile) differs while the pair
/// still self-verifies. Frozen scope, no new fixture surface.
fn s03_subject_b(r_a: &Report, p: &Plan) -> (Profile, Vec<u8>, Report) {
    use semantics::ledger::{Fact, Kind};
    use semantics::parse::Object;
    let pin = recipe::artifact(BRICK).unwrap();
    let mut r_b = s03_report();
    r_b.ledger.push(Fact { artifact: BRICK, sha256: pin.sha256, subject: "https://brickschema.org/schema/Brick#VAV".into(), predicate: "urn:verdant:s01:sliceE-subject".into(), object: Object::Iri("https://brickschema.org/schema/Brick#Equipment".into()), kind: Kind::Derived, rule: "synthetic-sliceE-distinct-subject", reason: "sliceE second seal subject".into(), provenance: pin.provenance });
    assert_eq!(r_b.rows, r_a.rows, "B shares A rows; only the ledger subject differs");
    let prof_b = Profile::capture(&r_b, p).expect("profile B");
    let ledger_b = ledger_bytes_of(&r_b);
    prof_b.ledger_status(&ledger_b).require().expect("B roots");
    (prof_b, ledger_b, r_b)
}
fn seal_ok() -> SealOrder {
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
fn pv_ok(binding: BindingRevision, accepted: accept::AcceptedRevision, sp: f64, rel: bool) -> Preview {
    Preview::preview(scope_a(), equipment("ahu-1"), binding, accepted, BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("u"), sp, None, &["ahu-1-sp"], fresh_pre(), &seal_ok(), equipment("ahu-1"), rel).expect("pv")
}
fn active1() -> (fixture::Fixture, accept::AcceptanceStore, BindingRevision, accept::AcceptedRevision) {
    let mut f = fixture::Fixture::new();
    let (store, sealed) = support::publish(&mut f, "sliceE-a", "AHU supply air");
    let pend = support::prepare(&mut f, &store, &sealed, "sliceE-acc-1", accept::AcceptedRevision::INITIAL);
    let acc = store.submit(&pend, &f.seals).expect("rev1");
    let req = accept::ActivationRequest::new(operation("sliceE-act-1"), accept::ActiveGeneration::INITIAL, acc.request.clone());
    store.prepare_activation(req.clone(), &f.seals).expect("prep");
    let act = store.activate(&req, &f.seals).expect("act");
    assert_eq!(act.revision().get(), 1);
    (f, store, sealed.config().binding_revision(), accept::AcceptedRevision::new(1).expect("r1"))
}
fn open_journal(scratch: &Scratch) -> Journal {
    let (j, _) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    j
}
fn shift_created(scratch: &Scratch, op: &str, delta: i64) {
    let j = open_journal(scratch);
    j.store().exec_script(&format!("UPDATE action_journal SET created = created + ({delta}) WHERE operation='{op}';")).expect("shift");
}
fn auth_set(journal: &Journal, store: &accept::AcceptanceStore, admitted: &action_journal::Admitted, pv: &Preview, current: &Current, route: &FrozenRoute) -> Result<action_dispatch::FrozenWrite, action_custody::CustodyError> {
    action_joined::authorize_joined_setpoint(journal, store, admitted, pv, current, route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved)
}
fn auth_release(journal: &Journal, store: &accept::AcceptanceStore, admitted: &action_journal::Admitted, pv: &Preview, current: &Current, route: &FrozenRoute) -> Result<action_dispatch::FrozenWrite, action_custody::CustodyError> {
    action_joined::authorize_joined_release(journal, store, admitted, pv, current, route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved)
}
// A (SET, live-path): exactly one WriteProperty, then every re-authorize
// refuses custody-unknown with zero new writes; identical retry is read-only.
#[tokio::test(flavor = "current_thread")]
async fn set_resend_brake_no_second_write() {
    let (_f, store, binding, rev) = active1();
    let pv = pv_ok(binding, rev, 22.0, false);
    let scratch = Scratch::new();
    let mut j = open_journal(&scratch);
    let adm = action_joined::admit_joined(&mut j, operation("e-brake-set-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv, 0).expect("admit");
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    auth_set(&j, &store, &adm, &pv, &cur(binding, rev, 0), &route).expect("first authorize");
    assert_eq!(j.reconcile(&operation("e-brake-set-1"), &scope_a()).expect("rec").lifecycle(), LifecycleState::Dispatched);
    let fresh = j.reconcile(&operation("e-brake-set-1"), &scope_a()).expect("fresh");
    action_dispatch::harness::execute_setpoint(&fresh, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &harness.fixture, None, None).await.expect("one send");
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 1, "exactly 1 WriteProperty");
    // Sequential double-authorize while Dispatched: stale snapshot or fresh,
    // both refuse before any mark, zero new writes.
    assert_eq!(auth_set(&j, &store, &adm, &pv, &cur(binding, rev, 0), &route).unwrap_err().code(), "custody-unknown");
    assert_eq!(auth_set(&j, &store, &fresh, &pv, &cur(binding, rev, 0), &route).unwrap_err().code(), "custody-unknown");
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 1, "0 new writes");
    // Honestly-lost outcome -> Unresolved still refuses.
    let unresolved = action_joined::record_unknown_unresolved(&j, &fresh).expect("unresolved");
    assert_eq!(unresolved.lifecycle(), LifecycleState::Unresolved);
    assert_eq!(auth_set(&j, &store, &unresolved, &pv, &cur(binding, rev, 0), &route).unwrap_err().code(), "custody-unknown");
    // Fresh process (reopen, no old objects) reconciles Unresolved and refuses.
    drop(j);
    let j2 = open_journal(&scratch);
    let rec = j2.reconcile(&operation("e-brake-set-1"), &scope_a()).expect("reopen");
    assert_eq!(rec.lifecycle(), LifecycleState::Unresolved);
    assert!(action_joined::is_conservatively_unresolved(&rec));
    assert_eq!(auth_set(&j2, &store, &rec, &pv, &cur(binding, rev, 0), &route).unwrap_err().code(), "custody-unknown");
    // Identical retry stays read-only inspect: +2 service-12 reads, 0 new writes.
    let reads = harness_restart::count_service(&harness.fixture, 12);
    action_dispatch::harness::inspect_identical(&rec, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &harness.fixture).await.expect("read-only");
    assert_eq!(harness_restart::count_service(&harness.fixture, 12), reads + 2, "slot+PV reads only");
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 1, "still exactly 1 WriteProperty");
    let reqs = harness.fixture.requests();
    harness.finish("sliceE-brake-set", &reqs).await;
}
// A (NULL release path): same brake shape without hiding behind the SET wall.
#[tokio::test(flavor = "current_thread")]
async fn release_resend_brake_null_path() {
    let (_f, store, binding, rev) = active1();
    let rel = pv_ok(binding, rev, 22.0, true);
    let scratch = Scratch::new();
    let mut j = open_journal(&scratch);
    let adm = action_joined::admit_joined(&mut j, operation("e-brake-rel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &rel, 0).expect("admit release");
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let write = auth_release(&j, &store, &adm, &rel, &cur(binding, rev, 0), &route).expect("first authorize");
    assert!(write.is_release());
    assert_eq!(write.value(), &[0x00]);
    let fresh = j.reconcile(&operation("e-brake-rel-1"), &scope_a()).expect("fresh");
    action_dispatch::harness::execute_release(&fresh, &rel, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &harness.fixture).await.expect("one NULL send");
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 1, "exactly 1 WriteProperty");
    assert_eq!(auth_release(&j, &store, &adm, &rel, &cur(binding, rev, 0), &route).unwrap_err().code(), "custody-unknown");
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 1, "0 new writes");
    let unresolved = action_joined::record_unknown_unresolved(&j, &fresh).expect("unresolved");
    assert_eq!(auth_release(&j, &store, &unresolved, &rel, &cur(binding, rev, 0), &route).unwrap_err().code(), "custody-unknown");
    drop(j);
    let j2 = open_journal(&scratch);
    let rec = j2.reconcile(&operation("e-brake-rel-1"), &scope_a()).expect("reopen");
    assert_eq!(auth_release(&j2, &store, &rec, &rel, &cur(binding, rev, 0), &route).unwrap_err().code(), "custody-unknown");
    let reads = harness_restart::count_service(&harness.fixture, 12);
    action_dispatch::harness::inspect_identical(&rec, &rel, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &harness.fixture).await.expect("read-only");
    assert_eq!(harness_restart::count_service(&harness.fixture, 12), reads + 2, "slot+PV reads only");
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 1, "still exactly 1 WriteProperty");
    let reqs = harness.fixture.requests();
    harness.finish("sliceE-brake-release", &reqs).await;
}
// B (live-path): durable currency. Pre-admission token (expected, checked
// against caller Current), post-admission value (target = expected + 1, set
// at admit), and durable current (action_targets, advanced by later admits)
// stay distinct: handoff needs target == durable-current.
#[tokio::test(flavor = "current_thread")]
async fn durable_currency_supersession_refuses() {
    let (_f, store, binding, rev) = active1();
    let set = pv_ok(binding, rev, 22.0, false);
    let rel = pv_ok(binding, rev, 22.0, true);
    let scratch = Scratch::new();
    let mut j = open_journal(&scratch);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    action_joined::admit_joined(&mut j, operation("e-cur-set-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &set, 0).expect("SET(0)");
    action_joined::admit_joined(&mut j, operation("e-cur-rel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &rel, 1).expect("release(1)");
    assert_eq!(j.durable_current_generation(&scope_a(), &equipment("ahu-1")).expect("durable"), 2);
    // Old SET with its original token: token check would pass (0 == expected
    // 0) but durable current (2) != post-admission value (1) -> stale refuse.
    let old = j.reconcile(&operation("e-cur-set-1"), &scope_a()).expect("old");
    assert_eq!(auth_set(&j, &store, &old, &set, &cur(binding, rev, 0), &route).unwrap_err().code(), "dispatch-stale-generation");
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 0, "0 sends");
    assert!(harness.fixture.requests().is_empty());
    assert_eq!(j.reconcile(&operation("e-cur-set-1"), &scope_a()).expect("rec").lifecycle(), LifecycleState::Admitted, "refusal leaves Admitted");
    // Release with token 1: target 2 == durable 2 -> allowed.
    let rel_adm = j.reconcile(&operation("e-cur-rel-1"), &scope_a()).expect("rel");
    auth_release(&j, &store, &rel_adm, &rel, &cur(binding, rev, 1), &route).expect("release allowed");
    // One Harness at a time (PORT_GUARD): finish the idle harness before the
    // lossy one. Honestly-lost release outcome via a peer that accepts then
    // drops the reply: real send, lost response -> Unknown -> Unresolved.
    let reqs = harness.fixture.requests();
    harness.finish("sliceE-currency-idle", &reqs).await;
    let harness2 = Harness::new(PeerTable::default(), PeerMode::DropAfterAccept).await;
    let route2 = harness2.fixture.route("ahu-1");
    let fresh_rel = j.reconcile(&operation("e-cur-rel-1"), &scope_a()).expect("dispatched");
    assert_eq!(fresh_rel.lifecycle(), LifecycleState::Dispatched);
    let err = action_dispatch::harness::execute_release(&fresh_rel, &rel, &cur(binding, rev, 1), &route2, &DispatchCancel::new(), dl5(), &harness2.fixture).await.unwrap_err();
    assert_eq!(err.code(), "dispatch-unknown");
    let unresolved = action_joined::record_unknown_unresolved(&j, &fresh_rel).expect("unresolved");
    assert_eq!(unresolved.lifecycle(), LifecycleState::Unresolved);
    // New conflicting SET while Unresolved outstanding: stale token refuses
    // at admission (existing CAS, no regression).
    assert_eq!(action_joined::admit_joined(&mut j, operation("e-cur-set-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &set, 1).unwrap_err().code(), "admission-stale-generation");
    let reqs2 = harness2.fixture.requests();
    assert_eq!(harness_restart::write_property_count(&harness2.fixture), 1, "only the honestly-lost release sent");
    harness2.finish("sliceE-currency-lost", &reqs2).await;
}
// C (live-path): a hold refusal before any possible handoff leaves the row
// Admitted; the same row authorizes once fresh reads lift the hold.
#[test]
fn mark_ordering_held_refusal_stays_admitted() {
    let (_f, store, binding, rev) = active1();
    let pv = pv_ok(binding, rev, 22.0, false);
    let scratch = Scratch::new();
    let mut j = open_journal(&scratch);
    let adm = action_joined::admit_joined(&mut j, operation("e-mark-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv, 0).expect("admit");
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let mut holds = ScopeHolds::new();
    holds.hold("scope-a", HoldKind::Active, "synthetic maintenance").expect("hold");
    assert_eq!(action_joined::authorize_joined_setpoint(&j, &store, &adm, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).unwrap_err().code(), "custody-held");
    assert_eq!(j.reconcile(&operation("e-mark-1"), &scope_a()).expect("rec").lifecycle(), LifecycleState::Admitted, "pre-handoff refusal never marks");
    // Same row with fresh (unheld) reads: granted permit marks Dispatched.
    auth_set(&j, &store, &adm, &pv, &cur(binding, rev, 0), &route).expect("permit after hold lifted");
    assert_eq!(j.reconcile(&operation("e-mark-1"), &scope_a()).expect("rec2").lifecycle(), LifecycleState::Dispatched);
}
// D (deterministic boundary): wall math via explicit now_secs. Deadline is
// 5s: created+4 Active, created+5 Expired, now<created Indeterminate; an
// admitted NULL stays exempt.
#[test]
fn wall_boundaries_deterministic() {
    let (_f, store, binding, rev) = active1();
    let pv = pv_ok(binding, rev, 22.0, false);
    let rel = pv_ok(binding, rev, 22.0, true);
    let scratch = Scratch::new();
    let mut j = open_journal(&scratch);
    let adm = action_joined::admit_joined(&mut j, operation("e-wall-set-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv, 0).expect("admit");
    let rel_adm = action_joined::admit_joined(&mut j, operation("e-wall-rel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &rel, 1).expect("admit null");
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let created = adm.created_secs();
    assert!(action_expiry::authorize_set_with_wall(&adm, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, created + 4).is_ok(), "created+4 Active");
    assert_eq!(action_expiry::authorize_set_with_wall(&adm, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, created + 5).unwrap_err().code(), "expiry-expired", "created+5 Expired");
    assert_eq!(action_expiry::authorize_set_with_wall(&adm, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, created - 1).unwrap_err().code(), "expiry-indeterminate", "now<created Indeterminate");
    let rel_created = rel_adm.created_secs();
    assert!(action_expiry::authorize_release_with_wall(&rel_adm, &rel, &cur(binding, rev, 1), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, rel_created, rel_created + 5).is_ok(), "admitted NULL exempt when expired");
    // Same values through the dispatch transport-boundary gate: both
    // implementations share one boundary, drift fails here.
    assert!(action_dispatch::lifecycle_decision::verify_durable_wall_for_set_with_now(&adm, created + 4).is_ok(), "dispatch created+4 Active");
    assert_eq!(action_dispatch::lifecycle_decision::verify_durable_wall_for_set_with_now(&adm, created + 5).unwrap_err().code(), "dispatch-invalid", "dispatch created+5 Expired");
    assert!(action_dispatch::lifecycle_decision::verify_durable_wall_for_set_with_now(&adm, created + 5).unwrap_err().to_string().contains("durable deadline wall expired"));
    assert_eq!(action_dispatch::lifecycle_decision::verify_durable_wall_for_set_with_now(&adm, created - 1).unwrap_err().code(), "dispatch-invalid", "dispatch now<created Indeterminate");
    let _ = store;
}
// D (one live-path delay case): authorize, then the durable anchor expires;
// executing with a FRESH Instant/Current still refuses with zero capture,
// and a stale Current still gates on generation.
#[tokio::test(flavor = "current_thread")]
async fn delayed_execute_refuses_on_expired_anchor() {
    let (_f, store, binding, rev) = active1();
    let pv = pv_ok(binding, rev, 22.0, false);
    let scratch = Scratch::new();
    let mut j = open_journal(&scratch);
    let adm = action_joined::admit_joined(&mut j, operation("e-delay-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv, 0).expect("admit");
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    auth_set(&j, &store, &adm, &pv, &cur(binding, rev, 0), &route).expect("permit");
    drop(j);
    shift_created(&scratch, "e-delay-1", -6);
    let j2 = open_journal(&scratch);
    let aged = j2.reconcile(&operation("e-delay-1"), &scope_a()).expect("aged");
    assert_eq!(aged.lifecycle(), LifecycleState::Dispatched);
    // Fresh Instant (+5s) plus fresh Current cannot renew the durable anchor.
    let err = action_dispatch::harness::execute_setpoint(&aged, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &harness.fixture, None, None).await.unwrap_err();
    assert_eq!(err.code(), "dispatch-invalid");
    assert!(err.to_string().contains("durable deadline wall expired"), "got {err}");
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 0, "zero capture");
    assert!(harness.fixture.requests().is_empty());
    // Fresh target reads still gate: unexpired row but stale Current refuses.
    let adm2 = {
        let mut j3 = open_journal(&scratch);
        action_joined::admit_joined(&mut j3, operation("e-delay-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv, 1).expect("admit2")
    };
    let stale = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, binding, rev, BindingStatus::Valid, 99).expect("stale");
    let err2 = action_dispatch::harness::execute_setpoint(&adm2, &pv, &stale, &route, &DispatchCancel::new(), dl5(), &harness.fixture, None, None).await.unwrap_err();
    assert_eq!(err2.code(), "dispatch-stale-generation");
    assert_eq!(harness_restart::write_property_count(&harness.fixture), 0, "zero capture");
    let reqs = harness.fixture.requests();
    harness.finish("sliceE-delay", &reqs).await;
}
// E (live-path, no transport): rebind clears proof (G4 clear-on-subject-change).
#[test]
fn seal_rebind_clears_proof_no_mixed_digest() {
    let (prof_a, ledger_a, r_a, plan) = s03_all();
    let (prof_b, ledger_b, r_b) = s03_subject_b(&r_a, &plan);
    assert_ne!(prof_a.ledger_digest(), prof_b.ledger_digest(), "A and B are distinct subjects");
    // Verify A through the full real-owner chain.
    let mut seal = SealOrder::new();
    seal.check_custody_with(&prof_a, &ledger_a).expect("custody A");
    let pl_a: Vec<String> = prof_a.payloads().iter().map(|s| s.to_string()).collect();
    let refs_a: Vec<&str> = pl_a.iter().map(String::as_str).collect();
    seal.decode_with(&refs_a).expect("decode A");
    seal.reconstruct_with(&r_a, &plan).expect("reconstruct A");
    assert!(seal.is_verified());
    assert_eq!(seal.ledger_digest(), Some(prof_a.ledger_digest()));
    // Rebind to B is allowed (not rejected) but clears the proof: unverified,
    // B digest only, and no handoff-grade preview can be built from it.
    seal.check_custody_with(&prof_b, &ledger_b).expect("rebind allowed");
    assert!(!seal.is_verified(), "A proof must not verify B");
    assert_eq!(seal.ledger_digest(), Some(prof_b.ledger_digest()), "digest is B, never A mixed in");
    assert_eq!(seal.verified_availability().unwrap_err().code(), "preview-seal-order");
    let (_f, _store, binding, rev) = active1();
    assert_eq!(Preview::preview(scope_a(), equipment("ahu-1"), binding, rev, BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("u"), 22.0, None, &["ahu-1-sp"], fresh_pre(), &seal, equipment("ahu-1"), false).unwrap_err().code(), "preview-seal-order", "joined admit/handoff with B refuses");
    // Complete B: decode + reconstruct verifies with the B digest.
    let pl_b: Vec<String> = prof_b.payloads().iter().map(|s| s.to_string()).collect();
    let refs_b: Vec<&str> = pl_b.iter().map(String::as_str).collect();
    seal.decode_with(&refs_b).expect("decode B");
    seal.reconstruct_with(&r_b, &plan).expect("reconstruct B");
    assert!(seal.is_verified());
    assert_eq!(seal.ledger_digest(), Some(prof_b.ledger_digest()));
    // Failed B re-verification: still unverified, B digest, stable s03-* code.
    let mut seal2 = SealOrder::new();
    seal2.check_custody_with(&prof_a, &ledger_a).expect("custody A");
    seal2.decode_with(&refs_a).expect("decode A");
    seal2.reconstruct_with(&r_a, &plan).expect("reconstruct A");
    assert!(seal2.is_verified());
    seal2.check_custody_with(&prof_b, &ledger_b).expect("rebind B");
    seal2.decode_with(&refs_b).expect("decode B");
    let mut bad = s03_report();
    bad.ledger.pop();
    let code = seal2.reconstruct_with(&bad, &plan).unwrap_err().code();
    assert!(code == "s03-ledger-digest-mismatch" || code == "s03-meaning-mismatch", "stable s03 code, got {code}");
    assert!(!seal2.is_verified(), "failed B re-verification stays unverified");
    assert_eq!(seal2.ledger_digest(), Some(prof_b.ledger_digest()), "no A digest mixed back in");
}
// F (deterministic): spawn mandatoriness branches with a bogus target.
#[test]
fn spawn_mandatoriness_branches_with_bogus_target() {
    struct EnvGuard { saved: Option<String> }
    impl EnvGuard {
        fn hold() -> Self {
            let saved = std::env::var("VERDANT_REQUIRE_CHILD").ok();
            Self { saved }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.saved {
                Some(v) => std::env::set_var("VERDANT_REQUIRE_CHILD", v),
                None => std::env::remove_var("VERDANT_REQUIRE_CHILD"),
            }
        }
    }
    let _guard = EnvGuard::hold();
    // Bogus spawn target fails without touching real spawn.
    let bogus = std::path::Path::new("/nonexistent/verdant-sliceE-bogus-target");
    let spawn_err = harness_restart::spawn_child_test_with_exe(bogus, "sliced_bogus_target", &[], &[]).unwrap_err();
    assert_eq!(spawn_err.kind(), std::io::ErrorKind::NotFound);
    // Local default: SKIP-with-reason (returned Err, never a pass claim).
    std::env::remove_var("VERDANT_REQUIRE_CHILD");
    assert!(!harness_restart::child_spawn_mandatory());
    let skip = harness_restart::map_spawn_error("sliced_bogus_target", std::io::Error::new(std::io::ErrorKind::NotFound, "bogus")).unwrap_err();
    assert_eq!(skip.kind(), std::io::ErrorKind::NotFound);
    // CI mandatoriness: hard-fails (panics) instead of SKIP-and-pass.
    std::env::set_var("VERDANT_REQUIRE_CHILD", "1");
    assert!(harness_restart::child_spawn_mandatory());
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = harness_restart::map_spawn_error("sliced_bogus_target", std::io::Error::new(std::io::ErrorKind::NotFound, "bogus"));
    }));
    let panic_msg = caught.expect_err("mandatory branch must panic, never SKIP");
    let text = panic_msg.downcast_ref::<String>().cloned().or_else(|| panic_msg.downcast_ref::<&str>().map(|s| s.to_string())).expect("panic message");
    assert!(text.contains("VERDANT_REQUIRE_CHILD=1"), "got {text}");
}
