//! M02 Slice C: seal join, joined handoff, durable wall. SYNTHETIC/HARNESS-ONLY.
//! Frozen: AV2/PV85/P8 degC 20-24 tol0.1 15min/5s/R0/6h, unavailable-feedback.
//! M02-G HELD. Sec7 child-process proof is Slice D. No child process here.
//! Dispatch only via `action_joined`; raw prepare/admit/execute never called.
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
#[path = "seal_cases/fixture.rs"] mod fixture;
#[path = "accept_cases/support.rs"] mod support;
use access::RoleKind;
use action_custody::{HoldKind, ScopeHolds};
use action_dispatch::{Current, DispatchCancel, FrozenRoute};
use action_expiry::ExpiryState;
use action_journal::Journal;
use action_preview::{Precondition, Preview, SealOrder};
use action_publication::{ImpactGate, OldWriterExclusion};
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
        let dir = std::env::temp_dir().join(format!("verdant-m02-sliceC-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
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
fn s03_all() -> (Profile, Vec<u8>, Report, Plan) {
    let r = s03_report();
    let p = s03_plan(&r);
    let prof = Profile::capture(&r, &p).expect("profile");
    let mut facts: Vec<_> = r.ledger.iter().map(semantics::ledger::Fact::to_json).collect();
    facts.sort();
    facts.dedup();
    let ledger = facts.concat().into_bytes();
    prof.ledger_status(&ledger).require().expect("roots");
    (prof, ledger, r, p)
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
fn seal_mark() -> SealOrder {
    let mut o = SealOrder::new();
    o.check_custody().expect("c");
    o.decode().expect("d");
    o.reconstruct().expect("r");
    assert!(!o.is_verified());
    o
}
fn pv_ok(binding: BindingRevision, accepted: accept::AcceptedRevision, sp: f64, rel: bool) -> Preview {
    Preview::preview(scope_a(), equipment("ahu-1"), binding, accepted, BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("u"), sp, None, &["ahu-1-sp"], fresh_pre(), &seal_ok(), equipment("ahu-1"), rel).expect("pv")
}
fn pv_mark(binding: BindingRevision, accepted: accept::AcceptedRevision, sp: f64) -> Preview {
    Preview::preview(scope_a(), equipment("ahu-1"), binding, accepted, BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("u"), sp, None, &["ahu-1-sp"], fresh_pre(), &seal_mark(), equipment("ahu-1"), false).expect("pv")
}
fn active1() -> (fixture::Fixture, accept::AcceptanceStore, BindingRevision, accept::AcceptedRevision) {
    let mut f = fixture::Fixture::new();
    let (store, sealed) = support::publish(&mut f, "sliceC-a", "AHU supply air");
    let pend = support::prepare(&mut f, &store, &sealed, "sliceC-acc-1", accept::AcceptedRevision::INITIAL);
    let acc = store.submit(&pend, &f.seals).expect("rev1");
    let req = accept::ActivationRequest::new(operation("sliceC-act-1"), accept::ActiveGeneration::INITIAL, acc.request.clone());
    store.prepare_activation(req.clone(), &f.seals).expect("prep");
    let act = store.activate(&req, &f.seals).expect("act");
    assert_eq!(act.revision().get(), 1);
    (f, store, sealed.config().binding_revision(), accept::AcceptedRevision::new(1).expect("r1"))
}
fn open_journal(scratch: &Scratch) -> Journal {
    let (j, _) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    j
}
#[test]
fn seal_join_custody_decode_ledger_and_happy() {
    let (prof, ledger, r, p) = s03_all();
    assert_eq!(SealOrder::new().ledger_only().unwrap_err().code(), "preview-seal-order");
    let mut o = SealOrder::new();
    assert_eq!(o.check_custody_with(&prof, b"bad").unwrap_err().code(), "s03-ledger-digest-mismatch");
    o.check_custody_with(&prof, &ledger).expect("custody");
    assert_eq!(o.decode_with(&["x"]).unwrap_err().code(), "s03-invalid");
    let pl: Vec<String> = prof.payloads().iter().map(|s| s.to_string()).collect();
    let refs: Vec<&str> = pl.iter().map(String::as_str).collect();
    o.decode_with(&refs).expect("decode");
    let mut bad = s03_report();
    bad.ledger.pop();
    let code = o.reconstruct_with(&bad, &s03_plan(&s03_report())).unwrap_err().code();
    assert!(code == "s03-ledger-digest-mismatch" || code == "s03-meaning-mismatch", "got {code}");
    o.reconstruct_with(&r, &p).expect("reconstruct");
    o.verified_availability().expect("verified");
    let decoded = Profile::from_payloads(&refs).expect("from_payloads");
    decoded.ledger_status(&ledger).require().expect("Available");
}
#[test]
fn seal_marker_refuses_at_joined_handoff() {
    let (_f, store, binding, rev) = active1();
    let mark = pv_mark(binding, rev, 22.0);
    assert!(!mark.seal_verified());
    let scratch = Scratch::new();
    let mut j = open_journal(&scratch);
    assert_eq!(action_joined::admit_joined(&mut j, operation("c-mark-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &mark, 0).unwrap_err().code(), "preview-seal-order");
    let ok = pv_ok(binding, rev, 22.0, false);
    let adm = action_joined::admit_joined(&mut j, operation("c-mark-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &ok, 0).expect("admit");
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert_eq!(action_joined::authorize_joined_setpoint(&j, &store, &adm, &mark, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).unwrap_err().code(), "preview-seal-order");
}
#[test]
fn joined_activation_barriers_refuse_with_preserved_codes() {
    // Accepted-but-not-active.
    let mut f = fixture::Fixture::new();
    let (store, sealed) = support::publish(&mut f, "c-na", "AHU supply air");
    let pend = support::prepare(&mut f, &store, &sealed, "c-na-1", accept::AcceptedRevision::INITIAL);
    store.submit(&pend, &f.seals).expect("rev1");
    let b = sealed.config().binding_revision();
    let r1 = accept::AcceptedRevision::new(1).expect("r1");
    let pv = pv_ok(b, r1, 22.0, false);
    let scratch = Scratch::new();
    let mut j = open_journal(&scratch);
    let adm = action_joined::admit_joined(&mut j, operation("c-na-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv, 0).expect("admit");
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert_eq!(action_joined::authorize_joined_setpoint(&j, &store, &adm, &pv, &cur(b, r1, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).unwrap_err().code(), "accept-invalid");
    // Newer-accepted/older-active + stale admitted.
    let req = {
        let cur_store = support::reopen(&f);
        let _ = cur_store;
        let pend0 = support::prepare(&mut f, &store, &sealed, "c-na-act-prep", accept::AcceptedRevision::new(1).expect("e1"));
        let _ = pend0;
        // Activate rev1 on the original store.
        let acc = store.current(&fixture::scope()).expect("cur").expect("some");
        let areq = accept::ActivationRequest::new(operation("c-na-act"), accept::ActiveGeneration::INITIAL, acc.request.clone());
        store.prepare_activation(areq.clone(), &f.seals).expect("prep act");
        store.activate(&areq, &f.seals).expect("act");
        areq
    };
    let _ = req;
    let (store2, sealed2) = support::publish(&mut f, "c-na2", "AHU supply air v2");
    let pend2 = support::prepare(&mut f, &store2, &sealed2, "c-na-2", accept::AcceptedRevision::new(1).expect("e1"));
    let acc2 = store2.submit(&pend2, &f.seals).expect("rev2");
    assert_eq!(acc2.revision.get(), 2);
    let reopened = support::reopen(&f);
    let r2 = accept::AcceptedRevision::new(2).expect("r2");
    let pv2 = pv_ok(sealed2.config().binding_revision(), r2, 22.0, false);
    let adm2 = action_joined::admit_joined(&mut j, operation("c-na-3"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv2, 1).expect("admit2");
    assert_eq!(action_joined::authorize_joined_setpoint(&j, &reopened, &adm2, &pv2, &cur(sealed2.config().binding_revision(), r2, 1), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).unwrap_err().code(), "publication-blocked");
    let pv1 = pv_ok(b, r1, 22.0, false);
    let adm1 = action_joined::admit_joined(&mut j, operation("c-na-4"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv1, 2).expect("admit stale");
    assert_eq!(action_joined::authorize_joined_setpoint(&j, &reopened, &adm1, &pv1, &cur(b, r1, 2), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).unwrap_err().code(), "activation-superseded");
    // Stale binding (wrong binding rev, matching active revs) on a fresh
    // active-rev1 store where rev1 is still current (not superseded).
    let (_fb, storeb, bb, rb) = active1();
    let wrong = BindingRevision::new(bb.as_u32().wrapping_add(1000));
    let pvb = pv_ok(wrong, rb, 22.0, false);
    let s2 = Scratch::new();
    let mut j2 = open_journal(&s2);
    let admb = action_joined::admit_joined(&mut j2, operation("c-bind-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pvb, 0).expect("admit");
    assert_eq!(action_joined::authorize_joined_setpoint(&j2, &storeb, &admb, &pvb, &cur(wrong, rb, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).unwrap_err().code(), "publication-blocked");
    let _ = (_fb, bb, rb);
    // Gen-0 no acceptance + missing deps.
    let f0 = fixture::Fixture::new();
    let store0 = support::store(&f0);
    let pv0 = pv_ok(BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("r"), 22.0, false);
    let adm0 = action_joined::admit_joined(&mut j2, operation("c-gen0-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv0, 1).expect("admit");
    assert_eq!(action_joined::authorize_joined_setpoint(&j2, &store0, &adm0, &pv0, &cur(BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("r"), 1), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).unwrap_err().code(), "accept-invalid");
}
#[test]
fn joined_revoke_hold_stale_current_and_fresh_pass() {
    let (_f, store, binding, rev) = active1();
    let gate_dir = std::env::temp_dir().join(format!("verdant-sliceC-g-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir(&gate_dir).expect("gate");
    let (gate, creds) = access::AccessGate::bootstrap(&gate_dir.join("gate.db"), ConnectionSettings::local_wal_full(), StoreBounds::tiny(), &access::Reason::parse("synthetic SliceC").expect("r")).expect("boot");
    let pv = pv_ok(binding, rev, 22.0, false);
    let scratch = Scratch::new();
    let mut j = open_journal(&scratch);
    let adm = action_joined::admit_joined(&mut j, operation("c-rh-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv, 0).expect("admit");
    gate.revoke(&creds.publisher, &access::Reason::parse("synthetic offboard").expect("r")).expect("revoke");
    let revoked = gate.is_revoked(creds.publisher.capability(), creds.publisher.key_id()).expect("read");
    assert!(revoked);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let code = action_joined::authorize_joined_setpoint(&j, &store, &adm, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, revoked, &ImpactGate::Preserved).unwrap_err().code();
    assert!(code == "custody-revoked" || code == "publication-revoked", "got {code}");
    let mut holds = ScopeHolds::new();
    holds.hold("scope-a", HoldKind::Active, "synthetic maintenance").expect("hold");
    assert_eq!(action_joined::authorize_joined_setpoint(&j, &store, &adm, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &holds, None, false, &ImpactGate::Preserved).unwrap_err().code(), "custody-held");
    let stale = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, binding, rev, BindingStatus::Valid, 99).expect("stale");
    let code = action_joined::authorize_joined_setpoint(&j, &store, &adm, &pv, &stale, &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).unwrap_err().code();
    assert!(code == "dispatch-stale-generation" || code == "admission-stale-generation", "got {code}");
    let pv2 = pv_ok(binding, rev, 22.5, false);
    assert_eq!(action_joined::admit_joined(&mut j, operation("c-rh-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv2, 0).unwrap_err().code(), "admission-stale-generation");
    let w = action_joined::authorize_joined_setpoint(&j, &store, &adm, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).expect("fresh passes");
    assert_eq!((w.object_type(), w.instance(), w.property(), w.priority()), (2, 2, 85, 8));
    assert!(!w.is_release());
    std::fs::remove_dir_all(&gate_dir).expect("cleanup");
}
fn shift_created(scratch: &Scratch, op: &str, delta: i64) {
    let j = open_journal(scratch);
    j.store().exec_script(&format!("UPDATE action_journal SET created = created + ({delta}) WHERE operation='{op}';")).expect("shift");
}
#[tokio::test(flavor = "current_thread")]
async fn wall_expired_refuses_with_zero_capture_via_live_path() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let (_f, store, binding, rev) = active1();
    let pv = pv_ok(binding, rev, 22.0, false);
    let scratch = Scratch::new();
    let mut j = open_journal(&scratch);
    action_joined::admit_joined(&mut j, operation("c-wall-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv, 0).expect("admit");
    drop(j);
    shift_created(&scratch, "c-wall-1", -6);
    let j2 = open_journal(&scratch);
    let adm = j2.reconcile(&operation("c-wall-1"), &scope_a()).expect("reconstruct");
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    assert!(dl5() > Instant::now());
    assert_eq!(action_joined::authorize_joined_setpoint(&j2, &store, &adm, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).unwrap_err().code(), "expiry-expired");
    assert_eq!(harness.fixture.sent_count(), 0);
    assert!(harness.fixture.requests().is_empty());
    harness.finish("sliceC-wall-expired", &[]).await;
}
#[test]
fn wall_window_passes_rollback_indeterminate_null_exempt() {
    let (_f, store, binding, rev) = active1();
    let pv = pv_ok(binding, rev, 22.0, false);
    let rel = pv_ok(binding, rev, 22.0, true);
    let scratch = Scratch::new();
    let mut j = open_journal(&scratch);
    action_joined::admit_joined(&mut j, operation("c-wok-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv, 0).expect("set");
    action_joined::admit_joined(&mut j, operation("c-wnull-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &rel, 1).expect("null");
    drop(j);
    shift_created(&scratch, "c-wok-1", -4);
    shift_created(&scratch, "c-wnull-1", -4);
    let j2 = open_journal(&scratch);
    let adm = j2.reconcile(&operation("c-wok-1"), &scope_a()).expect("rec");
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert!(action_joined::authorize_joined_setpoint(&j2, &store, &adm, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).is_ok());
    shift_created(&scratch, "c-wok-1", 100);
    shift_created(&scratch, "c-wnull-1", 100);
    let j3 = open_journal(&scratch);
    let rolled = j3.reconcile(&operation("c-wok-1"), &scope_a()).expect("rolled");
    let reladm = j3.reconcile(&operation("c-wnull-1"), &scope_a()).expect("relnull");
    let cur1 = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, binding, rev, BindingStatus::Valid, 1).expect("c1");
    assert_eq!(action_joined::authorize_joined_setpoint(&j3, &store, &rolled, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).unwrap_err().code(), "expiry-indeterminate");
    assert_eq!(action_joined::authorize_joined_setpoint(&j3, &store, &rolled, &pv, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Indeterminate { reason: "cross-boot" }, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).unwrap_err().code(), "expiry-indeterminate");
    let out = action_joined::authorize_joined_release(&j3, &store, &reladm, &rel, &cur1, &route, &DispatchCancel::new(), dl5(), &ExpiryState::Indeterminate { reason: "wall-rollback" }, Freshness::Unknown, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).expect("null exempt");
    assert_eq!(out.value(), &[0x00]);
}
#[test]
fn wall_reopen_repeats_and_seventh_refuses() {
    let (_f, store, binding, rev) = active1();
    let scratch = Scratch::new();
    for i in 0..6 {
        let pv = pv_ok(binding, rev, 21.0 + (i as f64) * 0.2, false);
        let mut j = open_journal(&scratch);
        action_joined::admit_joined(&mut j, operation(&format!("c-rate-{i}")), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv, i).expect("admit");
    }
    shift_created(&scratch, "c-rate-0", -6);
    let fresh = open_journal(&scratch);
    let first = fresh.reconcile(&operation("c-rate-0"), &scope_a()).expect("rec");
    let pv0 = pv_ok(binding, rev, 21.0, false);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert_eq!(action_joined::authorize_joined_setpoint(&fresh, &store, &first, &pv0, &cur(binding, rev, 0), &route, &DispatchCancel::new(), dl5(), &ExpiryState::Active, Freshness::Fresh, &ScopeHolds::new(), None, false, &ImpactGate::Preserved).unwrap_err().code(), "expiry-expired");
    let pv7 = pv_ok(binding, rev, 22.0, false);
    let mut j7 = open_journal(&scratch);
    assert_eq!(action_joined::admit_joined(&mut j7, operation("c-rate-7"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv7, 6).unwrap_err().code(), "admission-rate-exceeded");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut th = Vec::new();
    for n in 0..2 {
        let b2 = barrier.clone();
        let db = scratch.db();
        let bb = binding;
        let rr = rev;
        th.push(std::thread::spawn(move || {
            b2.wait();
            let (prof, ledger, r, p) = s03_all();
            let mut seal = SealOrder::new();
            seal.check_custody_with(&prof, &ledger).expect("c");
            let pl: Vec<String> = prof.payloads().iter().map(|s| s.to_string()).collect();
            let rf: Vec<&str> = pl.iter().map(String::as_str).collect();
            seal.decode_with(&rf).expect("d");
            seal.reconstruct_with(&r, &p).expect("r");
            let pv = Preview::preview(scope_a(), equipment("ahu-1"), bb, rr, BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("u"), 22.0, None, &["ahu-1-sp"], fresh_pre(), &seal, equipment("ahu-1"), false).expect("pv");
            let (mut j, _) = Journal::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
            action_joined::admit_joined(&mut j, operation(&format!("c-rate-c{n}")), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &pv, 6).map(|_| "ok").map_err(|e| e.code().to_string())
        }));
    }
    for t in th {
        let r = t.join().expect("join");
        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), "admission-rate-exceeded");
    }
    let _ = OldWriterExclusion::exclude("operator-1/scope-a", "publisher-1/scope-a", "synthetic SliceC manual takeover").expect("excl");
}
