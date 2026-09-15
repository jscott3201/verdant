//! S03 isolated structural publication/reconstruction. Never field qualification.
#![allow(dead_code)]
#[path = "../src/accept/mod.rs"] mod accept;
#[path = "../src/access/mod.rs"] mod access;
#[path = "../src/binding/mod.rs"] mod binding;
#[path = "../src/domain/mod.rs"] mod domain;
#[path = "../src/native/mod.rs"] mod native;
#[path = "../src/seal/mod.rs"] mod seal;
#[path = "../src/semantics/mod.rs"] mod semantics;
#[path = "../src/storage/mod.rs"] mod storage;
#[path = "seal_cases/fixture.rs"] mod fixture;
#[path = "accept_cases/support.rs"] mod support;
// Reuse the existing JSON reader for independent assertions, not a new parser.
#[path = "../src/domain/json.rs"] mod json;
type Error = domain::Error;

use semantics::materialize::{self, Plan};
use semantics::matrix::Report;
use semantics::recipe::{self, Catalog, Input, ARTIFACTS, BRICK, S223};
use semantics::sealed_profile::{self as s03, Availability, Profile};
use semantics::ledger::{Fact, Kind};
use semantics::parse::{Document, Object};
use domain::values::Value;
use fixture::{operation, scope};
use std::path::PathBuf;
use std::io::Read;

const BRICK_EXCERPT: &[u8] = br#"
@prefix b: <https://brickschema.org/schema/Brick#> .
@prefix rec: <https://w3id.org/rec#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
b:AHU a owl:Class ; rdfs:subClassOf b:Equipment ; rdfs:label "Synthetic AHU" .
b:Equipment a owl:Class . b:VAV a owl:Class .
b:Supply_Air_Temperature_Sensor a owl:Class . rec:Room a rdfs:Class .
b:hasLocation a owl:ObjectProperty . b:feeds a owl:ObjectProperty .
b:hasPoint a owl:ObjectProperty ; owl:inverseOf b:isPointOf .
b:isPointOf a owl:ObjectProperty .
"#;
const S223_EXCERPT: &[u8] = br#"
@prefix s: <http://data.ashrae.org/standard223#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
s:QuantifiableObservableProperty a s:Class . s:observes a rdf:Property .
"#;

// Default-suite excerpts are explicitly synthetic, not replacements accepted by
// Catalog::load. Parse actual Turtle and build S01-shaped evidence as in S02.
fn source(brick: &[u8], s223: &[u8]) -> Report {
    let mut report = Report { rows: Vec::new(), ledger: Vec::new() };
    for (name, bytes) in [(BRICK, brick), (S223, s223)] {
        let pin = recipe::artifact(name).unwrap();
        let doc = Document::parse(bytes).unwrap();
        for (subject, predicate, object) in doc.facts() {
            report.rows.push(semantics::matrix::supported(name, subject).unwrap());
            report.ledger.push(Fact {
                artifact: name, sha256: pin.sha256, subject: subject.into(),
                predicate: predicate.into(), object: object.clone(), kind: Kind::Original,
                rule: "source-assertion", reason: "synthetic excerpt".into(), provenance: pin.provenance,
            });
        }
    }
    let pin = recipe::artifact(BRICK).unwrap();
    report.ledger.push(Fact {
        artifact: BRICK, sha256: pin.sha256, subject: "https://brickschema.org/schema/Brick#AHU".into(),
        predicate: "urn:verdant:s01:ancestry-path".into(),
        object: Object::Iri("https://brickschema.org/schema/Brick#Equipment".into()),
        kind: Kind::Derived, rule: "explicit-ancestry-path", reason: "synthetic ancestry".into(),
        provenance: pin.provenance,
    });
    report.rows.sort_by(|a, b| (a.artifact, &a.iri).cmp(&(b.artifact, &b.iri)));
    report.rows.dedup();
    report.ledger.sort_by_cached_key(Fact::to_json);
    report.ledger.dedup();
    report
}

fn plan(report: &Report) -> Result<Plan, materialize::Error> {
    let site = domain::fixture::tiny_site();
    let row = |iri: &str| report.rows.iter().find(|row| row.iri == iri).unwrap();
    let location = row("https://brickschema.org/schema/Brick#hasLocation");
    let point = row("https://brickschema.org/schema/Brick#hasPoint");
    Plan::tiny_site(report, &[
        (&site.relationships[0], location), (&site.relationships[1], location),
        (&site.relationships[2], location),
        (&site.relationships[3], row("https://brickschema.org/schema/Brick#feeds")),
        (&site.relationships[5], point), (&site.relationships[6], point),
        (&site.relationships[5], row("https://brickschema.org/schema/Brick#isPointOf")),
    ], Some(row("http://data.ashrae.org/standard223#observes")),
        native::NativeSettings::local().bounds.max_statement_bytes)
}

fn outside(dir: &std::path::Path) {
    let dir = dir.canonicalize().unwrap();
    assert!(!dir.starts_with(std::fs::canonicalize(env!("CARGO_MANIFEST_DIR")).unwrap()));
    assert!(!dir.ancestors().any(|p| p.join(".git").exists()), "artifacts must be outside repositories");
}
fn canonical_ledger(report: &Report) -> Vec<u8> {
    let mut facts: Vec<_> = report.ledger.iter().map(Fact::to_json).collect();
    facts.sort();
    facts.dedup();
    facts.concat().into_bytes()
}
fn fields(mut raw: &str) -> Vec<&str> {
    let mut result = Vec::new();
    while !raw.is_empty() {
        let (n, rest) = raw.split_once(':').unwrap();
        let (field, rest) = rest.split_at(n.parse().unwrap());
        result.push(field);
        raw = rest;
    }
    result
}
fn array(value: &json::JsonVal) -> &[json::JsonVal] {
    match value { json::JsonVal::Array(v) => v, other => panic!("not array: {other:?}") }
}
fn object(value: &json::JsonVal) -> &std::collections::BTreeMap<String, json::JsonVal> {
    match value { json::JsonVal::Object(v) => v, other => panic!("not object: {other:?}") }
}
fn string(value: &json::JsonVal) -> &str {
    match value { json::JsonVal::Str(v) => v, other => panic!("not string: {other:?}") }
}
// Independent dictionary expansion: restoring every byte from the staged data
// must agree with the REAL Plan callback stream, including exact facts_json.
fn expanded_steps(profile: &Profile) -> Vec<[String; 3]> {
    let body = json::parse(fields(profile.canonical_bytes())[6]).unwrap();
    let dictionary = array(&object(&body)["dictionary"]);
    array(&object(&body)["steps"]).iter().map(|step| {
        ["identity", "exact", "insert"].map(|key| array(&object(step)[key]).iter().map(|id| {
            let json::JsonVal::Number(n) = id else { panic!("not index") };
            string(&dictionary[n.parse::<usize>().unwrap()])
        }).collect())
    }).collect()
}
fn assert_plan_bytes(profile: &Profile, plan: &Plan) {
    let steps = expanded_steps(profile);
    assert_eq!(steps.len(), 15);
    let mut reads = Vec::new();
    plan.reconcile(|q| { reads.push(q.to_string()); Ok(Some(1)) }).unwrap();
    for pair in reads.chunks_exact(2) {
        assert_eq!(steps.iter().filter(|s| s[0] == pair[0] && s[1] == pair[1]).count(), 1);
    }
    let mut seen = std::collections::BTreeSet::new();
    assert_eq!(plan.reconcile(|q| {
        if let Some(step) = steps.iter().find(|s| s[0] == q) {
            Ok(Some(usize::from(seen.contains(&step[0]))))
        } else if steps.iter().any(|s| s[1] == q) { Ok(Some(1)) }
        else {
            let step = steps.iter().find(|s| s[2] == q).expect("all insert bytes captured");
            assert!(seen.insert(step[0].clone()));
            Ok(None)
        }
    }).unwrap(), 15);
}

#[test]
fn s03_capture_is_deterministic_literal_contract_and_ancestry_digest() {
    let mut report = source(BRICK_EXCERPT, S223_EXCERPT);
    let profile = Profile::capture(&report, &plan(&report).unwrap()).unwrap();
    assert_eq!(Profile::from_payloads(&profile.payloads()).unwrap(), profile);
    assert_plan_bytes(&profile, &plan(&report).unwrap());
    let f = fields(profile.canonical_bytes());
    assert_eq!(&f[..3], &["verdant-f02-s03-v1", "verdant-f02-s01-v1", "valid-structural-not-qualified;synthetic-fnv1a64-not-authority"]);
    assert!(f[3].contains(r#"{"name":"Brick.ttl","bytes":1749633,"sha256":"b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7","provenance":"Brick v1.4.4; tag 4b5be60d27f9b4d96fe477f45513fa71afebe684; release 216036536; asset 251163888; generated distribution; embedded REC 4.0","url":"https://github.com/BrickSchema/Brick/releases/download/v1.4.4/Brick.ttl"}"#));
    assert_eq!(array(&json::parse(f[3]).unwrap()).len(), 11);
    assert!(f[5].contains(r#"{"artifact":"223p.ttl","iri":"http://data.ashrae.org/standard223#observes","kind":"relation","direction":"subject Sensor -> object ObservableProperty"}"#));
    // Hardcoded complete Fact JSON, not an expected string from the encoder.
    const FACT: &str = r#"{"artifact":"test","sha256":"pin","subject":"urn:s","predicate":"urn:p","object_kind":"literal","object":"\"\\\n","kind":"derived","authored":false,"rule":"rule","rule_version":1,"recipe":"verdant-f02-s01-v1","reason":"reason","provenance":"synthetic","evidence":"parser-only; mapped; not observed-qualified; no native materialization"}"#;
    let fact = Fact { artifact: "test", sha256: "pin", subject: "urn:s".into(), predicate: "urn:p".into(),
        object: Object::Literal("\"\\\n".into()), kind: Kind::Derived, rule: "rule", reason: "reason".into(), provenance: "synthetic" };
    assert_eq!(fact.to_json(), FACT);
    assert_eq!(s03::ledger_digest(&Report { rows: vec![], ledger: vec![fact.clone(), fact] }).unwrap(),
        semantics::parse::sha256(FACT.as_bytes()).unwrap());
    report.rows.reverse(); report.rows.push(report.rows[0].clone());
    report.ledger.reverse(); report.ledger.push(report.ledger[0].clone());
    assert_eq!(Profile::capture(&report, &plan(&report).unwrap()).unwrap(), profile);
    report.ledger.retain(|f| f.predicate != "urn:verdant:s01:ancestry-path");
    let no_ancestry = Profile::capture(&report, &plan(&report).unwrap()).unwrap();
    assert_ne!(profile.ledger_digest(), no_ancestry.ledger_digest());
    assert_eq!(expanded_steps(&profile), expanded_steps(&no_ancestry), "S02 exclusion unchanged");
    assert_eq!(profile.verify_report(&report, &plan(&report).unwrap()).unwrap_err().code(), "s03-ledger-digest-mismatch");
}

fn stage(f: &fixture::Fixture, profile: &Profile) -> Vec<seal::RowKey> {
    profile.stage::<_, Box<dyn std::error::Error>>(&operation("profile-s03"), |op, seq, payload| {
        assert!(payload.len() <= 16_384);
        let value = seal::ContentNode::new(payload.into(), vec![f.finding.clone()])?.value();
        assert!(matches!(value, Value::Text(_)));
        f.registry.store().insert(op, &domain::ids::InstalledId::parse("ahu-1")?,
            &domain::ids::InstalledId::parse("sensor-sat-1")?, &value,
            &domain::values::Unit::parse("count")?, binding::synthetic_times(),
            &binding::synthetic_record(seq))?;
        Ok(seal::RowKey::new(op.clone(), seq)?)
    }).unwrap()
}
fn read_profile(f: &fixture::Fixture, manifest: &seal::Manifest) -> Profile {
    let raw = manifest.canonical_bytes();
    let m = fields(&raw);
    assert_eq!(m.len(), 14);
    assert_eq!(m[0], "verdant-seal-v1");
    assert_eq!(m[1], "valid-structural-not-qualified");
    assert_eq!(m[5], semantics::profile::PINNED_PROFILE_ID);
    assert_eq!(m[6], "verdant-converter-r07-v1");
    let roots = fields(m[10]);
    let rows = f.registry.store().exec_script("SELECT seq,quote(value_json) FROM outbox WHERE operation='profile-s03' ORDER BY CAST(seq AS INTEGER);").unwrap();
    let mut payloads = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row[0], (i + 1).to_string());
        assert!(roots.iter().any(|raw| fields(raw) == ["profile-s03", &row[0]]), "each chunk is a root");
        let json = binding::unquote_column(&row[1]).unwrap().unwrap();
        let Value::Text(raw) = Value::from_json(&json).unwrap() else { panic!("text only") };
        let content = fields(&raw);
        assert_eq!(&content[..2], &["verdant-content-v1", "valid-structural"]);
        payloads.push(content[2].to_string());
    }
    Profile::from_payloads(&payloads.iter().map(String::as_str).collect::<Vec<_>>()).unwrap()
}
fn profile_closure_bytes(f: &fixture::Fixture) -> usize {
    let rows = f.registry.store().exec_script("SELECT quote(operation),quote(seq),quote(entity),quote(sensor),quote(value_json),quote(unit),quote(source_ms),quote(receipt_ms),quote(ingestion_ms),quote(generation) FROM outbox WHERE operation='profile-s03';").unwrap();
    rows.iter().flatten().map(|v| {
        let v = binding::unquote_column(v).unwrap().unwrap();
        v.len() + v.len().to_string().len() + 1
    }).sum()
}
fn execute(handle: &native::NativeHandle, q: &str) -> Result<Option<usize>, materialize::Error> {
    handle.execute(q).map(|r| r.row_count).map_err(|e| materialize::Error::Execution { code: e.code().into(), detail: e.to_string() })
}
fn count(handle: &native::NativeHandle, q: &str, n: usize) {
    assert_eq!(handle.execute(q).unwrap().row_count, Some(n), "{q}");
}
fn readback(handle: &native::NativeHandle) {
    count(handle, "MATCH (n:S02Node) RETURN n", 7);
    count(handle, "MATCH ()-[e:S02Relation]->() RETURN e", 8);
    for (scope, id, iri, values) in [
        ("scope-a", "ahu-1", "https://brickschema.org/schema/Brick#AHU", r#"[{"type":"decimal","value":"21.50"},{"type":"diagnostic","kind":"+inf"}]"#),
        ("scope-a", "vav-101", "https://brickschema.org/schema/Brick#VAV", r#"[{"type":"integer","value":"9007199254740993"},{"type":"missing"}]"#),
        ("scope-b", "vav-102", "https://brickschema.org/schema/Brick#VAV", r#"[{"type":"integer","value":"0"},{"type":"bool","value":false},{"type":"diagnostic","kind":"nan"}]"#),
        ("scope-a", "sensor-sat-1", "https://brickschema.org/schema/Brick#Supply_Air_Temperature_Sensor", "[]"),
    ] {
        count(handle, &format!("MATCH (n:S02Node) WHERE n.key = '{scope}|installed|{id}' AND n.scope = '{scope}' AND n.role = 'installed' AND n.installed_id = '{id}' AND n.type_iri = '{iri}' AND n.values_json = '{values}' RETURN n"), 1);
    }
    for scope in ["scope-a", "scope-b"] {
        count(handle, &format!("MATCH (n:S02Node) WHERE n.key = '{scope}|location|' AND n.type_iri = 'https://w3id.org/rec#Room' AND n.role = 'location' AND n.installed_id = '' RETURN n"), 1);
    }
    count(handle, "MATCH (n:S02Node) WHERE n.key = 'scope-a|property|sensor-sat-1' AND n.role = 'property' AND n.type_iri = 'http://data.ashrae.org/standard223#QuantifiableObservableProperty' RETURN n", 1);
    for (scope, from, to, role, iri, direction) in [
        ("scope-a", "ahu-1", "", "location", "https://brickschema.org/schema/Brick#hasLocation", "subject entity -> object location; not service"),
        ("scope-a", "vav-101", "", "location", "https://brickschema.org/schema/Brick#hasLocation", "subject entity -> object location; not service"),
        ("scope-b", "vav-102", "", "location", "https://brickschema.org/schema/Brick#hasLocation", "subject entity -> object location; not service"),
        ("scope-a", "ahu-1", "vav-101", "installed", "https://brickschema.org/schema/Brick#feeds", "subject upstream -> object downstream"),
        ("scope-a", "ahu-1", "sensor-sat-1", "installed", "https://brickschema.org/schema/Brick#hasPoint", "subject telemetry-owner -> object point"),
        ("scope-a", "vav-101", "sensor-sat-1", "installed", "https://brickschema.org/schema/Brick#hasPoint", "subject telemetry-owner -> object point"),
        ("scope-a", "sensor-sat-1", "ahu-1", "installed", "https://brickschema.org/schema/Brick#isPointOf", "subject point -> object telemetry-owner"),
        ("scope-a", "sensor-sat-1", "sensor-sat-1", "property", "http://data.ashrae.org/standard223#observes", "subject Sensor -> object ObservableProperty"),
    ] {
        count(handle, &format!("MATCH (a:S02Node)-[e:S02Relation]->(b:S02Node) WHERE a.key = '{scope}|installed|{from}' AND b.key = '{scope}|{role}|{to}' AND e.key = '{scope}|installed|{from}|{iri}|{scope}|{role}|{to}' AND e.iri = '{iri}' AND e.direction = '{direction}' RETURN e"), 1);
    }
    count(handle, "MATCH (a:S02Node)-[p:S02Relation]->(s:S02Node)-[o:S02Relation]->(v:S02Node) WHERE p.iri = 'https://brickschema.org/schema/Brick#hasPoint' AND o.iri = 'http://data.ashrae.org/standard223#observes' AND v.key = 'scope-a|property|sensor-sat-1' RETURN a", 2);
}

fn reopen(f: fixture::Fixture) -> fixture::Fixture {
    let fixture::Fixture { gate, credentials, registry, native, seals, reference, finding, scratch } = f;
    drop(seals); drop(registry); drop(gate);
    let closed = native.close();
    let lock = std::fs::OpenOptions::new().read(true).write(true).open(closed.dir.join("LOCK")).unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                assert!(std::time::Instant::now() < until, "LOCK still held");
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(std::fs::TryLockError::Error(e)) => panic!("LOCK probe: {e}"),
        }
    }
    lock.unlock().unwrap();
    let (native, _) = closed.open().unwrap();
    let registry = binding::BindingRegistry::open(&scratch.db(), storage::ConnectionSettings::local_wal_full(), storage::StoreBounds::tiny()).unwrap();
    let gate = access::AccessGate::open(&scratch.db(), storage::ConnectionSettings::local_wal_full(), storage::StoreBounds::tiny()).unwrap();
    let seals = seal::SealStore::open(registry.store().try_clone().unwrap(), native.clone()).unwrap();
    fixture::Fixture { gate, credentials, registry, native, seals, reference, finding, scratch }
}

fn journey(report: &Report, reconstruct: impl Fn(&Profile) -> s03::Result<()>) {
    let mut f = fixture::Fixture::new();
    outside(&f.scratch.0);
    let plan = plan(report).unwrap();
    assert_eq!(plan.reconcile(|q| execute(&f.native, q)).unwrap(), 15);
    readback(&f.native);
    f.reference = seal::NativeRef::capture(&f.native, f.seals.hash_tool()).unwrap();
    let profile = Profile::capture(report, &plan).unwrap();
    assert_plan_bytes(&profile, &plan);
    let roots = stage(&f, &profile);
    let profile_bytes = profile_closure_bytes(&f);
    assert!(profile_bytes < seal::MAX_CLOSURE_BYTES / 2, "ample room for real closure: {profile_bytes}");
    println!("S03 payload={} bytes, {} content roots, encoded profile closure={} / {} bytes, ledger_digest={}", profile.canonical_bytes().len(), roots.len(), profile_bytes, seal::MAX_CLOSURE_BYTES, profile.ledger_digest());
    let store = support::store(&f);
    let config = support::config(&mut f, "S03 represented SAT");
    let revision = config.binding_revision();
    let finding = f.registry.findings().last().unwrap().clone();
    let staged = store.stage(&operation("accept-stage-s03"), config, vec![f.finding.clone()]).unwrap();
    let baseline = f.seal("seal-without-profile", &f.draft_with(vec![staged.root().unwrap()], "synthetic-s03")).unwrap();
    let mut all = roots; all.push(staged.root().unwrap());
    let draft = f.draft_with(all, "synthetic-s03");
    let commit = f.seal("seal-with-profile", &draft).unwrap();
    assert_ne!(commit.identity, baseline.identity);
    assert_eq!(f.seals.capture_simulation(&commit.identity).unwrap(), commit.manifest);
    assert_eq!(read_profile(&f, &commit.manifest), profile);
    let sealed = store.sealed(&staged, &commit.identity, &f.seals).unwrap();
    reconstruct(&read_profile(&f, &commit.manifest)).unwrap(); // availability gate
    assert_eq!(store.status(&sealed).unwrap(), accept::Stage::Sealed);
    let pending = support::prepare(&mut f, &store, &sealed, "accept-s03", accept::AcceptedRevision::INITIAL);
    let accepted = store.submit(&pending, &f.seals).unwrap();
    assert_eq!(store.status(&sealed).unwrap(), accept::Stage::Accepted);
    assert_eq!(store.transition(&accepted, accept::Stage::Qualified).unwrap_err().code(), "accept-not-yet");
    assert_eq!(sealed.config().binding_revision(), revision);
    assert!(sealed.config().facts().iter().any(|fact| fact.id() == finding.id().as_str() && fact.generation() == finding.binding_revision().as_u32()));
    assert!(f.registry.bindings().iter().all(|b| b.status() == binding::BindingStatus::Valid));
    assert!(commit.manifest.finding_fingerprints().iter().all(|f| f.contains("synthetic-fnv1a64-not-authority")));
    reconstruct(&profile).unwrap();
    let request = accept::ActivationRequest::new(operation("activate-s03"), accept::ActiveGeneration::INITIAL, accepted.request.clone());
    let activation = store.prepare_activation(request.clone(), &f.seals).unwrap();
    let contender = store.prepare_activation(accept::ActivationRequest::new(operation("activate-contender"),
        accept::ActiveGeneration::INITIAL, accepted.request.clone()), &f.seals).unwrap();
    let active = store.submit_activation(&activation, &f.seals).unwrap();
    assert_eq!(active.stage(), accept::Stage::Activated);
    assert_eq!(active.request().acceptance().seal(), &commit.identity);
    assert_eq!(store.status(&sealed).unwrap(), accept::Stage::Activated);
    let before = (support::counts(&f), support::bytes(&f));
    assert_eq!(store.submit_activation(&contender, &f.seals).unwrap_err().code(), "activation-stale-generation");
    assert_eq!(before, (support::counts(&f), support::bytes(&f)));
    drop(store);
    let mut f = reopen(f);
    let store = support::store(&f);
    assert_eq!(f.seals.capture_simulation(&commit.identity).unwrap(), commit.manifest);
    let profile = read_profile(&f, &commit.manifest);
    reconstruct(&profile).unwrap();
    let restored = store.read_staged(&operation("accept-stage-s03")).unwrap();
    let sealed = store.sealed(&restored, &commit.identity, &f.seals).unwrap();
    assert_eq!(store.current(&scope()).unwrap().unwrap(), accepted);
    assert_eq!(store.active(&scope()).unwrap().unwrap(), active);
    assert_eq!(store.status(&sealed).unwrap(), accept::Stage::Activated);
    assert_eq!(sealed.config().binding_revision(), revision);
    readback(&f.native);
    assert_eq!(plan.reconcile(|q| execute(&f.native, q)).unwrap(), 0);
    // Corrupt only a scratch reconstruction, NEVER the sealed stores/artifacts.
    let scratch = fixture::Scratch::new(); outside(&scratch.0);
    let path = scratch.0.join("reconstructed-ledger.json");
    let mut ledger = canonical_ledger(report);
    profile.ledger_status(&ledger).require().unwrap();
    ledger[10] ^= 1;
    std::fs::write(&path, &ledger).unwrap();
    let before = (support::counts(&f), support::bytes(&f));
    let unavailable = profile.ledger_status(&std::fs::read(&path).unwrap());
    assert!(matches!(unavailable, Availability::Unavailable(_)));
    assert_eq!(unavailable.require().unwrap_err().code(), "s03-ledger-digest-mismatch");
    assert_eq!(store.current(&scope()).unwrap().unwrap(), accepted);
    assert_eq!(store.status(&sealed).unwrap(), accept::Stage::Activated, "history is not availability");
    assert_eq!(f.seals.capture_simulation(&commit.identity).unwrap(), commit.manifest);
    assert_eq!(before, (support::counts(&f), support::bytes(&f)));
    // Existing stale-generation check, including submit of a prepared contender.
    let stale = accept::ActivationRequest::new(operation("activate-stale"), accept::ActiveGeneration::INITIAL, accepted.request.clone());
    assert_eq!(store.prepare_activation(stale, &f.seals).unwrap_err().code(), "activation-stale-generation");
    assert_eq!(before, (support::counts(&f), support::bytes(&f)));
    // A second acceptance supersedes the old activation request, never rolls back.
    let pending = support::prepare(&mut f, &store, &sealed, "accept-s03-second", accepted.revision);
    let second = store.submit(&pending, &f.seals).unwrap();
    let superseded = accept::ActivationRequest::new(operation("activate-old"), active.generation(), accepted.request.clone());
    let before = (support::counts(&f), support::bytes(&f));
    assert_eq!(store.prepare_activation(superseded, &f.seals).unwrap_err().code(), "activation-superseded");
    assert_eq!(store.current(&scope()).unwrap().unwrap(), second);
    assert_eq!(store.reconcile(&accepted.request).unwrap().unwrap().row_id, accepted.row_id);
    assert_eq!(before, (support::counts(&f), support::bytes(&f)));
    // require_revision must still reject stale profile-bearing new seals.
    f.registry.record_equipment("vav-101", binding::EquipmentKind::Vav, scope(), "VAV", "mstp://vav-101").unwrap();
    let before = (support::counts(&f), support::bytes(&f));
    let mut roots: Vec<_> = profile.payloads().iter().enumerate().map(|(i, _)| fixture::row("profile-s03", (i + 1) as u64)).collect();
    roots.push(staged.root().unwrap());
    let stale_draft = seal::Draft::new(revision, scope(), seal::RuntimeRef::new("new-context", "synthetic").unwrap(),
        roots, vec![f.reference.clone()]).unwrap();
    let stale = f.seal("seal-stale-s03", &stale_draft).unwrap_err();
    assert_eq!(stale.code(), "conflict");
    assert!(matches!(stale, seal::SealError::Binding(binding::BindingError::Conflict { detail })
        if detail.contains("input revision")));
    assert_eq!(before, (support::counts(&f), support::bytes(&f)));
    drop(store); drop(f);
}

#[test]
fn s03_refuses_bad_chunks_pins_namespaces_and_changed_meaning() {
    let mut report = source(BRICK_EXCERPT, S223_EXCERPT);
    let profile = Profile::capture(&report, &plan(&report).unwrap()).unwrap();
    let mut called = false;
    for op in ["seal-revision-v1", "seal-release-v1", "seal-row-v1", "seal-manifest", "accept-stage-x", "binding-finding"] {
        let result = profile.stage::<(), s03::Error>(&operation(op), |_, _, _| { called = true; Ok(()) });
        assert_eq!(result.unwrap_err().code(), "s03-invalid");
        assert!(!called);
    }
    assert_eq!(Profile::from_payloads(&[]).unwrap_err().code(), "s03-limit");
    assert_eq!(Profile::from_payloads(&["x"]).unwrap_err().code(), "s03-invalid");
    assert_eq!(Profile::from_payloads(&[&"x".repeat(s03::CHUNK_BYTES + 1)]).unwrap_err().code(), "s03-limit");
    for bad in ["01:x", "999999999999999999999999999:x", "1:é"] {
        assert_eq!(Profile::from_payloads(&[bad]).unwrap_err().code(), "s03-invalid");
    }
    let mut payloads = profile.payloads();
    payloads.reverse();
    assert!(Profile::from_payloads(&payloads).is_err());
    payloads = profile.payloads(); payloads.pop();
    assert!(Profile::from_payloads(&payloads).is_err());
    let mut chunks: Vec<_> = profile.payloads().iter().map(|s| s.to_string()).collect();
    chunks[0] = chunks[0].replacen("1749633", "1749634", 1);
    assert_eq!(Profile::from_payloads(&chunks.iter().map(String::as_str).collect::<Vec<_>>()).unwrap_err().code(), "s03-invalid");
    report.rows[0].direction = "wrong direction";
    let original_plan = plan(&source(BRICK_EXCERPT, S223_EXCERPT)).unwrap();
    assert_eq!(profile.verify_report(&report, &original_plan).unwrap_err().code(), "s03-meaning-mismatch");
    let report = source(BRICK_EXCERPT, S223_EXCERPT);
    let other = Plan::tiny_site(&report, &[], None, native::NativeSettings::local().bounds.max_statement_bytes).unwrap();
    assert_eq!(profile.verify_report(&report, &other).unwrap_err().code(), "s03-meaning-mismatch");
    // Real Catalog cannot be satisfied with excerpts or absent sources.
    assert!(matches!(profile.status(&[], plan), Availability::Unavailable(_)));
    let inputs = [Input { name: BRICK, bytes: BRICK_EXCERPT }];
    assert_eq!(profile.status(&inputs, plan).require().unwrap_err().code(), "s01-digest-mismatch");
}

#[test]
fn s03_lossless_unicode_chunks_and_staging_stops_on_first_failure() {
    let mut report = source(BRICK_EXCERPT, S223_EXCERPT);
    let mut fact = report.ledger.iter().find(|f| f.subject == "https://brickschema.org/schema/Brick#AHU").unwrap().clone();
    fact.predicate = "urn:inert-fixture".into();
    fact.object = Object::Literal(format!("\"quoted\"\n\\\t{}", "é".repeat(5_000)));
    report.ledger.push(fact);
    let plan = plan(&report).unwrap();
    let profile = Profile::capture(&report, &plan).unwrap();
    assert_plan_bytes(&profile, &plan);
    assert_eq!(Profile::from_payloads(&profile.payloads()).unwrap(), profile);
    let mut calls = Vec::new();
    let failure = profile.stage::<(), s03::Error>(&operation("profile-partial"), |op, seq, payload| {
        assert_eq!(op.as_str(), "profile-partial");
        assert!(payload.len() <= 16_384);
        calls.push(seq);
        if seq == 2 { Err(s03::Error::Invalid("injected adapter failure")) } else { Ok(()) }
    }).unwrap_err();
    assert_eq!(failure.code(), "s03-invalid");
    assert_eq!(calls, [1, 2], "do not dispatch later chunks after failed insert");
}

#[test]
fn s03_synthetic_reconstruction_seal_accept_activate_reopen_and_degrade() {
    let scratch = fixture::Scratch::new(); outside(&scratch.0);
    std::fs::write(scratch.0.join(BRICK), BRICK_EXCERPT).unwrap();
    std::fs::write(scratch.0.join(S223), S223_EXCERPT).unwrap();
    let report = source(BRICK_EXCERPT, S223_EXCERPT);
    journey(&report, |profile| {
        // Synthetic known-byte preflight, not a bypass of the real Catalog pin.
        let brick = std::fs::read(scratch.0.join(BRICK)).unwrap();
        let s223 = std::fs::read(scratch.0.join(S223)).unwrap();
        assert_eq!(brick, BRICK_EXCERPT); assert_eq!(s223, S223_EXCERPT);
        let reconstructed = source(&brick, &s223);
        profile.verify_report(&reconstructed, &plan(&reconstructed).unwrap())
    });
}

#[test]
#[ignore = "requires reacquired external pinned artifacts via VERDANT_S01_ARTIFACT_DIR"]
fn s03_full_artifact_reconstruction_seal_activation_reopen() {
    let dir = PathBuf::from(std::env::var_os("VERDANT_S01_ARTIFACT_DIR").expect("explicit external artifacts"));
    outside(&dir);
    let bytes: Vec<_> = ARTIFACTS.iter().map(|pin| {
        outside(&dir.join(pin.name));
        let mut bytes = Vec::new();
        std::fs::File::open(dir.join(pin.name)).unwrap().take((semantics::parse::MAX_BYTES + 1) as u64).read_to_end(&mut bytes).unwrap();
        bytes
    }).collect();
    let inputs: Vec<_> = ARTIFACTS.iter().zip(&bytes).map(|(pin, bytes)| Input { name: pin.name, bytes }).collect();
    let report = Report::extract(&Catalog::load(&inputs).unwrap()).unwrap();
    let profile = Profile::capture(&report, &plan(&report).unwrap()).unwrap();
    println!("S03 full facts={} rows={} ledger_bytes={} payload_bytes={} ledger_digest={}", report.ledger.len(), report.rows.len(), canonical_ledger(&report).len(), profile.canonical_bytes().len(), profile.ledger_digest());
    assert_eq!(report.rows.len(), 39);
    assert_eq!(report.ledger.len(), 893);
    assert_eq!(profile.ledger_digest(), "1c40de020cd57ea70339459c96414f1c851ffdf40b795d9fc56ea4623503bd22");
    journey(&report, |sealed_profile| {
        // The reacquisition locator comes from the sealed, validated pins. The
        // caller supplied directory must contain fresh recipe-URL downloads.
        let reacquired: Vec<_> = sealed_profile.pins().iter().map(|pin| {
            assert!(pin.url.starts_with("https://"));
            let mut bytes = Vec::new();
            std::fs::File::open(dir.join(pin.name)).unwrap().take((pin.bytes + 1) as u64).read_to_end(&mut bytes).unwrap();
            bytes
        }).collect();
        let inputs: Vec<_> = sealed_profile.pins().iter().zip(&reacquired).map(|(pin, bytes)| Input { name: pin.name, bytes }).collect();
        sealed_profile.status(&inputs, plan).require()
    });
    let mut tampered = bytes;
    tampered[0][10] ^= 1;
    let inputs: Vec<_> = ARTIFACTS.iter().zip(&tampered).map(|(pin, bytes)| Input { name: pin.name, bytes }).collect();
    assert_eq!(profile.status(&inputs, plan).require().unwrap_err().code(), "s01-digest-mismatch");
}
