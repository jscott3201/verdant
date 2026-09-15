//! F02-S02 native writes ONLY in isolated disposable temp-dir stores, never a
//! CLI-visible store, startup activation, SQLite migration or S03 acceptance.
//! NativeHandle remains the only lifecycle/write owner (local bounds). Reopen
//! evidence is in-process WAL replay/checkpoint recovery, not power-loss proof.
//! Fixed source excerpts below are synthetic S01-shaped evidence, not a claim
//! that these tests reacquired full artifacts. The explicit ignored gate loads
//! external artifacts, checks S01 hashes, and consumes Report::extract directly.
#![allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "../src/storage/mod.rs"]
mod storage;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "../src/semantics/mod.rs"]
mod semantics;

use domain::fixture::{tiny_site, Relationship};
use native::{NativeHandle, NativeSettings};
use semantics::ledger::{Fact, Kind};
use semantics::materialize::{Error, Plan};
use semantics::matrix::{supported, Report, Row};
use semantics::parse::{Document, Object};
use semantics::recipe::{artifact, BRICK, S223};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("verdant-native-semantics-{}-{}",
            std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).expect("exclusive scratch directory");
        assert!(!dir.canonicalize().unwrap().starts_with(
            std::fs::canonicalize(env!("CARGO_MANIFEST_DIR")).unwrap()));
        Self(dir)
    }
    fn create(&self) -> NativeHandle {
        NativeHandle::create(&self.0, NativeSettings::local()).expect("create").0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

// Manual declarations from S01's frozen matrix, parsed by the actual S01
// parser. Label/inverse/equivalent facts deliberately have no executable role.
const BRICK_EXCERPT: &[u8] = br#"
@prefix b: <https://brickschema.org/schema/Brick#> .
@prefix rec: <https://w3id.org/rec#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
b:AHU a owl:Class . b:VAV a owl:Class .
b:Supply_Air_Temperature_Sensor a owl:Class .
rec:Room a rdfs:Class .
b:hasPoint a owl:ObjectProperty ; owl:inverseOf b:isPointOf .
b:isPointOf a owl:ObjectProperty . b:feeds a owl:ObjectProperty .
b:hasLocation a owl:ObjectProperty ; owl:equivalentProperty rec:locatedIn .
rec:locatedIn a owl:ObjectProperty .
b:AHU rdfs:label "Not an installed identity" ; owl:equivalentClass b:Air_Handling_Unit .
"#;
const S223_EXCERPT: &[u8] = br#"
@prefix s: <http://data.ashrae.org/standard223#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
s:QuantifiableObservableProperty a s:Class .
s:observes a rdf:Property .
"#;

fn source() -> Report {
    let mut report = Report { rows: Vec::new(), ledger: Vec::new() };
    for (name, bytes) in [(BRICK, BRICK_EXCERPT), (S223, S223_EXCERPT)] {
        let pin = artifact(name).unwrap();
        let doc = Document::parse(bytes).unwrap();
        for (subject, predicate, object) in doc.facts() {
            let row = supported(name, subject).unwrap();
            if !report.rows.contains(&row) { report.rows.push(row); }
            report.ledger.push(Fact {
                artifact: pin.name, sha256: pin.sha256, subject: subject.into(),
                predicate: predicate.into(), object: object.clone(), kind: Kind::Original,
                rule: "source-assertion", reason: "synthetic excerpt; not full artifact evidence".into(),
                provenance: pin.provenance,
            });
        }
    }
    // Include the frozen direction as derived evidence as S01 does. It is
    // preserved separately from original assertions, not upgraded into one.
    for row in &report.rows {
        if !row.direction.is_empty() {
            let pin = artifact(row.artifact).unwrap();
            report.ledger.push(Fact {
                artifact: pin.name, sha256: pin.sha256, subject: row.iri.clone(),
                predicate: "urn:verdant:s01:direction".into(),
                object: Object::Literal(row.direction.into()), kind: Kind::Derived,
                rule: "direction-mapping", reason: "synthetic direction excerpt".into(),
                provenance: pin.provenance,
            });
        }
    }
    report
}
fn row(source: &Report, iri: &str) -> Row {
    source.rows.iter().find(|r| r.iri == iri).expect("required row").clone()
}
fn plan(source: &Report) -> Plan {
    let site = tiny_site();
    let location = row(source, "https://brickschema.org/schema/Brick#hasLocation");
    let rec = row(source, "https://w3id.org/rec#locatedIn");
    let feeds = row(source, "https://brickschema.org/schema/Brick#feeds");
    let point = row(source, "https://brickschema.org/schema/Brick#hasPoint");
    let inverse = row(source, "https://brickschema.org/schema/Brick#isPointOf");
    let observes = row(source, "http://data.ashrae.org/standard223#observes");
    Plan::tiny_site(source, &[
        (&site.relationships[0], &location), (&site.relationships[0], &rec),
        (&site.relationships[1], &rec), (&site.relationships[2], &location),
        (&site.relationships[3], &feeds), (&site.relationships[5], &point),
        (&site.relationships[6], &point), (&site.relationships[5], &inverse),
        (&site.relationships[5], &point), // repeated request is reconciled, too
    ], Some(&observes), NativeSettings::local().bounds.max_statement_bytes).unwrap()
}
fn execute(handle: &NativeHandle, query: &str) -> Result<Option<usize>, Error> {
    handle.execute(query).map(|r| r.row_count).map_err(|e| Error::Execution {
        code: e.code().into(), detail: e.to_string(),
    })
}
fn import(handle: &NativeHandle, plan: &Plan) -> Result<usize, Error> {
    assert_eq!(handle.settings(), NativeSettings::local());
    plan.reconcile(|query| execute(handle, query))
}
fn count(handle: &NativeHandle, query: &str, expected: usize) {
    assert_eq!(handle.execute(query).unwrap().row_count, Some(expected), "{query}");
}

// Independent read predicates and hardcoded JSON, never Plan queries or encoder
// output. Exact property matches plus totals detect omissions AND extra rows.
fn readback(handle: &NativeHandle) {
    count(handle, "MATCH (n:S02Node) RETURN n", 7);
    count(handle, "MATCH ()-[e:S02Relation]->() RETURN e", 9);
    count(handle, "MATCH (n:S02Node) WHERE n.role = 'installed' RETURN n", 4);
    for (scope, id, iri, label, values) in [
        ("scope-a", "ahu-1", "https://brickschema.org/schema/Brick#AHU", "AHU",
            r#"[{"type":"decimal","value":"21.50"},{"type":"diagnostic","kind":"+inf"}]"#),
        ("scope-a", "vav-101", "https://brickschema.org/schema/Brick#VAV", "VAV",
            r#"[{"type":"integer","value":"9007199254740993"},{"type":"missing"}]"#),
        ("scope-b", "vav-102", "https://brickschema.org/schema/Brick#VAV", "VAV",
            r#"[{"type":"integer","value":"0"},{"type":"bool","value":false},{"type":"diagnostic","kind":"nan"}]"#),
        ("scope-a", "sensor-sat-1", "https://brickschema.org/schema/Brick#Supply_Air_Temperature_Sensor", "SAT", "[]"),
    ] {
        count(handle, &format!("MATCH (n:S02Node) WHERE n.scope = '{scope}' AND n.role = 'installed' AND n.installed_id = '{id}' AND n.type_iri = '{iri}' AND n.label = '{label}' AND n.values_json = '{values}' AND n.artifact = 'Brick.ttl' AND n.sha256 = 'b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7' RETURN n"), 1);
    }
    for scope in ["scope-a", "scope-b"] {
        count(handle, &format!("MATCH (n:S02Node) WHERE n.scope = '{scope}' AND n.role = 'location' AND n.installed_id = '' AND n.type_iri = 'https://w3id.org/rec#Room' RETURN n"), 1);
    }
    count(handle, "MATCH (n:S02Node) WHERE n.scope = 'scope-a' AND n.role = 'property' AND n.installed_id = 'sensor-sat-1' AND n.type_iri = 'http://data.ashrae.org/standard223#QuantifiableObservableProperty' AND n.artifact = '223p.ttl' AND n.sha256 = '47bdad8925032c84e750e46b3649d102f4e41190c8161df3c9efa3265009b0e0' RETURN n", 1);
    for (scope, from, to, target_role, iri, direction, artifact, sha) in [
        ("scope-a", "ahu-1", "", "location", "https://brickschema.org/schema/Brick#hasLocation", "subject entity -> object location; not service", "Brick.ttl", "b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7"),
        ("scope-a", "ahu-1", "", "location", "https://w3id.org/rec#locatedIn", "subject entity -> object location; not service", "Brick.ttl", "b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7"),
        ("scope-a", "vav-101", "", "location", "https://w3id.org/rec#locatedIn", "subject entity -> object location; not service", "Brick.ttl", "b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7"),
        ("scope-b", "vav-102", "", "location", "https://brickschema.org/schema/Brick#hasLocation", "subject entity -> object location; not service", "Brick.ttl", "b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7"),
        ("scope-a", "ahu-1", "vav-101", "installed", "https://brickschema.org/schema/Brick#feeds", "subject upstream -> object downstream", "Brick.ttl", "b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7"),
        ("scope-a", "ahu-1", "sensor-sat-1", "installed", "https://brickschema.org/schema/Brick#hasPoint", "subject telemetry-owner -> object point", "Brick.ttl", "b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7"),
        ("scope-a", "vav-101", "sensor-sat-1", "installed", "https://brickschema.org/schema/Brick#hasPoint", "subject telemetry-owner -> object point", "Brick.ttl", "b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7"),
        ("scope-a", "sensor-sat-1", "ahu-1", "installed", "https://brickschema.org/schema/Brick#isPointOf", "subject point -> object telemetry-owner", "Brick.ttl", "b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7"),
        ("scope-a", "sensor-sat-1", "sensor-sat-1", "property", "http://data.ashrae.org/standard223#observes", "subject Sensor -> object ObservableProperty", "223p.ttl", "47bdad8925032c84e750e46b3649d102f4e41190c8161df3c9efa3265009b0e0"),
    ] {
        count(handle, &format!("MATCH (a:S02Node)-[e:S02Relation]->(b:S02Node) WHERE a.scope = '{scope}' AND b.scope = '{scope}' AND a.installed_id = '{from}' AND a.role = 'installed' AND b.installed_id = '{to}' AND b.role = '{target_role}' AND e.iri = '{iri}' AND e.direction = '{direction}' AND e.artifact = '{artifact}' AND e.sha256 = '{sha}' RETURN e"), 1);
    }
    // Two telemetry owners reach the SAME property, through one sensor node.
    count(handle, "MATCH (a:S02Node)-[p:S02Relation]->(s:S02Node)-[o:S02Relation]->(v:S02Node) WHERE p.iri = 'https://brickschema.org/schema/Brick#hasPoint' AND o.iri = 'http://data.ashrae.org/standard223#observes' AND s.role = 'installed' AND v.role = 'property' AND v.key = 'scope-a|property|sensor-sat-1' RETURN a", 2);
    // No auto-inverse for vav-101, equivalent location edge, alias or ancestry.
    count(handle, "MATCH (a:S02Node)-[e:S02Relation]->(b:S02Node) WHERE a.installed_id = 'sensor-sat-1' AND b.installed_id = 'vav-101' RETURN e", 0);
    count(handle, "MATCH (a:S02Node)-[e:S02Relation]->(b:S02Node) WHERE a.installed_id = 'vav-101' AND e.iri = 'https://brickschema.org/schema/Brick#hasLocation' RETURN e", 0);
    count(handle, "MATCH (n:S02Node) WHERE n.type_iri = 'https://brickschema.org/schema/Brick#Air_Handling_Unit' RETURN n", 0);
    count(handle, "MATCH (a:S02Node)-[e:S02Relation]->(b:S02Node) WHERE a.scope <> b.scope RETURN e", 0);
}

fn reopen(handle: NativeHandle) -> (NativeHandle, native::RecoverySummary) {
    use std::fs::{OpenOptions, TryLockError};
    use std::time::{Duration, Instant};
    let closed = handle.close();
    let lock = OpenOptions::new().read(true).write(true).open(closed.dir.join("LOCK")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(TryLockError::WouldBlock) => {
                assert!(Instant::now() < deadline, "writer LOCK was not released");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(TryLockError::Error(error)) => panic!("writer LOCK probe failed: {error}"),
        }
    }
    lock.unlock().unwrap();
    let (handle, report) = closed.open().expect("ClosedStore::open");
    assert_eq!(report.settings, NativeSettings::local());
    (handle, report.recovery.expect("RecoverySummary"))
}

#[test]
fn s02_exact_readback_repeat_and_wal_reopen() {
    let scratch = Scratch::new();
    let handle = scratch.create();
    let source = source();
    let before = (source.rows.clone(), source.ledger.clone());
    let plan = plan(&source);
    assert_eq!(import(&handle, &plan).unwrap(), 16);
    readback(&handle);
    assert_eq!(import(&handle, &plan).unwrap(), 0);
    assert_eq!(before, (source.rows, source.ledger), "S01 inputs untouched");
    let (handle, recovery) = reopen(handle); // no checkpoint
    assert!(recovery.replayed_suffix_records >= 16, "{recovery:?}");
    assert_eq!(recovery.rebuilt_indexes, 0);
    readback(&handle);
    assert_eq!(import(&handle, &plan).unwrap(), 0);
    drop(handle.close());
}

#[test]
fn s02_checkpoint_reopen_preserves_exact_readback() {
    let scratch = Scratch::new();
    let handle = scratch.create();
    let plan = plan(&source());
    assert_eq!(import(&handle, &plan).unwrap(), 16);
    readback(&handle);
    let checkpoint = handle.checkpoint().and_then(native::CheckpointOutcome::completed).unwrap();
    assert!(checkpoint.generation > 0);
    let (handle, recovery) = reopen(handle);
    assert_eq!(recovery.rebuilt_indexes, 0);
    readback(&handle);
    assert_eq!(import(&handle, &plan).unwrap(), 0);
    assert!(handle.checkpoint().and_then(native::CheckpointOutcome::completed).unwrap().generation > checkpoint.generation);
    drop(handle.close());
}

#[test]
fn s02_cross_scope_unknown_meaning_and_bad_provenance_refuse_before_writes() {
    let scratch = Scratch::new();
    let handle = scratch.create();
    let mut source = source();
    let site = tiny_site();
    let feeds = row(&source, "https://brickschema.org/schema/Brick#feeds");
    let point = row(&source, "https://brickschema.org/schema/Brick#hasPoint");
    let limit = NativeSettings::local().bounds.max_statement_bytes;
    assert_eq!(Error::CrossScope.code(), "s02-cross-scope");
    for (relationship, row) in [(&site.relationships[4], &feeds), (&site.relationships[7], &point)] {
        assert_eq!(Plan::tiny_site(&source, &[(relationship, row)], None, limit).unwrap_err(), Error::CrossScope);
    }
    let mut wrong = feeds.clone();
    wrong.iri = "https://brickschema.org/schema/Brick#isFedBy".into();
    assert_eq!(Plan::tiny_site(&source, &[(&site.relationships[3], &wrong)], None, limit).unwrap_err().code(), "s02-unsupported-meaning");
    wrong = feeds.clone();
    wrong.direction = "object downstream -> subject upstream";
    assert_eq!(Plan::tiny_site(&source, &[(&site.relationships[3], &wrong)], None, limit).unwrap_err().code(), "s02-unsupported-meaning");
    let foreign = Relationship::ServedBy { ahu: site.ahu.clone(), vav: domain::ids::InstalledId::parse("vav-999").unwrap() };
    assert_eq!(Plan::tiny_site(&source, &[(&foreign, &feeds)], None, limit).unwrap_err(), Error::OutsideFixture);
    assert_eq!(Plan::tiny_site(&source, &[], None, 64).unwrap_err(), Error::StatementLimit);
    let unsupported = supported(S223, "http://data.ashrae.org/standard223#connectsTo").unwrap();
    source.rows.push(unsupported.clone());
    assert_eq!(Plan::tiny_site(&source, &[], Some(&unsupported), limit).unwrap_err().code(), "s02-unsupported-meaning");
    source.ledger.iter_mut().find(|f| f.subject == "https://brickschema.org/schema/Brick#AHU").unwrap().sha256 = "wrong";
    assert_eq!(Plan::tiny_site(&source, &[], None, limit).unwrap_err().code(), "s02-source-evidence");
    count(&handle, "MATCH (n:S02Node) RETURN n", 0);
    count(&handle, "MATCH ()-[e:S02Relation]->() RETURN e", 0);
    drop(handle.close());
}

// Hardcoded JSON contracts: neither a snapshot nor Fact::to_json output. The
// refused literal includes quotes, backslash, newline and tab as inert text.
const PROPERTY_FACTS: &str = concat!(
    r#"[{"artifact":"223p.ttl","sha256":"47bdad8925032c84e750e46b3649d102f4e41190c8161df3c9efa3265009b0e0","subject":"http://data.ashrae.org/standard223#QuantifiableObservableProperty","predicate":"http://www.w3.org/1999/02/22-rdf-syntax-ns#type","object_kind":"iri","object":"http://data.ashrae.org/standard223#Class","kind":"original","authored":true,"rule":"source-assertion","rule_version":1,"recipe":"verdant-f02-s01-v1","reason":"synthetic excerpt; not full artifact evidence","provenance":"open223 97656845cab16183e64e9611c94f40a6fad95226; blob fcc29f7bc88df4188a35992c1ef9104d1cbe4297; v1.0.0-2026; community snapshot, not official-publication qualification","evidence":"parser-only; mapped; not observed-qualified; no native materialization"},"#,
    r#"{"artifact":"223p.ttl","sha256":"47bdad8925032c84e750e46b3649d102f4e41190c8161df3c9efa3265009b0e0","subject":"http://data.ashrae.org/standard223#QuantifiableObservableProperty","predicate":"urn:unsupported-rule","object_kind":"literal","object":"\"quoted\"\n\\\t","kind":"refusal","authored":false,"rule":"no-execution","rule_version":1,"recipe":"verdant-f02-s01-v1","reason":"inert fixture","provenance":"open223 97656845cab16183e64e9611c94f40a6fad95226; blob fcc29f7bc88df4188a35992c1ef9104d1cbe4297; v1.0.0-2026; community snapshot, not official-publication qualification","evidence":"parser-only; mapped; not observed-qualified; no native materialization"}]"#,
);
const OBSERVES_FACTS: &str = concat!(
    r#"[{"artifact":"223p.ttl","sha256":"47bdad8925032c84e750e46b3649d102f4e41190c8161df3c9efa3265009b0e0","subject":"http://data.ashrae.org/standard223#observes","predicate":"http://www.w3.org/1999/02/22-rdf-syntax-ns#type","object_kind":"iri","object":"http://www.w3.org/1999/02/22-rdf-syntax-ns#Property","kind":"original","authored":true,"rule":"source-assertion","rule_version":1,"recipe":"verdant-f02-s01-v1","reason":"synthetic excerpt; not full artifact evidence","provenance":"open223 97656845cab16183e64e9611c94f40a6fad95226; blob fcc29f7bc88df4188a35992c1ef9104d1cbe4297; v1.0.0-2026; community snapshot, not official-publication qualification","evidence":"parser-only; mapped; not observed-qualified; no native materialization"},"#,
    r#"{"artifact":"223p.ttl","sha256":"47bdad8925032c84e750e46b3649d102f4e41190c8161df3c9efa3265009b0e0","subject":"http://data.ashrae.org/standard223#observes","predicate":"urn:verdant:s01:direction","object_kind":"literal","object":"subject Sensor -> object ObservableProperty","kind":"derived","authored":false,"rule":"direction-mapping","rule_version":1,"recipe":"verdant-f02-s01-v1","reason":"synthetic direction excerpt","provenance":"open223 97656845cab16183e64e9611c94f40a6fad95226; blob fcc29f7bc88df4188a35992c1ef9104d1cbe4297; v1.0.0-2026; community snapshot, not official-publication qualification","evidence":"parser-only; mapped; not observed-qualified; no native materialization"}]"#,
);
fn fact_readback(handle: &NativeHandle) {
    // A different GQL literal delimiter/escape path from the product mapper.
    let property = PROPERTY_FACTS.replace('\\', "\\\\");
    let observes = OBSERVES_FACTS.replace('\\', "\\\\");
    count(handle, &format!("MATCH (n:S02Node) WHERE n.role = 'property' AND n.facts_json = '{property}' RETURN n"), 1);
    count(handle, &format!("MATCH ()-[e:S02Relation]->() WHERE e.iri = 'http://data.ashrae.org/standard223#observes' AND e.facts_json = '{observes}' RETURN e"), 1);
}

#[test]
fn s02_fact_literals_provenance_and_kinds_survive_reopen_without_execution() {
    let mut source = source();
    let pin = artifact(S223).unwrap();
    source.ledger.push(Fact {
        artifact: pin.name, sha256: pin.sha256,
        subject: "http://data.ashrae.org/standard223#QuantifiableObservableProperty".into(),
        predicate: "urn:unsupported-rule".into(), object: Object::Literal("\"quoted\"\n\\\t".into()),
        kind: Kind::Refusal, rule: "no-execution", reason: "inert fixture".into(), provenance: pin.provenance,
    });
    let scratch = Scratch::new();
    let handle = scratch.create();
    let plan = plan(&source);
    import(&handle, &plan).unwrap();
    readback(&handle);
    fact_readback(&handle);
    let (handle, _) = reopen(handle);
    readback(&handle);
    fact_readback(&handle);
    source.rows.reverse();
    source.ledger.reverse();
    // A reordered/duplicated ledger is not a new identity or changed provenance.
    source.ledger.push(source.ledger[0].clone());
    // Derived ancestry belongs to S01's report only, never native closure bytes.
    source.ledger.push(Fact {
        artifact: pin.name, sha256: pin.sha256,
        subject: "http://data.ashrae.org/standard223#QuantifiableObservableProperty".into(),
        predicate: "urn:verdant:s01:ancestry-path".into(),
        object: Object::Iri("http://data.ashrae.org/standard223#ObservableProperty".into()),
        kind: Kind::Derived, rule: "explicit-ancestry-path", reason: "report-only path".into(),
        provenance: pin.provenance,
    });
    assert_eq!(import(&handle, &self::plan(&source)).unwrap(), 0);
    fact_readback(&handle);
    drop(handle.close());
}

#[test]
fn s02_duplicate_or_drifted_native_identity_refuses_without_more_writes() {
    for duplicate in [false, true] {
        let scratch = Scratch::new();
        let handle = scratch.create();
        let plan = plan(&source());
        import(&handle, &plan).unwrap();
        if duplicate {
            handle.execute("INSERT (:S02Node {key: 'scope-a|installed|ahu-1'})").unwrap();
        } else {
            handle.execute("MATCH (n:S02Node) WHERE n.key = 'scope-a|installed|ahu-1' SET n.type_iri = 'wrong'").unwrap();
        }
        assert_eq!(import(&handle, &plan).unwrap_err(), Error::Conflict);
        count(&handle, "MATCH (n:S02Node) RETURN n", if duplicate { 8 } else { 7 });
        count(&handle, "MATCH ()-[e:S02Relation]->() RETURN e", 9);
        drop(handle.close());
    }
}

#[test]
fn s02_native_error_keeps_committed_prefix_retryable() {
    let scratch = Scratch::new();
    let handle = scratch.create();
    let plan = plan(&source());
    let mut writes = 0;
    let result = plan.reconcile(|query| {
        if query.starts_with("INSERT") || query.contains(" INSERT ") {
            if writes == 3 {
                return execute(&handle, "THIS IS NOT GQL");
            }
            writes += 1;
        }
        execute(&handle, query)
    });
    assert_eq!(result.unwrap_err().code(), "s02-native-execution");
    count(&handle, "MATCH (n:S02Node) RETURN n", 3);
    let (handle, recovery) = reopen(handle);
    assert!(recovery.replayed_suffix_records >= 3);
    assert_eq!(import(&handle, &plan).unwrap(), 13);
    readback(&handle);
    drop(handle.close());
}

#[test]
#[ignore = "requires external pinned S01 artifacts via VERDANT_S01_ARTIFACT_DIR"]
fn s02_full_s01_report_materializes_and_reopens() {
    use semantics::recipe::{Catalog, Input, ARTIFACTS};
    use std::io::Read;
    let dir = PathBuf::from(std::env::var_os("VERDANT_S01_ARTIFACT_DIR").expect("explicit external artifacts"));
    assert!(!dir.canonicalize().unwrap().starts_with(
        std::fs::canonicalize(env!("CARGO_MANIFEST_DIR")).unwrap()));
    let bytes: Vec<_> = ARTIFACTS.iter().map(|pin| {
        let mut bytes = Vec::new();
        std::fs::File::open(dir.join(pin.name)).unwrap()
            .take((semantics::parse::MAX_BYTES + 1) as u64).read_to_end(&mut bytes).unwrap();
        bytes
    }).collect();
    let inputs: Vec<_> = ARTIFACTS.iter().zip(&bytes)
        .map(|(pin, bytes)| Input { name: pin.name, bytes }).collect();
    let source = Report::extract(&Catalog::load(&inputs).unwrap()).unwrap();
    assert_eq!(source.rows.len(), 39);
    let plan = plan(&source);
    let scratch = Scratch::new();
    let handle = scratch.create();
    assert_eq!(import(&handle, &plan).unwrap(), 16);
    readback(&handle);
    let (handle, recovery) = reopen(handle);
    assert!(recovery.replayed_suffix_records >= 16);
    readback(&handle);
    assert_eq!(import(&handle, &plan).unwrap(), 0);
    drop(handle.close());
}
