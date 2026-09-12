//! M01-PR07 binding records: scoped equipment/spaces/points/sources.
//!
//! Every test runs against an isolated synthetic database in an OS temp dir
//! (unique per process/test/sequence; removed on drop; never a repo path).
//! One supported target only (macOS arm64, rustc 1.97.1, system sqlite3
//! 3.54.0): other targets, power loss, real disk-full, Selene and
//! PostgreSQL are untested limits.
//!
//! No new migrations: binding records live in the PR03 0001 outbox via
//! reserved `binding-*` operations (see `src/binding/mod.rs`); the
//! reservation test below still observes exactly one numbered migration.

#[allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;

#[allow(dead_code)]
#[path = "../src/storage/mod.rs"]
mod storage;

#[allow(dead_code)]
#[path = "../src/access/mod.rs"]
mod access;

#[allow(dead_code)]
#[path = "../src/semantics/mod.rs"]
mod semantics;

#[allow(dead_code)]
#[path = "../src/binding/mod.rs"]
mod binding;

use access::{AccessGate, Reason};
use binding::{BindingRegistry, EndpointClass, EquipmentKind};
use domain::scope::TrustedScope;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(test: &str) -> Scratch {
        let id = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "verdant-pr07-rec-{}-{}-{}",
            std::process::id(),
            test,
            id
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Scratch { dir }
    }

    fn db(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn reason(test: &str) -> Reason {
    Reason::parse(&format!(
        "synthetic {} {} {}",
        test,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ))
    .expect("synthetic reason")
}

fn scope_a() -> TrustedScope {
    TrustedScope::parse("scope-a").expect("frozen scope-a")
}

fn scope_b() -> TrustedScope {
    TrustedScope::parse("scope-b").expect("frozen scope-b")
}

fn open_gate(scratch: &Scratch, name: &str) -> (AccessGate, access::BootstrapCredentials) {
    AccessGate::bootstrap(
        &scratch.db(name),
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
        &reason(name),
    )
    .unwrap_or_else(|e| panic!("bootstrap {name}: {e} [{}]", e.code()))
}

fn open_registry(scratch: &Scratch, name: &str) -> BindingRegistry {
    BindingRegistry::open(
        &scratch.db(name),
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
    )
    .unwrap_or_else(|e| panic!("open registry {name}: {e} [{}]", e.code()))
}

fn seed_tiny(registry: &mut BindingRegistry) {
    registry
        .record_equipment(
            "ahu-1",
            EquipmentKind::Ahu,
            scope_a(),
            "AHU",
            "mstp://ahu-1",
        )
        .expect("ahu-1");
    registry
        .record_equipment(
            "vav-101",
            EquipmentKind::Vav,
            scope_a(),
            "VAV",
            "mstp://vav-101",
        )
        .expect("vav-101");
    registry
        .record_equipment(
            "vav-102",
            EquipmentKind::Vav,
            scope_b(),
            "VAV",
            "mstp://vav-102",
        )
        .expect("vav-102 duplicate label allowed");
    registry
        .record_space("space-a-1", scope_a(), "Floor-A")
        .expect("space-a-1");
    registry
        .record_space("space-b-1", scope_b(), "Floor-B")
        .expect("space-b-1");
    registry
        .record_source("sensor-sat-1", scope_a(), "SAT")
        .expect("shared sensor");
    registry
        .record_point(
            "ahu-1",
            "supply-air-temp",
            scope_a(),
            "degC",
            EndpointClass::Location,
        )
        .expect("ahu point");
    registry
        .record_point(
            "vav-101",
            "airflow",
            scope_a(),
            "L/s",
            EndpointClass::Service,
        )
        .expect("vav-101 point");
    registry
        .record_point(
            "vav-102",
            "airflow",
            scope_b(),
            "L/s",
            EndpointClass::Service,
        )
        .expect("vav-102 point");
}

// ---------------------------------------------------------------------------
// Tiny-site records + shared source.
// ---------------------------------------------------------------------------

#[test]
fn tiny_site_records_cover_equipment_spaces_points_and_shared_source() {
    let scratch = Scratch::new("tiny-records");
    let (_gate, _creds) = open_gate(&scratch, "tiny.db");
    let mut registry = open_registry(&scratch, "tiny.db");
    seed_tiny(&mut registry);
    assert_eq!(registry.equipment("ahu-1").expect("ahu").label(), "AHU");
    assert_eq!(registry.equipment("vav-101").expect("vav").label(), "VAV");
    assert_eq!(registry.equipment("vav-102").expect("vav").label(), "VAV");
    assert_eq!(
        registry.equipment("ahu-1").expect("scope").scope().as_str(),
        "scope-a"
    );
    assert_eq!(
        registry
            .equipment("vav-102")
            .expect("scope")
            .scope()
            .as_str(),
        "scope-b"
    );
    // Shared source exists exactly once; both VAV bindings will cite it
    // (sharing is asserted in the proposals suite via binding source ids).
    assert!(registry.equipment("sensor-sat-1").is_none());
    // Revision bumped once per record (9 records: 3 equipment + 2 spaces +
    // 1 source + 3 points).
    assert_eq!(registry.revision().as_u32(), 9);
}

#[test]
fn duplicate_labels_are_allowed_but_duplicate_identity_is_refused() {
    let scratch = Scratch::new("dup-labels");
    let (_gate, _creds) = open_gate(&scratch, "dup.db");
    let mut registry = open_registry(&scratch, "dup.db");
    registry
        .record_equipment(
            "vav-101",
            EquipmentKind::Vav,
            scope_a(),
            "VAV",
            "mstp://vav-101",
        )
        .expect("first VAV");
    // Same label, different identity: allowed.
    registry
        .record_equipment(
            "vav-102",
            EquipmentKind::Vav,
            scope_b(),
            "VAV",
            "mstp://vav-102",
        )
        .expect("duplicate label allowed");
    // Same installed identity, different labels: refused, never overwritten.
    let err = registry
        .record_equipment(
            "vav-101",
            EquipmentKind::Vav,
            scope_a(),
            "VAV-NEW",
            "mstp://vav-101-x",
        )
        .unwrap_err();
    assert_eq!(err.code(), "duplicate-identity");
    assert_eq!(registry.equipment("vav-101").expect("kept").label(), "VAV");
}

#[test]
fn duplicate_space_and_source_identities_are_refused() {
    let scratch = Scratch::new("dup-space");
    let (_gate, _creds) = open_gate(&scratch, "dup2.db");
    let mut registry = open_registry(&scratch, "dup2.db");
    registry
        .record_space("space-a-1", scope_a(), "Floor-A")
        .expect("space");
    let err = registry
        .record_space("space-a-1", scope_a(), "Floor-A2")
        .unwrap_err();
    assert_eq!(err.code(), "duplicate-identity");
    registry
        .record_source("sensor-sat-1", scope_a(), "SAT")
        .expect("source");
    let err = registry
        .record_source("sensor-sat-1", scope_a(), "SAT2")
        .unwrap_err();
    assert_eq!(err.code(), "duplicate-identity");
}

// ---------------------------------------------------------------------------
// Retirement, history retention, reassessment.
// ---------------------------------------------------------------------------

#[test]
fn retired_records_stay_readable_and_are_never_overwritten() {
    let scratch = Scratch::new("retire");
    let (_gate, _creds) = open_gate(&scratch, "retire.db");
    let mut registry = open_registry(&scratch, "retire.db");
    seed_tiny(&mut registry);
    registry
        .retire("vav-101", "synthetic damper replacement")
        .expect("retire");
    assert!(registry.is_retired("vav-101"));
    // Old history retained, not overwritten or merged.
    let kept = registry
        .equipment("vav-101")
        .expect("retired stays readable");
    assert_eq!(kept.label(), "VAV");
    assert_eq!(kept.address().as_str(), "mstp://vav-101");
    assert!(!registry.is_retired("vav-102"));
}

#[test]
fn replacement_at_a_retired_address_needs_fresh_qualification() {
    let scratch = Scratch::new("reassess");
    let (_gate, _creds) = open_gate(&scratch, "reassess.db");
    let mut registry = open_registry(&scratch, "reassess.db");
    seed_tiny(&mut registry);
    registry
        .retire("vav-101", "synthetic swap")
        .expect("retire");
    // New record at the same field-bus address: recorded, but flagged.
    registry
        .record_equipment(
            "vav-103",
            EquipmentKind::Vav,
            scope_a(),
            "VAV",
            "mstp://vav-101",
        )
        .expect("replacement recorded");
    assert!(registry.needs_reassessment("vav-103"));
    assert!(!registry.needs_reassessment("vav-102"));
    // Old history retained, not overwritten.
    assert_eq!(
        registry
            .equipment("vav-101")
            .expect("old")
            .address()
            .as_str(),
        "mstp://vav-101"
    );
    assert_eq!(
        registry
            .equipment("vav-103")
            .expect("new")
            .address()
            .as_str(),
        "mstp://vav-101"
    );
}

// ---------------------------------------------------------------------------
// Findings: stable, citable, deterministic.
// ---------------------------------------------------------------------------

#[test]
fn findings_carry_stable_id_and_generation_for_pr11() {
    let scratch = Scratch::new("findings");
    let (gate, creds) = open_gate(&scratch, "find.db");
    let mut registry = open_registry(&scratch, "find.db");
    seed_tiny(&mut registry);
    let binding = registry
        .propose_with_credential(
            &gate,
            Some(&creds.publisher),
            "mstp://vav-101",
            EndpointClass::Service,
            scope_a(),
            "vav-101",
            "airflow",
            "sensor-sat-1",
            domain::values::Unit::parse("L/s").expect("unit"),
            None,
            binding::BindingRole::Sense,
            binding::BindingRole::Sense,
            binding::Feedback::Absent,
        )
        .expect("propose");
    let first = registry
        .emit_finding(&binding, &creds.publisher)
        .expect("finding");
    // Citable pair: id plus generation (generation equals the revision).
    assert!(first.id().as_str().starts_with("finding-"));
    assert_eq!(first.generation(), registry.revision().as_u32());
    assert_eq!(first.binding_revision(), registry.revision());
    assert!(!first.digest().is_empty());
    assert!(!first.summary().is_empty());
    // Fingerprint scopes the finding to the proposing credential.
    assert_eq!(
        first.capability_fingerprint_text(),
        creds.publisher.key().fingerprint()
    );
    assert_eq!(
        first.capability_fingerprint_text(),
        binding::capability_fingerprint(&creds.publisher)
    );
    // Deterministic: same binding, revision and fingerprint re-derive the
    // same id and digest.
    let again = binding::Finding::for_binding(
        &binding,
        registry.revision(),
        &creds.publisher.key().fingerprint(),
    );
    assert_eq!(again.id(), first.id());
    assert_eq!(again.digest(), first.digest());
}

// ---------------------------------------------------------------------------
// Persistence: 0001 reuse, coexistence, replay.
// ---------------------------------------------------------------------------

#[test]
fn no_new_migration_binding_rows_reuse_0001_outbox() {
    let scratch = Scratch::new("migration");
    let (_gate, _creds) = open_gate(&scratch, "mig.db");
    let mut registry = open_registry(&scratch, "mig.db");
    seed_tiny(&mut registry);
    // Exactly one numbered migration still.
    let mut migrations = Vec::new();
    for entry in std::fs::read_dir("migrations/sqlite").expect("migrations dir") {
        let entry = entry.expect("entry");
        migrations.push(entry.file_name().to_string_lossy().into_owned());
    }
    migrations.sort();
    assert_eq!(migrations, vec!["0001_init.sql".to_string()]);
    assert_eq!(storage::SCHEMA_GENERATION, 1);
    assert_eq!(binding::registry::BINDING_SCHEMA_GENERATION, 1);
    // Binding rows coexist with access rows in the same outbox.
    let rows = registry
        .store()
        .exec_script("SELECT COUNT(*) FROM outbox;")
        .expect("count");
    let total: u64 = rows[0][0].parse().expect("count parses");
    // 3 access rows (bootstrap) + 9 binding rows.
    assert_eq!(total, 12, "access + binding rows share the 0001 outbox");
}

#[test]
fn history_replays_across_reopen_with_retirement_intact() {
    let scratch = Scratch::new("replay");
    let (gate, creds) = open_gate(&scratch, "replay.db");
    let mut registry = open_registry(&scratch, "replay.db");
    seed_tiny(&mut registry);
    let binding = registry
        .propose_with_credential(
            &gate,
            Some(&creds.publisher),
            "mstp://ahu-1",
            EndpointClass::Location,
            scope_a(),
            "ahu-1",
            "supply-air-temp",
            "sensor-sat-1",
            domain::values::Unit::parse("degC").expect("unit"),
            None,
            binding::BindingRole::Sense,
            binding::BindingRole::Sense,
            binding::Feedback::Absent,
        )
        .expect("propose");
    let finding = registry
        .emit_finding(&binding, &creds.publisher)
        .expect("finding");
    let finding_id = finding.id().as_str().to_string();
    registry
        .retire("vav-101", "synthetic swap")
        .expect("retire");
    let revision_before = registry.revision();
    drop(registry);
    // Reopen the same file: history replays deterministically.
    let reopened = open_registry(&scratch, "replay.db");
    assert_eq!(reopened.equipment("ahu-1").expect("ahu").label(), "AHU");
    assert_eq!(reopened.bindings().len(), 1);
    assert_eq!(reopened.findings().len(), 1);
    assert_eq!(reopened.findings()[0].id().as_str(), finding_id);
    assert!(reopened.is_retired("vav-101"));
    assert_eq!(reopened.revision(), revision_before);
}
