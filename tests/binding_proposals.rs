//! M01-PR07 proposed bindings: units, roles, feedback, scopes, imports.
//! Isolated synthetic DBs in OS temp dirs (unique, removed on drop).
//! One target only (macOS arm64, rustc 1.97.1, sqlite3 3.54.0).

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
use binding::{
    import_site, BindingRegistry, BindingRole, BindingStatus, EndpointClass, EquipmentKind,
    Feedback,
};
use domain::scope::TrustedScope;
use domain::values::{OpMode, Unit, Value};
use semantics::convert::{ExternalItem, ExternalSite};
use semantics::profile::{Profile, SUPPORTED_AHU_CLASS};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static SEQ: AtomicU64 = AtomicU64::new(0);

#[path = "semantics_cases/provenance.rs"]
mod provenance;

struct Scratch {
    dir: PathBuf,
}
impl Scratch {
    fn new(test: &str) -> Scratch {
        let id = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "verdant-pr07-prop-{}-{}-{}",
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
        .expect("vav-102");
    registry
        .record_space("space-a-1", scope_a(), "Floor-A")
        .expect("space-a-1");
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

fn unit(text: &str) -> Unit {
    Unit::parse(text).expect("unit")
}

// Positive proposals with explicit unit, enum and roles.

#[test]
fn sense_and_drive_proposals_carry_explicit_unit_enum_and_roles() {
    let scratch = Scratch::new("positive");
    let (gate, creds) = open_gate(&scratch, "pos.db");
    let mut registry = open_registry(&scratch, "pos.db");
    seed_tiny(&mut registry);
    // Sense (review-grade) with an explicit enum carried alongside the unit.
    let sense = registry
        .propose_with_credential(
            &gate,
            Some(&creds.publisher),
            "mstp://ahu-1",
            EndpointClass::Location,
            scope_a(),
            "ahu-1",
            "supply-air-temp",
            "sensor-sat-1",
            unit("degC"),
            Some(OpMode::Occupied),
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .expect("sense proposes");
    assert_eq!(sense.status(), BindingStatus::Valid);
    assert_eq!(sense.unit().as_str(), "degC");
    assert_eq!(sense.mode().expect("enum").as_str(), "occupied");
    assert_eq!(sense.requested(), BindingRole::Sense);
    assert_eq!(sense.effective(), BindingRole::Sense);
    assert_eq!(sense.source().as_str(), "sensor-sat-1");
    // Drive (publish-grade) needs the publisher ceiling.
    let drive = registry
        .propose_with_credential(
            &gate,
            Some(&creds.publisher),
            "mstp://vav-101",
            EndpointClass::Service,
            scope_a(),
            "vav-101",
            "airflow",
            "sensor-sat-1",
            unit("L/s"),
            None,
            BindingRole::Drive,
            BindingRole::Drive,
            Feedback::Single(BindingRole::Drive),
        )
        .expect("drive proposes");
    assert_eq!(drive.status(), BindingStatus::Valid);
    assert_eq!(drive.unit().as_str(), "L/s");
}

#[test]
fn imported_valid_and_observed_qualified_statuses_stay_separate() {
    provenance::assert_writer_separation_and_fidelity();
}

#[test]
fn shared_sensor_is_one_source_for_both_vavs() {
    let scratch = Scratch::new("shared");
    let (gate, creds) = open_gate(&scratch, "shared.db");
    let mut registry = open_registry(&scratch, "shared.db");
    seed_tiny(&mut registry);
    // Scope-b needs its own credential: bootstrap only mints scope-a.
    let scope_b_pub = gate
        .issue(
            &access::CapabilityName::parse("publisher-b").expect("cap"),
            &scope_b(),
            2,
            access::RoleKind::Publisher,
            &access::KeyId::parse("key-publisher-b").expect("key id"),
            &access::SyntheticKey::parse(&format!("synthetic-shared-{}-b", std::process::id()))
                .expect("key"),
            &creds.publisher,
            &reason("scope-b-issue"),
            &access::DisplayLabel::parse("synthetic").expect("label"),
        )
        .expect("scope-b publisher");
    let first = registry
        .propose_with_credential(
            &gate,
            Some(&creds.publisher),
            "mstp://vav-101",
            EndpointClass::Service,
            scope_a(),
            "vav-101",
            "airflow",
            "sensor-sat-1",
            unit("L/s"),
            None,
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .expect("vav-101 binds");
    let second = registry
        .propose_with_credential(
            &gate,
            Some(&scope_b_pub),
            "mstp://vav-102",
            EndpointClass::Service,
            scope_b(),
            "vav-102",
            "airflow",
            "sensor-sat-1",
            unit("L/s"),
            None,
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .expect("vav-102 binds");
    // ONE source for both VAVs; installed identities stay distinct.
    assert_eq!(first.source().as_str(), "sensor-sat-1");
    assert_eq!(second.source().as_str(), "sensor-sat-1");
    assert_ne!(first.point_equipment(), second.point_equipment());
}

// Refusals: units, roles, feedback, scopes, endpoint class, reassessment.

#[test]
fn wrong_unit_is_refused() {
    let scratch = Scratch::new("wrong-unit");
    let (gate, creds) = open_gate(&scratch, "wu.db");
    let mut registry = open_registry(&scratch, "wu.db");
    seed_tiny(&mut registry);
    let err = registry
        .propose_with_credential(
            &gate,
            Some(&creds.publisher),
            "mstp://ahu-1",
            EndpointClass::Location,
            scope_a(),
            "ahu-1",
            "supply-air-temp",
            "sensor-sat-1",
            unit("percent"),
            None,
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "wrong-unit");
}

#[test]
fn wrong_role_is_refused_for_mismatch_and_insufficient_capability() {
    // Pure mismatch (no silent downgrade), no store needed.
    let err = binding::propose(
        binding::EndpointAddress::parse("mstp://ahu-1").expect("endpoint"),
        EndpointClass::Location,
        scope_a(),
        domain::ids::InstalledId::parse("ahu-1").expect("id"),
        binding::PropertyName::parse("supply-air-temp").expect("property"),
        scope_a(),
        domain::ids::InstalledId::parse("sensor-sat-1").expect("source"),
        &unit("degC"),
        EndpointClass::Location,
        unit("degC"),
        None,
        BindingRole::Drive,
        BindingRole::Sense,
        Feedback::Absent,
    )
    .unwrap_err();
    assert_eq!(err.code(), "wrong-role");
    // Reviewer credential cannot cover a Drive request (role + ceiling).
    let scratch = Scratch::new("wrong-role-cap");
    let (gate, creds) = open_gate(&scratch, "wr.db");
    let mut registry = open_registry(&scratch, "wr.db");
    seed_tiny(&mut registry);
    let err = registry
        .propose_with_credential(
            &gate,
            Some(&creds.reviewer),
            "mstp://vav-101",
            EndpointClass::Service,
            scope_a(),
            "vav-101",
            "airflow",
            "sensor-sat-1",
            unit("L/s"),
            None,
            BindingRole::Drive,
            BindingRole::Drive,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "wrong-role");
}

#[test]
fn ambiguous_feedback_is_refused() {
    let scratch = Scratch::new("feedback");
    let (gate, creds) = open_gate(&scratch, "fb.db");
    let mut registry = open_registry(&scratch, "fb.db");
    seed_tiny(&mut registry);
    let err = registry
        .propose_with_credential(
            &gate,
            Some(&creds.publisher),
            "mstp://ahu-1",
            EndpointClass::Location,
            scope_a(),
            "ahu-1",
            "supply-air-temp",
            "sensor-sat-1",
            unit("degC"),
            None,
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Ambiguous,
        )
        .unwrap_err();
    assert_eq!(err.code(), "ambiguous-feedback");
}

#[test]
fn cross_scope_traversal_grants_nothing() {
    let scratch = Scratch::new("xscope");
    let (gate, creds) = open_gate(&scratch, "xs.db");
    let mut registry = open_registry(&scratch, "xs.db");
    seed_tiny(&mut registry);
    // Scope-A credential cannot bind a scope-B endpoint/point.
    let err = registry
        .propose_with_credential(
            &gate,
            Some(&creds.publisher),
            "mstp://vav-102",
            EndpointClass::Service,
            scope_b(),
            "vav-102",
            "airflow",
            "sensor-sat-1",
            unit("L/s"),
            None,
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "scope-denied");
    // Pure structural cross-scope (endpoint vs point) is also refused.
    let err = binding::propose(
        binding::EndpointAddress::parse("mstp://vav-101").expect("endpoint"),
        EndpointClass::Service,
        scope_a(),
        domain::ids::InstalledId::parse("vav-102").expect("id"),
        binding::PropertyName::parse("airflow").expect("property"),
        scope_b(),
        domain::ids::InstalledId::parse("sensor-sat-1").expect("source"),
        &unit("L/s"),
        EndpointClass::Service,
        unit("L/s"),
        None,
        BindingRole::Sense,
        BindingRole::Sense,
        Feedback::Absent,
    )
    .unwrap_err();
    assert_eq!(err.code(), "scope-denied");
}

#[test]
fn endpoint_service_vs_location_confusion_is_refused() {
    let scratch = Scratch::new("eclass");
    let (gate, creds) = open_gate(&scratch, "ec.db");
    let mut registry = open_registry(&scratch, "ec.db");
    seed_tiny(&mut registry);
    // Correctly classified endpoints pass (service for airflow).
    registry
        .propose_with_credential(
            &gate,
            Some(&creds.publisher),
            "mstp://vav-101",
            EndpointClass::Service,
            scope_a(),
            "vav-101",
            "airflow",
            "sensor-sat-1",
            unit("L/s"),
            None,
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .expect("service endpoint for airflow");
    // Service/location confusion is refused.
    let err = registry
        .propose_with_credential(
            &gate,
            Some(&creds.publisher),
            "mstp://vav-101",
            EndpointClass::Location,
            scope_a(),
            "vav-101",
            "airflow",
            "sensor-sat-1",
            unit("L/s"),
            None,
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "endpoint-confusion");
}

#[test]
fn replacement_at_a_retired_address_needs_reassessment_on_propose() {
    let scratch = Scratch::new("reassess-prop");
    let (gate, creds) = open_gate(&scratch, "rp.db");
    let mut registry = open_registry(&scratch, "rp.db");
    seed_tiny(&mut registry);
    registry
        .retire("vav-101", "synthetic swap")
        .expect("retire");
    registry
        .record_equipment(
            "vav-103",
            EquipmentKind::Vav,
            scope_a(),
            "VAV",
            "mstp://vav-101",
        )
        .expect("replacement");
    registry
        .record_point(
            "vav-103",
            "airflow",
            scope_a(),
            "L/s",
            EndpointClass::Service,
        )
        .expect("replacement point");
    let err = registry
        .propose_with_credential(
            &gate,
            Some(&creds.publisher),
            "mstp://vav-101",
            EndpointClass::Service,
            scope_a(),
            "vav-103",
            "airflow",
            "sensor-sat-1",
            unit("L/s"),
            None,
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "needs-reassessment");
}
