//! M01-PR07 binding imports and authority boundaries.
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
    import_diagnostic, import_site, BindingRegistry, BindingRole, EndpointClass, EquipmentKind,
    Feedback,
};
use domain::scope::TrustedScope;
use domain::values::{Unit, Value};
use semantics::convert::{ExternalItem, ExternalSite};
use semantics::profile::{Profile, SUPPORTED_SAT_CLASS, SUPPORTED_VAV_CLASS};
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
            "verdant-pr07-imp-{}-{}-{}",
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
        .expect("vav point");
}
fn unit(text: &str) -> Unit {
    Unit::parse(text).expect("unit")
}
// Imports: mapped outcomes plus diagnostics with cause preserved.
#[test]
fn import_diagnostics_surface_as_binding_refusals_with_cause() {
    let profile = Profile::pinned();
    let chiller = ExternalItem::parse(
        "ext-chiller-1",
        "brick:Chiller",
        "ahu-1",
        "CHILLER",
        "degC",
        Value::Missing,
    )
    .expect("parses; refused at convert");
    let site = ExternalSite::new(vec![chiller]).expect("site");
    let err = import_site(&site, &profile).unwrap_err();
    assert_eq!(err.code(), "import-out-of-scenario");
    let unknown = ExternalItem::parse(
        "ext-weird-1",
        "brick:Not-A-Real-Class",
        "ahu-1",
        "WEIRD",
        "degC",
        Value::Missing,
    )
    .expect("parses; refused at convert");
    let site = ExternalSite::new(vec![unknown]).expect("site");
    let err = import_site(&site, &profile).unwrap_err();
    assert_eq!(err.code(), "import-unknown-class");
    let first = ExternalItem::parse(
        "ext-a-1",
        SUPPORTED_VAV_CLASS,
        "vav-101",
        "VAV",
        "L/s",
        Value::Integer(1),
    )
    .expect("first");
    let second = ExternalItem::parse(
        "ext-a-2",
        SUPPORTED_VAV_CLASS,
        "vav-101",
        "VAV",
        "L/s",
        Value::Integer(2),
    )
    .expect("second");
    let site = ExternalSite::new(vec![first, second]).expect("site");
    let err = import_site(&site, &profile).unwrap_err();
    assert_eq!(err.code(), "import-collision");
    let mismatch = ExternalItem::parse(
        "ext-m-1",
        SUPPORTED_VAV_CLASS,
        "ahu-9",
        "VAV",
        "L/s",
        Value::Integer(1),
    )
    .expect("parses; refused at convert");
    let site = ExternalSite::new(vec![mismatch]).expect("site");
    let err = import_site(&site, &profile).unwrap_err();
    assert_eq!(err.code(), "import-slot-mismatch");
    let direct = semantics::convert::SemanticsError::UnknownClass {
        class: "brick:X".to_string(),
        profile: profile.id().to_string(),
    };
    let mapped = import_diagnostic(&direct);
    assert_eq!(mapped.code(), "import-unknown-class");
    let sat = ExternalItem::parse(
        "ext-sat-1",
        SUPPORTED_SAT_CLASS,
        "sensor-sat-1",
        "SAT",
        "degC",
        Value::Missing,
    )
    .expect("sat item");
    let site = ExternalSite::new(vec![sat]).expect("site");
    let conversion = import_site(&site, &profile).expect("sat converts");
    assert_eq!(conversion.bindings().len(), 1);
    assert_eq!(conversion.bindings()[0].unit().as_str(), "degC");
}
// Revocation and actuation boundaries.
#[test]
fn revoked_credentials_cannot_propose_and_verify_offline() {
    let scratch = Scratch::new("revoked");
    let (gate, creds) = open_gate(&scratch, "rv.db");
    let mut registry = open_registry(&scratch, "rv.db");
    seed_tiny(&mut registry);
    gate.revoke(&creds.publisher, &reason("revoke-pub"))
        .expect("revoke");
    assert!(gate
        .is_revoked(creds.publisher.capability(), creds.publisher.key_id())
        .expect("offline verification"));
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
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "capability-denied");
}
#[test]
fn bindings_never_authorize_actuation_from_class_or_address_alone() {
    let scratch = Scratch::new("no-act");
    let (gate, creds) = open_gate(&scratch, "na.db");
    let mut registry = open_registry(&scratch, "na.db");
    seed_tiny(&mut registry);
    let err = registry
        .propose_with_credential(
            &gate,
            None,
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
    assert_eq!(err.code(), "capability-denied");
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
    assert!(gate
        .enter_publish(Some(&creds.reviewer), &scope_a())
        .is_err());
}
