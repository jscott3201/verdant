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
    import_diagnostic, import_site, BindingRegistry, BindingRole, BindingStatus, EndpointClass,
    EquipmentKind, Feedback,
};
use domain::scope::TrustedScope;
use domain::values::{Unit, Value};
use semantics::convert::{ExternalItem, ExternalSite};
use semantics::profile::{Profile, SUPPORTED_AHU_CLASS, SUPPORTED_SAT_CLASS, SUPPORTED_VAV_CLASS};
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
// ARCH-1: credentialed imports anchor to recorded point truth, exactly
// like propose. The conversion's verdant slot plus the point property
// locate the stored PointRecord; unit/class/scope and capability all check
// against that stored truth. Caller-supplied expectations cannot smuggle a
// cross-scope binding past the gate.
fn ahu_conversion(unit_text: &str) -> semantics::convert::Binding {
    let profile = Profile::pinned();
    let item = ExternalItem::parse(
        "ext-ahu-1",
        SUPPORTED_AHU_CLASS,
        "ahu-1",
        "AHU",
        unit_text,
        Value::Missing,
    )
    .expect("ahu item parses; unit is preserved verbatim");
    let site = ExternalSite::new(vec![item]).expect("site");
    let conversion = import_site(&site, &profile).expect("ahu converts");
    assert_eq!(conversion.bindings().len(), 1);
    conversion.bindings()[0].clone()
}
fn vav_conversion(slot: &str, key: &str) -> semantics::convert::Binding {
    let profile = Profile::pinned();
    let item = ExternalItem::parse(key, SUPPORTED_VAV_CLASS, slot, "VAV", "L/s", Value::Missing)
        .expect("vav item parses");
    let site = ExternalSite::new(vec![item]).expect("site");
    let conversion = import_site(&site, &profile).expect("vav converts");
    assert_eq!(conversion.bindings().len(), 1);
    conversion.bindings()[0].clone()
}
#[test]
fn credentialed_import_happy_path_persists_imported_and_replays_across_reopen() {
    let scratch = Scratch::new("cred-import-ok");
    let (gate, creds) = open_gate(&scratch, "ci-ok.db");
    let mut registry = open_registry(&scratch, "ci-ok.db");
    seed_tiny(&mut registry);
    let conversion = ahu_conversion("degC");
    let revision_before = registry.revision().as_u32();
    let imported = registry
        .import_with_credential(
            &gate,
            Some(&creds.publisher),
            &conversion, registry.revision(),
            "mstp://ahu-1",
            EndpointClass::Location,
            scope_a(),
            "supply-air-temp",
            "sensor-sat-1",
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .expect("anchored import proposes");
    assert_eq!(imported.status(), BindingStatus::Imported);
    assert_eq!(imported.unit().as_str(), "degC");
    assert_eq!(imported.point_equipment().as_str(), "ahu-1");
    assert_eq!(imported.point_property().as_str(), "supply-air-temp");
    assert_eq!(imported.point_scope().as_str(), "scope-a");
    assert_eq!(registry.bindings().len(), 1);
    assert_eq!(registry.revision().as_u32(), revision_before + 1);
    // Finding cites the post-import revision, exactly like propose.
    let finding = registry
        .emit_finding(&gate, &imported, &creds.publisher)
        .expect("finding");
    assert_eq!(finding.binding_revision(), registry.revision());
    drop(registry);
    let reopened = open_registry(&scratch, "ci-ok.db");
    assert_eq!(reopened.bindings().len(), 1);
    assert_eq!(reopened.bindings()[0].status(), BindingStatus::Imported);
    assert_eq!(reopened.bindings()[0].unit().as_str(), "degC");
    assert_eq!(reopened.findings().len(), 1);
}
#[test]
fn credentialed_import_cross_scope_is_refused() {
    let scratch = Scratch::new("cred-import-xscope");
    let (gate, creds) = open_gate(&scratch, "ci-xs.db");
    let mut registry = open_registry(&scratch, "ci-xs.db");
    seed_tiny(&mut registry);
    // Scope-b point truth exists; the scope-a-only publisher must not persist
    // it no matter which endpoint scope the caller claims.
    registry
        .record_equipment(
            "vav-102",
            EquipmentKind::Vav,
            scope_b(),
            "VAV",
            "mstp://vav-102",
        )
        .expect("scope-b equipment");
    registry
        .record_point(
            "vav-102",
            "airflow",
            scope_b(),
            "L/s",
            EndpointClass::Service,
        )
        .expect("scope-b point");
    let conversion = vav_conversion("vav-102", "ext-vav-102");
    let revision_before = registry.revision();
    // Caller claims the endpoint lives in scope-b (structurally consistent
    // with the stored point): the STORED-scope capability check still fails.
    let err = registry
        .import_with_credential(
            &gate,
            Some(&creds.publisher),
            &conversion, registry.revision(),
            "mstp://vav-102",
            EndpointClass::Service,
            scope_b(),
            "airflow",
            "sensor-sat-1",
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "scope-denied");
    // Caller claims the endpoint lives in scope-a instead: the
    // endpoint-vs-stored scope check fails first.
    let err = registry
        .import_with_credential(
            &gate,
            Some(&creds.publisher),
            &conversion, registry.revision(),
            "mstp://vav-102",
            EndpointClass::Service,
            scope_a(),
            "airflow",
            "sensor-sat-1",
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "scope-denied");
    // Neither refusal persisted a binding, bumped the revision, or left a
    // replayable row behind.
    assert_eq!(registry.bindings().len(), 0);
    assert_eq!(registry.revision(), revision_before);
    drop(registry);
    let reopened = open_registry(&scratch, "ci-xs.db");
    assert_eq!(reopened.bindings().len(), 0);
    assert_eq!(reopened.revision(), revision_before);
}
#[test]
fn credentialed_import_wrong_unit_and_class_against_truth_are_refused() {
    let scratch = Scratch::new("cred-import-truth");
    let (gate, creds) = open_gate(&scratch, "ci-truth.db");
    let mut registry = open_registry(&scratch, "ci-truth.db");
    seed_tiny(&mut registry);
    // Stored truth is degC + Location for ahu-1:supply-air-temp. A
    // conversion carrying percent refuses against truth (wrong-unit), even
    // though the caller cannot override the expectation anymore.
    let wrong_unit = ahu_conversion("percent");
    let err = registry
        .import_with_credential(
            &gate,
            Some(&creds.publisher),
            &wrong_unit, registry.revision(),
            "mstp://ahu-1",
            EndpointClass::Location,
            scope_a(),
            "supply-air-temp",
            "sensor-sat-1",
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "wrong-unit");
    // Same stored truth with a Service endpoint refuses (endpoint-confusion).
    let conversion = ahu_conversion("degC");
    let err = registry
        .import_with_credential(
            &gate,
            Some(&creds.publisher),
            &conversion, registry.revision(),
            "mstp://ahu-1",
            EndpointClass::Service,
            scope_a(),
            "supply-air-temp",
            "sensor-sat-1",
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "endpoint-confusion");
    assert_eq!(registry.bindings().len(), 0);
}
#[test]
fn credentialed_import_unknown_point_is_refused() {
    let scratch = Scratch::new("cred-import-unknown");
    let (gate, creds) = open_gate(&scratch, "ci-unk.db");
    let mut registry = open_registry(&scratch, "ci-unk.db");
    seed_tiny(&mut registry);
    // ahu-9 converts (slot prefix matches) but no point was ever recorded.
    let profile = Profile::pinned();
    let item = ExternalItem::parse(
        "ext-ahu-9",
        SUPPORTED_AHU_CLASS,
        "ahu-9",
        "AHU",
        "degC",
        Value::Missing,
    )
    .expect("ahu-9 parses; refused at import");
    let site = ExternalSite::new(vec![item]).expect("site");
    let conversion = import_site(&site, &profile).expect("ahu-9 converts");
    let unknown = conversion.bindings()[0].clone();
    let err = registry
        .import_with_credential(
            &gate,
            Some(&creds.publisher),
            &unknown, registry.revision(),
            "mstp://ahu-9",
            EndpointClass::Location,
            scope_a(),
            "supply-air-temp",
            "sensor-sat-1",
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid-record");
    assert_eq!(registry.bindings().len(), 0);
}
#[test]
fn credentialed_import_revoked_and_over_ceiling_are_refused() {
    let scratch = Scratch::new("cred-import-cap");
    let (gate, creds) = open_gate(&scratch, "ci-cap.db");
    let mut registry = open_registry(&scratch, "ci-cap.db");
    seed_tiny(&mut registry);
    let conversion = ahu_conversion("degC");
    // Reviewer (review-grade ceiling) cannot cover a Drive import: the
    // stored-scope capability check maps to wrong-role, as in propose.
    let err = registry
        .import_with_credential(
            &gate,
            Some(&creds.reviewer),
            &conversion, registry.revision(),
            "mstp://ahu-1",
            EndpointClass::Location,
            scope_a(),
            "supply-air-temp",
            "sensor-sat-1",
            BindingRole::Drive,
            BindingRole::Drive,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "wrong-role");
    // Revoked publisher cannot import even a well-formed Sense binding.
    gate.revoke(&creds.publisher, &reason("revoke-pub-import"))
        .expect("revoke");
    let err = registry
        .import_with_credential(
            &gate,
            Some(&creds.publisher),
            &conversion, registry.revision(),
            "mstp://ahu-1",
            EndpointClass::Location,
            scope_a(),
            "supply-air-temp",
            "sensor-sat-1",
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "capability-denied");
    assert_eq!(registry.bindings().len(), 0);
}
#[test]
fn credentialed_import_reassessment_address_is_refused() {
    let scratch = Scratch::new("cred-import-reassess");
    let (gate, creds) = open_gate(&scratch, "ci-re.db");
    let mut registry = open_registry(&scratch, "ci-re.db");
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
    assert!(registry.needs_reassessment("vav-103"));
    let conversion = vav_conversion("vav-103", "ext-vav-103");
    // Reassessment is checked before capability, as in propose: even the
    // publisher is refused here.
    let err = registry
        .import_with_credential(
            &gate,
            Some(&creds.publisher),
            &conversion, registry.revision(),
            "mstp://vav-101",
            EndpointClass::Service,
            scope_a(),
            "airflow",
            "sensor-sat-1",
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert_eq!(err.code(), "needs-reassessment");
    assert_eq!(registry.bindings().len(), 0);
}
