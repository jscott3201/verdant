use super::support::*;
use crate::{
    accept::{self, EffectiveConfig, Entry, Error, SourceKind},
    binding::{BindingRole, ProposedBinding},
    domain,
    fixture::*,
};

fn entry(key: &str, label: &str, binding: ProposedBinding) -> Entry {
    Entry::new(
        domain::ids::InstalledId::parse(key).unwrap(),
        label,
        binding,
    )
    .unwrap()
}
fn changed(
    original: &ProposedBinding,
    target: &str,
    unit: &str,
    role: BindingRole,
) -> ProposedBinding {
    ProposedBinding::from_import(
        original.endpoint().clone(),
        original.endpoint_class(),
        original.endpoint_scope().clone(),
        domain::ids::InstalledId::parse(target).unwrap(),
        original.point_property().clone(),
        original.point_scope().clone(),
        original.source().clone(),
        domain::values::Unit::parse(unit).unwrap(),
        original.mode().cloned(),
        role,
        role,
        original.feedback(),
        original.status(),
    )
}

#[test]
fn fixed_sources_precedence_and_local_fingerprint_impact() {
    let mut f = Fixture::new();
    let site = domain::fixture::tiny_site();
    let binding = f.registry.bindings()[0].clone();
    let domain = vec![
        entry(
            "sat-binding",
            site.label_of(&site.ahu).unwrap(),
            binding.clone(),
        ),
        entry("unaffected-binding", "other", binding.clone()),
    ];
    let original =
        EffectiveConfig::resolve(&f.gate, &mut f.registry, scope(), domain.clone(), vec![])
            .unwrap();
    assert_eq!(original.bootstrap_source(), SourceKind::Bootstrap);
    assert_eq!(
        original.bootstrap_reason(),
        f.gate.bootstrap_reason().unwrap()
    );
    let facts: &[accept::ObservedFact] = original.facts();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].source(), SourceKind::ObservedFact);
    assert_eq!(facts[0].id(), f.registry.findings()[0].id().as_str());
    assert_eq!(facts[0].generation(), f.registry.findings()[0].generation());
    let cosmetic = EffectiveConfig::resolve(
        &f.gate,
        &mut f.registry,
        scope(),
        domain.clone(),
        vec![entry("sat-binding", "new display label", binding.clone())],
    )
    .unwrap();
    assert_eq!(
        cosmetic.entries()["sat-binding"].source(),
        SourceKind::TemporaryIntent
    );
    assert_eq!(
        cosmetic.entries()["sat-binding"].label(),
        "new display label"
    );
    assert_eq!(
        cosmetic.entries()["unaffected-binding"].source(),
        SourceKind::Domain
    );
    let diff: accept::ImpactDiff = cosmetic.impact_from(&original);
    assert_eq!(diff.cosmetic, ["sat-binding".into()].into());
    assert_eq!(
        diff.preserved,
        ["sat-binding".into(), "unaffected-binding".into()].into()
    );
    assert!(diff.invalidated.is_empty());
    assert!(diff.provenance_changed);
    assert_ne!(cosmetic.canonical_bytes(), original.canonical_bytes());
    for key in ["sat-binding", "unaffected-binding"] {
        assert_eq!(
            cosmetic.entries()[key]
                .fingerprint(f.seals.hash_tool())
                .unwrap(),
            original.entries()[key]
                .fingerprint(f.seals.hash_tool())
                .unwrap()
        );
    }
    for (target, unit, role) in [
        ("vav-101", "degC", BindingRole::Sense),
        ("ahu-1", "degF", BindingRole::Sense),
        ("ahu-1", "degC", BindingRole::Drive),
    ] {
        let edited = EffectiveConfig::resolve(
            &f.gate,
            &mut f.registry,
            scope(),
            domain.clone(),
            vec![entry(
                "sat-binding",
                "AHU",
                changed(&binding, target, unit, role),
            )],
        )
        .unwrap();
        let diff = edited.impact_from(&original);
        assert_eq!(diff.invalidated, ["sat-binding".into()].into());
        assert_eq!(diff.preserved, ["unaffected-binding".into()].into());
        assert_ne!(
            edited.entries()["sat-binding"]
                .fingerprint(f.seals.hash_tool())
                .unwrap(),
            original.entries()["sat-binding"]
                .fingerprint(f.seals.hash_tool())
                .unwrap()
        );
        assert_eq!(
            edited.entries()["unaffected-binding"]
                .fingerprint(f.seals.hash_tool())
                .unwrap(),
            original.entries()["unaffected-binding"]
                .fingerprint(f.seals.hash_tool())
                .unwrap()
        );
        assert_eq!(
            edited.facts(),
            original.facts(),
            "facts never overwrite changed intent"
        );
    }
    println!("FIXED bootstrap/access + domain/tiny_site + temporary-intent + observed-fact/durable finding; cosmetic preserves 2 fingerprints, target/unit/role invalidate only sat-binding");
}

#[test]
fn fixed_new_target_cannot_combine_with_old_sealed_approval() {
    let mut f = Fixture::new();
    let store = store(&f);
    let binding = f.registry.bindings()[0].clone();
    let config = EffectiveConfig::resolve(
        &f.gate,
        &mut f.registry,
        scope(),
        vec![entry("sat-binding", "same display label", binding.clone())],
        vec![entry(
            "sat-binding",
            "same display label",
            changed(&binding, "vav-101", "degC", BindingRole::Sense),
        )],
    )
    .unwrap();
    // Deliberately publish changed content with the old finding child. Seal
    // validates the immutable closure; accept must validate this semantic join.
    let staged: accept::Staged = store
        .stage(
            &operation("accept-stage-new-target"),
            config,
            vec![f.finding.clone()],
        )
        .unwrap();
    let seal = f
        .seal(
            "seal-wrong-approval",
            &f.draft_with(vec![staged.root().unwrap()], "pr08a-old-approval"),
        )
        .unwrap();
    let before = (counts(&f), bytes(&f));
    let error = store.sealed(&staged, &seal.identity, &f.seals).unwrap_err();
    assert!(matches!(error, Error::ApprovalMismatch));
    assert_eq!(error.code(), "accept-approval-mismatch");
    assert!(events(&f).is_empty());
    assert_eq!(before, (counts(&f), bytes(&f)));
    println!("FIXED changed target + old approval rejected even with a valid seal; events=0 rows+bytes unchanged");
}

#[test]
fn fixed_unpublished_effective_bytes_and_changed_stage_identity_are_refused() {
    let mut f = Fixture::new();
    let store = store(&f);
    let first = config(&mut f, "first label");
    let staged = store
        .stage(
            &operation("accept-stage-identity"),
            first.clone(),
            vec![f.finding.clone()],
        )
        .unwrap();
    assert_eq!(
        store
            .stage(staged.operation(), first, vec![f.finding.clone()])
            .unwrap(),
        staged
    );
    let changed = config(&mut f, "changed label");
    let snapshot = (counts(&f), bytes(&f));
    assert!(matches!(
        store.stage(staged.operation(), changed, vec![f.finding.clone()]),
        Err(Error::Conflict(_))
    ));
    assert_eq!(snapshot, (counts(&f), bytes(&f)));
    let seal = f.seal("seal-not-config", &f.draft()).unwrap();
    let snapshot = (counts(&f), bytes(&f));
    assert!(matches!(
        store.sealed(&staged, &seal.identity, &f.seals),
        Err(Error::Conflict(_))
    ));
    assert!(events(&f).is_empty());
    assert_eq!(snapshot, (counts(&f), bytes(&f)));
}

#[test]
fn fixed_source_ambiguity_is_refused_not_last_entry_wins() {
    let mut f = Fixture::new();
    let original = entry("sat-binding", "label", f.registry.bindings()[0].clone());
    assert!(matches!(
        EffectiveConfig::resolve(
            &f.gate,
            &mut f.registry,
            scope(),
            vec![original.clone(), original.clone()],
            vec![]
        ),
        Err(Error::Invalid("duplicate source key"))
    ));
    let other = entry("unknown-key", "label", original.binding().clone());
    assert!(matches!(
        EffectiveConfig::resolve(
            &f.gate,
            &mut f.registry,
            scope(),
            vec![original],
            vec![other]
        ),
        Err(Error::Invalid("intent needs a domain key"))
    ));
}

#[test]
fn fixed_environment_collision_refuses_equal_different_and_unknown_policy() {
    for name in [
        "VERDANT_POLICY_ROLE",
        "VERDANT_POLICY_UNKNOWN",
        "VERDANT_TARGET",
        "VERDANT_UNIT",
        "VERDANT_ROLE",
    ] {
        assert!(matches!(
            accept::check_environment_names([name]),
            Err(Error::EnvironmentOverride)
        ));
    }
    accept::check_environment_names(["HOME", "TMPDIR", "VERDANT_BOOTSTRAP_SECRET"]).unwrap();
    // Real environment collision isolated to child processes; no mutation of
    // the test runner's global environment and no secret value in diagnostics.
    let mut f = Fixture::new();
    let (store, sealed) = publish(&mut f, "environment", "published label");
    let snapshot = (counts(&f), bytes(&f));
    for value in ["sense", "drive", ""] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "effective::environment_child", "--nocapture"])
            .env("VERDANT_PR08A_ENV_CHILD", "yes")
            .env("VERDANT_POLICY_ROLE", value)
            .env("VERDANT_PR08A_STAGE_DB", f.scratch.db())
            .env(
                "VERDANT_PR08A_STAGE_OP",
                sealed.staged().operation().as_str(),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains("colliding environment refused; rows+bytes unchanged"));
    }
    assert_eq!(store.status(&sealed).unwrap(), accept::Stage::Sealed);
    assert_eq!(snapshot, (counts(&f), bytes(&f)));
    println!("FIXED actual child env: equal/different/empty policy values refused; unknown policy keys refused; values never retained");
}

#[test]
fn environment_child() {
    if std::env::var_os("VERDANT_PR08A_ENV_CHILD").is_none() {
        return;
    }
    let db = std::path::PathBuf::from(std::env::var_os("VERDANT_PR08A_STAGE_DB").unwrap());
    let op = operation(&std::env::var("VERDANT_PR08A_STAGE_OP").unwrap());
    let (db, _) = crate::storage::sqlite::SqliteStore::open(
        &db,
        crate::storage::ConnectionSettings::local_wal_full(),
        crate::storage::StoreBounds::tiny(),
    )
    .unwrap();
    let store = accept::AcceptanceStore::new(db);
    let published = store.read_staged(&op).unwrap();
    let error = store
        .stage(
            &operation("accept-stage-env-override"),
            published.config().clone(),
            vec![],
        )
        .unwrap_err();
    assert!(matches!(error, Error::EnvironmentOverride));
    assert_eq!(store.read_staged(&op).unwrap(), published);
    let mut f = Fixture::new();
    let binding = f.registry.bindings()[0].clone();
    let before = (counts(&f), bytes(&f));
    let error = EffectiveConfig::resolve(
        &f.gate,
        &mut f.registry,
        scope(),
        vec![entry("sat-binding", "AHU", binding)],
        vec![],
    )
    .unwrap_err();
    assert!(matches!(error, Error::EnvironmentOverride));
    assert_eq!(error.code(), "accept-environment-override");
    assert_eq!(before, (counts(&f), bytes(&f)));
    println!("colliding environment refused; rows+bytes unchanged");
}
