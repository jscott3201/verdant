use crate::{fixture::*, seal, storage};

#[test]
fn seal_twice_and_different_operation_have_one_identity_and_row() {
    let mut f = Fixture::new();
    let draft = f.draft();
    let first = f.seal("seal-once", &draft).unwrap();
    let before = f.seal_rows();
    let bytes = std::fs::read(f.scratch.db()).unwrap();
    let twice = f.seal("seal-once", &draft).unwrap();
    assert_eq!(first.identity, twice.identity);
    assert_eq!(first.row_id, twice.row_id);
    assert!(twice.reconciled);
    assert_eq!(f.seal_rows(), before);
    assert_eq!(std::fs::read(f.scratch.db()).unwrap(), bytes);
    let alias = f.seal("seal-alias", &draft).unwrap();
    assert_eq!(first.identity, alias.identity);
    assert_eq!(f.seal_rows(), before);
    assert_eq!(
        f.seals
            .reconcile(&operation("seal-alias"), &first.identity)
            .unwrap()
            .unwrap()
            .row_id,
        first.row_id
    );
    assert_eq!(
        f.seals.check_before_activation(&first.identity).unwrap(),
        first.manifest
    );
    let changed = f.draft_with(vec![f.finding.clone()], "binary-context-changed");
    assert_eq!(
        f.seal("seal-alias", &changed).unwrap_err().code(),
        "seal-conflict"
    );
    let canonical = first.manifest.canonical_bytes();
    assert!(canonical.contains("valid-structural-not-qualified"));
    assert!(canonical.contains("synthetic-fnv1a64-not-authority"));
    assert!(canonical.contains("binding-canonical-v2-sha256"));
    assert!(canonical.contains("verdant-pinned-brick-223p-rec-v1"));
    assert!(canonical.contains("verdant-converter-r07-v1"));
    assert!(canonical.contains(crate::native::SELENE_REV));
    assert!(!canonical.contains("key_id="));
    assert!(canonical.starts_with("15:verdant-seal-v130:valid-structural-not-qualified7:scope-a1:31:132:verdant-pinned-brick-223p-rec-v124:verdant-converter-r07-v1"));
    assert_eq!(first.manifest.row_count(), 1);
    println!("FIXED seal twice + alias: row_id={} identities={} rows=1 manifest_bytes={} native_generation={} native_manifest_bytes={} hash_tool={}", first.row_id, first.identity.as_str(), canonical.len(), f.reference.generation(), f.reference.manifest_bytes(), f.seals.hash_tool().reference());
}

#[test]
fn independent_content_fixture_and_reference_set_order_are_canonical() {
    let mut f = Fixture::new();
    assert_eq!(
        seal::ContentNode::new("A".into(), vec![]).unwrap().value(),
        crate::domain::values::Value::Text("18:verdant-content-v116:valid-structural1:A0:".into())
    );
    let leaf = f.content("leaf", "A", vec![]);
    let roots = vec![leaf.clone(), f.finding.clone()];
    let first = f.seal("set-first", &f.draft_with(roots, "set")).unwrap();
    let roots = vec![f.finding.clone(), leaf.clone(), f.finding.clone(), leaf];
    let second = f.seal("set-second", &f.draft_with(roots, "set")).unwrap();
    assert_eq!(first.identity, second.identity);
    assert_eq!(first.manifest.row_count(), 2);
    assert_eq!(f.seal_rows().len(), 1);
}

#[test]
fn changed_row_byte_or_inert_context_is_new_identity_and_old_seal_is_immutable() {
    let mut f = Fixture::new();
    let content = f.content("meaning", "A", vec![f.finding.clone()]);
    let draft = f.draft_with(vec![content.clone()], "test-binary-A");
    let mut first = f.seal("meaning-first", &draft).unwrap();
    assert_eq!(
        first.manifest.replace(draft.clone()).unwrap_err().code(),
        "sealed-mutation"
    );
    // Deliberate raw source corruption simulates a byte change outside the
    // guarded writer. It must never silently change an accepted seal's meaning.
    let value = seal::ContentNode::new("B".into(), vec![f.finding.clone()])
        .unwrap()
        .value()
        .to_json();
    f.registry
        .store()
        .exec_script(&format!(
            "UPDATE outbox SET value_json={} WHERE operation='meaning';",
            crate::binding::sql_quote(&value)
        ))
        .unwrap();
    assert_eq!(
        f.seals
            .capture_simulation(&first.identity)
            .unwrap_err()
            .code(),
        "seal-reference-changed"
    );
    let second = f.seal("meaning-second", &draft).unwrap();
    assert_ne!(first.identity, second.identity);
    let context = f.draft_with(vec![content], "test-binary-B");
    let third = f.seal("meaning-third", &context).unwrap();
    assert_ne!(second.identity, third.identity);
    assert_eq!(f.seal_rows().len(), 3);
    println!("FIXED one-byte source mutation: {} -> {}; context change -> {}; accepted manifests immutable", first.identity.as_str(), second.identity.as_str(), third.identity.as_str());
}

#[test]
fn uncertain_commit_reconciles_operation_before_acceptance_without_second_row() {
    let mut f = Fixture::new();
    let draft = f.draft();
    storage::sqlite::faults::inject(
        &f.scratch.db(),
        storage::sqlite::faults::Fault::LostResponse,
    );
    let seal = f.seal("uncertain-seal", &draft).unwrap();
    assert!(seal.reconciled);
    assert_eq!(f.seal_rows().len(), 1);
    let again = f.seal("uncertain-seal", &draft).unwrap();
    assert_eq!(seal.identity, again.identity);
    assert_eq!(seal.row_id, again.row_id);
    assert_eq!(
        f.seals.capture_simulation(&seal.identity).unwrap(),
        seal.manifest
    );
    println!(
        "FIXED unknown submit -> writer-barrier receipt -> accepted row {} identity={} rows=1",
        seal.row_id,
        seal.identity.as_str()
    );
}

#[test]
fn failed_staging_or_precommit_leaves_accepted_rows_and_bytes_untouched() {
    let mut f = Fixture::new();
    let first = f.seal("stable-seal", &f.draft()).unwrap();
    let before = f.seal_rows();
    let db = std::fs::read(f.scratch.db()).unwrap();
    let missing = f.draft_with(vec![row("missing-nested", 1), f.finding.clone()], "missing");
    assert_eq!(
        f.seal("missing-seal", &missing).unwrap_err().code(),
        "seal-missing-reference"
    );
    let next = f.draft_with(vec![f.finding.clone()], "new-context");
    storage::sqlite::faults::inject(
        &f.scratch.db(),
        storage::sqlite::faults::Fault::BeforeCommit,
    );
    assert_eq!(
        f.seal("precommit-seal", &next).unwrap_err().code(),
        "sqlite-failure"
    );
    assert_eq!(f.seal_rows(), before);
    assert_eq!(std::fs::read(f.scratch.db()).unwrap(), db);
    assert_eq!(
        f.seals.capture_simulation(&first.identity).unwrap(),
        first.manifest
    );
    let fixed = f.seal("precommit-seal", &next).unwrap();
    assert_ne!(fixed.identity, first.identity);
    println!("FIXED staging/precommit failures: accepted row unchanged, database bytes={} unchanged, same operation retry accepted", db.len());
}
