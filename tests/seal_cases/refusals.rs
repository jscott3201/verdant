use crate::{binding, fixture::*, seal};

#[test]
fn imported_finding_is_not_sealable_or_upgraded_to_qualified() {
    let mut f = Fixture::with_status(binding::BindingStatus::Imported);
    let error = f.seal("imported-seal", &f.draft()).unwrap_err();
    assert!(matches!(error, seal::SealError::Status(ref status) if status == "imported"));
    assert!(f.seal_rows().is_empty());
    assert_eq!(
        f.registry.bindings()[0].status(),
        binding::BindingStatus::Imported
    );
    println!("FIXED imported status refused without row or status upgrade: {error}");
}

#[test]
fn missing_nested_ref_and_cycle_refuse_without_rows() {
    let mut f = Fixture::new();
    let outer = f.content(
        "outer",
        "parent",
        vec![row("not-present", 1), f.finding.clone()],
    );
    let error = f
        .seal("missing-nested-seal", &f.draft_with(vec![outer], "nested"))
        .unwrap_err();
    assert_eq!(error.code(), "seal-missing-reference");
    let a = f.content("cycle-a", "a", vec![row("cycle-b", 1)]);
    f.content("cycle-b", "b", vec![a.clone(), f.finding.clone()]);
    let error = f
        .seal("cyclic-seal", &f.draft_with(vec![a], "cycle"))
        .unwrap_err();
    assert!(matches!(error, seal::SealError::Cycle));
    assert!(f.seal_rows().is_empty());
    println!("FIXED durable nested missing/cyclic closure refused: {error}");
}

#[test]
fn closure_depth_and_byte_limits_fail_closed() {
    let mut f = Fixture::new();
    let mut parent = f.finding.clone();
    for i in 0..=seal::MAX_DEPTH {
        parent = f.content(&format!("deep-{i}"), "depth", vec![parent]);
    }
    assert_eq!(
        f.seal("deep-seal", &f.draft_with(vec![parent], "depth"))
            .unwrap_err()
            .code(),
        "seal-limit"
    );
    let mut roots = vec![f.finding.clone()];
    for i in 0..16 {
        roots.push(f.content(&format!("large-{i}"), &"x".repeat(16_384), Vec::new()));
    }
    let error = f
        .seal("oversized-seal", &f.draft_with(roots, "large"))
        .unwrap_err();
    assert!(matches!(error, seal::SealError::Limit("closure bytes")));
    assert!(f.seal_rows().is_empty());
    println!("FIXED over-depth and >256KiB closure refused before seal acceptance: {error}");
}

#[test]
fn closure_node_limit_and_draft_limits_are_not_silent_truncation() {
    let mut f = Fixture::new();
    let mut children = vec![f.finding.clone()];
    for i in 0..63 {
        children.push(f.content(&format!("leaf-{i}"), "leaf", Vec::new()));
    }
    let root = f.content("many-children", "root", children);
    let error = f
        .seal("node-limit-seal", &f.draft_with(vec![root], "nodes"))
        .unwrap_err();
    assert!(matches!(error, seal::SealError::Limit("closure nodes")));
    assert!(seal::Draft::new(
        f.registry.revision(),
        scope(),
        seal::RuntimeRef::new("test", "host").unwrap(),
        vec![f.finding.clone(); 65],
        vec![f.reference.clone()]
    )
    .is_err());
    assert!(seal::Draft::new(
        f.registry.revision(),
        scope(),
        seal::RuntimeRef::new("test", "host").unwrap(),
        vec![f.finding.clone()],
        vec![f.reference.clone(); 9]
    )
    .is_err());
    assert!(f.seal_rows().is_empty());
}

#[test]
fn source_change_at_writer_boundary_is_refused_atomically() {
    let mut f = Fixture::new();
    let node = f.content("boundary-row", "before", vec![f.finding.clone()]);
    let draft = f.draft_with(vec![node], "boundary");
    let store = f.registry.store().try_clone().unwrap();
    let value = seal::ContentNode::new("after".into(), vec![f.finding.clone()])
        .unwrap()
        .value()
        .to_json();
    seal::on_boundary(move || {
        store
            .exec_script(&format!(
                "UPDATE outbox SET value_json={} WHERE operation='boundary-row';",
                binding::sql_quote(&value)
            ))
            .unwrap();
    });
    let error = f.seal("boundary-seal", &draft).unwrap_err();
    assert_eq!(error.code(), "sqlite-failure");
    assert!(f.seal_rows().is_empty());
    assert!(error.to_string().contains("access_guard_unchanged"));
}

#[test]
fn digest_never_authorizes_seal_or_release() {
    let mut f = Fixture::new();
    let draft = f.draft();
    let error = f
        .seals
        .seal(
            &operation("reviewer-seal"),
            &draft,
            &mut f.registry,
            &f.gate,
            &f.credentials.reviewer,
        )
        .unwrap_err();
    assert!(matches!(error, seal::SealError::Binding(_)));
    assert!(f.seal_rows().is_empty());
    let sealed = f.seal("publisher-seal", &draft).unwrap();
    f.gate
        .revoke(
            &f.credentials.publisher,
            &crate::access::Reason::parse("synthetic revoked publisher").unwrap(),
        )
        .unwrap();
    assert_eq!(
        f.release("revoked-release", &sealed.identity)
            .unwrap_err()
            .code(),
        "capability-denied"
    );
    // Receipt/capture evidence is read-only and grants no dependent operation.
    assert_eq!(
        f.seals.capture_simulation(&sealed.identity).unwrap(),
        sealed.manifest
    );
    assert!(matches!(
        f.native.prune().unwrap_err(),
        crate::native::NativeError::Custody { .. }
    ));
}

#[test]
fn observed_qualified_assertion_is_refused_even_in_a_durable_finding() {
    let mut f = Fixture::new();
    let original = f
        .registry
        .store()
        .exec_script("SELECT value_json FROM outbox WHERE operation='binding-finding';")
        .unwrap()[0][0]
        .clone();
    let forged = original.replace("valid", "observed-qualified");
    f.registry
        .store()
        .exec_script(&format!(
            "UPDATE outbox SET value_json={} WHERE operation='binding-finding';",
            binding::sql_quote(&forged)
        ))
        .unwrap();
    let error = f.seal("forged-qualified", &f.draft()).unwrap_err();
    assert_eq!(error.code(), "seal-status-refused");
    assert!(f.seal_rows().is_empty());
}

#[test]
fn revoked_at_commit_boundary_is_not_authorized_by_staged_actor_reference() {
    let mut f = Fixture::new();
    let gate = crate::access::AccessGate::open(
        &f.scratch.db(),
        crate::storage::ConnectionSettings::local_wal_full(),
        crate::storage::StoreBounds::tiny(),
    )
    .unwrap();
    let credential = f.credentials.publisher.clone();
    seal::on_boundary(move || {
        gate.revoke(
            &credential,
            &crate::access::Reason::parse("revoke staged actor").unwrap(),
        )
        .unwrap();
    });
    let error = f.seal("revoked-boundary", &f.draft()).unwrap_err();
    assert!(error.to_string().contains("access_guard_unchanged"));
    assert!(f.seal_rows().is_empty());
}
