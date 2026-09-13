use crate::{accept, access, api, binding, domain, fixture::*, operations::*, storage, support};

#[test]
fn fixed_semantic_edit_invalidates_fingerprint_and_requires_new_finding() {
    let mut f = Fixture::new();
    let original = content(&mut f, "SAT");
    let binding = f.registry.bindings()[0].clone();
    let changed = binding::ProposedBinding::from_import(
        binding::EndpointAddress::parse("mstp://changed-target").unwrap(),
        binding.endpoint_class(),
        scope(),
        binding.point_equipment().clone(),
        binding.point_property().clone(),
        scope(),
        binding.source().clone(),
        binding.unit().clone(),
        binding.mode().cloned(),
        binding.requested(),
        binding.effective(),
        binding.feedback(),
        binding.status(),
    );
    let entry = accept::Entry::new(
        domain::ids::InstalledId::parse("sat-binding").unwrap(),
        "SAT",
        changed,
    )
    .unwrap();
    let finding = reference(&f);
    let changed = with_api(&mut f, |api, credential| {
        api.resolve(
            Some(credential),
            &scope(),
            vec![entry],
            vec![],
            vec![finding],
        )
        .unwrap()
    });
    let first_op = operation("api-semantic-before");
    let next_op = operation("api-semantic-after");
    let (first, second) = with_api(&mut f, |api, credential| {
        let first = api.draft(Some(credential), &first_op, &original).unwrap();
        let (second, impact) = api
            .edit(Some(credential), &next_op, &first_op, &changed)
            .unwrap();
        assert_eq!(
            impact.invalidated.iter().cloned().collect::<Vec<_>>(),
            ["sat-binding"]
        );
        assert!(impact.cosmetic.is_empty());
        let report = api
            .validate(Some(credential), &scope(), &next_op, all())
            .unwrap();
        assert!(report.items.contains(&api::Diagnostic::MissingFinding {
            prerequisite: "finding:sat-binding".into()
        }));
        assert_eq!(
            api.entries(
                Some(credential),
                &scope(),
                &next_op,
                api::PageRequest::new(0, 1).unwrap()
            )
            .unwrap()
            .items
            .len(),
            1
        );
        (first, second)
    });
    let owner = support::store(&f);
    let first = owner.read_staged(first.staged_operation()).unwrap();
    let second = owner.read_staged(second.staged_operation()).unwrap();
    assert_ne!(
        first.config().entries()["sat-binding"]
            .fingerprint(f.seals.hash_tool())
            .unwrap(),
        second.config().entries()["sat-binding"]
            .fingerprint(f.seals.hash_tool())
            .unwrap()
    );
    println!("FIXED: semantic target edit changes fingerprint and invalidates old approval; entries are explicitly paged");
}

#[test]
fn fixed_interrupted_draft_keeps_inspectable_intent_and_retry_has_one_effect() {
    let mut f = Fixture::new();
    let input = content(&mut f, "interrupted");
    let op = operation("api-interrupted-draft");
    let path = f.scratch.db();
    api::on_draft_boundary(move || {
        storage::sqlite::faults::inject(&path, storage::sqlite::faults::Fault::BeforeCommit)
    });
    with_api(&mut f, |api, credential| {
        assert!(matches!(
            api.draft(Some(credential), &op, &input),
            Err(api::Error::Accept(accept::Error::Storage(
                storage::StorageError::SqliteFailure { .. }
            )))
        ));
        let work = api.work(Some(credential), &scope(), &op).unwrap();
        assert!(work.intent_row > 0 && work.effect_known && work.effect_row.is_none());
        assert_eq!(
            api.read(Some(credential), &scope(), &op)
                .unwrap_err()
                .code(),
            "api-missing-content"
        );
    });
    assert_eq!(
        f.registry
            .store()
            .exec_script("SELECT COUNT(*) FROM outbox WHERE operation='api-intent-v1';")
            .unwrap(),
        vec![vec!["1"]]
    );
    let (intent, effect) = with_api(&mut f, |api, credential| {
        api.draft(Some(credential), &op, &input).unwrap();
        let work = api.work(Some(credential), &scope(), &op).unwrap();
        (work.intent_row, work.effect_row.unwrap())
    });
    let before = (support::counts(&f), support::bytes(&f));
    with_api(&mut f, |api, credential| {
        api.draft(Some(credential), &op, &input).unwrap();
        let work = api.work(Some(credential), &scope(), &op).unwrap();
        assert_eq!(work.intent_row, intent);
        assert_eq!(work.effect_row, Some(effect));
    });
    assert_eq!((support::counts(&f), support::bytes(&f)), before);
    assert_eq!(f.registry.store().execution_report().running, 0);
    println!("FIXED: interrupted second commit leaves one visible intent and no draft effect; retry writes exactly one stage, later retries preserve bytes");
}

#[test]
fn fixed_prepared_acceptance_reauthenticates_after_revocation() {
    let mut f = Fixture::new();
    let input = content(&mut f, "revoke");
    let publication = publication(&f);
    let op = operation("api-revoked-accept");
    with_api(&mut f, |api, credential| {
        api.draft(Some(credential), &operation("api-revoked-draft"), &input)
            .unwrap();
        api.seal(
            Some(credential),
            &scope(),
            &operation("api-revoked-seal"),
            &operation("api-revoked-draft"),
            &publication,
        )
        .unwrap();
        api.prepare_accept(
            Some(credential),
            &scope(),
            &op,
            &operation("api-revoked-seal"),
            accept::AcceptedRevision::INITIAL,
        )
        .unwrap();
    });
    f.gate
        .revoke(
            &f.credentials.publisher,
            &access::Reason::parse("synthetic revoke prepared API work").unwrap(),
        )
        .unwrap();
    let before = (support::counts(&f), support::bytes(&f));
    with_api(&mut f, |api, credential| {
        assert_eq!(
            api.submit_accept(Some(credential), &scope(), &op)
                .unwrap_err()
                .code(),
            "revoked-credential"
        );
    });
    assert_eq!((support::counts(&f), support::bytes(&f)), before);
    assert!(support::events(&f).is_empty());
}
