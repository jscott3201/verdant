use crate::{accept, access, api, binding, domain, fixture::*, support};
use api::{Api, Availability, Diagnostic, PageRequest, Readiness};

pub fn reference(f: &Fixture) -> api::Reference {
    let rows = f
        .registry
        .store()
        .exec_script("SELECT seq FROM outbox WHERE operation='binding-finding' ORDER BY id;")
        .unwrap();
    api::Reference::new(
        operation(binding::OP_FINDING_TEXT),
        rows[0][0].parse().unwrap(),
    )
    .unwrap()
}
pub fn content(f: &mut Fixture, label: &str) -> api::DraftContent {
    let findings = vec![reference(f)];
    api::DraftContent::new(support::config(f, label), findings).unwrap()
}
pub fn publication(f: &Fixture) -> api::Publication {
    api::Publication {
        binary: "synthetic-pr09-api".into(),
        host: "macos-arm64-debug".into(),
        native: vec![f.reference.clone()],
    }
}
pub fn all() -> PageRequest {
    PageRequest::new(0, 64).unwrap()
}
pub fn with_api<T>(f: &mut Fixture, run: impl FnOnce(&mut Api<'_>, &access::Credential) -> T) -> T {
    let mut api = Api::new(&f.gate, &mut f.registry, &f.seals).unwrap();
    run(&mut api, &f.credentials.publisher)
}

#[test]
fn fixed_authentication_and_scope_refusals_preserve_rows_events_and_bytes() {
    let mut f = Fixture::new();
    let input = content(&mut f, "SAT");
    let publication = publication(&f);
    let before = support::counts(&f);
    let bytes = support::bytes(&f);
    with_api(&mut f, |api, credential| {
        let op = operation("api-no-auth");
        let refusal = |result: api::Result<()>| {
            let error = result.unwrap_err();
            assert_eq!(error.code(), "anonymous-denied");
        };
        refusal(api.draft(None, &op, &input).map(|_| ()));
        refusal(api.edit(None, &op, &op, &input).map(|_| ()));
        refusal(api.validate(None, &scope(), &op, all()).map(|_| ()));
        refusal(api.seal(None, &scope(), &op, &op, &publication).map(|_| ()));
        refusal(
            api.accept(None, &scope(), &op, &op, accept::AcceptedRevision::INITIAL)
                .map(|_| ()),
        );
        refusal(api.status(None, &scope()).map(|_| ()));
        refusal(api.read(None, &scope(), &op).map(|_| ()));
        let foreign = domain::scope::TrustedScope::parse("scope-b").unwrap();
        assert_eq!(
            api.status(Some(credential), &foreign).unwrap_err().code(),
            "scope-denied"
        );
        assert_eq!(
            api.seal(Some(credential), &foreign, &op, &op, &publication)
                .unwrap_err()
                .code(),
            "scope-denied"
        );
        let forged = access::Credential::new(
            credential.capability().clone(),
            credential.key_id().clone(),
            access::SyntheticKey::parse("synthetic-forged").unwrap(),
        );
        assert_eq!(
            api.draft(Some(&forged), &op, &input).unwrap_err().code(),
            "forged-credential"
        );
    });
    assert_eq!(support::counts(&f), before);
    assert_eq!(support::events(&f), Vec::<Vec<String>>::new());
    assert_eq!(support::bytes(&f), bytes);
    println!("FIXED: seven unauthenticated operations, forged credential and cross-scope calls refused; rows/events/main+WAL+SHM unchanged");
}

#[test]
fn fixed_draft_edit_fingerprints_retry_and_sealed_freeze() {
    let mut f = Fixture::new();
    let original = content(&mut f, "SAT");
    let cosmetic = content(&mut f, "Supply air | l'état °C");
    let publication = publication(&f);
    let draft_op = operation("api-draft");
    let edit_op = operation("api-edit");
    let seal_op = operation("api-seal");
    let first = with_api(&mut f, |api, credential| {
        api.draft(Some(credential), &draft_op, &original).unwrap()
    });
    let counts = support::counts(&f);
    let bytes = support::bytes(&f);
    with_api(&mut f, |api, credential| {
        let retry = api.draft(Some(credential), &draft_op, &original).unwrap();
        assert_eq!(retry.staged_operation(), first.staged_operation());
        assert_eq!(retry.author, first.author);
        assert_eq!(
            api.draft(Some(credential), &draft_op, &cosmetic)
                .unwrap_err()
                .code(),
            "api-conflict"
        );
    });
    assert_eq!(support::counts(&f), counts);
    assert_eq!(support::bytes(&f), bytes);
    let (edited, impact) = with_api(&mut f, |api, credential| {
        api.edit(Some(credential), &edit_op, &draft_op, &cosmetic)
            .unwrap()
    });
    assert_eq!(
        impact.cosmetic.iter().cloned().collect::<Vec<_>>(),
        ["sat-binding"]
    );
    assert!(impact.invalidated.is_empty());
    let owner = support::store(&f);
    let old_config = owner.read_staged(first.staged_operation()).unwrap();
    let new_config = owner.read_staged(edited.staged_operation()).unwrap();
    assert_eq!(
        new_config.config().entries()["sat-binding"]
            .fingerprint(f.seals.hash_tool())
            .unwrap(),
        old_config.config().entries()["sat-binding"]
            .fingerprint(f.seals.hash_tool())
            .unwrap()
    );
    drop(owner);
    let commit = with_api(&mut f, |api, credential| {
        api.seal(Some(credential), &scope(), &seal_op, &edit_op, &publication)
            .unwrap()
    });
    let counts = support::counts(&f);
    let rows = f.seal_rows();
    let bytes = support::bytes(&f);
    with_api(&mut f, |api, credential| {
        assert_eq!(
            api.seal(Some(credential), &scope(), &seal_op, &edit_op, &publication)
                .unwrap()
                .row_id,
            commit.row_id
        );
        assert_eq!(
            api.edit(
                Some(credential),
                &operation("api-frozen-edit"),
                &edit_op,
                &original
            )
            .unwrap_err()
            .code(),
            "api-sealed-mutation"
        );
    });
    assert_eq!(f.seal_rows(), rows);
    assert_eq!(support::counts(&f), counts);
    assert_eq!(support::bytes(&f), bytes);
    println!("FIXED: draft retry same row/bytes/authorship, cosmetic fingerprint preserved, sealed edit denied, seal retry same row");
}

#[test]
fn fixed_missing_content_unqualified_entries_and_named_prerequisite_chain() {
    let mut f = Fixture::new();
    let config = support::config(&mut f, "SAT");
    // Valid binding but no supplied finding: report the actual missing reference,
    // the resolvable approval gap, and the independent qualification gap.
    let input = api::DraftContent::new(
        config.clone(),
        vec![api::Reference::new(operation("absent-content"), 1).unwrap()],
    )
    .unwrap();
    let before = operation("api-incomplete");
    with_api(&mut f, |api, credential| {
        api.draft(Some(credential), &before, &input).unwrap();
        let report = api
            .validate(Some(credential), &scope(), &before, all())
            .unwrap();
        assert_eq!(
            report.items,
            vec![
                Diagnostic::MissingContent {
                    reference: "content:absent-content:1".into()
                },
                Diagnostic::MissingFinding {
                    prerequisite: "finding:sat-binding".into()
                },
                Diagnostic::Unqualified {
                    key: "sat-binding".into(),
                    status: "valid".into()
                },
            ]
        );
    });
    let finding = with_api(&mut f, |api, credential| {
        api.record_finding(
            Some(credential),
            &scope(),
            &operation("api-find-sat"),
            &before,
            "sat-binding",
        )
        .unwrap()
    });
    let counts = support::counts(&f);
    with_api(&mut f, |api, credential| {
        assert_eq!(
            api.record_finding(
                Some(credential),
                &scope(),
                &operation("api-find-sat"),
                &before,
                "sat-binding"
            )
            .unwrap(),
            finding
        )
    });
    assert_eq!(support::counts(&f), counts);
    let domain = config.entries().values().cloned().collect();
    let resolved = with_api(&mut f, |api, credential| {
        api.resolve(Some(credential), &scope(), domain, vec![], vec![finding])
            .unwrap()
    });
    let revised = operation("api-resolved");
    with_api(&mut f, |api, credential| {
        api.edit(Some(credential), &revised, &before, &resolved)
            .unwrap();
        assert_eq!(
            api.validate(Some(credential), &scope(), &revised, all())
                .unwrap()
                .items,
            vec![Diagnostic::Unqualified {
                key: "sat-binding".into(),
                status: "valid".into()
            }]
        );
    });
    let publication = publication(&f);
    with_api(&mut f, |api, credential| {
        api.seal(
            Some(credential),
            &scope(),
            &operation("api-chain-seal"),
            &revised,
            &publication,
        )
        .unwrap();
        let accepted = api
            .accept(
                Some(credential),
                &scope(),
                &operation("api-chain-accept"),
                &operation("api-chain-seal"),
                accept::AcceptedRevision::INITIAL,
            )
            .unwrap();
        assert_eq!(accepted.revision.get(), 1);
        let status = api.status(Some(credential), &scope()).unwrap();
        assert_eq!(status.accepted_content, Availability::Available);
        assert_eq!(status.operational, Readiness::Unknown);
        assert_eq!(status.qualification, Readiness::Unsupported);
        assert_eq!(status.field_authority, Readiness::Unsupported);
        assert!(status.active.is_none());
    });
    assert_eq!(support::events(&f).len(), 1);
    println!("FIXED: missing content + missing finding + unqualified field explicitly reported; finding -> resolve/edit -> seal -> accept without raw DB edits");
}
