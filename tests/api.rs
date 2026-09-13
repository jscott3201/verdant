//! PR09A isolated synthetic API evidence. No program-repository stores.
#![allow(dead_code)]
#[path = "../src/accept/mod.rs"]
mod accept;
#[path = "../src/access/mod.rs"]
mod access;
#[path = "../src/api/mod.rs"]
mod api;
#[path = "../src/binding/mod.rs"]
mod binding;
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "api_cases/failures.rs"]
mod failures;
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "api_cases/lifecycle.rs"]
mod lifecycle;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "api_cases/operations.rs"]
mod operations;
#[path = "api_cases/recovery.rs"]
mod recovery;
#[path = "../src/seal/mod.rs"]
mod seal;
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "../src/storage/mod.rs"]
mod storage;
#[path = "accept_cases/support.rs"]
mod support;

#[test]
fn base_owner_staging_is_unapproved_intent_not_an_authenticated_api() {
    let mut f = fixture::Fixture::new();
    let store = support::store(&f);
    let config = support::config(&mut f, "SAT");
    let before = support::counts(&f);
    // The existing stage/read APIs deliberately take no credential. PR09 must
    // authenticate the facade, not redefine these internal owner contracts.
    let staged = store
        .stage(
            &fixture::operation("accept-stage-base-api"),
            config,
            vec![f.finding.clone()],
        )
        .unwrap();
    assert_eq!(store.read_staged(staged.operation()).unwrap(), staged);
    assert_ne!(support::counts(&f), before);
    assert!(store.current(&fixture::scope()).unwrap().is_none());
    assert!(store.active(&fixture::scope()).unwrap().is_none());
    assert_eq!(
        staged.config().entries()["sat-binding"].binding().status(),
        binding::BindingStatus::Valid
    );
    println!("BASE: uncredentialed internal staging writes intent; accepted=none active=none; structural Valid is not observed qualification");
}
