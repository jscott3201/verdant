//! PR08B coordinator contracts; path includes remain necessary for this binary crate.
#![allow(dead_code)]
#[path = "../src/accept/mod.rs"]
mod accept;
#[path = "../src/access/mod.rs"]
mod access;
#[path = "../src/binding/mod.rs"]
mod binding;
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "../src/seal/mod.rs"]
mod seal;
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "../src/storage/mod.rs"]
mod storage;
#[path = "accept_cases/support.rs"]
mod support;
#[path = "activation_cases/helpers.rs"]
mod helpers;
#[path = "activation_cases/ordering.rs"]
mod ordering;
#[path = "activation_cases/recovery.rs"]
mod recovery;
#[path = "activation_cases/scopes.rs"]
mod scopes;
#[path = "activation_cases/restart.rs"]
mod restart;

#[test]
fn activation_after_accepted_commit() {
    let mut f = fixture::Fixture::new();
    let (store, sealed) = support::publish(&mut f, "activation", "AHU supply air");
    let pending = support::prepare(
        &mut f, &store, &sealed, "accept-activation", accept::AcceptedRevision::INITIAL,
    );
    let accepted = store.submit(&pending, &f.seals).unwrap();
    let before = (support::counts(&f), support::bytes(&f));
    // Simulate interruption after the accepted COMMIT, before any activation dispatch.
    drop(store);
    let reopened = support::reopen(&f);
    assert!(reopened.active(&fixture::scope()).unwrap().is_none());
    assert_eq!(before, (support::counts(&f), support::bytes(&f)));
    let request = accept::ActivationRequest::new(
        fixture::operation("activate-first"), accept::ActiveGeneration::INITIAL, accepted.request,
    );
    let active = reopened.activate(&request, &f.seals).unwrap();
    assert_eq!(active.stage(), accept::Stage::Activated);
    assert_eq!(active.revision().get(), 1);
    assert_eq!(active.generation().get(), 1);
    assert_eq!(active.request().acceptance().seal(), sealed.identity());
    let rows = helpers::active_events(&f);
    assert_eq!(rows.len(), 1);
    let raw = domain::values::Value::from_json(&rows[0][2]).unwrap();
    // Independent frozen framing, not the encoder under test.
    assert_eq!(raw, domain::values::Value::Text(format!(
        "17:verdant-active-v114:activate-first1:01:17:scope-a17:accept-activation1:01:123:accept-stage-activation64:{}9:activated",
        sealed.identity().as_str(),
    )));
    assert_eq!(reopened.status(&sealed).unwrap(), accept::Stage::Activated);
    let snapshot = (support::counts(&f), support::bytes(&f));
    let repeated = support::reopen(&f).activate(&request, &f.seals).unwrap();
    assert!(repeated.reconciled());
    assert_eq!(active.row_id(), repeated.row_id());
    assert_eq!(snapshot, (support::counts(&f), support::bytes(&f)));
    assert_eq!(snapshot.0[0][0].parse::<u64>().unwrap(), before.0[0][0].parse::<u64>().unwrap() + 1);
    assert_eq!(snapshot.0[0][1].parse::<u64>().unwrap(), before.0[0][1].parse::<u64>().unwrap() + 1);
    assert_eq!(snapshot.0[0][2], before.0[0][2]);
    println!("FIXED accepted commit -> interrupted -> reopen -> exact seal active revision=1 generation=1; event_delta=1 receipt_delta=1 mark_delta=0; retry rows/bytes identical");
}
