use crate::{binding, domain, fixture::*, storage::sqlite::MutationOutcome};

#[test]
fn base_outbox_business_duplicates_are_not_checked_acceptance() {
    let f = Fixture::new();
    let store = f.registry.store();
    let prepare = || {
        store
            .prepare_insert(
                &operation("base-accept-intent"),
                &domain::ids::InstalledId::parse("ahu-1").unwrap(),
                &domain::ids::InstalledId::parse("sensor-sat-1").unwrap(),
                &domain::values::Value::Text("expected=0".into()),
                &domain::values::Unit::parse("count").unwrap(),
                binding::synthetic_times(),
                &binding::synthetic_record(1),
            )
            .unwrap()
    };
    let first = prepare();
    let second = prepare();
    assert!(matches!(
        store.submit(&first),
        MutationOutcome::Committed { .. }
    ));
    assert!(matches!(
        store.submit(&second),
        MutationOutcome::Committed { .. }
    ));
    let rows = store
        .exec_script("SELECT COUNT(*) FROM outbox WHERE operation='base-accept-intent';")
        .unwrap();
    assert_eq!(rows, vec![vec!["2"]]);
    assert_eq!(
        store
            .exec_script("SELECT COUNT(*) FROM outbox WHERE operation='accept-revision-v1';")
            .unwrap(),
        vec![vec!["0"]]
    );
    println!("BASE two different storage attempts at expected=0 produce 2 business rows; no checked accepted revision/event exists");
}

#[test]
fn base_sealing_does_not_accept_or_activate() {
    let mut f = Fixture::new();
    let sealed = f.seal("base-only-sealed", &f.draft()).unwrap();
    assert_eq!(f.seal_rows().len(), 1);
    assert_eq!(
        f.seals.capture_simulation(&sealed.identity).unwrap(),
        sealed.manifest
    );
    assert_eq!(
        f.registry
            .store()
            .exec_script("SELECT COUNT(*) FROM outbox WHERE operation='accept-revision-v1';")
            .unwrap(),
        vec![vec!["0"]]
    );
    println!("BASE seal rows=1 accepted events=0; availability does not establish acceptance or qualification");
}
