use crate::{accept, fixture::*, seal, storage};

pub fn store(f: &Fixture) -> accept::AcceptanceStore {
    accept::AcceptanceStore::new(f.registry.store().try_clone().unwrap())
}
pub fn config(f: &mut Fixture, label: &str) -> accept::EffectiveConfig {
    let entry = accept::Entry::new(
        crate::domain::ids::InstalledId::parse("sat-binding").unwrap(),
        label,
        f.registry.bindings()[0].clone(),
    )
    .unwrap();
    accept::EffectiveConfig::resolve(&f.gate, &mut f.registry, scope(), vec![entry], vec![])
        .unwrap()
}
pub fn publish(
    f: &mut Fixture,
    tag: &str,
    label: &str,
) -> (accept::AcceptanceStore, accept::Sealed) {
    let store = store(f);
    let config = config(f, label);
    let staged = store
        .stage(
            &operation(&format!("accept-stage-{tag}")),
            config,
            vec![f.finding.clone()],
        )
        .unwrap();
    let draft = f.draft_with(vec![staged.root().unwrap()], "synthetic-pr08a-binary");
    let commit = f.seal(&format!("seal-{tag}"), &draft).unwrap();
    let sealed = store.sealed(&staged, &commit.identity, &f.seals).unwrap();
    (store, sealed)
}
pub fn prepare(
    f: &mut Fixture,
    store: &accept::AcceptanceStore,
    sealed: &accept::Sealed,
    op: &str,
    revision: accept::AcceptedRevision,
) -> accept::PendingAcceptance {
    store
        .prepare(
            operation(op),
            revision,
            sealed,
            &f.seals,
            &mut f.registry,
            &f.gate,
            &f.credentials.publisher,
        )
        .unwrap()
}
pub fn events(f: &Fixture) -> Vec<Vec<String>> {
    f.registry.store().exec_script("SELECT id,seq,value_json FROM outbox WHERE operation='accept-revision-v1' ORDER BY id;").unwrap()
}
pub fn counts(f: &Fixture) -> Vec<Vec<String>> {
    f.registry.store().exec_script("SELECT (SELECT COUNT(*) FROM outbox),(SELECT COUNT(*) FROM storage_receipts),(SELECT COUNT(*) FROM derived_marks);").unwrap()
}
/// Main DB plus optional WAL/SHM, not just logical query results. No checkpoint
/// or normalizing write between the two snapshots used by refusal assertions.
pub fn bytes(f: &Fixture) -> Vec<(String, Option<Vec<u8>>)> {
    ["meaning.db", "meaning.db-wal", "meaning.db-shm"]
        .into_iter()
        .map(|name| {
            let path = f.scratch.0.join(name);
            (
                name.into(),
                match std::fs::read(path) {
                    Ok(bytes) => Some(bytes),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => panic!("snapshot: {e}"),
                },
            )
        })
        .collect()
}
pub fn reopen(f: &Fixture) -> accept::AcceptanceStore {
    let (db, _) = storage::sqlite::SqliteStore::open(
        &f.scratch.db(),
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
    )
    .unwrap();
    accept::AcceptanceStore::new(db)
}
pub fn availability_store(
    db: &std::path::Path,
    native: crate::native::NativeHandle,
) -> seal::SealStore {
    let (store, _) = storage::sqlite::SqliteStore::open(
        db,
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
    )
    .unwrap();
    seal::SealStore::open(store, native).unwrap()
}
