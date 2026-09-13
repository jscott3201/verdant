//! Observed process exit after accepted COMMIT, not a timeout or power-loss claim.
use crate::helpers::*;

#[test]
fn accepted_commit_process_exit_child() {
    if std::env::var_os("VERDANT_PR08B_EXIT_CHILD").is_none() {
        return;
    }
    let mut f = Fixture::new();
    let (store, accepted) = accepted(&mut f, "process-exit", Revision::INITIAL);
    assert_eq!(accepted.revision.get(), 1);
    assert!(store.active(&scope()).unwrap().is_none());
    assert!(active_events(&f).is_empty());
    println!("PR08B_COMMITTED_ROOT={}", f.scratch.0.display());
    // No destructor/activation runs. The parent owns cleanup after observing exit.
    std::process::exit(42);
}

#[test]
fn process_exit_after_acceptance_recovers_exact_active_revision_once() {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "restart::accepted_commit_process_exit_child", "--nocapture"])
        .env("VERDANT_PR08B_EXIT_CHILD", "1")
        .output()
        .unwrap();
    assert_eq!(child.status.code(), Some(42), "{child:?}");
    let output = String::from_utf8(child.stdout).unwrap();
    let path = output.lines().find_map(|line| line.strip_prefix("PR08B_COMMITTED_ROOT="))
        .expect("committed root marker");
    let scratch = Scratch(std::path::PathBuf::from(path));
    let (db, _) = crate::storage::sqlite::SqliteStore::open(
        &scratch.db(), crate::storage::ConnectionSettings::local_wal_full(),
        crate::storage::StoreBounds::tiny(),
    ).unwrap();
    let store = accept::AcceptanceStore::new(db.try_clone().unwrap());
    let accepted = store.current(&scope()).unwrap().unwrap();
    assert_eq!(accepted.request.operation().as_str(), "accept-process-exit");
    assert!(store.active(&scope()).unwrap().is_none());
    let (native, _) = crate::native::NativeHandle::open(
        &scratch.native(), crate::native::NativeSettings::local(),
    ).unwrap();
    let seals = crate::seal::SealStore::open(db.try_clone().unwrap(), native).unwrap();
    let request = request("activate-after-process-exit", Generation::INITIAL, &accepted);
    let count = || db.exec_script("SELECT (SELECT COUNT(*) FROM outbox WHERE operation='accept-revision-v1'),(SELECT COUNT(*) FROM outbox WHERE operation='accept-active-v1'),(SELECT COUNT(*) FROM storage_receipts);").unwrap();
    let before = count();
    assert_eq!(&before[0][..2], ["1", "0"]);
    let active = store.activate(&request, &seals).unwrap();
    assert_eq!(active.revision(), accepted.revision);
    assert_eq!(active.request().acceptance().seal(), accepted.request.seal());
    let after = count();
    assert_eq!(&after[0][..2], ["1", "1"]);
    assert_eq!(after[0][2].parse::<u64>().unwrap(), before[0][2].parse::<u64>().unwrap() + 1);
    let bytes = || ["meaning.db", "meaning.db-wal", "meaning.db-shm"].map(|name| {
        match std::fs::read(scratch.0.join(name)) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("snapshot: {error}"),
        }
    });
    let committed_bytes = bytes();
    assert_eq!(store.activate(&request, &seals).unwrap().row_id(), active.row_id());
    assert_eq!(store.reconcile_activation(&request).unwrap().unwrap().row_id(), active.row_id());
    assert_eq!(after, count());
    assert_eq!(committed_bytes, bytes());
    drop(seals);
    drop(store);
    drop(db);
    println!("FIXED observed child exit=42 after accepted COMMIT; native/SQLite reopen -> exact active revision=1; accepted=1 active=1 receipt_delta=1; retry byte-identical; no power-loss claim");
}
