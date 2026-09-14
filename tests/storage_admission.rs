//! R03 fixed counterexamples and receipt/upgrade evidence. Synthetic temp
//! stores only; process/response fault injection is NOT power-loss evidence.
#[allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;
#[allow(dead_code)]
#[path = "../src/storage/mod.rs"]
mod storage;

use domain::clock::{TimeTriple, UnixMillis};
use domain::ids::{InstalledId, OperationId, SourceGenerationId};
use domain::outcomes::RecordIdentity;
use domain::values::{Unit, Value};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use storage::sqlite::faults::{self, Fault};
use storage::sqlite::{MutationOutcome, PreparedMutation, SqliteStore};
use storage::{ConnectionSettings, StorageError, StoreBounds};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("verdant-r03-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&path).expect("isolated scratch");
        Self(path)
    }
    fn db(&self) -> PathBuf { self.0.join("store.db") }
    fn open(&self) -> SqliteStore { open(&self.db()).expect("open").0 }
}
impl Drop for Scratch { fn drop(&mut self) { std::fs::remove_dir_all(&self.0).expect("cleanup scratch"); } }
fn open(path: &Path) -> Result<(SqliteStore, storage::sqlite::OpenReport), StorageError> {
    SqliteStore::open(path, ConnectionSettings::local_wal_full(), StoreBounds::tiny())
}
fn raw(path: &Path, sql: &str) -> String {
    // 3.50.x has no -noinit; these stdin fixtures use HOME without ~/.sqliterc.
    let mut child = Command::new("sqlite3").args(["-batch", "-bail"]).arg(path)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("sqlite");
    child.stdin.take().expect("stdin").write_all(sql.as_bytes()).expect("SQL");
    let out = child.wait_with_output().expect("exit");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("UTF8").trim().to_owned()
}
fn pending(store: &SqliteStore, seq: u64) -> PreparedMutation {
    store.prepare_insert(
        &OperationId::parse("same-business-operation").expect("operation"),
        &InstalledId::parse("ahu-1").expect("entity"),
        &InstalledId::parse("sensor-sat-1").expect("sensor"),
        &Value::Missing, &Unit::parse("degC").expect("unit"),
        TimeTriple::new(UnixMillis::new(1), UnixMillis::new(2), UnixMillis::new(3)).expect("time"),
        &RecordIdentity::new(SourceGenerationId::parse("gen-1").expect("gen"), seq),
    ).expect("prepare")
}
fn committed(outcome: MutationOutcome) -> Vec<Vec<String>> {
    match outcome { MutationOutcome::Committed { rows, .. } => rows, other => panic!("not committed: {other:?}") }
}
fn counts(path: &Path) -> String {
    raw(path, "SELECT (SELECT count(*) FROM outbox), (SELECT count(*) FROM derived_marks), (SELECT count(*) FROM storage_receipts);")
}

#[test]
fn fixed_generation_before_mutation_preserves_rows_receipts_and_bytes() {
    let scratch = Scratch::new();
    let store = scratch.open();
    committed(store.submit(&pending(&store, 1)));
    let request = pending(&store, 2);
    raw(&scratch.db(), "PRAGMA user_version=9;");
    let bytes = std::fs::read(scratch.db()).expect("bytes");
    assert!(matches!(store.submit(&request), MutationOutcome::NotCommitted { error: StorageError::SchemaMismatch { .. }, .. }));
    assert_eq!(counts(&scratch.db()), "1|1|1");
    assert_eq!(std::fs::read(scratch.db()).expect("bytes"), bytes);
}

#[test]
fn fixed_generation_between_file_check_and_mutation_is_rechecked_in_owner() {
    let scratch = Scratch::new();
    let store = scratch.open();
    let request = pending(&store, 1);
    let db = scratch.db();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let after = Arc::clone(&observed);
    faults::on_admission(move || {
        raw(&db, "PRAGMA user_version=9;");
        *after.lock().expect("lock") = std::fs::read(db).expect("bytes");
    });
    assert!(matches!(store.submit(&request), MutationOutcome::NotCommitted { error: StorageError::SchemaMismatch { .. }, .. }));
    assert_eq!(counts(&scratch.db()), "0|0|0");
    assert_eq!(std::fs::read(scratch.db()).expect("bytes"), *observed.lock().expect("bytes"));
}

#[test]
fn fixed_foreign_zero_and_empty_existing_files_are_not_adopted() {
    for sql in ["CREATE TABLE foreign_data(value); INSERT INTO foreign_data VALUES ('untouched');", ""] {
        let scratch = Scratch::new();
        std::fs::write(scratch.db(), []).expect("existing file");
        if !sql.is_empty() { raw(&scratch.db(), sql); }
        let bytes = std::fs::read(scratch.db()).expect("before");
        assert_eq!(open(&scratch.db()).unwrap_err().code(), "schema-generation-mismatch");
        assert_eq!(std::fs::read(scratch.db()).expect("after"), bytes);
        assert_eq!(std::fs::read_dir(&scratch.0).expect("dir").count(), 1);
    }
}

#[test]
fn fixed_missing_table_is_refused_without_silent_repair() {
    let scratch = Scratch::new();
    let store = scratch.open();
    committed(store.submit(&pending(&store, 1)));
    raw(&scratch.db(), "DROP TABLE derived_marks;");
    let bytes = std::fs::read(scratch.db()).expect("before");
    assert_eq!(open(&scratch.db()).unwrap_err().code(), "sqlite-failure");
    assert!(matches!(store.submit(&pending(&store, 2)), MutationOutcome::NotCommitted { .. }));
    assert_eq!(raw(&scratch.db(), "SELECT count(*) FROM outbox; SELECT count(*) FROM storage_receipts; SELECT count(*) FROM sqlite_schema WHERE name='derived_marks';"), "1\n1\n0");
    assert_eq!(std::fs::read(scratch.db()).expect("after"), bytes);
}

#[test]
fn fixed_interrupted_bootstrap_and_durability_refusal_publish_nothing() {
    let scratch = Scratch::new();
    faults::inject(&scratch.db(), Fault::BeforePublish);
    assert!(open(&scratch.db()).is_err());
    assert!(!scratch.db().exists());
    assert_eq!(std::fs::read_dir(&scratch.0).expect("cleaned private files").count(), 0);
    let mut settings = ConnectionSettings::local_wal_full();
    settings.synchronous_level = "1";
    assert_eq!(SqliteStore::open(&scratch.db(), settings, StoreBounds::tiny()).unwrap_err().code(), "durability-unavailable");
    assert!(!scratch.db().exists());
    assert_eq!(std::fs::read_dir(&scratch.0).expect("dir").count(), 0);
    let (_, report) = open(&scratch.db()).expect("later fresh install");
    assert!(report.fresh);
}

#[test]
fn fixed_two_initializers_publish_one_complete_store() {
    let scratch = Scratch::new();
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let launch = || { barrier.wait(); open(&scratch.db()).expect("initializer") };
        let left = scope.spawn(launch);
        let right = scope.spawn(launch);
        let (left, a) = left.join().expect("left");
        let (right, b) = right.join().expect("right");
        assert_ne!(a.fresh, b.fresh, "exactly one publication winner");
        committed(left.submit(&pending(&left, 1)));
        committed(right.submit(&pending(&right, 2)));
    });
    assert_eq!(counts(&scratch.db()), "2|1|2");
    assert_eq!(raw(&scratch.db(), "SELECT group_concat(generation) FROM schema_migrations; SELECT count(*) FROM storage_identity;"), "1,2,3\n1");
    let mut names = std::fs::read_dir(&scratch.0).expect("no private leftovers")
        .map(|entry| {
            let entry = entry.expect("directory entry");
            assert!(entry.file_type().expect("file type").is_file(), "unexpected artifact: {entry:?}");
            entry.file_name().into_string().expect("fixture filename")
        }).collect::<Vec<_>>();
    names.sort();
    println!("initializer artifacts: {names:?}");
    assert_eq!(names.iter().filter(|name| name.ends_with(".db")).count(), 1, "{names:?}");
    assert!(names.iter().any(|name| name == "store.db"), "{names:?}");
    // WAL connections may leave their shared-memory and journal sidecars after
    // exit. Only these exact companions belong to the single published store;
    // bootstrap files, additional databases and all other artifacts are leaks.
    assert!(names.iter().all(|name| matches!(name.as_str(), "store.db" | "store.db-shm" | "store.db-wal")), "unexpected artifacts: {names:?}");
}

#[test]
fn fixed_winner_loser_claim_receipts_do_not_steal_or_reclaim() {
    let scratch = Scratch::new();
    let store = scratch.open();
    committed(store.submit(&pending(&store, 1)));
    let a = store.prepare_claim(1, "winner").expect("claim");
    let b = store.prepare_claim(1, "loser").expect("claim");
    let first = committed(store.submit(&a));
    assert_eq!(first.len(), 1);
    assert!(committed(store.submit(&b)).is_empty());
    assert_eq!(store.acknowledge(1, "loser").unwrap_err().code(), "conflict");
    store.acknowledge(1, "winner").expect("ack");
    assert_eq!(committed(store.submit(&a)), first, "receipt replays original snapshot");
    assert!(committed(store.submit(&b)).is_empty());
    assert_eq!(raw(&scratch.db(), "SELECT status,claimed_by FROM outbox;"), "acked|winner");
    assert_eq!(counts(&scratch.db()), "1|1|5");
}

#[test]
fn fixed_lost_response_and_malformed_response_reconcile_same_identity() {
    for fault in [Fault::LostResponse, Fault::MalformedResponse] {
        let scratch = Scratch::new();
        let store = scratch.open();
        let request = pending(&store, 1);
        faults::inject(&scratch.db(), fault);
        assert!(matches!(store.submit(&request), MutationOutcome::Unknown { .. }));
        assert_eq!(counts(&scratch.db()), "1|1|1");
        let bytes = std::fs::read(scratch.db()).expect("committed bytes");
        let result = committed(store.reconcile(&request));
        assert_eq!(committed(store.submit(&request)), result);
        drop(store);
        let store = scratch.open();
        let reconstructed = pending(&store, 1).with_operation(request.operation().clone());
        assert_eq!(committed(store.submit(&reconstructed)), result);
        assert_eq!(committed(store.reconcile_operation(request.operation())), result);
        assert_eq!(std::fs::read(scratch.db()).expect("no second mutation"), bytes);
        let different = pending(&store, 2).with_operation(request.operation().clone());
        assert!(matches!(store.submit(&different), MutationOutcome::Conflict { .. }));
        assert_eq!(counts(&scratch.db()), "1|1|1");
        raw(&scratch.db(), "PRAGMA user_version=9;");
        assert!(matches!(store.submit(&request), MutationOutcome::Unknown { .. }), "refused retry cannot negate a prior possible commit");
        assert!(matches!(store.reconcile(&request), MutationOutcome::Unknown { .. }));
    }
}

#[test]
fn fixed_partial_retry_is_atomic_and_does_not_replay_prior_work() {
    let scratch = Scratch::new();
    let store = scratch.open();
    let first = pending(&store, 1);
    let second = pending(&store, 2);
    committed(store.submit(&first));
    let bytes = std::fs::read(scratch.db()).expect("before failed second");
    faults::inject(&scratch.db(), Fault::BeforeCommit);
    assert!(matches!(store.submit(&second), MutationOutcome::NotCommitted { .. }));
    assert_eq!(counts(&scratch.db()), "1|1|1");
    assert_eq!(std::fs::read(scratch.db()).expect("no partial commit"), bytes);
    assert!(matches!(store.reconcile(&second), MutationOutcome::NotCommitted { .. }));
    committed(store.submit(&first));
    committed(store.submit(&second));
    assert_eq!(counts(&scratch.db()), "2|1|2");
    assert_eq!(raw(&scratch.db(), "SELECT group_concat(seq) FROM outbox;"), "1,2");
}

#[test]
fn migration_0001_upgrade_backfills_duplicates_without_touching_history() {
    let scratch = Scratch::new();
    raw(&scratch.db(), &format!("PRAGMA journal_mode=WAL; BEGIN; {}\nPRAGMA user_version=1; INSERT INTO schema_migrations VALUES (1,'M01-PR03 0001_init: initial tiny outbox'); INSERT INTO outbox(operation,entity,sensor,value_json,unit,source_ms,receipt_ms,ingestion_ms,generation,seq,status,claimed_by) VALUES ('op-1','ahu-1','sensor-sat-1','{{\"type\":\"missing\"}}','degC','1','2','3','gen-1','1','claimed','dangling'); INSERT INTO outbox(operation,entity,sensor,value_json,unit,source_ms,receipt_ms,ingestion_ms,generation,seq,status,claimed_by) SELECT operation,entity,sensor,value_json,unit,source_ms,receipt_ms,ingestion_ms,generation,seq,status,claimed_by FROM outbox; INSERT INTO derived_marks VALUES ('ahu-1',1,0); COMMIT;", storage::MIGRATION_0001_SQL));
    let before = raw(&scratch.db(), "SELECT * FROM outbox; SELECT * FROM derived_marks;");
    let (store, report) = open(&scratch.db()).expect("supported upgrade");
    assert!(!report.fresh);
    assert_eq!(store.schema_generation(), 1, "row contract unchanged");
    assert_eq!(report.store.dangling.len(), 2);
    assert_eq!(raw(&scratch.db(), "SELECT * FROM outbox; SELECT * FROM derived_marks;"), before);
    assert_eq!(raw(&scratch.db(), "SELECT operation,request,response FROM storage_receipts ORDER BY operation;"), "legacy:1|legacy-outbox-row-only|1\nlegacy:2|legacy-outbox-row-only|2");
    assert_eq!(counts(&scratch.db()), "2|1|2");
}

#[test]
fn downgrade_unknown_ledger_and_replaced_identity_are_refused() {
    for sql in ["DELETE FROM schema_migrations WHERE generation=2;", "INSERT INTO schema_migrations VALUES(4,'unknown');", "PRAGMA application_id=0;", "UPDATE storage_identity SET identity='bad';"] {
        let scratch = Scratch::new();
        let store = scratch.open();
        raw(&scratch.db(), sql);
        let bytes = std::fs::read(scratch.db()).expect("before");
        assert!(open(&scratch.db()).is_err());
        assert!(matches!(store.submit(&pending(&store, 1)), MutationOutcome::NotCommitted { .. }));
        assert_eq!(std::fs::read(scratch.db()).expect("after"), bytes);
    }
    let scratch = Scratch::new();
    let store = scratch.open();
    let other = Scratch::new();
    drop(other.open());
    std::fs::rename(other.db(), scratch.db()).expect("replace inode");
    let bytes = std::fs::read(scratch.db()).expect("replacement");
    assert!(matches!(store.submit(&pending(&store, 1)), MutationOutcome::NotCommitted { .. }));
    assert_eq!(std::fs::read(scratch.db()).expect("untouched replacement"), bytes);
}
