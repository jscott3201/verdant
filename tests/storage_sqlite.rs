//! M01-PR03 SQLite storage tests: tiny outbox operations + failure behavior.
//!
//! Every test runs against an isolated synthetic database in an OS temp dir
//! (unique per process/test/sequence per D09; removed on drop; never a repo
//! path, never production/field/paid anything). One supported target only
//! (macOS 27 arm64, rustc 1.97.1, system sqlite3 3.54.0): other targets,
//! power loss, real disk-full, Selene, and PostgreSQL are untested limits.
//!
//! Crash labeling: the kill test below is PROCESS-CRASH evidence (SIGKILL of
//! the `sqlite3` client; OS caches intact; journal recovery rolls back the
//! uncommitted tail), never a power-loss proof.

#[path = "../src/domain/mod.rs"]
mod domain;

#[path = "../src/storage/mod.rs"]
mod storage;

use domain::clock::{TimeTriple, UnixMillis};
use domain::fixture::tiny_site;
use domain::ids::{InstalledId, OperationId, SourceGenerationId};
use domain::outcomes::RecordIdentity;
use domain::values::{Decimal, Unit, Value};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Barrier;
use std::time::Duration;
use storage::sqlite::SqliteStore;
use storage::{ConnectionSettings, Handoff, StoreBounds, SCHEMA_GENERATION};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Isolated scratch root for one test. Removed on drop.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(test: &str) -> Scratch {
        let id = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "verdant-pr03-{}-{}-{}",
            std::process::id(),
            test,
            id
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Scratch { dir }
    }

    fn db(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn open_tiny(scratch: &Scratch, name: &str) -> SqliteStore {
    SqliteStore::open(
        &scratch.db(name),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .unwrap_or_else(|e| panic!("open {}: {e} [{}]", scratch.db(name).display(), e.code()))
    .0
}

fn triple() -> TimeTriple {
    TimeTriple::new(
        UnixMillis::new(1_700_000_000_123),
        UnixMillis::new(1_700_000_000_456),
        UnixMillis::new(1_700_000_000_789),
    )
    .expect("valid triple")
}

fn record(seq: u64) -> RecordIdentity {
    RecordIdentity::new(SourceGenerationId::parse("gen-1").expect("gen"), seq)
}

fn token(test: &str, n: u64) -> String {
    format!(
        "claim-{}-{}-{}-{}",
        test,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst),
        n
    )
}

fn insert_fixture_row(store: &SqliteStore, op: &str, seq: u64) -> i64 {
    store
        .insert(
            &OperationId::parse(op).expect("op"),
            &InstalledId::parse("ahu-1").expect("entity"),
            &InstalledId::parse("sensor-sat-1").expect("sensor"),
            &Value::Decimal(Decimal::parse("21.50").expect("decimal")),
            &Unit::parse("degC").expect("unit"),
            triple(),
            &record(seq),
        )
        .expect("insert")
}

fn sqlite_raw(db: &Path, script: &str) -> (bool, String, String) {
    let output = Command::new("sqlite3")
        .arg(db)
        .arg(script)
        .stdin(Stdio::null())
        .output()
        .expect("spawn sqlite3");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// Migration reservation + change record.
// ---------------------------------------------------------------------------

#[test]
fn migration_reservation_0001_is_exclusive_and_matches_source() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations/sqlite");
    let mut numbered: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("migrations/sqlite exists") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".sql") {
            numbered.push(name);
        }
    }
    numbered.sort();
    // Reservation: exactly one numbered migration, prefix 0001, no others.
    assert_eq!(
        numbered,
        vec!["0001_init.sql".to_string()],
        "only 0001 exists"
    );
    assert_eq!(storage::MIGRATION_ID, "0001_init");
    let on_disk = std::fs::read_to_string(dir.join("0001_init.sql")).expect("read 0001_init.sql");
    assert_eq!(
        on_disk,
        storage::MIGRATION_0001_SQL,
        "embedded SQL and the file on disk must agree byte for byte"
    );
    for fragment in [
        "CREATE TABLE IF NOT EXISTS schema_migrations",
        "CREATE TABLE IF NOT EXISTS outbox",
        "CREATE TABLE IF NOT EXISTS derived_marks",
        "queued', 'claimed', 'acked",
    ] {
        assert!(on_disk.contains(fragment), "migration missing {fragment}");
    }
    // Compact change record (integration §2): predecessors none, owner PR03.
    let record = storage::MIGRATION_0001;
    assert_eq!(record.backend, "sqlite");
    assert_eq!(record.owner, "M01-PR03");
    assert_eq!(record.id, "0001_init");
    assert!(record.predecessors.is_empty(), "no predecessors for 0001");
    assert_eq!(SCHEMA_GENERATION, 1);
}

// ---------------------------------------------------------------------------
// Open: WAL + FULL-sync recorded per connection, driver pinned.
// ---------------------------------------------------------------------------

#[test]
fn open_records_wal_full_per_connection_and_pins_driver() {
    let scratch = Scratch::new("open");
    let (store, report) = SqliteStore::open(
        &scratch.db("tiny.db"),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("open");
    assert!(report.fresh, "first open is a fresh install");
    assert_eq!(store.schema_generation(), 1);
    assert!(
        report.store.sqlite_version.starts_with("3."),
        "{}",
        report.store.sqlite_version
    );
    assert_eq!(report.store.sqlite_version, store.sqlite_version());
    let settings = store.settings().to_string();
    assert!(settings.contains("journal_mode=wal"), "{settings}");
    assert!(settings.contains("FULL"), "{settings}");
    assert!(settings.contains("busy_timeout_ms=5000"), "{settings}");
    // The open-time report re-read the live connection (never inferred).
    assert_eq!(report.store.schema_generation, 1);
    assert_eq!(report.store.settings_recorded, settings);
    assert_eq!(report.store.sqlite_version, report.store.sqlite_version);
    assert_eq!(report.store.dangling.len(), 0);
    assert_eq!(report.store.queued, 0);
    drop(store);
    // Reopen: not fresh, same generation, same recorded settings.
    let (again, reopen) = SqliteStore::open(
        &scratch.db("tiny.db"),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("reopen");
    assert!(!reopen.fresh);
    assert_eq!(reopen.store.schema_generation, 1);
    assert_eq!(again.settings().to_string(), settings);
    println!(
        "open: sqlite='{}' settings='{}' db_bytes={} wal_bytes={}",
        reopen.store.sqlite_version,
        settings,
        again.db_size_bytes(),
        again.wal_size_bytes()
    );
}

// ---------------------------------------------------------------------------
// Insert / claim / acknowledge round-trip with typed domain payloads.
// ---------------------------------------------------------------------------

#[test]
fn insert_claim_acknowledge_round_trip() {
    let scratch = Scratch::new("round-trip");
    let store = open_tiny(&scratch, "tiny.db");
    assert_eq!(store.db_path(), scratch.db("tiny.db"));
    assert_eq!(
        store.bounds().max_replay_rows,
        StoreBounds::tiny().max_replay_rows
    );
    let id = insert_fixture_row(&store, "op-1", 41);
    assert_eq!(id, 1);

    let page = store.replay_queued(10).expect("replay");
    assert_eq!(page.requested, 10);
    assert_eq!(page.served, 1);
    assert!(!page.truncated);
    let row = &page.rows[0];
    assert_eq!(row.operation.as_str(), "op-1");
    assert_eq!(row.entity.as_str(), "ahu-1");
    assert_eq!(row.sensor.as_str(), "sensor-sat-1");
    assert_eq!(
        row.value,
        Value::Decimal(Decimal::parse("21.50").expect("decimal"))
    );
    assert_eq!(row.unit, Unit::parse("degC").expect("unit"));
    assert_eq!(row.times, triple());
    assert_eq!(row.record, record(41));
    assert_eq!(row.claimed_by, None);

    let tok = token("round-trip", 0);
    let claimed = store.claim_queued(10, &tok).expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].claimed_by.as_deref(), Some(tok.as_str()));
    assert_eq!(
        store.dirty_entities().expect("dirty"),
        vec!["ahu-1".to_string()]
    );

    store.acknowledge(id, &tok).expect("ack");
    let report = store.report().expect("report");
    assert_eq!((report.queued, report.claimed, report.acked), (0, 0, 1));
    assert!(store.replay_queued(10).expect("replay").rows.is_empty());
}

// ---------------------------------------------------------------------------
// Tiny-site breadth: every fixture reading persists exactly.
// ---------------------------------------------------------------------------

#[test]
fn tiny_site_readings_persist_exactly() {
    let scratch = Scratch::new("breadth");
    let store = open_tiny(&scratch, "tiny.db");
    let site = tiny_site();
    for (index, reading) in site.readings.iter().enumerate() {
        let op = format!("op-breadth-{}", index + 1);
        store
            .insert(
                &OperationId::parse(&op).expect("op"),
                &reading.entity,
                &reading.sensor,
                &reading.value,
                &reading.unit,
                reading.times,
                &RecordIdentity::new(
                    SourceGenerationId::parse("gen-1").expect("gen"),
                    index as u64,
                ),
            )
            .expect("insert reading");
    }
    let page = store.replay_queued(64).expect("replay");
    assert_eq!(page.served, site.readings.len() as u32);
    assert!(!page.truncated);
    for (row, reading) in page.rows.iter().zip(site.readings.iter()) {
        assert_eq!(row.entity, reading.entity);
        assert_eq!(row.sensor, reading.sensor);
        assert_eq!(row.value, reading.value);
        assert_eq!(row.unit, reading.unit);
        assert_eq!(row.times, reading.times);
    }
}

// ---------------------------------------------------------------------------
// Reopen preserves committed work (close + reopen).
// ---------------------------------------------------------------------------

#[test]
fn reopen_preserves_committed_work() {
    let scratch = Scratch::new("reopen");
    let db = scratch.db("tiny.db");
    {
        let store = open_tiny(&scratch, "tiny.db");
        insert_fixture_row(&store, "op-1", 1);
        insert_fixture_row(&store, "op-2", 2);
        let close = store.close().expect("close");
        assert_eq!(close.checkpoint.busy, 0);
        assert!(close.db_size_bytes > 0);
    }
    assert!(db.exists(), "db file survives close");
    let store = open_tiny(&scratch, "tiny.db");
    let page = store.replay_queued(10).expect("replay");
    assert_eq!(page.served, 2, "committed rows survive close + reopen");
    assert_eq!(page.rows[0].operation.as_str(), "op-1");
    assert_eq!(page.rows[1].operation.as_str(), "op-2");
    // Dirty derived marks survive restart too (checkpoint is not recalculation).
    assert_eq!(
        store.dirty_entities().expect("dirty"),
        vec!["ahu-1".to_string()]
    );
}

// ---------------------------------------------------------------------------
// Rollback: failed batches and explicit ROLLBACK leave nothing behind.
// ---------------------------------------------------------------------------

#[test]
fn failed_batch_and_explicit_rollback_leave_nothing() {
    let scratch = Scratch::new("rollback");
    let store = open_tiny(&scratch, "tiny.db");
    let bad = store.run_transaction(&[
        "INSERT INTO outbox(operation, entity, sensor, value_json, unit, source_ms, receipt_ms, ingestion_ms, generation, seq) VALUES('op-rollback','ahu-1','sensor-sat-1','{\"type\":\"missing\"}','degC','1','2','3','gen-1','9')",
        "THIS IS NOT SQL",
    ]);
    assert_eq!(bad.unwrap_err().code(), "sqlite-failure");
    assert_eq!(
        store.report().expect("report").queued,
        0,
        "failed batch committed nothing"
    );

    store
        .exec_script("BEGIN; INSERT INTO outbox(operation, entity, sensor, value_json, unit, source_ms, receipt_ms, ingestion_ms, generation, seq) VALUES('op-rolled-back','ahu-1','sensor-sat-1','{\"type\":\"missing\"}','degC','1','2','3','gen-1','10'); ROLLBACK;")
        .expect("explicit rollback script runs");
    assert_eq!(
        store.report().expect("report").queued,
        0,
        "explicit ROLLBACK leaves no row"
    );
}

// ---------------------------------------------------------------------------
// Process-crash (SIGKILL) mid-transaction: uncommitted work does not survive.
// Label: process-crash evidence, NOT power-loss proof.
// ---------------------------------------------------------------------------

#[test]
fn process_crash_mid_transaction_rolls_back_uncommitted() {
    let scratch = Scratch::new("crash");
    let db = scratch.db("tiny.db");
    {
        let store = open_tiny(&scratch, "tiny.db");
        insert_fixture_row(&store, "op-committed", 1);
    } // store dropped: no held locks for the victim process.

    let mut child = Command::new("sqlite3")
        .arg(&db)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sqlite3 victim");
    child
        .stdin
        .as_mut()
        .expect("victim stdin")
        .write_all(
            b"BEGIN; INSERT INTO outbox(operation, entity, sensor, value_json, unit, source_ms, receipt_ms, ingestion_ms, generation, seq) VALUES('op-uncommitted','ahu-1','sensor-sat-1','{\"type\":\"missing\"}','degC','1','2','3','gen-1','99');\n",
        )
        .expect("feed victim");
    child.stdin.as_mut().expect("flush").flush().expect("flush");
    std::thread::sleep(Duration::from_secs(1));
    child
        .kill()
        .expect("SIGKILL the victim (process crash, not power loss)");
    let status = child.wait().expect("observed victim exit");
    assert!(!status.success(), "killed victim must not exit 0");
    std::thread::sleep(Duration::from_millis(200)); // lock release, no inference.

    let store = open_tiny(&scratch, "tiny.db");
    let page = store.replay_queued(10).expect("replay after crash");
    assert_eq!(page.served, 1, "only the committed row survives the crash");
    assert_eq!(page.rows[0].operation.as_str(), "op-committed");
    println!(
        "process-crash (SIGKILL, not power loss): uncommitted row absent, committed row present"
    );
}

// ---------------------------------------------------------------------------
// Restart honors dangling claims: reported, never silently rolled back.
// ---------------------------------------------------------------------------

#[test]
fn dangling_claim_survives_reopen_without_silent_rollback() {
    let scratch = Scratch::new("dangling");
    let tok = token("dangling", 0);
    let id = {
        let store = open_tiny(&scratch, "tiny.db");
        let id = insert_fixture_row(&store, "op-1", 1);
        let claimed = store.claim_queued(10, &tok).expect("claim");
        assert_eq!(claimed.len(), 1);
        id
    }; // drop without acknowledge: the claim dangles.

    let store = open_tiny(&scratch, "tiny.db");
    let report = store.report().expect("restart report");
    assert_eq!((report.queued, report.claimed, report.acked), (0, 1, 0));
    assert_eq!(report.dangling.len(), 1);
    assert_eq!(report.dangling[0].id, id);
    assert_eq!(report.dangling[0].operation.as_str(), "op-1");
    assert_eq!(report.dangling[0].claimed_by, tok);
    // Not silently requeued: nothing is claimable under a fresh token.
    assert!(store
        .claim_queued(10, &token("dangling", 1))
        .expect("claim")
        .is_empty());

    // Wrong token cannot clear it either (conflict, not success).
    assert_eq!(
        store
            .requeue_claim(id, &token("dangling", 2))
            .unwrap_err()
            .code(),
        "conflict"
    );
    // Explicit operator requeue is the only path back.
    store.requeue_claim(id, &tok).expect("explicit requeue");
    let report = store.report().expect("report");
    assert_eq!((report.queued, report.claimed), (1, 0));
    assert!(report.dangling.is_empty());
}

// ---------------------------------------------------------------------------
// Claim race: exactly one winner; losers get conflicts, never silent success.
// ---------------------------------------------------------------------------

#[test]
fn claim_race_has_single_winner_and_conflicts() {
    let scratch = Scratch::new("race-claim");
    let store = open_tiny(&scratch, "tiny.db");
    let id = insert_fixture_row(&store, "op-1", 1);
    let left = store.try_clone().expect("clone");
    let right = store.try_clone().expect("clone");
    let gate = Barrier::new(3);
    let tok_left = token("race", 0);
    let tok_right = token("race", 1);
    std::thread::scope(|scope| {
        let (gate, tok_left, tok_right) = (&gate, &tok_left, &tok_right);
        let won_left = scope.spawn(move || {
            gate.wait();
            left.claim_queued(5, tok_left).expect("claim left").len()
        });
        let won_right = scope.spawn(move || {
            gate.wait();
            right.claim_queued(5, tok_right).expect("claim right").len()
        });
        gate.wait();
        let total = won_left.join().expect("left") + won_right.join().expect("right");
        assert_eq!(total, 1, "exactly one claimant wins the row");
    });
    let report = store.report().expect("report");
    assert_eq!(report.claimed, 1);
    let winner = report.dangling[0].claimed_by.clone();
    let loser = if winner == tok_left {
        tok_right.clone()
    } else {
        tok_left.clone()
    };
    // Loser cannot acknowledge (conflict); winner can; double ack conflicts.
    assert_eq!(
        store.acknowledge(id, &loser).unwrap_err().code(),
        "conflict"
    );
    store.acknowledge(id, &winner).expect("winner acks");
    assert_eq!(
        store.acknowledge(id, &winner).unwrap_err().code(),
        "conflict"
    );
}

// ---------------------------------------------------------------------------
// Concurrent writers: small duplicates tolerated + counted, never merged.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_writers_duplicates_tolerated_not_merged() {
    let scratch = Scratch::new("race-write");
    let store = open_tiny(&scratch, "tiny.db");
    const THREADS: u64 = 8;
    const PER_THREAD: u64 = 4;
    std::thread::scope(|scope| {
        for t in 0..THREADS {
            let handle = store.try_clone().expect("clone for writer");
            scope.spawn(move || {
                for n in 0..PER_THREAD {
                    // Same operation text on every writer: duplicates must be
                    // stored as separate rows (binding rules arrive PR07+).
                    handle
                        .insert(
                            &OperationId::parse("op-shared").expect("op"),
                            &InstalledId::parse("ahu-1").expect("entity"),
                            &InstalledId::parse("sensor-sat-1").expect("sensor"),
                            &Value::Decimal(Decimal::parse("21.50").expect("decimal")),
                            &Unit::parse("degC").expect("unit"),
                            triple(),
                            &RecordIdentity::new(
                                SourceGenerationId::parse("gen-1").expect("gen"),
                                t * 100 + n,
                            ),
                        )
                        .expect("concurrent insert");
                }
            });
        }
    });
    let report = store.report().expect("report");
    assert_eq!(
        report.queued,
        THREADS * PER_THREAD,
        "every concurrent row is stored; nothing merged, nothing lost"
    );
    println!(
        "race-write: {} threads x {} = {} rows, all present",
        THREADS, PER_THREAD, report.queued
    );
}

// ---------------------------------------------------------------------------
// Finite replay horizon: requests clamp, truncation is explicit.
// ---------------------------------------------------------------------------

#[test]
fn finite_replay_horizon_is_explicit() {
    let scratch = Scratch::new("horizon");
    let mut bounds = StoreBounds::tiny();
    bounds.max_replay_rows = 2;
    let store = SqliteStore::open(
        &scratch.db("tiny.db"),
        ConnectionSettings::local_wal_full(),
        bounds,
    )
    .expect("open")
    .0;
    for n in 1..=5u64 {
        insert_fixture_row(&store, &format!("op-{n}"), n);
    }
    let page = store.replay_queued(100).expect("replay");
    assert_eq!(page.requested, 100);
    assert_eq!(page.served, 2, "horizon clamps the page");
    assert!(page.truncated, "over-horizon request says so");
    let exact = store.replay_queued(2).expect("replay");
    assert_eq!(exact.served, 2);
    assert!(!exact.truncated);
    // Claims clamp to the same horizon.
    let claimed = store
        .claim_queued(100, &token("horizon", 0))
        .expect("claim");
    assert_eq!(claimed.len(), 2);
}

// ---------------------------------------------------------------------------
// Bounds: payload, maintenance, and synthetic space refusals (no partials).
// ---------------------------------------------------------------------------

#[test]
fn value_too_large_refused_before_any_write() {
    let scratch = Scratch::new("too-large");
    let mut bounds = StoreBounds::tiny();
    bounds.max_value_bytes = 10; // the decimal JSON (~35 bytes) exceeds this.
    let store = SqliteStore::open(
        &scratch.db("tiny.db"),
        ConnectionSettings::local_wal_full(),
        bounds,
    )
    .expect("open")
    .0;
    let err = store
        .insert(
            &OperationId::parse("op-1").expect("op"),
            &InstalledId::parse("ahu-1").expect("entity"),
            &InstalledId::parse("sensor-sat-1").expect("sensor"),
            &Value::Decimal(Decimal::parse("21.50").expect("decimal")),
            &Unit::parse("degC").expect("unit"),
            triple(),
            &record(1),
        )
        .unwrap_err();
    assert_eq!(err.code(), "value-too-large");
    assert_eq!(store.report().expect("report").queued, 0);
}

#[test]
fn maintenance_and_space_budgets_refuse_without_partials() {
    let scratch = Scratch::new("space");
    let baseline = open_tiny(&scratch, "tiny.db");
    let current_db = baseline.db_size_bytes();
    assert!(current_db > 0);
    drop(baseline);

    // Operator-maintenance refusal: the live DB already exceeds the budget.
    let mut tight = StoreBounds::tiny();
    tight.max_db_bytes = 1;
    let store = SqliteStore::open(
        &scratch.db("tiny.db"),
        ConnectionSettings::local_wal_full(),
        tight,
    )
    .expect("open")
    .0;
    assert!(store.maintenance_required());
    assert_eq!(
        store
            .insert(
                &OperationId::parse("op-1").expect("op"),
                &InstalledId::parse("ahu-1").expect("entity"),
                &InstalledId::parse("sensor-sat-1").expect("sensor"),
                &Value::Missing,
                &Unit::parse("degC").expect("unit"),
                triple(),
                &record(1),
            )
            .unwrap_err()
            .code(),
        "maintenance-required"
    );
    drop(store);

    // Synthetic space exhaustion: budget fits today, not the next payload.
    let mut snug = StoreBounds::tiny();
    snug.max_db_bytes = current_db;
    let store = SqliteStore::open(
        &scratch.db("tiny.db"),
        ConnectionSettings::local_wal_full(),
        snug,
    )
    .expect("open")
    .0;
    assert!(!store.maintenance_required());
    assert_eq!(
        store
            .insert(
                &OperationId::parse("op-1").expect("op"),
                &InstalledId::parse("ahu-1").expect("entity"),
                &InstalledId::parse("sensor-sat-1").expect("sensor"),
                &Value::Missing,
                &Unit::parse("degC").expect("unit"),
                triple(),
                &record(1),
            )
            .unwrap_err()
            .code(),
        "space-exhausted"
    );
    assert_eq!(store.report().expect("report").queued, 0, "no partial row");
}

// ---------------------------------------------------------------------------
// Refused, not silent: read-only dir, unwritable path, bad generation.
// ---------------------------------------------------------------------------

#[test]
fn read_only_dir_is_a_typed_refusal() {
    let scratch = Scratch::new("readonly");
    let dir = scratch.dir.join("ro");
    std::fs::create_dir_all(&dir).expect("ro dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).expect("chmod 555");
        // Guard: a privileged runner (root) still writes through mode bits.
        let probe = dir.join(".privileged-probe");
        if std::fs::write(&probe, b"1").is_ok() {
            let _ = std::fs::remove_file(&probe);
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
                .expect("chmod back");
            println!("read_only_dir: skipped (runner writes through 555; not a refusal gap)");
            return;
        }
        let err = SqliteStore::open(
            &dir.join("tiny.db"),
            ConnectionSettings::local_wal_full(),
            StoreBounds::tiny(),
        )
        .unwrap_err();
        assert_eq!(err.code(), "read-only-path", "unexpected: {err}");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod back");
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, scratch);
        println!("read_only_dir: untested on non-unix targets (explicit limit)");
    }
}

#[test]
fn unwritable_paths_are_typed_refusals() {
    let scratch = Scratch::new("unwritable");
    // Missing parent: never created implicitly.
    let missing = scratch.dir.join("never-created").join("tiny.db");
    let err = SqliteStore::open(
        &missing,
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "unwritable-path");
    assert!(
        !scratch.dir.join("never-created").exists(),
        "refusal creates nothing"
    );

    // Database path that is itself a directory.
    let dir_as_db = scratch.dir.join("is-a-dir.db");
    std::fs::create_dir_all(&dir_as_db).expect("dir as db");
    let err = SqliteStore::open(
        &dir_as_db,
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "unwritable-path");
}

#[test]
fn schema_generation_mismatch_refuses_and_preserves_data() {
    let scratch = Scratch::new("generation");
    let db = scratch.db("tiny.db");
    let store = open_tiny(&scratch, "tiny.db");
    insert_fixture_row(&store, "op-1", 1);
    // Live statements are bound to 0001: tamper, then the old handle refuses.
    let (ok, _, _) = sqlite_raw(&db, "PRAGMA user_version = 9;");
    assert!(ok, "tamper the generation out of band");
    assert_eq!(
        store.report().unwrap_err().code(),
        "schema-generation-mismatch"
    );
    assert_eq!(
        store
            .insert(
                &OperationId::parse("op-2").expect("op"),
                &InstalledId::parse("ahu-1").expect("entity"),
                &InstalledId::parse("sensor-sat-1").expect("sensor"),
                &Value::Missing,
                &Unit::parse("degC").expect("unit"),
                triple(),
                &record(2),
            )
            .unwrap_err()
            .code(),
        "schema-generation-mismatch"
    );
    drop(store);
    // Reopen refuses before touching data (no silent migrate, no wipe).
    assert_eq!(
        SqliteStore::open(
            &db,
            ConnectionSettings::local_wal_full(),
            StoreBounds::tiny()
        )
        .unwrap_err()
        .code(),
        "schema-generation-mismatch"
    );
    let (ok, out, _) = sqlite_raw(&db, "SELECT COUNT(*) FROM outbox;");
    assert!(ok);
    assert_eq!(out.trim(), "1", "tampered data is preserved, not wiped");
}

// ---------------------------------------------------------------------------
// Corrupt rows are refused as invalid records, never coerced or dropped.
// ---------------------------------------------------------------------------

#[test]
fn corrupt_row_is_an_invalid_record_not_a_coercion() {
    let scratch = Scratch::new("corrupt");
    let db = scratch.db("tiny.db");
    let store = open_tiny(&scratch, "tiny.db");
    let id = insert_fixture_row(&store, "op-1", 1);
    let (ok, _, _) = sqlite_raw(
        &db,
        &format!("UPDATE outbox SET value_json = 'garbage!!!' WHERE id = {id};"),
    );
    assert!(ok, "inject corruption out of band");
    let err = store.replay_queued(10).unwrap_err();
    assert_eq!(err.code(), "invalid-record", "unexpected: {err}");
    // The row is still there (reported, not silently dropped).
    let (ok, out, _) = sqlite_raw(&db, "SELECT COUNT(*) FROM outbox;");
    assert!(ok);
    assert_eq!(out.trim(), "1");
}

// ---------------------------------------------------------------------------
// Foreground + explicit background task handoff: bounded, counted, no loss.
// ---------------------------------------------------------------------------

#[test]
fn foreground_background_handoff_is_bounded_counted_lossless() {
    let scratch = Scratch::new("handoff");
    let store = open_tiny(&scratch, "tiny.db");
    const ROWS: u64 = 12;
    for n in 1..=ROWS {
        insert_fixture_row(&store, &format!("op-{n}"), n);
    }
    let tok = token("handoff", 0);
    let claimed = store.claim_queued(64, &tok).expect("claim all");
    assert_eq!(claimed.len(), ROWS as usize);
    let ids: Vec<i64> = claimed.iter().map(|row| row.id).collect();

    let (mut sender, receiver) = Handoff::new(32).split();
    for id in &ids {
        sender.announce(*id).expect("announce within bound");
    }
    assert_eq!(sender.announced(), ROWS);
    assert_eq!(sender.refused(), 0);
    let sender_report = sender.finish();

    let worker = store.try_clone().expect("background handle");
    let background = std::thread::spawn(move || {
        let delivery = receiver.drain();
        let mut acked = 0u64;
        for id in &delivery.items {
            worker.acknowledge(*id, &tok).expect("background ack");
            acked += 1;
        }
        (delivery.delivered, acked)
    });
    let (delivered, acked) = background.join().expect("background task");
    assert_eq!(sender_report.announced, ROWS);
    assert_eq!(sender_report.refused, 0);
    assert_eq!(delivered, ROWS, "every announcement delivered");
    assert_eq!(acked, ROWS, "every delivery acknowledged");
    let report = store.report().expect("report");
    assert_eq!((report.queued, report.claimed, report.acked), (0, 0, ROWS));
    assert!(report.dangling.is_empty());
    println!(
        "handoff: announced={} delivered={} acked={} lost=0",
        ROWS, delivered, acked
    );
}

#[test]
fn handoff_full_is_a_refusal_not_a_drop() {
    let (mut sender, receiver) = Handoff::new(1).split();
    sender.announce(7i64).expect("first fits");
    assert_eq!(sender.announce(8i64).unwrap_err().code(), "handoff-full");
    assert_eq!(sender.announced(), 1);
    assert_eq!(sender.refused(), 1);
    let report = sender.finish();
    assert_eq!((report.announced, report.refused), (1, 1));
    let delivery = receiver.drain();
    assert_eq!(delivery.delivered, 1);
    assert_eq!(delivery.items, vec![7i64], "only the accepted item exists");
}

// ---------------------------------------------------------------------------
// Connection budget, checkpoint honesty, checked recalculation, input guards.
// ---------------------------------------------------------------------------

#[test]
fn in_process_handle_budget_is_enforced() {
    // Invariant: `try_clone` is the sole handle-creation path. `SqliteStore`
    // deliberately has no `Clone` impl: a derived `Clone` would share the
    // `Arc<Inner>` without incrementing `handles` while `Drop` always
    // decrements, underflowing the counter to `u32::MAX` and permanently
    // refusing legitimate `try_clone` calls. These drop cycles pin the
    // counter integrity: after every release the budget must recover exactly,
    // never stick at refused.
    let scratch = Scratch::new("budget");
    let mut bounds = StoreBounds::tiny();
    bounds.max_connections = 2;
    let store = SqliteStore::open(
        &scratch.db("tiny.db"),
        ConnectionSettings::local_wal_full(),
        bounds,
    )
    .expect("open")
    .0;
    let extra = store.try_clone().expect("second handle within budget");
    assert_eq!(
        store.try_clone().unwrap_err().code(),
        "too-many-connections"
    );
    drop(extra);
    let recovered = store.try_clone().expect("slot released on drop");
    drop(recovered);
    for _ in 0..5 {
        let handle = store
            .try_clone()
            .expect("budget recovers after each drop cycle (no counter underflow)");
        drop(handle);
    }
    // Counter never underflowed to u32::MAX: a fresh clone still fits, the
    // next still refuses, and the survivor still serves reads.
    let extra = store
        .try_clone()
        .expect("slot still available after drop cycles");
    assert_eq!(
        store.try_clone().unwrap_err().code(),
        "too-many-connections"
    );
    drop(extra);
    store.try_clone().expect("slot released on drop");
    store.report().expect("surviving handle still serves reads");
}

#[test]
fn checkpoint_protects_bytes_not_derived_correctness() {
    let scratch = Scratch::new("checkpoint");
    let store = open_tiny(&scratch, "tiny.db");
    insert_fixture_row(&store, "op-1", 1);
    insert_fixture_row(&store, "op-2", 2);
    let checkpoint = store.checkpoint().expect("checkpoint");
    assert_eq!(checkpoint.busy, 0, "uncontended checkpoint is not blocked");
    assert!(checkpoint.checkpointed_frames >= 0);
    assert!(
        store.wal_size_bytes() <= StoreBounds::tiny().max_wal_bytes,
        "WAL stays within the explicit bound"
    );
    assert!(!store.maintenance_required());
    assert_eq!(store.maintenance_window_secs(), 3_600, "window is explicit");

    // Checkpointing bytes never clears derived dirtiness.
    let entity = InstalledId::parse("ahu-1").expect("entity");
    assert_eq!(
        store.dirty_entities().expect("dirty"),
        vec!["ahu-1".to_string()]
    );
    // Stale generation: refused, flag stays dirty.
    assert_eq!(
        store.mark_recalculated(&entity, 7).unwrap_err().code(),
        "invalid-input"
    );
    assert_eq!(
        store.dirty_entities().expect("dirty"),
        vec!["ahu-1".to_string()]
    );
    // Checked recalculation for 0001 clears it (and survives reopen).
    store.mark_recalculated(&entity, 1).expect("recalculated");
    assert!(store.dirty_entities().expect("dirty").is_empty());
    // Unknown entity: conflict, not success.
    assert_eq!(
        store
            .mark_recalculated(&InstalledId::parse("vav-101").expect("vav"), 1)
            .unwrap_err()
            .code(),
        "conflict"
    );
    drop(store);
    let store = open_tiny(&scratch, "tiny.db");
    assert!(store.dirty_entities().expect("dirty").is_empty());
}

#[test]
fn invalid_inputs_are_refused_with_codes() {
    let scratch = Scratch::new("inputs");
    let store = open_tiny(&scratch, "tiny.db");
    assert_eq!(
        store.claim_queued(0, "tok").unwrap_err().code(),
        "invalid-input"
    );
    assert_eq!(
        store.claim_queued(5, "").unwrap_err().code(),
        "invalid-input"
    );
    assert_eq!(store.replay_queued(0).unwrap_err().code(), "invalid-input");
    assert_eq!(
        store
            .acknowledge(999_999, &token("inputs", 0))
            .unwrap_err()
            .code(),
        "conflict"
    );
    assert_eq!(
        store
            .requeue_claim(999_999, &token("inputs", 1))
            .unwrap_err()
            .code(),
        "conflict"
    );
    assert_eq!(
        store.run_transaction(&[]).unwrap_err().code(),
        "invalid-input"
    );
    assert_eq!(
        store.exec_script("   ").unwrap_err().code(),
        "invalid-input"
    );
}

// ---------------------------------------------------------------------------
// Envelope framing: storage-side refusal of 0x1F/0x0A/0x0D + sentinels.
// Domain `Unit::parse` semantics are PR02-frozen (still accepts these labels
// as unknown units); the store refuses them at the insert/token boundary so
// one row can never poison its whole page at decode time.
// ---------------------------------------------------------------------------

fn insert_with_unit(
    store: &SqliteStore,
    op: &str,
    unit: &Unit,
    seq: u64,
) -> Result<i64, storage::StorageError> {
    store.insert(
        &OperationId::parse(op).expect("op"),
        &InstalledId::parse("ahu-1").expect("entity"),
        &InstalledId::parse("sensor-sat-1").expect("sensor"),
        &Value::Decimal(Decimal::parse("21.50").expect("decimal")),
        unit,
        triple(),
        &record(seq),
    )
}

fn assert_unit_refused(store: &SqliteStore, label: &str, op: &str, seq: u64) {
    // Domain still preserves the label (PR02-frozen); the store refuses it.
    let unit = Unit::parse(label).expect("domain preserves unknown unit labels");
    match insert_with_unit(store, op, &unit, seq) {
        Err(storage::StorageError::InvalidInput { what, .. }) => {
            assert_eq!(what, "unit", "framing refusal is typed to the unit path");
        }
        other => panic!("poison unit {op} must be refused with invalid-input, got {other:?}"),
    }
}

#[test]
fn envelope_framing_poison_unit_is_refused() {
    let scratch = Scratch::new("framing-unit");
    let store = open_tiny(&scratch, "tiny.db");
    assert_unit_refused(&store, "a\x1fb", "op-sep", 1);
    assert_unit_refused(&store, "a\nb", "op-lf", 2);
    assert_unit_refused(&store, "a\rb", "op-cr", 3);
    for sentinel in ["VERDANT_BEGIN", "VERDANT_DATA", "VERDANT_END"] {
        assert_unit_refused(&store, sentinel, &format!("op-{sentinel}"), 10);
    }
    // Nothing was written: every refusal happened before any write.
    assert_eq!(
        store.report().expect("report").queued,
        0,
        "refused poison units leave no rows"
    );
}

#[test]
fn envelope_framing_poison_token_is_refused() {
    let scratch = Scratch::new("framing-token");
    let store = open_tiny(&scratch, "tiny.db");
    insert_fixture_row(&store, "op-1", 1);
    for poison in [
        "a\x1fb".to_string(),
        "a\nb".to_string(),
        "a\rb".to_string(),
        "VERDANT_BEGIN".to_string(),
        "VERDANT_DATA".to_string(),
        "VERDANT_END".to_string(),
    ] {
        assert_eq!(
            store.claim_queued(5, &poison).unwrap_err().code(),
            "invalid-input",
            "poison claim token must be refused"
        );
        assert_eq!(
            store.acknowledge(1, &poison).unwrap_err().code(),
            "invalid-input",
            "poison acknowledge token must be refused"
        );
        assert_eq!(
            store.requeue_claim(1, &poison).unwrap_err().code(),
            "invalid-input",
            "poison requeue token must be refused"
        );
    }
    // The queued row is untouched and still claimable under a clean token.
    assert_eq!(store.report().expect("report").queued, 1);
    let claimed = store
        .claim_queued(5, &token("framing-token", 0))
        .expect("clean token still claims");
    assert_eq!(claimed.len(), 1);
}

#[test]
fn envelope_framing_refusal_preserves_neighbor_rows() {
    let scratch = Scratch::new("framing-neighbors");
    let store = open_tiny(&scratch, "tiny.db");
    insert_fixture_row(&store, "op-1", 1);
    insert_fixture_row(&store, "op-2", 2);
    // Poison attempts are refused; legitimate rows on the same page stay readable.
    assert_unit_refused(&store, "a\x1fb", "op-poison", 3);
    assert_eq!(
        store.claim_queued(5, "bad\x1ftoken").unwrap_err().code(),
        "invalid-input"
    );
    let page = store.replay_queued(10).expect("neighbors still decode");
    assert_eq!(page.served, 2, "no whole-page poisoning");
    assert_eq!(page.rows[0].operation.as_str(), "op-1");
    assert_eq!(page.rows[1].operation.as_str(), "op-2");
    // Claims, reports, and dangling scans all still decode the same page.
    let tok = token("framing-neighbors", 0);
    let claimed = store.claim_queued(10, &tok).expect("claim neighbors");
    assert_eq!(claimed.len(), 2);
    assert_eq!(store.report().expect("report").claimed, 2);
    assert_eq!(store.dangling_claims().expect("dangling").len(), 2);
}

// ---------------------------------------------------------------------------
// Insert atomicity: outbox row + derived mark commit together or not at all.
// ---------------------------------------------------------------------------

#[test]
fn insert_is_atomic_when_derived_mark_write_fails() {
    let scratch = Scratch::new("insert-atomic");
    let store = open_tiny(&scratch, "tiny.db");
    insert_fixture_row(&store, "op-good", 1);
    // Force the second statement of `insert` to fail out of band.
    store
        .exec_script("DROP TABLE derived_marks;")
        .expect("drop derived_marks out of band");
    let err =
        insert_with_unit(&store, "op-partial", &Unit::parse("degC").expect("unit"), 2).unwrap_err();
    assert_eq!(
        err.code(),
        "sqlite-failure",
        "failed second statement surfaces as sqlite failure, got {err}"
    );
    // No partial: the outbox INSERT rolled back with the failed batch.
    let rows = store
        .exec_script("SELECT COUNT(*) FROM outbox;")
        .expect("count outbox without touching derived_marks");
    assert_eq!(
        rows.first()
            .and_then(|cols| cols.first())
            .map(String::as_str),
        Some("1"),
        "only the pre-existing row survives; the failed insert left no partial"
    );
    let ops = store
        .exec_script("SELECT quote(operation) FROM outbox ORDER BY id;")
        .expect("list operations");
    assert_eq!(ops.len(), 1, "failed operation stored nothing");
}

// ---------------------------------------------------------------------------
// Restricted runtime role: file ownership / mode on synthetic temp paths.
// ---------------------------------------------------------------------------

#[test]
#[cfg(unix)]
fn db_file_ownership_and_mode_are_recorded() {
    use std::os::unix::fs::MetadataExt as _;
    let scratch = Scratch::new("ownership");
    let db = scratch.db("tiny.db");
    let (store, report) = SqliteStore::open(
        &db,
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("open");
    let mode = report.file_mode.expect("mode recorded on unix");
    let uid = report.file_uid.expect("uid recorded on unix");
    assert_ne!(mode, 0, "mode bits are actually read");
    let meta = std::fs::metadata(&db).expect("stat db");
    assert_eq!(mode, meta.mode() & 0o7777, "recorded mode matches the file");
    assert_eq!(uid, meta.uid(), "recorded uid matches the file");
    let parent_uid = std::fs::metadata(&scratch.dir).expect("stat dir").uid();
    assert_eq!(
        uid, parent_uid,
        "synthetic db is owned by the synthetic dir creator"
    );
    drop(store);
}

#[test]
#[cfg(not(unix))]
fn db_file_identity_untested_off_unix() {
    println!("file ownership/mode: untested on non-unix targets (explicit limit)");
}
