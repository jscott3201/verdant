//! R04 bounded-execution evidence; synthetic stores only. Process-crash and
//! response-interruption evidence, not power-loss or a child-memory quota.
use super::*;
use super::execution::{ExecutionState, Operation, Process};
use std::fs;
use std::time::{Duration, Instant};

const COMPUTE: &str = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) SELECT sum(x) FROM n;";
thread_local! { static AFTER_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

pub(super) fn after_commit_reply(process: &mut Process) -> Result<(), StorageError> {
    if AFTER_COMMIT.with(|flag| flag.replace(false)) { process.exchange(COMPUTE)?; }
    Ok(())
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("verdant-r04-{}-{}-{}", std::process::id(), epoch_nanos_now(), mutation::next_sequence()));
        fs::create_dir(&path).expect("exclusive scratch");
        Self(path.canonicalize().expect("physical path"))
    }
    fn db(&self) -> PathBuf { self.0.join("store.db") }
    fn open(&self) -> SqliteStore {
        SqliteStore::open(&self.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open").0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).expect("cleanup scratch"); }
}

fn children(path: &Path) -> Vec<u32> {
    let output = Command::new("ps").args(["-axo", "pid=,ppid=,command="]).output().expect("ps");
    assert!(output.status.success());
    String::from_utf8(output.stdout).expect("ps UTF8").lines().filter_map(|line| {
        let mut words = line.split_whitespace();
        let pid = words.next()?.parse().ok()?;
        let parent: u32 = words.next()?.parse().ok()?;
        (parent == std::process::id() && line.contains(path.to_str().expect("path"))).then_some(pid)
    }).collect()
}

fn assert_reaped(pid: u32) {
    let out = Command::new("ps").args(["-p", &pid.to_string(), "-o", "pid="]).output().expect("ps PID");
    assert!(!out.status.success() && out.stdout.is_empty(), "survivor/zombie {pid}: {out:?}");
}

fn idle(store: &SqliteStore) -> ExecutionReport {
    let report = store.execution_report();
    assert_eq!(report.running, 0, "permit leaked: {report:?}");
    assert_eq!(report.spawned, report.reaped, "child unreaped: {report:?}");
    assert!(children(store.db_path()).is_empty(), "survivors");
    report
}

fn tune(store: &mut SqliteStore) -> &mut Inner { Arc::get_mut(&mut store.inner).expect("sole handle") }

fn pending(store: &SqliteStore) -> PreparedMutation {
    store.prepare_insert(
        &OperationId::parse("op-r04").expect("operation"),
        &InstalledId::parse("ahu-1").expect("entity"), &InstalledId::parse("sensor-sat-1").expect("sensor"),
        &Value::Missing, &Unit::parse("degC").expect("unit"),
        TimeTriple::new(UnixMillis::new(1), UnixMillis::new(2), UnixMillis::new(3)).expect("times"),
        &RecordIdentity::new(SourceGenerationId::parse("gen-1").expect("generation"), 1),
    ).expect("prepare")
}

fn counts(store: &SqliteStore) -> Vec<Vec<String>> {
    store.exec_verified("SELECT (SELECT count(*) FROM outbox), (SELECT count(*) FROM derived_marks), (SELECT count(*) FROM storage_receipts);", false).expect("counts").body_rows
}

#[test]
fn r04_capacity_refuses_zero_spawn_on_one_shared_handle_and_recovers() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    tune(&mut store).bounds.max_connections = 1;
    tune(&mut store).bounds.max_running_operations = 2;
    let barrier = std::sync::Barrier::new(3);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let store = &store;
            let barrier = &barrier;
            scope.spawn(move || {
                let conn = store.admitted(false).expect("admit");
                barrier.wait();
                barrier.wait();
                drop(conn);
            });
        }
        barrier.wait();
        let before = store.execution_report();
        let pids = children(&scratch.db());
        let refused: Vec<_> = (0..4).map(|_| store.admitted(false).err().expect("over capacity")).collect();
        let after = store.execution_report();
        barrier.wait();
        assert_eq!(pids.len(), 2);
        assert_eq!(before.running, 2);
        assert_eq!(after.spawned, before.spawned, "refusal must not spawn");
        assert_eq!(after.refused - before.refused, 4);
        assert!(refused.iter().all(|e| matches!(e, StorageError::TooManyRunningOperations { max: 2 })));
        assert_eq!(store.inner.handles.load(Ordering::SeqCst), 1);
        println!("FIXED capacity: handles=1 children=2 refused=4 refusal_spawns=0 pids={pids:?}");
    });
    for _ in 0..5 { drop(store.admitted(false).expect("recovered permit")); }
    println!("FIXED capacity: {:?} survivors=0", idle(&store));
}

#[test]
fn r04_operation_permit_is_shared_by_clones_not_handle_budget() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    tune(&mut store).bounds.max_running_operations = 1;
    let clone = store.try_clone().expect("clone unchanged");
    let conn = clone.admitted(false).expect("one operation");
    assert_eq!(store.admitted(false).err().expect("shared gate").code(), "too-many-running-operations");
    drop(conn);
    drop(store.admitted(false).expect("recovered across clone"));
    idle(&store);
}

#[test]
fn r04_deadline_kills_computation_without_busy_retry() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    tune(&mut store).settings.operation_timeout_ms = 150;
    let before = idle(&store);
    let started = Instant::now();
    let error = store.exec_verified(COMPUTE, false).unwrap_err();
    assert!(matches!(error, StorageError::DeadlineExceeded { timeout_ms: 150 }));
    let after = idle(&store);
    assert_eq!(after.spawned - before.spawned, 1, "computation must never be retried");
    assert!(started.elapsed() < Duration::from_secs(3));
    println!("FIXED deadline: elapsed_ms={} spawned=1 reaped=1 survivors=0", started.elapsed().as_millis());
}

#[test]
fn r04_output_limit_kills_mid_read_and_returns_no_partial_result() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    tune(&mut store).bounds.max_output_bytes = 32_768;
    let before = idle(&store);
    let error = store.exec_verified("SELECT hex(zeroblob(2097152));", false).unwrap_err();
    assert!(matches!(error, StorageError::ExecutionLimit { resource: "output bytes", max: 32_768 }));
    let after = idle(&store);
    let read = after.output_bytes - before.output_bytes;
    assert!(read > 32_768 && read <= 32_768 + 4096, "counter includes first over-cap chunk: {read}");
    assert_eq!(after.spawned - before.spawned, 1);
    println!("FIXED output: generated_row=4194304 cap=32768 observed_pipe_bytes={read} reaped=1 survivors=0");
}

#[test]
fn r04_stderr_flood_is_bounded_and_reaped() {
    let mut bounds = StoreBounds::tiny();
    bounds.max_output_bytes = 1024;
    let state = Arc::new(ExecutionState::default());
    let operation = Operation::start(Arc::clone(&state), &ConnectionSettings::local_wal_full(), &bounds).expect("permit");
    let mut command = Command::new("sh");
    command.args(["-c", "while :; do printf 'synthetic-stderr-flood\n' >&2; done"]);
    let mut child = Process::spawn(command, Path::new("synthetic-stderr"), operation).expect("spawn");
    let pid = child.id();
    assert!(matches!(child.collect(&["test"]).unwrap_err(), StorageError::ExecutionLimit { resource: "output bytes", max: 1024 }));
    assert_reaped(pid);
    drop(child);
    assert_eq!(state.report().running, 0);
    assert_eq!(state.report().reaped, 1);
}

#[test]
fn r04_broken_stdin_kills_live_child_and_reaps_with_typed_io() {
    let state = Arc::new(ExecutionState::default());
    let operation = Operation::start(Arc::clone(&state), &ConnectionSettings::local_wal_full(), &StoreBounds::tiny()).expect("permit");
    let mut command = Command::new("sh");
    // Close stdin then replace the shell, so no descendant escapes ownership.
    command.args(["-c", "exec 0<&-; exec sleep 60"]);
    let mut child = Process::spawn(command, Path::new("synthetic-broken-stdin"), operation).expect("spawn");
    let pid = child.id();
    let error = child.collect(&[&"x".repeat(1_048_576)]).unwrap_err();
    assert!(matches!(error, StorageError::Io { .. }), "{error}");
    assert_reaped(pid);
    drop(child);
    assert_eq!(state.report().running, 0);
    assert_eq!((state.report().spawned, state.report().reaped), (1, 1));
    // Exercise the actual SQLite stdin driver too, including its early exit.
    let error = run_script_stdin(Path::new(":memory:"), &[], &format!(".quit\n--{}", "x".repeat(1_048_576))).unwrap_err();
    assert!(matches!(error, StorageError::Io { .. }));
    println!("FIXED broken stdin: code=io live-child-killed reaped=1 survivors=0 pid={pid}");
}

#[test]
fn r04_input_and_rows_are_cumulative_not_per_exchange() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let mut conn = store.admitted(false).expect("connection");
    for _ in 0..3 { assert_eq!(conn.exchange("SELECT 1;").expect("small replies"), vec![vec!["1"]]); }
    drop(conn);
    tune(&mut store).bounds.max_input_bytes = 32_768;
    let mut conn = store.admitted(false).expect("connection");
    let script = format!("SELECT 1; --{}", "x".repeat(16_000));
    conn.exchange(&script).expect("one fits");
    assert!(matches!(conn.exchange(&script).unwrap_err(), StorageError::ExecutionLimit { resource: "input bytes", max: 32_768 }));
    drop(conn);
    idle(&store);
    tune(&mut store).bounds.max_output_rows = 80;
    let mut conn = store.admitted(false).expect("protocol fits");
    let many = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<30) SELECT x FROM n;";
    conn.exchange(many).expect("first rows fit");
    assert!(matches!(conn.exchange(many).unwrap_err(), StorageError::ExecutionLimit { resource: "output rows", max: 80 }));
    drop(conn);
    idle(&store);
}

#[test]
fn r04_full_history_is_never_clamped_to_replay_horizon() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    tune(&mut store).bounds.max_replay_rows = 2;
    let history = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100) SELECT x FROM n ORDER BY x;";
    assert_eq!(store.exec_verified(history, false).expect("full-history product path").body_rows.len(), 100);
    assert_eq!(store.exec_script(history).expect("test envelope also complete").len(), 100);
    for _ in 0..3 { assert!(matches!(store.submit(&pending(&store)), MutationOutcome::Committed { .. })); }
    let replay = store.replay_queued(100).expect("bounded replay");
    assert_eq!(replay.served, 2);
    assert!(replay.truncated);
    assert_eq!(store.claim_queued(100, "r04").expect("bounded claim").len(), 2);
    tune(&mut store).bounds.max_output_rows = 80;
    assert_eq!(store.exec_verified(history, false).unwrap_err().code(), "execution-limit");
    assert_eq!(store.exec_script(history).unwrap_err().code(), "execution-limit");
    idle(&store);
}

#[test]
fn r04_timeout_before_commit_is_noncommit_with_preserved_bytes() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    tune(&mut store).settings.operation_timeout_ms = 150;
    let bytes = fs::read(store.db_path()).expect("before bytes");
    let request = PreparedMutation::new(&store, &format!("INSERT INTO derived_marks VALUES ('ahu-1',1,0); {COMPUTE}"), Shape::Change).expect("test request");
    assert!(matches!(store.submit(&request), MutationOutcome::NotCommitted { error: StorageError::DeadlineExceeded { .. }, .. }));
    idle(&store);
    assert_eq!(counts(&store), vec![vec!["0", "0", "0"]]);
    assert_eq!(fs::read(store.db_path()).expect("after bytes"), bytes);
    println!("FIXED precommit deadline: outbox=0 marks=0 receipts=0 preserved_db_bytes={} survivors=0", bytes.len());
}

#[test]
fn r04_timeout_after_commit_is_unknown_then_same_identity_reconciles() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    tune(&mut store).settings.operation_timeout_ms = 150;
    let request = pending(&store);
    AFTER_COMMIT.with(|flag| flag.set(true));
    let outcome = store.submit(&request);
    assert!(matches!(outcome, MutationOutcome::Unknown { ref detail, .. } if detail.contains("deadline")), "{outcome:?}");
    idle(&store);
    assert_eq!(counts(&store), vec![vec!["1", "1", "1"]]);
    let bytes = fs::read(store.db_path()).expect("committed bytes");
    let reconciled = store.reconcile(&request);
    assert!(matches!(reconciled, MutationOutcome::Committed { .. }));
    assert_eq!(store.submit(&request), reconciled);
    assert_eq!(counts(&store), vec![vec!["1", "1", "1"]]);
    assert_eq!(fs::read(store.db_path()).expect("no second mutation"), bytes);
    println!("FIXED postcommit deadline: UNKNOWN -> same-ID committed; outbox=1 marks=1 receipts=1 unchanged_bytes={} survivors=0", bytes.len());
    idle(&store);
}

#[test]
fn r04_lock_wait_retries_share_deadline_and_permit() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let mut lock = store.admitted(true).expect("writer barrier");
    tune(&mut store).settings.busy_timeout_ms = 5;
    tune(&mut store).settings.operation_timeout_ms = 70;
    let before = store.execution_report();
    let error = store.admitted(true).err().expect("locked deadline");
    assert!(matches!(error, StorageError::DeadlineExceeded { .. }), "{error}");
    let after = store.execution_report();
    assert!((1..=3).contains(&(after.spawned - before.spawned)), "{before:?} {after:?}");
    assert_eq!(after.running, 1, "only the original lock remains admitted");
    // BUSY_RETRIES=5 and BUSY_RETRY_PAUSE_MS=25 (mod.rs): six 5ms waits
    // + five 25ms pauses = 155ms nominal retry horizon, excluding CLI overhead.
    // Keep the deadline orders of magnitude larger so retry exhaustion, not
    // scheduler stalls, decides "busy"; a >30s stall is a CI-health failure.
    // Retries still consume one shared, bounded deadline/permit budget.
    tune(&mut store).settings.operation_timeout_ms = 30_000;
    assert_eq!(store.admitted(true).err().expect("bounded lock retries").code(), "busy");
    lock.exchange("ROLLBACK;").expect("release writer");
    drop(lock);
    idle(&store);
}

#[test]
fn r04_wal_behind_reader_is_accounted_and_degraded_until_checkpoint() {
    let scratch = Scratch::new();
    let mut store = scratch.open();
    let mut reader = store.admitted(false).expect("reader snapshot");
    reader.exchange("SELECT count(*) FROM outbox;").expect("pin reader");
    tune(&mut store).settings.journal_size_limit_bytes = 1;
    assert!(matches!(store.submit(&pending(&store)), MutationOutcome::Committed { .. }));
    let db = store.db_size_bytes();
    let wal = store.wal_size_bytes();
    let capacity = store.capacity_bytes();
    let blocked_insert = pending(&store);
    assert!(wal > 1, "journal_size_limit is not a live hard cap");
    assert!(capacity >= db + wal + 32_768);
    tune(&mut store).bounds.max_db_bytes = db + 32_768;
    assert!(store.maintenance_required());
    assert!(matches!(store.submit(&blocked_insert), MutationOutcome::NotCommitted { error: StorageError::MaintenanceRequired { .. }, .. }));
    assert_eq!(counts(&store), vec![vec!["1", "1", "1"]]);
    tune(&mut store).settings.busy_timeout_ms = 5;
    let checkpoint = store.checkpoint().expect("blocked checkpoint reported");
    assert_eq!(checkpoint.busy, 1);
    assert!(checkpoint.log_frames > checkpoint.checkpointed_frames);
    assert!(store.maintenance_required());
    println!("FIXED capacity: main={db} WAL={wal} SHM={} total={capacity} checkpoint={checkpoint:?} degraded=true", capacity - db - wal);
    drop(reader);
    assert_eq!(store.checkpoint().expect("checkpoint without reader").busy, 0);
    assert_eq!(store.wal_size_bytes(), 0);
    assert!(!store.maintenance_required());
    idle(&store);
}

#[test]
fn r04_open_forwards_budgets_and_rejects_zero_replay() {
    let scratch = Scratch::new();
    let mut bounds = StoreBounds::tiny();
    bounds.max_replay_rows = 0;
    assert_eq!(SqliteStore::open(&scratch.db(), ConnectionSettings::local_wal_full(), bounds).unwrap_err().code(), "invalid-input");
    let mut bounds = StoreBounds::tiny();
    bounds.max_input_bytes = 1;
    assert_eq!(SqliteStore::open(&scratch.db(), ConnectionSettings::local_wal_full(), bounds).unwrap_err().code(), "execution-limit");
    assert!(!scratch.db().exists());
    assert_eq!(fs::read_dir(&scratch.0).expect("private cleanup").count(), 0);
    let mut bounds = StoreBounds::tiny();
    bounds.max_running_operations = 0;
    assert_eq!(SqliteStore::open(&scratch.db(), ConnectionSettings::local_wal_full(), bounds).unwrap_err().code(), "too-many-running-operations");
    assert!(children(&scratch.db()).is_empty());
}

#[test]
fn r04_drop_cancels_staged_transaction_before_releasing_permit() {
    let scratch = Scratch::new();
    let store = scratch.open();
    let bytes = fs::read(store.db_path()).expect("before");
    let mut conn = store.admitted(true).expect("admitted writer");
    conn.exchange("INSERT INTO derived_marks VALUES ('ahu-1',1,0);").expect("staged");
    let pids = children(store.db_path());
    assert_eq!(pids.len(), 1);
    drop(conn);
    for pid in pids { assert_reaped(pid); }
    idle(&store);
    assert_eq!(counts(&store), vec![vec!["0", "0", "0"]]);
    assert_eq!(fs::read(store.db_path()).expect("after"), bytes);
}

#[test]
fn r04_deadline_also_bounds_blocked_stdin_and_final_exit() {
    for (script, input) in [
        ("exec sleep 60", "x".repeat(1_048_576)),
        ("exec 1>&- 2>&-; exec sleep 60", String::new()),
    ] {
        let state = Arc::new(ExecutionState::default());
        let mut settings = ConnectionSettings::local_wal_full();
        settings.operation_timeout_ms = 100;
        let operation = Operation::start(Arc::clone(&state), &settings, &StoreBounds::tiny()).expect("permit");
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        let mut process = Process::spawn(command, Path::new("synthetic-deadline"), operation).expect("spawn");
        let pid = process.id();
        assert!(matches!(process.collect(&[&input]).unwrap_err(), StorageError::DeadlineExceeded { .. }));
        assert_reaped(pid);
        drop(process);
        assert_eq!(state.report().running, 0);
        assert_eq!((state.report().spawned, state.report().reaped), (1, 1));
    }
}

#[test]
fn r04_unterminated_last_row_counts_and_exact_budget_fits() {
    for (row_cap, succeeds) in [(1, false), (2, true)] {
        let mut bounds = StoreBounds::tiny();
        bounds.max_output_rows = row_cap;
        bounds.max_output_bytes = 3;
        let operation = Operation::standalone(&ConnectionSettings::local_wal_full(), &bounds).expect("permit");
        let mut command = Command::new("sh");
        command.args(["-c", "printf 'a\nb'"]);
        let mut process = Process::spawn(command, Path::new("synthetic-rows"), operation).expect("spawn");
        let result = process.collect(&[]);
        if succeeds { assert_eq!(result.expect("exact byte/row budget").stdout, b"a\nb"); }
        else { assert!(matches!(result.unwrap_err(), StorageError::ExecutionLimit { resource: "output rows", max: 1 })); }
    }
}

#[test]
fn r04_long_allowed_line_streams_without_repeated_prefix_scans() {
    let scratch = Scratch::new();
    let store = scratch.open();
    let rows = store.exec_verified("SELECT hex(zeroblob(1048576));", false).expect("bounded large line").body_rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].len(), 1);
    assert_eq!(rows[0][0].len(), 2_097_152);
    assert!(rows[0][0].bytes().all(|b| b == b'0'));
    idle(&store);
}
