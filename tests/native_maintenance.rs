//! R09 synthetic native lifecycle evidence; isolated OS-temp stores only.
//! File-content comparisons prove no durable byte changes, not absence of fsync.
#![allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "../src/storage/mod.rs"]
mod storage;
#[path = "../src/native/mod.rs"]
mod native;

use native::{NativeError, NativeHandle, NativeSettings};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "verdant-r09-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("isolated store");
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove isolated store");
    }
}
fn files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    for entry in std::fs::read_dir(dir).expect("list") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            for (name, data) in files(&path) {
                result.insert(path.file_name().map(PathBuf::from).expect("basename").join(name), data);
            }
        } else {
            result.insert(PathBuf::from(path.file_name().expect("basename")), std::fs::read(path).expect("read"));
        }
    }
    result
}
fn bytes(dir: &Path) -> u64 {
    files(dir).values().map(|data| data.len() as u64).sum()
}
fn insert(handle: &NativeHandle, n: u64) {
    assert_eq!(handle.execute(&format!("INSERT (:Reading {{seq: {n}}})")).expect("insert").changes, Some(1));
}

fn wait_for_writer_release(dir: &Path) {
    use std::fs::{OpenOptions, TryLockError};
    use std::time::{Duration, Instant};
    // Selene b65c234 holds LOCK in an Arc<File>, released by synchronous
    // drop. CI nevertheless observed contention at the immediate next open.
    // Synchronize setup on the actual lock, not a fixed delay or retried product
    // operation. Never use this while testing a live owner's refusal.
    let before = files(dir);
    let lock = OpenOptions::new().read(true).write(true).open(dir.join("LOCK")).expect("existing LOCK");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(TryLockError::WouldBlock) => {
                assert!(Instant::now() < deadline, "writer LOCK not released: {}", dir.display());
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(TryLockError::Error(error)) => panic!("writer LOCK probe failed: {error}"),
        }
    }
    lock.unlock().expect("release synchronization lock");
    assert_eq!(before, files(dir), "release synchronization must not change the store");
}

#[test]
fn r09_fixed_measurements() {
    let scratch = Scratch::new();
    let (handle, created) = NativeHandle::create(&scratch.0, NativeSettings::local()).expect("create");
    insert(&handle, 1);
    let first = handle.checkpoint().and_then(native::CheckpointOutcome::completed).expect("checkpoint");
    let before = files(&scratch.0);
    let second = handle.checkpoint().and_then(native::CheckpointOutcome::completed).expect("checkpoint twice");
    assert_eq!(first.generation, 4);
    assert_eq!(first.snapshot, "SNAPSHOT-00000000000000000004.logical");
    assert_eq!(first.bytes, 59_879);
    assert_eq!(first.bytes, std::fs::metadata(scratch.0.join(&first.snapshot)).expect("snapshot").len());
    assert_eq!(first.position.sequence, 3);
    assert_eq!(first.generation, second.generation);
    assert_eq!(first.snapshot, second.snapshot);
    assert_eq!(first.digest_hex, second.digest_hex);
    assert_eq!(first.bytes, second.bytes);
    assert_eq!(first.position, second.position);
    assert_eq!(first.store_bytes_after, second.store_bytes_after);
    assert_eq!(before, files(&scratch.0));
    println!("FIXED create={created:?}; checkpoint1={first:?}; checkpoint2={second:?}; same_files=true");
    let before = files(&scratch.0);
    let err = NativeHandle::open(&scratch.0, NativeSettings::local()).expect_err("live owner");
    assert!(matches!(err, NativeError::Contention { .. }));
    assert_eq!(before, files(&scratch.0));
    let closed = handle.close();
    let before = files(&scratch.0);
    let (handle, reopened) = closed.open().expect("reopen");
    assert_eq!(before, files(&scratch.0));
    assert_eq!(reopened.recovery.expect("recovery").replayed_suffix_records, 0);
    println!("FIXED reopen={reopened:?}");
    drop(handle);
    let mut settings = NativeSettings::local();
    settings.bounds.max_store_bytes = bytes(&scratch.0);
    let (handle, _) = NativeHandle::open(&scratch.0, settings).expect("exact ceiling");
    let before = bytes(&scratch.0);
    insert(&handle, 2);
    let after = bytes(&scratch.0);
    // Observed admission ceiling, NOT a hard growth quota: this accepted
    // statement at equality appends 398 bytes before the next call refuses.
    assert_eq!(after - before, 398);
    let durable = files(&scratch.0);
    let refused = handle.execute("INSERT (:Reading {seq: 3})").expect_err("above ceiling");
    assert_eq!(refused.code(), "maintenance-required");
    assert!(matches!(refused.storage_maintenance_error(), Some(storage::StorageError::MaintenanceRequired { .. })));
    assert_eq!(durable, files(&scratch.0));
    let checkpoint = handle.checkpoint().expect("typed outcome");
    let prune = handle.prune().expect("typed outcome");
    assert!(matches!(checkpoint, native::CheckpointOutcome::RefusedExhausted { .. }));
    assert!(matches!(prune, native::PruneOutcome::RefusedExhausted { .. }));
    assert_eq!(durable, files(&scratch.0));
    println!("FIXED exact ceiling={before}; after accepted insert={after}; above refusal={refused:?}; checkpoint={checkpoint:?}; prune={prune:?}");
}

#[test]
fn r09_fixed_error_mapping() {
    use selene_db::{StorageErrorKind as K, StoragePhase as P};
    let scratch = Scratch::new();
    for kind in [K::Io, K::UnsupportedPlatform, K::MissingArtifact, K::InvalidArtifact, K::CheckpointUncertain, K::ResourceLimit] {
        // The public diagnostic fields permit a mapping-only fixture; its cause
        // remains a real failed empty open, not an injected filesystem failure.
        let mut source = selene_db::Database::open(&scratch.0).err().expect("empty");
        source.kind = kind;
        source.phase = P::Checkpoint;
        let mapped = NativeError::from_storage_in(source, &scratch.0);
        println!("FIXED kind={kind:?} mapped={mapped:?}");
        assert_eq!(mapped.code(), match kind {
            K::Io => "io", K::UnsupportedPlatform => "unsupported-platform",
            K::MissingArtifact | K::InvalidArtifact => "integrity",
            K::CheckpointUncertain => "checkpoint-uncertain", K::ResourceLimit => "maintenance-required",
            _ => unreachable!("fixture kinds enumerated above"),
        });
        assert_eq!(mapped.storage_maintenance_error().is_some(), kind == K::ResourceLimit);
        assert!(format!("{mapped}").contains("Checkpoint"));
        assert!(format!("{mapped}").contains(&format!("{kind:?}")));
    }
}

#[test]
fn r09_maintenance_exact_boundaries_and_reserves() {
    for checkpoint in [true, false] {
        for margin in [-1i64, 0, 1] {
            let scratch = Scratch::new();
            let (handle, _) = NativeHandle::create(&scratch.0, NativeSettings::local()).expect("create");
            insert(&handle, 1);
            drop(handle);
            wait_for_writer_release(&scratch.0);
            let measured = bytes(&scratch.0);
            let mut settings = NativeSettings::local();
            settings.bounds.native_reserve_bytes = 128;
            settings.bounds.future_journal_reserve_bytes = 256;
            settings.bounds.max_store_bytes = (measured as i64 + 384 + margin) as u64;
            let (handle, _) = NativeHandle::open(&scratch.0, settings).expect("open below store ceiling");
            let before = files(&scratch.0);
            let plan = settings.bounds.plan_maintenance(measured).expect("plan");
            assert_eq!(plan.required_bytes, Some(measured + 384));
            assert_eq!(plan.admitted(), margin >= 0);
            let accepted = if checkpoint {
                match handle.checkpoint().expect("checkpoint outcome") {
                    native::CheckpointOutcome::Completed(report) => {
                        assert_eq!(report.plan, plan);
                        assert_eq!(report.generation, 4);
                        true
                    }
                    native::CheckpointOutcome::RefusedExhausted { plan: got, detail } => {
                        assert_eq!(got, plan);
                        assert!(detail.contains("checkpoint plan exhausted"));
                        false
                    }
                }
            } else {
                match handle.prune().expect("prune outcome") {
                    native::PruneOutcome::Reclaimed(report) => {
                        assert_eq!(report.plan, plan);
                        assert!(report.cleanup_error.is_none());
                        true
                    }
                    native::PruneOutcome::RefusedExhausted { plan: got, detail } => {
                        assert_eq!(got, plan);
                        assert!(detail.contains("prune plan exhausted"));
                        false
                    }
                    native::PruneOutcome::CleanupIncomplete(report) => panic!("unexpected debt: {report:?}"),
                }
            };
            assert_eq!(accepted, margin >= 0, "checkpoint={checkpoint} margin={margin}");
            if !accepted { assert_eq!(before, files(&scratch.0)); }
            println!("FIXED checkpoint={checkpoint} margin={margin} plan={plan:?} accepted={accepted}");
        }
    }
}

#[test]
fn r09_one_mib_budget_plan_and_validation() {
    let mut bounds = native::NativeBounds::local();
    bounds.native_reserve_bytes = 65_536;
    bounds.future_journal_reserve_bytes = 262_144;
    bounds.max_store_bytes = 1_376_256;
    let exact = bounds.plan_maintenance(1_048_576).expect("1 MiB plan");
    assert_eq!(exact.required_bytes, Some(1_376_256));
    assert!(exact.admitted());
    bounds.max_store_bytes -= 1;
    assert!(!bounds.plan_maintenance(1_048_576).expect("valid exhausted plan").admitted());
    bounds.max_store_bytes += 2;
    assert!(bounds.plan_maintenance(1_048_576).expect("spare byte").admitted());
    assert!(!bounds.plan_maintenance(u64::MAX).expect("overflow is exhausted").admitted());
    assert_eq!(bounds.plan_maintenance(u64::MAX).expect("overflow").required_bytes, None);
    for (native, journal) in [(0, 1), (1, 0), (u64::MAX, 1)] {
        bounds.native_reserve_bytes = native;
        bounds.future_journal_reserve_bytes = journal;
        assert_eq!(bounds.validate().expect_err("invalid reserves").code(), "invalid-input");
    }
    println!("FIXED 1 MiB planning={exact:?}; not a disk reservation");
}

#[test]
fn r09_execute_statement_and_store_exact_boundaries() {
    for len in [63, 64, 65] {
        let scratch = Scratch::new();
        let mut settings = NativeSettings::local();
        settings.bounds.max_statement_bytes = 64;
        // Statement admission needs no close/reopen transition.
        let (handle, _) = NativeHandle::create(&scratch.0, settings).expect("create");
        let statement = format!("{:<len$}", "INSERT (:Reading {seq: 1})");
        assert_eq!(statement.len(), len);
        let before = files(&scratch.0);
        match handle.execute(&statement) {
            Ok(report) => { assert!(len <= 64); assert_eq!(report.changes, Some(1)); }
            Err(error) => {
                assert_eq!(len, 65);
                assert_eq!(error.code(), "resource-limit");
                assert!(error.storage_maintenance_error().is_none());
                assert_eq!(before, files(&scratch.0));
            }
        }
    }
    for margin in [0, 1] {
        let scratch = Scratch::new();
        let (handle, _) = NativeHandle::create(&scratch.0, NativeSettings::local()).expect("create");
        drop(handle);
        wait_for_writer_release(&scratch.0);
        let mut settings = NativeSettings::local();
        settings.bounds.max_store_bytes = bytes(&scratch.0) + margin;
        let (handle, report) = NativeHandle::open(&scratch.0, settings).expect("at/below ceiling");
        assert_eq!(report.store_bytes + margin, settings.bounds.max_store_bytes);
        // A statement may grow beyond the observed ceiling: never claim a hard quota.
        insert(&handle, 1);
        let before = files(&scratch.0);
        let error = handle.execute("INSERT (:Reading {seq: 2})").expect_err("now above ceiling");
        assert_eq!(error.code(), "maintenance-required");
        assert_eq!(before, files(&scratch.0));
    }
}

#[test]
fn r09_bootstrap_refusals_and_stale_close_authority_preserve_files() {
    let scratch = Scratch::new();
    let mut tight = NativeSettings::local();
    tight.bounds.max_store_bytes = 512;
    let before = files(&scratch.0);
    assert_eq!(NativeHandle::create(&scratch.0, tight).expect_err("bootstrap reserve").code(), "maintenance-required");
    assert_eq!(before, files(&scratch.0));
    let (handle, _) = NativeHandle::create(&scratch.0, NativeSettings::local()).expect("original bootstrap");
    insert(&handle, 1);
    let clone = handle.clone();
    let closed = handle.close();
    let before = files(&scratch.0);
    assert_eq!(closed.clone().open().expect_err("clone still holds owner").code(), "contention");
    assert!(matches!(NativeHandle::create(&scratch.0, NativeSettings::local()), Err(NativeError::UnsupportedFormat { .. } | NativeError::AlreadyInitialized { .. })));
    assert_eq!(before, files(&scratch.0));
    drop(clone);
    let (handle, report) = closed.open().expect("owner released");
    assert_eq!(report.recovery.expect("replayed").replayed_suffix_records, 3);
    assert_eq!(before, files(&scratch.0));
    assert_eq!(handle.execute("MATCH (r:Reading) RETURN r").expect("row intact").row_count, Some(1));
    drop(handle);
    let before = files(&scratch.0);
    tight.bounds.max_store_bytes = bytes(&scratch.0) - 1;
    assert_eq!(NativeHandle::open(&scratch.0, tight).expect_err("over-capacity activation").code(), "maintenance-required");
    assert_eq!(before, files(&scratch.0));
}

#[test]
fn r09_prune_views_and_partial_maintenance_outcome() {
    let scratch = Scratch::new();
    let (handle, _) = NativeHandle::create(&scratch.0, NativeSettings::local()).expect("create");
    for n in 0..3 {
        insert(&handle, n);
        handle.checkpoint().and_then(native::CheckpointOutcome::completed).expect("checkpoint");
    }
    // Only API-managed checkpoints/WALs contribute to this space comparison.
    let verified_before = selene_db::Database::verify(&scratch.0).expect("Selene view");
    let report = match handle.prune().expect("prune") {
        native::PruneOutcome::Reclaimed(report) => report,
        other => panic!("expected reclaimed: {other:?}"),
    };
    assert!(report.removed_bytes > 0);
    assert!(report.store_bytes_after < report.store_bytes_before);
    assert!(report.retained_bytes < report.retained_bytes + report.removed_bytes);
    assert_eq!(report.store_bytes_before - report.store_bytes_after, report.removed_bytes);
    let verified_after = selene_db::Database::verify(&scratch.0).expect("selected bytes retained");
    assert_eq!(verified_before.snapshot, verified_after.snapshot);
    assert_eq!(verified_before.nodes, verified_after.nodes);
    // Retention includes classified coordination/control files; only verify's
    // selected snapshot+WAL view excludes history and that managed overhead.
    assert!(report.retained_bytes > verified_after.snapshot_bytes + verified_after.captured_wal_bytes);
    println!("FIXED qualitative whole-dir {} -> {}; Selene accounted {} -> {}; selected snapshot+captured WAL={} (different mapping)", report.store_bytes_before, report.store_bytes_after, report.retained_bytes + report.removed_bytes, report.retained_bytes, verified_after.snapshot_bytes + verified_after.captured_wal_bytes);
    drop(handle);
    let mut settings = NativeSettings::local();
    settings.bounds.native_reserve_bytes = 128;
    settings.bounds.future_journal_reserve_bytes = 256;
    settings.bounds.max_store_bytes = bytes(&scratch.0) + 384;
    let (handle, _) = NativeHandle::open(&scratch.0, settings).expect("open");
    match handle.maintain().expect("pass outcome") {
        native::MaintenanceOutcome::RefusedExhausted { checkpoint: Some(checkpoint), plan, .. } => {
            assert!(!plan.admitted());
            assert_eq!(checkpoint.position.sequence, 5);
            assert_eq!(checkpoint.generation, 7);
            let verified = selene_db::Database::verify(&scratch.0).expect("checkpoint committed despite prune refusal");
            assert_eq!(checkpoint.generation, verified.generation);
            assert_eq!(checkpoint.snapshot, verified.snapshot);
        }
        other => panic!("must retain completed checkpoint: {other:?}"),
    }
}

#[test]
fn r09_foreign_artifact_refused_without_changing_any_file() {
    let scratch = Scratch::new();
    let (handle, _) = NativeHandle::create(&scratch.0, NativeSettings::local()).expect("create");
    insert(&handle, 1);
    handle.checkpoint().and_then(native::CheckpointOutcome::completed).expect("checkpoint");
    // Deliberately invalidate an otherwise valid store. This is a refusal
    // fixture, never an artifact used to establish valid-store space accounting.
    std::fs::write(scratch.0.join("operator-note"), b"synthetic").expect("foreign fixture");
    let before = files(&scratch.0);
    let verify = selene_db::Database::verify(&scratch.0).expect_err("foreign artifact");
    assert_eq!(verify.kind, selene_db::StorageErrorKind::UnsupportedFormat);
    assert_eq!(before, files(&scratch.0));
    let prune = handle.prune().expect_err("prune must not delete foreign bytes");
    assert!(matches!(prune, NativeError::UnsupportedFormat { .. }));
    assert_eq!(before, files(&scratch.0));
    drop(handle);
    let open = NativeHandle::open(&scratch.0, NativeSettings::local()).expect_err("strict open");
    assert!(matches!(open, NativeError::UnsupportedFormat { .. }));
    assert_eq!(before, files(&scratch.0));
    println!("FIXED foreign artifact verify={verify:?}; prune={prune:?}; open={open:?}; same_files=true");
}

#[test]
fn r09_post_checkpoint_dirty_recovery_repair_and_shutdown() {
    for dirty_writes in [1, 3] {
        let scratch = Scratch::new();
        let (handle, _) = NativeHandle::create(&scratch.0, NativeSettings::local()).expect("create");
        insert(&handle, 0);
        let selected = handle.checkpoint().and_then(native::CheckpointOutcome::completed).expect("checkpoint");
        for n in 1..=dirty_writes { insert(&handle, n); }
        let dirty = files(&scratch.0);
        assert_ne!(dirty, BTreeMap::new());
        let closed = handle.close(); // Dirty means committed suffix, not corrupt bytes.
        assert_eq!(dirty, files(&scratch.0));
        let (handle, reopened) = closed.open().expect("recover dirty suffix");
        let recovery = reopened.recovery.expect("RecoverySummary");
        assert_eq!(recovery.replayed_suffix_records, dirty_writes);
        assert_eq!(recovery.rebuilt_indexes, 0);
        assert_eq!(dirty, files(&scratch.0));
        assert_eq!(handle.execute("MATCH (r:Reading) RETURN r").expect("recovered rows").row_count, Some((dirty_writes + 1) as usize));
        // Explicit checkpoint+prune repairs maintenance debt, not corruption.
        let repaired = match handle.maintain().expect("repair maintenance debt") {
            native::MaintenanceOutcome::Completed(report) => report,
            other => panic!("repair incomplete: {other:?}"),
        };
        assert!(repaired.checkpoint.generation > selected.generation);
        assert_eq!(repaired.checkpoint.position.sequence, selected.position.sequence + dirty_writes);
        assert_ne!(repaired.checkpoint.digest_hex, selected.digest_hex);
        let stable = files(&scratch.0);
        let repeated = handle.checkpoint().and_then(native::CheckpointOutcome::completed).expect("no new writes");
        assert_eq!(repeated.generation, repaired.checkpoint.generation);
        assert_eq!(repeated.digest_hex, repaired.checkpoint.digest_hex);
        assert_eq!(repeated.bytes, repaired.checkpoint.bytes);
        assert_eq!(stable, files(&scratch.0));
        let closed = handle.close();
        assert_eq!(stable, files(&scratch.0));
        let (handle, shutdown_reopen) = closed.open().expect("open after repaired shutdown");
        let clean = shutdown_reopen.recovery.expect("post-shutdown RecoverySummary");
        assert_eq!(clean.replayed_suffix_records, 0);
        assert_eq!(clean.rebuilt_indexes, 0);
        assert_eq!(handle.execute("MATCH (r:Reading) RETURN r").expect("rows after shutdown").row_count, Some((dirty_writes + 1) as usize));
        assert_eq!(stable, files(&scratch.0));
        println!("FIXED dirty_writes={dirty_writes}; recovery={recovery:?}; repaired={repaired:?}; shutdown_recovery={clean:?}; same_files=true; in-process close/reopen only");
    }
}

#[test]
fn r09_open_race_retains_original_winner_and_typed_gql_refusal() {
    use std::sync::{Arc, Barrier};
    // Simultaneous probes can refuse every contender. Also force a schedule
    // with an established winner; never reopen a replacement to claim success.
    for established in [false, true] {
        let scratch = Scratch::new();
        let (handle, _) = NativeHandle::create(&scratch.0, NativeSettings::local()).expect("create");
        insert(&handle, 1);
        let closed = handle.close();
        let before = files(&scratch.0);
        let mut winners = Vec::new();
        if established { winners.push(closed.open().expect("established open winner")); }
        let barrier = Arc::new(Barrier::new(2));
        let outcomes = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..2).map(|_| {
                let barrier = Arc::clone(&barrier);
                let dir = &scratch.0;
                scope.spawn(move || {
                    barrier.wait();
                    NativeHandle::open(dir, NativeSettings::local())
                })
            }).collect();
            // Successful results retain their actual owner through ALL joins.
            workers.into_iter().map(|worker| worker.join().expect("open thread")).collect::<Vec<_>>()
        });
        let mut refusals = Vec::new();
        for outcome in outcomes {
            match outcome {
                Ok(winner) => winners.push(winner),
                Err(error) => {
                    match &error {
                        NativeError::Contention { .. } => {}
                        NativeError::Io { path, message } => {
                            // R09 owner adjudication: concurrent probe removal can
                            // surface a directory-measurement diagnostic. Require
                            // the exact probe or store path, never an arbitrary suffix.
                            let probe = scratch.0.join(".verdant-write-probe");
                            assert!(Path::new(path) == probe || Path::new(path) == scratch.0, "established={established}; store={:?}; open refusal={error:?}", scratch.0);
                            if Path::new(path) == probe {
                                assert!(message.contains("fresh writability probe"), "established={established}; store={:?}; open refusal={error:?}", scratch.0);
                            } else {
                                assert!(message.starts_with("file type: ") || message.starts_with("metadata: "), "established={established}; store={:?}; open refusal={error:?}", scratch.0);
                            }
                        }
                        NativeError::UnsupportedFormat { detail } => assert!(detail.contains(".verdant-write-probe")),
                        other => panic!("unexpected open refusal: {other:?}"),
                    }
                    refusals.push(error);
                }
            }
        }
        assert!(winners.len() <= 1, "never two native owners");
        assert_eq!(winners.len() + refusals.len(), if established { 3 } else { 2 });
        if established { assert_eq!(winners.len(), 1); }
        assert_eq!(before, files(&scratch.0));
        for (winner, opened) in &winners {
            assert_eq!(opened.recovery.expect("winner recovery").replayed_suffix_records, 3);
            let failure = winner.execute("INSERT (:Reading {seq: })").expect_err("GQL is a typed refusal, not a thread panic");
            assert!(matches!(failure, NativeError::StatementRejected { .. }));
            assert!(format!("{failure}").contains("status="));
            assert_eq!(before, files(&scratch.0));
            assert_eq!(winner.execute("MATCH (r:Reading) RETURN r").expect("original winner rows").row_count, Some(1));
            assert_eq!(before, files(&scratch.0));
            println!("FIXED original winner={opened:?}; GQL refusal={failure:?}; same_files=true");
        }
        println!("FIXED open race established={established}; winners={}; refusals={refusals:?}; no replacement open", winners.len());
    }
}

#[test]
fn r09_native_sqlite_space_views_agree_qualitatively() {
    use domain::clock::{TimeTriple, UnixMillis};
    use domain::ids::{InstalledId, OperationId, SourceGenerationId};
    use domain::outcomes::RecordIdentity;
    use domain::values::{Unit, Value};
    use storage::{sqlite::SqliteStore, ConnectionSettings, StoreBounds};
    let native_dir = Scratch::new();
    let sqlite_dir = Scratch::new();
    let (handle, _) = NativeHandle::create(&native_dir.0, NativeSettings::local()).expect("native");
    let (sqlite, _) = SqliteStore::open(&sqlite_dir.0.join("store.db"), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("SQLite");
    let native_initial = handle.store_bytes().expect("native initial");
    let sqlite_initial = sqlite.capacity_bytes();
    let native_files_initial = bytes(&native_dir.0);
    let sqlite_files_initial = bytes(&sqlite_dir.0);
    assert_eq!(native_initial, native_files_initial);
    assert_eq!(sqlite_initial, sqlite_files_initial);
    for n in 0..3 {
        insert(&handle, n);
        handle.checkpoint().and_then(native::CheckpointOutcome::completed).expect("managed snapshot");
        sqlite.insert(
            &OperationId::parse("r09-space-view").expect("operation"),
            &InstalledId::parse("ahu-1").expect("entity"),
            &InstalledId::parse("sensor-sat-1").expect("sensor"),
            &Value::Text("synthetic".repeat(4096)), &Unit::parse("degC").expect("unit"),
            TimeTriple::new(UnixMillis::new(1), UnixMillis::new(2), UnixMillis::new(3)).expect("time"),
            &RecordIdentity::new(SourceGenerationId::parse("gen-1").expect("generation"), n),
        ).expect("managed SQLite write");
    }
    let native_written = handle.store_bytes().expect("native written");
    let sqlite_written = sqlite.capacity_bytes();
    let native_files_written = bytes(&native_dir.0);
    let sqlite_files_written = bytes(&sqlite_dir.0);
    assert!(native_written > native_initial);
    assert!(sqlite_written > sqlite_initial);
    assert_eq!(native_written - native_initial, native_files_written - native_files_initial);
    assert_eq!(sqlite_written - sqlite_initial, sqlite_files_written - sqlite_files_initial);
    let prune = match handle.prune().expect("native prune") {
        native::PruneOutcome::Reclaimed(report) => report,
        other => panic!("native reclaim incomplete: {other:?}"),
    };
    let checkpoint = sqlite.checkpoint().expect("SQLite checkpoint");
    assert_eq!(checkpoint.busy, 0);
    let native_after = handle.store_bytes().expect("native after");
    let sqlite_after = sqlite.capacity_bytes();
    let native_files_after = bytes(&native_dir.0);
    let sqlite_files_after = bytes(&sqlite_dir.0);
    assert!(native_after < native_written);
    // Each API view must move with its independent filesystem view in this
    // run: both grow on writes, and native prune reclaims its reported bytes.
    // SQLite checkpoint may grow, shrink, or retain main+WAL+SHM capacity
    // (page allocation and short-lived connection cleanup vary by environment).
    // Its signed delta must agree exactly with disk, but claims NO reclaim.
    // Neither absolute byte expectations nor cross-engine byte equality apply.
    let sqlite_checkpoint_delta = i128::from(sqlite_after) - i128::from(sqlite_written);
    assert_eq!(sqlite_checkpoint_delta, i128::from(sqlite_files_after) - i128::from(sqlite_files_written));
    assert_eq!(native_written - native_after, native_files_written - native_files_after);
    assert_eq!(sqlite.wal_size_bytes(), 0);
    assert_eq!(native_after, native_files_after);
    assert_eq!(sqlite_after, sqlite_files_after);
    assert_eq!(native_written - native_after, prune.removed_bytes);
    assert_eq!(handle.execute("MATCH (r:Reading) RETURN r").expect("native rows").row_count, Some(3));
    assert_eq!(sqlite.report().expect("SQLite rows").queued, 3);
    println!("FIXED space views native whole-directory {native_initial} -> {native_written} -> {native_after}, Selene retained={}; SQLite main+WAL+SHM {sqlite_initial} -> {sqlite_written} -> {sqlite_after}; checkpoint={checkpoint:?}; SQLite checkpoint delta={sqlite_checkpoint_delta}; API/filesystem deltas agree; no SQLite reclaim claimed", prune.retained_bytes);
}
