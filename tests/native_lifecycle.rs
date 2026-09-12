//! M01-PR05 Selene native lifecycle tests: one facade, synthetic stores.
//!
//! Every test runs against an isolated synthetic store in an OS temp dir
//! (unique per process/test/sequence; removed on drop; never a repo path,
//! never production/field/paid anything). One supported target only
//! (macOS arm64, rustc 1.97.1, APFS temp FS): other targets, power loss,
//! real disk-full and PostgreSQL are untested limits.
//!
//! Crash labeling: the uncheckpointed close+reopen test below is WAL-REPLAY
//! evidence in-process (no checkpoint, no clean protocol), never SIGKILL or
//! power-loss proof. Selene's own suite owns process-kill evidence
//! (`durable/process_tests.rs` at the pinned rev); this suite proves the
//! Verdant facade preserves committed state across its own close/reopen and
//! maintenance boundaries.
//!
//! Determinism: no wall-clock assertions tighter than a 120 s completion
//! budget on the concurrency test; everything else asserts exact values and
//! stable machine codes.

#[path = "../src/native/mod.rs"]
mod native;

use native::{
    presence, NativeBounds, NativeError, NativeHandle, NativeSettings, CHANNEL_IDENTITY, FORMAT_ID,
    SELENE_CRATE_VERSION, SELENE_REV,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Isolated scratch root for one test. Removed on drop.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(test: &str) -> Scratch {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "verdant-native-{}-{}-{}",
            std::process::id(),
            test,
            seq
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir must be creatable");
        Scratch { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn store(&self, name: &str) -> PathBuf {
        let dir = self.dir.join(name);
        std::fs::create_dir_all(&dir).expect("store dir must be creatable");
        dir
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn local_settings() -> NativeSettings {
    NativeSettings::local()
}

fn insert_seq(handle: &NativeHandle, seq: u64) {
    let report = handle
        .execute(&format!("INSERT (:Reading {{seq: {seq}}})"))
        .expect("synthetic insert must commit");
    assert_eq!(report.changes, Some(1), "one implicit commit, one change");
}

fn count_rows(handle: &NativeHandle) -> usize {
    handle
        .execute("MATCH (r:Reading) RETURN r")
        .expect("synthetic read must succeed")
        .row_count
        .expect("read outcome carries a row count")
}

fn create_with_rows(scratch: &Scratch, name: &str, rows: u64) -> (NativeHandle, PathBuf) {
    let dir = scratch.store(name);
    let (handle, _) = NativeHandle::create(&dir, local_settings()).expect("create must succeed");
    for seq in 0..rows {
        insert_seq(&handle, seq);
    }
    assert_eq!(count_rows(&handle), rows as usize);
    (handle, dir)
}

#[test]
fn presence_reports_format_rev_without_touching_a_store() {
    let present = presence();
    assert!(present.bundled);
    assert_eq!(present.facade, "selene-db");
    assert_eq!(present.crate_version, SELENE_CRATE_VERSION);
    assert_eq!(present.rev, SELENE_REV);
    assert_eq!(present.rev, "b65c2344c916d2c3ceeb72cefcd72e7960e95e25");
    assert_eq!(present.format_id, FORMAT_ID);
    assert_eq!(present.format_id, "selene-format-2");
    assert_eq!(present.channel, CHANNEL_IDENTITY);
}

#[test]
fn create_open_reports_format_channel_rev_and_footprint() {
    let scratch = Scratch::new("create-report");
    let dir = scratch.store("store");
    let (handle, report) = NativeHandle::create(&dir, local_settings()).expect("create");
    assert_eq!(report.format_id, "selene-format-2");
    assert_eq!(report.channel, CHANNEL_IDENTITY);
    assert_eq!(report.selene_rev, SELENE_REV);
    assert_eq!(report.selene_crate, SELENE_CRATE_VERSION);
    assert_eq!(report.mode, "durable");
    assert!(report.store_bytes > 0, "pre-sized mapping is disclosed");
    assert_eq!(report.digest_hex.len(), 64);
    assert!(!report.fenced);
    assert!(report.recovery.is_none(), "create performs no replay");
    assert_eq!(report.settings, local_settings());
    assert_eq!(handle.settings(), local_settings());
    assert_eq!(report.dir, dir.display().to_string());
    assert!(
        dir.starts_with(scratch.path()),
        "synthetic store stays inside its isolated scratch root"
    );

    let readiness = handle.readiness();
    assert!(readiness.ready);
    assert!(!readiness.fenced);
    assert_eq!(readiness.mode, "durable");
    assert!(readiness.reason.contains(FORMAT_ID));
    assert!(readiness.reason.contains(SELENE_REV));
}

#[test]
fn transactions_commit_and_read_back() {
    let scratch = Scratch::new("transactions");
    let (handle, _) = create_with_rows(&scratch, "store", 3);
    // Each implicit transaction committed exactly one change (asserted in
    // insert_seq); the read path observes all three.
    let outcome = handle.execute("MATCH (r:Reading) RETURN r").expect("read");
    assert_eq!(outcome.row_count, Some(3));
    assert_eq!(outcome.changes, None, "reads commit no changes");
}

#[test]
fn checkpoint_prune_maintain_through_single_facade() {
    let scratch = Scratch::new("maintain");
    let (handle, _) = create_with_rows(&scratch, "store", 4);

    let checkpoint = handle.checkpoint().expect("checkpoint");
    assert!(checkpoint.generation >= 1);
    assert!(checkpoint.bytes > 0);
    assert_eq!(checkpoint.digest_hex.len(), 64);
    assert!(!checkpoint.snapshot.is_empty());
    assert!(checkpoint.store_bytes_after > 0);

    let prune = handle.prune().expect("prune");
    assert!(prune.cleanup_error.is_none(), "no cleanup debt expected");
    assert!(
        !prune.retained.is_empty(),
        "CURRENT + previous checkpoint stay retained"
    );

    let maintained = handle.maintain().expect("maintain");
    assert!(maintained.checkpoint.generation >= checkpoint.generation);
    assert!(maintained.prune.cleanup_error.is_none());
    assert_eq!(count_rows(&handle), 4, "maintenance preserves evidence");
}

#[test]
fn wrong_version_probe_refused_before_activation() {
    let scratch = Scratch::new("wrong-version");
    let dir = scratch.store("legacy");
    // Synthetic v1-era WAL header: `SLDB` magic + major version 1. The
    // read-only legacy probe recognizes the magic and refuses the version.
    let probe: [u8; 8] = [b'S', b'L', b'D', b'B', 0x01, 0x00, 0x00, 0x00];
    std::fs::write(dir.join("wal.log"), probe).expect("probe must be writable");

    let err = match NativeHandle::open(&dir, local_settings()) {
        Ok(_) => panic!("v1-era bytes must never activate a handle"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "unsupported-format");
    assert!(
        format!("{err}").contains("before activation"),
        "refusal names its boundary: {err}"
    );

    // Store untouched: the probe bytes are intact and no selection was
    // published (no CURRENT manifest).
    let back = std::fs::read(dir.join("wal.log")).expect("probe must remain readable");
    assert_eq!(back, probe);
    assert!(
        !dir.join("CURRENT").exists(),
        "refused open publishes no selection"
    );
}

#[test]
fn open_empty_dir_is_typed_not_initialized() {
    let scratch = Scratch::new("empty-open");
    let dir = scratch.store("empty");
    let err = NativeHandle::open(&dir, local_settings()).expect_err("empty dir is not a store");
    assert_eq!(err.code(), "not-initialized");
}

#[test]
fn double_create_is_refused_never_overwritten() {
    let scratch = Scratch::new("double-create");
    let dir = scratch.store("store");
    let (handle, first) = NativeHandle::create(&dir, local_settings()).expect("first create");
    insert_seq(&handle, 0);
    let before = first.store_bytes;

    let err = NativeHandle::create(&dir, local_settings()).expect_err("second create must fail");
    // Probe-first ordering (source-verified at the pin:
    // `EmptyStoreControl::create_empty` runs `legacy_probe::reject` BEFORE
    // the AlreadyInitialized check, and the initialized store's own WAL
    // carries the recognized `SLDB` magic): strict create on a live store is
    // refused as unsupported-format. The contract that matters — refusal,
    // never overwrite — holds either way.
    assert_eq!(err.code(), "unsupported-format");
    // First owner is undisturbed: its row is still the only row.
    assert_eq!(count_rows(&handle), 1);
    let after = handle
        .checkpoint()
        .expect("first owner still checkpoints")
        .store_bytes_after;
    assert!(after >= before, "no second owner truncated the store");
}

#[test]
fn close_reopen_preserves_committed_state_via_wal_replay() {
    let scratch = Scratch::new("restart");
    let (handle, _) = create_with_rows(&scratch, "store", 5);
    // Deliberately NO checkpoint: committed (WAL-appended) rows must replay
    // on open. This is in-process WAL-replay evidence, not SIGKILL proof.
    // Reopen through the recorded close authority (ClosedStore::open).
    let closed = handle.close();
    let (reopened, report) = closed.open().expect("reopen");
    let recovery = report.recovery.expect("open reports its recovery work");
    // The five committed inserts (plus the lifecycle schema/graph writes)
    // sit past the create-time checkpoint, so the suffix replay must account
    // at least them. No secondary indexes exist on this store, so
    // rebuilt_indexes is 0 by construction (open still eagerly validates the
    // catalog and rebuilds all retained runtime state before returning).
    assert!(
        recovery.replayed_suffix_records >= 5,
        "suffix replay must cover the five committed inserts: {recovery:?}"
    );
    assert_eq!(recovery.rebuilt_indexes, 0);
    assert_eq!(count_rows(&reopened), 5, "committed rows survive reopen");
    assert!(reopened.readiness().ready);
}

#[test]
fn maintenance_preserves_evidence_across_restart() {
    let scratch = Scratch::new("maintain-restart");
    let (handle, _) = create_with_rows(&scratch, "store", 6);
    let outcome = handle.maintain().expect("maintain");
    assert!(outcome.prune.cleanup_error.is_none());
    let closed = handle.close();
    let (reopened, _) = closed.open().expect("reopen");
    assert_eq!(count_rows(&reopened), 6);
    // Steady restart timing shape: a post-restart checkpoint still selects.
    let again = reopened.checkpoint().expect("post-restart checkpoint");
    assert!(again.generation >= outcome.checkpoint.generation);
}

#[test]
fn over_budget_statement_refused_before_promise() {
    let scratch = Scratch::new("stmt-budget");
    let (handle, _) = create_with_rows(&scratch, "store", 2);
    let tight = NativeSettings {
        bounds: NativeBounds {
            max_statement_bytes: 64,
            ..NativeBounds::local()
        },
    };
    assert!(tight.validate().is_ok());
    let dir = handle.dir().to_path_buf();
    drop(handle.close());
    let (handle, _) = NativeHandle::open(&dir, tight).expect("reopen with tight ceiling");

    let long = "MATCH (r:Reading) RETURN r, r AS s, r AS t, r AS u, r AS v, r AS w";
    assert!(long.len() > 64);
    let err = handle.execute(long).expect_err("over-budget statement");
    assert_eq!(err.code(), "resource-limit");
    // Store untouched by the refused promise: still exactly two rows, and a
    // small statement still works under the same ceiling.
    assert_eq!(count_rows(&handle), 2);
}

#[test]
fn over_budget_store_refused_before_promise() {
    let scratch = Scratch::new("store-budget");
    let (handle, dir) = create_with_rows(&scratch, "store", 2);
    drop(handle.close());
    // A ceiling below any real fresh store refuses activation itself.
    let tiny = NativeSettings {
        bounds: NativeBounds {
            max_store_bytes: 512,
            ..NativeBounds::local()
        },
    };
    assert!(tiny.validate().is_ok());
    let err = NativeHandle::open(&dir, tiny).expect_err("tiny ceiling must refuse");
    assert_eq!(err.code(), "resource-limit");
    // Untouched: a normal open still sees both rows.
    let (handle, _) = NativeHandle::open(&dir, local_settings()).expect("normal reopen");
    assert_eq!(count_rows(&handle), 2);
}

#[test]
fn invalid_settings_refused_with_typed_errors() {
    let scratch = Scratch::new("bad-settings");
    let dir = scratch.store("store");
    let cases: &[(&str, NativeBounds)] = &[
        (
            "max_statement_bytes",
            NativeBounds {
                max_statement_bytes: 63,
                ..NativeBounds::local()
            },
        ),
        (
            "max_store_bytes",
            NativeBounds {
                max_store_bytes: 511,
                ..NativeBounds::local()
            },
        ),
        (
            "max_inflight",
            NativeBounds {
                max_inflight: 0,
                ..NativeBounds::local()
            },
        ),
    ];
    for (what, bounds) in cases {
        let settings = NativeSettings { bounds: *bounds };
        let err = settings.validate().expect_err("degenerate bound");
        assert_eq!(err.code(), "invalid-input", "case {what}");
        let err = NativeHandle::create(&dir, settings).expect_err("create with bad settings");
        assert_eq!(err.code(), "invalid-input", "case {what}");
    }
    // No refused create left a store behind.
    let err = NativeHandle::open(&dir, local_settings()).expect_err("nothing was created");
    assert_eq!(err.code(), "not-initialized");
}

#[test]
fn statement_rejected_leaves_store_untouched() {
    let scratch = Scratch::new("rejected");
    let (handle, _) = create_with_rows(&scratch, "store", 2);
    let err = handle
        .execute("INSERT (:Reading {seq: })")
        .expect_err("malformed statement must not commit");
    assert_eq!(err.code(), "statement-rejected");
    assert_eq!(count_rows(&handle), 2);
    let empty = handle.execute("").expect_err("empty statement");
    assert_eq!(empty.code(), "invalid-input");
    assert_eq!(
        NativeError::invalid_input("x", "y".to_string()).code(),
        "invalid-input"
    );
}

#[test]
fn checkpoint_does_not_stall_readers() {
    let scratch = Scratch::new("concurrency");
    let (handle, _) = create_with_rows(&scratch, "store", 8);
    let start = Instant::now();
    let budget = std::time::Duration::from_secs(120);
    std::thread::scope(|scope| {
        let worker = handle.clone();
        let checkpoint = scope.spawn(move || worker.checkpoint());
        // Admission path keeps serving reads while the checkpoint holds
        // Selene's serial write reservation (held reader views stay valid).
        let mut observed = 0usize;
        for _ in 0..8 {
            observed += count_rows(&handle);
        }
        let report = checkpoint
            .join()
            .expect("checkpoint thread joins")
            .expect("checkpoint succeeds beside readers");
        assert!(report.generation >= 1);
        assert_eq!(observed, 8 * 8);
    });
    assert!(
        start.elapsed() < budget,
        "bounded blocking work completes inside the stated budget"
    );
}
