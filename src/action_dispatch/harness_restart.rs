//! Slice D child-spawn/kill-after-accept orchestration + rediscovery, TEST-ONLY.
//!
//! Factored helper following `harness_provenance.rs` precedent (owner M02-PR07
//! dispatch). Moves, not grows: this file does NOT move `Port`,
//! `handle_request`, or `finish` (they stay in `harness.rs` untouched); it
//! imports [`Fixture`]/[`Harness`] read-only for capture assertions plus the
//! existing bounded `outstanding_page` -> `reconcile` scan for rediscovery.
//!
//! Purpose: prove post-handoff durability with TRUE child OS processes (separate
//! PID, separate memory after spawn, `kill()` before any
//! `mark_terminal`/`mark_unresolved`), never in-process simulation claimed as
//! process proof. The child admits via the joined path, `mark_dispatched`,
//! then `execute_*` with `Confirm` vs `DropAfterAccept`; the existing
//! `after_write` hook persists a marker file (kill signal: peer accept
//! observed, write left the writer) then sleeps so the parent can `kill()`
//! before any post-harness mark. The parent reopens the same Scratch DB file
//! with NO old Rust objects (fresh `Journal::open`), rediscovers via the
//! bounded scan, honestly marks `Unresolved` (or `Terminal` for the confirmed
//! variant after qualified proof), and proves no second `WriteProperty` via
//! read-only capture counts plus `inspect_identical` (reads only).
//!
//! Inclusion: this file lives under `src/action_dispatch/` for ownership but
//! is compiled only when included via `#[path]` in Slice D tests (no parent
//! `mod` touch, no `harness.rs` diff). All imports use `crate::` so they
//! resolve both as a future `action_dispatch::harness_restart` submodule and
//! as a test-root `harness_restart` sibling. `cargo build` (non-test) never
//! compiles this file; `cargo nextest` compiles it through the test binary
//! (`cfg(test)` true, `harness` present).
//!
//! Reliability under nextest: no hangs (bounded timeouts on marker + reap,
//! `Stdio::null` to avoid pipe-buffer deadlock), unique ports (harness uses
//! ephemeral `127.0.0.1:0`, never fixed facility ports) and unique Scratch
//! dirs per test (caller-supplied `pid + seq + test-name`), explicit skip only
//! when OS spawn is unavailable (caller maps `Err` to a pass-with-reason,
//! never a fake in-process proof).
//!
//! Memory-only rules (no `0007`, no receipt/outcome columns): `PendingRelease`
//! stays memory-only; obligations are rediscovered here via the existing
//! bounded scan (all fields already durable). Receipts stay memory-only with
//! a no-fabrication rule: reopened `Admitted` exposes no receipts; fresh
//! processes re-observe via read-only `inspect_identical` with fresh
//! `receipt_now` times.

use crate::action_custody::custody::rediscover_obligations_via_custody;
use crate::action_dispatch::harness::Fixture;
use crate::action_journal::{Admitted, Journal};
use crate::domain::scope::TrustedScope;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Bounded rediscovery for dropped `PendingRelease` / killed-child obligations.
///
/// Thin test-orchestration wrapper over the custody owner (which delegates to
/// the expiry owner, which delegates to `Journal::outstanding_page`):
/// state-filtered (terminal excluded), exact scope, bounded `LIMIT`/`OFFSET`.
/// Read-only recovery; never sends, marks, or resends. Cross-scope callers
/// observe nothing.
pub(crate) fn rediscover_via_outstanding(
    journal: &Journal,
    scope: &TrustedScope,
) -> Result<Vec<Admitted>, crate::action_custody::CustodyError> {
    let bound = journal.store().bounds().max_replay_rows;
    rediscover_obligations_via_custody(journal, scope, bound, 0)
}

/// Count `WriteProperty` (service 15) requests in a read-only capture.
///
/// `requests()` returns stripped NPDUs (`[1,4,0,3,invoke,service,...]`); index
/// 5 is the service. A second `WriteProperty` after restart would appear here;
/// `inspect_identical` (reads only, service 12) must not grow this count.
pub(crate) fn write_property_count(fixture: &Fixture) -> usize {
    count_service(fixture, 15)
}

/// Count requests for one BACnet service read-only (15 = write, 12 = read).
pub(crate) fn count_service(fixture: &Fixture, service: u8) -> usize {
    fixture
        .requests()
        .iter()
        .filter(|npdu| npdu.len() > 5 && npdu[5] == service)
        .count()
}

/// Resolve the current test binary for child spawn.
///
/// Returns `Err` when the OS cannot supply the exe path; callers must skip
/// gracefully with an explicit ignore reason (never fake with in-process
/// simulation and claim process proof).
pub(crate) fn current_test_exe() -> std::io::Result<PathBuf> {
    std::env::current_exe()
}

/// Whether a child-spawn failure must hard-fail instead of SKIP-with-reason.
///
/// Explicit applicability: this gates ONLY child-spawn orchestration tests
/// (Slice D `kill_*`/`receipt_*` parents plus future child-spawn proofs).
/// Local default (unset/anything but `1`) keeps SKIP-with-reason so a host
/// without process spawn still runs the suite honestly. The CI product job
/// sets `VERDANT_REQUIRE_CHILD=1`, turning an unavailable/broken spawn into
/// a hard failure (fail, never a SKIP-and-pass).
pub(crate) fn child_spawn_mandatory() -> bool {
    matches!(std::env::var("VERDANT_REQUIRE_CHILD").as_deref(), Ok("1"))
}

/// Map a child-spawn `Err` to SKIP (local default) or hard failure (CI).
/// Callers keep their `match` shape: `Ok(child)` proceeds, `Err` skips
/// locally via the returned `Err`, and the mandatory branch panics with the
/// explicit reason instead of returning (so CI fails, never passes).
pub(crate) fn map_spawn_error(test_name: &str, err: std::io::Error) -> std::io::Result<Child> {
    if child_spawn_mandatory() {
        panic!(
            "VERDANT_REQUIRE_CHILD=1: child-spawn failure hard-fails for '{test_name}' (no SKIP-and-pass in CI): {err}"
        );
    }
    Err(err)
}

/// Spawn one child test as a TRUE separate OS process.
///
/// Runs `current_exe --exact <test_name> --nocapture` plus `extra_args` with
/// `envs` added. `Stdio::null` avoids pipe-buffer hangs. The child test must
/// early-return when its `VERDANT_SLICED_*` envs are absent (so a normal
/// full-suite run passes trivially) and run child logic only when present.
pub(crate) fn spawn_child_test(
    test_name: &str,
    envs: &[(&str, &str)],
    extra_args: &[&str],
) -> std::io::Result<Child> {
    match current_test_exe().and_then(|exe| spawn_child_test_with_exe(&exe, test_name, envs, extra_args)) {
        Ok(child) => Ok(child),
        Err(err) => map_spawn_error(test_name, err),
    }
}

/// Spawn `test_name` from an explicit test-binary path (seam for the
/// mandatoriness unit proof, which passes a bogus target to observe the
/// failure branch without breaking real spawn).
pub(crate) fn spawn_child_test_with_exe(
    exe: &Path,
    test_name: &str,
    envs: &[(&str, &str)],
    extra_args: &[&str],
) -> std::io::Result<Child> {
    let mut cmd = Command::new(exe);
    cmd.arg("--exact")
        .arg(test_name)
        .arg("--nocapture");
    for arg in extra_args {
        cmd.arg(arg);
    }
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
}

/// Poll until `path` exists or `timeout` elapses (10 ms cadence).
///
/// Returns `true` when the marker appeared (kill signal: peer accept observed
/// in the child); `false` on timeout (caller must kill + fail, never hang).
pub(crate) fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}

/// `kill()` then reap with a bounded wait.
///
/// Returns `true` when the child was reaped (exit observed) within `timeout`;
/// `false` on timeout (caller must fail, never infer a stop from a timeout).
/// Stops are observed exits only; this helper never claims a pass from a
/// timeout.
pub(crate) fn kill_and_reap(child: &mut Child, timeout: Duration) -> bool {
    let _ = child.kill();
    let start = Instant::now();
    while start.elapsed() < timeout {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => return false,
        }
    }
    matches!(child.try_wait(), Ok(Some(_)))
}

/// Bounded reap without kill (for children expected to exit on their own).
///
/// Returns `true` when exited within `timeout`; `false` otherwise.
pub(crate) fn reap_without_kill(child: &mut Child, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => return false,
        }
    }
    matches!(child.try_wait(), Ok(Some(_)))
}
