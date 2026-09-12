//! M01-PR05 Selene native database lifecycle (B01 last slice): one
//! owner, single public/native facade.
//!
//! ## D05 record (owner-set for this slice)
//!
//! Track SeleneDB `development` with exact-commit-per-validation discipline.
//! The pin below is qualified ONLY for this validation; any Selene bump needs
//! re-qualification. Selene alpha carries NO persisted-data compat across
//! builds: treat native stores as disposable (recreate from source), assert
//! exact format identity at open, refuse unknown versions before activation.
//!
//! * Reference: SeleneDB at `/Users/justin/Development/selene-db`, branch
//!   `development` (NOT `dev`; NOT the checked-out
//!   `feat/f04-pr01-batch-substrate` worktree state observed during mapping).
//! * Pin used by this validation: `origin/development` @
//!   `b65c2344c916d2c3ceeb72cefcd72e7960e95e25` (F03-PR03 #1198; format-2
//!   exclusive #1197; WAL + audit-log channels per [`CHANNEL_IDENTITY`];
//!   public row APIs removed #1184; values unification #1191; MSRV 1.97.1
//!   aligns with ours).
//! * MOVE NOTE: `origin/development` advanced DURING this slice to
//!   `bb6da71f55e53e5382a53f0b4bae948a5c0d9ab6` (F04-PR01 #1199, batch
//!   substrate merged). The move was NOT adopted: `Cargo.lock` pins the
//!   exact `b65c2344` SHA (immutable git-rev dependency), and every build
//!   and test in this validation ran against `b65c2344` only. Any bump to
//!   `bb6da71f` needs re-qualification per D05.
//! * Untracked `crates/selene-gql/src/plan/logical/path/` content observed in
//!   the reference worktree is not ours and was never touched.
//! * Mechanism: git dependency at the EXACT pinned rev (reproducible for
//!   public clones; see `Cargo.toml` + `Cargo.lock`). Never a path
//!   dependency, never vendored sources. Default features only: the facade
//!   lifecycle surface (`Database::create`/`open`/`checkpoint`/`prune` +
//!   session execute). No `test-harness`, no metrics, no wgpu/GPU, no
//!   benchmark/opt-in features, no algorithms/catalog direct use, no GQL
//!   operators beyond lifecycle need, no session-control-plane/F04 in-flight
//!   APIs.
//!
//! ## What lives here
//!
//! * [`NativeHandle`] — create/open/transactions/checkpoint/prune/
//!   maintenance + readiness/presence reporting (see `handle`).
//! * [`NativeSettings`]/[`NativeBounds`] — explicit per-handle settings and
//!   tested pre-promise ceilings (see `settings`).
//! * [`NativeError`] — typed failures with stable machine codes (see
//!   `error`).
//! * [`presence`] — native backend presence (format id, rev, readiness
//!   shape) without opening a store.
//!
//! ## Scope (B01/PR05 only)
//!
//! CONSUMED, not redefined:
//!
//! * PR02 `BootId`/`MonotonicMark`/`BindingRevision` + domain ids (callers
//!   may key native rows by them, but this module mints no trusted context).
//! * PR03 store conventions (native lifecycle records live alongside, not
//!   inside, store internals).
//! * PR01 config/CLI (no output rewording — the CLI surface is unchanged in
//!   this slice).
//!
//! EXCLUDED (stop, do not implement here): native salvage/graph server,
//! embedded peer features beyond the facade surface, general
//! plugin/extension framework, field/hub/MCP/workers, reduced operational
//! visibility. No new SQLite migrations (none needed: lifecycle records are
//! Selene-native, not SQLite rows); `0001` untouched.
//!
//! ## Durability honesty
//!
//! Acknowledged commits are durable through the format-2 WAL (observed via
//! checkpoint outcomes and [`selene_db::DurableStatus`]); kill-mid-flight
//! evidence is labeled PROCESS-CRASH (OS caches intact), never power-loss
//! proof. See `handle` docs and `tests/native_lifecycle.rs`.

mod error;
mod handle;
mod report;
mod settings;

// Re-exports are the public facade for the next consumer (M01-PR08+) and
// for `tests/native_lifecycle.rs` (which includes this module via `#[path]`).
// The binary itself wires the module without calling it yet, so the
// re-exports would read as unused imports here.
#[allow(unused_imports)]
pub use error::NativeError;
#[allow(unused_imports)]
pub use handle::NativeHandle;
#[allow(unused_imports)]
pub use report::{
    CheckpointReport, ClosedStore, ExecReport, MaintenanceOutcome, OpenReport, PruneReport,
    Readiness, RecoverySummary,
};
#[allow(unused_imports)]
pub use settings::{NativeBounds, NativeSettings};

/// Exact Selene `development` commit qualified by this validation (D05).
pub const SELENE_REV: &str = "b65c2344c916d2c3ceeb72cefcd72e7960e95e25";

/// Selene facade crate version at [`SELENE_REV`] (workspace.package).
pub const SELENE_CRATE_VERSION: &str = "2.0.0-alpha.1";

/// Native format identity asserted at every create/open.
pub const FORMAT_ID: &str = "selene-format-2";

/// Channel identity observed at [`SELENE_REV`] (`control.rs`: "Version-1
/// control envelopes describe an empty format-2 store only; WAL 3.1,
/// snapshot 1.6, legacy MANIFEST 1 and audit 2 ... until F02-PR08").
///
/// NOTE: the planning brief recorded "WAL 3.0 + audit-log 2"; the pinned
/// source documents WAL 3.1 for the control-envelope channel while the
/// `selene-persist` fuzz target still references WAL 3.0 framing. The
/// constant below records the pinned source verbatim; runtime compatibility
/// is asserted by Selene itself (profile/Unicode/collation identity match
/// inside `Database::create`/`open`), never by re-parsing this string.
pub const CHANNEL_IDENTITY: &str = "control-v1/wal-3.1/snapshot-1.6/manifest-1/audit-2";

/// Native backend presence: what is bundled, without opening a store.
///
/// The next consumer (M01-PR08+) reports this alongside readiness; version
/// decisions key off [`OpenReport`], never off this static shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativePresence {
    /// Always true once this module compiles: the Selene facade is linked.
    pub bundled: bool,
    /// Facade crate name (`selene-db`).
    pub facade: &'static str,
    /// Facade crate version at the pin.
    pub crate_version: &'static str,
    /// Exact Selene rev qualified by this validation.
    pub rev: &'static str,
    /// Native format identity.
    pub format_id: &'static str,
    /// Channel identity observed at the pin.
    pub channel: &'static str,
}

impl NativePresence {
    /// Describe the linked native backend (no I/O, no store touched).
    pub fn describe() -> NativePresence {
        NativePresence {
            bundled: true,
            facade: "selene-db",
            crate_version: SELENE_CRATE_VERSION,
            rev: SELENE_REV,
            format_id: FORMAT_ID,
            channel: CHANNEL_IDENTITY,
        }
    }
}

/// Describe the linked native backend (no I/O, no store touched).
pub fn presence() -> NativePresence {
    NativePresence::describe()
}
