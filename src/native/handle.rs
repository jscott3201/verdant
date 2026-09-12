//! Single public/native facade: one owner for the Selene lifecycle.
//!
//! [`NativeHandle`] is the only entry point. It creates, opens, transacts
//! (one GQL statement per implicit commit), checkpoints, prunes and maintains
//! a format-2 native store through the pinned Selene facade, with explicit
//! [`NativeSettings`], a bounded admission gate, and readiness/presence
//! reporting. There is exactly one of these owners per store directory:
//! handles are cheap to clone ([`std::sync::Arc`] over one shared owner).
//!
//! ## Authority and commit order
//!
//! Facade validation (settings, statement bytes, store-bytes ceiling,
//! admission gate) comes first, then the Selene mutation (one session per
//! call; sessions never escape the call), then Selene's own durability
//! action (format-2 WAL append under its internal policy), then the visible
//! commit outcome. `flush` honesty: Rust-side buffering is flushed before any
//! child/process boundary is waited on, and durability itself is the observed
//! Selene commit/checkpoint outcome — never an inferred stop.
//!
//! ## Narrow locking
//!
//! The facade mutex is held only to clone the [`selene_db::Database`] handle
//! (an `Arc` clone, microseconds). Every Selene call runs OUTSIDE the facade
//! lock on that clone, so a long checkpoint serializes inside Selene's own
//! write reservation — where held reader views stay valid and foreground
//! writes wait — instead of stalling facade admission. Past the
//! [`NativeBounds::max_inflight`] concurrent admissions, work is refused with
//! [`NativeError::Busy`], never queued without bound.
//!
//! ## Failure labeling
//!
//! Kill-mid-transaction evidence is **process-crash** evidence (OS caches stay
//! intact; WAL replay rolls the store forward to the last committed record),
//! never power-loss proof. Real disk-full, power loss, other targets and
//! PostgreSQL are untested limits (see the delivery handoff).

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
};

use selene_db::{CreatePolicy, Database, ObjectPath, SchemaPath};

use super::error::NativeError;
use super::report::{
    hex32, CheckpointReport, ClosedStore, ExecReport, MaintenanceOutcome, OpenReport, PositionHint,
    PruneReport, Readiness, RecoverySummary,
};
use super::settings::NativeSettings;
use super::{CHANNEL_IDENTITY, FORMAT_ID, SELENE_CRATE_VERSION, SELENE_REV};

/// Frozen synthetic lifecycle catalog layout (proven by the Selene facade
/// doctests at the pinned rev; synthetic only, never field data).
const LIFECYCLE_SCHEMA_CATALOG: &str = "selene";
const LIFECYCLE_SCHEMA_NAME: &str = "memory";
const LIFECYCLE_GRAPH_NAME: &str = "data";

/// Compile-time proof that the facade can share one owner across threads:
/// [`NativeHandle`] is `Send + Sync` exactly when [`Database`] is `Send`.
#[allow(dead_code)]
fn assert_database_sharable() {
    fn assert_send<T: Send>() {}
    assert_send::<Database>();
}

/// Bounded admission gate: at most `max` concurrent admissions hold a
/// [`AdmissionGuard`]; the next arrival is refused, never queued.
#[derive(Debug)]
struct AdmissionGate {
    used: AtomicU32,
    max: u32,
}

impl AdmissionGate {
    fn new(max: u32) -> AdmissionGate {
        AdmissionGate {
            used: AtomicU32::new(0),
            max,
        }
    }

    fn try_enter(&self) -> Result<AdmissionGuard<'_>, NativeError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                if used >= self.max {
                    None
                } else {
                    Some(used + 1)
                }
            })
            .map(|_| AdmissionGuard { gate: self })
            .map_err(|used| NativeError::Busy {
                detail: format!(
                    "admission gate saturated ({used} of {} in flight); refusing, not queueing",
                    self.max
                ),
            })
    }
}

/// Held admission slot; released (count decremented) on drop.
#[derive(Debug)]
struct AdmissionGuard<'a> {
    gate: &'a AdmissionGate,
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        self.gate.used.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Shared lifecycle owner behind every clone of [`NativeHandle`].
///
/// No `Debug` derive: [`selene_db::Database`] is not `Debug`, and the owner
/// must not leak internals through diagnostics. The manual impl below
/// reports directory, settings and graph only.
struct Shared {
    db: Mutex<Database>,
    dir: PathBuf,
    settings: NativeSettings,
    graph: ObjectPath,
    gate: AdmissionGate,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("dir", &self.dir)
            .field("settings", &self.settings)
            .field("graph", &self.graph)
            .field("gate", &self.gate)
            .finish_non_exhaustive()
    }
}

/// One established native store owner (clone = same owner, new admission).
#[derive(Clone)]
pub struct NativeHandle {
    shared: Arc<Shared>,
}

impl fmt::Debug for NativeHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeHandle")
            .field("shared", &self.shared)
            .finish()
    }
}

/// Reopen half of the close authority: [`ClosedStore`] is constructed by
/// [`NativeHandle::close`]; its recorded directory + settings reopen here.
/// (The struct itself lives in [`super::report`] with the other report
/// shapes; same crate, so this impl block is local.)
impl ClosedStore {
    /// Reopen a closed store with its recorded settings.
    pub fn open(self) -> Result<(NativeHandle, OpenReport), NativeError> {
        NativeHandle::open(&self.dir, self.settings)
    }
}

impl NativeHandle {
    /// Strictly create a format-2 native store in an existing directory.
    ///
    /// Refuses existing/foreign artifacts (never overwrites, migrates, or
    /// opens existing data) and initializes the synthetic lifecycle schema
    /// and graph. Returns the owner plus its [`OpenReport`].
    pub fn create(dir: &Path, settings: NativeSettings) -> Result<(Self, OpenReport), NativeError> {
        settings.validate()?;
        let gate = AdmissionGate::new(settings.bounds.max_inflight);
        let _admission = gate.try_enter()?;
        Self::check_dir_usable(dir)?;
        let db = Database::create(dir).map_err(|e| NativeError::from_storage_in(e, dir))?;
        let graph = Self::init_lifecycle(&db)?;
        let shared = Arc::new(Shared {
            db: Mutex::new(db),
            dir: dir.to_path_buf(),
            settings,
            graph,
            gate: AdmissionGate::new(settings.bounds.max_inflight),
        });
        let handle = NativeHandle { shared };
        let report = handle.open_report(None)?;
        Ok((handle, report))
    }

    /// Open an existing format-2 native store, non-destructively.
    ///
    /// Exact-format mismatch (v1-era bytes, tampered headers, foreign
    /// artifacts) is refused BEFORE activation: no handle is returned and
    /// the store is left untouched. Eagerly rebuilds every retained
    /// supported index before returning (Selene all-or-error open).
    pub fn open(dir: &Path, settings: NativeSettings) -> Result<(Self, OpenReport), NativeError> {
        settings.validate()?;
        let gate = AdmissionGate::new(settings.bounds.max_inflight);
        let _admission = gate.try_enter()?;
        Self::check_dir_usable(dir)?;
        let db = Database::open(dir).map_err(|e| NativeError::from_storage_in(e, dir))?;
        let graph = Self::lifecycle_graph()?;
        // Prove activation against the expected lifecycle graph before
        // reporting readiness: a store without it is not our lifecycle.
        let recovery = db.recovery_info();
        let shared = Arc::new(Shared {
            db: Mutex::new(db),
            dir: dir.to_path_buf(),
            settings,
            graph,
            gate: AdmissionGate::new(settings.bounds.max_inflight),
        });
        let handle = NativeHandle { shared };
        let report = handle.open_report(recovery)?;
        Ok((handle, report))
    }

    /// Execute one GQL statement as one implicit transaction and return its
    /// committed outcome. The session never escapes the call, so no caller
    /// can retain the writer lease past the outcome.
    pub fn execute(&self, statement: &str) -> Result<ExecReport, NativeError> {
        if statement.is_empty() {
            return Err(NativeError::invalid_input(
                "statement",
                "must not be empty".to_string(),
            ));
        }
        let statement_bytes = statement.len();
        if statement_bytes > self.shared.settings.bounds.max_statement_bytes {
            return Err(NativeError::ResourceLimit {
                detail: format!(
                    "statement is {statement_bytes} bytes; maximum is {} (refused before promise)",
                    self.shared.settings.bounds.max_statement_bytes
                ),
            });
        }
        let _admission = self.shared.gate.try_enter()?;
        self.check_store_ceiling()?;
        let db = self.clone_db()?;
        let outcome = db
            .session(&self.shared.graph)
            .map_err(NativeError::from_statement)?
            .execute(statement)
            .map_err(NativeError::from_statement)?;
        Ok(ExecReport {
            statement_bytes,
            row_count: outcome.row_count(),
            changes: outcome.write_summary().map(|s| s.change_count()),
        })
    }

    /// Hold the serial write reservation through full image encoding and
    /// durable selection. Held reader views stay valid; foreground writes
    /// wait inside Selene; facade admission stays narrow (clone outside the
    /// lock). Never auto-prunes: call [`Self::prune`] explicitly.
    pub fn checkpoint(&self) -> Result<CheckpointReport, NativeError> {
        let _admission = self.shared.gate.try_enter()?;
        self.check_store_ceiling()?;
        let db = self.clone_db()?;
        let outcome = db
            .checkpoint()
            .map_err(|e| NativeError::from_storage_in(e, &self.shared.dir))?;
        // Post-selection footprint is a measurement, never a sentinel: a
        // failed measure is a typed Io refusal (matching open_report and
        // check_store_ceiling), never 16 EiB (`u64::MAX`).
        let store_bytes_after =
            measure_store_bytes(&self.shared.dir).map_err(|message| NativeError::Io {
                path: self.shared.dir.display().to_string(),
                message,
            })?;
        Ok(CheckpointReport {
            generation: outcome.generation,
            snapshot: outcome.snapshot.clone(),
            bytes: outcome.bytes,
            digest_hex: hex32(&outcome.digest),
            store_bytes_after,
        })
    }

    /// Explicitly reclaim obsolete durable artifacts. Retains CURRENT, one
    /// previous completed checkpoint, all their dependencies and every
    /// active lease. Validation/durability errors occur before any deletion.
    pub fn prune(&self) -> Result<PruneReport, NativeError> {
        let _admission = self.shared.gate.try_enter()?;
        self.check_store_ceiling()?;
        let db = self.clone_db()?;
        let outcome = db
            .prune()
            .map_err(|e| NativeError::from_storage_in(e, &self.shared.dir))?;
        Ok(PruneReport {
            removed_count: outcome.removed.len(),
            removed_bytes: outcome.removed.iter().map(|a| a.bytes).sum(),
            retained: outcome
                .retained
                .iter()
                .map(|a| (a.artifact.name.clone(), format!("{:?}", a.reason)))
                .collect(),
            cleanup_error: outcome.cleanup_error.map(|e| format!("{e:?}")),
        })
    }

    /// One maintenance pass: checkpoint, then prune. Committed evidence is
    /// preserved across the pass (asserted across restarts by tests).
    pub fn maintain(&self) -> Result<MaintenanceOutcome, NativeError> {
        let checkpoint = self.checkpoint()?;
        let prune = self.prune()?;
        Ok(MaintenanceOutcome { checkpoint, prune })
    }

    /// Readiness + native presence for this handle.
    pub fn readiness(&self) -> Readiness {
        let db = self.shared.db.lock();
        match db {
            Ok(db) => {
                let mode = if db.open_mode() == selene_db::OpenMode::Durable {
                    "durable"
                } else {
                    "memory"
                };
                match db.durable_status() {
                    Some(status) if mode == "durable" && !status.fenced => Readiness {
                        ready: true,
                        reason: format!(
                            "{FORMAT_ID} @ {SELENE_REV} ready: durable boundary {}",
                            status.position_digest_hint(),
                        ),
                        format_id: FORMAT_ID,
                        selene_rev: SELENE_REV,
                        mode,
                        fenced: false,
                    },
                    Some(status) => Readiness {
                        ready: false,
                        reason: format!(
                            "{FORMAT_ID} @ {SELENE_REV} not ready: fenced owner, drop every handle and reopen"
                        ),
                        format_id: FORMAT_ID,
                        selene_rev: SELENE_REV,
                        mode,
                        fenced: status.fenced,
                    },
                    None => Readiness {
                        ready: false,
                        reason: format!(
                            "{FORMAT_ID} @ {SELENE_REV} not ready: no durable boundary established"
                        ),
                        format_id: FORMAT_ID,
                        selene_rev: SELENE_REV,
                        mode,
                        fenced: false,
                    },
                }
            }
            Err(_) => Readiness {
                ready: false,
                reason: format!("{FORMAT_ID} @ {SELENE_REV} not ready: owner lock poisoned"),
                format_id: FORMAT_ID,
                selene_rev: SELENE_REV,
                mode: "unknown",
                fenced: false,
            },
        }
    }

    /// Close the store: consume the last facade owner and return the
    /// directory authority for a later [`ClosedStore::open`]. All sessions
    /// minted by this handle are already dropped (they never escape a
    /// call), so dropping this handle releases the writer lease.
    pub fn close(self) -> ClosedStore {
        ClosedStore {
            dir: self.shared.dir.clone(),
            settings: self.shared.settings,
        }
    }

    /// Borrow the enforced settings.
    pub fn settings(&self) -> NativeSettings {
        self.shared.settings
    }

    /// Borrow the store directory.
    pub fn dir(&self) -> &Path {
        &self.shared.dir
    }

    fn clone_db(&self) -> Result<Database, NativeError> {
        // Narrow locking: hold the facade mutex for the Arc clone only.
        self.lock_db(|db| db.clone())
    }

    fn lock_db<T>(&self, with: impl FnOnce(&Database) -> T) -> Result<T, NativeError> {
        match self.shared.db.lock() {
            Ok(guard) => Ok(with(&guard)),
            Err(_) => Err(NativeError::Lifecycle {
                phase: "Facade".to_string(),
                kind: "OwnerLockPoisoned".to_string(),
                detail: "native owner lock poisoned; drop every handle and reopen".to_string(),
            }),
        }
    }

    fn open_report(
        &self,
        recovery: Option<selene_db::RecoveryInfo>,
    ) -> Result<OpenReport, NativeError> {
        let (mode, position, digest_hex, fenced) = self.lock_db(|db| {
            let mode = if db.open_mode() == selene_db::OpenMode::Durable {
                "durable"
            } else {
                "memory"
            };
            match db.durable_status() {
                Some(status) => (
                    mode,
                    format!("{:?}", status.position),
                    hex32(&status.digest),
                    status.fenced,
                ),
                None => (mode, "none".to_string(), "none".to_string(), false),
            }
        })?;
        // Activation proof: resolve the lifecycle graph before reporting.
        // A foreign-but-valid format-2 store without it is quarantine-class
        // (Integrity), never statement-rejected: reserve StatementRejected
        // for execute()-time outcomes.
        let db = self.clone_db()?;
        db.session(&self.shared.graph)
            .map_err(NativeError::from_activation)?;
        Ok(OpenReport {
            dir: self.shared.dir.display().to_string(),
            format_id: FORMAT_ID,
            channel: CHANNEL_IDENTITY,
            selene_rev: SELENE_REV,
            selene_crate: SELENE_CRATE_VERSION,
            mode,
            store_bytes: self.measure_or_refuse()?,
            position,
            digest_hex,
            fenced,
            recovery: recovery.map(|info| RecoverySummary {
                snapshot_elapsed: info.snapshot_elapsed,
                wal_elapsed: info.wal_elapsed,
                rebuild_elapsed: info.rebuild_elapsed,
                synchronize_elapsed: info.synchronize_elapsed,
                verified_prefix_records: info.verified_prefix_records,
                replayed_suffix_records: info.replayed_suffix_records,
                rebuilt_indexes: info.rebuilt_indexes,
            }),
            settings: self.shared.settings,
        })
    }

    fn check_store_ceiling(&self) -> Result<(), NativeError> {
        self.measure_or_refuse().map(|_| ())
    }

    fn measure_or_refuse(&self) -> Result<u64, NativeError> {
        let bytes = measure_store_bytes(&self.shared.dir).map_err(|e| NativeError::Io {
            path: self.shared.dir.display().to_string(),
            message: e,
        })?;
        if bytes > self.shared.settings.bounds.max_store_bytes {
            return Err(NativeError::ResourceLimit {
                detail: format!(
                    "store footprint is {bytes} bytes; maximum is {} (refused before promise)",
                    self.shared.settings.bounds.max_store_bytes
                ),
            });
        }
        Ok(bytes)
    }

    fn check_dir_usable(dir: &Path) -> Result<(), NativeError> {
        if !dir.is_dir() {
            return Err(NativeError::Io {
                path: dir.display().to_string(),
                message: "store directory does not exist (create it first; the facade creates no directories)".to_string(),
            });
        }
        // Atomically create a probe that this call owns. Never truncate or
        // follow a pre-existing probe path (including a dangling symlink).
        // A collision is a refusal, not permission to remove someone else's
        // artifact. The directory must still be trusted against concurrent
        // hostile replacement; this is not a general filesystem sandbox.
        let probe = dir.join(".verdant-write-probe");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
            .map_err(|e| NativeError::Io {
                path: probe.display().to_string(),
                message: format!("cannot create a fresh writability probe: {e}"),
            })?;
        drop(file);
        std::fs::remove_file(&probe).map_err(|e| NativeError::Io {
            path: probe.display().to_string(),
            message: format!("cannot remove the probe created by this call: {e}"),
        })
    }

    fn lifecycle_graph() -> Result<ObjectPath, NativeError> {
        ObjectPath::regular(
            LIFECYCLE_SCHEMA_CATALOG,
            LIFECYCLE_SCHEMA_NAME,
            LIFECYCLE_GRAPH_NAME,
        )
        .map_err(|e| {
            NativeError::invalid_input(
                "lifecycle-graph",
                format!("frozen lifecycle graph path rejected: {e:?}"),
            )
        })
    }

    fn init_lifecycle(db: &Database) -> Result<ObjectPath, NativeError> {
        let schema =
            SchemaPath::regular(LIFECYCLE_SCHEMA_CATALOG, LIFECYCLE_SCHEMA_NAME).map_err(|e| {
                NativeError::invalid_input(
                    "lifecycle-schema",
                    format!("frozen lifecycle schema path rejected: {e:?}"),
                )
            })?;
        db.catalog()
            .create_schema(&schema, CreatePolicy::Strict)
            .map_err(NativeError::from_activation)?;
        let graph = Self::lifecycle_graph()?;
        db.catalog()
            .create_graph(&graph, None, CreatePolicy::Strict)
            .map_err(NativeError::from_activation)?;
        Ok(graph)
    }
}

/// Measure the on-disk footprint of a store directory (all regular files,
/// recursively, including lock/manifest files: the disclosed mapping is the
/// whole directory, not a selected subset).
fn measure_store_bytes(dir: &Path) -> Result<u64, String> {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let entries = std::fs::read_dir(&next).map_err(|e| format!("read_dir: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
            let kind = entry.file_type().map_err(|e| format!("file type: {e}"))?;
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_file() {
                let len = entry
                    .metadata()
                    .map_err(|e| format!("metadata: {e}"))?
                    .len();
                total = total.saturating_add(len);
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod probe_tests;
