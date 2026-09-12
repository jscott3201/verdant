//! M01-PR03 SQLite backend: tiny outbox over the system `sqlite3` CLI.
//!
//! Std-only envelope (`std::process`): one invocation is one connection. Every
//! invocation sets `busy_timeout` + `synchronous=FULL` + `foreign_keys=ON` +
//! `journal_mode=WAL` and then re-reads all four plus `user_version` in-band
//! between `VERDANT_BEGIN` / `VERDANT_DATA` / `VERDANT_END` sentinels, so the
//! recorded [`ConnectionSettings`](super::ConnectionSettings) are verified per
//! connection and never inferred from another connection. A mismatch is a
//! typed refusal.
//!
//! Text-shape contract of one invocation (list mode, `\x1f` column separator;
//! all stored text travels through SQL `quote()` and is unquoted in Rust):
//!
//! ```text
//! <pragma chatter, ignored>
//! VERDANT_BEGIN
//! <user_version>            (must be 0001 generation: "1")
//! <journal_mode>            (must be "wal")
//! <synchronous>             (must be "2" = FULL)
//! <foreign_keys>            (must be "1")
//! <busy_timeout>            (must be the recorded milliseconds)
//! VERDANT_DATA
//! <body rows...>
//! VERDANT_END
//! ```

use super::{ConnectionSettings, StorageError, StoreBounds, SCHEMA_GENERATION};
use crate::domain::clock::{TimeTriple, UnixMillis};
use crate::domain::ids::{InstalledId, OperationId, SourceGenerationId};
use crate::domain::outcomes::RecordIdentity;
use crate::domain::values::{Unit, Value};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Column separator for the CLI envelope (unit separator; excluded from
/// validated id alphabets and escaped inside stored JSON).
const COL_SEP: char = '\x1f';

const SENT_BEGIN: &str = "VERDANT_BEGIN";
const SENT_DATA: &str = "VERDANT_DATA";
const SENT_END: &str = "VERDANT_END";

/// Bounded writer-lock retries after `SQLITE_BUSY` (explicit, not silent).
const BUSY_RETRIES: u32 = 5;
const BUSY_RETRY_PAUSE_MS: u64 = 25;

/// Claim lifecycle; exhaustive so new states break the build, not behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxStatus {
    Queued,
    Claimed,
    Acked,
}

impl OutboxStatus {
    fn as_str(self) -> &'static str {
        match self {
            OutboxStatus::Queued => "queued",
            OutboxStatus::Claimed => "claimed",
            OutboxStatus::Acked => "acked",
        }
    }

    fn parse(raw: &str) -> Result<OutboxStatus, StorageError> {
        match raw {
            "queued" => Ok(OutboxStatus::Queued),
            "claimed" => Ok(OutboxStatus::Claimed),
            "acked" => Ok(OutboxStatus::Acked),
            other => Err(StorageError::InvalidRecord {
                detail: format!("unknown outbox status '{other}'"),
            }),
        }
    }
}

/// One decoded outbox row: domain types only, never raw strings outward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    /// SQLite row id (ordering + claim addressing; not a domain identity).
    pub id: i64,
    /// Business operation identity (reconciliation key).
    pub operation: OperationId,
    /// Installed equipment the operation describes.
    pub entity: InstalledId,
    /// Installed sensor source.
    pub sensor: InstalledId,
    /// Scalar value (exact, missing, or diagnostic).
    pub value: Value,
    /// Engineering unit (known or preserved unknown).
    pub unit: Unit,
    /// Source/receipt/ingestion triple.
    pub times: TimeTriple,
    /// Record identity (generation + sequence).
    pub record: RecordIdentity,
    /// Claim lifecycle state.
    pub status: OutboxStatus,
    /// Handoff token owning the claim (`None` when never claimed).
    pub claimed_by: Option<String>,
}

/// A claimed-but-unacked row: dangling work reported honestly on restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DanglingClaim {
    /// SQLite row id.
    pub id: i64,
    /// Business operation identity.
    pub operation: OperationId,
    /// Token owning the dangling claim.
    pub claimed_by: String,
}

/// Restart / inspection report: unclean state is listed, never silently fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreReport {
    /// Schema generation actually read back (`PRAGMA user_version`).
    pub schema_generation: u32,
    /// Recorded per-connection settings string.
    pub settings_recorded: String,
    /// Exact `sqlite3 --version` output.
    pub sqlite_version: String,
    /// Claimed-but-unacked rows (dangling prepared work).
    pub dangling: Vec<DanglingClaim>,
    /// Entities with dirty derived marks.
    pub dirty_entities: Vec<String>,
    /// Current `-wal` file size in bytes (0 when absent).
    pub wal_size_bytes: u64,
    /// Current main DB file size in bytes.
    pub db_size_bytes: u64,
    /// Effective `journal_size_limit` read back.
    pub journal_size_limit_bytes: u64,
    /// Queued row count.
    pub queued: u64,
    /// Claimed row count.
    pub claimed: u64,
    /// Acknowledged row count.
    pub acked: u64,
}

/// Report returned by [`SqliteStore::open`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReport {
    /// Fresh install (`true`) vs existing generation-0001 database (`false`).
    pub fresh: bool,
    /// Unclean-state report observed at open (before any caller mutation).
    pub store: StoreReport,
    /// DB file permission mode bits (`None` on non-unix targets).
    pub file_mode: Option<u32>,
    /// DB file owner uid (`None` on non-unix targets).
    pub file_uid: Option<u32>,
}

/// Checkpoint outcome: only checkpointed content is protected afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointReport {
    /// `1` when another connection blocked the checkpoint, else `0`.
    pub busy: i64,
    /// WAL frames present.
    pub log_frames: i64,
    /// WAL frames checkpointed into the main database.
    pub checkpointed_frames: i64,
}

/// Bounded replay outcome: the horizon is finite and explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    /// Rows actually served (capped by `max_replay_rows`).
    pub rows: Vec<OutboxRow>,
    /// Rows requested by the caller.
    pub requested: u32,
    /// Rows served.
    pub served: u32,
    /// `true` when the request exceeded the finite horizon.
    pub truncated: bool,
}

/// Report returned by [`SqliteStore::close`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseReport {
    /// Final checkpoint outcome.
    pub checkpoint: CheckpointReport,
    /// Final `-wal` size in bytes.
    pub wal_size_bytes: u64,
    /// Final DB size in bytes.
    pub db_size_bytes: u64,
}

#[derive(Debug)]
struct Inner {
    db_path: PathBuf,
    settings: ConnectionSettings,
    bounds: StoreBounds,
    sqlite_version: String,
    /// In-process handle budget for this store family (see `try_clone`).
    handles: AtomicU32,
    /// Last operator checkpoint (epoch seconds; 0 = never this process).
    last_checkpoint_epoch_secs: AtomicU64,
}

/// Tiny SQLite outbox handle. `Clone` shares one budget family; every method
/// call spawns short-lived `sqlite3` connections (never a held-open writer),
/// so handles are `Send + Sync` and concurrent writers serialize in SQLite.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    inner: Arc<Inner>,
}

impl SqliteStore {
    /// Open (or freshly initialize) the database at `db_path`.
    ///
    /// Refuses — never silently drops — when the parent directory is missing
    /// or unwritable, when `sqlite3` is unavailable, when the recorded
    /// durability settings are not honored, or when the schema generation is
    /// anything but 0001. Existing unclean state is reported, not repaired.
    pub fn open(
        db_path: &Path,
        settings: ConnectionSettings,
        bounds: StoreBounds,
    ) -> Result<(SqliteStore, OpenReport), StorageError> {
        let parent = db_path
            .parent()
            .ok_or_else(|| StorageError::UnwritablePath {
                path: db_path.display().to_string(),
                reason: "database path has no parent directory".to_string(),
            })?;
        if !parent.is_dir() {
            return Err(StorageError::UnwritablePath {
                path: db_path.display().to_string(),
                reason: "parent directory is missing (the store never creates it implicitly)"
                    .to_string(),
            });
        }
        if db_path.exists() && db_path.is_dir() {
            return Err(StorageError::UnwritablePath {
                path: db_path.display().to_string(),
                reason: "database path exists but is a directory".to_string(),
            });
        }
        // Honest writability probe: create + remove one probe file. A
        // read-only directory refuses here with a typed error.
        let probe = parent.join(format!(".verdant-write-probe-{}", std::process::id()));
        match std::fs::write(&probe, b"probe") {
            Ok(()) => {
                let _ = std::fs::remove_file(&probe);
            }
            Err(e) => {
                if parent_permissions_readonly(parent) {
                    return Err(StorageError::ReadOnlyPath {
                        path: parent.display().to_string(),
                    });
                }
                return Err(StorageError::UnwritablePath {
                    path: db_path.display().to_string(),
                    reason: e.to_string(),
                });
            }
        }

        let sqlite_version = sqlite_version()?;
        let preexisting = db_path.exists();
        let found_generation = read_user_version(db_path)?;
        let fresh = found_generation == 0;
        if found_generation != 0 && found_generation != SCHEMA_GENERATION {
            return Err(StorageError::SchemaMismatch {
                expected: SCHEMA_GENERATION,
                found: found_generation.to_string(),
            });
        }
        // Fresh install: apply the reserved migration, stamp the generation,
        // record the change note. Existing 0001 databases re-apply the same
        // idempotent file (IF NOT EXISTS) and re-verify objects.
        apply_migration(db_path)?;
        write_user_version(db_path, SCHEMA_GENERATION)?;
        record_migration_note(db_path)?;
        verify_schema_objects(db_path)?;
        // No persistent durability setup lives outside the envelope:
        // journal_size_limit included — every connection sets and re-reads
        // the full settings block in-band (see envelope_script).

        let store = SqliteStore {
            inner: Arc::new(Inner {
                db_path: db_path.to_path_buf(),
                settings,
                bounds,
                sqlite_version: sqlite_version.clone(),
                handles: AtomicU32::new(1),
                last_checkpoint_epoch_secs: AtomicU64::new(0),
            }),
        };
        // Full per-connection verification before acknowledging the open.
        store.exec_verified("SELECT 1;", false)?;
        let report = store.report()?;
        let (file_mode, file_uid) = db_file_identity(db_path);
        Ok((
            store,
            OpenReport {
                fresh: fresh || !preexisting,
                store: StoreReport {
                    sqlite_version,
                    ..report
                },
                file_mode,
                file_uid,
            },
        ))
    }

    /// Clone within the in-process handle budget (`max_connections`).
    /// Cross-process/file-lock isolation stays with SQLite (busy timeout);
    /// this budget only caps handles in this process family.
    pub fn try_clone(&self) -> Result<SqliteStore, StorageError> {
        let mut current = self.inner.handles.load(Ordering::SeqCst);
        loop {
            if current >= self.inner.bounds.max_connections {
                return Err(StorageError::TooManyConnections {
                    max: self.inner.bounds.max_connections,
                });
            }
            match self.inner.handles.compare_exchange_weak(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Ok(SqliteStore {
                        inner: Arc::clone(&self.inner),
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Database file path (synthetic temp paths in tests; never a repo path).
    pub fn db_path(&self) -> &Path {
        &self.inner.db_path
    }

    /// Schema generation this handle is bound to (always 0001 here).
    pub fn schema_generation(&self) -> u32 {
        SCHEMA_GENERATION
    }

    /// Recorded per-connection settings.
    pub fn settings(&self) -> &ConnectionSettings {
        &self.inner.settings
    }

    /// Explicit bounds.
    pub fn bounds(&self) -> &StoreBounds {
        &self.inner.bounds
    }

    /// Exact `sqlite3` version string observed at open.
    pub fn sqlite_version(&self) -> &str {
        &self.inner.sqlite_version
    }

    /// Insert one outbox row and dirty-mark the entity, atomically in one
    /// connection. Small duplicate rows under concurrent writers are stored as
    /// separate rows (tolerated + counted, never merged).
    ///
    /// Refuses when the payload exceeds `max_value_bytes`, when maintenance is
    /// due, or when the synthetic space budget would be exceeded — before any
    /// write, so a refusal never leaves a partial row.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &self,
        operation: &OperationId,
        entity: &InstalledId,
        sensor: &InstalledId,
        value: &Value,
        unit: &Unit,
        times: TimeTriple,
        record: &RecordIdentity,
    ) -> Result<i64, StorageError> {
        let value_json = value.to_json();
        if value_json.len() > self.inner.bounds.max_value_bytes {
            return Err(StorageError::ValueTooLarge {
                len: value_json.len(),
                max: self.inner.bounds.max_value_bytes,
            });
        }
        if let Some(reason) = self.maintenance_reason() {
            return Err(StorageError::MaintenanceRequired { detail: reason });
        }
        let projected = self.db_size_bytes() + value_json.len() as u64;
        if projected > self.inner.bounds.max_db_bytes {
            return Err(StorageError::SpaceExhausted {
                detail: format!(
                    "synthetic space budget: db {} bytes + {} payload bytes exceeds max_db_bytes {}",
                    self.db_size_bytes(),
                    value_json.len(),
                    self.inner.bounds.max_db_bytes
                ),
            });
        }
        self.check_generation()?;
        let body = format!(
            "INSERT INTO outbox(operation, entity, sensor, value_json, unit, source_ms, receipt_ms, ingestion_ms, generation, seq, status, claimed_by, created_nanos) VALUES ({op}, {entity}, {sensor}, {value}, {unit}, {source}, {receipt}, {ingestion}, {generation}, {seq}, 'queued', NULL, {now}); SELECT last_insert_rowid(); INSERT INTO derived_marks(entity, dirty, checked_generation) VALUES ({entity}, 1, 0) ON CONFLICT(entity) DO UPDATE SET dirty = 1; SELECT changes();",
            op = sql_quote(operation.as_str()),
            entity = sql_quote(entity.as_str()),
            sensor = sql_quote(sensor.as_str()),
            value = sql_quote(&value_json),
            unit = sql_quote(unit.as_str()),
            source = sql_quote(&times.source().as_millis().to_string()),
            receipt = sql_quote(&times.receipt().as_millis().to_string()),
            ingestion = sql_quote(&times.ingestion().as_millis().to_string()),
            generation = sql_quote(record.generation().as_str()),
            seq = sql_quote(&record.seq().to_string()),
            now = sql_quote(&epoch_nanos_now()),
        );
        let out = self.exec_verified(&body, true)?;
        match out.body_rows.first() {
            Some(cols) if !cols.is_empty() => {
                cols[0]
                    .parse::<i64>()
                    .map_err(|_| StorageError::SqliteFailure {
                        detail: format!("last_insert_rowid unreadable: '{}'", cols.join(",")),
                    })
            }
            _ => Err(StorageError::SqliteFailure {
                detail: "insert returned no row id".to_string(),
            }),
        }
    }

    /// Claim up to `limit` queued rows for `claimed_by`, oldest first.
    /// The limit is clamped to the finite replay horizon (`max_replay_rows`).
    /// Concurrent claimants split the queue; each row goes to exactly one
    /// winner (single atomic `UPDATE ... RETURNING`).
    pub fn claim_queued(
        &self,
        limit: u32,
        claimed_by: &str,
    ) -> Result<Vec<OutboxRow>, StorageError> {
        if limit == 0 {
            return Err(StorageError::InvalidInput {
                what: "claim limit",
                detail: "limit must be at least 1".to_string(),
            });
        }
        let token = validate_token(claimed_by)?;
        let effective = limit.min(self.inner.bounds.max_replay_rows).max(1);
        self.check_generation()?;
        let body = format!(
            "UPDATE outbox SET status = 'claimed', claimed_by = {token} WHERE id IN (SELECT id FROM outbox WHERE status = 'queued' ORDER BY id LIMIT {effective}) RETURNING id, quote(operation), quote(entity), quote(sensor), quote(value_json), quote(unit), quote(source_ms), quote(receipt_ms), quote(ingestion_ms), quote(generation), quote(seq), quote(status), quote(claimed_by);",
            token = sql_quote(&token),
        );
        let out = self.exec_verified(&body, true)?;
        out.body_rows.iter().map(|cols| decode_row(cols)).collect()
    }

    /// Acknowledge a claimed row. The token must match the claim owner and the
    /// row must be claimed: zero affected rows is [`StorageError::Conflict`],
    /// never success (double acknowledge, foreign token, or unknown id).
    pub fn acknowledge(&self, id: i64, expected_token: &str) -> Result<(), StorageError> {
        let token = validate_token(expected_token)?;
        self.check_generation()?;
        let body = format!(
            "UPDATE outbox SET status = 'acked' WHERE id = {id} AND status = 'claimed' AND claimed_by = {token}; SELECT changes();",
            token = sql_quote(&token),
        );
        let changed = self.exec_changes(&body)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StorageError::Conflict {
                detail: format!(
                    "acknowledge id {id}: zero affected rows (not claimed by this token)"
                ),
            })
        }
    }

    /// Explicitly requeue a dangling (claimed, unacked) row back to queued.
    /// This is the only path that clears a dangling claim: reopen never does
    /// it silently. Zero affected rows is a conflict.
    pub fn requeue_claim(&self, id: i64, expected_token: &str) -> Result<(), StorageError> {
        let token = validate_token(expected_token)?;
        self.check_generation()?;
        let body = format!(
            "UPDATE outbox SET status = 'queued', claimed_by = NULL WHERE id = {id} AND status = 'claimed' AND claimed_by = {token}; SELECT changes();",
            token = sql_quote(&token),
        );
        let changed = self.exec_changes(&body)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StorageError::Conflict {
                detail: format!(
                    "requeue id {id}: zero affected rows (not dangling under this token)"
                ),
            })
        }
    }

    /// Bounded replay of queued rows (oldest first) with an explicit
    /// truncation flag when the request exceeds the finite horizon.
    /// Corrupt rows are refused as [`StorageError::InvalidRecord`], never coerced.
    pub fn replay_queued(&self, limit: u32) -> Result<ReplayReport, StorageError> {
        if limit == 0 {
            return Err(StorageError::InvalidInput {
                what: "replay limit",
                detail: "limit must be at least 1".to_string(),
            });
        }
        let effective = limit.min(self.inner.bounds.max_replay_rows).max(1);
        let body = format!(
            "SELECT COUNT(*) FROM outbox WHERE status = 'queued'; SELECT id, quote(operation), quote(entity), quote(sensor), quote(value_json), quote(unit), quote(source_ms), quote(receipt_ms), quote(ingestion_ms), quote(generation), quote(seq), quote(status), quote(claimed_by) FROM outbox WHERE status = 'queued' ORDER BY id LIMIT {effective};",
        );
        let out = self.exec_verified(&body, false)?;
        let mut lines = out.body_rows.iter();
        let total: u64 = lines
            .next()
            .and_then(|cols| cols.first().map(String::as_str))
            .unwrap_or("0")
            .parse::<u64>()
            .unwrap_or(0);
        let mut rows = Vec::new();
        for cols in lines {
            rows.push(decode_row(cols)?);
        }
        let served = rows.len() as u32;
        let _ = total;
        Ok(ReplayReport {
            rows,
            requested: limit,
            served,
            truncated: limit > effective,
        })
    }

    /// Claimed-but-unacked rows. Reported honestly; never silently requeued.
    pub fn dangling_claims(&self) -> Result<Vec<DanglingClaim>, StorageError> {
        let body = "SELECT id, quote(operation), quote(claimed_by) FROM outbox WHERE status = 'claimed' ORDER BY id;";
        let out = self.exec_verified(body, false)?;
        let mut dangling = Vec::new();
        for cols in &out.body_rows {
            if cols.len() != 3 {
                return Err(StorageError::InvalidRecord {
                    detail: format!("dangling row has {} columns, expected 3", cols.len()),
                });
            }
            let id = cols[0]
                .parse::<i64>()
                .map_err(|_| StorageError::InvalidRecord {
                    detail: format!("dangling id unreadable: '{}'", cols[0]),
                })?;
            let operation_raw =
                unquote_text(&cols[1])?.ok_or_else(|| StorageError::InvalidRecord {
                    detail: "dangling operation is NULL".to_string(),
                })?;
            let operation =
                OperationId::parse(&operation_raw).map_err(|e| StorageError::InvalidRecord {
                    detail: format!("dangling operation invalid: {e}"),
                })?;
            let claimed_by =
                unquote_text(&cols[2])?.ok_or_else(|| StorageError::InvalidRecord {
                    detail: "dangling claim without a token".to_string(),
                })?;
            dangling.push(DanglingClaim {
                id,
                operation,
                claimed_by,
            });
        }
        Ok(dangling)
    }

    /// Entities whose derived quantities are still dirty.
    pub fn dirty_entities(&self) -> Result<Vec<String>, StorageError> {
        let body = "SELECT quote(entity) FROM derived_marks WHERE dirty = 1 ORDER BY entity;";
        let out = self.exec_verified(body, false)?;
        let mut entities = Vec::new();
        for cols in &out.body_rows {
            if cols.len() != 1 {
                return Err(StorageError::InvalidRecord {
                    detail: "dirty-mark row has an unexpected shape".to_string(),
                });
            }
            let entity = unquote_text(&cols[0])?.ok_or_else(|| StorageError::InvalidRecord {
                detail: "dirty-mark entity is NULL".to_string(),
            })?;
            entities.push(entity);
        }
        Ok(entities)
    }

    /// Checked recalculation: clears the dirty flag only for the current
    /// schema generation. A stale generation is refused and the flag stays
    /// dirty; an unknown entity is a conflict.
    pub fn mark_recalculated(
        &self,
        entity: &InstalledId,
        generation: u32,
    ) -> Result<(), StorageError> {
        if generation != SCHEMA_GENERATION {
            return Err(StorageError::InvalidInput {
                what: "recalculation generation",
                detail: format!(
                    "checked recalculation requires generation {SCHEMA_GENERATION:04}, got {generation:04}; dirty flag preserved"
                ),
            });
        }
        self.check_generation()?;
        let body = format!(
            "UPDATE derived_marks SET dirty = 0, checked_generation = {generation} WHERE entity = {entity}; SELECT changes();",
            entity = sql_quote(entity.as_str()),
        );
        let changed = self.exec_changes(&body)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StorageError::Conflict {
                detail: format!(
                    "no derived mark for '{}': nothing recalculated",
                    entity.as_str()
                ),
            })
        }
    }

    /// Current restart-honest report: dangling claims, dirty entities, WAL and
    /// DB sizes, lifecycle counts. Never repairs anything.
    pub fn report(&self) -> Result<StoreReport, StorageError> {
        let body = "SELECT COUNT(*) FROM outbox WHERE status = 'queued'; SELECT COUNT(*) FROM outbox WHERE status = 'claimed'; SELECT COUNT(*) FROM outbox WHERE status = 'acked';";
        let out = self.exec_verified(body, false)?;
        let mut counts = [0u64; 3];
        for (index, cols) in out.body_rows.iter().take(3).enumerate() {
            counts[index] = cols
                .first()
                .map(String::as_str)
                .unwrap_or("0")
                .parse::<u64>()
                .unwrap_or(0);
        }
        Ok(StoreReport {
            schema_generation: out.verified.generation,
            settings_recorded: self.inner.settings.to_string(),
            sqlite_version: self.inner.sqlite_version.clone(),
            dangling: self.dangling_claims()?,
            dirty_entities: self.dirty_entities()?,
            wal_size_bytes: self.wal_size_bytes(),
            db_size_bytes: self.db_size_bytes(),
            journal_size_limit_bytes: out.verified.journal_size_limit_bytes,
            queued: counts[0],
            claimed: counts[1],
            acked: counts[2],
        })
    }

    /// Operator checkpoint (`TRUNCATE`): protects only checkpointed content.
    /// The uncheckpointed WAL tail and dirty derived marks are unaffected —
    /// a checkpoint is byte durability, not derived correctness.
    pub fn checkpoint(&self) -> Result<CheckpointReport, StorageError> {
        let body = "PRAGMA wal_checkpoint(TRUNCATE);";
        let out = self.exec_verified(body, false)?;
        let cols = out
            .body_rows
            .first()
            .ok_or_else(|| StorageError::SqliteFailure {
                detail: "wal_checkpoint returned no row".to_string(),
            })?;
        if cols.len() != 3 {
            return Err(StorageError::SqliteFailure {
                detail: format!(
                    "wal_checkpoint returned {} columns, expected 3 (busy|log|checkpointed)",
                    cols.len()
                ),
            });
        }
        let parse = |index: usize| {
            cols[index]
                .parse::<i64>()
                .map_err(|_| StorageError::SqliteFailure {
                    detail: format!(
                        "wal_checkpoint column {index} unreadable: '{}'",
                        cols[index]
                    ),
                })
        };
        let report = CheckpointReport {
            busy: parse(0)?,
            log_frames: parse(1)?,
            checkpointed_frames: parse(2)?,
        };
        if report.busy == 0 {
            self.inner
                .last_checkpoint_epoch_secs
                .store(epoch_secs_now(), Ordering::SeqCst);
        }
        Ok(report)
    }

    /// `true` when the operator must run [`SqliteStore::checkpoint`] (or grow
    /// the synthetic budget) before further inserts are accepted.
    pub fn maintenance_required(&self) -> bool {
        self.maintenance_reason().is_some()
    }

    /// Explicit maintenance window in seconds (operator duty, not automatic).
    pub fn maintenance_window_secs(&self) -> u64 {
        self.inner.bounds.maintenance_window_secs
    }

    /// Current `-wal` file size in bytes (0 when absent).
    pub fn wal_size_bytes(&self) -> u64 {
        wal_path(&self.inner.db_path)
            .metadata()
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Current main DB file size in bytes (0 when missing).
    pub fn db_size_bytes(&self) -> u64 {
        self.inner.db_path.metadata().map(|m| m.len()).unwrap_or(0)
    }

    /// Run one `BEGIN; <statements>; COMMIT;` batch with `.bail on`.
    ///
    /// Operator / fault-injection seam: the first failing statement aborts the
    /// script, the connection closes without `COMMIT`, and SQLite rolls the
    /// batch back. A nonzero exit is [`StorageError::SqliteFailure`] and the
    /// caller must assume nothing in the batch committed.
    pub fn run_transaction(&self, statements: &[&str]) -> Result<(), StorageError> {
        if statements.is_empty() {
            return Err(StorageError::InvalidInput {
                what: "transaction",
                detail: "transaction requires at least one statement".to_string(),
            });
        }
        self.check_generation()?;
        let mut body = String::from("BEGIN; ");
        for statement in statements {
            body.push_str(statement);
            if !statement.trim_end().ends_with(';') {
                body.push(';');
            }
            body.push(' ');
        }
        body.push_str("COMMIT;");
        let out = self.exec_verified(&body, true)?;
        let _ = out;
        Ok(())
    }

    /// Run an arbitrary script body inside the verified envelope with
    /// `.bail on` (fault-injection seam: explicit `ROLLBACK`, corruption
    /// probes, generation tampering in tests). Returns raw body rows.
    pub fn exec_script(&self, script: &str) -> Result<Vec<Vec<String>>, StorageError> {
        if script.trim().is_empty() {
            return Err(StorageError::InvalidInput {
                what: "script",
                detail: "script must not be empty".to_string(),
            });
        }
        Ok(self.exec_verified(script, true)?.body_rows)
    }

    /// Checkpoint, then report final sizes. The handle budget slot is released
    /// when the returned value (and `self`) drops.
    pub fn close(&self) -> Result<CloseReport, StorageError> {
        let checkpoint = self.checkpoint()?;
        Ok(CloseReport {
            checkpoint,
            wal_size_bytes: self.wal_size_bytes(),
            db_size_bytes: self.db_size_bytes(),
        })
    }

    fn maintenance_reason(&self) -> Option<String> {
        if self.wal_size_bytes() > self.inner.bounds.max_wal_bytes {
            return Some(format!(
                "wal {} bytes exceeds max_wal_bytes {}: run checkpoint",
                self.wal_size_bytes(),
                self.inner.bounds.max_wal_bytes
            ));
        }
        if self.db_size_bytes() > self.inner.bounds.max_db_bytes {
            return Some(format!(
                "db {} bytes exceeds max_db_bytes {}: operator maintenance window is {} s",
                self.db_size_bytes(),
                self.inner.bounds.max_db_bytes,
                self.inner.bounds.maintenance_window_secs
            ));
        }
        None
    }

    fn check_generation(&self) -> Result<(), StorageError> {
        let found = read_user_version(&self.inner.db_path)?;
        if found != SCHEMA_GENERATION {
            return Err(StorageError::SchemaMismatch {
                expected: SCHEMA_GENERATION,
                found: found.to_string(),
            });
        }
        Ok(())
    }

    fn exec_changes(&self, body: &str) -> Result<i64, StorageError> {
        let out = self.exec_verified(body, true)?;
        out.body_rows
            .first()
            .and_then(|cols| cols.first())
            .and_then(|raw| raw.parse::<i64>().ok())
            .ok_or_else(|| StorageError::SqliteFailure {
                detail: "expected a single changes() row".to_string(),
            })
    }

    /// Run one verified envelope connection, with bounded `SQLITE_BUSY`
    /// retries. `mutating` selects the refusal wording only; verification is
    /// identical either way.
    fn exec_verified(&self, body: &str, mutating: bool) -> Result<VerifiedOutput, StorageError> {
        let mut attempt = 0;
        loop {
            match run_envelope(&self.inner.db_path, &self.inner.settings, body) {
                Ok(out) => return Ok(out),
                Err(StorageError::SqliteFailure { detail }) if is_busy_text(&detail) => {
                    attempt += 1;
                    if attempt > BUSY_RETRIES {
                        return Err(StorageError::Busy { detail });
                    }
                    std::thread::sleep(std::time::Duration::from_millis(BUSY_RETRY_PAUSE_MS));
                }
                Err(StorageError::SqliteFailure { detail }) => {
                    if is_readonly_text(&detail) {
                        return Err(StorageError::ReadOnlyPath {
                            path: self.inner.db_path.display().to_string(),
                        });
                    }
                    if is_unopenable_text(&detail) {
                        return Err(StorageError::UnwritablePath {
                            path: self.inner.db_path.display().to_string(),
                            reason: detail,
                        });
                    }
                    let _ = mutating;
                    return Err(StorageError::SqliteFailure { detail });
                }
                Err(other) => return Err(other),
            }
        }
    }
}

impl Drop for SqliteStore {
    fn drop(&mut self) {
        // Release this handle's budget slot. `inner` is an Arc: only the
        // counter matters here, never the database itself (durability is per
        // committed connection; dropping a handle commits nothing).
        self.inner.handles.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedSettings {
    generation: u32,
    journal_size_limit_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedOutput {
    verified: VerifiedSettings,
    body_rows: Vec<Vec<String>>,
}

fn envelope_script(settings: &ConnectionSettings, body: &str) -> String {
    format!(
        "PRAGMA busy_timeout = {timeout}; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA journal_size_limit = {wal_limit}; SELECT '{begin}'; PRAGMA user_version; PRAGMA journal_mode; PRAGMA synchronous; PRAGMA foreign_keys; PRAGMA busy_timeout; PRAGMA journal_size_limit; SELECT '{data}'; {body} SELECT '{end}';",
        timeout = settings.busy_timeout_ms,
        wal_limit = settings.journal_size_limit_bytes,
        begin = SENT_BEGIN,
        data = SENT_DATA,
        end = SENT_END,
        body = body,
    )
}

/// Feed one script to `sqlite3` on stdin (options + db on argv).
/// `.bail on` is always first so a failing statement aborts the script and
/// the connection closes without committing a partial batch.
fn run_script_stdin(
    db_path: &Path,
    extra_args: &[&str],
    script: &str,
) -> Result<Output, StorageError> {
    let mut child = Command::new("sqlite3")
        .args(extra_args)
        .arg(db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::MissingSqlite {
                    detail: "sqlite3 not found on PATH; system sqlite3 3.54.0 is required"
                        .to_string(),
                }
            } else {
                StorageError::Io {
                    path: db_path.display().to_string(),
                    message: format!("failed to spawn sqlite3: {e}"),
                }
            }
        })?;
    let full = format!(".bail on\n{script}\n");
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(full.as_bytes())
            .map_err(|e| StorageError::Io {
                path: db_path.display().to_string(),
                message: format!("failed to feed sqlite3 stdin: {e}"),
            })?;
        // Close stdin so the child observes EOF (flush happens on drop);
        // scripts are kilobytes, far below pipe-buffer deadlock territory.
    }
    child.wait_with_output().map_err(|e| StorageError::Io {
        path: db_path.display().to_string(),
        message: format!("failed to collect sqlite3 output: {e}"),
    })
}

fn run_envelope(
    db_path: &Path,
    settings: &ConnectionSettings,
    body: &str,
) -> Result<VerifiedOutput, StorageError> {
    let script = envelope_script(settings, body);
    let sep = COL_SEP.to_string();
    // Scripts travel on stdin, never argv: sqlite3 parses leading `-` argv
    // text as CLI options (migration headers start with `--`), while stdin
    // is always read as dot-commands/SQL.
    let output = run_script_stdin(db_path, &["-separator", &sep], &script)?;
    // Observed exit only: a stop (or pass) is never inferred from a timeout.
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let capped = truncate_text(&detail, 500);
        return Err(StorageError::SqliteFailure {
            detail: if capped.is_empty() {
                format!("sqlite3 exited with {}", output.status)
            } else {
                capped
            },
        });
    }
    let stdout = String::from_utf8(output.stdout).map_err(|e| StorageError::SqliteFailure {
        detail: format!("sqlite3 stdout is not UTF-8: {e}"),
    })?;
    parse_envelope(&stdout, settings)
}

fn parse_envelope(
    stdout: &str,
    settings: &ConnectionSettings,
) -> Result<VerifiedOutput, StorageError> {
    let lines: Vec<&str> = stdout
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
    let begin = lines
        .iter()
        .position(|line| *line == SENT_BEGIN)
        .ok_or_else(|| StorageError::SqliteFailure {
            detail: format!(
                "envelope markers missing (no {SENT_BEGIN}); stdout was: '{}'",
                truncate_text(stdout.trim(), 300)
            ),
        })?;
    let rest = &lines[begin + 1..];
    if rest.len() < 7 || rest[6] != SENT_DATA {
        return Err(StorageError::SqliteFailure {
            detail: "envelope verification block malformed".to_string(),
        });
    }
    let generation: u32 = rest[0]
        .parse::<u32>()
        .map_err(|_| StorageError::SqliteFailure {
            detail: format!("user_version unreadable: '{}'", rest[0]),
        })?;
    if generation != SCHEMA_GENERATION {
        return Err(StorageError::SchemaMismatch {
            expected: SCHEMA_GENERATION,
            found: rest[0].to_string(),
        });
    }
    let want = [
        settings.journal_mode,
        settings.synchronous_level,
        settings.foreign_keys,
        &settings.busy_timeout_ms.to_string(),
        &settings.journal_size_limit_bytes.to_string(),
    ];
    let labels = [
        "journal_mode",
        "synchronous",
        "foreign_keys",
        "busy_timeout",
        "journal_size_limit",
    ];
    for (index, (actual, expected)) in rest[1..6].iter().zip(want.iter()).enumerate() {
        if actual != expected {
            return Err(StorageError::DurabilityUnavailable {
                detail: format!(
                    "per-connection {} is '{actual}', required '{}' (recorded settings not honored)",
                    labels[index], expected
                ),
            });
        }
    }
    let tail = &rest[7..];
    let end = tail
        .iter()
        .position(|line| *line == SENT_END)
        .ok_or_else(|| StorageError::SqliteFailure {
            detail: format!("envelope markers missing (no {SENT_END})"),
        })?;
    let mut body_rows = Vec::new();
    for line in &tail[..end] {
        body_rows.push(line.split(COL_SEP).map(str::to_string).collect::<Vec<_>>());
    }
    let journal_size_limit_bytes =
        rest[5]
            .parse::<u64>()
            .map_err(|_| StorageError::SqliteFailure {
                detail: format!("journal_size_limit unreadable: '{}'", rest[5]),
            })?;
    Ok(VerifiedOutput {
        verified: VerifiedSettings {
            generation,
            journal_size_limit_bytes,
        },
        body_rows,
    })
}

fn decode_row(cols: &[String]) -> Result<OutboxRow, StorageError> {
    if cols.len() != 13 {
        return Err(StorageError::InvalidRecord {
            detail: format!("outbox row has {} columns, expected 13", cols.len()),
        });
    }
    let invalid = |what: &str| StorageError::InvalidRecord {
        detail: what.to_string(),
    };
    let id = cols[0]
        .parse::<i64>()
        .map_err(|_| invalid(&format!("row id unreadable: '{}'", cols[0])))?;
    let text = |index: usize, what: &str| {
        unquote_text(&cols[index])?.ok_or_else(|| invalid(&format!("{what} is NULL")))
    };
    let operation = OperationId::parse(&text(1, "operation")?)
        .map_err(|e| invalid(&format!("operation: {e}")))?;
    let entity =
        InstalledId::parse(&text(2, "entity")?).map_err(|e| invalid(&format!("entity: {e}")))?;
    let sensor =
        InstalledId::parse(&text(3, "sensor")?).map_err(|e| invalid(&format!("sensor: {e}")))?;
    let value =
        Value::from_json(&text(4, "value_json")?).map_err(|e| invalid(&format!("value: {e}")))?;
    let unit = Unit::parse(&text(5, "unit")?).map_err(|e| invalid(&format!("unit: {e}")))?;
    let millis = |index: usize, what: &str| {
        text(index, what)?
            .parse::<i64>()
            .map_err(|_| invalid(&format!("{what} is not an integer millis value")))
    };
    let times = TimeTriple::new(
        UnixMillis::new(millis(6, "source_ms")?),
        UnixMillis::new(millis(7, "receipt_ms")?),
        UnixMillis::new(millis(8, "ingestion_ms")?),
    )
    .map_err(|e| invalid(&format!("times: {e}")))?;
    let generation = SourceGenerationId::parse(&text(9, "generation")?)
        .map_err(|e| invalid(&format!("generation: {e}")))?;
    let seq = text(10, "seq")?
        .parse::<u64>()
        .map_err(|_| invalid("seq is not a u64"))?;
    let status =
        OutboxStatus::parse(&unquote_text(&cols[11])?.ok_or_else(|| invalid("status is NULL"))?)?;
    let claimed_by = unquote_text(&cols[12])?;
    Ok(OutboxRow {
        id,
        operation,
        entity,
        sensor,
        value,
        unit,
        times,
        record: RecordIdentity::new(generation, seq),
        status,
        claimed_by,
    })
}

/// SQL string literal quoting (`'` doubled). Backslashes need no special
/// handling in SQLite string literals.
fn sql_quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('\'');
    for ch in raw.chars() {
        if ch == '\'' {
            out.push_str("''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Decode a `quote()`-wrapped column: `NULL` (bare) becomes `None`, otherwise
/// the outer quotes are removed and `''` collapses to `'`.
fn unquote_text(raw: &str) -> Result<Option<String>, StorageError> {
    if raw == "NULL" {
        return Ok(None);
    }
    let inner = raw
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .ok_or_else(|| StorageError::InvalidRecord {
            detail: format!("quoted text malformed: '{raw}'"),
        })?;
    Ok(Some(inner.replace("''", "'")))
}

fn validate_token(raw: &str) -> Result<String, StorageError> {
    if raw.is_empty() {
        return Err(StorageError::InvalidInput {
            what: "claim token",
            detail: "token must not be empty".to_string(),
        });
    }
    if raw.len() > 128 {
        return Err(StorageError::InvalidInput {
            what: "claim token",
            detail: format!("token is {} chars; maximum is 128", raw.len()),
        });
    }
    Ok(raw.to_string())
}

fn sqlite_version() -> Result<String, StorageError> {
    let output = Command::new("sqlite3")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::MissingSqlite {
                    detail: "sqlite3 not found on PATH; system sqlite3 3.54.0 is required"
                        .to_string(),
                }
            } else {
                StorageError::Io {
                    path: "sqlite3 --version".to_string(),
                    message: format!("failed to spawn sqlite3: {e}"),
                }
            }
        })?;
    if !output.status.success() {
        return Err(StorageError::MissingSqlite {
            detail: format!("sqlite3 --version exited with {}", output.status),
        });
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !text.starts_with("3.") {
        return Err(StorageError::MissingSqlite {
            detail: format!("unsupported sqlite3 version: '{text}' (3.x required)"),
        });
    }
    Ok(text)
}

fn raw_pragma(db_path: &Path, pragma: &str) -> Result<String, StorageError> {
    // Same bounded busy-retry as the envelope: concurrent writers serialize
    // in SQLite, and a lone version read must wait its turn, not fail.
    let mut attempt = 0;
    loop {
        let output = Command::new("sqlite3")
            .arg(db_path)
            .arg(pragma)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| StorageError::Io {
                path: db_path.display().to_string(),
                message: format!("failed to spawn sqlite3: {e}"),
            })?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
        let detail = truncate_text(String::from_utf8_lossy(&output.stderr).trim(), 300);
        if is_busy_text(&detail) && attempt < BUSY_RETRIES {
            attempt += 1;
            std::thread::sleep(std::time::Duration::from_millis(BUSY_RETRY_PAUSE_MS));
            continue;
        }
        if is_busy_text(&detail) {
            return Err(StorageError::Busy { detail });
        }
        return Err(StorageError::SqliteFailure { detail });
    }
}

fn read_user_version(db_path: &Path) -> Result<u32, StorageError> {
    // A missing database reports generation 0 (fresh install path). An
    // unreadable EXISTING file is a failure, not a fresh install.
    if !db_path.exists() {
        return Ok(0);
    }
    let raw = raw_pragma(db_path, "PRAGMA user_version;")?;
    raw.parse::<u32>().map_err(|_| StorageError::SqliteFailure {
        detail: format!("user_version unreadable: '{raw}'"),
    })
}

fn write_user_version(db_path: &Path, generation: u32) -> Result<(), StorageError> {
    let raw = Command::new("sqlite3")
        .arg(db_path)
        .arg(format!("PRAGMA user_version = {generation};"))
        .stdin(Stdio::null())
        .output()
        .map_err(|e| StorageError::Io {
            path: db_path.display().to_string(),
            message: format!("failed to spawn sqlite3: {e}"),
        })?;
    if !raw.status.success() {
        return Err(StorageError::SqliteFailure {
            detail: "PRAGMA user_version write failed".to_string(),
        });
    }
    Ok(())
}

fn apply_migration(db_path: &Path) -> Result<(), StorageError> {
    // Fed on stdin (see run_script_stdin): the migration header starts with
    // `--` (SQL comments), which argv mode would misread as CLI options.
    let output = run_script_stdin(db_path, &[], super::MIGRATION_0001_SQL)?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(StorageError::SqliteFailure {
            detail: format!(
                "migration 0001_init failed: {}",
                truncate_text(&detail, 300)
            ),
        });
    }
    Ok(())
}

fn record_migration_note(db_path: &Path) -> Result<(), StorageError> {
    let script = "INSERT INTO schema_migrations(generation, applied_note) VALUES (1, 'M01-PR03 0001_init: initial tiny outbox') ON CONFLICT(generation) DO NOTHING;";
    let output = Command::new("sqlite3")
        .arg(db_path)
        .arg(script)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| StorageError::Io {
            path: db_path.display().to_string(),
            message: format!("failed to spawn sqlite3: {e}"),
        })?;
    if !output.status.success() {
        return Err(StorageError::SqliteFailure {
            detail: "schema_migrations record failed".to_string(),
        });
    }
    Ok(())
}

fn verify_schema_objects(db_path: &Path) -> Result<(), StorageError> {
    let raw = raw_pragma(
        db_path,
        "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table','index') AND name IN ('schema_migrations','outbox','derived_marks','idx_outbox_status');",
    )?;
    if raw.trim() == "4" {
        Ok(())
    } else {
        Err(StorageError::SqliteFailure {
            detail: format!("migration 0001_init objects incomplete (matched {raw} of 4)"),
        })
    }
}

fn wal_path(db_path: &Path) -> PathBuf {
    let mut name = db_path.as_os_str().to_owned();
    name.push("-wal");
    PathBuf::from(name)
}

fn parent_permissions_readonly(dir: &Path) -> bool {
    std::fs::metadata(dir)
        .map(|m| m.permissions().readonly())
        .unwrap_or(false)
}

#[cfg(unix)]
fn db_file_identity(db_path: &Path) -> (Option<u32>, Option<u32>) {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(db_path)
        .map(|m| (Some(m.mode() & 0o7777), Some(m.uid())))
        .unwrap_or((None, None))
}

#[cfg(not(unix))]
fn db_file_identity(_db_path: &Path) -> (Option<u32>, Option<u32>) {
    (None, None)
}

fn epoch_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn epoch_nanos_now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn truncate_text(raw: &str, max: usize) -> String {
    if raw.len() <= max {
        raw.to_string()
    } else {
        format!("{}…[truncated {} chars]", &raw[..max], raw.len() - max)
    }
}

fn is_busy_text(detail: &str) -> bool {
    detail.contains("database is locked") || detail.contains("database table is locked")
}

fn is_readonly_text(detail: &str) -> bool {
    detail.contains("readonly") || detail.contains("read-only") || detail.contains("read only")
}

fn is_unopenable_text(detail: &str) -> bool {
    detail.contains("unable to open")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_quote_doubles_single_quotes() {
        assert_eq!(sql_quote("abc"), "'abc'");
        assert_eq!(sql_quote("a'b"), "'a''b'");
        assert_eq!(sql_quote(""), "''");
    }

    #[test]
    fn unquote_round_trips_and_reports_null() {
        assert_eq!(unquote_text("NULL").expect("null"), None);
        assert_eq!(
            unquote_text("'a''b'").expect("quoted"),
            Some("a'b".to_string())
        );
        assert!(unquote_text("bare").is_err());
    }

    #[test]
    fn outbox_status_parses_exhaustively() {
        assert_eq!(
            OutboxStatus::parse("queued").expect("q"),
            OutboxStatus::Queued
        );
        assert_eq!(
            OutboxStatus::parse("claimed").expect("c"),
            OutboxStatus::Claimed
        );
        assert_eq!(
            OutboxStatus::parse("acked").expect("a"),
            OutboxStatus::Acked
        );
        assert_eq!(
            OutboxStatus::parse("rolled-back").unwrap_err().code(),
            "invalid-record"
        );
        assert_eq!(OutboxStatus::Queued.as_str(), "queued");
    }

    #[test]
    fn envelope_rejects_wrong_generation_and_durability() {
        let settings = ConnectionSettings::local_wal_full();
        let bad_gen = "VERDANT_BEGIN\n9\nwal\n2\n1\n5000\n8388608\nVERDANT_DATA\nVERDANT_END\n";
        assert_eq!(
            parse_envelope(bad_gen, &settings).unwrap_err().code(),
            "schema-generation-mismatch"
        );
        let bad_sync = "VERDANT_BEGIN\n1\nwal\n1\n1\n5000\n8388608\nVERDANT_DATA\nVERDANT_END\n";
        assert_eq!(
            parse_envelope(bad_sync, &settings).unwrap_err().code(),
            "durability-unavailable"
        );
        let bad_limit = "VERDANT_BEGIN\n1\nwal\n2\n1\n5000\n10\nVERDANT_DATA\nVERDANT_END\n";
        assert_eq!(
            parse_envelope(bad_limit, &settings).unwrap_err().code(),
            "durability-unavailable"
        );
        let missing = "wal\n2\n";
        assert_eq!(
            parse_envelope(missing, &settings).unwrap_err().code(),
            "sqlite-failure"
        );
    }

    #[test]
    fn storage_error_codes_are_stable() {
        let cases: Vec<(StorageError, &str)> = vec![
            (
                StorageError::MissingSqlite {
                    detail: "x".to_string(),
                },
                "missing-sqlite3",
            ),
            (
                StorageError::DurabilityUnavailable {
                    detail: "x".to_string(),
                },
                "durability-unavailable",
            ),
            (
                StorageError::ReadOnlyPath {
                    path: "x".to_string(),
                },
                "read-only-path",
            ),
            (
                StorageError::SpaceExhausted {
                    detail: "x".to_string(),
                },
                "space-exhausted",
            ),
            (
                StorageError::ValueTooLarge { len: 9, max: 8 },
                "value-too-large",
            ),
            (
                StorageError::MaintenanceRequired {
                    detail: "x".to_string(),
                },
                "maintenance-required",
            ),
            (
                StorageError::Conflict {
                    detail: "x".to_string(),
                },
                "conflict",
            ),
            (
                StorageError::SchemaMismatch {
                    expected: 1,
                    found: "9".to_string(),
                },
                "schema-generation-mismatch",
            ),
            (
                StorageError::InvalidRecord {
                    detail: "x".to_string(),
                },
                "invalid-record",
            ),
            (
                StorageError::Busy {
                    detail: "x".to_string(),
                },
                "busy",
            ),
            (
                StorageError::TooManyConnections { max: 1 },
                "too-many-connections",
            ),
            (StorageError::HandoffFull { capacity: 1 }, "handoff-full"),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code, "code drift for {error}");
            assert!(!error.to_string().is_empty());
        }
    }
}
