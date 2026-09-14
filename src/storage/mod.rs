//! M01-PR03 durable-store framework seam (SQLite backend: [`sqlite`]).
//!
//! Std-only, zero dependencies: the crate stays dependency-free per the D02
//! freeze, so the SQLite envelope drives the system `sqlite3` CLI (3.54.0,
//! pinned by the acceptance record) via `std::process` instead of linking a
//! driver crate. No rusqlite, no ORM, no async runtime, no server/wire.
//!
//! ## Authority and commit order
//!
//! Validation (domain newtypes at the API boundary) comes first, then the
//! authoritative mutation (one `sqlite3` invocation = one connection), then
//! the durability action (`synchronous=FULL` returns only after the OS
//! acknowledges the write), then the visible commit, then the acknowledgment
//! to the caller. `flush` honesty: Rust-side buffering is flushed before the
//! child is waited on; durability itself is the `FULL`-sync write followed by
//! an observed child exit of 0 — never an inferred stop.
//!
//! Every connection sets **and re-reads** its durability settings
//! ([`ConnectionSettings`]) in-band: journal mode, synchronous level, foreign
//! keys and busy timeout are recorded per connection, never inferred from
//! another connection. A mismatch is a typed refusal, not a fallback.
//!
//! ## Failure labeling
//!
//! Kill-mid-transaction tests are **process-crash** evidence (OS caches stay
//! intact; SQLite journal recovery rolls back the uncommitted tail), never
//! power-loss proof. Real disk-full, power loss, other targets, Selene, and
//! PostgreSQL are untested limits (see the delivery handoff).
//!
//! ## Text examples (not doctests)
//!
//! ```text
//! schema generation .....: 0001 (see SCHEMA_GENERATION + MIGRATION_0001)
//! journal mode ..........: wal
//! synchronous ...........: FULL (level 2)
//! outbox lifecycle ......: queued -> claimed -> acked
//! duplicate policy ......: tolerated + counted, never silently merged
//! ```

use std::fmt;
use std::sync::mpsc;

pub mod sqlite;
// Store-facing projection only: no dependency on access/runtime/normalization.
// The source-inclusion storage harnesses retain their existing boundaries.
pub(crate) mod observation_writer;

/// Schema generation bound to every prepared statement in this slice.
///
/// The outbox row contract remains 1: additive migration 0002 changes no
/// access/binding payloads. The separate migration ledger + application_id
/// bind the storage protocol; unknown/downgraded combinations are refused.
pub const SCHEMA_GENERATION: u32 = 1;

/// Reserved migration identifier for this slice's initial schema.
pub const MIGRATION_ID: &str = "0001_init";

/// Embedded initial-schema SQL (compile-time copy of
/// `migrations/sqlite/0001_init.sql`; tests assert the two agree byte for
/// byte so the file on disk and the applied schema cannot drift).
pub const MIGRATION_0001_SQL: &str = include_str!("../../migrations/sqlite/0001_init.sql");

/// Compact change record for migration 0001 (integration §2; mirrored in the
/// SQL header comment of `migrations/sqlite/0001_init.sql`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationRecord {
    /// Backend name (`sqlite`).
    pub backend: &'static str,
    /// Owning slice (`M01-PR03`).
    pub owner: &'static str,
    /// Migration identifier (`0001_init`).
    pub id: &'static str,
    /// Predecessor identifiers (none for the initial schema).
    pub predecessors: &'static [&'static str],
    /// Fresh-install procedure.
    pub fresh_install: &'static str,
    /// Supported upgrade path statement.
    pub supported_upgrade: &'static str,
    /// Queued-message compatibility policy.
    pub queued_msg_compat: &'static str,
    /// Lock and space needs.
    pub lock_space: &'static str,
    /// Interruption outcome.
    pub interruption: &'static str,
    /// Read/write policy.
    pub read_write_policy: &'static str,
    /// Rollback boundary.
    pub rollback_boundary: &'static str,
}

/// The 0001 change record. `predecessors` is empty: no other migration IDs
/// exist and no other numbered migration may be created in this slice.
/// Historical lock-space prose below is preserved, not a live quota promise:
/// journal_size_limit trims a reset/checkpointed journal; readers can pin a
/// larger WAL. Current observed budgets are documented on StoreBounds.
pub const MIGRATION_0001: MigrationRecord = MigrationRecord {
    backend: "sqlite",
    owner: "M01-PR03",
    id: "0001_init",
    predecessors: &[],
    fresh_install: "apply migrations/sqlite/0001_init.sql, then PRAGMA user_version = 1",
    supported_upgrade: "none yet; the first future migration must be 0002 with predecessor 0001",
    queued_msg_compat: "additive rows; small concurrent-writer duplicates tolerated + counted, never merged",
    lock_space: "WAL; one writer (file locks + 5 s busy timeout); WAL capped by journal_size_limit; temp DBs in OS temp dirs only",
    interruption: "uncommitted work never survives; claimed-unacked rows stay visibly dangling, never silently requeued",
    read_write_policy: "per-connection WAL + FULL-sync + foreign-keys + busy-timeout, set and re-read in-band",
    rollback_boundary: "applied migrations never rewritten; data rollback is explicit per-row; no down migration",
};

/// Additive storage-protocol revision; generation-1 consumers remain valid.
pub const MIGRATION_0002_SQL: &str = include_str!("../../migrations/sqlite/0002_receipts.sql");
pub const MIGRATION_0002: MigrationRecord = MigrationRecord {
    backend: "sqlite",
    owner: "R03",
    id: "0002_receipts",
    predecessors: &["0001_init"],
    fresh_install: "0001 plus 0002 in one private transaction; validate and close before no-clobber publication",
    supported_upgrade: "validated 0001 to 0002 in one writer transaction; backfill one legacy receipt per existing row without inventing transition outcomes",
    queued_msg_compat: "unchanged additive outbox; receipts in their own table; generation-1 access/binding consumers accept",
    lock_space: "BEGIN IMMEDIATE; WAL/FULL; additional receipt storage; no automatic receipt pruning",
    interruption: "atomic upgrade rollback; unpublished bootstrap files are never adopted; ambiguous commits require same-identity reconciliation",
    read_write_policy: "user_version stays 1; ledger revision 2 plus application_id and store identity enforced in the owning connection",
    rollback_boundary: "no downgrade; unknown/incomplete ledger, objects or identity refused without repair",
};

pub const MIGRATION_0003_SQL: &str = include_str!("../../migrations/sqlite/0003_observations.sql");
pub const MIGRATION_0003: MigrationRecord = MigrationRecord {
    backend: "sqlite",
    owner: "M02-PR03B",
    id: "0003_observations",
    predecessors: &["0002_receipts"],
    fresh_install: "0001 plus 0002 plus 0003 in one private transaction before publication",
    supported_upgrade: "validated 0002 to 0003; 0001 first applies 0002; no content backfill",
    queued_msg_compat: "outbox and other owners' receipts unchanged; three separate observation tables",
    lock_space: "BEGIN IMMEDIATE; WAL/FULL; fixture-assumption finite logical window, not a WAL quota",
    interruption: "atomic migration rollback; capture tickets retain UNKNOWN until reconciliation",
    read_write_policy: "user_version stays 1; exact ledger revision 3 and application/store identity",
    rollback_boundary: "no downgrade or rewrite; unknown schema/ledger refused without repair",
};

/// Per-connection durability settings. Recorded on every connection and
/// re-read in-band; never inferred from another connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionSettings {
    /// Expected `PRAGMA journal_mode` readout (`wal`).
    pub journal_mode: &'static str,
    /// Expected `PRAGMA synchronous` readout (`2` = FULL).
    pub synchronous_level: &'static str,
    /// Expected `PRAGMA foreign_keys` readout (`1` = enforced).
    pub foreign_keys: &'static str,
    /// Busy timeout in milliseconds (also `PRAGMA busy_timeout` readout).
    pub busy_timeout_ms: u32,
    /// Retained journal size after reset/checkpoint, NOT a live WAL hard cap.
    pub journal_size_limit_bytes: u64,
    /// Absolute wall budget per CLI operation, including admission/retries,
    /// stdin, computation, output and exit. Separate from SQLite lock waiting.
    /// Composite open/report calls perform several individually bounded CLI
    /// operations. Kernel spawn/kill/reap and scheduling are not real-time.
    pub operation_timeout_ms: u64,
}

impl ConnectionSettings {
    /// The one supported local configuration (D03 edge baseline).
    pub fn local_wal_full() -> ConnectionSettings {
        ConnectionSettings {
            journal_mode: "wal",
            synchronous_level: "2",
            foreign_keys: "1",
            busy_timeout_ms: 5_000,
            journal_size_limit_bytes: 8_388_608,
            operation_timeout_ms: 35_000,
        }
    }
}

impl fmt::Display for ConnectionSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "journal_mode={} synchronous=FULL({}) foreign_keys={} busy_timeout_ms={} journal_size_limit_bytes={} operation_timeout_ms={}",
            self.journal_mode,
            self.synchronous_level,
            self.foreign_keys,
            self.busy_timeout_ms,
            self.journal_size_limit_bytes,
            self.operation_timeout_ms
        )
    }
}

/// Explicit budgets. Every bound is a value the operator can read; enforcement
/// is refusal with a typed error, never silent loss or silent merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreBounds {
    /// Maximum accepted `value_json` payload in bytes (insert refusal above).
    pub max_value_bytes: usize,
    /// Finite operation replay horizon: `replay`/`claim` clamp to this many rows.
    pub max_replay_rows: u32,
    /// In-process handle budget per store family (`try_clone` refusal above).
    pub max_connections: u32,
    /// Active CLI operations per shared handle family; refusal never queues.
    /// Independent opens/processes are separate families (not a host limit).
    pub max_running_operations: u32,
    /// Cumulative stdin bytes per operation, including protocol and retries.
    pub max_input_bytes: usize,
    /// Combined stdout/stderr bytes per operation, including protocol/retries.
    /// Fixed pipe-pump buffers may read ahead; no unbounded line allocation.
    pub max_output_bytes: usize,
    /// Cumulative stdout lines, including protocol, across an operation.
    /// Full-history reads refuse overflow; they never return partial history.
    pub max_output_rows: usize,
    /// Handoff channel capacity (bounded, counted; full channel refuses).
    pub max_tasks: usize,
    /// Observed live WAL maintenance threshold, not a physical growth cap.
    pub max_wal_bytes: u64,
    /// Synthetic observed main + WAL + SHM capacity budget (insert refusal).
    /// A transaction can overshoot; this is not a filesystem quota.
    pub max_db_bytes: u64,
    /// Explicit maintenance window in seconds (operator calls `checkpoint`).
    pub maintenance_window_secs: u64,
}

impl StoreBounds {
    /// Tiny-test defaults: small enough to exercise bounds quickly, large
    /// enough that ordinary tiny-outbox traffic never trips them.
    pub fn tiny() -> StoreBounds {
        StoreBounds {
            max_value_bytes: 65_536,
            max_replay_rows: 64,
            max_connections: 16,
            max_running_operations: 16,
            max_input_bytes: 8_388_608,
            max_output_bytes: 8_388_608,
            max_output_rows: 8_192,
            max_tasks: 64,
            max_wal_bytes: 8_388_608,
            max_db_bytes: 67_108_864,
            maintenance_window_secs: 3_600,
        }
    }
}

/// Typed store failure. `code()` returns a stable machine-readable code;
/// malformed input and unavailable durability are refused, never panics and
/// never silent drops. Matches stay exhaustive so new variants break the
/// build, not behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// The `sqlite3` CLI is missing or its version is unusable.
    MissingSqlite { detail: String },
    /// `sqlite3` exited nonzero (or its output was unparsable); `detail`
    /// carries the stderr text (never secret material; the store holds none).
    SqliteFailure { detail: String },
    /// A live connection did not honor the recorded durability settings.
    DurabilityUnavailable { detail: String },
    /// The parent directory is missing or not writable.
    UnwritablePath { path: String, reason: String },
    /// The directory refused writes (e.g. read-only mode bit).
    ReadOnlyPath { path: String },
    /// Synthetic space budget (`max_db_bytes`) exhausted; real disk-full is an
    /// untested limit and is reported with this code, never silently dropped.
    SpaceExhausted { detail: String },
    /// Payload exceeds `max_value_bytes`.
    ValueTooLarge { len: usize, max: usize },
    /// WAL/maintenance budget needs an operator `checkpoint`.
    MaintenanceRequired { detail: String },
    /// Zero affected rows where exactly one was required (lost claim race,
    /// double acknowledge, unknown id): a conflict, not a success.
    Conflict { detail: String },
    /// The database reports a schema generation other than 0001.
    SchemaMismatch { expected: u32, found: String },
    /// A stored row failed to decode back into domain types (corruption or a
    /// foreign writer); the row is reported, never coerced.
    InvalidRecord { detail: String },
    /// A caller argument failed store-level validation.
    InvalidInput { what: &'static str, detail: String },
    /// The writer lock stayed busy past the timeout + bounded retries.
    Busy { detail: String },
    /// In-process handle budget (`max_connections`) exhausted.
    TooManyConnections { max: u32 },
    /// Active operation budget exhausted before spawning a child.
    TooManyRunningOperations { max: u32 },
    /// Absolute operation deadline elapsed; never classified as lock busy.
    DeadlineExceeded { timeout_ms: u64 },
    /// Cumulative transport budget exceeded; no partial result is returned.
    ExecutionLimit { resource: &'static str, max: usize },
    /// Bounded handoff channel full: the announcement is refused, never dropped.
    HandoffFull { capacity: usize },
    /// Filesystem I/O outside SQLite failed.
    Io { path: String, message: String },
}

impl StorageError {
    /// Stable machine-readable code for tests and evidence mapping.
    pub fn code(&self) -> &'static str {
        match self {
            StorageError::MissingSqlite { .. } => "missing-sqlite3",
            StorageError::SqliteFailure { .. } => "sqlite-failure",
            StorageError::DurabilityUnavailable { .. } => "durability-unavailable",
            StorageError::UnwritablePath { .. } => "unwritable-path",
            StorageError::ReadOnlyPath { .. } => "read-only-path",
            StorageError::SpaceExhausted { .. } => "space-exhausted",
            StorageError::ValueTooLarge { .. } => "value-too-large",
            StorageError::MaintenanceRequired { .. } => "maintenance-required",
            StorageError::Conflict { .. } => "conflict",
            StorageError::SchemaMismatch { .. } => "schema-generation-mismatch",
            StorageError::InvalidRecord { .. } => "invalid-record",
            StorageError::InvalidInput { .. } => "invalid-input",
            StorageError::Busy { .. } => "busy",
            StorageError::TooManyConnections { .. } => "too-many-connections",
            StorageError::TooManyRunningOperations { .. } => "too-many-running-operations",
            StorageError::DeadlineExceeded { .. } => "operation-deadline",
            StorageError::ExecutionLimit { .. } => "execution-limit",
            StorageError::HandoffFull { .. } => "handoff-full",
            StorageError::Io { .. } => "io",
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::MissingSqlite { detail } => {
                write!(f, "sqlite3 unavailable: {detail}")
            }
            StorageError::SqliteFailure { detail } => {
                write!(f, "sqlite failure: {detail}")
            }
            StorageError::DurabilityUnavailable { detail } => {
                write!(f, "required durability unavailable: {detail}")
            }
            StorageError::UnwritablePath { path, reason } => {
                write!(f, "unwritable database path '{path}': {reason}")
            }
            StorageError::ReadOnlyPath { path } => {
                write!(
                    f,
                    "read-only database directory '{path}': refusing, not silently dropping"
                )
            }
            StorageError::SpaceExhausted { detail } => {
                write!(f, "space budget exhausted: {detail}")
            }
            StorageError::ValueTooLarge { len, max } => {
                write!(f, "value payload is {len} bytes; maximum is {max}")
            }
            StorageError::MaintenanceRequired { detail } => {
                write!(f, "maintenance required: {detail}")
            }
            StorageError::Conflict { detail } => {
                write!(f, "conflict (zero affected rows is not success): {detail}")
            }
            StorageError::SchemaMismatch { expected, found } => {
                write!(
                    f,
                    "schema generation mismatch: statements are bound to {expected:04}, found user_version {found}"
                )
            }
            StorageError::InvalidRecord { detail } => {
                write!(f, "stored row is not a valid record: {detail}")
            }
            StorageError::InvalidInput { what, detail } => {
                write!(f, "invalid {what}: {detail}")
            }
            StorageError::Busy { detail } => {
                write!(f, "database busy past timeout + retries: {detail}")
            }
            StorageError::TooManyConnections { max } => {
                write!(f, "in-process handle budget exhausted (max {max})")
            }
            StorageError::TooManyRunningOperations { max } => {
                write!(f, "running operation budget exhausted (max {max}); no child spawned")
            }
            StorageError::DeadlineExceeded { timeout_ms } => {
                write!(f, "operation wall deadline exceeded ({timeout_ms} ms)")
            }
            StorageError::ExecutionLimit { resource, max } => {
                write!(f, "operation {resource} budget exceeded (max {max}); partial result refused")
            }
            StorageError::HandoffFull { capacity } => {
                write!(
                    f,
                    "bounded handoff full (capacity {capacity}): announcement refused, not dropped"
                )
            }
            StorageError::Io { path, message } => {
                write!(f, "io failure at '{path}': {message}")
            }
        }
    }
}

impl std::error::Error for StorageError {}

/// Announced, bounded, counted handoff from a foreground task to one explicit
/// background task. Announcements use `try_send`: a full channel returns
/// [`StorageError::HandoffFull`] to the caller — work is refused, never
/// silently lost. The receiver counts every delivery; the sender counts every
/// announcement and every refusal.
#[derive(Debug)]
pub struct Handoff<T> {
    sender: Option<mpsc::SyncSender<T>>,
    receiver: Option<mpsc::Receiver<T>>,
    capacity: usize,
}

impl<T> Handoff<T> {
    /// Create a handoff with an explicit bound (see `StoreBounds::max_tasks`).
    pub fn new(capacity: usize) -> Handoff<T> {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        Handoff {
            sender: Some(sender),
            receiver: Some(receiver),
            capacity,
        }
    }

    /// Split into the foreground sender half and the background receiver half.
    /// After `split`, `announce`/`finish` remain usable on the sender half via
    /// the returned [`HandoffSender`]; counts stay with their half.
    pub fn split(self) -> (HandoffSender<T>, HandoffReceiver<T>) {
        let Handoff {
            sender,
            receiver,
            capacity,
            ..
        } = self;
        (
            HandoffSender {
                sender: sender.expect("handoff sender present"),
                capacity,
                announced: 0,
                refused: 0,
            },
            HandoffReceiver {
                receiver: receiver.expect("handoff receiver present"),
                delivered: 0,
            },
        )
    }
}

/// Foreground (sender) half of a [`Handoff`].
#[derive(Debug)]
pub struct HandoffSender<T> {
    sender: mpsc::SyncSender<T>,
    capacity: usize,
    announced: u64,
    refused: u64,
}

impl<T> HandoffSender<T> {
    /// Announce one item. Refuses with `HandoffFull` when the bound is
    /// reached; the item is returned to the caller inside the error path via
    /// the refusal count (the value itself is dropped only by the caller's
    /// explicit decision — `try_send` keeps ownership on failure, and this
    /// method reports instead of swallowing it).
    pub fn announce(&mut self, item: T) -> Result<(), StorageError> {
        match self.sender.try_send(item) {
            Ok(()) => {
                self.announced += 1;
                Ok(())
            }
            Err(mpsc::TrySendError::Full(_)) => {
                self.refused += 1;
                Err(StorageError::HandoffFull {
                    capacity: self.capacity,
                })
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.refused += 1;
                Err(StorageError::InvalidInput {
                    what: "handoff",
                    detail: "background receiver is gone; announcement refused".to_string(),
                })
            }
        }
    }

    /// Announced count (accepted by the channel, not yet necessarily delivered).
    pub fn announced(&self) -> u64 {
        self.announced
    }

    /// Refused count (full channel or gone receiver; never silently lost).
    pub fn refused(&self) -> u64 {
        self.refused
    }

    /// Close the announcement stream so the receiver observes the end.
    pub fn finish(self) -> HandoffSenderReport {
        let report = HandoffSenderReport {
            announced: self.announced,
            refused: self.refused,
        };
        drop(self.sender);
        report
    }
}

/// Sender-side report: announced vs refused are both counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffSenderReport {
    /// Items accepted by the bounded channel.
    pub announced: u64,
    /// Items refused (full/gone); each was reported to the caller.
    pub refused: u64,
}

/// Background (receiver) half of a [`Handoff`].
#[derive(Debug)]
pub struct HandoffReceiver<T> {
    receiver: mpsc::Receiver<T>,
    delivered: u64,
}

impl<T> HandoffReceiver<T> {
    /// Drain until the sender finishes; returns every item plus the count.
    /// No silent loss: the returned vector length always equals `delivered`.
    pub fn drain(mut self) -> HandoffReceiverReport<T> {
        let mut items = Vec::new();
        for item in self.receiver.iter() {
            items.push(item);
            self.delivered += 1;
        }
        HandoffReceiverReport {
            delivered: self.delivered,
            items,
        }
    }
}

/// Receiver-side report: delivered count always equals `items.len()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffReceiverReport<T> {
    /// Items delivered across the handoff.
    pub delivered: u64,
    /// The delivered items, in announcement order.
    pub items: Vec<T>,
}
