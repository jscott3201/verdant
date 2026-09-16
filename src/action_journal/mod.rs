//! M02-PR06 durable admission and per-target state, SYNTHETIC-ONLY.
//! Assigned writer: per-target serialization of current intent. Persists
//! actor/ceiling, target/allocation/generation, payload, deadline and
//! request/attempt identities plus state before any handoff. Inert bounded
//! sink: admit+journal, emit nothing to wire. Dispatch stays disabled (PR07).
//! PR05 profile verbatim (owner-selected, not commissioned): BACnet/IP AV
//! presentValue tiny_site (ahu-1/vav-101 scope-a); P8, 1-3 refused, no empty
//! slot; degC 20-24 tol 0.1; 15min/5s/APDU_RETRIES(0)/6h; PV
//! unavailable-feedback, source_time None; NULL-only release; preview
//! revision-bound (no reservation/dispatch/qualification). Consumes Preview
//! fields read-only + canonical_bytes; never re-derives preview logic.
//! Lock order: preview reads (no lock) -> ceiling check (no lock) -> SQLite
//! writer txn (BEGIN IMMEDIATE, one writer, 5s busy, guard+journal+target+
//! receipt in one connection) -> COMMIT -> bounded handoff try_send. No
//! network under the SQL txn, no building-wide lock (per-target row guard,
//! never a global mutex). Essential capacity (max_tasks) is separate from
//! history/capture (bound 1); neither borrows the other, neither is a
//! host-global quota. Full queues refuse announcements but never lose rows:
//! reconcile recovers. Same-key/same-payload reconciles; conflicts refuse
//! without overwrite; stale generations refuse; cross-scope reads return
//! not-found without disclosure; journal failure never announces; cancel
//! writes nothing; deleted rows keep the target watermark so stale replays
//! stay refused; handoff-boundary crashes return UNKNOWN; lost wake-ups
//! reconcile from DB. Greenfield: no v1 conversion, no old previews beyond
//! verdant-preview-v1, no backfill, no rewrite helpers, no aliases.

use crate::accept::AcceptedRevision;
use crate::access::RoleKind;
use crate::action_preview::Preview;
use crate::binding;
use crate::domain::ids::{BindingRevision, InstalledId, OperationId};
use crate::domain::scope::TrustedScope;
use crate::storage::sqlite::{MutationOutcome, PreparedMutation, SqliteStore};
use crate::storage::{
    ConnectionSettings, Handoff, HandoffReceiver, HandoffSender, StorageError, StoreBounds,
};
use std::path::Path;

pub mod identity;
pub mod lifecycle;
pub mod rate;
pub use identity::{ActionKind, Identity};
pub use lifecycle::LifecycleState;
use self::identity::{check_actor, check_ceiling, check_preview, map_submit_error};

/// Journal wire format tag (inert sink; no wire emission in this slice).
pub const JOURNAL_FORMAT: &str = "verdant-action-journal-v1";
/// Independent optional history/capture capacity (separate from essential).
pub const HISTORY_CAPACITY: usize = 1;

/// Typed admission failure with a stable machine code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriterError {
    Invalid(&'static str),
    InvalidDetail { what: &'static str, detail: String },
    Ceiling { have: u8, required: u8 },
    ScopeDenied { expected: String, presented: String },
    Conflict { detail: String },
    StaleGeneration { expected: u32, current: u32 },
    StalePayload { detail: String },
    NotFound { operation: String },
    Unknown { operation: OperationId, detail: String },
    RateExceeded { used: u32, limit: u32 },
    DeadlineExceeded { elapsed_secs: u64, deadline_secs: u64 },
    RateIndeterminate { reason: &'static str },
    Storage(StorageError),
}

impl WriterError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) | Self::InvalidDetail { .. } => "admission-invalid",
            Self::Ceiling { .. } => "ceiling-exceeded",
            Self::ScopeDenied { .. } => "admission-scope-denied",
            Self::Conflict { .. } => "admission-conflict",
            Self::StaleGeneration { .. } => "admission-stale-generation",
            Self::StalePayload { .. } => "admission-stale-payload",
            Self::NotFound { .. } => "admission-not-found",
            Self::Unknown { .. } => "admission-unknown",
            Self::RateExceeded { .. } => "admission-rate-exceeded",
            Self::DeadlineExceeded { .. } => "admission-deadline-exceeded",
            Self::RateIndeterminate { .. } => "admission-indeterminate",
            Self::Storage(inner) => inner.code(),
        }
    }
}

impl std::fmt::Display for WriterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "admission invalid: {detail}"),
            Self::InvalidDetail { what, detail } => write!(f, "admission invalid {what}: {detail}"),
            Self::Ceiling { have, required } => {
                write!(f, "assistance ceiling {have} below required {required}")
            }
            Self::ScopeDenied { expected, presented } => write!(
                f,
                "admission scope denied: '{expected}' does not cover '{presented}'"
            ),
            Self::Conflict { detail } => write!(f, "admission conflict: {detail}"),
            Self::StaleGeneration { expected, current } => write!(
                f,
                "admission stale generation: expected {expected}, current is {current}"
            ),
            Self::StalePayload { detail } => write!(f, "admission stale payload (0004 rounded, lossless required): {detail}"),
            Self::NotFound { operation } => {
                write!(f, "admission not found for '{operation}' in this scope")
            }
            Self::Unknown { operation, detail } => write!(
                f,
                "admission outcome UNKNOWN for {}; reconcile this identity: {detail}",
                operation.as_str()
            ),
            Self::RateExceeded { used, limit } => write!(f, "admission rate exceeded: {used} >= {limit}/hour per scope-equipment wall-hour"),
            Self::DeadlineExceeded { elapsed_secs, deadline_secs } => write!(f, "admission deadline exceeded: elapsed {elapsed_secs}s >= deadline {deadline_secs}s; fresh Instant cannot renew durable wall anchor"),
            Self::RateIndeterminate { reason } => write!(f, "admission time indeterminate ({reason}): refuse new SET, allow only explicit cancel or admitted-NULL release"),
            Self::Storage(inner) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for WriterError {}
impl From<StorageError> for WriterError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::Conflict { detail } => Self::Conflict { detail },
            other => Self::Storage(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, WriterError>;

/// Durable admitted intent: the journal row plus reconciliation flag.
/// Slice-A lossless identity: exact `wire_bits`, explicit `set`/`release`
/// kind, release admission plus authorized target. Legacy 0004 rows carry
/// `None` and refuse for new handoffs as stale-payload (readable via
/// reconcile, no backfill). Slice-B adds the durable lifecycle state,
/// predecessor obligation link and `created` wall anchor (deadline/rate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    row_id: i64,
    operation: OperationId,
    scope: TrustedScope,
    equipment: InstalledId,
    binding_revision: BindingRevision,
    accepted_revision: AcceptedRevision,
    expected_generation: u32,
    target_generation: u32,
    payload: String,
    deadline_secs: u64,
    ceiling: u8,
    actor: String,
    attempt: OperationId,
    reconciled: bool,
    wire_bits: Option<u32>,
    action_kind: Option<ActionKind>,
    release_admitted: Option<bool>,
    release_target: Option<InstalledId>,
    lifecycle: LifecycleState,
    predecessor: Option<OperationId>,
    created_secs: i64,
}

impl Admitted {
    pub fn row_id(&self) -> i64 { self.row_id }
    pub fn operation(&self) -> &OperationId { &self.operation }
    pub fn scope(&self) -> &TrustedScope { &self.scope }
    pub fn equipment(&self) -> &InstalledId { &self.equipment }
    pub fn binding_revision(&self) -> BindingRevision { self.binding_revision }
    pub fn accepted_revision(&self) -> AcceptedRevision { self.accepted_revision }
    pub fn expected_generation(&self) -> u32 { self.expected_generation }
    pub fn target_generation(&self) -> u32 { self.target_generation }
    pub fn payload(&self) -> &str { &self.payload }
    pub fn deadline_secs(&self) -> u64 { self.deadline_secs }
    pub fn ceiling(&self) -> u8 { self.ceiling }
    pub fn actor(&self) -> &str { &self.actor }
    pub fn attempt(&self) -> &OperationId { &self.attempt }
    pub fn reconciled(&self) -> bool { self.reconciled }
    pub fn wire_bits(&self) -> Option<u32> { self.wire_bits }
    pub fn action_kind(&self) -> Option<ActionKind> { self.action_kind }
    pub fn release_admitted(&self) -> Option<bool> { self.release_admitted }
    pub fn release_target(&self) -> Option<&InstalledId> { self.release_target.as_ref() }
    pub fn lifecycle(&self) -> LifecycleState { self.lifecycle }
    pub fn predecessor(&self) -> Option<&OperationId> { self.predecessor.as_ref() }
    pub fn created_secs(&self) -> i64 { self.created_secs }
    /// Legacy 0004 rounded payload (no lossless identity): readable but stale.
    pub fn is_legacy(&self) -> bool { self.wire_bits.is_none() || self.action_kind.is_none() }
    /// Lossless identity string for identical-retry comparison (None if legacy).
    pub fn identity_string(&self) -> Option<String> {
        let kind = self.action_kind?;
        Some(format!("bits{:08X}|kind:{}|rel:{}:{}|{}", self.wire_bits?, kind.as_str(), u8::from(self.release_admitted?), self.release_target.as_ref()?.as_str(), self.payload))
    }
    pub fn journal_format(&self) -> &'static str { JOURNAL_FORMAT }
    /// Inert sink: admitted intent never dispatches to wire here.
    pub fn is_dispatch(&self) -> bool { false }
}

/// Prepared admission: validated intent plus a retained storage ticket.
/// Submit reconciles or commits; cancel drops without a row or handoff.
/// Carries lossless identity plus the durable predecessor link for
/// post-commit conflict comparison.
#[derive(Debug)]
pub struct PendingAdmission {
    operation: OperationId,
    scope: TrustedScope,
    equipment: InstalledId,
    binding_revision: BindingRevision,
    accepted_revision: AcceptedRevision,
    expected_generation: u32,
    target_generation: u32,
    payload: String,
    identity: Identity,
    deadline_secs: u64,
    ceiling: u8,
    actor: String,
    predecessor: Option<OperationId>,
    ticket: PreparedMutation,
}

impl PendingAdmission {
    pub fn operation(&self) -> &OperationId { &self.operation }
    pub fn scope(&self) -> &TrustedScope { &self.scope }
    pub fn expected_generation(&self) -> u32 { self.expected_generation }
    pub fn identity(&self) -> &Identity { &self.identity }
    pub fn predecessor(&self) -> Option<&OperationId> { self.predecessor.as_ref() }
}

/// Receivers for the two independent bounded queues.
#[derive(Debug)]
pub struct JournalReceivers {
    pub essential: HandoffReceiver<Admitted>,
    pub history: HandoffReceiver<String>,
}

/// Assigned writer over one store file plus two independent handoffs.
#[derive(Debug)]
pub struct Journal {
    store: SqliteStore,
    essential_tx: HandoffSender<Admitted>,
    history_tx: HandoffSender<String>,
}

impl Journal {
    pub fn open(
        db_path: &Path,
        settings: ConnectionSettings,
        bounds: StoreBounds,
    ) -> Result<(Self, JournalReceivers)> {
        let (store, _) = SqliteStore::open(db_path, settings, bounds.clone())?;
        ensure_0004(&store)?;
        crate::action_journal::identity::ensure_0005(&store)?;
        crate::action_journal::lifecycle::ensure_0006(&store)?;
        let (essential_tx, essential) = Handoff::new(bounds.max_tasks).split();
        let (history_tx, history) = Handoff::new(HISTORY_CAPACITY).split();
        Ok((
            Self {
                store,
                essential_tx,
                history_tx,
            },
            JournalReceivers { essential, history },
        ))
    }

    pub fn store(&self) -> &SqliteStore {
        &self.store
    }
    pub fn essential_announced(&self) -> u64 {
        self.essential_tx.announced()
    }
    pub fn essential_refused(&self) -> u64 {
        self.essential_tx.refused()
    }
    pub fn history_announced(&self) -> u64 {
        self.history_tx.announced()
    }
    pub fn history_refused(&self) -> u64 {
        self.history_tx.refused()
    }
    pub fn essential_capacity(&self) -> usize {
        self.store.bounds().max_tasks
    }
    pub fn history_capacity(&self) -> usize {
        HISTORY_CAPACITY
    }

    /// Validate preview read-only and stage a ticket; no durable write yet.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        &self,
        operation: OperationId,
        scope: TrustedScope,
        ceiling: u8,
        role: RoleKind,
        actor: &str,
        preview: &Preview,
        expected_generation: u32,
    ) -> Result<PendingAdmission> {
        self.prepare_with_predecessor(operation, scope, ceiling, role, actor, preview, expected_generation, None)
    }

    /// Validate plus stage with a durable predecessor obligation link in the
    /// same batch (`None` for fresh admissions). Equivalence is checked by
    /// the custody owner before this ticket; the writer only persists the link.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_predecessor(
        &self,
        operation: OperationId,
        scope: TrustedScope,
        ceiling: u8,
        role: RoleKind,
        actor: &str,
        preview: &Preview,
        expected_generation: u32,
        predecessor: Option<OperationId>,
    ) -> Result<PendingAdmission> {
        check_ceiling(ceiling, role)?;
        let actor = check_actor(actor)?;
        check_preview(preview)?;
        if preview.target().scope() != &scope {
            return Err(WriterError::ScopeDenied {
                expected: preview.target().scope().as_str().to_string(),
                presented: scope.as_str().to_string(),
            });
        }
        let target_generation = expected_generation
            .checked_add(1)
            .ok_or(WriterError::Invalid("target generation overflow"))?;
        let payload = preview.canonical_bytes();
        if payload.is_empty() || payload.len() > self.store.bounds().max_value_bytes {
            return Err(WriterError::InvalidDetail {
                what: "payload",
                detail: format!("payload is {} bytes", payload.len()),
            });
        }
        let identity = Identity::from_preview(preview);
        let body = crate::action_journal::identity::admission_body_v2(
            &operation, &scope, preview.target().equipment(), preview.target().binding_revision(), preview.target().accepted_revision(), expected_generation, target_generation, &payload, preview.timing().deadline_secs(), ceiling, &actor, &operation, &identity, predecessor.as_ref(),
        );
        let ticket = self
            .store
            .prepare_guarded_batch("1", &body, payload.len())?
            .with_operation(operation.clone());
        Ok(PendingAdmission { operation, scope, equipment: preview.target().equipment().clone(), binding_revision: preview.target().binding_revision(), accepted_revision: preview.target().accepted_revision(), expected_generation, target_generation, payload, identity, deadline_secs: preview.timing().deadline_secs(), ceiling, actor, predecessor, ticket })
    }

    /// Commit or reconcile one prepared admission, then announce to the
    /// essential queue. No network runs under the SQL transaction.
    pub fn submit(&mut self, pending: &PendingAdmission) -> Result<Admitted> {
        if let Some(committed) = self.try_reconcile_ticket(pending)? {
            return Ok(committed);
        }
        #[cfg(test)]
        let _ = ();
        let outcome = self.store.submit(&pending.ticket);
        let admitted = match outcome {
            MutationOutcome::Committed { .. } => {
                let mut found = self.read_row(&pending.operation, &pending.scope)?;
                found.reconciled = false;
                Self::require_identical(pending, &found)?;
                found
            }
            MutationOutcome::NotCommitted { error: StorageError::SqliteFailure { detail }, .. }
                if detail.contains("CHECK constraint failed: admission_generation") =>
            {
                let current = self.current_generation(&pending.scope, &pending.equipment)?;
                return Err(WriterError::StaleGeneration {
                    expected: pending.expected_generation,
                    current,
                });
            }
            MutationOutcome::NotCommitted { error: StorageError::SqliteFailure { detail }, .. }
                if crate::action_journal::rate::is_rate_guard_failure(&detail) =>
            {
                let used = self.rate_used(&pending.scope, &pending.equipment).unwrap_or(crate::action_journal::rate::OWNED_RATE_MAX_PER_HOUR);
                return Err(crate::action_journal::rate::rate_exceeded(used));
            }
            MutationOutcome::NotCommitted { error, .. } => return Err(map_submit_error(error)),
            MutationOutcome::Conflict { detail, .. } => {
                return Err(WriterError::Conflict { detail });
            }
            MutationOutcome::Unknown { operation, detail } => {
                return Err(WriterError::Unknown { operation, detail });
            }
        };
        #[cfg(test)]
        if take_handoff_crash() {
            return Err(WriterError::Unknown {
                operation: pending.operation.clone(),
                detail: "injected crash before handoff announce; reconcile identity".to_string(),
            });
        }
        let _ = self.essential_tx.announce(admitted.clone());
        let _ = self.history_tx.announce(format!(
            "journal {} scope={} target={}",
            admitted.operation.as_str(),
            admitted.scope.as_str(),
            admitted.equipment.as_str()
        ));
        Ok(admitted)
    }

    /// Convenience: prepare then submit with the same identities.
    pub fn admit(
        &mut self,
        operation: OperationId,
        scope: TrustedScope,
        ceiling: u8,
        role: RoleKind,
        actor: &str,
        preview: &Preview,
        expected_generation: u32,
    ) -> Result<Admitted> {
        let pending = self.prepare(operation, scope, ceiling, role, actor, preview, expected_generation)?;
        self.submit(&pending)
    }

    /// Convenience with a durable predecessor obligation link in the same batch.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_with_predecessor(
        &mut self,
        operation: OperationId,
        scope: TrustedScope,
        ceiling: u8,
        role: RoleKind,
        actor: &str,
        preview: &Preview,
        expected_generation: u32,
        predecessor: OperationId,
    ) -> Result<Admitted> {
        let pending = self.prepare_with_predecessor(operation, scope, ceiling, role, actor, preview, expected_generation, Some(predecessor))?;
        self.submit(&pending)
    }

    /// Drop a prepared intent before submit: no row, no handoff.
    pub fn cancel(pending: PendingAdmission) {
        drop(pending);
    }

    /// Read-only recovery from the durable rows (never dispatches).
    /// Cross-scope callers see `admission-not-found`, never another scope's row.
    pub fn reconcile(
        &self,
        operation: &OperationId,
        scope: &TrustedScope,
    ) -> Result<Admitted> {
        let mut found = self.read_row(operation, scope)?;
        found.reconciled = true;
        Ok(found)
    }

    fn try_reconcile_ticket(&self, pending: &PendingAdmission) -> Result<Option<Admitted>> {
        match self.store.reconcile(&pending.ticket) {
            MutationOutcome::Committed { .. } => {
                let mut found = self.read_row(&pending.operation, &pending.scope)?;
                Self::require_identical(pending, &found)?;
                found.reconciled = true;
                Ok(Some(found))
            }
            MutationOutcome::NotCommitted { .. } => Ok(None),
            MutationOutcome::Conflict { detail, .. } => Err(WriterError::Conflict { detail }),
            MutationOutcome::Unknown { operation, detail } => {
                Err(WriterError::Unknown { operation, detail })
            }
        }
    }

    fn read_row(
        &self,
        operation: &OperationId,
        scope: &TrustedScope,
    ) -> Result<Admitted> {
        // Slice-B join first (20 cols with created + lifecycle + predecessor);
        // fall back through 17/13 shapes so 0004/0005 rows stay readable.
        let script = crate::action_journal::lifecycle::read_row_sql(operation, scope);
        let rows = match self.store.exec_script(&script) {
            Ok(rows) => rows,
            Err(StorageError::SqliteFailure { detail }) if detail.contains("no such column") || detail.contains("no such table") => {
                let legacy17 = format!(
                    "SELECT operation, scope, equipment, binding_revision, accepted_revision, expected_generation, target_generation, payload, deadline_secs, ceiling, actor, attempt, state, wire_bits, action_kind, release_admitted, release_target FROM action_journal WHERE operation={} AND scope={};",
                    binding::sql_quote(operation.as_str()),
                    binding::sql_quote(scope.as_str()),
                );
                match self.store.exec_script(&legacy17) {
                    Ok(rows) => rows,
                    Err(StorageError::SqliteFailure { detail }) if detail.contains("no such column") => {
                        let legacy = format!(
                            "SELECT operation, scope, equipment, binding_revision, accepted_revision, expected_generation, target_generation, payload, deadline_secs, ceiling, actor, attempt, state FROM action_journal WHERE operation={} AND scope={};",
                            binding::sql_quote(operation.as_str()),
                            binding::sql_quote(scope.as_str()),
                        );
                        self.store.exec_script(&legacy).map_err(WriterError::from)?
                    }
                    Err(other) => return Err(WriterError::from(other)),
                }
            }
            Err(other) => return Err(WriterError::from(other)),
        };
        let row = rows.into_iter().next().ok_or_else(|| WriterError::NotFound {
            operation: operation.as_str().to_string(),
        })?;
        if row.len() != 13 && row.len() != 17 && row.len() != 20 {
            return Err(WriterError::Invalid("journal row shape"));
        }
        crate::action_journal::lifecycle::decode_row(row, scope)
    }

    /// Durable lifecycle state for one operation (conservative admitted when
    /// no lifecycle row exists; never invented dispatched/terminal).
    pub fn lifecycle_state(&self, operation: &OperationId, scope: &TrustedScope) -> Result<LifecycleState> {
        Ok(self.read_row(operation, scope)?.lifecycle())
    }

    /// Durable `created` wall anchor for deadline math across restart.
    pub fn created_secs(&self, operation: &OperationId, scope: &TrustedScope) -> Result<i64> {
        Ok(self.read_row(operation, scope)?.created_secs())
    }

    /// Owned 6/hour durable count for `(scope, equipment)` in the wall-hour.
    fn rate_used(&self, scope: &TrustedScope, equipment: &InstalledId) -> Result<u32> {
        let script = format!(
            "SELECT COUNT(*) FROM action_journal WHERE scope={} AND equipment={} AND created >= CAST(strftime('%s','now') AS INTEGER)-3600 AND (action_kind='set' OR action_kind IS NULL);",
            binding::sql_quote(scope.as_str()),
            binding::sql_quote(equipment.as_str()),
        );
        let rows = self.store.exec_script(&script)?;
        match rows.as_slice() {
            [row] if row.len() == 1 => row[0].parse::<u32>().map_err(|_| WriterError::Invalid("rate count")),
            _ => Err(WriterError::Invalid("rate count shape")),
        }
    }

    /// Atomic lifecycle transition before any external send (single writer).
    /// Terminal is final: transitions from terminal refuse as conflict (no
    /// blind resend). Missing lifecycle rows are created conservatively.
    pub fn transition(&self, operation: &OperationId, scope: &TrustedScope, new_state: LifecycleState) -> Result<Admitted> {
        let current = self.read_row(operation, scope)?;
        if current.lifecycle().is_terminal() && new_state != LifecycleState::Terminal {
            return Err(WriterError::Conflict { detail: "lifecycle terminal is final; reconcile history, do not resend".to_string() });
        }
        if current.lifecycle() == new_state {
            return Ok(current);
        }
        let body = crate::action_journal::lifecycle::transition_body(operation, new_state);
        let ticket = self.store.prepare_guarded_batch("1", &body, body.len())?;
        match self.store.submit(&ticket) {
            MutationOutcome::Committed { .. } => self.read_row(operation, scope),
            MutationOutcome::NotCommitted { error, .. } => Err(crate::action_journal::lifecycle::map_transition_error(error)),
            MutationOutcome::Conflict { detail, .. } => Err(WriterError::Conflict { detail }),
            MutationOutcome::Unknown { operation, detail } => Err(WriterError::Unknown { operation, detail }),
        }
    }

    /// Mark admitted -> dispatched before the handoff decision leaves the writer.
    pub fn mark_dispatched(&self, operation: &OperationId, scope: &TrustedScope) -> Result<Admitted> {
        self.transition(operation, scope, LifecycleState::Dispatched)
    }
    /// Mark dispatched/admitted -> terminal on confirmed outcome.
    pub fn mark_terminal(&self, operation: &OperationId, scope: &TrustedScope) -> Result<Admitted> {
        self.transition(operation, scope, LifecycleState::Terminal)
    }
    /// Mark admitted/dispatched -> unresolved on uncertain outcome (honest, never resend).
    pub fn mark_unresolved(&self, operation: &OperationId, scope: &TrustedScope) -> Result<Admitted> {
        self.transition(operation, scope, LifecycleState::Unresolved)
    }

    /// Bounded outstanding page: state-filtered (terminal excluded), exact
    /// scope filter, `LIMIT`/`OFFSET`. Cross-scope callers observe nothing.
    pub fn outstanding_page(&self, scope: &TrustedScope, limit: u32, offset: u32) -> Result<Vec<Admitted>> {
        let bound = limit.min(self.store.bounds().max_replay_rows).max(1);
        // Resolve the page via the lifecycle helper SQL, then hydrate each
        // operation through the scoped join (preserves nondisclosure).
        let script = crate::action_journal::lifecycle::outstanding_page_sql(scope, bound, offset);
        let rows = self.store.exec_script(&script)?;
        let mut out = Vec::new();
        for row in rows {
            if row.len() != 7 {
                return Err(WriterError::Invalid("outstanding row shape"));
            }
            let operation = OperationId::parse(&row[0]).map_err(|_| WriterError::Invalid("outstanding operation"))?;
            out.push(self.read_row(&operation, scope)?);
        }
        Ok(out)
    }

    /// Slice-B extension: payload plus lossless bits/kind/target plus durable
    /// predecessor link (see `lifecycle::require_identical`).
    fn require_identical(pending: &PendingAdmission, found: &Admitted) -> Result<()> {
        crate::action_journal::lifecycle::require_identical(pending, found)
    }

    fn current_generation(
        &self,
        scope: &TrustedScope,
        equipment: &InstalledId,
    ) -> Result<u32> {
        let script = format!(
            "SELECT current_generation FROM action_targets WHERE scope={} AND equipment={};",
            binding::sql_quote(scope.as_str()),
            binding::sql_quote(equipment.as_str()),
        );
        let rows = self.store.exec_script(&script)?;
        match rows.as_slice() {
            [] => Ok(0),
            [row] if row.len() == 1 => row[0].parse::<u32>().map_err(|_| WriterError::Invalid("target generation")),
            _ => Err(WriterError::Invalid("target generation shape")),
        }
    }
}

fn ensure_0004(store: &SqliteStore) -> Result<()> {
    crate::action_journal::lifecycle::ensure_0004(store)
}

#[cfg(test)]
thread_local! {
    static HANDOFF_CRASH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn inject_handoff_crash() {
    HANDOFF_CRASH.with(|flag| flag.set(true));
}
#[cfg(test)]
fn take_handoff_crash() -> bool {
    HANDOFF_CRASH.with(|flag| flag.replace(false))
}
