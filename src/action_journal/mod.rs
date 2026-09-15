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
use crate::access::{RoleKind, REQUIRED_PUBLISH_CEILING};
use crate::action_preview::{
    Preview, DEADLINE_SECS, DURATION_SECS, PREVIEW_FORMAT, RATE_MAX_PER_HOUR,
};
use crate::binding;
use crate::domain::ids::{BindingRevision, InstalledId, OperationId};
use crate::domain::scope::TrustedScope;
use crate::runtime::bacnet::APDU_RETRIES;
use crate::storage::sqlite::{MutationOutcome, PreparedMutation, SqliteStore};
use crate::storage::{
    ConnectionSettings, Handoff, HandoffReceiver, HandoffSender, StorageError, StoreBounds,
    MIGRATION_0004_SQL,
};
use std::path::Path;

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
    NotFound { operation: String },
    Unknown { operation: OperationId, detail: String },
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
            Self::NotFound { .. } => "admission-not-found",
            Self::Unknown { .. } => "admission-unknown",
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
            Self::NotFound { operation } => {
                write!(f, "admission not found for '{operation}' in this scope")
            }
            Self::Unknown { operation, detail } => write!(
                f,
                "admission outcome UNKNOWN for {}; reconcile this identity: {detail}",
                operation.as_str()
            ),
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
    pub fn reconciled(&self) -> bool { self.reconciled
    }
    pub fn journal_format(&self) -> &'static str {
        JOURNAL_FORMAT
    }
    /// Inert sink: admitted intent never dispatches to wire here.
    pub fn is_dispatch(&self) -> bool {
        false
    }
}

/// Prepared admission: validated intent plus a retained storage ticket.
/// Submit reconciles or commits; cancel drops without a row or handoff.
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
    deadline_secs: u64,
    ceiling: u8,
    actor: String,
    ticket: PreparedMutation,
}

impl PendingAdmission {
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }
    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }
    pub fn expected_generation(&self) -> u32 {
        self.expected_generation
    }
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
        let body = admission_body(
            &operation,
            &scope,
            preview.target().equipment(),
            preview.target().binding_revision(),
            preview.target().accepted_revision(),
            expected_generation,
            target_generation,
            &payload,
            preview.timing().deadline_secs(),
            ceiling,
            &actor,
            &operation,
        );
        let ticket = self
            .store
            .prepare_guarded_batch("1", &body, payload.len())?
            .with_operation(operation.clone());
        Ok(PendingAdmission {
            operation,
            scope,
            equipment: preview.target().equipment().clone(),
            binding_revision: preview.target().binding_revision(),
            accepted_revision: preview.target().accepted_revision(),
            expected_generation,
            target_generation,
            payload,
            deadline_secs: preview.timing().deadline_secs(),
            ceiling,
            actor,
            ticket,
        })
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
                if found.payload != pending.payload {
                    return Err(WriterError::Conflict {
                        detail: "operation identity reused with different payload".to_string(),
                    });
                }
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
                if found.payload != pending.payload {
                    return Err(WriterError::Conflict {
                        detail: "operation identity reused with different payload".to_string(),
                    });
                }
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
        let script = format!(
            "SELECT operation, scope, equipment, binding_revision, accepted_revision, expected_generation, target_generation, payload, deadline_secs, ceiling, actor, attempt, state FROM action_journal WHERE operation={} AND scope={};",
            binding::sql_quote(operation.as_str()),
            binding::sql_quote(scope.as_str()),
        );
        let rows = self.store.exec_script(&script)?;
        let row = rows.into_iter().next().ok_or_else(|| WriterError::NotFound {
            operation: operation.as_str().to_string(),
        })?;
        if row.len() != 13 {
            return Err(WriterError::Invalid("journal row shape"));
        }
        decode_row(row, scope)
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

fn check_ceiling(ceiling: u8, role: RoleKind) -> Result<()> {
    match role {
        RoleKind::Publisher => {
            if ceiling < REQUIRED_PUBLISH_CEILING {
                return Err(WriterError::Ceiling {
                    have: ceiling,
                    required: REQUIRED_PUBLISH_CEILING,
                });
            }
            Ok(())
        }
        RoleKind::Reviewer => Err(WriterError::Ceiling {
            have: ceiling,
            required: REQUIRED_PUBLISH_CEILING,
        }),
    }
}

fn check_actor(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Err(WriterError::Invalid("empty actor"));
    }
    if raw.len() > 128 {
        return Err(WriterError::Invalid("actor too long"));
    }
    let ok = raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
    if !ok {
        return Err(WriterError::Invalid("actor characters"));
    }
    if raw.contains('\x1f') || raw.contains('\n') || raw.contains('\r') {
        return Err(WriterError::Invalid("actor framing"));
    }
    if raw == "VERDANT_BEGIN" || raw == "VERDANT_DATA" || raw == "VERDANT_END" {
        return Err(WriterError::Invalid("actor sentinel"));
    }
    Ok(raw.to_string())
}

fn check_preview(preview: &Preview) -> Result<()> {
    if preview.format() != PREVIEW_FORMAT {
        return Err(WriterError::Invalid("preview format"));
    }
    if preview.is_reservation() || preview.is_dispatch() || preview.is_qualified() {
        return Err(WriterError::Invalid("preview is information only"));
    }
    if preview.timing().apdu_retries() != APDU_RETRIES {
        return Err(WriterError::Invalid("apdu_retries frozen"));
    }
    if preview.timing().duration_secs() != DURATION_SECS {
        return Err(WriterError::Invalid("duration 15min"));
    }
    if preview.timing().deadline_secs() != DEADLINE_SECS {
        return Err(WriterError::Invalid("deadline 5s"));
    }
    if preview.timing().rate_per_hour() != RATE_MAX_PER_HOUR {
        return Err(WriterError::Invalid("rate bound"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn admission_body(
    operation: &OperationId,
    scope: &TrustedScope,
    equipment: &InstalledId,
    binding_revision: BindingRevision,
    accepted_revision: AcceptedRevision,
    expected_generation: u32,
    target_generation: u32,
    payload: &str,
    deadline_secs: u64,
    ceiling: u8,
    actor: &str,
    attempt: &OperationId,
) -> String {
    let scope_q = binding::sql_quote(scope.as_str());
    let equip_q = binding::sql_quote(equipment.as_str());
    let op_q = binding::sql_quote(operation.as_str());
    let payload_q = binding::sql_quote(payload);
    let actor_q = binding::sql_quote(actor);
    let attempt_q = binding::sql_quote(attempt.as_str());
    let binding_rev = binding_revision.as_u32();
    let accepted_rev = accepted_revision.get();
    let expected = expected_generation;
    let target = target_generation;
    let deadline = deadline_secs;
    let mut body = String::new();
    body.push_str(&format!(
        "CREATE TEMP TABLE admission_generation(ok INTEGER NOT NULL CONSTRAINT admission_generation CHECK(ok=1)); INSERT INTO admission_generation VALUES(CASE WHEN ((SELECT COALESCE((SELECT current_generation FROM action_targets WHERE scope={scope_q} AND equipment={equip_q}), 0)) = {expected}) THEN 1 ELSE 0 END);"
    ));
    body.push_str(&format!(
        "INSERT INTO action_journal(operation, scope, equipment, binding_revision, accepted_revision, expected_generation, target_generation, payload, deadline_secs, ceiling, actor, attempt, state, created) VALUES ({op_q}, {scope_q}, {equip_q}, {binding_rev}, {accepted_rev}, {expected}, {target}, {payload_q}, {deadline}, {ceiling}, {actor_q}, {attempt_q}, 'admitted', CAST(strftime('%s','now') AS INTEGER));"
    ));
    body.push_str(&format!(
        "INSERT INTO action_targets(scope, equipment, current_generation) VALUES ({scope_q}, {equip_q}, {target}) ON CONFLICT(scope, equipment) DO UPDATE SET current_generation=excluded.current_generation;"
    ));
    body
}

fn decode_row(mut row: Vec<String>, scope: &TrustedScope) -> Result<Admitted> {
    let take = |row: &mut Vec<String>| {
        if row.is_empty() {
            Err(WriterError::Invalid("journal row shape"))
        } else {
            Ok(row.remove(0))
        }
    };
    let operation = OperationId::parse(&take(&mut row)?)
        .map_err(|_| WriterError::Invalid("journal operation"))?;
    let scope_text = take(&mut row)?;
    if scope_text != scope.as_str() {
        return Err(WriterError::ScopeDenied {
            expected: scope.as_str().to_string(),
            presented: scope_text,
        });
    }
    let equipment =
        InstalledId::parse(&take(&mut row)?).map_err(|_| WriterError::Invalid("journal equipment"))?;
    let binding_revision = take(&mut row)?
        .parse::<u32>()
        .map(|v| BindingRevision::new(v))
        .map_err(|_| WriterError::Invalid("journal binding revision"))?;
    let accepted_revision = AcceptedRevision::new(
        take(&mut row)?
            .parse::<u32>()
            .map_err(|_| WriterError::Invalid("journal accepted revision"))?,
    )
    .map_err(|_| WriterError::Invalid("journal accepted revision"))?;
    let expected_generation = take(&mut row)?
        .parse::<u32>()
        .map_err(|_| WriterError::Invalid("journal expected generation"))?;
    let target_generation = take(&mut row)?
        .parse::<u32>()
        .map_err(|_| WriterError::Invalid("journal target generation"))?;
    if target_generation != expected_generation.checked_add(1).ok_or(WriterError::Invalid("journal generation order"))? {
        return Err(WriterError::Invalid("journal generation order"));
    }
    let payload = take(&mut row)?;
    if payload.is_empty() {
        return Err(WriterError::Invalid("journal payload"));
    }
    let deadline_secs = take(&mut row)?
        .parse::<u64>()
        .map_err(|_| WriterError::Invalid("journal deadline"))?;
    if deadline_secs != DEADLINE_SECS {
        return Err(WriterError::Invalid("deadline 5s"));
    }
    let ceiling = take(&mut row)?
        .parse::<u8>()
        .map_err(|_| WriterError::Invalid("journal ceiling"))?;
    let actor = take(&mut row)?;
    check_actor(&actor)?;
    let attempt =
        OperationId::parse(&take(&mut row)?).map_err(|_| WriterError::Invalid("journal attempt"))?;
    if take(&mut row)? != "admitted" {
        return Err(WriterError::Invalid("journal state"));
    }
    Ok(Admitted {
        row_id: 0,
        operation,
        scope: scope.clone(),
        equipment,
        binding_revision,
        accepted_revision,
        expected_generation,
        target_generation,
        payload,
        deadline_secs,
        ceiling,
        actor,
        attempt,
        reconciled: false,
    })
}

fn map_submit_error(error: StorageError) -> WriterError {
    match error {
        StorageError::SqliteFailure { ref detail }
            if detail.contains("UNIQUE constraint failed: action_journal.operation") =>
        {
            WriterError::Conflict {
                detail: "journal operation already recorded with this store".to_string(),
            }
        }
        StorageError::Conflict { detail } => WriterError::Conflict { detail },
        other => WriterError::Storage(other),
    }
}

fn ensure_0004(store: &SqliteStore) -> Result<()> {
    let rows = store.exec_script("SELECT generation FROM schema_migrations ORDER BY generation;")?;
    let generations: Vec<String> = rows.into_iter().filter_map(|r| r.into_iter().next()).collect();
    if generations == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string()] {
        return Ok(());
    }
    if generations != vec!["1".to_string(), "2".to_string(), "3".to_string()] {
        return Err(WriterError::Invalid("unsupported ledger for 0004 upgrade"));
    }
    let ticket = store.prepare_guarded_batch("1", MIGRATION_0004_SQL, MIGRATION_0004_SQL.len())?;
    match store.submit(&ticket) {
        MutationOutcome::Committed { .. } => Ok(()),
        MutationOutcome::NotCommitted { error, .. } => {
            let again = store.exec_script("SELECT generation FROM schema_migrations ORDER BY generation;")?;
            let again: Vec<String> = again.into_iter().filter_map(|r| r.into_iter().next()).collect();
            if again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string()] {
                Ok(())
            } else {
                Err(map_submit_error(error))
            }
        }
        MutationOutcome::Conflict { detail, .. } => {
            let again = store.exec_script("SELECT generation FROM schema_migrations ORDER BY generation;")?;
            let again: Vec<String> = again.into_iter().filter_map(|r| r.into_iter().next()).collect();
            if again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string()] {
                Ok(())
            } else {
                Err(WriterError::Conflict { detail })
            }
        }
        MutationOutcome::Unknown { operation, detail } => {
            Err(WriterError::Unknown { operation, detail })
        }
    }
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
