//! Slice-B durable lifecycle: admitted -> dispatched -> terminal/unresolved.
//!
//! Factored from `mod.rs` to respect the 700-line cap; `mod.rs` stays the
//! owning writer, this module holds the additive 0006 ensure plus pure
//! lifecycle helpers and SQL bodies. Single writer only: all transitions run
//! through `Journal` guarded batches before any external send, never under
//! network, never a second writer. No backfill: missing lifecycle rows read
//! conservatively as admitted (never invented dispatched/terminal).
//!
//! Outstanding is state-filtered (terminal excluded), scope-filtered (exact
//! equality, cross-scope nondisclosure) and bounded (`LIMIT`, clamped to the
//! store replay horizon). History stays reconcile-readable via the journal
//! (no DELETE). Legacy 0004/0005 rows without lifecycle stay readable and
//! keep their stale-payload handoff refusal.

use crate::accept::AcceptedRevision;
use crate::action_journal::identity::{check_actor, ActionKind};
use crate::binding;
use crate::domain::ids::{BindingRevision, InstalledId, OperationId};
use crate::domain::scope::TrustedScope;
use crate::storage::sqlite::{MutationOutcome, SqliteStore};
use crate::storage::{StorageError, MIGRATION_0004_SQL, MIGRATION_0006_SQL};
use super::{Admitted, PendingAdmission, Result, WriterError};

/// Durable lifecycle state persisted in `action_lifecycle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Admitted,
    Dispatched,
    Terminal,
    Unresolved,
}

impl LifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Dispatched => "dispatched",
            Self::Terminal => "terminal",
            Self::Unresolved => "unresolved",
        }
    }
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "admitted" => Some(Self::Admitted),
            "dispatched" => Some(Self::Dispatched),
            "terminal" => Some(Self::Terminal),
            "unresolved" => Some(Self::Unresolved),
            _ => None,
        }
    }
    /// Terminal is final: absent from outstanding, history still readable.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }
    /// Outstanding states: admitted, dispatched, unresolved. Terminal excluded.
    pub fn is_outstanding(self) -> bool {
        !self.is_terminal()
    }
}

/// Parse nullable lifecycle text (`NULL`/empty => None) from the CLI envelope.
pub(crate) fn parse_lifecycle_nullable(raw: &str) -> Option<String> {
    crate::action_journal::identity::parse_nullable(raw)
}

/// Decode a lifecycle state with conservative default: missing (`None`)
/// reads as admitted, never invented dispatched/terminal.
pub(crate) fn decode_lifecycle_or_default(raw: Option<String>) -> Result<LifecycleState> {
    match raw {
        None => Ok(LifecycleState::Admitted),
        Some(text) => LifecycleState::parse(&text).ok_or(WriterError::Invalid("lifecycle state")),
    }
}

/// Additive 0006 ensure: validate 0005 ledger then apply 0006 once. Preserves
/// `user_version=1`; never rewrites 0004/0005; no backfill (lifecycle starts empty).
pub(crate) fn ensure_0006(store: &SqliteStore) -> Result<()> {
    let rows = store.exec_script("SELECT generation FROM schema_migrations ORDER BY generation;")?;
    let generations: Vec<String> = rows.into_iter().filter_map(|r| r.into_iter().next()).collect();
    if generations == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string(), "6".to_string()] {
        return Ok(());
    }
    if generations != vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string()] {
        return Err(WriterError::Invalid("unsupported ledger for 0006 upgrade"));
    }
    let ticket = store.prepare_guarded_batch("1", MIGRATION_0006_SQL, MIGRATION_0006_SQL.len())?;
    match store.submit(&ticket) {
        MutationOutcome::Committed { .. } => Ok(()),
        MutationOutcome::NotCommitted { error, .. } => {
            let again = store.exec_script("SELECT generation FROM schema_migrations ORDER BY generation;")?;
            let again: Vec<String> = again.into_iter().filter_map(|r| r.into_iter().next()).collect();
            if again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string(), "6".to_string()] {
                Ok(())
            } else {
                Err(crate::action_journal::identity::map_submit_error(error))
            }
        }
        MutationOutcome::Conflict { detail, .. } => {
            let again = store.exec_script("SELECT generation FROM schema_migrations ORDER BY generation;")?;
            let again: Vec<String> = again.into_iter().filter_map(|r| r.into_iter().next()).collect();
            if again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string(), "6".to_string()] {
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

/// Lifecycle INSERT for the admission batch (same writer txn as journal).
/// Predecessor is the durable obligation link (`None` for fresh admissions).
pub(crate) fn lifecycle_insert_sql(
    operation: &OperationId,
    attempt: &OperationId,
    predecessor: Option<&OperationId>,
) -> String {
    let op_q = binding::sql_quote(operation.as_str());
    let attempt_q = binding::sql_quote(attempt.as_str());
    let pred_q = match predecessor {
        None => "NULL".to_string(),
        Some(old) => binding::sql_quote(old.as_str()),
    };
    format!("INSERT INTO action_lifecycle(operation, attempt, state, updated, predecessor) VALUES ({op_q}, {attempt_q}, 'admitted', CAST(strftime('%s','now') AS INTEGER), {pred_q});")
}

/// Transition body for a guarded batch: upsert to `new_state`, preserving the
/// existing predecessor link (transitions never rewrite the obligation).
/// Callers check terminal beforehand; this body never overwrites predecessor.
pub(crate) fn transition_body(operation: &OperationId, new_state: LifecycleState) -> String {
    let op_q = binding::sql_quote(operation.as_str());
    let state_q = binding::sql_quote(new_state.as_str());
    format!("INSERT INTO action_lifecycle(operation, attempt, state, updated, predecessor) SELECT {op_q}, attempt, {state_q}, CAST(strftime('%s','now') AS INTEGER), NULL FROM action_journal WHERE operation={op_q} ON CONFLICT(operation) DO UPDATE SET state=excluded.state, updated=excluded.updated;")
}

/// Map a transition submit outcome to a typed error. `changes()==0` under
/// `Shape::Insert` surfaces as malformed-response; callers pre-check terminal
/// and existence so this is a conservative conflict, never invented success.
pub(crate) fn map_transition_error(error: StorageError) -> WriterError {
    crate::action_journal::identity::map_submit_error(error)
}

/// Bounded outstanding page SQL: state-filtered (terminal excluded, missing
/// reads as admitted/outstanding), scope-filtered (exact), ordered, `LIMIT`
/// plus `OFFSET`. Callers clamp `limit` to the store horizon; this builder
/// never invents a larger page.
pub(crate) fn outstanding_page_sql(scope: &TrustedScope, limit: u32, offset: u32) -> String {
    let scope_q = binding::sql_quote(scope.as_str());
    let limit = limit.max(1);
    format!("SELECT j.operation, j.scope, j.equipment, j.target_generation, j.actor, j.attempt, COALESCE(l.state, 'admitted') FROM action_journal j LEFT JOIN action_lifecycle l ON l.operation=j.operation WHERE j.scope={scope_q} AND COALESCE(l.state, 'admitted') != 'terminal' ORDER BY j.operation LIMIT {limit} OFFSET {offset};")
}

/// Durable `created` wall anchor for one operation (seconds since epoch).
/// Used for the 5s deadline wall check across restart; cross-boot/suspend
/// ambiguity is assessed by the expiry owner, not here.
pub(crate) fn created_select_sql(operation: &OperationId, scope: &TrustedScope) -> String {
    format!(
        "SELECT created FROM action_journal WHERE operation={} AND scope={};",
        binding::sql_quote(operation.as_str()),
        binding::sql_quote(scope.as_str()),
    )
}

/// Journal SELECT with lifecycle join: 17 journal columns plus `created`,
/// lifecycle `state` and `predecessor` (20 total). Missing lifecycle reads as
/// admitted via `COALESCE`; legacy identity NULLs stay legacy.
pub(crate) fn read_row_sql(operation: &OperationId, scope: &TrustedScope) -> String {
    format!(
        "SELECT j.operation, j.scope, j.equipment, j.binding_revision, j.accepted_revision, j.expected_generation, j.target_generation, j.payload, j.deadline_secs, j.ceiling, j.actor, j.attempt, j.state, j.wire_bits, j.action_kind, j.release_admitted, j.release_target, j.created, COALESCE(l.state, 'admitted'), l.predecessor FROM action_journal j LEFT JOIN action_lifecycle l ON l.operation=j.operation WHERE j.operation={} AND j.scope={};",
        binding::sql_quote(operation.as_str()),
        binding::sql_quote(scope.as_str()),
    )
}

/// Lossless identical-retry comparison extended for Slice B: payload text plus
/// exact wire_bits/kind/target plus durable predecessor link. Distinct
/// binary32 sharing `{:.4}` text MUST NOT reconcile; swapped kind/target or
/// a different predecessor refuses as conflict.
pub(crate) fn require_identical(pending: &PendingAdmission, found: &Admitted) -> Result<()> {
    if found.payload() != pending.payload {
        return Err(WriterError::Conflict { detail: "operation identity reused with different payload".to_string() });
    }
    let Some(found_bits) = found.wire_bits() else {
        return Err(WriterError::Conflict { detail: "operation identity reused: legacy rounded payload vs lossless identity".to_string() });
    };
    if found_bits != pending.identity().wire_bits
        || found.action_kind() != Some(pending.identity().kind)
        || found.release_admitted() != Some(pending.identity().release_admitted)
        || found.release_target().map(|t| t.as_str()) != Some(pending.identity().release_target.as_str())
    {
        return Err(WriterError::Conflict { detail: "operation identity reused with different lossless identity (bits/kind/target)".to_string() });
    }
    if found.predecessor().map(|o| o.as_str()) != pending.predecessor().map(|o| o.as_str()) {
        return Err(WriterError::Conflict { detail: "operation identity reused with different predecessor obligation link".to_string() });
    }
    Ok(())
}

/// Decode a journal row with lifecycle join: 13 (0004 legacy), 17 (0005) or
/// 20 (0006 with `created` + lifecycle + predecessor). Missing lifecycle
/// defaults to admitted/None/0-conservative; legacy keeps stale-payload refusal.
pub(crate) fn decode_row(mut row: Vec<String>, scope: &TrustedScope) -> Result<Admitted> {
    let is_legacy_shape = row.len() == 13;
    let is_identity_shape = row.len() == 17;
    let is_lifecycle_shape = row.len() == 20;
    if !is_legacy_shape && !is_identity_shape && !is_lifecycle_shape {
        return Err(WriterError::Invalid("journal row shape"));
    }
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
        .map(BindingRevision::new)
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
    if deadline_secs != crate::action_preview::DEADLINE_SECS {
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
    if is_legacy_shape {
        return Ok(Admitted { row_id: 0, operation, scope: scope.clone(), equipment, binding_revision, accepted_revision, expected_generation, target_generation, payload, deadline_secs, ceiling, actor, attempt, reconciled: false, wire_bits: None, action_kind: None, release_admitted: None, release_target: None, lifecycle: LifecycleState::Admitted, predecessor: None, created_secs: 0 });
    }
    let wire_bits = match crate::action_journal::identity::parse_nullable(&take(&mut row)?) {
        None => None,
        Some(raw) => Some(raw.parse::<u32>().map_err(|_| WriterError::Invalid("journal wire_bits"))?),
    };
    let action_kind = match crate::action_journal::identity::parse_nullable(&take(&mut row)?) {
        None => None,
        Some(raw) => Some(ActionKind::parse(&raw).ok_or(WriterError::Invalid("journal action kind"))?),
    };
    let release_admitted = match crate::action_journal::identity::parse_nullable(&take(&mut row)?) {
        None => None,
        Some(raw) => Some(match raw.as_str() { "0" => false, "1" => true, _ => return Err(WriterError::Invalid("journal release admission")) }),
    };
    let release_target = match crate::action_journal::identity::parse_nullable(&take(&mut row)?) {
        None => None,
        Some(raw) => Some(InstalledId::parse(&raw).map_err(|_| WriterError::Invalid("journal release target"))?),
    };
    let legacy = wire_bits.is_none() || action_kind.is_none() || release_admitted.is_none() || release_target.is_none();
    let complete = wire_bits.is_some() && action_kind.is_some() && release_admitted.is_some() && release_target.is_some();
    if !legacy && !complete {
        return Err(WriterError::Invalid("journal identity partial"));
    }
    if is_identity_shape {
        return Ok(Admitted { row_id: 0, operation, scope: scope.clone(), equipment, binding_revision, accepted_revision, expected_generation, target_generation, payload, deadline_secs, ceiling, actor, attempt, reconciled: false, wire_bits, action_kind, release_admitted, release_target, lifecycle: LifecycleState::Admitted, predecessor: None, created_secs: 0 });
    }
    // Lifecycle shape: created + state + predecessor.
    let created_secs = take(&mut row)?
        .parse::<i64>()
        .map_err(|_| WriterError::Invalid("journal created"))?;
    let lifecycle_raw = parse_lifecycle_nullable(&take(&mut row)?);
    let lifecycle = decode_lifecycle_or_default(lifecycle_raw)?;
    let predecessor = match crate::action_journal::identity::parse_nullable(&take(&mut row)?) {
        None => None,
        Some(raw) => {
            let unquoted = if raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2 {
                raw[1..raw.len() - 1].replace("''", "'")
            } else {
                raw
            };
            Some(OperationId::parse(&unquoted).map_err(|_| WriterError::Invalid("lifecycle predecessor"))?)
        }
    };
    Ok(Admitted { row_id: 0, operation, scope: scope.clone(), equipment, binding_revision, accepted_revision, expected_generation, target_generation, payload, deadline_secs, ceiling, actor, attempt, reconciled: false, wire_bits, action_kind, release_admitted, release_target, lifecycle, predecessor, created_secs })
}

pub(crate) fn ensure_0004(store: &SqliteStore) -> Result<()> {
    let rows = store.exec_script("SELECT generation FROM schema_migrations ORDER BY generation;")?;
    let generations: Vec<String> = rows.into_iter().filter_map(|r| r.into_iter().next()).collect();
    if generations == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string()]
        || generations == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string()]
        || generations == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string(), "6".to_string()] {
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
            if again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string()]
                || again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string()]
                || again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string(), "6".to_string()] {
                Ok(())
            } else {
                Err(crate::action_journal::identity::map_submit_error(error))
            }
        }
        MutationOutcome::Conflict { detail, .. } => {
            let again = store.exec_script("SELECT generation FROM schema_migrations ORDER BY generation;")?;
            let again: Vec<String> = again.into_iter().filter_map(|r| r.into_iter().next()).collect();
            if again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string()]
                || again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string()]
                || again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string(), "6".to_string()] {
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
