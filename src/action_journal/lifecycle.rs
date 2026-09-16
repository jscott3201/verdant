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

/// Cleanup horizon for terminal SET obligations: 15 minutes (900s), the same
/// admitted duration (`DURATION_SECS`). A terminal SET within this horizon
/// still carries its original-target cleanup obligation (relinquish the slot
/// via an admitted-NULL with a predecessor link); beyond it the obligation is
/// expired and no longer returned here. No new column/table/migration; this
/// reads only existing `action_journal` + `action_lifecycle` columns.
pub const CLEANUP_HORIZON_SECS: u64 = crate::action_preview::DURATION_SECS;

/// Pure horizon predicate for the cleanup scan (deterministic seam, no I/O).
/// True only when `created <= now < created + horizon` (elapsed `0..horizon`).
/// Rollback (`now < created`), exact-horizon expiry (`elapsed >= horizon`),
/// and overflow all report `false` (not due), never an invented obligation.
pub fn is_cleanup_due(created_secs: i64, now_secs: i64, horizon_secs: u64) -> bool {
    let horizon = i64::try_from(horizon_secs).unwrap_or(i64::MAX);
    match now_secs.checked_sub(created_secs) {
        None => false,
        Some(delta) if delta < 0 => false,
        Some(delta) => delta < horizon,
    }
}

/// Bounded cleanup-obligation SELECT over existing columns: terminal SET rows
/// in one scope within the horizon. State-filtered (`terminal` only, history
/// rows unchanged), kind-filtered (`set` only), scope-filtered (exact),
/// horizon-filtered (`created <= now` and `created > now - horizon`),
/// ordered, `LIMIT` plus `OFFSET`. Callers clamp `limit` to the store
/// horizon; this builder never invents a larger page. No `0007`, no receipt
/// columns.
pub(crate) fn cleanup_obligations_sql(
    scope: &TrustedScope,
    limit: u32,
    offset: u32,
    now_secs: i64,
    horizon_secs: u64,
) -> String {
    let scope_q = binding::sql_quote(scope.as_str());
    let limit = limit.max(1);
    let horizon = i64::try_from(horizon_secs).unwrap_or(i64::MAX);
    let cutoff = now_secs.checked_sub(horizon).unwrap_or(i64::MIN);
    format!("SELECT j.operation FROM action_journal j JOIN action_lifecycle l ON l.operation=j.operation WHERE j.scope={scope_q} AND l.state='terminal' AND j.action_kind='set' AND j.created <= {now_secs} AND j.created > {cutoff} ORDER BY j.operation LIMIT {limit} OFFSET {offset};")
}

/// Bounded cleanup-obligation discovery against an explicit wall `now_secs`
/// (deterministic seam; product callers pass the live wall via
/// [`cleanup_obligations`]). Read-only: `SELECT` plus scoped `reconcile`
/// hydration; Terminal history rows are never marked, moved, or deleted.
/// Scope-filtered (exact equality, cross-scope nondisclosure), `LIMIT`
/// clamped to the store horizon. Only terminal SET rows within
/// [`CLEANUP_HORIZON_SECS`] are returned; admitted/dispatched/unresolved,
/// release kinds, out-of-horizon, and rollback rows are excluded (Rust
/// re-checks the SQL filters so drift fails closed, never invents).
pub fn cleanup_obligations_with_now(
    journal: &super::Journal,
    scope: &TrustedScope,
    limit: u32,
    offset: u32,
    now_secs: i64,
) -> Result<Vec<Admitted>> {
    let bound = limit.min(journal.store().bounds().max_replay_rows).max(1);
    let horizon = CLEANUP_HORIZON_SECS;
    let script = cleanup_obligations_sql(scope, bound, offset, now_secs, horizon);
    let rows = journal.store().exec_script(&script)?;
    let mut out = Vec::new();
    for row in rows {
        if row.len() != 1 {
            return Err(WriterError::Invalid("cleanup row shape"));
        }
        let operation =
            OperationId::parse(&row[0]).map_err(|_| WriterError::Invalid("cleanup operation"))?;
        let admitted = journal.reconcile(&operation, scope)?;
        if admitted.lifecycle() != LifecycleState::Terminal {
            continue;
        }
        if admitted.action_kind() != Some(ActionKind::Set) {
            continue;
        }
        if !is_cleanup_due(admitted.created_secs(), now_secs, horizon) {
            continue;
        }
        if admitted.scope().as_str() != scope.as_str() {
            return Err(WriterError::ScopeDenied {
                expected: scope.as_str().to_string(),
                presented: admitted.scope().as_str().to_string(),
            });
        }
        out.push(admitted);
    }
    Ok(out)
}

/// Bounded cleanup-obligation discovery against the live wall (one live-wall
/// case; deterministic tests use [`cleanup_obligations_with_now`]). Same
/// read-only, scope-filtered, LIMIT-clamped terminal-SET-within-horizon scan
/// as above; a clock before the epoch refuses as invalid, never a renewed
/// window.
pub fn cleanup_obligations(
    journal: &super::Journal,
    scope: &TrustedScope,
    limit: u32,
    offset: u32,
) -> Result<Vec<Admitted>> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .map_err(|_| WriterError::Invalid("cleanup wall indeterminate: clock before epoch"))?;
    cleanup_obligations_with_now(journal, scope, limit, offset, now_secs)
}
