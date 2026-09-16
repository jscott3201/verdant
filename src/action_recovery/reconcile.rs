//! Thin reconciliation delegation: read-only consumes plus narrow calls.
//!
//! Every function below delegates to exactly one owning API and adds only the
//! recovery-level refusal or verdict mapping. No guard SQL, frozen-profile
//! check, or transport is re-derived here. Lock discipline follows the owner:
//! journal/store reconciles run under the admitted writer barrier (short,
//! bounded, no network); dispatch/expiry checks hold no SQL guard and no
//! building-wide lock.

use super::decisions::{
    assess_conflicting_request, check_peer_accepted_before_journal, classify_observation,
    require_current_generation, require_intact_backup, require_same_record, verify_backup,
    BackupVerdict, ConflictWait, ObservationVerdict, OrderingVerdict, PeerAcceptance, QuiescenceClaim,
};
use super::{RecoveryError, Result};
use crate::action_dispatch::{
    Current, DispatchCancel, FrozenRoute, FrozenWrite, ProtocolResult,
};
use crate::action_expiry::ExpiryState;
use crate::action_journal::{Admitted, Journal};
use crate::action_preview::Preview;
use crate::domain::ids::OperationId;
use crate::domain::outcomes::RecordIdentity;
use crate::domain::scope::TrustedScope;
use crate::observation::time::Freshness;
use crate::storage::sqlite::{MutationOutcome, PreparedMutation, SqliteStore};
use std::time::Instant;

/// Reconcile one journaled operation from durable rows (read-only recovery).
/// Cross-scope callers see `admission-not-found`, never another scope's row.
pub fn reconcile_journal(
    journal: &Journal,
    operation: &OperationId,
    scope: &TrustedScope,
) -> Result<Admitted> {
    journal.reconcile(operation, scope).map_err(RecoveryError::from)
}

/// Reconcile a persisted pending release from durable rows without resending.
/// Lost acknowledgment stays UNKNOWN until this reconcile recovers the
/// original identities.
pub fn reconcile_pending_release(
    pending: &crate::action_expiry::PendingRelease,
    journal: &Journal,
) -> Result<Admitted> {
    pending.reconcile_via(journal).map_err(RecoveryError::from)
}

/// Read-only store reconciliation under the writer barrier for one ticket.
/// Absence at the barrier is a known non-commit there, not permission for a
/// still-running caller to dispatch different work.
pub fn reconcile_store_ticket(
    store: &SqliteStore,
    ticket: &PreparedMutation,
) -> Result<MutationOutcome> {
    Ok(store.reconcile(ticket))
}

/// Read-only store reconciliation by operation identity. Looks up evidence
/// only; never dispatches another attempt.
pub fn reconcile_store_operation(
    store: &SqliteStore,
    operation: &OperationId,
) -> Result<MutationOutcome> {
    Ok(store.reconcile_operation(operation))
}

/// Verify content plus generation at the local handoff boundary with no SQL
/// guard and no building-wide lock. Delegates frozen-profile, actor, ceiling,
/// binding, payload, and generation checks to dispatch.
pub fn verify_handoff(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
) -> Result<()> {
    crate::action_dispatch::verify_content(admitted, preview, current, route)
        .map_err(RecoveryError::from)?;
    crate::action_dispatch::verify_generation(admitted, current).map_err(RecoveryError::from)?;
    Ok(())
}

/// Prepare one frozen SET write via dispatch (AV2/PV85/P8 Real only).
pub fn prepare_setpoint_via_dispatch(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
) -> Result<FrozenWrite> {
    crate::action_dispatch::prepare_setpoint(admitted, preview, current, route, cancel, deadline)
        .map_err(RecoveryError::from)
}

/// Prepare one frozen NULL release via dispatch (admitted releases only).
pub fn prepare_release_via_dispatch(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
) -> Result<FrozenWrite> {
    crate::action_dispatch::prepare_release(admitted, preview, current, route, cancel, deadline)
        .map_err(RecoveryError::from)
}

/// Recheck generation plus cancellation after the adapter op, with no SQL guard.
pub fn recheck_after_handoff_via_dispatch(
    admitted: &Admitted,
    current: &Current,
    cancel: &DispatchCancel,
    deadline: Instant,
) -> Result<()> {
    crate::action_dispatch::recheck_after_handoff(admitted, current, cancel, deadline)
        .map_err(RecoveryError::from)
}

/// Authorize one frozen SET handoff after the expiry/freshness gate via expiry.
pub fn authorize_set_via_expiry(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    expiry: &ExpiryState,
    freshness: Freshness,
) -> Result<FrozenWrite> {
    crate::action_expiry::authorize_set(
        admitted, preview, current, route, cancel, deadline, expiry, freshness,
    )
    .map_err(RecoveryError::from)
}

/// Authorize an explicit cancel of an unattempted generation via expiry.
/// Exact generation equality only; stale cancels refuse.
pub fn authorize_cancel_via_expiry(expected_generation: u32, current_generation: u32) -> Result<()> {
    crate::action_expiry::authorize_cancel(expected_generation, current_generation)
        .map_err(RecoveryError::from)
}

/// Joined SET authorization through the owned Slice C path (seal + activation
/// + holds + wall + dispatch). Thin delegation to `crate::action_joined`;
/// raw `prepare_setpoint_via_dispatch` bypasses those barriers. Returns the
/// joined (custody) error so machine codes stay preserved.
#[allow(clippy::too_many_arguments)]
pub fn authorize_joined_setpoint_via_recovery(
    journal: &Journal,
    store: &crate::accept::AcceptanceStore,
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    expiry: &ExpiryState,
    freshness: Freshness,
    holds: &crate::action_custody::ScopeHolds,
    exclusion: Option<&crate::action_publication::OldWriterExclusion>,
    is_revoked: bool,
    impact: &crate::action_publication::ImpactGate,
) -> std::result::Result<FrozenWrite, crate::action_custody::CustodyError> {
    crate::action_joined::authorize_joined_setpoint(
        journal, store, admitted, preview, current, route, cancel, deadline, expiry,
        freshness, holds, exclusion, is_revoked, impact,
    )
}

/// Authorize one frozen NULL release via expiry. Expired or indeterminate
/// time still permits an admitted NULL release; freshness does not gate it.
pub fn authorize_release_via_expiry(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    expiry: &ExpiryState,
    freshness: Freshness,
) -> Result<FrozenWrite> {
    crate::action_expiry::authorize_release(
        admitted, preview, current, route, cancel, deadline, expiry, freshness,
    )
    .map_err(RecoveryError::from)
}

/// Require peer acceptance before a journal result may be treated as more
/// than journaled intent. Thin wrapper over the pure ordering gate.
pub fn require_peer_accepted_before_journal(
    peer_accepted: bool,
    journal_announced: bool,
) -> Result<OrderingVerdict> {
    check_peer_accepted_before_journal(peer_accepted, journal_announced)
}

/// Map a protocol result to peer acceptance without resending on uncertainty.
pub fn peer_acceptance(protocol: &ProtocolResult) -> PeerAcceptance {
    super::decisions::classify_peer_protocol(protocol)
}

/// Require the qualified recovery procedure for a later conflicting request.
/// Reconciles peer state plus transport ownership first; refuses
/// lease-quiescence; never replays retained actions.
pub fn require_qualified_recovery(
    peer_reconciled: bool,
    transport_owned: bool,
    qualified_recovery_done: bool,
    quiescence: QuiescenceClaim,
) -> Result<ConflictWait> {
    assess_conflicting_request(
        peer_reconciled,
        transport_owned,
        qualified_recovery_done,
        quiescence,
    )
}

/// Reconcile current peer state and transport ownership before a conflicting
/// generation proceeds. Delegates content/generation verification to dispatch
/// (frozen route realm plus expected-generation equality); a mismatch waits
/// for qualified recovery rather than overwriting.
pub fn require_reconciled_peer_and_transport(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
) -> Result<()> {
    verify_handoff(admitted, preview, current, route)
}

/// Verify a restored backup against the current durable row without
/// overwriting newer state. REFUSE STALE: intact means the exact ledger
/// match (same payload, same generations, same scope/equipment, same store);
/// anything else refuses as conflict or stale.
pub fn verify_backup_against_current(
    store_identity_matches: bool,
    restored: &Admitted,
    current: &Admitted,
) -> Result<BackupVerdict> {
    let same_id_content_matches = restored.operation().as_str() == current.operation().as_str()
        && restored.payload() == current.payload()
        && restored.expected_generation() == current.expected_generation()
        && restored.target_generation() == current.target_generation()
        && restored.scope().as_str() == current.scope().as_str()
        && restored.equipment().as_str() == current.equipment().as_str();
    let verdict = verify_backup(
        store_identity_matches,
        same_id_content_matches,
        restored.target_generation(),
        current.target_generation(),
    );
    // A stale target generation is the REFUSE STALE path even when the
    // content otherwise matches: the restored ledger is older, not intact.
    if restored.target_generation() != current.target_generation()
        && restored.operation().as_str() == current.operation().as_str()
        && store_identity_matches
        && same_id_content_matches
    {
        require_current_generation(
            restored.target_generation(),
            current.target_generation(),
        )?;
    }
    require_intact_backup(verdict)?;
    Ok(verdict)
}

/// Preserve subsequent observations by full [`RecordIdentity`] equality.
/// Thin delegation to the pure identity table; never a sequence-only compare.
pub fn is_same_record(expected: &RecordIdentity, found: &RecordIdentity) -> bool {
    classify_observation(expected, found) == ObservationVerdict::SameRecord
}

/// Require full identity equality for a subsequent observation.
pub fn require_same_observation(
    expected: &RecordIdentity,
    found: &RecordIdentity,
) -> Result<()> {
    require_same_record(expected, found)
}

/// Equal slot values are never ownership proof. Always `false` by
/// construction; call sites must compare full identities instead.
pub fn slot_value_proves_ownership() -> bool {
    super::decisions::slot_value_proves_ownership()
}
