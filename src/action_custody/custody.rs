//! Thin custody delegation: read-only consumes plus narrow calls.
//!
//! Every function below delegates to exactly one owning API and adds only
//! the custody-level refusal or verdict mapping: scoped holds, pre-handoff
//! revocation ordering, transfer-narrow gating, and constrained-cleanup
//! limits. No guard SQL, frozen-profile check, alias rule, CAS, or transport
//! is re-derived here. Lock discipline follows the owner: accept/journal
//! reconciles run under the admitted writer barrier (short, bounded, no
//! network); dispatch/expiry/recovery checks hold no SQL guard and no
//! building-wide lock; the adapter op (owned by the harness) runs with NO
//! SQL guard and NO building-wide lock on a per-target frozen route only.

use super::policy::{
    authorize_constrained_cleanup as policy_cleanup, check_held_for_cleanup,
    check_pre_handoff_not_revoked, check_transfer_equivalence, check_transfer_narrow,
    clamp_page_limit, inspection_visible,
};
use super::{CustodyError, Result, ScopeHolds};
use crate::accept::AcceptanceStore;
use crate::action_dispatch::{Current, DispatchCancel, FrozenRoute, FrozenWrite};
use crate::action_expiry::ExpiryState;
use crate::action_journal::{Admitted, Journal, PendingAdmission};
use crate::action_preview::Preview;
use crate::action_publication::{ImpactGate, OldWriterExclusion};
use crate::domain::ids::{InstalledId, OperationId};
use crate::domain::outcomes::RecordIdentity;
use crate::domain::scope::TrustedScope;
use crate::observation::time::Freshness;
use std::time::Instant;

/// One outstanding action visible within its own scope: the journal
/// operation plus the target/allocation/generation identities needed for
/// cleanup and reconcile. Cross-scope callers never observe this row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutstandingAction {
    operation: OperationId,
    scope: TrustedScope,
    equipment: InstalledId,
    target_generation: u32,
    actor: String,
    attempt: OperationId,
}

impl OutstandingAction {
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }
    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }
    pub fn equipment(&self) -> &InstalledId {
        &self.equipment
    }
    pub fn target_generation(&self) -> u32 {
        self.target_generation
    }
    pub fn actor(&self) -> &str {
        &self.actor
    }
    pub fn attempt(&self) -> &OperationId {
        &self.attempt
    }
}

/// Verify content plus generation at the local handoff boundary with scoped
/// holds, manual exclusion, and pre-handoff revocation ordered alongside.
/// Delegates frozen-profile, actor, ceiling, binding, payload, and
/// generation checks to publication/recovery; adds only the custody gates.
pub fn verify_handoff_via_custody(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    holds: &ScopeHolds,
    exclusion: Option<&OldWriterExclusion>,
    is_revoked: bool,
) -> Result<()> {
    holds.check_not_held(admitted.scope().as_str())?;
    check_pre_handoff_not_revoked(is_revoked, admitted.actor())?;
    crate::action_publication::verify_handoff_via_publication(
        admitted, preview, current, route, exclusion, is_revoked,
    )
    .map_err(CustodyError::from)
}

/// Authorize one frozen SET handoff after the custody gates, then delegate
/// to the existing publication gate (impact plus expiry plus dispatch).
/// A held scope blocks new handoffs; pending rows are kept. No profile
/// widening.
#[allow(clippy::too_many_arguments)]
pub fn authorize_setpoint_via_custody(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    expiry: &ExpiryState,
    freshness: Freshness,
    holds: &ScopeHolds,
    exclusion: Option<&OldWriterExclusion>,
    is_revoked: bool,
    impact: &ImpactGate,
) -> Result<FrozenWrite> {
    holds.check_not_held(admitted.scope().as_str())?;
    check_pre_handoff_not_revoked(is_revoked, admitted.actor())?;
    crate::action_publication::authorize_setpoint_via_publication(
        admitted, preview, current, route, cancel, deadline, expiry, freshness, exclusion,
        is_revoked, impact,
    )
    .map_err(CustodyError::from)
}

/// Authorize one frozen NULL release via the same custody gates, then
/// delegate to the existing publication release path. Expired or
/// indeterminate time still permits an admitted NULL release; freshness
/// therefore does not gate release. NULL-only admission stays verbatim.
/// Held scope permits only original-target admitted-null-release; other
/// cleanup on a held scope returns explicit blocked-cleanup with the
/// obligation still outstanding (never hidden by a generic held error).
#[allow(clippy::too_many_arguments)]
pub fn authorize_release_via_custody(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    expiry: &ExpiryState,
    freshness: Freshness,
    holds: &ScopeHolds,
    exclusion: Option<&OldWriterExclusion>,
    is_revoked: bool,
    impact: &ImpactGate,
) -> Result<FrozenWrite> {
    let is_original = admitted.action_kind().map(|k| k.as_str()) == Some("release")
        && admitted.release_admitted() == Some(true)
        && preview.release_admitted()
        && admitted.release_target().map(|t| t.as_str()) == Some(preview.release_target().as_str())
        && admitted.equipment().as_str() == preview.target().equipment().as_str();
    check_held_for_cleanup(holds, admitted.scope().as_str(), "admitted-null-release", is_original)?;
    check_pre_handoff_not_revoked(is_revoked, admitted.actor())?;
    crate::action_publication::authorize_release_via_publication(
        admitted, preview, current, route, cancel, deadline, expiry, freshness, exclusion,
        is_revoked, impact,
    )
    .map_err(CustodyError::from)
}

/// Recheck generation plus cancellation after the adapter op, with no SQL
/// guard. Thin delegation to the publication recheck.
pub fn recheck_after_handoff_via_custody(
    admitted: &Admitted,
    current: &Current,
    cancel: &DispatchCancel,
    deadline: Instant,
) -> Result<()> {
    crate::action_publication::recheck_after_handoff_via_publication(
        admitted, current, cancel, deadline,
    )
    .map_err(CustodyError::from)
}

/// Inspect outstanding actions within one scope. Bounded page via the Journal
/// owner: state-filtered (terminal excluded), exact scope filter, `LIMIT`
/// clamped to the store horizon. Cross-scope callers observe nothing.
/// Pending rows are kept and stay visible; this read never erases.
pub fn inspect_outstanding(
    journal: &Journal,
    scope: &TrustedScope,
) -> Result<Vec<OutstandingAction>> {
    inspect_outstanding_bounded(journal, scope, journal.store().bounds().max_replay_rows, 0)
}

/// Bounded outstanding page consumer (thin delegation to the Journal owner).
/// `limit` is clamped to the store horizon; `offset` pages through history.
pub fn inspect_outstanding_bounded(
    journal: &Journal,
    scope: &TrustedScope,
    limit: u32,
    offset: u32,
) -> Result<Vec<OutstandingAction>> {
    let bound = clamp_page_limit(limit, journal.store().bounds().max_replay_rows);
    let page = journal.outstanding_page(scope, bound, offset).map_err(CustodyError::from)?;
    let mut out = Vec::new();
    for admitted in page {
        if !inspection_visible(admitted.scope().as_str(), scope.as_str()) {
            return Err(CustodyError::Invalid("inspection scope leak"));
        }
        out.push(OutstandingAction {
            operation: admitted.operation().clone(),
            scope: scope.clone(),
            equipment: admitted.equipment().clone(),
            target_generation: admitted.target_generation(),
            actor: admitted.actor().to_string(),
            attempt: admitted.attempt().clone(),
        });
    }
    Ok(out)
}

/// Reconcile one journaled operation from durable rows (read-only recovery).
/// Cross-scope callers see `admission-not-found`, never another scope's row.
pub fn reconcile_journal_via_custody(
    journal: &Journal,
    operation: &OperationId,
    scope: &TrustedScope,
) -> Result<Admitted> {
    crate::action_recovery::reconcile_journal(journal, operation, scope).map_err(CustodyError::from)
}

/// Reconcile a persisted pending release from durable rows without resending.
/// Lost acknowledgment stays UNKNOWN until this reconcile recovers the
/// original identities.
pub fn reconcile_pending_release_via_custody(
    pending: &crate::action_expiry::PendingRelease,
    journal: &Journal,
) -> Result<Admitted> {
    crate::action_recovery::reconcile_pending_release(pending, journal).map_err(CustodyError::from)
}

/// Transfer-narrow via NEW admission (TRANSFER NARROW): move unresolved
/// responsibility from an expired/offboarded actor to an active permitted
/// role. Long reads (old reconcile is caller-supplied via `old`) happen
/// before the ticket; the new ticket carries the exact journal guards plus
/// the durable predecessor obligation link in the same batch; no network runs
/// under the SQL transaction; announce/recheck after commit is owned by
/// `Journal::submit`. Old IDs and authorship are preserved (the old row is
/// never rewritten); the old actor must be excluded (real `AccessGate`
/// revocation observed by the caller); the new actor must already be
/// permitted (never broadened here); never orphaned without owner. The
/// successor must be equivalent on equipment/slot/value/wire_bits/kind/
/// binding+accepted revisions (any change needs a separate authorized SET;
/// release cannot migrate hardware). A held scope blocks the new admission.
#[allow(clippy::too_many_arguments)]
pub fn transfer_narrow_via_new_admission(
    journal: &mut Journal,
    old: &Admitted,
    new_operation: OperationId,
    new_scope: TrustedScope,
    new_ceiling: u8,
    new_role: crate::access::RoleKind,
    new_actor: &str,
    new_preview: &Preview,
    new_expected_generation: u32,
    holds: &ScopeHolds,
    exclusion: Option<&OldWriterExclusion>,
    new_is_permitted: bool,
) -> Result<Admitted> {
    holds.check_not_held(new_scope.as_str())?;
    if old.scope().as_str() != new_scope.as_str() {
        return Err(CustodyError::Transfer {
            detail: "transfer stays within the admitted scope; never broaden scope automatically"
                .to_string(),
        });
    }
    let old_excluded = exclusion.map(|e| e.excludes(old.actor())).unwrap_or(false);
    check_transfer_narrow(
        old.operation().as_str(),
        new_operation.as_str(),
        old.actor(),
        new_actor,
        old_excluded,
        new_is_permitted,
    )?;
    // Durable equivalence attestation before the ticket (pure, no I/O).
    check_transfer_equivalence(old, new_preview)?;
    let pending = journal
        .prepare_with_predecessor(
            new_operation,
            new_scope,
            new_ceiling,
            new_role,
            new_actor,
            new_preview,
            new_expected_generation,
            Some(old.operation().clone()),
        )
        .map_err(CustodyError::from)?;
    journal.submit(&pending).map_err(CustodyError::from)
}

/// Authorize an explicit cancel of an unattempted generation. Exact
/// generation equality only; a stale cancel for an old generation refuses
/// and leaves the current generation unaffected.
pub fn authorize_cancel_via_custody(expected_generation: u32, current_generation: u32) -> Result<()> {
    crate::action_expiry::authorize_cancel(expected_generation, current_generation)
        .map_err(CustodyError::from)
}

/// Drop a prepared intent before submit: no row, no handoff. Duplicate
/// cancels of the same unattempted identities remain idempotent.
pub fn cancel_pending(pending: PendingAdmission) {
    Journal::cancel(pending);
}

/// Constrained-cleanup gate: only `cancel-unattempted` and
/// `admitted-null-release` exist; LOTO/emergency-stop, all-slot reset,
/// actor-history deletion, broad grants, and notification/work/MCP bypasses
/// are refused with limits plus escalation.
pub fn authorize_constrained_cleanup(request: &str) -> Result<()> {
    policy_cleanup(request)
}

/// Equal slot values are never ownership proof. Always `false` by
/// construction; call sites must compare full identities instead.
pub fn slot_value_proves_ownership_via_custody() -> bool {
    crate::action_recovery::slot_value_proves_ownership()
}

/// Preserve subsequent observations by full [`RecordIdentity`] equality.
/// Thin delegation to the pure identity table; never a sequence-only compare.
pub fn is_same_record(expected: &RecordIdentity, found: &RecordIdentity) -> bool {
    crate::action_recovery::is_same_record(expected, found)
}

/// Require full identity equality for a subsequent observation.
pub fn require_same_observation_via_custody(
    expected: &RecordIdentity,
    found: &RecordIdentity,
) -> Result<()> {
    crate::action_recovery::require_same_observation(expected, found).map_err(CustodyError::from)
}

/// Verify a restored backup against the current durable row without
/// overwriting newer state. REFUSE STALE: intact means the exact ledger
/// match; anything else refuses as conflict or stale.
pub fn verify_backup_against_current_via_custody(
    store_identity_matches: bool,
    restored: &Admitted,
    current: &Admitted,
) -> Result<crate::action_recovery::BackupVerdict> {
    crate::action_recovery::verify_backup_against_current(
        store_identity_matches,
        restored,
        current,
    )
    .map_err(CustodyError::from)
}

/// Require the admitted revisions to match the currently accepted
/// publication before a new handoff. Thin delegation to publication; never
/// auto-promotes, never restores a superseded pointer.
pub fn require_activation_current_for_handoff_via_custody(
    store: &AcceptanceStore,
    scope: &TrustedScope,
    admitted_binding_revision: crate::domain::ids::BindingRevision,
    admitted_accepted_revision: crate::accept::AcceptedRevision,
) -> Result<()> {
    crate::action_publication::require_activation_current_for_handoff(
        store,
        scope,
        admitted_binding_revision,
        admitted_accepted_revision,
    )
    .map_err(CustodyError::from)
}

/// Require alias uniqueness without disclosure. Thin delegation to the
/// preview alias set.
pub fn require_aliases_unique_via_custody(aliases: &[&str]) -> Result<()> {
    crate::action_publication::require_aliases_unique(aliases).map_err(CustodyError::from)
}

/// Require peer acceptance before a journal result may be treated as more
/// than journaled intent. Thin delegation to the pure ordering gate.
pub fn require_peer_accepted_before_journal_via_custody(
    peer_accepted: bool,
    journal_announced: bool,
) -> Result<crate::action_recovery::OrderingVerdict> {
    crate::action_publication::require_peer_accepted_before_journal_via_publication(
        peer_accepted,
        journal_announced,
    )
    .map_err(CustodyError::from)
}

/// Joined admission through the owned Slice C path (seal verified + guarded
/// Journal batch). Thin delegation to `crate::action_joined`; raw
/// `Journal::prepare`/`admit` bypass the seal/activation/wall barriers.
#[allow(clippy::too_many_arguments)]
pub fn admit_joined_via_custody(
    journal: &mut Journal,
    operation: OperationId,
    scope: TrustedScope,
    ceiling: u8,
    role: crate::access::RoleKind,
    actor: &str,
    preview: &Preview,
    expected_generation: u32,
) -> Result<Admitted> {
    crate::action_joined::admit_joined(
        journal, operation, scope, ceiling, role, actor, preview, expected_generation,
    )
}

/// Joined SET authorization through the owned path (activation + holds +
/// revocation + wall + dispatch, fresh post-admission reads). Thin
/// delegation to `crate::action_joined`.
#[allow(clippy::too_many_arguments)]
pub fn authorize_joined_setpoint_via_custody(
    journal: &Journal,
    store: &AcceptanceStore,
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    expiry: &ExpiryState,
    freshness: Freshness,
    holds: &ScopeHolds,
    exclusion: Option<&OldWriterExclusion>,
    is_revoked: bool,
    impact: &ImpactGate,
) -> Result<FrozenWrite> {
    crate::action_joined::authorize_joined_setpoint(
        journal, store, admitted, preview, current, route, cancel, deadline, expiry,
        freshness, holds, exclusion, is_revoked, impact,
    )
}

/// Joined NULL-release authorization through the owned path (constrained
/// cleanup stays exempt from wall expiry). Thin delegation to joined.
#[allow(clippy::too_many_arguments)]
pub fn authorize_joined_release_via_custody(
    journal: &Journal,
    store: &AcceptanceStore,
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    expiry: &ExpiryState,
    freshness: Freshness,
    holds: &ScopeHolds,
    exclusion: Option<&OldWriterExclusion>,
    is_revoked: bool,
    impact: &ImpactGate,
) -> Result<FrozenWrite> {
    crate::action_joined::authorize_joined_release(
        journal, store, admitted, preview, current, route, cancel, deadline, expiry,
        freshness, holds, exclusion, is_revoked, impact,
    )
}
