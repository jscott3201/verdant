//! Thin publication delegation: read-only consumes plus narrow calls.
//!
//! Every function below delegates to exactly one owning API and adds only
//! the publication-level refusal or verdict mapping: manual exclusion,
//! pre-handoff revocation ordering, and material-impact blocking. No guard
//! SQL, frozen-profile check, alias rule, or transport is re-derived here.
//! Lock discipline follows the owner: accept/journal reconciles run under
//! the admitted writer barrier (short, bounded, no network);
//! dispatch/expiry/recovery checks hold no SQL guard and no building-wide
//! lock; the adapter op (owned by the harness) runs with NO SQL guard and
//! NO building-wide lock on a per-target frozen route only.

use super::policy::{check_not_excluded, check_pre_handoff_not_revoked, ImpactGate, OldWriterExclusion};
use super::{PublicationError, Result};
use crate::accept::AcceptanceStore;
use crate::action_dispatch::{Current, DispatchCancel, FrozenRoute, FrozenWrite};
use crate::action_expiry::ExpiryState;
use crate::action_journal::Admitted;
use crate::action_preview::Preview;
use crate::observation::time::Freshness;
use std::time::Instant;

/// Verify content plus generation at the local handoff boundary with manual
/// exclusion and pre-handoff revocation ordered alongside. Delegates the
/// frozen-profile, actor, ceiling, binding, payload, and generation checks
/// to recovery/dispatch; adds only the publication gates.
pub fn verify_handoff_via_publication(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    exclusion: Option<&OldWriterExclusion>,
    is_revoked: bool,
) -> Result<()> {
    check_not_excluded(exclusion, admitted.actor())?;
    check_not_excluded(exclusion, current.actor())?;
    check_pre_handoff_not_revoked(is_revoked, admitted.actor())?;
    crate::action_recovery::verify_handoff(admitted, preview, current, route)
        .map_err(PublicationError::from)
}

/// Authorize one frozen SET handoff after the publication gates, then
/// delegate to the existing expiry gate (time) and dispatch preparation
/// (actor/ceiling/policy/binding/generation/value/deadline plus cooperative
/// cancellation). Material impact blocks until accepted; exclusion and
/// pre-handoff revocation refuse before any send. No profile widening.
#[allow(clippy::too_many_arguments)]
pub fn authorize_setpoint_via_publication(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    expiry: &ExpiryState,
    freshness: Freshness,
    exclusion: Option<&OldWriterExclusion>,
    is_revoked: bool,
    impact: &ImpactGate,
) -> Result<FrozenWrite> {
    check_not_excluded(exclusion, admitted.actor())?;
    check_not_excluded(exclusion, current.actor())?;
    check_pre_handoff_not_revoked(is_revoked, admitted.actor())?;
    impact.require_preserved()?;
    crate::action_expiry::authorize_set(
        admitted, preview, current, route, cancel, deadline, expiry, freshness,
    )
    .map_err(PublicationError::from)
}

/// Authorize one frozen NULL release via the same publication gates, then
/// delegate to the existing expiry release path. Expired or indeterminate
/// time still permits an admitted NULL release (cancel-or-NULL only after
/// expiry); freshness therefore does not gate release. NULL-only admission
/// stays verbatim: a non-admitted NULL refuses, never widens.
#[allow(clippy::too_many_arguments)]
pub fn authorize_release_via_publication(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    expiry: &ExpiryState,
    freshness: Freshness,
    exclusion: Option<&OldWriterExclusion>,
    is_revoked: bool,
    impact: &ImpactGate,
) -> Result<FrozenWrite> {
    check_not_excluded(exclusion, admitted.actor())?;
    check_not_excluded(exclusion, current.actor())?;
    check_pre_handoff_not_revoked(is_revoked, admitted.actor())?;
    impact.require_preserved()?;
    crate::action_expiry::authorize_release(
        admitted, preview, current, route, cancel, deadline, expiry, freshness,
    )
    .map_err(PublicationError::from)
}

/// Recheck generation plus cancellation after the adapter op, with no SQL
/// guard. Thin delegation to the recovery recheck.
pub fn recheck_after_handoff_via_publication(
    admitted: &Admitted,
    current: &Current,
    cancel: &DispatchCancel,
    deadline: Instant,
) -> Result<()> {
    crate::action_recovery::recheck_after_handoff_via_dispatch(admitted, current, cancel, deadline)
        .map_err(PublicationError::from)
}

/// Require alias uniqueness without disclosure: a duplicate alias refuses
/// with the preserved `duplicate-identity` code carrying only the alias,
/// never another scope's row. Thin delegation to the preview alias set.
pub fn require_aliases_unique(aliases: &[&str]) -> Result<()> {
    let _ = crate::action_preview::AliasSet::new(aliases).map_err(PublicationError::from)?;
    Ok(())
}

/// Require peer acceptance before a journal result may be treated as more
/// than journaled intent. Thin delegation to the pure ordering gate.
pub fn require_peer_accepted_before_journal_via_publication(
    peer_accepted: bool,
    journal_announced: bool,
) -> Result<crate::action_recovery::OrderingVerdict> {
    crate::action_recovery::require_peer_accepted_before_journal(peer_accepted, journal_announced)
        .map_err(PublicationError::from)
}

/// Require the admitted revisions to match the currently accepted
/// publication before a new handoff. Reads the current accepted event plus
/// its staged configuration (long reads, no transaction) and refuses stale
/// or foreign revisions: a superseded acceptance refuses with the preserved
/// `activation-superseded` code, a binding-revision drift blocks with
/// `publication-blocked` until the new publication is accepted. Never
/// auto-promotes, never restores a superseded pointer.
pub fn require_activation_current_for_handoff(
    store: &AcceptanceStore,
    scope: &crate::domain::scope::TrustedScope,
    admitted_binding_revision: crate::domain::ids::BindingRevision,
    admitted_accepted_revision: crate::accept::AcceptedRevision,
) -> Result<()> {
    let current = store.current(scope).map_err(PublicationError::from_accept)?;
    let current = match current {
        Some(accepted) => accepted,
        None => {
            return Err(PublicationError::from_accept(crate::accept::Error::Invalid(
                "activation requires committed acceptance",
            )));
        }
    };
    if current.revision != admitted_accepted_revision {
        return Err(PublicationError::from_accept(
            crate::accept::Error::Superseded {
                requested: admitted_accepted_revision,
                current: current.revision,
            },
        ));
    }
    let staged = store
        .read_staged(current.request.staged_operation())
        .map_err(PublicationError::from_accept)?;
    if staged.config().binding_revision() != admitted_binding_revision {
        return Err(PublicationError::Blocked {
            detail: format!(
                "binding revision changed since admission: admitted {} != accepted {}; block until accepted",
                admitted_binding_revision.as_u32(),
                staged.config().binding_revision().as_u32(),
            ),
        });
    }
    Ok(())
}
