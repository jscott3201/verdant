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

/// Joined SET authorization through the owned Slice C path. Thin delegation
/// to `crate::action_joined` (seal + activation + holds + wall + dispatch);
/// raw dispatch preparation bypasses those barriers. Returns the joined
/// (custody) error so machine codes stay preserved without collapsing.
#[allow(clippy::too_many_arguments)]
pub fn authorize_joined_setpoint_via_publication(
    journal: &crate::action_journal::Journal,
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
    exclusion: Option<&OldWriterExclusion>,
    is_revoked: bool,
    impact: &ImpactGate,
) -> std::result::Result<FrozenWrite, crate::action_custody::CustodyError> {
    crate::action_joined::authorize_joined_setpoint(
        journal, store, admitted, preview, current, route, cancel, deadline, expiry,
        freshness, holds, exclusion, is_revoked, impact,
    )
}

/// Require the admitted revisions to match the currently ACTIVE publication
/// before a new handoff. Reads the durable active pointer PLUS the current
/// accepted event and its staged configuration (long reads, no transaction)
/// and refuses stale or foreign revisions. Never auto-promotes, never
/// restores a superseded pointer.
///
/// Pre/post generation (traced, not ±1): `AcceptedRevision::INITIAL` is the
/// pre-admission expectation; `revision = expected.next()` is the
/// post-CAS accepted value. `ActiveGeneration::INITIAL` is the pre-activation
/// token; `generation = expected.next()` is the post-CAS active value. This
/// gate compares post-CAS revisions (`current.revision`, `active.revision`)
/// to the admitted post-CAS revision, not pre tokens. Replacement/release
/// tracing (old-target pin, NULL reveal) lives with the active join; do not
/// fix mismatches by ±1 without that trace.
///
/// Barriers on owning ops, not `Current` swaps: this check reads the durable
/// `AcceptanceStore::active`/`current` directly. Caller-supplied `Current`
/// values (actor/ceiling/revisions) cannot substitute for it; ordinary
/// dispatch `prepare_*` without this barrier is harness-only and proves
/// nothing about activation. Tests assert `Current` swaps still refuse here.
///
/// Cases (distinguished, not collapsed):
/// - no current: `accept-invalid` (activation requires committed acceptance);
/// - admitted != current: `activation-superseded` (stale admitted);
/// - current exists but no active: `activation-superseded` with
///   `accepted-but-not-active` detail (accepted, never activated);
/// - admitted == current but active older (newer-accepted/older-active):
///   `activation-superseded` with `older-active` detail (activate current);
/// - admitted == active but != current is already stale-admitted above;
/// - binding drift: `publication-blocked` until the new publication is
///   accepted AND activated.
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
    // Durable active pointer: accepted-but-not-active must not dispatch.
    let active = store.active(scope).map_err(PublicationError::from_accept)?;
    let active = match active {
        Some(activated) => activated,
        None => {
            return Err(PublicationError::from_accept(crate::accept::Error::Invalid(
                "accepted-but-not-active; activate current publication before handoff",
            )));
        }
    };
    // Active must join the same accepted revision the admission was bound to.
    // Newer-accepted/older-active (current rev N, active rev N-1 with admitted
    // N) refuses as blocked until the current publication is activated, even
    // though admitted == current: the current publication is not yet active.
    // Older admitted (admitted != current) already refused above; an active
    // older than admitted is the same older-active refusal when admitted ==
    // current. Distinct codes preserve the distinction (blocked vs superseded).
    if active.revision() != admitted_accepted_revision {
        return Err(PublicationError::Blocked {
            detail: format!(
                "newer-accepted/older-active: admitted rev {} != active rev {}; activate current rev {} before handoff",
                admitted_accepted_revision.get(),
                active.revision().get(),
                current.revision.get(),
            ),
        });
    }
    // Active generation must be non-zero (at least one activation CAS won);
    // INITIAL (0) with a revision present is a corrupt join, not a bypass.
    if active.generation().get() == 0 {
        return Err(PublicationError::from_accept(crate::accept::Error::Invalid(
            "active generation 0 with accepted revision; activate before handoff",
        )));
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
