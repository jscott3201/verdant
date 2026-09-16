//! M02 Slice C joined seal/admission/dispatch/wall path, HARNESS-ONLY.
//!
//! One owned path from preview to send with no bypass: seal verified proof
//! (real S03 join) is threaded via [`Preview`](crate::action_preview::Preview),
//! activation is read from the owning [`AcceptanceStore`](crate::accept::AcceptanceStore)
//! (never `Current` swaps), holds/revocation/exclusion/impact are re-read
//! after admission but before send, admission runs as a guarded Journal batch,
//! lifecycle transitions to dispatched before the dispatch decision, and the
//! durable deadline wall plus expiry/freshness gates the send.
//!
//! Lock discipline (per publication/mod.rs:39-44, custody.rs:7-11,
//! journal/mod.rs:12-15): long reads (accept history, binding replay, seal
//! custody, revocation read, journal reconcile) happen before any ticket;
//! exact guards live in the owning tickets (`admission_generation`,
//! `admission_rate`, `activation_*`); no network/adapter op runs under a SQL
//! transaction; announce/recheck happens after commit. This module creates no
//! table/row/column/migration of its own: writes go only through
//! `Journal::admit` (guarded admission batch) and `Journal::mark_dispatched`
//! (guarded lifecycle batch). Raw `Journal::prepare`/`admit` and dispatch
//! `prepare_setpoint`/`prepare_release` are `pub(crate)` bypass entries;
//! product and gate callers must use this joined path.
//!
//! Codes are preserved via `From`, never collapsed: seal `s03-*` via
//! [`PreviewError`](crate::action_preview::PreviewError), activation
//! `accept-invalid`/`activation-superseded`/`publication-blocked` via
//! publication, holds `custody-held`, revocation `custody-revoked`/
//! `publication-revoked`, stale generations `admission-stale-generation`/
//! `dispatch-stale-generation`, wall `expiry-expired`/`expiry-indeterminate`.
//! Marker-only seals (ordered Booleans without the real S03 join) refuse here
//! as `preview-seal-order`; ordinary `prepare_setpoint` without this proof
//! cannot pass this path.
//!
//! Harness-only: loopback directed-unicast via the dispatch harness; ordinary
//! `verdant run` never constructs the network path. No new migration (wall
//! uses existing `created`, lifecycle uses the 0006 table, seal join is
//! call-level). Frozen numbers unchanged.

use crate::accept::AcceptanceStore;
use crate::access::RoleKind;
use crate::action_custody::{CustodyError, ScopeHolds};
use crate::action_dispatch::{Current, DispatchCancel, FrozenRoute, FrozenWrite};
use crate::action_expiry::ExpiryState;
use crate::action_journal::{Admitted, Journal};
use crate::action_preview::{Preview, PreviewError};
use crate::action_publication::{ImpactGate, OldWriterExclusion};
use crate::domain::ids::OperationId;
use crate::domain::scope::TrustedScope;
use crate::observation::time::Freshness;
use std::time::Instant;

pub type Result<T> = std::result::Result<T, CustodyError>;

/// Admit one preview through the joined path: seal verified proof is required
/// before any ticket, then the guarded Journal batch admits (per-target CAS
/// plus owned 6/hour rate). Holds/revocation/activation are handoff gates
/// (checked in [`authorize_joined_setpoint`]/[`authorize_joined_release`]
/// with fresh reads after admission), not admission gates, so admission can
/// succeed while a later handoff refuses.
#[allow(clippy::too_many_arguments)]
pub fn admit_joined(
    journal: &mut Journal,
    operation: OperationId,
    scope: TrustedScope,
    ceiling: u8,
    role: RoleKind,
    actor: &str,
    preview: &Preview,
    expected_generation: u32,
) -> Result<Admitted> {
    require_seal_verified(preview)?;
    journal
        .admit(operation, scope, ceiling, role, actor, preview, expected_generation)
        .map_err(CustodyError::from)
}

/// Authorize one frozen SET handoff through the joined path. Callers must
/// supply FRESH reads taken after admission (activation is re-read from the
/// store inside; `holds`/`is_revoked`/`current`/`impact` must be the current
/// values, never pre-admission copies): owner reads before ticket (admission
/// already committed) -> dispatched transition (guarded batch, no network)
/// -> dispatch decision before send -> authorize with wall (durable
/// `created` re-read plus real wall now, rollback/cross-boot indeterminate).
#[allow(clippy::too_many_arguments)]
pub fn authorize_joined_setpoint(
    journal: &Journal,
    accept_store: &AcceptanceStore,
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
    require_seal_verified(preview)?;
    require_preview_matches_admission(admitted, preview)?;
    // Owning-op activation barrier (reads the durable store, never Current swaps).
    // Preserve `publication-blocked` verbatim (do not remap to `custody-blocked`
    // via the generic custody `From`; other activation codes already preserve
    // via delegation).
    crate::action_publication::require_activation_current_for_handoff(
        accept_store,
        admitted.scope(),
        admitted.binding_revision(),
        admitted.accepted_revision(),
    )
    .map_err(|e| match e {
        crate::action_publication::PublicationError::Blocked { detail } => {
            CustodyError::Publication(crate::action_publication::PublicationError::Blocked {
                detail,
            })
        }
        other => CustodyError::from(other),
    })?;
    // Atomic lifecycle transition before any external send (guarded batch, no network).
    let dispatched = journal
        .mark_dispatched(admitted.operation(), admitted.scope())
        .map_err(CustodyError::from)?;
    // Custody/publication gates plus wall plus dispatch (no SQL guard, no network yet).
    // Holds/revocation/exclusion/impact are the fresh post-admission reads.
    crate::action_custody::authorize_setpoint_via_custody(
        &dispatched,
        preview,
        current,
        route,
        cancel,
        deadline,
        expiry,
        freshness,
        holds,
        exclusion,
        is_revoked,
        impact,
    )
}

/// Authorize one frozen NULL release through the joined path (same barriers;
/// wall-expired/indeterminate still permits an admitted NULL as constrained
/// cleanup; held scopes permit only original-target admitted NULL).
#[allow(clippy::too_many_arguments)]
pub fn authorize_joined_release(
    journal: &Journal,
    accept_store: &AcceptanceStore,
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
    require_seal_verified(preview)?;
    require_preview_matches_admission(admitted, preview)?;
    crate::action_publication::require_activation_current_for_handoff(
        accept_store,
        admitted.scope(),
        admitted.binding_revision(),
        admitted.accepted_revision(),
    )
    .map_err(|e| match e {
        crate::action_publication::PublicationError::Blocked { detail } => {
            CustodyError::Publication(crate::action_publication::PublicationError::Blocked {
                detail,
            })
        }
        other => CustodyError::from(other),
    })?;
    let dispatched = journal
        .mark_dispatched(admitted.operation(), admitted.scope())
        .map_err(CustodyError::from)?;
    crate::action_custody::authorize_release_via_custody(
        &dispatched,
        preview,
        current,
        route,
        cancel,
        deadline,
        expiry,
        freshness,
        holds,
        exclusion,
        is_revoked,
        impact,
    )
}

/// Seal gate for the joined path: only the real S03 verified join passes.
/// Marker-only ordered Booleans refuse as `preview-seal-order` (or the
/// preserved `s03-*` from the join); `ledger_only` never passes.
fn require_seal_verified(preview: &Preview) -> Result<()> {
    if preview.seal_verified() && preview.seal_ledger_digest().is_some() {
        Ok(())
    } else {
        Err(CustodyError::Preview(PreviewError::SealOrder {
            detail: "marker seal without real S03 custody/decode/reconstruct proof; joined handoff refused",
        }))
    }
}

/// Admission/handoff join: the handoff preview must be the admitted identity
/// (payload plus lossless bits/kind/target). A swapped preview refuses here
/// before any send; identical retries are authorized outcome inspection only
/// via the harness `inspect_identical`, never a new send through this path.
fn require_preview_matches_admission(admitted: &Admitted, preview: &Preview) -> Result<()> {
    if admitted.payload() != preview.canonical_bytes() {
        return Err(CustodyError::Preview(PreviewError::Invalid(
            "admitted payload differs from handoff preview",
        )));
    }
    if admitted.wire_bits() != Some(preview.encoded().wire_bits()) {
        return Err(CustodyError::Preview(PreviewError::Invalid(
            "wire identity mismatch: distinct binary32 sharing rounded text",
        )));
    }
    if admitted.action_kind().map(|k| k.as_str()) != Some(preview.action_kind()) {
        return Err(CustodyError::Preview(PreviewError::Invalid(
            "action kind mismatch: SET cannot authorize release and vice versa",
        )));
    }
    Ok(())
}
