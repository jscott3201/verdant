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
//!
//! Slice D post-handoff durability (outside harness, same ordering discipline
//! as `mark_dispatched`-before-send): the harness stays network-only (send +
//! readbacks, no SQL); the joined owner durably marks AFTER the harness
//! returns, never under network. `Unknown`/lost (timeout/abort/kill before
//! persist, `dispatch-unknown`) marks `Unresolved` (honest, never resend);
//! `Confirmed` (`ProtocolResult::Confirmed`) marks `Terminal` (history stays
//! reconcile-readable, no blind resend). No new table/column/migration;
//! writes go only through `Journal::mark_terminal`/`mark_unresolved` (guarded
//! lifecycle batches).
//!
//! Restart conservatism (decision lives here): a fresh process observing
//! `Dispatched` treats it conservatively as `Unresolved` until qualified
//! recovery (peer + transport reconciled, see `is_conservatively_unresolved`
//! and `refuse_resend_without_qualified_recovery`). `Dispatched` means the
//! send left the writer but no outcome was durably recorded; the peer may or
//! may not have accepted. Never invent `Terminal`/`Confirmed` from
//! `Dispatched` alone.
//!
//! Receipt honesty: `Outcome` receipts (`SlotReadback`/`PvReadback`
//! `receipt_wall`/`receipt_monotonic`) stay memory-only (no receipt/outcome
//! durable columns, no `0007`). A reopened `Admitted` exposes no receipt
//! accessors; fresh processes re-observe via read-only `inspect_identical`
//! with fresh `receipt_now` times (never equal to pre-kill times) and
//! `source_time` staying `None`. See `outcome.rs` and `Admitted` docs.
//!
//! PendingRelease stays memory-only: obligations are rediscovered via the
//! existing bounded `outstanding_page` -> `reconcile` scan (all fields already
//! durable); the dropped-object path is proved in Slice D tests. No
//! `PendingRelease` table, no resend.

use crate::accept::AcceptanceStore;
use crate::access::RoleKind;
use crate::action_custody::{CustodyError, ScopeHolds};
use crate::action_dispatch::{Current, DispatchCancel, FrozenRoute, FrozenWrite, Outcome, ProtocolResult};
use crate::action_expiry::ExpiryState;
use crate::action_journal::{Admitted, Journal, LifecycleState};
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

/// Record a confirmed harness outcome durably as terminal, outside harness.
/// Only `ProtocolResult::Confirmed` maps here; any other peer-responded
/// outcome (remote error/reject/abort/timeout/invalid/transport) or lost
/// response must use [`record_unknown_unresolved`] plus qualified recovery,
/// never an invented terminal. Identity-checked (operation/attempt/scope/
/// equipment/generations/revisions must match `admitted`); no network runs
/// here, only the guarded lifecycle batch. Harness stays network-only.
pub fn record_confirmed_terminal(
    journal: &Journal,
    admitted: &Admitted,
    outcome: &Outcome,
) -> Result<Admitted> {
    if outcome.operation() != admitted.operation().as_str()
        || outcome.attempt() != admitted.attempt().as_str()
        || outcome.scope() != admitted.scope().as_str()
        || outcome.equipment() != admitted.equipment().as_str()
        || outcome.binding_revision() != admitted.binding_revision().as_u32()
        || outcome.accepted_revision() != admitted.accepted_revision().get()
        || outcome.target_generation() != admitted.target_generation()
    {
        return Err(CustodyError::Invalid("outcome identity differs from admitted"));
    }
    // Exhaustive: new protocol variants break the build, never invent terminal.
    match outcome.protocol() {
        ProtocolResult::Confirmed => {}
        ProtocolResult::RemoteError { .. }
        | ProtocolResult::Reject(_)
        | ProtocolResult::Abort(_)
        | ProtocolResult::Timeout
        | ProtocolResult::InvalidReply
        | ProtocolResult::TransportFailure => {
            return Err(CustodyError::Invalid(
                "only Confirmed maps to terminal; other outcomes need qualified recovery via unresolved",
            ));
        }
    }
    journal
        .mark_terminal(admitted.operation(), admitted.scope())
        .map_err(CustodyError::from)
}

/// Record an unknown/lost harness outcome durably as unresolved, outside
/// harness. Call when the harness returned `DispatchError::Unknown`
/// (timeout/abort/lost response, `uncertain-not-resend`), when the child was
/// killed after peer accept before any mark, or when cancellation raced the
/// send with emission established. Honest, never a resend: the obligation
/// stays outstanding and discoverable via the bounded scan; a second
/// `execute_*` must refuse via [`refuse_resend_without_qualified_recovery`]
/// (or the terminal lifecycle gate) and only read-only `inspect_identical`
/// may re-observe. No network runs here.
pub fn record_unknown_unresolved(
    journal: &Journal,
    admitted: &Admitted,
) -> Result<Admitted> {
    journal
        .mark_unresolved(admitted.operation(), admitted.scope())
        .map_err(CustodyError::from)
}

/// Restart conservatism: `Dispatched` and `Unresolved` are both treated as
/// unresolved until qualified recovery (peer state plus transport ownership
/// reconciled first). A fresh process must never treat persisted `Dispatched`
/// as success, failure, or permission to resend; it is uncertain. `Admitted`
/// (pre-send) is not yet sent; `Terminal` is final history.
pub fn is_conservatively_unresolved(admitted: &Admitted) -> bool {
    // Exhaustive: new lifecycle variants break the build, never default.
    match admitted.lifecycle() {
        LifecycleState::Dispatched | LifecycleState::Unresolved => true,
        LifecycleState::Admitted | LifecycleState::Terminal => false,
    }
}

/// Refuse any resend without qualified recovery. `Admitted` (pre-send) may
/// proceed to the first handoff; `Dispatched`/`Unresolved` refuse as
/// `custody-unknown` (uncertain-not-resend: reconcile peer + transport first,
/// use read-only `inspect_identical`, never a second `WriteProperty`);
/// `Terminal` refuses as `custody-conflict` (final history, reconcile only).
/// This is the joined-path resend brake outside harness; the dispatch
/// lifecycle gate (`Terminal` final) remains the second brake for terminal.
pub fn refuse_resend_without_qualified_recovery(admitted: &Admitted) -> Result<()> {
    match admitted.lifecycle() {
        LifecycleState::Admitted => Ok(()),
        LifecycleState::Dispatched | LifecycleState::Unresolved => Err(CustodyError::Unknown {
            operation: admitted.operation().as_str().to_string(),
            attempt: admitted.attempt().as_str().to_string(),
            detail: "uncertain-not-resend: Dispatched/Unresolved after handoff; qualified recovery required before any resend; use read-only inspect_identical".to_string(),
        }),
        LifecycleState::Terminal => Err(CustodyError::Conflict {
            detail: "lifecycle terminal is final; reconcile history, do not resend".to_string(),
        }),
    }
}

/// Seal gate for the joined path: only the real S03 verified join passes
/// (verified requires ledger bytes held; digest threads only with ledger).
/// Marker-only/hybrid seals refuse as `preview-seal-order`; `ledger_only` never passes.
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
