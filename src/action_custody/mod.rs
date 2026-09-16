//! M02-PR12 maintenance, offboarding and current custody, HARNESS-ONLY.
//!
//! Assigned writer: scoped admission holds, inspection of outstanding
//! actions, actor/service revocation, constrained cleanup ownership.
//! Authorship plus original obligations are kept after credentials expire.
//! Unresolved responsibility is transferred to an active permitted role via
//! NEW admission (never rewritten in place, never auto-broadened, never
//! orphaned without owner). Pending cleanup survives visible in scope.
//! Failures expose limits plus escalation, never promised release.
//!
//! Frozen profile verbatim (explicit owner selection, not commissioned):
//! BACnet/IP Analog Value `presentValue` on `tiny_site` (`ahu-1`/`vav-101`,
//! `scope-a`); Analog Value instance 2, property 85; commissioned priority 8;
//! protected 1-3 refused; no empty slot; `degC` only, `20.0..=24.0`, tolerance
//! `0.1` wire-checked as `f32` Real; 15 minute duration (900s), 5 second
//! deadline, `APDU_RETRIES(0)` frozen, rate 6/hour; PV `unavailable-feedback`
//! stated where no meaningful immediate feedback exists; `source_time` is
//! always `None`; BACnet NULL (`0x00`) only for an explicitly admitted
//! release; preview revision-bound (`is_reservation`/`is_dispatch`/
//! `is_qualified` are all false).
//!
//! Compose, never duplicate (all read-only plus thin delegation):
//! [`AccessGate`](crate::access::AccessGate) `revoke`/`revocation_reason`,
//! [`ActorContext`](crate::access::ActorContext), ceilings,
//! `enter_review`/`enter_publish` for revocation and entry; binding
//! authority/registry for retirement and reassessment; accept
//! activation/publication (`AcceptanceStore::prepare`/`submit_activation`,
//! `current`) for currency; [`Journal`](crate::action_journal::Journal)
//! `prepare`/`submit`/`reconcile` per-target CAS; publication
//! exclusion/revocation/impact
//! ([`OldWriterExclusion`](crate::action_publication::OldWriterExclusion),
//! revocation ordering, [`ImpactGate`](crate::action_publication::ImpactGate));
//! expiry `authorize_cancel`/`authorize_release` plus
//! [`PendingRelease`](crate::action_expiry::PendingRelease); recovery
//! `verify_backup`/`reconcile` plus slot-identity rules. No guard SQL,
//! frozen-profile check, CAS, or transport is re-derived here.
//!
//! SQL-txn discipline: long reads (revocation read, accept history, binding
//! replay, seal custody, journal reconcile, custody inspection read) happen
//! before any ticket; exact guards live in the owning tickets
//! (`authority.guard`, `registry.guard`, `sealed.guard`,
//! `admission_generation`, `activation_*`); no network/adapter op runs under
//! a SQL transaction; announce/recheck happens after commit. This module
//! creates no ticket, row, column, table, index or migration of its own:
//! writes go only through existing `Journal::prepare`/`submit`,
//! `AcceptanceStore::prepare`/`submit_activation`,
//! `SqliteStore::prepare_guarded_batch`/`submit`. Custody itself writes no
//! new table. Holds are explicit in-memory gates; existing rows plus those
//! gates suffice.
//!
//! Transfer is NARROW only: expired-actor obligations move to an active
//! permitted role via NEW admission (new [`OperationId`](crate::domain::ids::OperationId))
//! by that role plus exclusion of the old actor; never rewrite
//! actor/operation/attempt in place; never broaden authority automatically;
//! never orphan without owner.
//!
//! Cleanup is CONSTRAINED: no LOTO/emergency-stop labeling, no all-slot
//! reset, no actor-history deletion, no broad permission grants to force
//! cleanup. Cancellation never clears field slots (`PendingRelease` pin plus
//! `authorize_cancel` equality plus `Journal::cancel` no-write stand).
//! Unauthorized other-person release is refused (`verify_content`
//! actor-equality plus NULL-only `prepare_release`). Ambiguous slot ownership
//! stays visible (`slot_value_proves_ownership` is false, full
//! [`RecordIdentity`](crate::domain::outcomes::RecordIdentity) equality
//! required). No future notification/work/MCP path bypasses these rules (no
//! new bypass surface is created here).
//!
//! Harness scope (PR07/PR08/PR09/PR11 precedent carries forward,
//! owner-selected): loopback-only directed-unicast to named isolated peers
//! with per-run capture proving no off-host packet plus full
//! stop/join/port-release cleanup. Exactly two `127.0.0.1:0` UDP binds per
//! run (ephemeral, printed by capture; forbids `502`/`802`/`8080`/`47808`
//! and fixed facility ports); directed-unicast only (NPDU version 1, no
//! route/network-message, `Original-Unicast-NPDU` only); no
//! broadcast/BBMD/foreign; no wildcard bind; no facility interface; MBAP
//! never as BACnet. Capture is instrumented socket boundaries only, never
//! host-wide pcap claims. Ordinary `verdant run` never constructs the
//! network path; the test-only harness owns both UDP binds.
//!
//! Greenfield forward-only: no v1 conversion, no backfill, no old-preview
//! support, no migration rewrite, no deprecated aliases, no compat shims.
//!
//! Limits (constrain the profile, stated here and asserted in tests):
//! delayed packets may still take effect later even after local expiry,
//! cancel, or release; third-party writers (other priority slots,
//! relinquish defaults, direct peer writes outside this journal) are outside
//! local transport ownership and cannot be bounded here; a NULL release can
//! reveal another system's command rather than renewing local intent; a
//! slept host's monotonic timer proves nothing current; synthetic budgets
//! are planning reserves, not host-global quotas, power-loss/disk-full
//! qualification, or real-time proof; custody scoped holds are admission
//! evidence, not physical lockout. See [`LIMITS`].
//!
//! Must NOT claim: exactly-once, active-active, field-CAS, revived-stack,
//! replay-all, quiescence-from-handle-drop/lease-expiry, automatic takeover,
//! obligation migration to replacement hardware, history rewrite/deletion,
//! LOTO/all-reset/broad-grant, `ObservedQualified` minting, `source_time`
//! invention, or `Freshness`-to-qualification upgrade.
#![allow(dead_code)]

pub mod custody;
pub mod policy;

#[allow(unused_imports)]
pub use custody::{
    authorize_cancel_via_custody, authorize_constrained_cleanup,
    authorize_release_via_custody, authorize_setpoint_via_custody, cancel_pending,
    inspect_outstanding, is_same_record, recheck_after_handoff_via_custody,
    reconcile_journal_via_custody, reconcile_pending_release_via_custody,
    require_activation_current_for_handoff_via_custody,
    require_aliases_unique_via_custody, require_peer_accepted_before_journal_via_custody,
    require_same_observation_via_custody, slot_value_proves_ownership_via_custody,
    transfer_narrow_via_new_admission, verify_backup_against_current_via_custody,
    verify_handoff_via_custody, OutstandingAction,
};
#[allow(unused_imports)]
pub use policy::{CustodyHold, HoldKind, ScopeHolds};

/// Custody decision-table wire-format tag (policy refusal only; no wire).
pub const CUSTODY_FORMAT: &str = "verdant-custody-v1";

/// Stated limits for delayed packets, third-party writers, budgets, and
/// scoped holds. These constrain the profile; they do not disappear from
/// reports. Tests assert the key phrases below so the limit text cannot
/// silently shrink.
pub const LIMITS: &str = "delayed-packets-may-take-effect-later; third-party-writers-outside-transport-ownership-unbounded; null-release-may-reveal-other-system-command; one-call-is-not-one-send; timeout-uncertain-never-resend; synthetic-budgets-not-host-quotas; no-power-loss-disk-full-real-time-claim; custody-scoped-hold-is-evidence-not-physical-lockout";

/// Typed custody failure with a stable machine code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyError {
    Invalid(&'static str),
    InvalidDetail { what: &'static str, detail: String },
    /// Scoped hold blocks new handoffs on the held scope. Other scopes
    /// proceed; pending rows are kept, never erased. In-memory gate only,
    /// never physical lockout.
    Held { scope: String, detail: String },
    /// Pre-handoff revocation ordering: a revocation read before the handoff
    /// prevents send. Post-handoff revocation cannot recall it (UNKNOWN until
    /// reconcile, never resend).
    Revoked { detail: String },
    /// Manual old-writer exclusion (transfer-narrow): independently
    /// effective, operator-gated, never automatic.
    Excluded { detail: String },
    /// Material impact blocks until accepted (delegated publication gate).
    Blocked { detail: String },
    /// Transfer-narrow refusal: requires a NEW admission by an active
    /// permitted role plus exclusion of the old actor; never rewrites in
    /// place, never broadens, never orphans.
    Transfer { detail: String },
    /// Constrained-cleanup refusal: the requested cleanup does not exist as
    /// an authorized surface (no LOTO, no all-slot reset, no history
    /// deletion, no broad grant, no notification/work/MCP bypass). Escalate
    /// to the owner via the qualified recovery procedure.
    Constrained { detail: String },
    /// Same identity with different content or a competing durable evolution.
    Conflict { detail: String },
    /// Commit state unknown: reconcile these identities; never resend.
    Unknown { operation: String, attempt: String, detail: String },
    /// Delegated dispatch refusal; preserves the dispatch machine code.
    Dispatch(crate::action_dispatch::DispatchError),
    /// Delegated admission/journal refusal; preserves the admission code.
    Admission(crate::action_journal::WriterError),
    /// Delegated expiry refusal; preserves the expiry code.
    Expiry(crate::action_expiry::ExpiryError),
    /// Delegated recovery refusal; preserves the recovery code.
    Recovery(crate::action_recovery::RecoveryError),
    /// Delegated publication refusal; preserves the publication code.
    Publication(crate::action_publication::PublicationError),
    /// Delegated preview refusal; preserves the preview machine code.
    Preview(crate::action_preview::PreviewError),
    /// Delegated binding refusal; preserves the binding code.
    Binding(crate::binding::BindingError),
    /// Delegated access refusal; preserves the access code.
    Access(crate::access::AccessError),
    /// Delegated accept/activation refusal; preserves the accept code.
    Accept { code: &'static str, detail: String },
}

impl CustodyError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) | Self::InvalidDetail { .. } => "custody-invalid",
            Self::Held { .. } => "custody-held",
            Self::Revoked { .. } => "custody-revoked",
            Self::Excluded { .. } => "custody-excluded",
            Self::Blocked { .. } => "custody-blocked",
            Self::Transfer { .. } => "custody-transfer",
            Self::Constrained { .. } => "custody-constrained",
            Self::Conflict { .. } => "custody-conflict",
            Self::Unknown { .. } => "custody-unknown",
            Self::Dispatch(inner) => inner.code(),
            Self::Admission(inner) => inner.code(),
            Self::Expiry(inner) => inner.code(),
            Self::Recovery(inner) => inner.code(),
            Self::Publication(inner) => inner.code(),
            Self::Preview(inner) => inner.code(),
            Self::Binding(inner) => inner.code(),
            Self::Access(inner) => inner.code(),
            Self::Accept { code, .. } => code,
        }
    }
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "custody invalid: {detail}"),
            Self::InvalidDetail { what, detail } => {
                write!(f, "custody invalid {what}: {detail}")
            }
            Self::Held { scope, detail } => write!(
                f,
                "custody held scope '{scope}' blocks new handoffs, pending rows kept: {detail}"
            ),
            Self::Revoked { detail } => write!(
                f,
                "custody revoked before handoff, send prevented: {detail}"
            ),
            Self::Excluded { detail } => write!(
                f,
                "custody excluded old writer (manual transfer-narrow only): {detail}"
            ),
            Self::Blocked { detail } => write!(
                f,
                "custody blocked until accepted (material change): {detail}"
            ),
            Self::Transfer { detail } => write!(
                f,
                "custody transfer-narrow refused (new admission by active permitted role plus old exclusion required, never rewrite/broaden/orphan): {detail}"
            ),
            Self::Constrained { detail } => write!(
                f,
                "custody constrained cleanup refused (no LOTO/emergency-stop, no all-slot reset, no actor-history deletion, no broad grant, no notification/work/MCP bypass; escalate to owner via qualified recovery): {detail}"
            ),
            Self::Conflict { detail } => write!(f, "custody conflict: {detail}"),
            Self::Unknown { operation, attempt, detail } => write!(
                f,
                "custody outcome UNKNOWN for {operation}/{attempt}; reconcile these identities, do not resend: {detail}"
            ),
            Self::Dispatch(inner) => write!(f, "{inner}"),
            Self::Admission(inner) => write!(f, "{inner}"),
            Self::Expiry(inner) => write!(f, "{inner}"),
            Self::Recovery(inner) => write!(f, "{inner}"),
            Self::Publication(inner) => write!(f, "{inner}"),
            Self::Preview(inner) => write!(f, "{inner}"),
            Self::Binding(inner) => write!(f, "{inner}"),
            Self::Access(inner) => write!(f, "{inner}"),
            Self::Accept { detail, .. } => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for CustodyError {}

impl From<crate::action_dispatch::DispatchError> for CustodyError {
    fn from(error: crate::action_dispatch::DispatchError) -> Self {
        Self::Dispatch(error)
    }
}

impl From<crate::action_journal::WriterError> for CustodyError {
    fn from(error: crate::action_journal::WriterError) -> Self {
        match error {
            crate::action_journal::WriterError::Conflict { detail } => {
                Self::Conflict { detail }
            }
            crate::action_journal::WriterError::Unknown { operation, detail } => {
                Self::Unknown {
                    operation: operation.as_str().to_string(),
                    attempt: operation.as_str().to_string(),
                    detail,
                }
            }
            other => Self::Admission(other),
        }
    }
}

impl From<crate::action_expiry::ExpiryError> for CustodyError {
    fn from(error: crate::action_expiry::ExpiryError) -> Self {
        Self::Expiry(error)
    }
}

impl From<crate::action_recovery::RecoveryError> for CustodyError {
    fn from(error: crate::action_recovery::RecoveryError) -> Self {
        Self::Recovery(error)
    }
}

impl From<crate::action_publication::PublicationError> for CustodyError {
    fn from(error: crate::action_publication::PublicationError) -> Self {
        match error {
            crate::action_publication::PublicationError::Excluded { detail } => {
                Self::Excluded { detail }
            }
            crate::action_publication::PublicationError::Revoked { detail } => {
                Self::Revoked { detail }
            }
            crate::action_publication::PublicationError::Blocked { detail } => {
                Self::Blocked { detail }
            }
            crate::action_publication::PublicationError::Conflict { detail } => {
                Self::Conflict { detail }
            }
            crate::action_publication::PublicationError::Unknown { operation, attempt, detail } => {
                Self::Unknown { operation, attempt, detail }
            }
            other => Self::Publication(other),
        }
    }
}

impl From<crate::binding::BindingError> for CustodyError {
    fn from(error: crate::binding::BindingError) -> Self {
        Self::Binding(error)
    }
}

impl From<crate::action_preview::PreviewError> for CustodyError {
    fn from(error: crate::action_preview::PreviewError) -> Self {
        Self::Preview(error)
    }
}

impl From<crate::access::AccessError> for CustodyError {
    fn from(error: crate::access::AccessError) -> Self {
        Self::Access(error)
    }
}

impl CustodyError {
    /// Preserve the accept/activation machine code without cloning its
    /// non-cloneable error body.
    pub fn from_accept(error: crate::accept::Error) -> Self {
        Self::Accept { code: error.code(), detail: error.to_string() }
    }
}

pub type Result<T> = std::result::Result<T, CustodyError>;
