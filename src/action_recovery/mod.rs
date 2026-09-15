//! M02-PR11 uncertain effects and restart recovery, HARNESS-ONLY.
//!
//! Recovery matrix for before/after handoff, peer acceptance before journal
//! result, pending release, intact restart and stale backup. Reconcile current
//! peer state and transport ownership before conflicting generations. Preserve
//! subsequent observations without treating equal slot values as ownership
//! proof. State what cannot be observed/bounded for delayed packets and
//! third-party writers (limits constrain the profile, they do not disappear
//! from reports).
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
//! `is_qualified` are all false). Consumes existing Journal, dispatch, expiry
//! and observation APIs read-only plus thin delegation; never re-derives
//! journal guard SQL, frozen-profile checks, or transport.
//!
//! Harness scope (PR07/PR08 precedent carries forward, owner-selected):
//! loopback-only directed-unicast to named isolated peers with per-run
//! capture proving no off-host packet plus full stop/join/port-release
//! cleanup. Exactly two `127.0.0.1:0` UDP binds per run (ephemeral, printed
//! by capture; forbids `502`/`802`/`8080`/`47808` and fixed facility ports);
//! directed-unicast only (NPDU version 1, no route/network-message,
//! `Original-Unicast-NPDU` only); no broadcast/BBMD/foreign; no wildcard
//! bind; no facility interface; MBAP never as BACnet. Capture is
//! instrumented socket boundaries only, never host-wide pcap claims.
//! Ordinary `verdant run` never constructs this module's network path; the
//! test-only harness owns both UDP binds.
//!
//! Greenfield forward-only: no v1 descriptor conversion, no backfill, no
//! old-preview support, no migration rewrite, no deprecated aliases, no
//! compat shims. No new migration is created here: the existing
//! admitted-plus-targets-plus-receipts-plus-checkpoints rows suffice (expiry
//! precedent: policy refusal is not new state). Telemetry generation
//! (observation [`SourceGenerationId`](crate::domain::ids::SourceGenerationId))
//! is separate from field-writer exclusion
//! (`action_targets.current_generation` CAS); neither resets old obligations
//! nor renews authority.
//!
//! Owner decisions (explicit):
//! - Stale backup: REFUSE STALE. A restored old journal never overwrites
//!   newer state; conflicting content is refused (`Conflict`), old
//!   obligations are kept with their old IDs, and new emission needs a new
//!   producer generation (M02-PR03 restart-identity precedent: rollback mints
//!   a fresh generation BEFORE emission even if values are equal; intact
//!   means an exact ledger match).
//! - Conflicts: WAIT plus QUALIFIED RECOVERY. Later conflicting requests wait
//!   or require the qualified recovery procedure (reconcile peer state plus
//!   transport ownership first). No quiescence is inferred from dropped
//!   handles or expired leases (absence is not permission). There is no
//!   replay of all retained actions.
//!
//! Lock order: time-evidence reads (no lock) -> expiry/freshness assessment
//! (no lock) -> content/generation verification via dispatch (no SQL guard)
//! -> journal/store reconcile under the admitted writer barrier (short,
//! bounded, no network) -> adapter op with NO SQL guard and NO
//! building-wide lock (per-target frozen route only). No network runs under
//! a SQL transaction. Per-target frozen route only; never a global mutex.
//! Timeout after handoff is uncertain, never permission to resend,
//! compensate, or treat `ack == movement` (`uncertain-not-resend`). One
//! logical call is audited against effective wire sends; one call is not one
//! send by assumption.
//!
//! Limits (constrain the profile, stated here and asserted in tests):
//! delayed packets may still take effect later even after local expiry,
//! cancel, or release; third-party writers (other priority slots,
//! relinquish defaults, direct peer writes outside this journal) are outside
//! local transport ownership and cannot be bounded here; a NULL release can
//! reveal another system's command rather than renewing local intent; a
//! slept host's monotonic timer proves nothing current; synthetic budgets
//! are planning reserves, not host-global quotas, power-loss/disk-full
//! qualification, or real-time proof. See [`LIMITS`].
//!
//! Must NOT claim: exactly-once, active-active, field-CAS, revived-stack,
//! replay-all, quiescence-from-handle-drop/lease-expiry, end-at-deadline,
//! exact stop at expiry, real-time proof, power-loss/disk-full qualification,
//! host-global quota, universal rollback, emergency-stop, guessed-restore,
//! blanket-release-on-shutdown, `ObservedQualified` minting, `source_time`
//! invention, or `Freshness`-to-qualification upgrade.
#![allow(dead_code)]
#![allow(unused_imports)]

pub mod decisions;
pub mod reconcile;

pub use decisions::{
    BackupVerdict, CancelVerdict, CommitVerdict, ConflictWait, ObservationVerdict, OrderingVerdict,
    PeerAcceptance,
};
pub use reconcile::{
    authorize_cancel_via_expiry, authorize_release_via_expiry, authorize_set_via_expiry,
    is_same_record, peer_acceptance, prepare_release_via_dispatch, prepare_setpoint_via_dispatch,
    recheck_after_handoff_via_dispatch, reconcile_journal, reconcile_pending_release,
    reconcile_store_operation, reconcile_store_ticket, require_peer_accepted_before_journal,
    require_qualified_recovery, require_reconciled_peer_and_transport, require_same_observation,
    slot_value_proves_ownership, verify_backup_against_current, verify_handoff,
};

/// Recovery decision-table wire-format tag (policy refusal only; no wire).
pub const RECOVERY_FORMAT: &str = "verdant-recovery-v1";

/// Stated limits for delayed packets and third-party writers. These constrain
/// the profile; they do not disappear from reports. Tests assert the key
/// phrases below so the limit text cannot silently shrink.
pub const LIMITS: &str = "delayed-packets-may-take-effect-later; third-party-writers-outside-transport-ownership-unbounded; null-release-may-reveal-other-system-command; one-call-is-not-one-send; timeout-uncertain-never-resend; synthetic-budgets-not-host-quotas; no-power-loss-disk-full-real-time-claim";

/// Typed recovery failure with a stable machine code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    Invalid(&'static str),
    InvalidDetail { what: &'static str, detail: String },
    /// Known non-commit before COMMIT dispatch (rollback): nothing admitted.
    NotCommitted { operation: String, detail: String },
    /// Commit state unknown (forced exit after commit, lost response,
    /// inaccessible peer, absent result): persists with identities for
    /// reconcile; never a resend.
    Unknown { operation: String, attempt: String, detail: String },
    /// Same identity with different content, wrong store, or conflicting
    /// generation: wait or run the qualified recovery procedure.
    Conflict { detail: String },
    /// Restored or presented generation is older than current: REFUSE STALE.
    StaleGeneration { expected: u32, current: u32 },
    /// Clock indeterminate or expired for a new SET: refuse SET, allow only
    /// explicit cancel or admitted-NULL release.
    Indeterminate { reason: &'static str },
    Expired { elapsed_secs: u64, duration_secs: u64 },
    /// Delegated dispatch refusal; preserves the dispatch machine code.
    Dispatch(crate::action_dispatch::DispatchError),
    /// Delegated admission/journal refusal; preserves the admission code.
    Admission(crate::action_journal::WriterError),
    /// Delegated expiry refusal; preserves the expiry code.
    Expiry(crate::action_expiry::ExpiryError),
}

impl RecoveryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) | Self::InvalidDetail { .. } => "recovery-invalid",
            Self::NotCommitted { .. } => "recovery-not-committed",
            Self::Unknown { .. } => "recovery-unknown",
            Self::Conflict { .. } => "recovery-conflict",
            Self::StaleGeneration { .. } => "recovery-stale-generation",
            Self::Indeterminate { .. } => "recovery-indeterminate",
            Self::Expired { .. } => "expiry-expired",
            Self::Dispatch(inner) => inner.code(),
            Self::Admission(inner) => inner.code(),
            Self::Expiry(inner) => inner.code(),
        }
    }
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "recovery invalid: {detail}"),
            Self::InvalidDetail { what, detail } => {
                write!(f, "recovery invalid {what}: {detail}")
            }
            Self::NotCommitted { operation, detail } => write!(
                f,
                "recovery not committed for {operation} (rollback, nothing admitted): {detail}"
            ),
            Self::Unknown { operation, attempt, detail } => write!(
                f,
                "recovery outcome UNKNOWN for {operation}/{attempt}; reconcile these identities, do not resend: {detail}"
            ),
            Self::Conflict { detail } => write!(
                f,
                "recovery conflict ({detail}); wait or run the qualified recovery procedure"
            ),
            Self::StaleGeneration { expected, current } => write!(
                f,
                "recovery stale generation: expected {expected}, current is {current}; REFUSE STALE"
            ),
            Self::Indeterminate { reason } => write!(
                f,
                "recovery time indeterminate ({reason}): refuse new SET, allow only explicit cancel or admitted-NULL release"
            ),
            Self::Expired { elapsed_secs, duration_secs } => write!(
                f,
                "recovery expired: elapsed {elapsed_secs}s >= duration {duration_secs}s; no new SET, cancel-or-NULL only"
            ),
            Self::Dispatch(inner) => write!(f, "{inner}"),
            Self::Admission(inner) => write!(f, "{inner}"),
            Self::Expiry(inner) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for RecoveryError {}

impl From<crate::action_dispatch::DispatchError> for RecoveryError {
    fn from(error: crate::action_dispatch::DispatchError) -> Self {
        Self::Dispatch(error)
    }
}

impl From<crate::action_journal::WriterError> for RecoveryError {
    fn from(error: crate::action_journal::WriterError) -> Self {
        match error {
            crate::action_journal::WriterError::Conflict { detail } => {
                Self::Conflict { detail }
            }
            crate::action_journal::WriterError::StaleGeneration { expected, current } => {
                Self::StaleGeneration { expected, current }
            }
            crate::action_journal::WriterError::Unknown { operation, detail } => Self::Unknown {
                operation: operation.as_str().to_string(),
                attempt: operation.as_str().to_string(),
                detail,
            },
            other => Self::Admission(other),
        }
    }
}

impl From<crate::action_expiry::ExpiryError> for RecoveryError {
    fn from(error: crate::action_expiry::ExpiryError) -> Self {
        match error {
            crate::action_expiry::ExpiryError::Expired { elapsed_secs, duration_secs } => {
                Self::Expired { elapsed_secs, duration_secs }
            }
            crate::action_expiry::ExpiryError::Indeterminate { reason } => {
                Self::Indeterminate { reason }
            }
            crate::action_expiry::ExpiryError::StaleGeneration { expected, current } => {
                Self::StaleGeneration { expected, current }
            }
            crate::action_expiry::ExpiryError::Dispatch(inner) => Self::Dispatch(inner),
            crate::action_expiry::ExpiryError::Admission(inner) => Self::from(inner),
            other => Self::Expiry(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, RecoveryError>;
