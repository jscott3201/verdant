//! M02-PR08 normal expiry and exact release, HARNESS-ONLY.
//!
//! Cancel unattempted intent separately from authorized NULL relinquishment.
//! Preserve original target/allocation/generation for cleanup. Explicit
//! elapsed/wall/boot policy with checked arithmetic and qualified suspend
//! behavior. No new authorized SET handoff after expiry. Pending release
//! persists when delivery fails. Strict release: NULL, zero and inactive are
//! different; release can reveal another system's command (residual risk
//! shown, not renewed intent).
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
//! `is_qualified` are all false). Consumes [`Admitted`](crate::action_journal::Admitted)
//! and [`Preview`](crate::action_preview::Preview) read-only plus
//! `canonical_bytes` and [`ReleasePlan`](crate::action_preview::ReleasePlan);
//! never re-derives preview/journal logic, never mutates
//! `APDU_RETRIES`/`ClientConfig`, never touches transport injection.
//!
//! Time policy (explicit owner selection): elapsed monotonic
//! ([`MonotonicMark::elapsed_since`](crate::domain::clock::MonotonicMark::elapsed_since))
//! for expiry plus wall/boot-anchored cleanup (`UnixMillis` checked_sub wall
//! age plus `BootId` equality plus [`Continuity::Confirmed`](crate::observation::time::Continuity)
//! on both evidence and now plus wall/monotonic skew agreement,
//! [`FreshnessPolicy::assess`](crate::observation::time::FreshnessPolicy::assess)
//! shape). All arithmetic checked (`checked_add` for generation/deadline,
//! `checked_sub`/`checked_duration_since` for ages). Suspend-qualified:
//! `WallOrSuspendAmbiguous` or cross-boot or skew-exceeded maps to
//! `Unknown`/`Stale`, which refuses new SET but permits only explicit cancel
//! or admitted-NULL release. A slept host's non-expired monotonic timer
//! proves nothing current.
//!
//! Residual risks (shown, not renewed): earlier packets and retained
//! controller values may take effect later even after local expiry; a NULL
//! release can reveal another system's command (higher-priority slot or
//! relinquish default) rather than renewing local intent; a slept host's
//! monotonic timer proves nothing current; synthetic budgets here are
//! planning reserves, not host-global quotas, power-loss/disk-full
//! qualification, or real-time proof. There is no end-at-deadline guarantee,
//! no exact stop at expiry, and no emergency-stop/guessed-restore claim.
//!
//! Harness scope (PR07 precedent carries forward, owner-selected):
//! loopback-only directed-unicast to named isolated peers with per-run
//! capture proving no off-host packet plus full stop/join/port-release
//! cleanup. Exactly two `127.0.0.1:0` UDP binds per run (ephemeral, printed
//! by capture; forbids `502`/`802`/`8080`/`47808` and fixed facility ports);
//! directed-unicast only (NPDU version 1, no route/network-message,
//! `Original-Unicast-NPDU` only); no broadcast/BBMD/foreign; no wildcard
//! bind; no facility interface; MBAP never as BACnet. Capture is
//! instrumented socket boundaries only, never host-wide pcap claims.
//! Ordinary `verdant run` never constructs the network path; the test-only
//! harness owns both UDP binds.
//!
//! Greenfield forward-only: no v1 descriptor conversion, no backfill, no
//! old-preview support, no migration rewrite, no deprecated aliases, no
//! compat shims. Expiry is policy refusal from existing `Admitted` plus
//! `Timing` plus time evidence, NOT a new row/state/column/table/index. No
//! migration is created here. No generic property-write API exists; the only
//! encodable writes remain the frozen SET (`FrozenWrite` Real) and the
//! admitted NULL release via `prepare_release`/`execute_release`.
//!
//! Lock order: time-evidence reads (no lock) -> expiry assessment (no lock)
//! -> freshness assessment (no lock) -> content/generation verification via
//! dispatch (no SQL guard) -> adapter op with NO SQL guard and NO
//! building-wide lock (per-target frozen route only). No network runs under
//! a SQL transaction. Per-target frozen route only; never a global mutex.
//! Timeout after handoff is uncertain, never permission to resend,
//! compensate, or treat `ack == movement` (`uncertain-not-resend`).
//!
//! Must NOT claim: monotonic-proves-current, end-at-deadline guarantee,
//! exact stop at expiry, real-time proof, power-loss/disk-full qualification,
//! host-global quota, universal rollback, emergency-stop, guessed-restore,
//! or blanket-release-on-shutdown.
#![allow(dead_code)]
#![allow(unused_imports)]

pub mod policy;
pub mod release;

pub use policy::{assess_cleanup, assess_expiry, authorize_cancel, authorize_set, decide_set_allowed, wall_age_millis};
pub use policy::{ExpiryHorizon, ExpiryState, deadline_instant, next_generation};
pub use policy::{require_confirmed, require_same_boot};
pub use release::{PendingRelease, authorize_release};
pub use release::{is_inactive_wire, is_null_wire, is_real_zero_wire};

/// Expiry policy wire-format tag (policy refusal only; no wire emission).
pub const EXPIRY_FORMAT: &str = "verdant-expiry-v1";
/// Frozen admitted duration re-exported without inventing a new value.
pub const EXPIRY_DURATION_SECS: u64 = crate::action_preview::DURATION_SECS;
/// Frozen dispatch deadline re-exported without inventing a new value.
pub const EXPIRY_DEADLINE_SECS: u64 = crate::action_preview::DEADLINE_SECS;

/// Typed expiry/release failure with a stable machine code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpiryError {
    Invalid(&'static str),
    InvalidDetail { what: &'static str, detail: String },
    /// Monotonic elapsed time reached the admitted duration. No new SET.
    Expired { elapsed_secs: u64, duration_secs: u64 },
    /// Suspend/rollback/skew/cross-boot ambiguity. Refuses SET, allows
    /// explicit cancel or admitted-NULL release only.
    Indeterminate { reason: &'static str },
    StaleGeneration { expected: u32, current: u32 },
    RevisionMismatch { detail: String },
    NullNotAdmitted,
    Unknown { operation: String, attempt: String, detail: String },
    /// Delegated dispatch refusal; preserves the dispatch machine code.
    Dispatch(crate::action_dispatch::DispatchError),
    /// Delegated admission/journal refusal; preserves the admission code.
    Admission(crate::action_journal::WriterError),
}

impl ExpiryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) | Self::InvalidDetail { .. } => "expiry-invalid",
            Self::Expired { .. } => "expiry-expired",
            Self::Indeterminate { .. } => "expiry-indeterminate",
            Self::StaleGeneration { .. } => "expiry-stale-generation",
            Self::RevisionMismatch { .. } => "expiry-revision-mismatch",
            Self::NullNotAdmitted => "dispatch-null-not-admitted",
            Self::Unknown { .. } => "expiry-unknown",
            Self::Dispatch(inner) => inner.code(),
            Self::Admission(inner) => inner.code(),
        }
    }
}

impl std::fmt::Display for ExpiryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "expiry invalid: {detail}"),
            Self::InvalidDetail { what, detail } => {
                write!(f, "expiry invalid {what}: {detail}")
            }
            Self::Expired { elapsed_secs, duration_secs } => write!(
                f,
                "intent expired: elapsed {elapsed_secs}s >= duration {duration_secs}s; no new SET, cancel-or-NULL only"
            ),
            Self::Indeterminate { reason } => write!(
                f,
                "time indeterminate ({reason}): refuse new SET, allow only explicit cancel or admitted-NULL release"
            ),
            Self::StaleGeneration { expected, current } => write!(
                f,
                "expiry stale generation: expected {expected}, current is {current}"
            ),
            Self::RevisionMismatch { detail } => {
                write!(f, "expiry revision mismatch: {detail}")
            }
            Self::NullNotAdmitted => write!(f, "encoded null only for admitted release"),
            Self::Unknown { operation, attempt, detail } => write!(
                f,
                "expiry outcome UNKNOWN for {operation}/{attempt}; reconcile these identities: {detail}"
            ),
            Self::Dispatch(inner) => write!(f, "{inner}"),
            Self::Admission(inner) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for ExpiryError {}

impl From<crate::action_dispatch::DispatchError> for ExpiryError {
    fn from(error: crate::action_dispatch::DispatchError) -> Self {
        match error {
            crate::action_dispatch::DispatchError::NullNotAdmitted => Self::NullNotAdmitted,
            crate::action_dispatch::DispatchError::StaleGeneration { expected, current } => {
                Self::Dispatch(
                    crate::action_dispatch::DispatchError::StaleGeneration { expected, current },
                )
            }
            crate::action_dispatch::DispatchError::RevisionMismatch { detail } => {
                Self::Dispatch(
                    crate::action_dispatch::DispatchError::RevisionMismatch { detail },
                )
            }
            other => Self::Dispatch(other),
        }
    }
}

impl From<crate::action_journal::WriterError> for ExpiryError {
    fn from(error: crate::action_journal::WriterError) -> Self {
        Self::Admission(error)
    }
}

pub type Result<T> = std::result::Result<T, ExpiryError>;
