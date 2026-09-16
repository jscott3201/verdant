//! M02-PR09 publication, replacement and exclusion, HARNESS-ONLY.
//!
//! Assigned writer: integrate exact M01 activation with per-target admission
//! for the frozen synthetic profile. Cosmetic (label-only) edits preserve
//! unaffected state; material route/target/unit/role/slot/policy/binding/
//! facts/provenance changes block affected new handoffs until the new
//! publication is accepted and activated. Already-attempted obligations stay
//! attached to their old physical target. Takeover uses manual, independently
//! effective old-writer exclusion only. Local before/after ordering is
//! recorded: pre-handoff revocation prevents send, post-handoff revocation
//! cannot recall it. An old release can never target replacement hardware.
//! A slow unrelated native publication never holds every controller
//! transaction hostage (per-target isolation, bounded budgets).
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
//! [`EffectiveConfig::impact_from`](crate::accept::EffectiveConfig::impact_from)
//! for cosmetic-vs-material gating; [`AcceptanceStore`](crate::accept::AcceptanceStore)
//! `active`/`current` plus `prepare`/`submit_activation` for exact activation
//! currency; [`Journal`](crate::action_journal::Journal) `prepare`/`submit`/
//! `reconcile` per-target CAS; dispatch `verify_content`/`verify_generation`/
//! `recheck_after_handoff` (via [`recovery`](crate::action_recovery)) for
//! handoff checks; [`verify_handoff`](crate::action_recovery::verify_handoff)
//! and
//! [`require_peer_accepted_before_journal`](crate::action_recovery::require_peer_accepted_before_journal)
//! for handoff verification and peer-before-journal ordering. Expiry
//! (`authorize_set`/`authorize_release`) gates time; never re-derived here.
//!
//! SQL-txn discipline: long reads (accept history, binding replay, seal
//! custody, revocation read) happen before any ticket; exact guards live in
//! the owning tickets (`authority.guard`, `registry.guard`, `sealed.guard`,
//! `admission_generation`, `activation_*`); no network/adapter op runs under
//! a SQL transaction; announce/recheck happens after commit. This module
//! creates no ticket, row, column, table, index or migration of its own.
//!
//! Takeover is MANUAL EXCLUSION only: [`OldWriterExclusion`] is constructed
//! by an explicit operator call with a validated reason, is independently
//! effective (refuses the named old writer even when every other check would
//! pass), and is checked pre-handoff alongside content/generation plus as a
//! durable CAS where durable (the existing revocation rows plus generation
//! advance plus binding retire — `access-revoke`, `action_targets`, and
//! `binding-retire` — already guarded by the owning tickets). Never
//! file-lock/heartbeat/replica-count/generation/lost-hub fencing. Never
//! automatic: there is no `Default`, no `From<String>`, no background task.
//! No profile widening on takeover: `check_frozen_preview` and admitted-NULL
//! `authorize_release` stay verbatim.
//!
//! Replacement is OLD-TARGET PINNED: a reused address surfaces
//! `is_retired`/`needs_reassessment` plus a binding-revision mismatch and
//! refuses new handoffs until fresh qualification/acceptance (no
//! auto-promotion; record a new id per the retired-address precedent); a
//! stale activation surfaces `StaleGeneration`/`Superseded` plus
//! `verify_backup` REFUSE STALE; an old-instance restart mints a new
//! producer generation before emission with old IDs pinned
//! (`PendingRelease` plus `verify_backup_against_current`), never replays
//! retained actions; an old release can never target replacement hardware.
//!
//! Harness scope (PR07/PR08/PR11 precedent carries forward,
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
//! qualification, or real-time proof. See [`LIMITS`].
//!
//! Must NOT claim: exactly-once, active-active, field-CAS, revived-stack,
//! replay-all, quiescence-from-handle-drop/lease-expiry, automatic takeover,
//! obligation migration to replacement hardware, end-at-deadline, exact stop
//! at expiry, real-time proof, power-loss/disk-full qualification,
//! host-global quota, universal rollback, emergency-stop, guessed-restore,
//! blanket-release-on-shutdown, `ObservedQualified` minting, `source_time`
//! invention, or `Freshness`-to-qualification upgrade.
#![allow(dead_code)]

pub mod policy;
pub mod publication;

#[allow(unused_imports)]
pub use policy::{assess_impact, assess_target_impact, ImpactGate, OldWriterExclusion};
#[allow(unused_imports)]
pub use publication::{
    authorize_joined_setpoint_via_publication, authorize_release_via_publication,
    authorize_setpoint_via_publication, recheck_after_handoff_via_publication,
    require_activation_current_for_handoff, require_aliases_unique,
    require_peer_accepted_before_journal_via_publication, verify_handoff_via_publication,
};

/// Publication decision-table wire-format tag (policy refusal only; no wire).
pub const PUBLICATION_FORMAT: &str = "verdant-publication-v1";

/// Stated limits for delayed packets and third-party writers. These constrain
/// the profile; they do not disappear from reports. Tests assert the key
/// phrases below so the limit text cannot silently shrink.
pub const LIMITS: &str = "delayed-packets-may-take-effect-later; third-party-writers-outside-transport-ownership-unbounded; null-release-may-reveal-other-system-command; one-call-is-not-one-send; timeout-uncertain-never-resend; synthetic-budgets-not-host-quotas; no-power-loss-disk-full-real-time-claim";

/// Typed publication failure with a stable machine code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationError {
    Invalid(&'static str),
    InvalidDetail { what: &'static str, detail: String },
    /// Manual old-writer exclusion (takeover): independently effective,
    /// operator-gated, never automatic.
    Excluded { detail: String },
    /// Pre-handoff revocation ordering: a revocation read before the handoff
    /// prevents send. Post-handoff revocation cannot recall (UNKNOWN until
    /// reconcile, never resend).
    Revoked { detail: String },
    /// Material route/target/unit/role/slot/policy/binding/facts/provenance
    /// change: the affected new handoff is blocked until the new publication
    /// is accepted and activated.
    Blocked { detail: String },
    /// Old-target pin: already-attempted obligations stay attached to their
    /// old physical target; an old release can never target replacement
    /// hardware; a reused address needs fresh qualification/acceptance.
    Pinned { detail: String },
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
    /// Delegated preview refusal; preserves the preview machine code
    /// (`duplicate-identity` for aliases, `preview-revision-mismatch`, ...).
    Preview(crate::action_preview::PreviewError),
    /// Delegated binding refusal; preserves the binding code
    /// (`needs-reassessment` for reused addresses, `duplicate-identity`,
    /// `conflict`, ...).
    Binding(crate::binding::BindingError),
    /// Delegated access refusal; preserves the access code
    /// (`revoked-credential`, `ceiling-exceeded`, ...).
    Access(crate::access::AccessError),
    /// Delegated accept/activation refusal; preserves the accept code
    /// (`accept-invalid`, `activation-stale-generation`,
    /// `activation-superseded`, `accept-conflict`, ...).
    Accept { code: &'static str, detail: String },
}

impl PublicationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) | Self::InvalidDetail { .. } => "publication-invalid",
            Self::Excluded { .. } => "publication-excluded",
            Self::Revoked { .. } => "publication-revoked",
            Self::Blocked { .. } => "publication-blocked",
            Self::Pinned { .. } => "publication-pinned",
            Self::Conflict { .. } => "publication-conflict",
            Self::Unknown { .. } => "publication-unknown",
            Self::Dispatch(inner) => inner.code(),
            Self::Admission(inner) => inner.code(),
            Self::Expiry(inner) => inner.code(),
            Self::Recovery(inner) => inner.code(),
            Self::Preview(inner) => inner.code(),
            Self::Binding(inner) => inner.code(),
            Self::Access(inner) => inner.code(),
            Self::Accept { code, .. } => code,
        }
    }
}

impl std::fmt::Display for PublicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "publication invalid: {detail}"),
            Self::InvalidDetail { what, detail } => {
                write!(f, "publication invalid {what}: {detail}")
            }
            Self::Excluded { detail } => write!(
                f,
                "publication excluded old writer (manual takeover only): {detail}"
            ),
            Self::Revoked { detail } => write!(
                f,
                "publication revoked before handoff, send prevented: {detail}"
            ),
            Self::Blocked { detail } => write!(
                f,
                "publication blocked until accepted (material change): {detail}"
            ),
            Self::Pinned { detail } => write!(
                f,
                "publication pinned to old target (no obligation migration): {detail}"
            ),
            Self::Conflict { detail } => write!(f, "publication conflict: {detail}"),
            Self::Unknown { operation, attempt, detail } => write!(
                f,
                "publication outcome UNKNOWN for {operation}/{attempt}; reconcile these identities, do not resend: {detail}"
            ),
            Self::Dispatch(inner) => write!(f, "{inner}"),
            Self::Admission(inner) => write!(f, "{inner}"),
            Self::Expiry(inner) => write!(f, "{inner}"),
            Self::Recovery(inner) => write!(f, "{inner}"),
            Self::Preview(inner) => write!(f, "{inner}"),
            Self::Binding(inner) => write!(f, "{inner}"),
            Self::Access(inner) => write!(f, "{inner}"),
            Self::Accept { detail, .. } => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for PublicationError {}

impl From<crate::action_dispatch::DispatchError> for PublicationError {
    fn from(error: crate::action_dispatch::DispatchError) -> Self {
        Self::Dispatch(error)
    }
}

impl From<crate::action_journal::WriterError> for PublicationError {
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

impl From<crate::action_expiry::ExpiryError> for PublicationError {
    fn from(error: crate::action_expiry::ExpiryError) -> Self {
        Self::Expiry(error)
    }
}

impl From<crate::action_recovery::RecoveryError> for PublicationError {
    fn from(error: crate::action_recovery::RecoveryError) -> Self {
        Self::Recovery(error)
    }
}

impl From<crate::binding::BindingError> for PublicationError {
    fn from(error: crate::binding::BindingError) -> Self {
        Self::Binding(error)
    }
}

impl From<crate::action_preview::PreviewError> for PublicationError {
    fn from(error: crate::action_preview::PreviewError) -> Self {
        Self::Preview(error)
    }
}

impl From<crate::access::AccessError> for PublicationError {
    fn from(error: crate::access::AccessError) -> Self {
        Self::Access(error)
    }
}

impl PublicationError {
    /// Preserve the accept/activation machine code without cloning its
    /// non-cloneable error body.
    pub fn from_accept(error: crate::accept::Error) -> Self {
        Self::Accept { code: error.code(), detail: error.to_string() }
    }
}

pub type Result<T> = std::result::Result<T, PublicationError>;
