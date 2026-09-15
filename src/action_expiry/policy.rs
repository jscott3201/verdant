//! Expiry horizons and handoff gates with checked arithmetic.
//!
//! Elapsed monotonic time decides expiry; wall/boot-anchored cleanup decides
//! whether the clock itself is trustworthy. Suspend-qualified clocks refuse
//! new SET and permit only explicit cancel or admitted-NULL release. Earlier
//! packets and retained controller values may still take effect later; that
//! residual risk is shown, never renewed as intent.

use super::{ExpiryError, Result};
use crate::action_dispatch::{Current, DispatchCancel, FrozenRoute, FrozenWrite};
use crate::action_journal::Admitted;
use crate::action_preview::Preview;
use crate::domain::clock::{MonotonicMark, UnixMillis};
use crate::observation::time::{ClockReading, Continuity, Freshness, FreshnessPolicy, TimeEvidence};
use std::time::{Duration, Instant};

/// Monotonic expiry verdict. Exhaustive by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryState {
    Active,
    Expired { elapsed_secs: u64, duration_secs: u64 },
    Indeterminate { reason: &'static str },
}

impl ExpiryState {
    pub fn is_active(self) -> bool {
        match self {
            Self::Active => true,
            Self::Expired { .. } | Self::Indeterminate { .. } => false,
        }
    }
    pub fn is_expired(self) -> bool {
        match self {
            Self::Expired { .. } => true,
            Self::Active | Self::Indeterminate { .. } => false,
        }
    }
    pub fn is_indeterminate(self) -> bool {
        match self {
            Self::Indeterminate { .. } => true,
            Self::Active | Self::Expired { .. } => false,
        }
    }
}

/// Admitted horizon snapshot: duration/deadline/generations frozen at
/// admission. An edited duration applies only to a new horizon for a new
/// generation; the in-flight horizon keeps its admitted deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryHorizon {
    duration_secs: u64,
    deadline_secs: u64,
    expected_generation: u32,
    target_generation: u32,
}

impl ExpiryHorizon {
    /// Snapshot the admitted horizon read-only from preview timing plus
    /// journal generations. Delegates frozen-profile checks to dispatch
    /// rather than re-deriving them.
    pub fn from_admitted(admitted: &Admitted, preview: &Preview) -> Result<Self> {
        crate::action_dispatch::check_frozen_preview(preview).map_err(ExpiryError::from)?;
        let duration_secs = preview.timing().duration_secs();
        let deadline_secs = preview.timing().deadline_secs();
        if deadline_secs != admitted.deadline_secs() {
            return Err(ExpiryError::Invalid("admitted deadline differs from preview"));
        }
        let expected_generation = admitted.expected_generation();
        let target_generation = admitted.target_generation();
        let recomputed = expected_generation
            .checked_add(1)
            .ok_or(ExpiryError::Invalid("target generation overflow"))?;
        if recomputed != target_generation {
            return Err(ExpiryError::Invalid("journal generation order"));
        }
        Ok(Self {
            duration_secs,
            deadline_secs,
            expected_generation,
            target_generation,
        })
    }

    /// New horizon for a new generation with an edited duration. The
    /// receiver (`self`) is unchanged; callers must keep the in-flight
    /// horizon for already-admitted generations. `new_duration_secs` is a
    /// synthetic test-only edit here, never a commissioned facility value.
    pub fn with_edited_duration_for_new_generation(
        &self,
        new_duration_secs: u64,
        new_expected_generation: u32,
    ) -> Result<Self> {
        if new_duration_secs == 0 {
            return Err(ExpiryError::Invalid("edited duration non-zero"));
        }
        let new_target = new_expected_generation
            .checked_add(1)
            .ok_or(ExpiryError::Invalid("target generation overflow"))?;
        let _ = self.expected_generation;
        Ok(Self {
            duration_secs: new_duration_secs,
            deadline_secs: self.deadline_secs,
            expected_generation: new_expected_generation,
            target_generation: new_target,
        })
    }

    pub fn duration_secs(self) -> u64 {
        self.duration_secs
    }
    pub fn deadline_secs(self) -> u64 {
        self.deadline_secs
    }
    pub fn expected_generation(self) -> u32 {
        self.expected_generation
    }
    pub fn target_generation(self) -> u32 {
        self.target_generation
    }
}

/// Checked successor generation. Overflow refuses instead of wrapping.
pub fn next_generation(expected: u32) -> Result<u32> {
    expected
        .checked_add(1)
        .ok_or(ExpiryError::Invalid("target generation overflow"))
}

/// Checked deadline instant. Overflow refuses instead of wrapping.
pub fn deadline_instant(start: Instant, deadline_secs: u64) -> Result<Instant> {
    start
        .checked_add(Duration::from_secs(deadline_secs))
        .ok_or(ExpiryError::Invalid("deadline instant overflow"))
}

/// Checked wall age in millis. Rollback (now before receipt) refuses as
/// indeterminate, never a silently wrapped age.
pub fn wall_age_millis(now_wall: UnixMillis, receipt_wall: UnixMillis) -> Result<u64> {
    let delta = now_wall
        .as_millis()
        .checked_sub(receipt_wall.as_millis())
        .ok_or(ExpiryError::Indeterminate {
            reason: "wall-rollback",
        })?;
    u64::try_from(delta).map_err(|_| ExpiryError::Indeterminate {
        reason: "wall-rollback",
    })
}

/// Boot equality for monotonic comparisons. Cross-boot refuses as
/// indeterminate; a slept host's timer proves nothing current.
pub fn require_same_boot(first: &MonotonicMark, second: &MonotonicMark) -> Result<()> {
    if first.boot().as_str() == second.boot().as_str() {
        Ok(())
    } else {
        Err(ExpiryError::Indeterminate { reason: "cross-boot" })
    }
}

/// Confirmed continuity on one reading. Suspend-ambiguous refuses as
/// indeterminate.
pub fn require_confirmed(continuity: Continuity) -> Result<()> {
    match continuity {
        Continuity::Confirmed => Ok(()),
        Continuity::WallOrSuspendAmbiguous => Err(ExpiryError::Indeterminate {
            reason: "suspend-qualified",
        }),
    }
}

/// Assess monotonic expiry from identified marks. Cross-boot and
/// impossible-elapsed refuse as indeterminate, never as active. Elapsed at
/// or beyond the admitted duration is expired; a slept host's non-expired
/// timer proves nothing current (callers must also check freshness).
pub fn assess_expiry(
    start: &MonotonicMark,
    now: &MonotonicMark,
    duration_secs: u64,
) -> ExpiryState {
    match now.elapsed_since(start) {
        Ok(elapsed) => {
            let horizon = Duration::from_secs(duration_secs);
            if elapsed >= horizon {
                ExpiryState::Expired {
                    elapsed_secs: elapsed.as_secs(),
                    duration_secs,
                }
            } else {
                ExpiryState::Active
            }
        }
        Err(error) => match error {
            crate::domain::Error::BootMismatch { .. } => {
                ExpiryState::Indeterminate { reason: "cross-boot" }
            }
            crate::domain::Error::ImpossibleElapsed { .. } => {
                ExpiryState::Indeterminate {
                    reason: "impossible-elapsed",
                }
            }
            crate::domain::Error::Empty { .. }
            | crate::domain::Error::TooLong { .. }
            | crate::domain::Error::BadChars { .. }
            | crate::domain::Error::InvalidValue { .. }
            | crate::domain::Error::MissingField { .. }
            | crate::domain::Error::UnexpectedField { .. }
            | crate::domain::Error::UnexpectedType { .. }
            | crate::domain::Error::ImpossibleOrder { .. }
            | crate::domain::Error::Json { .. } => {
                ExpiryState::Indeterminate { reason: "clock-error" }
            }
        },
    }
}

/// Assess wall/boot-anchored cleanup in the shape of
/// `FreshnessPolicy::assess`: confirmed continuity on both evidence and now,
/// same boot, checked wall age, and wall/monotonic skew agreement. Any
/// ambiguity returns `Unknown`/`Stale`, never `Fresh`. Delegates to the
/// existing policy rather than re-deriving its logic.
pub fn assess_cleanup(
    evidence: &TimeEvidence,
    now: &ClockReading,
    policy: FreshnessPolicy,
) -> Freshness {
    policy.assess(evidence, now)
}

/// Gate a new authorized SET handoff. Only `Active` plus `Fresh` proceeds;
/// `Expired` and any `Unknown`/`Stale` refuse. Earlier packets may still take
/// effect later; refusal renews nothing.
pub fn decide_set_allowed(expiry: &ExpiryState, freshness: Freshness) -> Result<()> {
    match expiry {
        ExpiryState::Active => match freshness {
            Freshness::Fresh => Ok(()),
            Freshness::Stale => Err(ExpiryError::Indeterminate { reason: "stale" }),
            Freshness::Unknown => Err(ExpiryError::Indeterminate {
                reason: "unknown-time",
            }),
        },
        ExpiryState::Expired {
            elapsed_secs,
            duration_secs,
        } => Err(ExpiryError::Expired {
            elapsed_secs: *elapsed_secs,
            duration_secs: *duration_secs,
        }),
        ExpiryState::Indeterminate { reason } => {
            Err(ExpiryError::Indeterminate { reason: *reason })
        }
    }
}

/// Authorize one frozen SET handoff after the expiry/freshness gate, then
/// delegate to the existing dispatch preparation (actor/ceiling/policy/
/// binding/generation/value/deadline plus cooperative cancellation). No new
/// SET is authorized after expiry or under indeterminate time.
pub fn authorize_set(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    expiry: &ExpiryState,
    freshness: Freshness,
) -> Result<FrozenWrite> {
    decide_set_allowed(expiry, freshness)?;
    crate::action_dispatch::prepare_setpoint(admitted, preview, current, route, cancel, deadline)
        .map_err(ExpiryError::from)
}

/// Authorize an explicit cancel of an unattempted generation. Exact
/// generation equality only; a stale cancel for an old generation refuses
/// and leaves the current generation unaffected. Duplicate cancels of the
/// same unattempted identities remain idempotent (no row, no handoff).
pub fn authorize_cancel(expected_generation: u32, current_generation: u32) -> Result<()> {
    if expected_generation == current_generation {
        Ok(())
    } else {
        Err(ExpiryError::StaleGeneration {
            expected: expected_generation,
            current: current_generation,
        })
    }
}
