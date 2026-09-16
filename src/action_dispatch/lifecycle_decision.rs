//! Pure lifecycle gate consulted before any send (no I/O, no SQL, no network).
//!
//! The Journal owner persists `admitted -> dispatched -> terminal/unresolved`
//! before the external send; dispatch consults the already-read `Admitted`
//! lifecycle here. Terminal refuses (history stays reconcile-readable, no
//! blind resend); admitted/dispatched/unresolved proceed to the existing
//! content/generation/value checks. This table never runs SQL under network
//! and never touches transport.

use crate::action_journal::{Admitted, LifecycleState};
use super::{DispatchError, Result};

/// Consult the durable lifecycle before encoding a send. Terminal is final.
pub fn check_lifecycle_for_dispatch(admitted: &Admitted) -> Result<()> {
    match admitted.lifecycle() {
        LifecycleState::Admitted | LifecycleState::Dispatched | LifecycleState::Unresolved => Ok(()),
        LifecycleState::Terminal => Err(DispatchError::Invalid("lifecycle terminal is final; reconcile history, do not resend")),
    }
}

/// Re-verify the durable deadline wall at the transport boundary (SET-only).
///
/// `authorize_joined_setpoint` grants a permit anchored to the durable
/// `created_secs`; the harness `execute_setpoint` funnels through
/// `prepare_setpoint`, which calls this with the live wall so a delayed queue
/// plus a fresh `Instant` cannot renew the anchor. The boundary intentionally
/// mirrors the expiry owner (`assess_deadline_wall`: elapsed at or beyond
/// the admitted deadline is expired, rollback before `created` is
/// indeterminate) without importing it: several test binaries include
/// `action_dispatch` without `action_expiry`, and a new cross-owner edge
/// would break them. The Slice E wall tests pin both boundaries to the same
/// values, so drift fails closed and loud. Release stays exempt
/// (constrained cleanup, see `prepare_release`, which never calls this).
/// Pure decision, no I/O: reads the already-reconciled `admitted` row.
pub fn verify_durable_wall_for_set(admitted: &Admitted) -> Result<()> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| DispatchError::InvalidDetail {
            what: "wall",
            detail: "durable wall indeterminate: clock before epoch; fresh Instant cannot renew durable anchor".to_string(),
        })?;
    let now_secs = i64::try_from(now_secs).map_err(|_| DispatchError::InvalidDetail {
        what: "wall",
        detail: "durable wall indeterminate: wall out of range; fresh Instant cannot renew durable anchor".to_string(),
    })?;
    verify_durable_wall_for_set_with_now(admitted, now_secs)
}

/// Deterministic variant of [`verify_durable_wall_for_set`] against an
/// explicit wall `now_secs` (same boundary, no clock read). Test-only seam
/// for the Slice E wall-boundary proofs; product callers use the live wall.
pub fn verify_durable_wall_for_set_with_now(admitted: &Admitted, now_secs: i64) -> Result<()> {
    let elapsed = now_secs.checked_sub(admitted.created_secs());
    match elapsed {
        None => Err(DispatchError::InvalidDetail {
            what: "wall",
            detail: "durable wall indeterminate (wall-rollback); fresh Instant cannot renew durable anchor".to_string(),
        }),
        Some(delta) if delta < 0 => Err(DispatchError::InvalidDetail {
            what: "wall",
            detail: "durable wall indeterminate (wall-rollback); fresh Instant cannot renew durable anchor".to_string(),
        }),
        Some(delta) => {
            let elapsed_u = u64::try_from(delta).map_err(|_| DispatchError::InvalidDetail {
                what: "wall",
                detail: "durable wall indeterminate (wall-rollback); fresh Instant cannot renew durable anchor".to_string(),
            })?;
            if elapsed_u >= admitted.deadline_secs() {
                return Err(DispatchError::InvalidDetail {
                    what: "wall",
                    detail: format!("durable deadline wall expired: elapsed {elapsed_u}s >= deadline {}s; fresh Instant cannot renew durable anchor", admitted.deadline_secs()),
                });
            }
            Ok(())
        }
    }
}
