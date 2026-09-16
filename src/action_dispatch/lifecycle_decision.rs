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
