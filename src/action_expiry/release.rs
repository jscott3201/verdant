//! Strict NULL release and pending-release persistence.
//!
//! NULL (`0x00`), Real zero (`0x44 0x00 0x00 0x00 0x00`) and enumerated
//! inactive (`0x91 0x00`) are three different wire values by construction.
//! A NULL release is authorized only for an explicitly admitted release;
//! otherwise `NullNotAdmitted`. A release can reveal another system's
//! command (higher-priority slot or relinquish default); that residual value
//! is shown, not renewed as local intent. Pending release persists as
//! UNKNOWN with original identities for reconcile; delivery uncertainty
//! never authorizes a resend.

use super::{ExpiryError, Result};
use crate::action_dispatch::{Current, DispatchCancel, FrozenRoute, FrozenWrite};
use crate::action_journal::{Admitted, Journal};
use crate::action_preview::Preview;
use crate::domain::ids::{BindingRevision, InstalledId, OperationId};
use crate::domain::scope::TrustedScope;
use crate::observation::time::Freshness;
use super::policy::ExpiryState;
use std::time::Instant;

/// BACnet NULL application bytes (`0x00`): the only relinquish encoding.
pub const NULL_WIRE: [u8; 1] = [0x00];
/// BACnet Real zero bytes: distinct from NULL and from inactive.
pub const REAL_ZERO_WIRE: [u8; 5] = [0x44, 0x00, 0x00, 0x00, 0x00];
/// Enumerated inactive bytes: distinct from NULL and from Real zero.
pub const INACTIVE_WIRE: [u8; 2] = [0x91, 0x00];

/// True only for the exact NULL relinquish encoding.
pub fn is_null_wire(value: &[u8]) -> bool {
    value == NULL_WIRE
}

/// True only for the exact Real-zero encoding.
pub fn is_real_zero_wire(value: &[u8]) -> bool {
    value == REAL_ZERO_WIRE
}

/// True only for the exact enumerated-inactive encoding.
pub fn is_inactive_wire(value: &[u8]) -> bool {
    value == INACTIVE_WIRE
}

/// Authorize one frozen NULL release. Unlike SET, an expired or
/// indeterminate clock still permits an admitted NULL release (cancel-or-
/// NULL only after expiry); freshness therefore does not gate release.
/// Delegates exact admission/generation/binding/value checks to the existing
/// dispatch preparation, never re-derives them. Wrong target, wrong
/// generation, or a non-admitted NULL refuses before any send.
pub fn authorize_release(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
    _expiry: &ExpiryState,
    _freshness: Freshness,
) -> Result<FrozenWrite> {
    let write =
        crate::action_dispatch::prepare_release(admitted, preview, current, route, cancel, deadline)
            .map_err(ExpiryError::from)?;
    if !is_null_wire(write.value()) {
        return Err(ExpiryError::Invalid("null wire 0x00"));
    }
    if write.wire_bits().is_some() {
        return Err(ExpiryError::Invalid("release carries no Real bits"));
    }
    if !write.is_release() {
        return Err(ExpiryError::Invalid("release flag"));
    }
    Ok(write)
}

/// Pending release that persists when delivery fails. Holds the original
/// target/allocation/generation identities for reconcile; uncertain delivery
/// never authorizes a resend. Already-attempted obligations stay attached to
/// the old target even after a slot/binding change blocks new handoffs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRelease {
    operation: OperationId,
    attempt: OperationId,
    scope: TrustedScope,
    equipment: InstalledId,
    binding_revision: BindingRevision,
    accepted_revision: crate::accept::AcceptedRevision,
    expected_generation: u32,
    target_generation: u32,
}

impl PendingRelease {
    /// Preserve the original admitted identities read-only for cleanup.
    pub fn from_admitted(admitted: &Admitted) -> Self {
        Self {
            operation: admitted.operation().clone(),
            attempt: admitted.attempt().clone(),
            scope: admitted.scope().clone(),
            equipment: admitted.equipment().clone(),
            binding_revision: admitted.binding_revision(),
            accepted_revision: admitted.accepted_revision(),
            expected_generation: admitted.expected_generation(),
            target_generation: admitted.target_generation(),
        }
    }

    pub fn operation(&self) -> &OperationId {
        &self.operation
    }
    pub fn attempt(&self) -> &OperationId {
        &self.attempt
    }
    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }
    pub fn equipment(&self) -> &InstalledId {
        &self.equipment
    }
    pub fn binding_revision(&self) -> BindingRevision {
        self.binding_revision
    }
    pub fn accepted_revision(&self) -> crate::accept::AcceptedRevision {
        self.accepted_revision
    }
    pub fn expected_generation(&self) -> u32 {
        self.expected_generation
    }
    pub fn target_generation(&self) -> u32 {
        self.target_generation
    }

    /// Reconcile the persisted release from durable rows without resending.
    /// Cross-scope callers see `admission-not-found`, never another scope's
    /// row. Lost acknowledgment stays UNKNOWN until this reconcile recovers
    /// the original identities.
    pub fn reconcile_via(&self, journal: &Journal) -> Result<Admitted> {
        journal
            .reconcile(&self.operation, &self.scope)
            .map_err(ExpiryError::from)
    }
}
