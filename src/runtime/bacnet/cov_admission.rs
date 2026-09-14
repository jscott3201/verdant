//! PR02 integration: subscriptions share the existing runtime budget family.
//! Fixture partition: a subscription holds one CurrentSensing retained slot;
//! receive/revalidation uses the other, and one CurrentSensing running slot.
//! Reconciliation and its mandatory reserve are never borrowed. No new semaphore.
use super::{BindingPlan, Property};
use crate::runtime::{admission::*, task::Cancellation, *};
use std::sync::atomic::AtomicBool;

pub(crate) struct Slot {
    pub(super) budget: Arc<Budget>,
    _retained: Arc<Reservation>,
    _lease: Option<Arc<Lease>>,
    cancel: Cancellation,
    joined: AtomicBool,
    deadline: Instant,
}
impl Slot {
    pub fn joined(&self) -> bool {
        self.joined.load(Ordering::SeqCst)
    }
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
    pub(super) fn finish(&self) {
        self.joined.store(true, Ordering::SeqCst);
    }
    pub(super) fn check(&self) -> Result<()> {
        self.cancel.check(self.deadline)
    }
    pub(super) fn receive(&self) -> Result<(Arc<Reservation>, Arc<Reservation>)> {
        self.check()?;
        Ok((
            self.budget.reserve(WorkClass::CurrentSensing, false)?,
            self.budget.reserve(WorkClass::CurrentSensing, true)?,
        ))
    }
}

/// Private construction binds the owner to exactly the admitted immutable plan.
pub(crate) struct Permit {
    pub(super) slot: Arc<Slot>,
    pub(super) plan: BindingPlan,
    pub(super) property: Property,
}
impl Runtime {
    /// Synchronous authority/content verification BEFORE async protocol work.
    /// This does not start a client or expose a transport through the CLI.
    pub(crate) fn admit_cov(&mut self, plan: BindingPlan) -> Result<Permit> {
        if self.state != State::RunningInert {
            return Err(Error::NotRunning);
        }
        let session = self.session.as_ref().ok_or(Error::NotRunning)?;
        let owners = self.owners.as_ref().ok_or(Error::NotRunning)?;
        owners.verify_content(&session.selected)?;
        owners.check_generation(&session.selected, &session.credential)?;
        let entry = session.selected.config.entries().get(plan.key.as_str()).ok_or(Error::Stale)?;
        let binding = entry.binding();
        if binding.source() != &plan.source
            || binding.endpoint().as_str() != plan.endpoint
            || binding.point_property().as_str() != plan.property
            || binding.requested() != BindingRole::Sense
            || binding.effective() != BindingRole::Sense
            || binding.status() != BindingStatus::Valid
        {
            return Err(Error::Stale);
        }
        self.reserve_cov(plan)
    }
    fn reserve_cov(&mut self, plan: BindingPlan) -> Result<Permit> {
        self.cov_slots.retain(|slot| !slot.joined());
        // One subscription per synthetic runtime, preserving the second sensing
        // slot for bounded receive/revalidation. Not a host-global quota.
        if !self.cov_slots.is_empty() {
            return Err(Error::Saturated { class: WorkClass::CurrentSensing, running: false });
        }
        let property = match plan.request.operation() {
            super::model::Operation::Single(p) => *p,
            super::model::Operation::Multiple(_) | super::model::Operation::Discover { .. } => {
                return Err(Error::Invalid("COV requires one bounded property"))
            }
        };
        let slot = Arc::new(Slot {
            budget: self.budget.clone(),
            _retained: self.budget.reserve(WorkClass::CurrentSensing, false)?,
            _lease: self.lease.clone(),
            cancel: Cancellation::default(),
            joined: AtomicBool::new(false),
            deadline: Instant::now() + MAX_LIFETIME,
        });
        self.cov_slots.push(slot.clone());
        Ok(Permit { slot, plan, property })
    }
    #[cfg(test)]
    pub(crate) fn fixture_cov(&mut self, plan: BindingPlan) -> Result<Permit> {
        // Explicit synthetic scheduling seam; no authentication/field qualification.
        self.reserve_cov(plan)
    }
}
