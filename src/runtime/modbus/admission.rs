//! PR04 uses the original runtime family, never a second semaphore or capacity
//! borrowed from reconciliation. A connection holds one sensing retained slot;
//! its sequential read holds the other plus one active sensing reservation.
use super::{mapping::Map, Error, Result};
use crate::runtime::{admission::*, owners::Lease, task::Cancellation, *};
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

// Alongside BACNET_FAKE_PAYLOAD_BYTES=57344 (unchanged): eight scripted replies
// <=260 bytes, eight request/response exchanges captured at both boundaries
// <=32*260 bytes, four active slots <=2*260 bytes each = 12480 payload bytes.
// Payload only: excludes vector/executor/socket/OS overhead, not an RSS quota.
pub(crate) const MODBUS_FAKE_PAYLOAD_BYTES: usize = (8 + 32 + 4 * 2) * 260;
pub(crate) const MAX_SCRIPTS: usize = 8;

pub(crate) struct Slot {
    budget: Arc<Budget>,
    held: Mutex<Option<(Arc<Reservation>, Option<Arc<Lease>>)>>,
    cancel: Cancellation,
    joined: AtomicBool,
    deadline: Instant,
    pub(super) incarnation: RuntimeIncarnation,
    pub(super) source: SourceGeneration,
}
impl Slot {
    pub fn joined(&self) -> bool {
        self.joined.load(Ordering::SeqCst)
    }
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
    pub(super) fn finish(&self) {
        // A closed Client may remain inspectable without occupying admission.
        // No callbacks run while this short resource-release guard is held.
        match self.held.lock() {
            Ok(mut held) => {
                held.take();
            }
            Err(_) => return, // fail closed: preserve the unresolved reservation
        }
        self.joined.store(true, Ordering::SeqCst);
    }
    pub(super) fn check(&self) -> Result<()> {
        self.cancel.check(self.deadline).map_err(|_| Error::Cancelled)
    }
    pub(super) fn receive(&self) -> Result<(Arc<Reservation>, Arc<Reservation>)> {
        self.check()?;
        Ok((
            self.budget
                .reserve(WorkClass::CurrentSensing, false)
                .map_err(|_| Error::Budget)?,
            self.budget
                .reserve(WorkClass::CurrentSensing, true)
                .map_err(|_| Error::Budget)?,
        ))
    }
    pub(super) async fn cancelled(&self) {
        while self.check().is_ok() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// One admitted, immutable explicit map, not arbitrary unit/range routing.
pub(crate) struct Permit {
    pub(super) slot: Option<Arc<Slot>>,
    pub(super) map: Map,
}
impl Drop for Permit {
    fn drop(&mut self) {
        // No upstream task exists until connect hands this slot to the client.
        if let Some(slot) = &self.slot {
            slot.finish();
        }
    }
}
impl Runtime {
    /// Verify accepted binding and current generations outside network processing.
    /// This private synthetic API is not wired to CLI dispatch or a facility.
    pub(crate) fn admit_modbus(
        &mut self,
        key: &str,
        source: &str,
        endpoint: &str,
        property: &str,
        map: Map,
    ) -> crate::runtime::Result<Permit> {
        if self.state != State::RunningInert {
            return Err(crate::runtime::Error::NotRunning);
        }
        let session = self.session.as_ref().ok_or(crate::runtime::Error::NotRunning)?;
        let owners = self.owners.as_ref().ok_or(crate::runtime::Error::NotRunning)?;
        owners.verify_content(&session.selected)?;
        owners.check_generation(&session.selected, &session.credential)?;
        let binding = session
            .selected
            .config
            .entries()
            .get(key)
            .ok_or(crate::runtime::Error::Stale)?
            .binding();
        if binding.source().as_str() != source
            || binding.endpoint().as_str() != endpoint
            || binding.point_property().as_str() != property
            || binding.requested() != BindingRole::Sense
            || binding.effective() != BindingRole::Sense
            || binding.status() != BindingStatus::Valid
        {
            return Err(crate::runtime::Error::Stale);
        }
        self.reserve_modbus(map, session.incarnation, session.source)
    }
    fn reserve_modbus(
        &mut self,
        map: Map,
        incarnation: RuntimeIncarnation,
        source: SourceGeneration,
    ) -> crate::runtime::Result<Permit> {
        self.modbus_slots.retain(|s| !s.joined());
        if !self.modbus_slots.is_empty() {
            return Err(crate::runtime::Error::Saturated {
                class: WorkClass::CurrentSensing,
                running: false,
            });
        }
        let slot = Arc::new(Slot {
            budget: self.budget.clone(),
            held: Mutex::new(Some((
                self.budget.reserve(WorkClass::CurrentSensing, false)?,
                self.lease.clone(),
            ))),
            cancel: Cancellation::default(),
            joined: AtomicBool::new(false),
            deadline: Instant::now() + MAX_LIFETIME,
            incarnation,
            source,
        });
        self.modbus_slots.push(slot.clone());
        Ok(Permit {
            slot: Some(slot),
            map,
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture_modbus(&mut self, map: Map) -> crate::runtime::Result<Permit> {
        self.reserve_modbus(
            map,
            RuntimeIncarnation(next(&INCARNATION)?),
            SourceGeneration(next(&SOURCE)?),
        )
    }
}
