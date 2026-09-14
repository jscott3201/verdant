//! PR01B reads remain socket-free; PR02 adds a finite direct COV owner and
//! test-only loopback peers under the 2026-09-14 E03 amendment. No CLI activation.
//! Inherited zero-retry failure-path wire semantics remain unqualified.
//! PR01B dependency profile, E02 assumptions and B01–B12 manifest: CONTRACT.md.
#[cfg(test)]
mod bounds_tests;
mod client;
pub(crate) mod cov;
pub(crate) mod cov_admission;
#[cfg(test)]
mod cov_tests;
#[cfg(test)]
pub(crate) mod test_loopback;
pub mod fake;
mod model;
pub mod poll;
mod quarantine;
use crate::runtime::{
    admission::{Budget, WorkClass},
    owners::Selection,
    task::Cancellation,
    RawEnvelope, RawOutcome, ReceiptOrigin,
};
pub use model::*;
pub use quarantine::{Advertisement, Candidate, CANDIDATE_TTL, MAX_CANDIDATES, MAX_CONFLICTS};
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    DeniedDestination,
    DeniedService,
    BindingMismatch,
    InvalidReply,
    Oversized,
    Budget,
    QuarantineFull,
    Poisoned,
    ClientStart,
    ClientStop,
    NotCurrent,
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "bacnet-invalid",
            Self::DeniedDestination => "bacnet-destination-denied",
            Self::DeniedService => "bacnet-service-denied",
            Self::BindingMismatch => "bacnet-binding-mismatch",
            Self::InvalidReply => "bacnet-invalid-reply",
            Self::Oversized => "bacnet-oversized",
            Self::Budget => "bacnet-shared-budget",
            Self::QuarantineFull => "bacnet-quarantine-full",
            Self::Poisoned => "bacnet-poisoned",
            Self::ClientStart => "bacnet-client-start",
            Self::ClientStop => "bacnet-client-stop",
            Self::NotCurrent => "bacnet-not-current",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}
impl std::error::Error for Error {}
impl From<Error> for crate::runtime::Error {
    fn from(error: Error) -> Self {
        Self::Bacnet(error.code())
    }
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub(super) struct Adapter {
    profile: Arc<Profile>,
    peer: fake::ScriptedPeer,
    executor: Arc<tokio::runtime::Runtime>,
    quarantine: Arc<Mutex<quarantine::Quarantine>>,
}
impl Adapter {
    pub fn new(profile: Profile, peer: fake::ScriptedPeer, budget: Arc<Budget>) -> Result<Self> {
        // One timer-only executor per configured adapter, not one runtime per
        // request. PR01A's admitted/joined threads drive it; no worker starts here.
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|_| Error::ClientStart)?;
        Ok(Self {
            profile: Arc::new(profile),
            peer,
            executor: Arc::new(executor),
            quarantine: Arc::new(Mutex::new(quarantine::Quarantine::new(budget))),
        })
    }
    pub fn admit(&self, selected: &Selection, key: &str, class: WorkClass) -> Result<BindingPlan> {
        if selected.config.scope() != &self.profile.scope {
            return Err(Error::BindingMismatch);
        }
        let plan =
            self.profile.plans.iter().find(|plan| plan.key.as_str() == key).ok_or(Error::BindingMismatch)?;
        if !self.profile.destinations.contains(&plan.target) {
            return Err(Error::DeniedDestination);
        }
        if !self.profile.services.contains(&plan.request.service()) {
            return Err(Error::DeniedService);
        }
        if plan.request.service() == Service::DirectedWhoIs && class != WorkClass::OptionalDiscovery {
            return Err(Error::DeniedService);
        }
        let entry = selected.config.entries().get(key).ok_or(Error::BindingMismatch)?;
        let binding = entry.binding();
        if binding.source() != &plan.source
            || binding.endpoint().as_str() != plan.endpoint
            || binding.point_property().as_str() != plan.property
        {
            return Err(Error::BindingMismatch);
        }
        // Admission owns this snapshot; neither profile nor candidate table can
        // resolve/retarget it between queueing and dispatch.
        Ok(plan.clone())
    }
    pub fn read(
        &self,
        context: super::plug::Context<'_>,
        plan: BindingPlan,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> crate::runtime::Result<RawEnvelope> {
        let port = fake::FakePort::new(
            self.peer.clone(),
            plan.target.clone(),
            plan.request.service(),
            self.profile.destinations.clone(),
            (cancel.clone(), deadline),
        );
        let (outcome, receipt) = self.executor.block_on(client::execute(port, &plan, cancel, deadline))?;
        let raw = RawEnvelope {
            work: context.work,
            scope: context.selected.config.scope().clone(),
            accepted_revision: context.selected.accepted.revision,
            active_generation: context.selected.active.generation(),
            runtime_incarnation: context.incarnation,
            source_generation: context.source,
            binding_key: plan.key,
            source: plan.source,
            endpoint: plan.endpoint,
            property: plan.property,
            source_time: None,
            receipt_time: receipt.wall,
            receipt_monotonic: receipt.monotonic,
            receipt_origin: ReceiptOrigin::BacnetClientReturn,
            outcome,
        };
        check_envelope(&raw)?;
        Ok(raw)
    }
    pub fn retain_candidates(&self, raw: &RawEnvelope) -> Result<()> {
        if let RawOutcome::Quarantined(advertisements) = &raw.outcome {
            let mut quarantine = self.quarantine.lock().map_err(|_| Error::Poisoned)?;
            for advertisement in advertisements {
                quarantine.observe(advertisement.clone(), raw.receipt_monotonic)?;
            }
        }
        Ok(())
    }
    pub fn candidates(&self, now: Instant) -> Result<Vec<Candidate>> {
        Ok(self.quarantine.lock().map_err(|_| Error::Poisoned)?.snapshot(now))
    }
    pub fn clear_candidates(&self) -> Result<()> {
        self.quarantine.lock().map_err(|_| Error::Poisoned)?.clear();
        Ok(())
    }
}

fn check_envelope(raw: &RawEnvelope) -> Result<()> {
    let mut bytes = std::mem::size_of::<RawEnvelope>()
        + raw.endpoint.capacity()
        + raw.property.capacity()
        + raw.scope.as_str().len()
        + raw.binding_key.as_str().len()
        + raw.source.as_str().len();
    match &raw.outcome {
        RawOutcome::Bacnet(batch) => {
            bytes += batch.target.realm().as_str().len()
                + batch.properties.capacity() * std::mem::size_of::<PropertyResult>();
            for property in &batch.properties {
                if let PropertyOutcome::Value(value) = &property.outcome {
                    bytes += value.capacity();
                }
            }
        }
        RawOutcome::Quarantined(advertisements) => {
            bytes += advertisements.capacity() * std::mem::size_of::<Advertisement>();
            for advertisement in advertisements {
                bytes += advertisement.target.realm().as_str().len();
            }
        }
        RawOutcome::NotAttemptedInert | RawOutcome::DiscoveryRefused => {}
    }
    if bytes > crate::runtime::admission::MAX_ENVELOPE_BYTES {
        Err(Error::Oversized)
    } else {
        Ok(())
    }
}
