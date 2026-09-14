//! Closed read-only boundary. No trait accepting arbitrary client callbacks,
//! socket, raw protocol operation, WriteProperty or device-management surface.
//!
//! E01: no dependency amendment in PR01A. Pending PR01B input ONLY:
//! bacnet-client at observed rusty-bacnet dev
//! c19f6922b26dbdf00a0f1b4d95f8123cc99176ee requires a Tokio runtime.
//! apdu_retries(0) type-expressibility was confirmed in preparation; zero-retry
//! wire semantics remain UNVERIFIED. Verdant's service/destination allowlist
//! is still required. No package/revision/runtime is adopted here.
use super::{owners::Selection, RuntimeIncarnation, SourceGeneration, WorkId};
use crate::{
    accept::{AcceptedRevision, ActiveGeneration},
    domain::{ids::InstalledId, scope::TrustedScope},
};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Instant, SystemTime},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptOrigin {
    InertAdapterReturn,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawOutcome {
    NotAttemptedInert,
}

/// PR01A raw-envelope shape: identities and timestamp origins, not a normalized
/// observation, durable producer position or qualification. Source time is
/// absent, never replaced with dequeue/receipt time. No synthetic value/zero is
/// manufactured. PR01B must add bounded per-property transport outcomes.
#[derive(Debug, Clone)]
pub struct RawEnvelope {
    pub work: WorkId,
    pub scope: TrustedScope,
    pub accepted_revision: AcceptedRevision,
    pub active_generation: ActiveGeneration,
    pub runtime_incarnation: RuntimeIncarnation,
    pub source_generation: SourceGeneration,
    pub binding_key: InstalledId,
    pub source: InstalledId,
    pub endpoint: String,
    pub property: String,
    pub source_time: Option<SystemTime>,
    pub receipt_time: SystemTime,
    pub receipt_monotonic: Instant,
    pub receipt_origin: ReceiptOrigin,
    pub outcome: RawOutcome,
}
#[derive(Default, Clone)]
pub(super) struct InertAdapter {
    calls: Arc<AtomicU64>,
}
impl InertAdapter {
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
    pub fn read(
        &self,
        selected: &Selection,
        key: &str,
        work: WorkId,
        incarnation: RuntimeIncarnation,
        source_generation: SourceGeneration,
    ) -> super::Result<RawEnvelope> {
        let entry = selected.config.entries().get(key).ok_or(super::Error::Invalid("binding key"))?;
        let binding = entry.binding();
        let raw = RawEnvelope {
            work,
            scope: selected.config.scope().clone(),
            accepted_revision: selected.accepted.revision,
            active_generation: selected.active.generation(),
            runtime_incarnation: incarnation,
            source_generation,
            binding_key: entry.key().clone(),
            source: binding.source().clone(),
            endpoint: binding.endpoint().as_str().into(),
            property: binding.point_property().as_str().into(),
            source_time: None,
            receipt_time: SystemTime::now(),
            receipt_monotonic: Instant::now(),
            receipt_origin: ReceiptOrigin::InertAdapterReturn,
            outcome: RawOutcome::NotAttemptedInert,
        };
        let bytes = std::mem::size_of::<RawEnvelope>()
            + raw.endpoint.capacity()
            + raw.property.capacity()
            + raw.scope.as_str().len()
            + raw.binding_key.as_str().len()
            + raw.source.as_str().len();
        if bytes > super::admission::MAX_ENVELOPE_BYTES {
            return Err(super::Error::Invalid("raw envelope exceeds reservation"));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(raw)
    }
}
