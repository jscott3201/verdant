//! M02-PR03A: pure normalization and a synthetic in-memory receiver/read index.
//! No stores, schema, sockets, workers, editable meaning, or CLI activation.
//! New-file-only composition is exercised by tests/observation.rs, following the
//! existing source-inclusion harness. The ordinary binary does not wire this API.
//! PR03B owns durable custody, finite retention and process-crash continuity.
#![allow(dead_code)] // API-first: the PR03B consumer is pending.
pub mod identity;
pub mod index;
pub mod normalize;
pub mod time;
pub(crate) mod window;
pub(crate) mod spool;
pub(crate) mod pins;
pub(crate) mod custody;

use crate::{
    accept::{AcceptedRevision, ActiveGeneration, EffectiveConfig},
    domain::{
        ids::{BindingRevision, InstalledId},
        scope::TrustedScope,
    },
    runtime::{self, bacnet::Property, RawEnvelope, RawOutcome, ReceiptOrigin},
};
use identity::{ObservationId, ProducerIncarnation};
use normalize::{Codec, Decoded, Refusal, Suitability, UnitProvenance};
use std::{sync::Arc, time::SystemTime};
use time::{ClockReading, Freshness, FreshnessPolicy, TimeEvidence};

#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Conflict(&'static str),
    Domain(crate::domain::Error),
    Access(crate::access::AccessError),
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid-input",
            Self::Conflict(_) => "conflict",
            Self::Domain(error) => error.code(),
            Self::Access(error) => error.code(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) | Self::Conflict(detail) => write!(f, "[{}] {detail}", self.code()),
            Self::Domain(error) => error.fmt(f),
            Self::Access(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
impl From<crate::domain::Error> for Error {
    fn from(error: crate::domain::Error) -> Self {
        Self::Domain(error)
    }
}
impl From<crate::access::AccessError> for Error {
    fn from(error: crate::access::AccessError) -> Self {
        Self::Access(error)
    }
}

/// Immutable raw evidence reference target. Omits only the process-local Instant;
/// its portable counterpart is an independently supplied identified MonotonicMark.
/// Retains the entire batch, including other property failures, and exact wall times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRecord {
    pub work: runtime::WorkId,
    pub scope: TrustedScope,
    pub accepted_revision: AcceptedRevision,
    pub active_generation: ActiveGeneration,
    pub runtime_incarnation: runtime::RuntimeIncarnation,
    pub source_generation: runtime::SourceGeneration,
    pub binding_key: InstalledId,
    pub source: InstalledId,
    pub endpoint: String,
    pub property: String,
    pub source_time: Option<SystemTime>,
    pub receipt_time: SystemTime,
    pub receipt_origin: ReceiptOrigin,
    pub outcome: RawOutcome,
}
impl From<&RawEnvelope> for RawRecord {
    fn from(raw: &RawEnvelope) -> Self {
        Self {
            work: raw.work,
            scope: raw.scope.clone(),
            accepted_revision: raw.accepted_revision,
            active_generation: raw.active_generation,
            runtime_incarnation: raw.runtime_incarnation,
            source_generation: raw.source_generation,
            binding_key: raw.binding_key.clone(),
            source: raw.source.clone(),
            endpoint: raw.endpoint.clone(),
            property: raw.property.clone(),
            source_time: raw.source_time,
            receipt_time: raw.receipt_time,
            receipt_origin: raw.receipt_origin,
            outcome: raw.outcome.clone(),
        }
    }
}

/// Read-only join to the existing meaning owner's selected config. No new graph.
/// This constructor validates a synthetic selection, NOT live acceptance authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingContext {
    scope: TrustedScope,
    key: InstalledId,
    binding_revision: BindingRevision,
    accepted_revision: AcceptedRevision,
    active_generation: ActiveGeneration,
    runtime_incarnation: runtime::RuntimeIncarnation,
    source_generation: runtime::SourceGeneration,
    entry: crate::accept::Entry,
    property: Property,
}
impl BindingContext {
    /// Test-only join for PR36 loopback read envelopes; confers no field authority.
    /// Retains every synthetic selection check and adds a loopback/property guard.
    /// Neither a peer response nor this context establishes observed qualification.
    #[cfg(test)]
    pub(crate) fn loopback(
        config: &EffectiveConfig,
        raw: &RawEnvelope,
        property: Property,
    ) -> Result<Self> {
        let RawOutcome::Bacnet(batch) = &raw.outcome else {
            return Err(Error::Invalid("not a loopback property read"));
        };
        let [a, b, c, d, hi, lo] = *batch.target.mac();
        if [a, b, c, d] != [127, 0, 0, 1]
            || u16::from_be_bytes([hi, lo]) == 0
            || raw.receipt_origin != ReceiptOrigin::BacnetClientReturn
            || batch.properties.iter().filter(|p| p.property == property).count() != 1
        {
            return Err(Error::Invalid("loopback read context"));
        }
        Self::synthetic(config, raw, property)
    }

    pub fn synthetic(config: &EffectiveConfig, raw: &RawEnvelope, property: Property) -> Result<Self> {
        let entry = config
            .entries()
            .get(raw.binding_key.as_str())
            .ok_or(Error::Invalid("binding not selected"))?;
        let binding = entry.binding();
        if config.scope() != &raw.scope
            || binding.point_scope() != &raw.scope
            || binding.endpoint_scope() != &raw.scope
            || binding.source() != &raw.source
            || binding.endpoint().as_str() != raw.endpoint
            || binding.point_property().as_str() != raw.property
        {
            return Err(Error::Invalid("raw envelope does not match synthetic selection"));
        }
        Ok(Self {
            scope: raw.scope.clone(),
            key: raw.binding_key.clone(),
            binding_revision: config.binding_revision(),
            accepted_revision: raw.accepted_revision,
            active_generation: raw.active_generation,
            runtime_incarnation: raw.runtime_incarnation,
            source_generation: raw.source_generation,
            entry: entry.clone(),
            property,
        })
    }
    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }
    pub fn key(&self) -> &InstalledId {
        &self.key
    }
    pub fn binding_revision(&self) -> BindingRevision {
        self.binding_revision
    }
    pub fn accepted_revision(&self) -> AcceptedRevision {
        self.accepted_revision
    }
    pub fn active_generation(&self) -> ActiveGeneration {
        self.active_generation
    }
    fn matches(&self, raw: &RawEnvelope) -> bool {
        self.scope == raw.scope
            && self.key == raw.binding_key
            && self.accepted_revision == raw.accepted_revision
            && self.active_generation == raw.active_generation
            && self.runtime_incarnation == raw.runtime_incarnation
            && self.source_generation == raw.source_generation
            && self.entry.binding().source() == &raw.source
            && self.entry.binding().endpoint().as_str() == raw.endpoint
            && self.entry.binding().point_property().as_str() == raw.property
    }
}

#[derive(Debug, Clone)]
pub struct Normalization {
    pub units: UnitProvenance,
    pub codec: Codec,
    pub receipt_mark: crate::domain::clock::MonotonicMark,
    pub ingestion: ClockReading,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingObservation {
    raw: Arc<RawRecord>,
    binding: BindingContext,
    decoded: Decoded,
    time: TimeEvidence,
    freshness: Freshness,
    policy: FreshnessPolicy,
}
impl PendingObservation {
    /// Preserve invalid value evidence; refuse only an unjoinable/raw non-read
    /// envelope or a timestamp outside the representable range. No I/O.
    pub fn from_bacnet(
        raw: &RawEnvelope,
        binding: BindingContext,
        input: Normalization,
        policy: FreshnessPolicy,
    ) -> Result<Self> {
        if !binding.matches(raw) {
            return Err(Error::Invalid("binding revision/generation join"));
        }
        let RawOutcome::Bacnet(batch) = &raw.outcome else {
            return Err(Error::Invalid("not a property read"));
        };
        if batch.properties.is_empty() || batch.properties.len() > runtime::bacnet::MAX_PROPERTIES {
            return Err(Error::Invalid("property count"));
        }
        let mut matching = batch
            .properties
            .iter()
            .filter(|result| result.property == binding.property);
        let result = matching
            .next()
            .ok_or(Error::Invalid("selected property absent"))?;
        if matching.next().is_some() {
            return Err(Error::Invalid("ambiguous repeated property"));
        }
        let mut decoded = normalize::decode(&result.outcome, input.units, input.codec);
        if decoded.suitability == Suitability::SyntheticValueOnly
            && decoded.unit != *binding.entry.binding().unit()
        {
            decoded.suitability = Suitability::Refused(Refusal::WrongUnit);
        }
        let time = TimeEvidence::new(
            raw.source_time,
            raw.receipt_time,
            raw.receipt_origin,
            input.receipt_mark,
            input.ingestion,
        )?;
        let freshness = policy.assess(&time, &time.ingestion);
        Ok(Self {
            raw: Arc::new(RawRecord::from(raw)),
            binding,
            decoded,
            time,
            freshness,
            policy,
        })
    }
    /// Pure identity attachment supports receiver reconciliation tests; constructing
    /// a record is not permission to insert/read it or proof of producer continuity.
    pub fn identify(
        self,
        id: ObservationId,
        incarnation: ProducerIncarnation,
    ) -> Result<NormalizedObservation> {
        if id.scope() != self.binding.scope() {
            return Err(Error::Invalid("identity scope"));
        }
        Ok(NormalizedObservation {
            id,
            incarnation,
            content: self,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedObservation {
    id: ObservationId,
    incarnation: ProducerIncarnation,
    content: PendingObservation,
}
impl NormalizedObservation {
    pub fn id(&self) -> &ObservationId {
        &self.id
    }
    pub fn incarnation(&self) -> &ProducerIncarnation {
        &self.incarnation
    }
    pub fn raw(&self) -> &Arc<RawRecord> {
        &self.content.raw
    }
    pub fn binding(&self) -> &BindingContext {
        &self.content.binding
    }
    pub fn decoded(&self) -> &Decoded {
        &self.content.decoded
    }
    pub fn time(&self) -> &TimeEvidence {
        &self.content.time
    }
    pub fn freshness_at_ingestion(&self) -> Freshness {
        self.content.freshness
    }
    pub(super) fn assess(&self, now: &ClockReading) -> Freshness {
        self.content.policy.assess(self.time(), now)
    }
}
