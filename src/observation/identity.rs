//! Stable positions are (scope, producer, generation, sequence), never value hashes.
use super::{Error, Result};
use crate::domain::{
    ids::{InstalledId, SourceGenerationId},
    outcomes::RecordIdentity,
    scope::TrustedScope,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProducerId(InstalledId);
impl ProducerId {
    pub fn parse(text: &str) -> Result<Self> {
        Ok(Self(InstalledId::parse(text)?))
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerIncarnation(InstalledId);
impl ProducerIncarnation {
    pub fn parse(text: &str) -> Result<Self> {
        Ok(Self(InstalledId::parse(text)?))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObservationId {
    scope: TrustedScope,
    producer: ProducerId,
    position: RecordIdentity,
}
impl ObservationId {
    pub fn new(scope: TrustedScope, producer: ProducerId, position: RecordIdentity) -> Self {
        Self {
            scope,
            producer,
            position,
        }
    }
    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }
    pub fn producer(&self) -> &ProducerId {
        &self.producer
    }
    pub fn position(&self) -> &RecordIdentity {
        &self.position
    }
}

/// Caller-retained snapshot may be stale. Only a surviving synthetic receiver's
/// exact ledger match proves continuity. No disk persistence claim or Instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerCheckpoint {
    pub(super) scope: TrustedScope,
    pub(super) producer: ProducerId,
    pub(super) generation: SourceGenerationId,
    pub(super) next: u64,
}
impl ProducerCheckpoint {
    pub fn generation(&self) -> &SourceGenerationId {
        &self.generation
    }
    pub fn next_sequence(&self) -> u64 {
        self.next
    }
}
#[derive(Debug)]
pub struct Producer {
    pub(super) checkpoint: ProducerCheckpoint,
    pub(super) incarnation: ProducerIncarnation,
    pub(super) lease: u64,
}
impl Producer {
    pub fn checkpoint(&self) -> ProducerCheckpoint {
        self.checkpoint.clone()
    }
    pub fn incarnation(&self) -> &ProducerIncarnation {
        &self.incarnation
    }
    pub(super) fn next_id(&self) -> Result<(ObservationId, u64)> {
        let next = self
            .checkpoint
            .next
            .checked_add(1)
            .ok_or(Error::Invalid("producer sequence exhausted"))?;
        Ok((
            ObservationId::new(
                self.checkpoint.scope.clone(),
                self.checkpoint.producer.clone(),
                RecordIdentity::new(self.checkpoint.generation.clone(), self.checkpoint.next),
            ),
            next,
        ))
    }
}
