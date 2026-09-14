//! Synthetic receiver only. A surviving receiver ledger adjudicates restored
//! counters. No real hub, persistent table, custody promise or automatic eviction.
use super::{
    identity::{Producer, ProducerCheckpoint, ProducerId, ProducerIncarnation},
    normalize::{Refusal, Suitability},
    time::{ClockReading, Freshness},
    BindingContext, Error, NormalizedObservation, ObservationId, PendingObservation, Result,
};
use crate::{
    access::{AccessGate, Credential},
    domain::{
        ids::{InstalledId, SourceGenerationId},
        scope::TrustedScope,
    },
};

struct Ledger {
    checkpoint: ProducerCheckpoint,
    lease: u64,
}
struct Stored {
    observation: NormalizedObservation,
    freshness: Freshness,
}
struct Current {
    scope: TrustedScope,
    key: InstalledId,
    record: usize,
}

pub struct SyntheticReceiver {
    namespace: SourceGenerationId,
    allocation: u64,
    limit: usize,
    producers: Vec<Ledger>,
    records: Vec<Stored>,
    bindings: Vec<BindingContext>,
    current: Vec<Current>,
}
/// Move-only intact image: local readback/rebuild test seam, NOT serialized data,
/// process-crash recovery, safe cloning of a receiver, or durable custody.
pub struct ReceiverImage(SyntheticReceiver);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconciliation {
    SameContent,
}
pub struct CurrentValue<'a> {
    pub observation: &'a NormalizedObservation,
    pub freshness: Freshness,
    pub suitability: Suitability,
}
impl CurrentValue<'_> {
    pub fn dependent_value(&self) -> std::result::Result<&crate::domain::values::Value, Refusal> {
        match self.suitability {
            Suitability::SyntheticValueOnly => Ok(&self.observation.decoded().value),
            Suitability::Refused(reason) => Err(reason),
        }
    }
}
impl SyntheticReceiver {
    /// Namespace must be fresh for a newly created independent synthetic receiver.
    /// Continuity across receiver loss is explicitly unproved (PR03B/M04).
    /// `limit` is caller-selected fixture capacity: exhaustion refuses, never evicts.
    pub fn new(namespace: SourceGenerationId, limit: usize) -> Result<Self> {
        if limit == 0 || namespace.as_str().len() > 96 {
            return Err(Error::Invalid("receiver namespace/capacity"));
        }
        Ok(Self {
            namespace,
            allocation: 0,
            limit,
            producers: Vec::new(),
            records: Vec::new(),
            bindings: Vec::new(),
            current: Vec::new(),
        })
    }
    fn allocate(&mut self) -> Result<(SourceGenerationId, u64)> {
        let allocation = self
            .allocation
            .checked_add(1)
            .ok_or(Error::Invalid("receiver generation exhausted"))?;
        let generation = SourceGenerationId::parse(&format!("{}:{allocation}", self.namespace.as_str()))?;
        self.allocation = allocation;
        Ok((generation, allocation))
    }
    pub fn start(
        &mut self,
        gate: &AccessGate,
        credential: Option<&Credential>,
        scope: TrustedScope,
        producer: ProducerId,
        incarnation: ProducerIncarnation,
    ) -> Result<Producer> {
        gate.enter_review(credential, &scope)?;
        if self
            .producers
            .iter()
            .any(|p| p.checkpoint.scope == scope && p.checkpoint.producer == producer)
        {
            return Err(Error::Conflict("producer exists; reconcile its checkpoint"));
        }
        if self.producers.len() >= self.limit {
            return Err(Error::Invalid("producer capacity"));
        }
        let (generation, lease) = self.allocate()?;
        let checkpoint = ProducerCheckpoint {
            scope,
            producer,
            generation,
            next: 0,
        };
        self.producers.push(Ledger {
            checkpoint: checkpoint.clone(),
            lease,
        });
        Ok(Producer {
            checkpoint,
            incarnation,
            lease,
        })
    }
    pub fn resume(
        &mut self,
        gate: &AccessGate,
        credential: Option<&Credential>,
        restored: ProducerCheckpoint,
        incarnation: ProducerIncarnation,
    ) -> Result<Producer> {
        gate.enter_review(credential, &restored.scope)?;
        let index = self
            .producers
            .iter()
            .position(|p| p.checkpoint.scope == restored.scope && p.checkpoint.producer == restored.producer)
            .ok_or(Error::Conflict("receiver has no continuity evidence"))?;
        let intact = self.producers[index].checkpoint == restored;
        // Every resume fences a still-held old producer. Ambiguous rollback mints
        // a generation BEFORE emitting, even if equal values might hide reuse.
        let (fresh_generation, lease) = self.allocate()?;
        let checkpoint = if intact {
            restored
        } else {
            ProducerCheckpoint {
                scope: restored.scope,
                producer: restored.producer,
                generation: fresh_generation,
                next: 0,
            }
        };
        self.producers[index] = Ledger {
            checkpoint: checkpoint.clone(),
            lease,
        };
        Ok(Producer {
            checkpoint,
            incarnation,
            lease,
        })
    }
    /// Update a derived local selection, not accepted/native meaning. Expected
    /// context gives local CAS; older activations cannot reactivate historical data.
    pub fn select_binding(
        &mut self,
        gate: &AccessGate,
        credential: Option<&Credential>,
        expected: Option<&BindingContext>,
        selected: BindingContext,
    ) -> Result<()> {
        gate.enter_review(credential, selected.scope())?;
        let old = self
            .bindings
            .iter()
            .position(|b| b.scope() == selected.scope() && b.key() == selected.key());
        if old.map(|i| &self.bindings[i]) != expected {
            return Err(Error::Conflict("selection changed"));
        }
        match old {
            Some(i) if self.bindings[i] == selected => return Ok(()),
            Some(i) => {
                if selected.active_generation().get() <= self.bindings[i].active_generation().get() {
                    return Err(Error::Conflict("selection requires a newer activation"));
                }
                self.bindings[i] = selected;
            }
            None => {
                if self.bindings.len() >= self.limit {
                    return Err(Error::Invalid("binding capacity"));
                }
                self.bindings.push(selected);
            }
        }
        self.rebuild_current();
        Ok(())
    }
    pub fn emit(
        &mut self,
        gate: &AccessGate,
        credential: Option<&Credential>,
        producer: &mut Producer,
        pending: PendingObservation,
    ) -> Result<NormalizedObservation> {
        gate.enter_review(credential, &producer.checkpoint.scope)?;
        let index = self
            .producers
            .iter()
            .position(|p| p.checkpoint == producer.checkpoint && p.lease == producer.lease)
            .ok_or(Error::Conflict("stale producer or restored counter"))?;
        if self.records.len() >= self.limit {
            return Err(Error::Invalid("observation capacity; no eviction"));
        }
        let (id, next) = producer.next_id()?;
        let observation = pending.identify(id, producer.incarnation.clone())?;
        // Advance only after construction; replay never advances producer state.
        producer.checkpoint.next = next;
        self.producers[index].checkpoint.next = next;
        self.records.push(Stored {
            freshness: observation.freshness_at_ingestion(),
            observation: observation.clone(),
        });
        self.consider(self.records.len() - 1);
        Ok(observation)
    }
    pub fn reconcile(
        &self,
        gate: &AccessGate,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        observation: &NormalizedObservation,
    ) -> Result<Reconciliation> {
        gate.enter_review(credential, scope)?;
        let old = self
            .records
            .iter()
            .find(|r| r.observation.id().scope() == scope && r.observation.id() == observation.id())
            .ok_or(Error::Conflict("no matching scoped identity"))?;
        if old.observation != *observation {
            return Err(Error::Conflict("same identity, different content"));
        }
        Ok(Reconciliation::SameContent)
    }
    pub fn read(
        &self,
        gate: &AccessGate,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        id: &ObservationId,
    ) -> Result<Option<&NormalizedObservation>> {
        gate.enter_review(credential, scope)?;
        Ok(self
            .records
            .iter()
            .find(|r| r.observation.id().scope() == scope && r.observation.id() == id)
            .map(|r| &r.observation))
    }
    pub fn history(
        &self,
        gate: &AccessGate,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        key: &InstalledId,
    ) -> Result<Vec<&NormalizedObservation>> {
        gate.enter_review(credential, scope)?;
        Ok(self
            .records
            .iter()
            .filter(|r| r.observation.id().scope() == scope && r.observation.binding().key() == key)
            .map(|r| &r.observation)
            .collect())
    }
    pub fn current(
        &mut self,
        gate: &AccessGate,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        key: &InstalledId,
        now: &ClockReading,
    ) -> Result<Option<CurrentValue<'_>>> {
        gate.enter_review(credential, scope)?;
        let Some(current) = self.current.iter().find(|c| &c.scope == scope && &c.key == key) else {
            return Ok(None);
        };
        let stored = &mut self.records[current.record];
        stored.freshness = stored.freshness.retain(stored.observation.assess(now));
        let suitability = match stored.observation.decoded().suitability {
            Suitability::SyntheticValueOnly if stored.freshness != Freshness::Fresh => {
                Suitability::Refused(Refusal::NotFresh)
            }
            suitability => suitability,
        };
        Ok(Some(CurrentValue {
            observation: &stored.observation,
            freshness: stored.freshness,
            suitability,
        }))
    }
    pub fn into_image(self) -> ReceiverImage {
        ReceiverImage(self)
    }
    pub fn reopen(image: ReceiverImage) -> Self {
        let mut receiver = image.0;
        receiver.rebuild_current();
        receiver
    }
    fn rebuild_current(&mut self) {
        self.current.clear();
        for i in 0..self.records.len() {
            self.consider(i);
        }
    }
    fn consider(&mut self, index: usize) {
        let observation = &self.records[index].observation;
        let context = observation.binding();
        if !self.bindings.iter().any(|b| b == context) {
            return;
        }
        let slot = self
            .current
            .iter()
            .position(|c| &c.scope == context.scope() && &c.key == context.key());
        if let Some(slot) = slot {
            let old = &self.records[self.current[slot].record].observation;
            // Neither late arrivals nor an incomparable boot can become current.
            if observation
                .time()
                .receipt_mark
                .elapsed_since(&old.time().receipt_mark)
                .is_err()
                || observation.raw().receipt_time < old.raw().receipt_time
                || matches!((observation.time().times.source(), old.time().times.source()), (Some(new), Some(old)) if new < old)
            {
                return;
            }
            self.current[slot].record = index;
        } else {
            self.current.push(Current {
                scope: context.scope().clone(),
                key: context.key().clone(),
                record: index,
            });
        }
    }
}
