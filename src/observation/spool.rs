//! Finite append, explicit refusal and exact ticket reconciliation. No workers.
use super::{window::*, NormalizedObservation};
use crate::storage::{
    observation_writer::{self as db, encode, number, object, put, text, JsonVal, Ticket},
    sqlite::MutationOutcome,
};

#[derive(Debug, Clone)]
pub struct Capture {
    pub(super) ticket: Ticket,
    origin: String,
}
impl Capture {
    pub fn reconciliation_bytes(&self) -> &str {
        self.ticket.reconciliation_bytes()
    }
}
impl Window {
    /// Takes the canonical PR03A type directly. No shadow storage module/type,
    /// no hash-of-value deduplication, and no counter advance before commit.
    pub fn prepare_capture(
        &self,
        access: Access<'_>,
        observation: &NormalizedObservation,
        class: Retention,
        now: &super::time::ClockReading,
    ) -> Result<Capture> {
        let (old, mut f) = self.load(access)?;
        let origin = clock_json(now)?;
        if observation.id().scope() != &self.scope
            || observation.id().producer() != &self.producer
            || observation.incarnation() != &self.incarnation
            || observation.id().position().generation().as_str() != text(&f, "generation")?
            || observation.id().position().seq() != number(&f, "next")?
        {
            return Err(Error::Refused("identity-conflict"));
        }
        let payload = self.project(observation, class)?;
        let mut optional_count = 0;
        let mut optional_bytes: usize = 0;
        let mut total_bytes: usize = 0;
        for raw in &old.rows {
            total_bytes += raw.len();
            if text(&object(raw)?, "retention")? == "optional" {
                optional_count += 1;
                optional_bytes += raw.len();
            }
        }
        if old.rows.len() >= SPOOL_SLOTS || total_bytes.saturating_add(payload.len()) > SPOOL_BYTES
        {
            return Err(Error::Refused("spool-full-escalate"));
        }
        if class == Retention::OptionalHistory
            && (optional_count >= SPOOL_SLOTS - RESERVE_SLOTS
                || optional_bytes.saturating_add(payload.len()) > SPOOL_BYTES - RESERVE_BYTES)
        {
            return Err(Error::Refused("mandatory-reserve"));
        }
        let mut current = map(&f, "current")?;
        let key = observation.binding().key().as_str();
        let selected = map(&f, "selected")?;
        if selected.get(key) == Some(&JsonVal::Str(format!("{:?}", observation.binding()))) {
            let mut newer = true;
            if let Some(JsonVal::Str(seq)) = current.get(key) {
                let seq: u64 = seq.parse().map_err(|_| db::invalid("current sequence"))?;
                let previous = old
                    .rows
                    .iter()
                    .find(|raw| object(raw).and_then(|f| number(&f, "seq")).ok() == Some(seq))
                    .ok_or(Error::Refused("current-reference-missing"))?;
                let previous = self.decode(previous)?;
                newer = observation
                    .time()
                    .receipt_mark
                    .elapsed_since(&previous.receipt_mark)
                    .is_ok()
                    && observation.time().times.receipt().as_millis() >= previous.receipt_ms
                    && !matches!((observation.time().times.source(),previous.source_ms),(Some(n),Some(o)) if n.as_millis()<o);
            }
            if newer {
                put(&mut current, key, observation.id().position().seq());
            }
        }
        set_map(&mut f, "current", current);
        let next = number(&f, "next")?
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Error::Refused("sequence-exhausted"))?;
        put(&mut f, "next", next);
        let mut new = old.clone();
        new.rows.push(payload);
        Self::advance(&mut new, f)?;
        Ok(Capture {
            ticket: self.writer.prepare(&old, &new)?,
            origin,
        })
    }
    /// Expired/ambiguous authority cannot dispatch, even if its receipt was
    /// pruned while the caller still held a valid-looking ticket. CAS/epoch also
    /// survives the replay horizon. Capture errors never mean captured.
    pub fn submit_capture(
        &self,
        access: Access<'_>,
        capture: &Capture,
        now: &super::time::ClockReading,
    ) -> Result<MutationOutcome> {
        self.load(access)?;
        if elapsed(&capture.origin, now)? >= LIFETIME {
            return Err(Error::Refused("capture-expired"));
        }
        Ok(self.writer.submit(&capture.ticket))
    }
    /// Read-only: callers keep the SAME Capture across interruptions. Never
    /// transform receipt absence into a new observation or a new attempt ID.
    pub fn reconcile_capture(
        &self,
        access: Access<'_>,
        capture: &Capture,
    ) -> Result<MutationOutcome> {
        self.load(access)?;
        Ok(self.writer.reconcile(&capture.ticket))
    }
    pub fn reconcile_saved_capture(
        &self,
        access: Access<'_>,
        saved: &str,
    ) -> Result<MutationOutcome> {
        self.load(access)?;
        Ok(self.writer.reconcile_saved(saved)?)
    }
    pub fn reconcile_observation(
        &self,
        access: Access<'_>,
        observation: &NormalizedObservation,
    ) -> Result<()> {
        let row = self
            .read(access, observation.id())?
            .ok_or(Error::Refused("identity-outside-retention"))?;
        if row.raw_evidence != format!("{observation:?}") {
            return Err(Error::Refused("identity-conflict"));
        }
        Ok(())
    }
    /// Mandatory records are not optional history. Only this explicit local
    /// acknowledgment permits later eviction; it is NOT physical/hub delivery.
    pub fn settle(&self, access: Access<'_>, id: &super::identity::ObservationId) -> Result<()> {
        let (old, f) = self.load(access)?;
        if id.scope() != &self.scope || id.producer() != &self.producer {
            return Err(Error::Refused("scope-or-producer-mismatch"));
        }
        let mut new = old.clone();
        let mut found = false;
        for raw in &mut new.rows {
            if self.decode(raw)?.id == *id {
                let mut fields = object(raw)?;
                put(&mut fields, "settled", "true");
                *raw = encode(fields);
                found = true;
            }
        }
        if !found {
            return Err(Error::Refused("identity-outside-retention"));
        }
        Self::advance(&mut new, f)?;
        Self::committed(&self.writer, &self.writer.prepare(&old, &new)?)
    }
}
