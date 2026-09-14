//! Synthetic-only finite observation service, not a CLI activation or historian.
//! The materialized contract is a typed value plus an exact same-build PR03A
//! evidence witness. The witness is opaque (not a portable NormalizedObservation
//! decoder); M03 byte-fit and a cross-build raw-envelope codec remain unqualified.
//! Reopening evidence never gives it fresh dependent-use authority.
use super::{
    identity::{ObservationId, ProducerId, ProducerIncarnation},
    time::{ClockReading, Continuity, Freshness},
    BindingContext, NormalizedObservation, PendingObservation,
};
use crate::{
    access::{AccessGate, Credential},
    domain::{
        clock::MonotonicMark,
        ids::{InstalledId, SourceGenerationId},
        outcomes::RecordIdentity,
        scope::TrustedScope,
        values::{Unit, Value},
    },
    storage::{
        observation_writer as db,
        sqlite::{MutationOutcome, SqliteStore},
        StorageError,
    },
};
use db::{encode, number, object, put, signed, text, Image, JsonVal, Object, Ticket, Writer};
use std::time::{Duration, UNIX_EPOCH};

pub const WINDOW_SLOTS: usize = 2; // All budgets here are owner-approved E02 fixtures.
pub const SPOOL_SLOTS: usize = 32;
pub const SPOOL_BYTES: usize = 2 * 1024 * 1024;
pub const RESERVE_SLOTS: usize = 4;
pub const RESERVE_BYTES: usize = 256 * 1024;
pub const LIFETIME: Duration = Duration::from_secs(35);

#[derive(Debug)]
pub enum Error {
    Storage(StorageError),
    Observation(super::Error),
    Refused(&'static str),
    Unknown { ticket: Ticket, detail: String },
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Storage(e) => e.code(),
            Self::Observation(e) => e.code(),
            Self::Refused(code) => code,
            Self::Unknown { .. } => "unknown",
        }
    }
}
impl From<StorageError> for Error {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Observation(e)
    }
}
impl From<crate::domain::Error> for Error {
    fn from(e: crate::domain::Error) -> Self {
        Self::Observation(e.into())
    }
}

/// Explicit managed-recovery input. None/ambiguous never guesses continuity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub generation: SourceGenerationId,
    pub next: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    OptionalHistory,
    Mandatory,
}
impl Retention {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::OptionalHistory => "optional",
            Self::Mandatory => "mandatory",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Materialized {
    pub id: ObservationId,
    pub value: Value,
    pub unit: Unit,
    pub source_ms: Option<i64>,
    pub receipt_ms: i64,
    pub ingestion_ms: i64,
    pub receipt_mark: MonotonicMark,
    pub raw_evidence: String,
    pub freshness: Freshness,
    pub(super) fields: Object,
}
impl Materialized {
    pub fn dependent_value(&self) -> Result<&Value> {
        Err(Error::Refused("replayed-evidence-not-fresh"))
    }
    pub(super) fn decode(scope: &TrustedScope, producer: &ProducerId, raw: &str) -> Result<Self> {
        let f = object(raw)?;
        if text(&f, "format")? != "obw-synthetic-v1" {
            return Err(Error::Refused("observation-format"));
        }
        let source_ms = match f.get("source") {
            Some(JsonVal::Null) => None,
            Some(JsonVal::Str(s)) => Some(s.parse().map_err(|_| db::invalid("source"))?),
            _ => return Err(db::invalid("source").into()),
        };
        let id = ObservationId::new(
            scope.clone(),
            producer.clone(),
            RecordIdentity::new(
                SourceGenerationId::parse(&text(&f, "generation")?)?,
                number(&f, "seq")?,
            ),
        );
        Ok(Self {
            id,
            value: Value::from_json(&text(&f, "value")?)?,
            unit: Unit::parse(&text(&f, "unit")?)?,
            source_ms,
            receipt_ms: signed(&f, "receipt")?,
            ingestion_ms: signed(&f, "ingestion")?,
            receipt_mark: MonotonicMark::from_json(&text(&f, "mark")?)?,
            raw_evidence: text(&f, "witness")?,
            freshness: Freshness::Unknown,
            fields: f,
        })
    }
}

/// Access is checked for every operation; this is synthetic review authority,
/// not genuine operator provisioning, physical control or observed qualification.
#[derive(Clone, Copy)]
pub struct Access<'a> {
    pub gate: &'a AccessGate,
    pub credential: Option<&'a Credential>,
}
pub struct Window {
    pub(super) writer: Writer,
    pub(super) scope: TrustedScope,
    pub(super) producer: ProducerId,
    pub(super) incarnation: ProducerIncarnation,
    pub(super) lease: u64,
}
pub(super) fn map(f: &Object, key: &'static str) -> Result<Object> {
    match f.get(key) {
        Some(JsonVal::Object(m)) => Ok(m.clone()),
        _ => Err(db::invalid(key).into()),
    }
}
pub(super) fn set_map(f: &mut Object, key: &str, m: Object) {
    f.insert(key.into(), JsonVal::Object(m));
}
pub(super) fn millis(now: &ClockReading) -> Result<i64> {
    i64::try_from(
        now.wall
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Refused("clock-ambiguous"))?
            .as_millis(),
    )
    .map_err(|_| Error::Refused("clock-range"))
}
pub(super) fn clock_json(now: &ClockReading) -> Result<String> {
    if now.continuity != Continuity::Confirmed {
        return Err(Error::Refused("clock-ambiguous"));
    }
    let mut f = Object::new();
    put(&mut f, "wall", millis(now)?);
    put(&mut f, "mark", now.monotonic.to_json());
    Ok(encode(f))
}
pub(super) fn elapsed(origin: &str, now: &ClockReading) -> Result<Duration> {
    if now.continuity != Continuity::Confirmed {
        return Err(Error::Refused("clock-ambiguous"));
    }
    let f = object(origin)?;
    let mark = MonotonicMark::from_json(&text(&f, "mark")?)?;
    let duration = now
        .monotonic
        .elapsed_since(&mark)
        .map_err(|_| Error::Refused("clock-ambiguous"))?;
    let wall = millis(now)?
        .checked_sub(signed(&f, "wall")?)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(Error::Refused("clock-ambiguous"))?;
    // Allow only timestamp flooring error, not an invented suspend tolerance.
    if duration.abs_diff(Duration::from_millis(wall)) > Duration::from_millis(1) {
        return Err(Error::Refused("clock-ambiguous"));
    }
    Ok(duration)
}

impl Window {
    pub fn open_synthetic(
        store: SqliteStore,
        access: Access<'_>,
        scope: TrustedScope,
        producer: ProducerId,
        incarnation: ProducerIncarnation,
        intact: Option<&Checkpoint>,
    ) -> Result<Self> {
        access
            .gate
            .enter_review(access.credential, &scope)
            .map_err(super::Error::from)?;
        let writer = Writer(store);
        let old = writer.load()?;
        let mut new = old.clone();
        let mut f = match &old.state {
            Some(raw) => {
                let f = object(raw)?;
                if text(&f, "scope")? != scope.as_str()
                    || text(&f, "producer")? != producer.as_str()
                {
                    return Err(Error::Refused("scope-or-producer-mismatch"));
                }
                f
            }
            None => {
                let mut f = Object::new();
                put(&mut f, "scope", scope.as_str());
                put(&mut f, "producer", producer.as_str());
                for k in ["revision", "epoch", "next"] {
                    put(&mut f, k, 0);
                }
                for k in ["selected", "activations", "current", "pin_clocks"] {
                    set_map(&mut f, k, Object::new());
                }
                f
            }
        };
        let lease = number(&f, "epoch")?
            .checked_add(1)
            .ok_or(Error::Refused("generation-exhausted"))?;
        let proven = if let Some(checkpoint) = intact {
            old.state.is_some()
                && text(&f, "generation")? == checkpoint.generation.as_str()
                && number(&f, "next")? == checkpoint.next
        } else {
            false
        };
        if !proven {
            let generation =
                SourceGenerationId::parse(&format!("obw:{}:{lease}", writer.identity()?))?;
            put(&mut f, "generation", generation.as_str());
        }
        put(&mut f, "epoch", lease);
        Self::advance(&mut new, f)?;
        let ticket = writer.prepare(&old, &new)?;
        Self::committed(&writer, &ticket)?;
        Ok(Self {
            writer,
            scope,
            producer,
            incarnation,
            lease,
        })
    }
    pub(super) fn load(&self, access: Access<'_>) -> Result<(Image, Object)> {
        access
            .gate
            .enter_review(access.credential, &self.scope)
            .map_err(super::Error::from)?;
        let image = self.writer.load()?;
        let f = object(
            image
                .state
                .as_deref()
                .ok_or(Error::Refused("continuity-missing"))?,
        )?;
        if text(&f, "scope")? != self.scope.as_str()
            || text(&f, "producer")? != self.producer.as_str()
            || number(&f, "epoch")? != self.lease
        {
            return Err(Error::Refused("stale-owner"));
        }
        Ok((image, f))
    }
    pub(super) fn advance(image: &mut Image, mut f: Object) -> Result<()> {
        let next = number(&f, "revision")?
            .checked_add(1)
            .ok_or(Error::Refused("revision-exhausted"))?;
        put(&mut f, "revision", next);
        image.state = Some(encode(f));
        Ok(())
    }
    pub(super) fn committed(writer: &Writer, ticket: &Ticket) -> Result<()> {
        match writer.submit(ticket) {
            MutationOutcome::Committed { .. } => Ok(()),
            MutationOutcome::NotCommitted { error, .. } => Err(error.into()),
            MutationOutcome::Conflict { .. } => Err(Error::Refused("conflict")),
            MutationOutcome::Unknown { detail, .. } => Err(Error::Unknown {
                ticket: ticket.clone(),
                detail,
            }),
        }
    }
    pub fn checkpoint(&self, access: Access<'_>) -> Result<Checkpoint> {
        let (_, f) = self.load(access)?;
        Ok(Checkpoint {
            generation: SourceGenerationId::parse(&text(&f, "generation")?)?,
            next: number(&f, "next")?,
        })
    }
    /// Identity attachment is not a successful capture. The sequence advances
    /// only with the durable append; competing/stale attachments cannot overwrite.
    pub fn identify(
        &self,
        access: Access<'_>,
        pending: PendingObservation,
    ) -> Result<NormalizedObservation> {
        let checkpoint = self.checkpoint(access)?;
        Ok(pending.identify(
            ObservationId::new(
                self.scope.clone(),
                self.producer.clone(),
                RecordIdentity::new(checkpoint.generation, checkpoint.next),
            ),
            self.incarnation.clone(),
        )?)
    }
    pub fn select_binding(&self, access: Access<'_>, binding: &BindingContext) -> Result<()> {
        let (old, mut f) = self.load(access)?;
        if binding.scope() != &self.scope {
            return Err(Error::Refused("scope-mismatch"));
        }
        let key = binding.key().as_str();
        let mut selected = map(&f, "selected")?;
        let signature = format!("{binding:?}");
        if selected.get(key) == Some(&JsonVal::Str(signature.clone())) {
            return Ok(());
        }
        let mut activations = map(&f, "activations")?;
        if let Some(JsonVal::Str(old)) = activations.get(key) {
            if binding.active_generation().get() as u64
                <= old.parse().map_err(|_| db::invalid("activation"))?
            {
                return Err(Error::Refused("old-binding-selection"));
            }
        } else if selected.len() >= WINDOW_SLOTS {
            return Err(Error::Refused("window-full"));
        }
        put(&mut selected, key, signature);
        put(&mut activations, key, binding.active_generation().get());
        let mut current = map(&f, "current")?;
        current.remove(key);
        set_map(&mut f, "selected", selected);
        set_map(&mut f, "activations", activations);
        set_map(&mut f, "current", current);
        let mut new = old.clone();
        Self::advance(&mut new, f)?;
        Self::committed(&self.writer, &self.writer.prepare(&old, &new)?)
    }
    pub(super) fn decode(&self, raw: &str) -> Result<Materialized> {
        Materialized::decode(&self.scope, &self.producer, raw)
    }
    pub fn read(&self, access: Access<'_>, id: &ObservationId) -> Result<Option<Materialized>> {
        let (image, _) = self.load(access)?;
        if id.scope() != &self.scope || id.producer() != &self.producer {
            return Err(Error::Refused("scope-or-producer-mismatch"));
        }
        for raw in &image.rows {
            let row = self.decode(raw)?;
            if &row.id == id {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }
    pub fn current(&self, access: Access<'_>, key: &InstalledId) -> Result<Option<Materialized>> {
        let (image, f) = self.load(access)?;
        let current = map(&f, "current")?;
        let Some(JsonVal::Str(seq)) = current.get(key.as_str()) else {
            return Ok(None);
        };
        for raw in &image.rows {
            let row = self.decode(raw)?;
            if row.id.position().seq().to_string() == *seq {
                return Ok(Some(row));
            }
        }
        Err(Error::Refused("current-reference-missing"))
    }
    pub(super) fn project(
        &self,
        observation: &NormalizedObservation,
        class: Retention,
    ) -> Result<String> {
        let mut f = Object::new();
        put(&mut f, "format", "obw-synthetic-v1");
        put(&mut f, "seq", observation.id().position().seq());
        put(
            &mut f,
            "generation",
            observation.id().position().generation().as_str(),
        );
        put(&mut f, "key", observation.binding().key().as_str());
        put(&mut f, "binding", format!("{:?}", observation.binding()));
        put(&mut f, "value", observation.decoded().value.to_json());
        put(&mut f, "unit", observation.decoded().unit.as_str());
        put(
            &mut f,
            "receipt",
            observation.time().times.receipt().as_millis(),
        );
        put(&mut f, "ingestion", millis(&observation.time().ingestion)?);
        f.insert(
            "source".into(),
            observation
                .time()
                .times
                .source()
                .map(|s| JsonVal::Str(s.as_millis().to_string()))
                .unwrap_or(JsonVal::Null),
        );
        put(&mut f, "mark", observation.time().receipt_mark.to_json());
        put(
            &mut f,
            "incarnation",
            format!("{:?}", observation.incarnation()),
        );
        put(
            &mut f,
            "suitability",
            match observation.decoded().suitability {
                super::normalize::Suitability::SyntheticValueOnly => "synthetic-value-only",
                super::normalize::Suitability::Refused(_) => "refused",
            },
        );
        // Full same-build witness retains batch errors, exact source/wall times,
        // quality, codec/unit provenance and freshness policy. Never parsed as
        // authority or silently replaced by the normalized value.
        put(&mut f, "witness", format!("{observation:?}"));
        put(&mut f, "retention", class.label());
        put(&mut f, "settled", "false");
        Ok(encode(f))
    }
}
