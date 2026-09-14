//! Finite acknowledged custody: 8 pins, fixed 35-second fixture lifetime.
//! No renewal. Clock ambiguity refuses read/expiry instead of extending a lease.
use super::{identity::ObservationId, time::ClockReading, window::*};
use crate::{
    domain::ids::InstalledId,
    storage::observation_writer::{self as db, number, put, Pin},
};

pub const PIN_LIMIT: usize = 8;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinToken {
    pub(super) pin: Pin,
    pub(super) id: ObservationId,
}
impl PinToken {
    pub fn id(&self) -> &ObservationId {
        &self.id
    }
    pub fn expires_ms(&self) -> i64 {
        self.pin.expiry_ms
    }
}
pub(super) fn reap(image: &mut db::Image, f: &mut db::Object, now: &ClockReading) -> Result<()> {
    let mut clocks = map(f, "pin_clocks")?;
    let mut keep = Vec::new();
    for pin in &image.pins {
        let origin = dynamic_text(&clocks, &pin.id)?;
        if elapsed(&origin, now)? >= LIFETIME {
            clocks.remove(&pin.id);
        } else {
            keep.push(pin.clone());
        }
    }
    image.pins = keep;
    set_map(f, "pin_clocks", clocks);
    Ok(())
}
impl Window {
    pub fn pin(
        &self,
        access: Access<'_>,
        id: &ObservationId,
        now: &ClockReading,
    ) -> Result<PinToken> {
        let (old, mut f) = self.load(access)?;
        if id.scope() != &self.scope || id.producer() != &self.producer {
            return Err(Error::Refused("scope-or-producer-mismatch"));
        }
        let mut new = old.clone();
        reap(&mut new, &mut f, now)?;
        if new.pins.len() >= PIN_LIMIT {
            return Err(Error::Refused("pin-full"));
        }
        if !new
            .rows
            .iter()
            .any(|r| self.decode(r).is_ok_and(|r| r.id == *id))
        {
            return Err(Error::Refused("pin-data-missing"));
        }
        let admit_seq = number(&f, "revision")?
            .checked_add(1)
            .ok_or(Error::Refused("revision-exhausted"))?;
        let name = InstalledId::parse(&format!("pin-{}-{admit_seq}", self.lease))?;
        let pin = Pin {
            id: name.as_str().into(),
            generation: id.position().generation().as_str().into(),
            seq: id.position().seq(),
            expiry_ms: millis(now)?
                .checked_add(35_000)
                .ok_or(Error::Refused("clock-range"))?,
            admit_seq,
        };
        let mut clocks = map(&f, "pin_clocks")?;
        put(&mut clocks, &pin.id, clock_json(now)?);
        set_map(&mut f, "pin_clocks", clocks);
        new.pins.push(pin.clone());
        Self::advance(&mut new, f)?;
        Self::committed(&self.writer, &self.writer.prepare(&old, &new)?)?;
        Ok(PinToken {
            pin,
            id: id.clone(),
        })
    }
    /// Reads and copies the exact pinned record from one snapshot. Releasing a
    /// pin afterwards cannot invalidate the returned owned materialization.
    pub fn materialize(
        &self,
        access: Access<'_>,
        token: &PinToken,
        now: &ClockReading,
    ) -> Result<Materialized> {
        let (image, f) = self.load(access)?;
        if token.id.scope() != &self.scope || token.id.producer() != &self.producer {
            return Err(Error::Refused("scope-or-producer-mismatch"));
        }
        if !image.pins.contains(&token.pin) {
            return Err(Error::Refused("pin-not-held"));
        }
        let clocks = map(&f, "pin_clocks")?;
        let origin = dynamic_text(&clocks, &token.pin.id)?;
        if elapsed(&origin, now)? >= LIFETIME {
            return Err(Error::Refused("pin-expired"));
        }
        for raw in &image.rows {
            let row = self.decode(raw)?;
            if row.id == token.id {
                return Ok(row);
            }
        }
        Err(Error::Refused("pin-data-missing"))
    }
    pub fn release_pin(&self, access: Access<'_>, token: &PinToken) -> Result<()> {
        let (old, mut f) = self.load(access)?;
        if token.id.scope() != &self.scope
            || token.id.producer() != &self.producer
            || !old.pins.contains(&token.pin)
        {
            return Err(Error::Refused("pin-not-held"));
        }
        let mut new = old.clone();
        new.pins.retain(|p| p != &token.pin);
        let mut clocks = map(&f, "pin_clocks")?;
        clocks.remove(&token.pin.id);
        set_map(&mut f, "pin_clocks", clocks);
        Self::advance(&mut new, f)?;
        Self::committed(&self.writer, &self.writer.prepare(&old, &new)?)
    }
}
fn dynamic_text(f: &db::Object, key: &str) -> Result<String> {
    match f.get(key) {
        Some(db::JsonVal::Str(s)) => Ok(s.clone()),
        _ => Err(db::invalid("pin clock").into()),
    }
}
