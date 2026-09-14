//! Explicit phase: first poll after one period. A missed interval is recorded,
//! never replayed as a burst. This is scheduling arithmetic, not observed samples.
use super::{Error, Result};
use std::time::{Duration, Instant};

pub struct PollSchedule {
    period: Duration,
    next: Instant,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Due {
    pub missed: u64,
}
impl PollSchedule {
    pub fn new(start: Instant, period: Duration) -> Result<Self> {
        if period < Duration::from_millis(100) || period > Duration::from_secs(30) {
            return Err(Error::Invalid("fixture poll period outside 100..30000 ms"));
        }
        let next = start.checked_add(period).ok_or(Error::Invalid("poll horizon"))?;
        Ok(Self { period, next })
    }
    pub fn due(&mut self, now: Instant) -> Result<Option<Due>> {
        if now < self.next {
            return Ok(None);
        }
        let missed = u64::try_from(now.duration_since(self.next).as_nanos() / self.period.as_nanos())
            .map_err(|_| Error::Invalid("missed poll overflow"))?;
        // Delay from actual scheduling, not catch-up on the old phase.
        self.next = now.checked_add(self.period).ok_or(Error::Invalid("poll horizon"))?;
        Ok(Some(Due { missed }))
    }
}
