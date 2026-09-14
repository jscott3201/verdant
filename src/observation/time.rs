//! Observation clock evidence. Missing source time has its own state; no receipt
//! or monotonic mark is ever converted into a source timestamp. No Instant codec.
use super::{Error, Result};
use crate::domain::clock::{MonotonicMark, TimeTriple, UnixMillis};
use crate::runtime::ReceiptOrigin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationTimes {
    SourcePresent(TimeTriple),
    SourceAbsent {
        receipt: UnixMillis,
        ingestion: UnixMillis,
    },
    /// Preserve the supplied times when wall-clock order itself is ambiguous.
    WallAmbiguous {
        source: Option<UnixMillis>,
        receipt: UnixMillis,
        ingestion: UnixMillis,
    },
}
impl ObservationTimes {
    pub fn source(&self) -> Option<UnixMillis> {
        match self {
            Self::SourcePresent(triple) => Some(triple.source()),
            Self::SourceAbsent { .. } => None,
            Self::WallAmbiguous { source, .. } => *source,
        }
    }
    pub fn receipt(&self) -> UnixMillis {
        match self {
            Self::SourcePresent(triple) => triple.receipt(),
            Self::SourceAbsent { receipt, .. } | Self::WallAmbiguous { receipt, .. } => *receipt,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Continuity {
    Confirmed,
    WallOrSuspendAmbiguous,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale,
    Unknown,
}
impl Freshness {
    /// Uncertainty or staleness is sticky for an existing record, including replay.
    pub fn retain(self, assessed: Self) -> Self {
        match self {
            Self::Stale => Self::Stale,
            Self::Unknown => Self::Unknown,
            Self::Fresh => assessed,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockReading {
    pub wall: SystemTime,
    pub monotonic: MonotonicMark,
    pub continuity: Continuity,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeEvidence {
    /// Source, when present, comes from the raw envelope, never an estimate.
    pub times: ObservationTimes,
    pub receipt_origin: ReceiptOrigin,
    /// Explicit boot-domain receipt mark supplied alongside the envelope. Never
    /// derived by serializing the raw envelope's process-local Instant.
    pub receipt_mark: MonotonicMark,
    /// Synthetic normalizer ingestion, not sensor/device time or durable commit.
    pub ingestion: ClockReading,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessPolicy {
    max_age: Duration,
    max_wall_skew: Duration,
}
impl FreshnessPolicy {
    /// Explicit fixture policy, not facility values or suspend qualification.
    pub fn new(max_age: Duration, max_wall_skew: Duration) -> Result<Self> {
        if max_age.is_zero() {
            return Err(Error::Invalid("zero freshness horizon"));
        }
        Ok(Self {
            max_age,
            max_wall_skew,
        })
    }
    pub fn assess(self, evidence: &TimeEvidence, now: &ClockReading) -> Freshness {
        if evidence.ingestion.continuity != Continuity::Confirmed
            || now.continuity != Continuity::Confirmed
            || matches!(evidence.times, ObservationTimes::WallAmbiguous { .. })
        {
            return Freshness::Unknown;
        }
        let Ok(elapsed) = now.monotonic.elapsed_since(&evidence.receipt_mark) else {
            return Freshness::Unknown;
        };
        // Reading before ingestion or on another boot cannot refresh a record.
        if now
            .monotonic
            .elapsed_since(&evidence.ingestion.monotonic)
            .is_err()
        {
            return Freshness::Unknown;
        }
        let Ok(wall) = millis(now.wall) else {
            return Freshness::Unknown;
        };
        let Some(wall_age) = wall.as_millis().checked_sub(evidence.times.receipt().as_millis()) else {
            return Freshness::Unknown;
        };
        let Ok(wall_age) = u64::try_from(wall_age) else {
            return Freshness::Unknown;
        };
        let wall_age = Duration::from_millis(wall_age);
        if elapsed.abs_diff(wall_age) > self.max_wall_skew {
            return Freshness::Unknown;
        }
        let source_age = match evidence.times.source() {
            None => Duration::ZERO,
            Some(source) => match wall
                .as_millis()
                .checked_sub(source.as_millis())
                .and_then(|n| u64::try_from(n).ok())
            {
                Some(n) => Duration::from_millis(n),
                None => return Freshness::Unknown,
            },
        };
        if elapsed >= self.max_age || wall_age >= self.max_age || source_age >= self.max_age {
            Freshness::Stale
        } else {
            Freshness::Fresh
        }
    }
}
impl TimeEvidence {
    pub fn new(
        source: Option<SystemTime>,
        receipt: SystemTime,
        receipt_origin: ReceiptOrigin,
        receipt_mark: MonotonicMark,
        ingestion: ClockReading,
    ) -> Result<Self> {
        let source = source.map(millis).transpose()?;
        let receipt = millis(receipt)?;
        let ingested = millis(ingestion.wall)?;
        let times = if source.is_some_and(|s| s > receipt) || receipt > ingested {
            ObservationTimes::WallAmbiguous {
                source,
                receipt,
                ingestion: ingested,
            }
        } else if let Some(source) = source {
            ObservationTimes::SourcePresent(TimeTriple::new(source, receipt, ingested)?)
        } else {
            ObservationTimes::SourceAbsent {
                receipt,
                ingestion: ingested,
            }
        };
        Ok(Self {
            times,
            receipt_origin,
            receipt_mark,
            ingestion,
        })
    }
}
fn millis(time: SystemTime) -> Result<UnixMillis> {
    let value = match time.duration_since(UNIX_EPOCH) {
        Ok(d) => i128::try_from(d.as_millis()).map_err(|_| Error::Invalid("wall time range"))?,
        Err(e) => {
            // Floor pre-epoch fractional milliseconds rather than moving forward.
            let d = e.duration();
            -i128::try_from(d.as_millis()).map_err(|_| Error::Invalid("wall time range"))?
                - i128::from(d.subsec_nanos() % 1_000_000 != 0)
        }
    };
    Ok(UnixMillis::new(
        i64::try_from(value).map_err(|_| Error::Invalid("wall time range"))?,
    ))
}
