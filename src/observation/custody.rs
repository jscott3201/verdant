//! Explicit bounded eviction and recoverable lag/gap pages. Latest-value
//! selection does not preserve every transition; mandatory unresolved records
//! and acknowledged pins are never cleanup candidates.
use super::{pins, time::ClockReading, window::*};
use crate::storage::observation_writer::{self as db, number, object, text, Gap, JsonVal};

pub const EVICT_ROWS: usize = 8;
pub const EVICT_BYTES: usize = 512 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub records: Vec<Materialized>,
    pub gaps: Vec<Gap>,
    pub next: u64,
    pub more: bool,
}

fn add_gap(gaps: &mut Vec<Gap>, seq: u64) -> Result<()> {
    gaps.push(Gap {
        from: seq,
        to: seq,
        reason: "window-evicted".into(),
    });
    gaps.sort_by_key(|g| g.from);
    let mut merged: Vec<Gap> = Vec::new();
    for gap in gaps.iter() {
        if let Some(last) = merged.last_mut() {
            if last.reason == gap.reason && last.to.checked_add(1) == Some(gap.from) {
                last.to = gap.to;
                continue;
            }
        }
        merged.push(gap.clone());
    }
    if merged.len() > 64 {
        return Err(Error::Refused("gap-ledger-full-escalate"));
    }
    *gaps = merged;
    Ok(())
}
impl Window {
    pub fn evict(&self, access: Access<'_>, now: &ClockReading) -> Result<usize> {
        let (old, mut f) = self.load(access)?;
        let mut new = old.clone();
        pins::reap(&mut new, &mut f, now)?;
        let current = map(&f, "current")?
            .values()
            .map(|v| match v {
                JsonVal::Str(s) => s.parse().map_err(|_| db::invalid("current seq")),
                _ => Err(db::invalid("current seq")),
            })
            .collect::<std::result::Result<Vec<u64>, _>>()?;
        let mut rows = old
            .rows
            .iter()
            .map(|raw| Ok((number(&object(raw)?, "seq")?, raw)))
            .collect::<Result<Vec<_>>>()?;
        rows.sort_by_key(|r| r.0);
        let keep_from = rows.len().saturating_sub(WINDOW_SLOTS);
        let mut removed = 0;
        let mut bytes = 0;
        for (seq, raw) in rows.iter().take(keep_from) {
            let fields = object(raw)?;
            let mandatory =
                text(&fields, "retention")? == "mandatory" && text(&fields, "settled")? != "true";
            if mandatory || current.contains(seq) || new.pins.iter().any(|p| p.seq == *seq) {
                continue;
            }
            if removed == EVICT_ROWS || bytes + raw.len() > EVICT_BYTES {
                break;
            }
            add_gap(&mut new.gaps, *seq)?;
            new.rows.retain(|r| r != *raw);
            removed += 1;
            bytes += raw.len();
        }
        if new == old {
            return Ok(0);
        }
        Self::advance(&mut new, f)?;
        Self::committed(&self.writer, &self.writer.prepare(&old, &new)?)?;
        Ok(removed)
    }
    /// At most 64 positions per page, plus clipped tombstones. No missing row
    /// below the durable tail is silently treated as an empty successful page.
    pub fn replay(&self, access: Access<'_>, from: u64, limit: u64) -> Result<Page> {
        if limit == 0 {
            return Err(Error::Refused("replay-limit"));
        }
        let (image, f) = self.load(access)?;
        let tail = number(&f, "next")?;
        if from > tail {
            return Err(Error::Refused("replay-position"));
        }
        let next = from.saturating_add(limit.min(db::REPLAY_ROWS)).min(tail);
        let mut records = Vec::new();
        for raw in &image.rows {
            let row = self.decode(raw)?;
            if (from..next).contains(&row.id.position().seq()) {
                records.push(row);
            }
        }
        records.sort_by_key(|r| r.id.position().seq());
        let gaps = image
            .gaps
            .into_iter()
            .filter_map(|g| {
                if g.from >= next || g.to < from {
                    None
                } else {
                    Some(Gap {
                        from: g.from.max(from),
                        to: g.to.min(next - 1),
                        reason: g.reason,
                    })
                }
            })
            .collect::<Vec<_>>();
        for seq in from..next {
            if !records.iter().any(|r| r.id.position().seq() == seq)
                && !gaps.iter().any(|g| (g.from..=g.to).contains(&seq))
            {
                return Err(Error::Refused("unaccounted-history-gap"));
            }
        }
        Ok(Page {
            records,
            gaps,
            next,
            more: next < tail,
        })
    }
}
