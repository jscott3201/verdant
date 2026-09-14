//! E02 local fixture assumptions, NOT measured facility or host capacity.
//!
//! One family covers startup, SQLite/hash/native verification, acquisition and
//! retained results. Partitioned capacity cannot be borrowed from mandatory work.
//! A reservation survives cancellation and is held until the actual job is joined
//! (or its explicitly unresolved owner is dropped after the worker exits).
use super::{Error, Result};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

/// No subscription/writer admission exists in PR01A. Reconciliation is inert too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkClass {
    CurrentSensing,
    Reconciliation,
    OptionalDiscovery,
}
impl WorkClass {
    fn index(self) -> usize {
        match self {
            Self::CurrentSensing => 0,
            Self::Reconciliation => 1,
            Self::OptionalDiscovery => 2,
        }
    }
}

/// Conservative derivation: queue <= tiny.max_tasks/MAX_PAGE (64); total active
/// 4 <= native.local.max_inflight (8) and tiny.max_running_operations (16).
/// Two slots EACH for current sensing and reconciliation are never optional.
/// At most 64 retained envelopes * tiny.max_value_bytes (65536) = 4 MiB.
/// Every running verification is sequential inside one slot, even though the
/// supported access and binding openers create separate SQLite handle families.
pub const QUEUE_SLOTS: [usize; 3] = [2, 2, 60];
pub const RUNNING_SLOTS: [usize; 3] = [1, 1, 2];
pub const MAX_ENVELOPE_BYTES: usize = 65_536;
pub const MAX_RETAINED_BYTES: usize = 64 * MAX_ENVELOPE_BYTES;
pub const MAX_LIFETIME: Duration = Duration::from_millis(35_000);
pub const MAX_DRAIN: Duration = Duration::from_millis(35_000);
// PR01B extends THIS runtime family, not an independent acquisition semaphore.
// One configured fake peer: 8 scripts x 4 replies x 1024 bytes = 32768 bytes;
// 8 captured requests x 1024 = 8192 bytes. Up to 4 active slots x 4 replies x
// 1024 = 16384 bytes in transit. Total scripted/captured/in-flight payload bound
// is 57344 bytes, separate from the 4 MiB envelope reservation. This is NOT an
// allocator/RSS limit (upstream fixed queues and executor overhead are excluded).
// Each quarantined device consumes one of the SAME 60 optional retained slots;
// max 16 candidates x 4 inspectable advertisements, with explicit discard.
pub const BACNET_FAKE_PAYLOAD_BYTES: usize = 57_344;
// No durable observation spool/pins in this slice: zero admitted bytes/pins.
// Existing seal custody stays seal-owned (32 live, 256 history, 64 nodes,
// depth 16, 262144 closure bytes, 8 native refs, 2097152 bytes/artifact).
// Native maintenance keeps 1048576 native + 1048576 future-journal bytes;
// these are synthetic planning reserves, not allocated disk or a live WAL cap.

#[derive(Default)]
pub(super) struct Budget {
    queued: [AtomicUsize; 3],
    running: [AtomicUsize; 3],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub retained: [usize; 3],
    pub running: [usize; 3],
}
impl Budget {
    pub fn can_run(&self, class: WorkClass) -> bool {
        self.running[class.index()].load(Ordering::SeqCst) < RUNNING_SLOTS[class.index()]
    }
    pub fn reserve(self: &Arc<Self>, class: WorkClass, running: bool) -> Result<Arc<Reservation>> {
        let index = class.index();
        let (counts, bounds) = if running { (&self.running, RUNNING_SLOTS) } else { (&self.queued, QUEUE_SLOTS) };
        counts[index]
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| (used < bounds[index]).then_some(used + 1))
            .map_err(|_| Error::Saturated { class, running })?;
        Ok(Arc::new(Reservation { family: self.clone(), index, running }))
    }
    pub fn usage(&self) -> Usage {
        Usage {
            retained: std::array::from_fn(|i| self.queued[i].load(Ordering::SeqCst)),
            running: std::array::from_fn(|i| self.running[i].load(Ordering::SeqCst)),
        }
    }
}
pub(super) struct Reservation {
    family: Arc<Budget>,
    index: usize,
    running: bool,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let counts = if self.running { &self.family.running } else { &self.family.queued };
        counts[self.index].fetch_sub(1, Ordering::SeqCst);
    }
}
