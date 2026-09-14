//! Advertisements remain candidates. This table cannot produce a BindingPlan.
use super::{DirectTarget, Error, Result};
use crate::runtime::admission::{Budget, Reservation, WorkClass};
use bacnet_services::who_is::IAmRequest;
use bacnet_types::enums::ObjectType;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub const CANDIDATE_TTL: Duration = Duration::from_secs(30);
pub const MAX_CANDIDATES: usize = 16;
pub const MAX_CONFLICTS: usize = 4;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    pub target: DirectTarget,
    pub instance: u32,
    pub max_apdu: u32,
    pub segmentation: u8,
    pub vendor: u16,
}
impl Advertisement {
    pub(super) fn decode(target: DirectTarget, bytes: &[u8]) -> Result<Self> {
        let iam = IAmRequest::decode(bytes).map_err(|_| Error::InvalidReply)?;
        if iam.object_identifier.object_type() != ObjectType::DEVICE {
            return Err(Error::InvalidReply);
        }
        Ok(Self {
            target,
            instance: iam.object_identifier.instance_number(),
            max_apdu: iam.max_apdu_length,
            segmentation: iam.segmentation_supported.to_raw(),
            vendor: iam.vendor_id,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub advertisements: Vec<Advertisement>,
    pub last_receipt: Instant,
    pub expired: bool,
}
impl Candidate {
    pub fn conflicted(&self) -> bool {
        self.advertisements.len() > 1
    }
}
struct HeldCandidate {
    candidate: Candidate,
    _reservation: Arc<Reservation>,
}
pub(super) struct Quarantine {
    budget: Arc<Budget>,
    entries: Vec<HeldCandidate>,
}
impl Quarantine {
    pub fn new(budget: Arc<Budget>) -> Self {
        Self { budget, entries: Vec::new() }
    }
    pub fn observe(&mut self, advertisement: Advertisement, now: Instant) -> Result<()> {
        if let Some(entry) = self.entries.iter_mut().find(|entry| {
            let prior = &entry.candidate.advertisements[0];
            prior.instance == advertisement.instance && prior.target.realm() == advertisement.target.realm()
        }) {
            if !entry.candidate.advertisements.contains(&advertisement) {
                if entry.candidate.advertisements.len() == MAX_CONFLICTS {
                    return Err(Error::QuarantineFull);
                }
                entry.candidate.advertisements.push(advertisement);
            }
            entry.candidate.last_receipt = now;
            entry.candidate.expired = false;
            return Ok(());
        }
        if self.entries.len() == MAX_CANDIDATES {
            return Err(Error::QuarantineFull);
        }
        let reservation =
            self.budget.reserve(WorkClass::OptionalDiscovery, false).map_err(|_| Error::Budget)?;
        self.entries.push(HeldCandidate {
            candidate: Candidate { advertisements: vec![advertisement], last_receipt: now, expired: false },
            _reservation: reservation,
        });
        Ok(())
    }
    pub fn snapshot(&mut self, now: Instant) -> Vec<Candidate> {
        for entry in &mut self.entries {
            entry.candidate.expired =
                now.saturating_duration_since(entry.candidate.last_receipt) >= CANDIDATE_TTL;
        }
        self.entries.iter().map(|entry| entry.candidate.clone()).collect()
    }
    /// Explicit discard only; an expired conflict is still inspectable until this call.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}
