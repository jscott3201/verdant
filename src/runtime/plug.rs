//! Closed PR01A plug: the default remains inert; the only second variant has a
//! private socket-free transport. No generic transport/client injection seam.
use super::{bacnet, inert, owners::Selection, task::Cancellation, *};

#[derive(Clone)]
pub(super) enum Adapter {
    Inert(inert::InertAdapter),
    FakeBacnet(bacnet::Adapter),
}
pub(super) struct Context<'a> {
    pub selected: &'a Selection,
    pub key: &'a str,
    pub work: WorkId,
    pub incarnation: RuntimeIncarnation,
    pub source: SourceGeneration,
}
impl Default for Adapter {
    fn default() -> Self {
        Self::Inert(inert::InertAdapter::default())
    }
}
impl Adapter {
    pub fn admit(
        &self,
        selected: &Selection,
        key: &str,
        class: WorkClass,
    ) -> Result<Option<bacnet::BindingPlan>> {
        match self {
            Self::Inert(_) => Ok(None),
            Self::FakeBacnet(adapter) => Ok(Some(adapter.admit(selected, key, class)?)),
        }
    }
    pub fn read(
        &self,
        context: Context<'_>,
        admitted: Option<bacnet::BindingPlan>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<RawEnvelope> {
        match (self, admitted) {
            (Self::Inert(adapter), None) => {
                adapter.read(context.selected, context.key, context.work, context.incarnation, context.source)
            }
            (Self::FakeBacnet(adapter), Some(plan)) => adapter.read(context, plan, cancel, deadline),
            (Self::Inert(_), Some(_)) | (Self::FakeBacnet(_), None) => {
                Err(Error::Invalid("adapter admission mismatch"))
            }
        }
    }
    pub fn retain_candidates(&self, raw: &RawEnvelope) -> Result<()> {
        match self {
            Self::Inert(_) => Ok(()),
            Self::FakeBacnet(adapter) => Ok(adapter.retain_candidates(raw)?),
        }
    }
    pub fn calls(&self) -> u64 {
        match self {
            Self::Inert(adapter) => adapter.calls(),
            Self::FakeBacnet(_) => 0,
        }
    }
}
impl Runtime {
    /// Explicit socket-free fixture selection before start. No default/CLI caller
    /// configures this. It cannot replace an adapter with queued/surviving work.
    pub fn configure_fake_bacnet(
        &mut self,
        profile: bacnet::Profile,
        peer: bacnet::fake::ScriptedPeer,
    ) -> Result<()> {
        if self.state != State::Stopped
            || !self.running.is_empty()
            || !self.queue.is_empty()
            || !self.completed.is_empty()
        {
            return Err(Error::NotStopped);
        }
        self.adapter = Adapter::FakeBacnet(bacnet::Adapter::new(profile, peer, self.budget.clone())?);
        Ok(())
    }
    pub fn candidates(&self, now: Instant) -> Result<Vec<bacnet::Candidate>> {
        match &self.adapter {
            Adapter::Inert(_) => Ok(Vec::new()),
            Adapter::FakeBacnet(adapter) => Ok(adapter.candidates(now)?),
        }
    }
    pub fn discard_candidates(&mut self) -> Result<()> {
        match &self.adapter {
            Adapter::Inert(_) => Ok(()),
            Adapter::FakeBacnet(adapter) => Ok(adapter.clear_candidates()?),
        }
    }
}
