//! B03 M02-PR01A: explicitly started synthetic/inert runtime, not PR01 completion.
//! Default constructs no owner or worker and does no I/O. The existing CLI `run`
//! remains the no-field shell. This API does not activate/publish/mutate content.
//!
//! Integration owner: Muse Spark contributor orchestrator; implementation: Astra.
//! E01 preserves Rust/Cargo 1.97.1, Selene b65c2344/default features, system
//! sqlite3 and /usr/bin/shasum. Fixture target: macOS/arm64/debug only. E02's
//! numeric local assumptions/enforcement are in admission, not facility D06/D07.
//! No E03 traffic, E05 real-source claims or E06 non-fixture authentication.
//!
//! Call begin_start -> poll until RunningInert/refusal. Queue explicit read keys
//! from that exact selection, then dispatch_next. Each dispatch rechecks content,
//! current authority and generations outside all protocol handoffs. Poll joins
//! actual jobs; take_result consumes a bounded result slot. stop seals intake,
//! cancels and joins, or returns Unresolved while retaining the jobs/reservations.
//! Retry stop to observe their exit; never interpret a deadline/Drop as a join.
#![allow(dead_code)] // API-first: ordinary CLI run deliberately does not start it.
#![allow(unused_imports)]

pub mod admission;
pub mod bacnet;
mod inert;
pub mod inventory;
mod owners;
mod plug;
mod task;
use crate::{
    access::Credential,
    binding::{BindingRole, BindingStatus},
    domain::scope::TrustedScope,
};
use admission::{Budget, Reservation, Usage, WorkClass};
pub use inert::{RawEnvelope, RawOutcome, ReceiptOrigin};
use owners::{Lease, Owners, Selection};
use std::{
    collections::VecDeque,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use task::Task;

static INCARNATION: AtomicU64 = AtomicU64::new(1);
static SOURCE: AtomicU64 = AtomicU64::new(1);
fn next(counter: &AtomicU64) -> Result<u64> {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
        .map_err(|_| Error::Invalid("identity exhausted"))
}
/// Process-local identity only; restart continuity/durable observations are PR03A.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeIncarnation(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceGeneration(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkId {
    incarnation: RuntimeIncarnation,
    sequence: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disabled,
    Stopped,
    Starting,
    RunningInert,
    Held,
    Stopping,
    Unresolved,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drain {
    Stopped,
    Unresolved { jobs: usize },
}
#[derive(Debug)]
pub struct Status {
    pub state: State,
    pub incarnation: Option<RuntimeIncarnation>,
    pub accepted_revision: Option<crate::accept::AcceptedRevision>,
    pub active_generation: Option<crate::accept::ActiveGeneration>,
    pub source_generation: Option<SourceGeneration>,
    pub usage: Usage,
    pub last_error: Option<&'static str>,
    pub inert_handoffs: u64,
    pub network_calls: u64,
    pub observed_qualification: bool,
}
struct Session {
    selected: Selection,
    credential: Credential,
    incarnation: RuntimeIncarnation,
    source: SourceGeneration,
}
struct Queued {
    id: WorkId,
    class: WorkClass,
    key: String,
    deadline: Instant,
    reserved: Arc<Reservation>,
    admitted: Option<bacnet::BindingPlan>,
}
enum Output {
    Started(Arc<Owners>, Result<Selection>, Credential, SourceGeneration),
    Read(RawEnvelope),
    #[cfg(test)]
    Native,
}
struct Running {
    id: Option<WorkId>,
    incarnation: RuntimeIncarnation,
    deadline: Instant,
    reserved: Arc<Reservation>,
    task: Task<Result<Output>>,
}
struct Completed {
    id: WorkId,
    result: Result<RawEnvelope>,
    _reserved: Arc<Reservation>,
}

#[must_use = "retain the runtime after unresolved stop, then poll/join it"]
pub struct Runtime {
    lease: Option<Arc<Lease>>,
    scope: Option<TrustedScope>,
    owners: Option<Arc<Owners>>,
    opened: bool,
    session: Option<Arc<Session>>,
    incarnation: Option<RuntimeIncarnation>,
    sequence: u64,
    state: State,
    last_error: Option<&'static str>,
    budget: Arc<Budget>,
    adapter: plug::Adapter,
    queue: VecDeque<Queued>,
    running: Vec<Running>,
    completed: VecDeque<Completed>,
    #[cfg(test)]
    pub(crate) before_handoff: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    pub(crate) before_callback: Option<Arc<dyn Fn() + Send + Sync>>,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            lease: None,
            scope: None,
            owners: None,
            opened: false,
            session: None,
            incarnation: None,
            sequence: 0,
            state: State::Disabled,
            last_error: None,
            budget: Arc::new(Budget::default()),
            adapter: plug::Adapter::default(),
            queue: VecDeque::new(),
            running: Vec::new(),
            completed: VecDeque::new(),
            #[cfg(test)]
            before_handoff: None,
            #[cfg(test)]
            before_callback: None,
        }
    }
}
impl Runtime {
    /// Existing trusted local stores only. Filesystem identity checks do not open
    /// stores or establish authority. Lease rejects competing in-process owners.
    pub fn inert(root: &Path, scope: TrustedScope) -> Result<Self> {
        let mut runtime = Self::default();
        runtime.lease = Some(Lease::acquire(root)?);
        runtime.scope = Some(scope);
        runtime.state = State::Stopped;
        Ok(runtime)
    }
    pub fn begin_start(&mut self, credential: Credential) -> Result<()> {
        if self.state != State::Stopped || !self.running.is_empty() {
            return Err(Error::NotStopped);
        }
        let lease = self.lease.clone().ok_or(Error::Disabled)?;
        let scope = self.scope.clone().ok_or(Error::Disabled)?;
        if self.opened && self.owners.is_none() {
            return Err(Error::Invalid("prior open failed; owner reconstruction required"));
        }
        let incarnation = RuntimeIncarnation(next(&INCARNATION)?);
        let source = SourceGeneration(next(&SOURCE)?);
        let reserved = self.budget.reserve(WorkClass::Reconciliation, false)?;
        let active = self.budget.reserve(WorkClass::Reconciliation, true)?;
        let owners = self.owners.clone();
        let deadline = Instant::now() + admission::MAX_LIFETIME;
        let open_lease = lease.clone();
        let task = Task::spawn((lease, reserved.clone(), active), move |cancel| {
            cancel.check(deadline)?;
            let owners = match owners {
                Some(owners) => owners,
                None => Owners::open(open_lease)?,
            };
            let selected = cancel.check(deadline).and_then(|()| owners.select(&credential, &scope));
            Ok(Output::Started(owners, selected, credential, source))
        })?;
        self.opened = true;
        self.incarnation = Some(incarnation);
        self.session = None;
        self.last_error = None;
        self.state = State::Starting;
        self.running.push(Running { id: None, incarnation, deadline, reserved, task });
        Ok(())
    }
    /// Internal composition authority is the successfully authenticated runtime,
    /// not caller-provided ActorContext/scope/endpoint. Only selected sensing keys
    /// enter this queue. Optional discovery is an inert reservation, not a scan.
    pub fn enqueue(&mut self, class: WorkClass, key: &str, deadline: Instant) -> Result<WorkId> {
        if self.state != State::RunningInert {
            return Err(Error::NotRunning);
        }
        let session = self.session.as_ref().ok_or(Error::NotRunning)?;
        let now = Instant::now();
        if deadline <= now {
            return Err(Error::Deadline);
        }
        if deadline.duration_since(now) > admission::MAX_LIFETIME {
            return Err(Error::Invalid("request lifetime exceeds fixture cap"));
        }
        let entry = session.selected.config.entries().get(key).ok_or(Error::Invalid("unselected binding key"))?;
        let binding = entry.binding();
        if binding.effective() != BindingRole::Sense
            || binding.requested() != BindingRole::Sense
            || binding.status() != BindingStatus::Valid
        {
            return Err(Error::Invalid("inert sensing requires structurally valid sense binding"));
        }
        let admitted = self.adapter.admit(&session.selected, key, class)?;
        let reserved = self.budget.reserve(class, false)?;
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Invalid("work identity exhausted"))?;
        let id = WorkId { incarnation: session.incarnation, sequence: self.sequence };
        self.queue.push_back(Queued { id, class, key: key.into(), deadline, reserved, admitted });
        Ok(id)
    }
    /// Dispatch at most one queued item. Mandatory classes precede optional work;
    /// None means no eligible item (possibly all classes busy). No automatic
    /// tick/catch-up/retry loop is installed by this slice.
    pub fn dispatch_next(&mut self) -> Result<Option<WorkId>> {
        if self.state != State::RunningInert {
            return Err(Error::NotRunning);
        }
        let eligible = |q: &Queued| Instant::now() >= q.deadline || self.budget.can_run(q.class);
        let index = self
            .queue
            .iter()
            .position(|q| q.class != WorkClass::OptionalDiscovery && eligible(q))
            .or_else(|| self.queue.iter().position(eligible));
        let Some(index) = index else {
            return Ok(None);
        };
        let queued = &self.queue[index];
        if Instant::now() >= queued.deadline {
            let queued = self.queue.remove(index).ok_or(Error::Invalid("queue index"))?;
            let id = queued.id;
            self.completed.push_back(Completed { id, result: Err(Error::Deadline), _reserved: queued.reserved });
            return Ok(Some(id));
        }
        let active = self.budget.reserve(queued.class, true)?;
        let owners = self.owners.clone().ok_or(Error::NotRunning)?;
        let session = self.session.clone().ok_or(Error::NotRunning)?;
        let adapter = self.adapter.clone();
        let queued = self.queue.remove(index).ok_or(Error::Invalid("queue index"))?;
        let Queued { id, key, deadline, reserved, admitted, .. } = queued;
        #[cfg(test)]
        let before_handoff = self.before_handoff.take();
        #[cfg(test)]
        let before_callback = self.before_callback.take();
        let task = Task::spawn((owners.lease.clone(), reserved.clone(), active), move |cancel| {
            cancel.check(deadline)?;
            owners.verify_content(&session.selected)?;
            #[cfg(test)]
            if let Some(hook) = before_handoff {
                hook();
            }
            owners.check_generation(&session.selected, &session.credential)?;
            cancel.check(deadline)?;
            // NO SQL transaction, registry/native/custody guard here.
            let raw = adapter.read(plug::Context {
                selected: &session.selected, key: &key, work: id,
                incarnation: session.incarnation, source: session.source,
            }, admitted, &cancel, deadline)?;
            #[cfg(test)]
            if let Some(hook) = before_callback {
                hook();
            }
            owners.check_generation(&session.selected, &session.credential)?;
            cancel.check(deadline)?;
            adapter.retain_candidates(&raw)?;
            Ok(Output::Read(raw))
        });
        match task {
            Ok(task) => {
                self.running.push(Running { id: Some(id), incarnation: id.incarnation, deadline, reserved, task })
            }
            Err(error) => self.completed.push_back(Completed { id, result: Err(error), _reserved: reserved }),
        }
        Ok(Some(id))
    }
    pub fn cancel(&mut self, id: WorkId) -> Result<()> {
        if let Some(index) = self.queue.iter().position(|q| q.id == id) {
            let queued = self.queue.remove(index).ok_or(Error::Invalid("queue index"))?;
            self.completed.push_back(Completed { id, result: Err(Error::Cancelled), _reserved: queued.reserved });
            return Ok(());
        }
        if let Some(job) = self.running.iter().find(|job| job.id == Some(id)) {
            job.task.cancel.cancel();
            return Ok(());
        }
        Err(Error::Invalid("unknown live work"))
    }
    pub fn poll(&mut self) {
        let mut index = 0;
        while index < self.running.len() {
            if Instant::now() >= self.running[index].deadline {
                self.running[index].task.cancel.cancel();
            }
            let Some(result) = self.running[index].task.poll() else {
                index += 1;
                continue;
            };
            let job = self.running.remove(index);
            let mut result = result.and_then(|value| value);
            // Keep opened owners even when start was canceled; do not reopen them
            // on the next start or infer running status from selected content.
            if let Ok(Output::Started(owners, _, _, _)) = &result {
                self.owners = Some(owners.clone());
            }
            if let Err(error) = job.task.cancel.check(job.deadline) {
                result = Err(error);
            }
            if self.incarnation != Some(job.incarnation) {
                result = Err(Error::Stale);
            }
            if matches!(self.state, State::Stopping | State::Unresolved) {
                continue;
            }
            match (job.id, result) {
                (None, Ok(Output::Started(_, selected, credential, source))) => match selected {
                    Ok(selected) => {
                        self.session =
                            Some(Arc::new(Session { selected, credential, incarnation: job.incarnation, source }));
                        self.state = State::RunningInert;
                    }
                    Err(error) => {
                        self.last_error = Some(error.code());
                        self.state = State::Held;
                    }
                },
                (None, Err(error)) => {
                    self.last_error = Some(error.code());
                    self.state = State::Held;
                }
                (Some(id), result) => {
                    let result = match result {
                        Ok(Output::Read(raw)) => Ok(raw),
                        Err(error) => Err(error),
                        Ok(Output::Started(..)) => Err(Error::Invalid("unexpected start result")),
                        #[cfg(test)]
                        Ok(Output::Native) => continue,
                    };
                    if let Err(error) = &result {
                        self.last_error = Some(error.code());
                        if matches!(
                            error,
                            Error::Stale
                                | Error::NoAcceptance
                                | Error::NoActivation
                                | Error::Access(_)
                                | Error::Accept(_)
                                | Error::Seal(_)
                                | Error::Api(_)
                        ) {
                            self.state = State::Held;
                            for queued in self.queue.drain(..) {
                                self.completed.push_back(Completed {
                                    id: queued.id,
                                    result: Err(Error::Cancelled),
                                    _reserved: queued.reserved,
                                });
                            }
                            for running in &self.running {
                                running.task.cancel.cancel();
                            }
                        }
                    }
                    self.completed.push_back(Completed { id, result, _reserved: job.reserved });
                }
                (None, Ok(Output::Read(_))) => {
                    self.last_error = Some("runtime-invalid");
                    self.state = State::Held;
                }
                #[cfg(test)]
                (None, Ok(Output::Native)) => {}
            }
        }
        if matches!(self.state, State::Stopping | State::Unresolved) && self.running.is_empty() {
            self.state = State::Stopped;
        }
    }
    pub fn take_result(&mut self, id: WorkId) -> Option<Result<RawEnvelope>> {
        let index = self.completed.iter().position(|result| result.id == id)?;
        self.completed.remove(index).map(|completed| completed.result)
    }
    /// Does not close the retained stores: Stopped means this runtime's admitted
    /// jobs were joined. Kernel scheduling is not a real-time guarantee. On
    /// Unresolved keep this object, its slots and owners, and poll/stop again.
    pub fn stop(&mut self, budget: Duration) -> Result<Drain> {
        if budget > admission::MAX_DRAIN {
            return Err(Error::Invalid("drain exceeds fixture cap"));
        }
        self.state = State::Stopping;
        self.queue.clear();
        self.completed.clear();
        self.session = None;
        for job in &self.running {
            job.task.cancel.cancel();
        }
        let deadline = Instant::now() + budget;
        loop {
            self.poll();
            if self.running.is_empty() {
                self.state = State::Stopped;
                return Ok(Drain::Stopped);
            }
            if Instant::now() >= deadline {
                self.state = State::Unresolved;
                return Ok(Drain::Unresolved { jobs: self.running.len() });
            }
            std::thread::sleep(Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())));
        }
    }
    /// Last checked content identities, not current availability or a freshness
    /// lease. No I/O and no path from structural meaning to observed qualification.
    pub fn status(&self) -> Status {
        Status {
            state: self.state,
            incarnation: self.incarnation,
            accepted_revision: self.session.as_ref().map(|s| s.selected.accepted.revision),
            active_generation: self.session.as_ref().map(|s| s.selected.active.generation()),
            source_generation: self.session.as_ref().map(|s| s.source),
            usage: self.budget.usage(),
            last_error: self.last_error,
            inert_handoffs: self.adapter.calls(),
            network_calls: 0,
            observed_qualification: false,
        }
    }
}
#[cfg(test)]
impl Runtime {
    pub(crate) fn test_stores(
        &self,
    ) -> (&crate::accept::AcceptanceStore, &crate::seal::SealStore, &crate::access::AccessGate) {
        let owners = self.owners.as_ref().expect("test runtime opened");
        (&owners.accepted, &owners.seals, &owners.gate)
    }
    /// Synthetic scheduling seam around real native work. Not a product API.
    pub(crate) fn test_native_job(
        &mut self,
        work: impl FnOnce(&crate::native::NativeHandle) + Send + 'static,
    ) -> Result<()> {
        let owners = self.owners.clone().ok_or(Error::NotRunning)?;
        let incarnation = self.incarnation.ok_or(Error::NotRunning)?;
        let reserved = self.budget.reserve(WorkClass::OptionalDiscovery, false)?;
        let active = self.budget.reserve(WorkClass::OptionalDiscovery, true)?;
        let task = Task::spawn((owners.lease.clone(), reserved.clone(), active), move |_| {
            work(&owners.native);
            Ok(Output::Native)
        })?;
        self.running.push(Running {
            id: None,
            incarnation,
            deadline: Instant::now() + admission::MAX_LIFETIME,
            reserved,
            task,
        });
        Ok(())
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        for job in &self.running {
            job.task.cancel.cancel();
        }
        // Task::drop explicitly reports unresolved rather than blocking or
        // claiming that caller disappearance joined the actual work.
    }
}

#[derive(Debug)]
pub enum Error {
    Disabled,
    NotStopped,
    NotRunning,
    OwnerBusy,
    NoAcceptance,
    NoActivation,
    Stale,
    Deadline,
    Cancelled,
    WorkerPanic,
    Invalid(&'static str),
    Saturated { class: WorkClass, running: bool },
    // Preserve typed origin and stable cause code, not potentially multi-MiB
    // subprocess diagnostics in every retained completion slot.
    Access(&'static str),
    Binding(&'static str),
    Accept(&'static str),
    Api(&'static str),
    Seal(&'static str),
    Storage(&'static str),
    Native(&'static str),
    Bacnet(&'static str),
    Io(Option<i32>),
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Disabled => "runtime-disabled",
            Self::NotStopped => "runtime-not-stopped",
            Self::NotRunning => "runtime-not-running",
            Self::OwnerBusy => "runtime-owner-busy",
            Self::NoAcceptance => "runtime-no-acceptance",
            Self::NoActivation => "runtime-no-activation",
            Self::Stale => "runtime-stale-generation",
            Self::Deadline => "runtime-deadline",
            Self::Cancelled => "runtime-cancelled",
            Self::WorkerPanic => "runtime-worker-panic",
            Self::Invalid(_) => "runtime-invalid",
            Self::Saturated { .. } => "runtime-saturated",
            Self::Access(code)
            | Self::Binding(code)
            | Self::Accept(code)
            | Self::Api(code)
            | Self::Seal(code)
            | Self::Storage(code)
            | Self::Bacnet(code)
            | Self::Native(code) => code,
            Self::Io(_) => "runtime-io",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}
impl std::error::Error for Error {}
macro_rules! source_error {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for Error {
            fn from(value: $ty) -> Self {
                Self::$variant(value.code())
            }
        }
    };
}
source_error!(crate::access::AccessError, Access);
source_error!(crate::binding::BindingError, Binding);
source_error!(crate::accept::Error, Accept);
source_error!(crate::api::Error, Api);
source_error!(crate::seal::SealError, Seal);
source_error!(crate::storage::StorageError, Storage);
source_error!(crate::native::NativeError, Native);
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.raw_os_error())
    }
}
pub type Result<T> = std::result::Result<T, Error>;
