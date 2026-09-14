//! Bounded controller-side joining. Native/OS work is not presumed abortable.
use super::{admission::Reservation, owners::Lease, Error, Result};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::Instant,
};

#[derive(Clone, Default)]
pub(super) struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn check(&self, deadline: Instant) -> Result<()> {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        if self.0.load(Ordering::SeqCst) {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
}
type Held = (Arc<Lease>, Arc<Reservation>, Arc<Reservation>);
pub(super) struct Task<T> {
    handle: Option<JoinHandle<(std::thread::Result<T>, Held)>>,
    pub cancel: Cancellation,
}
impl<T: Send + 'static> Task<T> {
    pub fn spawn(held: Held, work: impl FnOnce(Cancellation) -> T + Send + 'static) -> Result<Self> {
        let cancel = Cancellation::default();
        let worker_cancel = cancel.clone();
        let handle = std::thread::Builder::new().name("verdant-inert-runtime".into()).spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(worker_cancel)));
            // Retain resources even after completion until the actual join.
            (result, held)
        })?;
        Ok(Self { handle: Some(handle), cancel })
    }
    pub fn poll(&mut self) -> Option<Result<T>> {
        if !self.handle.as_ref().is_some_and(JoinHandle::is_finished) {
            return None;
        }
        self.handle.take().map(|handle| {
            handle
                .join()
                .map_err(|_| Error::WorkerPanic)
                .and_then(|(value, _held)| value.map_err(|_| Error::WorkerPanic))
        })
    }
}
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.cancel.cancel();
            // Drop is NOT a graceful stop. The worker still owns its lease and
            // reservations; a replacement owner is refused while it survives.
            // Call Runtime::stop and retain Runtime after Unresolved to join it.
            eprintln!("verdant runtime unresolved: abandoned job; cancellation requested, not joined");
        }
    }
}
