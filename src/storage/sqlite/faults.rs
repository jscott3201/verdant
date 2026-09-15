//! Path-scoped, thread-local injection: absent from product builds. No PATH
//! replacement, environment mutation, credentials, or global test races.
use super::*;
use std::cell::{Cell, RefCell};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault { BeforePublish, BeforeCommit, LostResponse, MalformedResponse }
thread_local! {
    static FAULT: RefCell<Option<(PathBuf, Fault)>> = const { RefCell::new(None) };
    static ADMISSION: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    static SPAWN_ATTEMPTS: Cell<u64> = const { Cell::new(0) };
}
// Count at the actual process boundary, including failed spawn attempts. The
// calling thread owns admission and CLI spawning; pipe workers never spawn.
pub(super) fn record_spawn_attempt() {
    SPAWN_ATTEMPTS.with(|count| count.set(count.get() + 1));
}
pub(super) fn spawn_attempts() -> u64 { SPAWN_ATTEMPTS.with(Cell::get) }

pub(crate) fn inject(path: &Path, fault: Fault) {
    FAULT.with(|slot| *slot.borrow_mut() = Some((path.to_path_buf(), fault)));
}
pub(crate) fn on_admission(hook: impl FnOnce() + 'static) {
    ADMISSION.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}
fn take(path: &Path, wanted: Fault) -> bool {
    FAULT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(p, f)| p == path && *f == wanted) {
            slot.take(); true
        } else { false }
    })
}
pub(super) fn before_publish(path: &Path) -> Result<(), StorageError> {
    if take(path, Fault::BeforePublish) { Err(connection::failure("injected interrupted bootstrap before publication")) } else { Ok(()) }
}
pub(super) fn before_admission(_path: &Path) {
    let hook = ADMISSION.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook { hook(); }
}
pub(super) fn before_commit(path: &Path) -> bool { take(path, Fault::BeforeCommit) }
pub(super) fn commit_response(path: &Path, result: Result<(), StorageError>) -> Result<(), StorageError> {
    result?;
    if take(path, Fault::LostResponse) { return Err(connection::failure("injected lost response after observed commit")); }
    if take(path, Fault::MalformedResponse) { return Err(connection::failure("injected malformed response after observed commit")); }
    Ok(())
}
