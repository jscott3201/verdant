//! Path-scoped, one-shot scheduling seams. Never compiled into the product.
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

thread_local! { static NOW: Cell<Option<i64>> = const { Cell::new(None) }; }
thread_local! { static INTERRUPT_MARKER: RefCell<Option<PathBuf>> = const { RefCell::new(None) }; }
pub(crate) fn interrupt_after_marker(path: &Path) {
    INTERRUPT_MARKER.with(|slot| *slot.borrow_mut() = Some(path.into()));
}
pub(super) fn after_marker(path: &Path) -> &'static str {
    INTERRUPT_MARKER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_deref() == Some(path) {
            slot.take();
            // SQLite executes this only after the marker INSERT and dirty mark.
            "SELECT r05_injected_marker_interruption(); "
        } else {
            ""
        }
    })
}
pub(super) fn now() -> Option<i64> {
    NOW.with(Cell::get)
}
pub(crate) fn with_clock<T>(now: i64, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<i64>);
    impl Drop for Restore {
        fn drop(&mut self) {
            NOW.with(|slot| slot.set(self.0));
        }
    }
    let _restore = Restore(NOW.with(|slot| slot.replace(Some(now))));
    run()
}

type Action = Arc<dyn Fn() + Send + Sync>;
static HOOKS: Mutex<BTreeMap<(PathBuf, &'static str), (usize, Action)>> =
    Mutex::new(BTreeMap::new());

pub(crate) fn arm(path: &Path, stage: &'static str, times: usize, action: Action) {
    assert!(times > 0);
    assert!(HOOKS
        .lock()
        .unwrap()
        .insert((path.into(), stage), (times, action))
        .is_none());
}

pub(super) fn at(path: &Path, stage: &'static str) {
    let action = {
        let mut hooks = HOOKS.lock().unwrap();
        let key = (path.to_path_buf(), stage);
        hooks
            .get_mut(&key)
            .map(|(times, action)| {
                *times -= 1;
                action.clone()
            })
            .inspect(|_| {
                if hooks.get(&key).unwrap().0 == 0 {
                    hooks.remove(&key);
                }
            })
    };
    if let Some(action) = action {
        action();
    }
}
