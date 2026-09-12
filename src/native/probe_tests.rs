//! Independent regression cases for the pre-open writability probe.
//! Tests own their temporary directory; no real native store is modified.

use super::{NativeError, NativeHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "verdant-native-probe-review-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        // Refuse an existing path: never take ownership of another test's data.
        std::fs::create_dir(&path).expect("create task-owned test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_io_refusal(result: Result<(), NativeError>) {
    let error = result.expect_err("existing probe must be refused");
    assert_eq!(error.code(), "io");
    assert!(matches!(error, NativeError::Io { .. }));
}

#[test]
fn fresh_probe_is_cleaned_before_native_open() {
    let dir = TestDir::new();
    NativeHandle::check_dir_usable(dir.path()).expect("fresh writable directory");
    assert_eq!(std::fs::read_dir(dir.path()).expect("list directory").count(), 0);
}

#[test]
fn existing_probe_file_is_neither_truncated_nor_removed() {
    let dir = TestDir::new();
    let probe = dir.path().join(".verdant-write-probe");
    std::fs::write(&probe, b"not owned by this call").expect("fixture file");
    let result = NativeHandle::check_dir_usable(dir.path());
    assert_eq!(std::fs::read(&probe).expect("retained file"), b"not owned by this call");
    assert_io_refusal(result);
}

#[test]
fn existing_probe_directory_is_preserved() {
    let dir = TestDir::new();
    let probe = dir.path().join(".verdant-write-probe");
    std::fs::create_dir(&probe).expect("fixture subdirectory");
    assert_io_refusal(NativeHandle::check_dir_usable(dir.path()));
    assert!(probe.is_dir());
}

#[cfg(unix)]
#[test]
fn existing_probe_symlink_does_not_modify_its_target() {
    let dir = TestDir::new();
    let target = dir.path().join("unrelated-data");
    let probe = dir.path().join(".verdant-write-probe");
    std::fs::write(&target, b"preserve this content").expect("fixture target");
    std::os::unix::fs::symlink(&target, &probe).expect("fixture symlink");
    let result = NativeHandle::check_dir_usable(dir.path());
    assert_eq!(std::fs::read(&target).expect("retained target"), b"preserve this content");
    assert_eq!(std::fs::read_link(&probe).expect("retained link"), target);
    assert_io_refusal(result);
}

#[cfg(unix)]
#[test]
fn dangling_probe_symlink_does_not_create_a_target() {
    let dir = TestDir::new();
    let target = dir.path().join("must-not-be-created");
    let probe = dir.path().join(".verdant-write-probe");
    std::os::unix::fs::symlink(&target, &probe).expect("fixture symlink");
    let result = NativeHandle::check_dir_usable(dir.path());
    assert_eq!(
        std::fs::symlink_metadata(&target).expect_err("no target created").kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(std::fs::read_link(&probe).expect("retained link"), target);
    assert_io_refusal(result);
}
