//! R01 preservation principle at R03's create_new bootstrap reservation.
//! Fixed names target the actual reservation primitive, not a duplicate probe.
use super::*;
use std::os::unix::fs::symlink;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("verdant-r04-probe-{}-{}-{}", std::process::id(), epoch_nanos_now(), mutation::next_sequence()));
        fs::create_dir(&path).expect("exclusive scratch");
        Self(path)
    }
    fn probe(&self) -> PathBuf { self.0.join(".verdant-bootstrap-fixture") }
    fn reserve(&self) -> Result<PrivateFile, StorageError> {
        PrivateFile::reserve(&self.0.join("store.db"), self.probe())
    }
    fn refused(&self) {
        let error = self.reserve().err().expect("existing reservation refused");
        assert!(matches!(error, StorageError::Io { .. }));
        assert_eq!(error.code(), "io");
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).expect("cleanup"); } }

#[test]
fn r04_probe_fresh_reservation_cleans_up() {
    let scratch = Scratch::new();
    let private = scratch.reserve().expect("reserve fresh");
    assert!(scratch.probe().is_file());
    drop(private);
    assert_eq!(fs::read_dir(&scratch.0).expect("dir").count(), 0);
}

#[test]
fn r04_probe_existing_file_preserves_bytes_and_name() {
    let scratch = Scratch::new();
    fs::write(scratch.probe(), b"unowned\0bytes\xff").expect("file");
    scratch.refused();
    assert_eq!(fs::read(scratch.probe()).expect("preserved"), b"unowned\0bytes\xff");
    assert_eq!(fs::read_dir(&scratch.0).expect("dir").count(), 1);
    println!("probe: file preserved byte-for-byte (14 bytes); no truncation/removal");
}

#[test]
fn r04_probe_existing_directory_preserves_contents() {
    let scratch = Scratch::new();
    fs::create_dir(scratch.probe()).expect("directory");
    let file = scratch.probe().join("keep");
    fs::write(&file, b"directory content").expect("content");
    scratch.refused();
    assert!(scratch.probe().is_dir());
    assert_eq!(fs::read(file).expect("preserved"), b"directory content");
}

#[test]
fn r04_probe_existing_symlink_preserves_link_and_target() {
    let scratch = Scratch::new();
    let target = scratch.0.join("target");
    fs::write(&target, b"unrelated bytes").expect("target");
    symlink(&target, scratch.probe()).expect("symlink");
    scratch.refused();
    assert_eq!(fs::read_link(scratch.probe()).expect("preserved link"), target);
    assert_eq!(fs::read(target).expect("preserved target"), b"unrelated bytes");
}

#[test]
fn r04_probe_dangling_symlink_never_creates_target() {
    let scratch = Scratch::new();
    let target = scratch.0.join("must-not-exist");
    symlink(&target, scratch.probe()).expect("dangling symlink");
    scratch.refused();
    assert_eq!(fs::read_link(scratch.probe()).expect("preserved link"), target);
    assert_eq!(fs::symlink_metadata(target).unwrap_err().kind(), std::io::ErrorKind::NotFound);
    assert_eq!(fs::read_dir(&scratch.0).expect("dir").count(), 1);
}
