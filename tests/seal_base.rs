//! Baseline: ordinary unsealed checkpoint selections carry no application custody.
#![allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "../src/storage/mod.rs"]
mod storage;

#[test]
fn base_unsealed_checkpoint_is_not_a_revision_or_retention_promise() {
    let dir = std::env::temp_dir().join(format!("verdant-seal-base-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let (native, _) = native::NativeHandle::create(&dir, native::NativeSettings::local()).unwrap();
    native.execute("INSERT (:Reading {seq: 1})").unwrap();
    let first = native.checkpoint().unwrap().completed().unwrap();
    let manifest = dir.join(format!("MANIFEST-{:020}.control", first.generation));
    let bytes = std::fs::read(&manifest).unwrap();
    for n in 2..=4 {
        native
            .execute(&format!("INSERT (:Reading {{seq: {n}}})"))
            .unwrap();
        native.checkpoint().unwrap().completed().unwrap();
    }
    let prune = native.prune().unwrap().report().unwrap();
    assert!(!manifest.exists());
    assert!(!dir.join(&first.snapshot).exists());
    assert!(prune.removed_count > 0);
    println!("BASE unsealed generation={} manifest_bytes={} snapshot_bytes={} removed_count={}; names do not retain meaning", first.generation, bytes.len(), first.bytes, prune.removed_count);
}
