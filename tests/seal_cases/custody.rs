use crate::{fixture::*, native, seal, storage};

fn files(dir: &std::path::Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let path = e.unwrap().path();
            (path.clone(), std::fs::read(path).unwrap())
        })
        .collect()
}

#[test]
fn raw_handle_prune_and_maintain_refuse_sealed_only_generation_with_guard_plan() {
    let mut f = Fixture::new();
    let seal = f.seal("retained-seal", &f.draft()).unwrap();
    for n in 2..=4 {
        f.native
            .execute(&format!("INSERT (:Reading {{seq: {n}}})"))
            .unwrap();
        f.native.checkpoint().unwrap().completed().unwrap();
    }
    let before = files(&f.scratch.native());
    let outcome = f.native.clone().prune().unwrap_err();
    let native::NativeError::Custody { plan } = &outcome else {
        panic!("raw handle bypass: {outcome:?}");
    };
    assert_eq!(plan.live_seals, vec![seal.identity.as_str()]);
    assert_eq!(plan.generations, vec![f.reference.generation()]);
    assert_eq!(before, files(&f.scratch.native()));
    assert_eq!(outcome.code(), "seal-custody");
    assert!(plan.checkpoint.is_none());
    let maintenance = f.native.maintain().unwrap_err();
    assert!(
        matches!(&maintenance, native::NativeError::Custody { plan } if plan.checkpoint.as_ref().unwrap().generation > f.reference.generation() && plan.generations == vec![f.reference.generation()])
    );
    assert_eq!(
        f.seals.capture_simulation(&seal.identity).unwrap(),
        seal.manifest
    );
    println!("FIXED sealed-only generation retained through raw prune: {plan:?}; maintain={maintenance:?}; native bytes unchanged=true");
    f.release("end-custody", &seal.identity).unwrap();
    assert_eq!(
        f.seals
            .check_before_activation(&seal.identity)
            .unwrap_err()
            .code(),
        "seal-released"
    );
    let prune = f.native.prune().unwrap().report().unwrap();
    assert!(prune.removed_count > 0);
    assert!(!f
        .scratch
        .native()
        .join(format!("MANIFEST-{:020}.control", f.reference.generation()))
        .exists());
    assert_eq!(f.seal_rows().len(), 1, "release does not edit the seal");
    println!("FIXED explicit finite custody release: prune removed {} artifacts; immutable seal row retained", prune.removed_count);
}

#[test]
fn raw_reopen_cannot_bypass_guard_and_application_reopen_recovers_live_seals() {
    let mut f = Fixture::new();
    let sealed = f.seal("reopen-seal", &f.draft()).unwrap();
    assert_eq!(
        seal::SealStore::open(f.registry.store().try_clone().unwrap(), f.native.clone())
            .err()
            .unwrap()
            .code(),
        "seal-conflict"
    );
    drop(f.seals);
    let closed = f.native.close();
    {
        use std::fs::{OpenOptions, TryLockError};
        use std::time::{Duration, Instant};
        // Both native owners are dropped. As in R09, synchronize fixture setup
        // on the actual Selene writer LOCK: contention was observed immediately
        // after drop. Never retry the product open or accept a reopen refusal.
        let native_path = f.scratch.native();
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(native_path.join("LOCK"))
            .expect("existing writer LOCK");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) => {
                    assert!(
                        Instant::now() < deadline,
                        "writer LOCK not released: {}",
                        native_path.display()
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(TryLockError::Error(error)) => panic!("writer LOCK probe failed: {error}"),
            }
        }
        lock.unlock().expect("release synchronization lock");
    }
    let (native, _) = closed.open().unwrap();
    let native::NativeError::Custody { plan } = native.prune().unwrap_err() else {
        panic!("unguarded reopened prune accepted");
    };
    assert!(plan.detail.contains("reopen the application guard"));
    assert!(
        plan.live_seals.is_empty(),
        "unavailable is not fabricated live evidence"
    );
    let foreign_db = f.scratch.0.join("wrong.db");
    let (foreign, _) = storage::sqlite::SqliteStore::open(
        &foreign_db,
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
    )
    .unwrap();
    assert_eq!(
        seal::SealStore::open(foreign, native.clone())
            .err()
            .unwrap()
            .code(),
        "seal-conflict"
    );
    let recovered =
        seal::SealStore::open(f.registry.store().try_clone().unwrap(), native.clone()).unwrap();
    assert_eq!(
        recovered.capture_simulation(&sealed.identity).unwrap(),
        sealed.manifest
    );
    let native::NativeError::Custody { plan } = native.prune().unwrap_err() else {
        panic!("recovered seal not retained");
    };
    assert_eq!(plan.live_seals, vec![sealed.identity.as_str()]);
    println!(
        "FIXED raw reopen missing guard refused; foreign SQLite guard refused; recovered {plan:?}"
    );
}

#[test]
fn missing_manifest_and_changed_snapshot_fail_before_capture_or_activation() {
    let mut f = Fixture::new();
    let sealed = f.seal("artifact-seal", &f.draft()).unwrap();
    let manifest = f
        .scratch
        .native()
        .join(format!("MANIFEST-{:020}.control", f.reference.generation()));
    let bytes = std::fs::read(&manifest).unwrap();
    std::fs::remove_file(&manifest).unwrap();
    assert_eq!(
        f.seals
            .capture_simulation(&sealed.identity)
            .unwrap_err()
            .code(),
        "seal-missing-reference"
    );
    assert_eq!(
        f.seal("missing-artifact", &f.draft()).unwrap_err().code(),
        "seal-missing-reference"
    );
    std::fs::write(&manifest, &bytes).unwrap();
    let snapshot = f
        .scratch
        .native()
        .join(format!("SNAPSHOT-{:020}.logical", f.reference.generation()));
    let mut bytes = std::fs::read(&snapshot).unwrap();
    bytes[50] ^= 1;
    std::fs::write(&snapshot, &bytes).unwrap();
    assert_eq!(
        f.seals
            .check_before_activation(&sealed.identity)
            .unwrap_err()
            .code(),
        "seal-reference-changed"
    );
    assert_eq!(f.seal_rows().len(), 1);
    assert!(matches!(
        f.native.prune().unwrap_err(),
        native::NativeError::Custody { .. }
    ));
}

#[test]
fn guard_does_not_disappear_when_application_drops_and_corrupt_sidecar_fails_closed() {
    let mut f = Fixture::new();
    let sealed = f.seal("drop-seal", &f.draft()).unwrap();
    drop(f.seals);
    let native::NativeError::Custody { plan } = f.native.prune().unwrap_err() else {
        panic!("dropped application lost custody");
    };
    assert_eq!(plan.live_seals, vec![sealed.identity.as_str()]);
    std::fs::write(f.native.custody_path().unwrap(), "invalid pair").unwrap();
    let native::NativeError::Custody { plan } = f.native.prune().unwrap_err() else {
        panic!("corrupt sidecar bypass");
    };
    assert!(plan.detail.contains("unavailable"));
    assert!(plan.live_seals.is_empty());
}

#[test]
fn in_progress_seal_excludes_raw_prune_and_guard_replacement_is_refused() {
    let mut f = Fixture::new();
    let raw = f.native.clone();
    seal::on_boundary(move || {
        assert!(matches!(raw.prune(), Err(native::NativeError::Busy { .. })));
    });
    let sealed = f.seal("interleaved-prune", &f.draft()).unwrap();
    struct Bypass;
    impl native::CustodyGuard for Bypass {
        fn check_prune(&self) -> Result<(), native::CustodyPlan> {
            Ok(())
        }
    }
    let mut window = f.native.custody_lock().unwrap();
    assert_eq!(
        window
            .install(std::sync::Arc::new(Bypass))
            .unwrap_err()
            .code(),
        "seal-custody"
    );
    drop(window);
    let native::NativeError::Custody { plan } = f.native.prune().unwrap_err() else {
        panic!("replacement bypass");
    };
    assert_eq!(plan.live_seals, vec![sealed.identity.as_str()]);
    println!("FIXED in-progress native prune refused Busy; installed guard cannot be cleared/replaced; accepted seal retains bytes");
}

#[test]
fn finite_live_custody_refuses_before_row_and_release_frees_a_slot() {
    let mut f = Fixture::new();
    let mut first = None;
    for n in 0..seal::MAX_LIVE_SEALS {
        let draft = f.draft_with(vec![f.finding.clone()], &format!("bounded-publication-{n}"));
        let sealed = f.seal(&format!("bounded-seal-{n}"), &draft).unwrap();
        if first.is_none() {
            first = Some(sealed.identity);
        }
    }
    let before = f.seal_rows();
    let next = f.draft_with(vec![f.finding.clone()], "one-more-publication");
    let error = f.seal("over-live-limit", &next).unwrap_err();
    assert!(matches!(error, seal::SealError::Limit("live seal custody")));
    assert_eq!(f.seal_rows(), before);
    let native::NativeError::Custody { plan } = f.native.prune().unwrap_err() else {
        panic!("custody absent");
    };
    assert_eq!(plan.live_seals.len(), seal::MAX_LIVE_SEALS);
    f.release("release-slot", &first.unwrap()).unwrap();
    f.seal("over-live-limit", &next).unwrap();
    assert_eq!(f.seal_rows().len(), seal::MAX_LIVE_SEALS + 1);
    println!("FIXED scoped custody: live limit={}, excess row refused, explicit release freed one slot; historical seals remain", seal::MAX_LIVE_SEALS);
}
