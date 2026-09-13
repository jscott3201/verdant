use crate::helpers::*;
use crate::storage::sqlite::faults::{inject, Fault};

#[test]
fn activation_lost_response_and_mismatched_operation_identity() {
    let mut f = Fixture::new();
    let (store, accepted) = accepted(&mut f, "lost-active", Revision::INITIAL);
    let request = request("activate-lost", Generation::INITIAL, &accepted);
    let pending = store.prepare_activation(request.clone(), &f.seals).unwrap();
    let before = counts(&f);
    inject(&f.scratch.db(), Fault::LostResponse);
    let active = store.submit_activation(&pending, &f.seals).unwrap();
    assert!(active.reconciled());
    one_effect(&before, &counts(&f));
    let snapshot = snapshot(&f);
    assert_eq!(reopen(&f).reconcile_activation(&request).unwrap().unwrap(), active);
    assert_eq!(store.submit_activation(&pending, &f.seals).unwrap(), active);
    let mismatch = ActivationRequest::new(request.operation().clone(), Generation::new(1).unwrap(), accepted.request.clone());
    assert!(matches!(store.reconcile_activation(&mismatch), Err(Error::Conflict(_))));
    assert!(matches!(store.activate(&mismatch, &f.seals), Err(Error::Conflict(_))));
    // A fresh operation at the now-current generation cannot duplicate effects.
    let duplicate = ActivationRequest::new(operation("activate-duplicate"), active.generation(), accepted.request);
    assert!(matches!(store.activate(&duplicate, &f.seals), Err(Error::Conflict(_))));
    assert!(store.reconcile_activation(&duplicate).unwrap().is_none());
    assert_eq!(snapshot, crate::helpers::snapshot(&f));
    println!("FIXED lost activation response reconciled by exact operation; 1 row+receipt, no duplicate effects; changed identity refused with identical bytes");
}

#[test]
fn activation_precommit_interruption_is_zero_partial_and_retryable() {
    let mut f = Fixture::new();
    let (store, accepted) = accepted(&mut f, "precommit", Revision::INITIAL);
    let pending = store.prepare_activation(request("activate-precommit", Generation::INITIAL, &accepted), &f.seals).unwrap();
    let before = snapshot(&f);
    inject(&f.scratch.db(), Fault::BeforeCommit);
    assert!(matches!(store.submit_activation(&pending, &f.seals),
        Err(Error::Storage(crate::storage::StorageError::SqliteFailure { detail }))
        if detail.contains("injected precommit interruption")));
    assert!(store.active(&scope()).unwrap().is_none());
    assert!(store.reconcile_activation(pending.request()).unwrap().is_none());
    assert_eq!(before, snapshot(&f));
    let active = reopen(&f).activate(pending.request(), &f.seals).unwrap();
    assert_eq!(active.revision(), accepted.revision);
    assert_eq!(active_events(&f).len(), 1);
    one_effect(&before.1, &counts(&f));
    println!("FIXED activation interrupted pre-COMMIT: event/receipt/mark delta=0, bytes identical; same-ID restart -> one exact active event");
}

#[test]
fn missing_native_content_blocks_only_named_capability_without_rollback() {
    for previously_active in [false, true] {
    let mut f = Fixture::new();
    let (store, accepted) = accepted(&mut f, "missing-active", Revision::INITIAL);
    let request = request("activate-missing", Generation::INITIAL, &accepted);
    // Commit once, then lose an older retained source. Recovery of history remains
    // distinct from a new claim that the selected capability is available.
    let active = previously_active.then(|| store.activate(&request, &f.seals).unwrap());
    for seq in 2..=4 {
        f.native.execute(&format!("INSERT (:Reading {{seq: {seq}}})")).unwrap();
        f.native.checkpoint().unwrap().completed().unwrap();
    }
    let before = snapshot(&f);
    let db = f.scratch.db();
    let native_path = f.scratch.native();
    let generation = f.reference.generation();
    drop(f.seals);
    drop(f.native);
    std::fs::remove_file(native_path.join(format!("SNAPSHOT-{generation:020}.logical"))).unwrap();
    let (native, _) = crate::native::NativeHandle::open(&native_path, crate::native::NativeSettings::local()).unwrap();
    let seals = availability_store(&db, native);
    let error = store.activate(&request, &seals).unwrap_err();
    assert_eq!(error.code(), "activation-blocked");
    assert!(matches!(error, Error::ActivationBlocked { scope: affected, seal, .. }
        if affected == scope() && &seal == request.acceptance().seal()));
    assert_eq!(store.active(&scope()).unwrap().map(|a| a.row_id()), active.as_ref().map(|a| a.row_id()));
    assert_eq!(store.reconcile_activation(&request).unwrap().map(|a| a.row_id()), active.as_ref().map(|a| a.row_id()));
    // The active event is inspectable; unavailable content never selects a fallback.
    let after = f.registry.store().exec_script("SELECT id,seq,value_json FROM outbox WHERE operation='accept-active-v1' ORDER BY id;").unwrap();
    assert_eq!(before.0, after);
    let after_counts = f.registry.store().exec_script("SELECT (SELECT COUNT(*) FROM outbox),(SELECT COUNT(*) FROM storage_receipts),(SELECT COUNT(*) FROM derived_marks);").unwrap();
    assert_eq!(before.1, after_counts);
    for (name, expected) in before.2 { assert_eq!(std::fs::read(f.scratch.0.join(name)).ok(), expected); }
    println!("FIXED missing sealed native snapshot blocks named scope+seal; previously_active={previously_active}, historical pointer unchanged, no fallback, rows/bytes identical");
    }
}

#[test]
fn missing_content_before_first_activation_leaves_no_pointer() {
    let mut f = Fixture::new();
    let (store, accepted) = accepted(&mut f, "released-active", Revision::INITIAL);
    let request = request("activate-released", Generation::INITIAL, &accepted);
    let pending = store.prepare_activation(request.clone(), &f.seals).unwrap();
    f.release("release-before-active", accepted.request.seal()).unwrap();
    let before = snapshot(&f);
    let error = store.submit_activation(&pending, &f.seals).unwrap_err();
    assert!(matches!(error, Error::ActivationBlocked { cause: crate::seal::SealError::Released, .. }));
    assert!(store.active(&scope()).unwrap().is_none());
    assert!(store.reconcile_activation(&request).unwrap().is_none());
    assert_eq!(before, snapshot(&f));
}

#[test]
fn release_racing_activation_is_blocked_in_short_transaction() {
    let mut f = Fixture::new();
    let (store, accepted) = accepted(&mut f, "release-active", Revision::INITIAL);
    let pending = store.prepare_activation(request("activate-release-race", Generation::INITIAL, &accepted), &f.seals).unwrap();
    let (ready, waiting) = std::sync::mpsc::channel();
    let (resume, paused) = std::sync::mpsc::channel();
    let seals = &f.seals;
    let result = std::thread::scope(|threads| {
        let worker = threads.spawn(|| {
            accept::on_activation_boundary(move || {
                ready.send(()).unwrap();
                paused.recv_timeout(WAIT).unwrap();
            });
            store.submit_activation(&pending, seals)
        });
        waiting.recv_timeout(WAIT).unwrap();
        seals.release(&operation("release-in-active-window"), accepted.request.seal(),
            &mut f.registry, &f.gate, &f.credentials.publisher).unwrap();
        resume.send(()).unwrap();
        worker.join().unwrap()
    });
    assert!(matches!(result, Err(Error::ActivationBlocked { .. })));
    assert!(store.active(&scope()).unwrap().is_none());
    assert!(store.reconcile_activation(pending.request()).unwrap().is_none());
    assert!(active_events(&f).is_empty());
    println!("FIXED release proceeds while activation waits without custody/writer lock; publication CAS blocks activation, no active row/receipt");
}

#[test]
fn activation_requires_real_acceptance_and_qualification_stays_not_yet() {
    let mut f = Fixture::new();
    let (store, sealed) = publish(&mut f, "not-accepted", "sealed not accepted");
    let acceptance = accept::AcceptanceRequest::new(operation("accept-not-committed"), Revision::INITIAL,
        scope(), sealed.staged().operation().clone(), sealed.identity().clone());
    let fake = ActivationRequest::new(operation("activate-not-accepted"), Generation::INITIAL, acceptance);
    let before = snapshot(&f);
    assert!(matches!(store.activate(&fake, &f.seals), Err(Error::Invalid("activation requires committed acceptance"))));
    assert_eq!(before, snapshot(&f));
    let pending = prepare(&mut f, &store, &sealed, "accept-real", Revision::INITIAL);
    let accepted = store.submit(&pending, &f.seals).unwrap();
    let before = snapshot(&f);
    assert!(matches!(store.transition(&accepted, Stage::Activated), Err(Error::Invalid("use activation request API"))));
    assert!(matches!(store.transition(&accepted, Stage::Qualified), Err(Error::NotYet { requested: Stage::Qualified })));
    assert_eq!(before, snapshot(&f));
}

#[test]
fn canceled_activation_caller_is_recoverable_after_dispatcher_join() {
    let mut f = Fixture::new();
    let (store, accepted) = accepted(&mut f, "canceled-active", Revision::INITIAL);
    let request = request("activate-canceled", Generation::INITIAL, &accepted);
    let pending = store.prepare_activation(request.clone(), &f.seals).unwrap();
    let (response, caller) = std::sync::mpsc::channel();
    let (ready, waiting) = std::sync::mpsc::channel();
    let (resume, paused) = std::sync::mpsc::channel();
    std::thread::scope(|threads| {
        let worker = threads.spawn(|| {
            accept::on_activation_boundary(move || {
                ready.send(()).unwrap();
                paused.recv_timeout(WAIT).unwrap();
            });
            let result = store.submit_activation(&pending, &f.seals);
            assert!(result.is_ok());
            assert!(response.send(result).is_err());
        });
        waiting.recv_timeout(WAIT).unwrap();
        drop(caller);
        assert!(store.active(&scope()).unwrap().is_none());
        resume.send(()).unwrap();
        worker.join().unwrap();
    });
    let committed = reopen(&f).reconcile_activation(&request).unwrap().unwrap();
    assert_eq!(committed.request(), &request);
    assert_eq!(active_events(&f).len(), 1);
    println!("FIXED canceled activation receiver; dispatcher joined; exact operation reconciles one durable pointer");
}
