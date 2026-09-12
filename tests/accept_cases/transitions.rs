use super::support::*;
use crate::{
    accept::{self, AcceptedRevision as Revision, Error, Stage},
    fixture::*,
    storage::sqlite::faults::{inject as inject_fault, Fault as AdmissionFault},
};

#[test]
fn fixed_stages_events_reopen_and_not_yet_seam() {
    let mut f = Fixture::new();
    let store = store(&f);
    let config = config(&mut f, "AHU supply air");
    let op = operation("accept-stage-states");
    let staged = store.stage(&op, config, vec![f.finding.clone()]).unwrap();
    assert_eq!(staged.stage(), Stage::Staged);
    assert_eq!(store.read_staged(&op).unwrap(), staged);
    assert!(store.current(&scope()).unwrap().is_none());
    let seal = f
        .seal(
            "seal-states",
            &f.draft_with(vec![staged.root().unwrap()], "pr08a-states"),
        )
        .unwrap();
    let sealed = store.sealed(&staged, &seal.identity, &f.seals).unwrap();
    assert_eq!(sealed.stage(), Stage::Sealed);
    assert_eq!(store.status(&sealed).unwrap(), Stage::Sealed);
    let pending = prepare(&mut f, &store, &sealed, "accept-states", Revision::INITIAL);
    assert!(events(&f).is_empty());
    let accepted: accept::Accepted = store.submit(&pending, &f.seals).unwrap();
    assert_eq!(accepted.stage(), Stage::Accepted);
    assert_eq!(accepted.revision.get(), 1);
    assert_eq!(events(&f).len(), 1);
    let reopened = reopen(&f);
    assert_eq!(reopened.status(&sealed).unwrap(), Stage::Accepted);
    assert_eq!(
        reopened.current(&scope()).unwrap().unwrap().row_id,
        accepted.row_id
    );
    assert_eq!(reopened.read_staged(&op).unwrap(), staged);
    let before = (counts(&f), bytes(&f));
    for stage in [Stage::Activated, Stage::Qualified] {
        let error = store.transition(&accepted, stage).unwrap_err();
        assert_eq!(error.code(), "accept-not-yet");
        assert!(matches!(error, Error::NotYet { requested } if requested == stage));
    }
    assert_eq!(before, (counts(&f), bytes(&f)));
    println!("FIXED staged -> sealed -> accepted revision=1 event_row={} reopened; activated/qualified=not-yet, rows+bytes unchanged", accepted.row_id);
}

#[test]
fn fixed_successor_is_additive_and_stale_expectation_never_rolls_back() {
    let mut f = Fixture::new();
    let (store, first) = publish(&mut f, "successor-a", "old label");
    let pending = prepare(
        &mut f,
        &store,
        &first,
        "accept-successor-a",
        Revision::INITIAL,
    );
    let one = store.submit(&pending, &f.seals).unwrap();
    let (_, second) = publish(&mut f, "successor-b", "cosmetic edit");
    let next = prepare(&mut f, &store, &second, "accept-successor-b", one.revision);
    let two = store.submit(&next, &f.seals).unwrap();
    assert_eq!(two.revision.get(), 2);
    assert_eq!(events(&f).len(), 2);
    assert_eq!(store.status(&first).unwrap(), Stage::Accepted);
    assert_eq!(store.status(&second).unwrap(), Stage::Accepted);
    assert_eq!(
        reopen(&f).current(&scope()).unwrap().unwrap().row_id,
        two.row_id
    );
    let stale = prepare(&mut f, &store, &first, "accept-stale", Revision::INITIAL);
    let before = (events(&f), counts(&f), bytes(&f));
    assert!(matches!(
        store.submit(&stale, &f.seals),
        Err(Error::Conflict(_))
    ));
    assert_eq!(before, (events(&f), counts(&f), bytes(&f)));
    assert_eq!(
        store.reconcile(pending.request()).unwrap().unwrap().row_id,
        one.row_id
    );
    assert_eq!(store.current(&scope()).unwrap().unwrap().row_id, two.row_id);
    println!("FIXED revisions=1,2 additive; stale expected=0 Conflict; historical recovery does not roll back current head");
}

#[test]
fn fixed_prepared_authority_is_not_a_cached_grant() {
    let mut f = Fixture::new();
    let (store, sealed) = publish(&mut f, "revoke", "label");
    let pending = prepare(&mut f, &store, &sealed, "accept-revoked", Revision::INITIAL);
    f.gate
        .revoke(
            &f.credentials.publisher,
            &crate::access::Reason::parse("synthetic revoked before admission").unwrap(),
        )
        .unwrap();
    let before = (counts(&f), bytes(&f));
    let error = store.submit(&pending, &f.seals).unwrap_err();
    assert!(matches!(error, Error::Conflict(_)));
    assert_eq!(before, (counts(&f), bytes(&f)));
    assert!(events(&f).is_empty());
    assert!(store.reconcile(pending.request()).unwrap().is_none());
}

#[test]
fn fixed_release_between_availability_and_writer_admission_conflicts() {
    let mut f = Fixture::new();
    let (store, sealed) = publish(&mut f, "release-race", "label");
    let pending = prepare(
        &mut f,
        &store,
        &sealed,
        "accept-release-race",
        Revision::INITIAL,
    );
    let before = counts(&f);
    let (ready, at_boundary) = std::sync::mpsc::channel();
    let (resume, continue_work) = std::sync::mpsc::channel();
    let seals = &f.seals;
    let result = std::thread::scope(|threads| {
        let worker = threads.spawn(|| {
            accept::on_boundary(move || {
                ready.send(()).unwrap();
                continue_work.recv().unwrap();
            });
            store.submit(&pending, seals)
        });
        at_boundary.recv().unwrap();
        seals
            .release(
                &operation("release-during-accept"),
                sealed.identity(),
                &mut f.registry,
                &f.gate,
                &f.credentials.publisher,
            )
            .unwrap();
        resume.send(()).unwrap();
        worker.join().unwrap()
    });
    assert!(matches!(result, Err(Error::Conflict(_))));
    assert!(events(&f).is_empty());
    assert!(store.reconcile(pending.request()).unwrap().is_none());
    let after = counts(&f);
    assert_eq!(
        after[0][0].parse::<u64>().unwrap(),
        before[0][0].parse::<u64>().unwrap() + 1
    );
    assert_eq!(
        after[0][1].parse::<u64>().unwrap(),
        before[0][1].parse::<u64>().unwrap() + 1
    );
    println!("FIXED seal release proceeds while acceptance paused without locks; admission conflicts, only release row+receipt survive");
}

#[test]
fn fixed_conflicting_expected_revisions_have_one_winner_and_zero_row_conflict() {
    let mut f = Fixture::new();
    let (store, first) = publish(&mut f, "race-a", "first label");
    let (_, second) = publish(&mut f, "race-b", "second label");
    let a = prepare(&mut f, &store, &first, "accept-race-a", Revision::INITIAL);
    let b = prepare(&mut f, &store, &second, "accept-race-b", Revision::INITIAL);
    // Serialize only seal availability checks (seal uses fail-fast custody).
    // First then waits WITHOUT a lock; both enter writer admission together.
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let before = counts(&f);
    let (left, right) = std::thread::scope(|threads| {
        let barrier_a = barrier.clone();
        let left = threads.spawn(|| {
            accept::on_boundary(move || {
                ready_tx.send(()).unwrap();
                barrier_a.wait();
            });
            store.submit(&a, &f.seals)
        });
        ready_rx.recv().unwrap();
        let right = threads.spawn(|| {
            accept::on_boundary(move || {
                barrier.wait();
            });
            store.submit(&b, &f.seals)
        });
        (left.join().unwrap(), right.join().unwrap())
    });
    let (winner, loser, lost_request) = match (left, right) {
        (Ok(winner), Err(loser)) => (winner, loser, b.request()),
        (Err(loser), Ok(winner)) => (winner, loser, a.request()),
        results => panic!("expected one winner: {results:?}"),
    };
    assert!(matches!(&loser, Error::Conflict(detail) if detail.contains("zero affected rows")));
    assert_eq!(loser.code(), "accept-conflict");
    assert_eq!(events(&f).len(), 1);
    let after = counts(&f);
    assert_eq!(
        after[0][0].parse::<u64>().unwrap(),
        before[0][0].parse::<u64>().unwrap() + 1
    );
    assert_eq!(
        after[0][1].parse::<u64>().unwrap(),
        before[0][1].parse::<u64>().unwrap() + 1
    );
    assert_eq!(after[0][2], before[0][2]);
    assert!(store.reconcile(lost_request).unwrap().is_none());
    assert_eq!(
        store.current(&scope()).unwrap().unwrap().row_id,
        winner.row_id
    );
    println!("FIXED concurrent expected=0 winners=1 Conflict=1 events=1 receipt_delta=1; loser has no receipt; {loser}");
}

#[test]
fn fixed_lost_response_reconciles_same_event_and_reused_identity_refuses() {
    let mut f = Fixture::new();
    let (store, sealed) = publish(&mut f, "lost", "label");
    let pending = prepare(&mut f, &store, &sealed, "accept-lost", Revision::INITIAL);
    inject_fault(&f.scratch.db(), AdmissionFault::LostResponse);
    let first = store.submit(&pending, &f.seals).unwrap();
    assert!(first.reconciled);
    let snapshot = (events(&f), counts(&f), bytes(&f));
    let repeated = store.submit(&pending, &f.seals).unwrap();
    let recovered = reopen(&f).reconcile(pending.request()).unwrap().unwrap();
    assert_eq!(first.row_id, repeated.row_id);
    assert_eq!(first, recovered);
    let wrong = accept::AcceptanceRequest::new(
        pending.request().operation().clone(),
        Revision::new(1).unwrap(),
        scope(),
        sealed.staged().operation().clone(),
        sealed.identity().clone(),
    );
    assert!(matches!(store.reconcile(&wrong), Err(Error::Conflict(_))));
    assert_eq!(snapshot, (events(&f), counts(&f), bytes(&f)));
    println!("FIXED lost-response/retry/reopen event_row={} events=1 identical rows/bytes; mismatched identity refused", first.row_id);
}

#[test]
fn fixed_precommit_interruption_has_zero_rows_receipts_and_identical_bytes() {
    let mut f = Fixture::new();
    let (store, sealed) = publish(&mut f, "interrupted", "label");
    let pending = prepare(
        &mut f,
        &store,
        &sealed,
        "accept-interrupted",
        Revision::INITIAL,
    );
    let before = (counts(&f), bytes(&f));
    inject_fault(&f.scratch.db(), AdmissionFault::BeforeCommit);
    let error = store.submit(&pending, &f.seals).unwrap_err();
    assert!(
        matches!(error, Error::Storage(crate::storage::StorageError::SqliteFailure { ref detail }) if detail.contains("injected precommit interruption"))
    );
    assert!(events(&f).is_empty());
    assert!(store.reconcile(pending.request()).unwrap().is_none());
    assert!(reopen(&f).current(&scope()).unwrap().is_none());
    assert_eq!(before, (counts(&f), bytes(&f)));
    println!("FIXED before-COMMIT interruption event_delta=0 receipt_delta=0 mark_delta=0 main/WAL/SHM byte-identical; no timeout inference");
}

#[test]
fn fixed_canceled_caller_leaves_inspectable_and_reconcilable_operation() {
    let mut f = Fixture::new();
    let (store, sealed) = publish(&mut f, "canceled", "label");
    let pending = prepare(
        &mut f,
        &store,
        &sealed,
        "accept-canceled",
        Revision::INITIAL,
    );
    let retained = pending.request().clone();
    let (response, caller) = std::sync::mpsc::channel();
    let (ready, at_boundary) = std::sync::mpsc::channel();
    let (resume, continue_work) = std::sync::mpsc::channel();
    std::thread::scope(|threads| {
        let worker = threads.spawn(|| {
            accept::on_boundary(move || {
                ready.send(()).unwrap();
                continue_work.recv().unwrap();
            });
            let result = store.submit(&pending, &f.seals);
            assert!(result.is_ok());
            assert!(response.send(result).is_err());
        });
        at_boundary.recv().unwrap();
        drop(caller); // caller canceled while operation is in flight, not after completion
        assert!(store.current(&scope()).unwrap().is_none());
        resume.send(()).unwrap();
        worker.join().unwrap(); // absence/commit only interpreted AFTER dispatcher joins
    });
    let committed = reopen(&f).reconcile(&retained).unwrap().unwrap();
    assert_eq!(committed.request, retained);
    assert_eq!(events(&f).len(), 1);
    assert_eq!(
        store.current(&scope()).unwrap().unwrap().row_id,
        committed.row_id
    );
    println!(
        "FIXED canceled receiver; joined dispatcher; retained operation={} event_row={} events=1",
        retained.operation().as_str(),
        committed.row_id
    );
}

#[test]
fn fixed_missing_native_content_on_reopen_blocks_new_acceptance() {
    let mut f = Fixture::new();
    let (store, sealed) = publish(&mut f, "missing", "label");
    let pending = prepare(&mut f, &store, &sealed, "accept-missing", Revision::INITIAL);
    for seq in 2..=4 {
        f.native
            .execute(&format!("INSERT (:Reading {{seq: {seq}}})"))
            .unwrap();
        f.native.checkpoint().unwrap().completed().unwrap();
    }
    let before = (counts(&f), bytes(&f));
    let generation = f.reference.generation();
    let native_path = f.scratch.native();
    let db_path = f.scratch.db();
    drop(f.seals);
    drop(f.native);
    std::fs::remove_file(native_path.join(format!("SNAPSHOT-{generation:020}.logical"))).unwrap();
    // Reopen is a concrete native attempt. Missing required native data may
    // itself refuse; if it opens, recovered seal availability must refuse.
    match crate::native::NativeHandle::open(&native_path, crate::native::NativeSettings::local()) {
        Ok((native, _)) => {
            let seals = availability_store(&db_path, native);
            assert!(matches!(
                store.submit(&pending, &seals),
                Err(Error::Blocked(_))
            ));
        }
        Err(error) => {
            panic!("fixture requires an older retained snapshot, got reopen refusal: {error}")
        }
    }
    // Remaining fields stay usable after dropping native owners.
    let after = f.registry.store().exec_script("SELECT (SELECT COUNT(*) FROM outbox),(SELECT COUNT(*) FROM storage_receipts),(SELECT COUNT(*) FROM derived_marks);").unwrap();
    assert_eq!(before.0, after);
    assert!(store.reconcile(pending.request()).unwrap().is_none());
    assert!(store.current(&scope()).unwrap().is_none());
    for (name, expected) in before.1 {
        let actual = std::fs::read(f.scratch.0.join(name)).ok();
        assert_eq!(actual, expected);
    }
    println!("FIXED native reopen missing sealed snapshot BLOCKS acceptance; events=0 rows/SQLite bytes unchanged");
}
