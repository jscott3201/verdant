use crate::helpers::*;
use std::sync::{mpsc, Arc, Barrier};

#[test]
fn stale_callbacks_and_historical_recovery_never_restore_superseded_pointer() {
    let mut f = Fixture::new();
    let (store, one) = accepted(&mut f, "old", Revision::INITIAL);
    let old = request("activate-old", Generation::INITIAL, &one);
    let first = store.activate(&old, &f.seals).unwrap();
    let (_, two) = accepted(&mut f, "new", one.revision);
    let newer = request("activate-new", first.generation(), &two);
    let second = store.activate(&newer, &f.seals).unwrap();
    assert_eq!(second.generation().get(), 2);
    assert_eq!(second.revision().get(), 2);
    let before = snapshot(&f);
    for stale in [old.clone(), request("late-callback", Generation::INITIAL, &one)] {
        let error = store.activate(&stale, &f.seals).unwrap_err();
        assert_eq!(error.code(), "activation-stale-generation");
        assert!(matches!(error, Error::StaleGeneration { expected, current }
            if expected.get() == 0 && current.get() == 2));
    }
    // Even a fresh active token cannot authorize an older accepted revision.
    let old_target = request("fresh-token-old-target", second.generation(), &one);
    assert!(matches!(store.activate(&old_target, &f.seals),
        Err(Error::Superseded { requested, current }) if requested.get() == 1 && current.get() == 2));
    let historical = reopen(&f).reconcile_activation(&old).unwrap().unwrap();
    assert_eq!(historical.row_id(), first.row_id());
    assert_eq!(store.active(&scope()).unwrap().unwrap().row_id(), second.row_id());
    assert_eq!(before, snapshot(&f));
    println!("FIXED old callback expected=0/current=2 refused; fresh-token old target superseded; historical reconcile leaves active revision=2; rows/bytes identical");
}

#[test]
fn two_concurrent_activations_have_one_cas_winner() {
    let mut f = Fixture::new();
    let (store, accepted) = accepted(&mut f, "race", Revision::INITIAL);
    let a = store.prepare_activation(request("activate-race-a", Generation::INITIAL, &accepted), &f.seals).unwrap();
    let b = store.prepare_activation(request("activate-race-b", Generation::INITIAL, &accepted), &f.seals).unwrap();
    let before = counts(&f);
    let barrier = Arc::new(Barrier::new(2));
    let (ready, waiting) = mpsc::channel();
    let (left, right) = std::thread::scope(|threads| {
        let barrier_a = barrier.clone();
        let left = threads.spawn(|| {
            accept::on_activation_boundary(move || {
                ready.send(()).unwrap();
                barrier_a.wait();
            });
            store.submit_activation(&a, &f.seals)
        });
        waiting.recv_timeout(WAIT).unwrap(); // seal custody is fail-fast, not queued
        let right = threads.spawn(|| {
            accept::on_activation_boundary(move || { barrier.wait(); });
            store.submit_activation(&b, &f.seals)
        });
        (left.join().unwrap(), right.join().unwrap())
    });
    let (winner, loser, lost) = match (left, right) {
        (Ok(winner), Err(loser)) => (winner, loser, b.request()),
        (Err(loser), Ok(winner)) => (winner, loser, a.request()),
        results => panic!("expected one CAS winner: {results:?}"),
    };
    assert!(matches!(loser, Error::StaleGeneration { expected, current }
        if expected.get() == 0 && current.get() == 1));
    assert_eq!(active_events(&f).len(), 1);
    assert_eq!(store.active(&scope()).unwrap().unwrap().row_id(), winner.row_id());
    assert!(store.reconcile_activation(lost).unwrap().is_none());
    one_effect(&before, &counts(&f));
    let before_retry = snapshot(&f);
    assert_eq!(store.activate(winner.request(), &f.seals).unwrap().row_id(), winner.row_id());
    assert_eq!(before_retry, snapshot(&f));
    println!("FIXED concurrent activation winners=1 stale=1 active_events=1 receipt_delta=1 mark_delta=0; loser has no receipt; winning retry rows/bytes identical");
}

#[test]
fn supersede_during_native_check_window_refuses_old_callback_at_admission() {
    let mut f = Fixture::new();
    let (store, one) = accepted(&mut f, "supersede-old", Revision::INITIAL);
    let (_, next_seal) = publish(&mut f, "supersede-new", "newer accepted label");
    let next = prepare(&mut f, &store, &next_seal, "accept-supersede-new", one.revision);
    let old = store.prepare_activation(request("activate-superseded", Generation::INITIAL, &one), &f.seals).unwrap();
    let (ready, waiting) = mpsc::channel();
    let (resume, paused) = mpsc::channel();
    let (old_result, winner) = std::thread::scope(|threads| {
        let worker = threads.spawn(|| {
            accept::on_activation_boundary(move || {
                ready.send(()).unwrap();
                paused.recv_timeout(WAIT).unwrap();
            });
            store.submit_activation(&old, &f.seals)
        });
        waiting.recv_timeout(WAIT).unwrap();
        let two = store.submit(&next, &f.seals).unwrap();
        // Acceptance has superseded the request while active generation is still 0.
        // The old ticket must lose on accepted identity, not just active CAS.
        let before = snapshot(&f);
        resume.send(()).unwrap();
        let result = worker.join().unwrap();
        assert_eq!(before, snapshot(&f));
        let winner = store.activate(&request("activate-supersede-new", Generation::INITIAL, &two), &f.seals).unwrap();
        (result, winner)
    });
    assert!(matches!(old_result, Err(Error::Superseded { requested, current })
        if requested.get() == 1 && current.get() == 2));
    assert!(store.reconcile_activation(old.request()).unwrap().is_none());
    assert_eq!(winner.revision().get(), 2);
    assert_eq!(winner.generation().get(), 1); // accepted revision 1 deliberately skipped
    assert_eq!(active_events(&f).len(), 1);
    println!("FIXED concurrent supersede: accepted=2 wins; old expected-active=0 loses accepted CAS, no receipt/bytes; active revision=2 generation=1, winners=1");
}

#[test]
fn superseding_activation_wins_while_old_callback_is_in_flight() {
    let mut f = Fixture::new();
    let (store, one) = accepted(&mut f, "inflight-old", Revision::INITIAL);
    let (_, next_seal) = publish(&mut f, "inflight-new", "superseding publication");
    let next = prepare(&mut f, &store, &next_seal, "accept-inflight-new", one.revision);
    let old = store.prepare_activation(request("activate-inflight-old", Generation::INITIAL, &one), &f.seals).unwrap();
    let (ready, waiting) = mpsc::channel();
    let (resume, paused) = mpsc::channel();
    let seals = &f.seals;
    let (result, winner) = std::thread::scope(|threads| {
        let worker = threads.spawn(|| {
            accept::on_activation_boundary(move || {
                ready.send(()).unwrap();
                paused.recv_timeout(WAIT).unwrap();
            });
            store.submit_activation(&old, seals)
        });
        waiting.recv_timeout(WAIT).unwrap();
        let two = store.submit(&next, seals).unwrap();
        let winner = store.activate(&request("activate-inflight-new", Generation::INITIAL, &two), seals).unwrap();
        let before = snapshot(&f);
        resume.send(()).unwrap();
        let result = worker.join().unwrap();
        assert_eq!(before, snapshot(&f));
        (result, winner)
    });
    assert!(matches!(result, Err(Error::StaleGeneration { expected, current })
        if expected.get() == 0 && current.get() == 1), "{result:?}");
    assert_eq!(winner.revision().get(), 2);
    assert_eq!(active_events(&f).len(), 1);
    assert!(store.reconcile_activation(old.request()).unwrap().is_none());
    println!("FIXED inflight old callback loses to completed superseding activation; winners=1 active generation=1 revision=2, old operation absent");
}

#[test]
fn slow_unrelated_scope_edit_does_not_hold_activation_or_reconciliation() {
    let mut f = Fixture::new();
    let (store, accepted) = accepted(&mut f, "independent", Revision::INITIAL);
    let request = request("activate-independent", Generation::INITIAL, &accepted);
    let ticket = store.prepare_activation(request.clone(), &f.seals).unwrap();
    let other_scope = crate::domain::scope::TrustedScope::parse("scope-b").unwrap();
    let (ready, waiting) = mpsc::channel();
    let (resume, paused) = mpsc::channel();
    let seals = &f.seals;
    let active = std::thread::scope(|threads| {
        let edit = threads.spawn(|| {
            crate::binding::writer::on_boundary(move || {
                ready.send(()).unwrap();
                paused.recv_timeout(WAIT).unwrap();
            });
            f.registry.record_equipment("vav-101", crate::binding::EquipmentKind::Vav,
                other_scope.clone(), "slow unrelated model edit", "mstp://vav-101")
        });
        waiting.recv_timeout(WAIT).unwrap();
        // The edit stays paused until BOTH activation and receipt recovery finish.
        let active = store.submit_activation(&ticket, seals).unwrap();
        let reconciled = store.reconcile_activation(&request).unwrap().unwrap();
        assert_eq!(active.row_id(), reconciled.row_id());
        resume.send(()).unwrap();
        edit.join().unwrap().unwrap();
        active
    });
    assert_eq!(store.activate(&request, &f.seals).unwrap().row_id(), active.row_id());
    assert!(store.active(&other_scope).unwrap().is_none());
    assert_eq!(active_events(&f).len(), 1);
    assert_eq!(store.reconcile_activation(&request).unwrap().unwrap().row_id(), active.row_id());
    println!("FIXED scope-b edit paused before writer; scope-a activation + reconcile finish independently; later binding revision change does not invalidate active replay");
}
