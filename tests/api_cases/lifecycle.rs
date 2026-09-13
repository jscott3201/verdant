use crate::{accept, access, api, binding, fixture::*, operations::*, seal, storage, support};
use api::{Api, Availability, PageRequest, Readiness};
use std::time::Duration;

fn published(
    f: &mut Fixture,
    tag: &str,
) -> (
    crate::domain::ids::OperationId,
    crate::domain::ids::OperationId,
) {
    let input = content(f, tag);
    let publication = publication(f);
    let draft = operation(&format!("api-draft-{tag}"));
    let seal = operation(&format!("api-seal-{tag}"));
    with_api(f, |api, credential| {
        api.draft(Some(credential), &draft, &input).unwrap();
        api.seal(Some(credential), &scope(), &seal, &draft, &publication)
            .unwrap();
    });
    (draft, seal)
}

#[test]
fn fixed_close_reopen_preserves_exact_accepted_revision_authorship_and_separate_active_generation()
{
    let mut f = Fixture::new();
    let (draft_one, seal_one) = published(&mut f, "restart-one");
    let one = with_api(&mut f, |api, credential| {
        api.accept(
            Some(credential),
            &scope(),
            &operation("api-accept-one"),
            &seal_one,
            accept::AcceptedRevision::INITIAL,
        )
        .unwrap()
    });
    let acceptance_owner = support::store(&f);
    acceptance_owner
        .activate(
            &accept::ActivationRequest::new(
                operation("base-existing-owner-activation"),
                accept::ActiveGeneration::INITIAL,
                one.request.clone(),
            ),
            &f.seals,
        )
        .unwrap();
    drop(acceptance_owner);
    let (draft_two, seal_two) = published(&mut f, "restart-two");
    let two = with_api(&mut f, |api, credential| {
        api.accept(
            Some(credential),
            &scope(),
            &operation("api-accept-two"),
            &seal_two,
            one.revision,
        )
        .unwrap()
    });
    assert_eq!(
        two.actor_reference,
        "capability=publisher-1;scope=scope-a;capgen=1;issuer=bootstrap-issuer-1"
    );
    let (stage_operation, draft_author) = with_api(&mut f, |api, credential| {
        let d = api.read(Some(credential), &scope(), &draft_two).unwrap();
        (d.staged_operation().clone(), d.author)
    });
    let staged = support::store(&f).read_staged(&stage_operation).unwrap();
    let events = support::events(&f);
    let bytes = support::bytes(&f);
    let Fixture {
        gate,
        credentials,
        registry,
        native,
        seals,
        scratch,
        ..
    } = f;
    drop(seals);
    drop(registry);
    drop(gate);
    let closed = native.close(); // every native clone above has been dropped
    {
        use std::fs::{OpenOptions, TryLockError};
        use std::time::{Duration, Instant};
        // All fixture native owners are dropped. Synchronize on the actual
        // writer LOCK, not a fixed delay or a retried product operation.
        let native_path = scratch.native();
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
    let gate = access::AccessGate::open(
        &scratch.db(),
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
    )
    .unwrap();
    let mut registry = binding::BindingRegistry::open(
        &scratch.db(),
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
    )
    .unwrap();
    let seals =
        seal::SealStore::open(registry.store().try_clone().unwrap(), native.clone()).unwrap();
    {
        let mut api = Api::new(&gate, &mut registry, &seals).unwrap();
        let status = api.status(Some(&credentials.publisher), &scope()).unwrap();
        assert_eq!(status.accepted.as_ref().unwrap().revision.get(), 2);
        assert_eq!(
            status.accepted.as_ref().unwrap().actor_reference,
            two.actor_reference
        );
        assert_eq!(status.accepted.as_ref().unwrap().request, two.request);
        assert_eq!(status.active.as_ref().unwrap().generation().get(), 1);
        assert_eq!(status.active.as_ref().unwrap().revision().get(), 1);
        assert_eq!(status.accepted_content, Availability::Available);
        assert_eq!(status.active_content, Some(Availability::Available));
        assert_eq!(status.operational, Readiness::Unknown);
        assert_eq!(
            api.read_accepted(Some(&credentials.publisher), &scope(), all())
                .unwrap()
                .unwrap()
                .items,
            staged
                .config()
                .entries()
                .values()
                .cloned()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            api.read_active(Some(&credentials.publisher), &scope(), all())
                .unwrap()
                .unwrap()
                .items,
            api.entries(Some(&credentials.publisher), &scope(), &draft_one, all())
                .unwrap()
                .items
        );
        assert_eq!(
            api.read(Some(&credentials.publisher), &scope(), &draft_two)
                .unwrap()
                .author,
            draft_author
        );
        assert_eq!(
            api.submit_accept(
                Some(&credentials.publisher),
                &scope(),
                &operation("api-accept-two")
            )
            .unwrap()
            .row_id,
            two.row_id
        );
    }
    assert_eq!(
        accept::AcceptanceStore::new(registry.store().try_clone().unwrap())
            .read_staged(&stage_operation)
            .unwrap(),
        staged
    );
    assert_eq!(registry.store().exec_script("SELECT id,seq,value_json FROM outbox WHERE operation='accept-revision-v1' ORDER BY id;").unwrap(), events);
    for (name, original) in bytes {
        let actual = std::fs::read(scratch.0.join(name)).ok();
        assert_eq!(actual, original);
    }
    drop(seals);
    drop(registry);
    drop(gate);
    drop(native.close());
    drop(scratch);
    println!("FIXED: all owners closed/reopened; exact accepted revision=2/authorship/bytes retained, active generation=1/revision=1; no native-open readiness inference");
}

#[test]
fn fixed_cancel_before_dispatch_is_inspectable_and_lost_caller_reconciles_after_join() {
    let mut f = Fixture::new();
    let (_, seal) = published(&mut f, "cancel");
    let canceled = operation("api-canceled");
    with_api(&mut f, |api, credential| {
        api.prepare_accept(
            Some(credential),
            &scope(),
            &canceled,
            &seal,
            accept::AcceptedRevision::INITIAL,
        )
        .unwrap();
        api.cancel(Some(credential), &scope(), &canceled).unwrap();
    });
    let before = (support::counts(&f), support::bytes(&f));
    with_api(&mut f, |api, credential| {
        let work = api.work(Some(credential), &scope(), &canceled).unwrap();
        assert!(work.cancel_requested && work.effect_known && work.effect_row.is_none());
        assert!(work.intent_row > 0);
        assert_eq!(
            api.submit_accept(Some(credential), &scope(), &canceled)
                .unwrap_err()
                .code(),
            "api-cancelled"
        );
    });
    assert_eq!((support::counts(&f), support::bytes(&f)), before);
    assert!(support::events(&f).is_empty());
    let lost = operation("api-lost-caller");
    with_api(&mut f, |api, credential| {
        api.prepare_accept(
            Some(credential),
            &scope(),
            &lost,
            &seal,
            accept::AcceptedRevision::INITIAL,
        )
        .unwrap();
    });
    let (send, receive) = std::sync::mpsc::channel();
    let (ready, waiting) = std::sync::mpsc::channel();
    let (resume, paused) = std::sync::mpsc::channel();
    std::thread::scope(|threads| {
        let worker = threads.spawn(|| {
            accept::on_boundary(move || {
                ready.send(()).unwrap();
                paused.recv_timeout(Duration::from_secs(20)).unwrap();
            });
            let mut api = Api::new(&f.gate, &mut f.registry, &f.seals).unwrap();
            let outcome = api
                .submit_accept(Some(&f.credentials.publisher), &scope(), &lost)
                .unwrap();
            assert!(send.send(outcome).is_err());
        });
        waiting.recv_timeout(Duration::from_secs(20)).unwrap();
        drop(receive); // cancellation of caller, not rollback of dispatched work
        resume.send(()).unwrap();
        worker.join().unwrap();
    });
    let before = (support::counts(&f), support::bytes(&f));
    with_api(&mut f, |api, credential| {
        let work = api.work(Some(credential), &scope(), &lost).unwrap();
        assert!(work.effect_known && work.effect_row.is_some());
        let result = api
            .submit_accept(Some(credential), &scope(), &lost)
            .unwrap();
        assert_eq!(Some(result.row_id), work.effect_row);
        assert!(result.reconciled);
    });
    assert_eq!((support::counts(&f), support::bytes(&f)), before);
    assert_eq!(support::events(&f).len(), 1);
    println!("FIXED: canceled prepared intent remains inspectable, no acceptance; dropped dispatched caller joined, retry reconciles exactly one accepted event");
}

#[test]
fn fixed_pagination_refuses_bounds_and_unavailable_content_does_not_erase_acceptance() {
    let mut f = Fixture::new();
    let (_, seal) = published(&mut f, "availability");
    let accepted = with_api(&mut f, |api, credential| {
        api.accept(
            Some(credential),
            &scope(),
            &operation("api-accept-availability"),
            &seal,
            accept::AcceptedRevision::INITIAL,
        )
        .unwrap()
    });
    let before = (support::counts(&f), support::bytes(&f));
    for (offset, size) in [(0, 0), (0, 65), (257, 1), (usize::MAX, 1), (0, usize::MAX)] {
        assert_eq!(
            PageRequest::new(offset, size).unwrap_err().code(),
            "api-limit"
        );
    }
    with_api(&mut f, |api, credential| {
        let first = api
            .operations(Some(credential), &scope(), PageRequest::new(0, 1).unwrap())
            .unwrap();
        assert_eq!(first.items.len(), 1);
        let second = api
            .operations(Some(credential), &scope(), first.next.unwrap())
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert_ne!(first.items[0].operation, second.items[0].operation);
        let last = api
            .operations(Some(credential), &scope(), second.next.unwrap())
            .unwrap();
        assert_eq!(last.items.len(), 1);
        assert!(last.next.is_none());
        assert!(api
            .operations(
                Some(credential),
                &scope(),
                PageRequest::new(256, 64).unwrap()
            )
            .unwrap()
            .items
            .is_empty());
    });
    assert_eq!((support::counts(&f), support::bytes(&f)), before);
    // Synthetic artifact loss, not a disk-full/power-loss qualification.
    std::fs::remove_file(
        f.scratch
            .native()
            .join(format!("SNAPSHOT-{:020}.logical", f.reference.generation())),
    )
    .unwrap();
    with_api(&mut f, |api, credential| {
        let status = api.status(Some(credential), &scope()).unwrap();
        assert_eq!(status.accepted.as_ref().unwrap().row_id, accepted.row_id);
        assert!(matches!(
            status.accepted_content,
            Availability::Unavailable {
                code: "accept-blocked",
                ..
            }
        ));
        assert!(matches!(status.operational, Readiness::Unavailable { .. }));
        assert_eq!(
            api.work(
                Some(credential),
                &scope(),
                &operation("api-accept-availability")
            )
            .unwrap()
            .effect_row,
            Some(accepted.row_id)
        );
    });
    assert_eq!(support::events(&f).len(), 1);
    println!("FIXED: every listing takes explicit bounded page; missing snapshot is unavailable, accepted event and authorship retained");
}
