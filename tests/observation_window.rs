//! D01–D10 synthetic temp-store evidence, not parent PR03 closure or field use.
#![allow(dead_code)]
#[path = "../src/accept/mod.rs"]
mod accept;
#[path = "../src/access/mod.rs"]
mod access;
#[path = "../src/api/mod.rs"]
mod api;
#[path = "bacnet_cases/support.rs"]
mod bacnet_support;
#[path = "../src/binding/mod.rs"]
mod binding;
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "runtime_cases/helpers.rs"]
mod helpers;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "../src/observation/mod.rs"]
mod observation;
#[path = "observation_cases/support.rs"]
mod observation_support;
#[path = "../src/runtime/mod.rs"]
mod runtime;
#[path = "../src/seal/mod.rs"]
mod seal;
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "../src/storage/mod.rs"]
mod storage;
#[path = "accept_cases/support.rs"]
mod support;

use observation::{
    identity::ProducerId, normalize::Codec, window::*, BindingContext, NormalizedObservation,
};
use observation_support::{bytes, clock, incarnation, key, unit, Harness};
use storage::{
    sqlite::{
        faults::{self, Fault},
        MutationOutcome, SqliteStore,
    },
    ConnectionSettings, StoreBounds,
};
fn access(h: &Harness) -> Access<'_> {
    Access {
        gate: &h.gate,
        credential: Some(&h.credentials.reviewer),
    }
}
fn open(h: &Harness, checkpoint: Option<&Checkpoint>) -> Window {
    let store = SqliteStore::open(
        &h.scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .unwrap()
    .0;
    Window::open_synthetic(
        store,
        access(h),
        fixture::scope(),
        ProducerId::parse("sensor-sat-producer").unwrap(),
        incarnation("process-b"),
        checkpoint,
    )
    .unwrap()
}
fn row(h: &Harness, window: &Window, value: &[u8], ms: u64) -> NormalizedObservation {
    let raw = bytes(value, ms);
    window
        .identify(
            access(h),
            h.pending(&raw, &h.context, Codec::Scalar, unit(), ms),
        )
        .unwrap()
}
fn committed(result: MutationOutcome) {
    assert!(
        matches!(result, MutationOutcome::Committed { .. }),
        "{result:?}"
    );
}
fn capture(
    h: &Harness,
    window: &Window,
    row: &NormalizedObservation,
    class: Retention,
    ms: u64,
) -> observation::spool::Capture {
    let ticket = window
        .prepare_capture(access(h), row, class, &clock(ms))
        .unwrap();
    committed(
        window
            .submit_capture(access(h), &ticket, &clock(ms))
            .unwrap(),
    );
    ticket
}
fn append(h: &Harness, window: &Window, n: u64, class: Retention) -> NormalizedObservation {
    let row = row(h, window, &[0x21, 7], 1000 + n);
    capture(h, window, &row, class, 1000 + n);
    row
}
fn sql(h: &Harness, query: &str) -> Vec<Vec<String>> {
    h.registry.store().exec_script(query).unwrap()
}

#[test]
fn d01_slow_subscriber_recovers_or_reads_durable_explicit_tombstones() {
    let h = Harness::new();
    let w = open(&h, None);
    for n in 0..12 {
        append(&h, &w, n, Retention::OptionalHistory);
    }
    let page = w.replay(access(&h), 0, 64).unwrap();
    assert_eq!(page.records.len(), 12);
    assert!(page.gaps.is_empty());
    assert!(!page.more);
    assert_eq!(w.evict(access(&h), &clock(1100)).unwrap(), 8);
    let checkpoint = w.checkpoint(access(&h)).unwrap();
    drop(w);
    let w = open(&h, Some(&checkpoint));
    let page = w.replay(access(&h), 0, 64).unwrap();
    assert_eq!(
        page.records
            .iter()
            .map(|r| r.id.position().seq())
            .collect::<Vec<_>>(),
        vec![8, 9, 10, 11]
    );
    assert_eq!(
        page.gaps,
        vec![storage::observation_writer::Gap {
            from: 0,
            to: 7,
            reason: "window-evicted".into()
        }]
    );
    assert_eq!(page.next, 12);
    let page = w.replay(access(&h), 4, 2).unwrap();
    assert_eq!(
        (page.gaps[0].from, page.gaps[0].to, page.next, page.more),
        (4, 5, 6, true)
    );
    assert_eq!(
        w.replay(access(&h), 0, 0).unwrap_err().code(),
        "replay-limit"
    );
}

#[test]
fn d02_optional_slots_cannot_borrow_mandatory_reserve() {
    let h = Harness::new();
    let w = open(&h, None);
    for n in 0..28 {
        append(&h, &w, n, Retention::OptionalHistory);
    }
    let refused = row(&h, &w, &[0x21, 0], 1100);
    let before = w.checkpoint(access(&h)).unwrap();
    assert_eq!(
        w.prepare_capture(
            access(&h),
            &refused,
            Retention::OptionalHistory,
            &clock(1100)
        )
        .unwrap_err()
        .code(),
        "mandatory-reserve"
    );
    assert_eq!(w.checkpoint(access(&h)).unwrap(), before);
    for n in 0..4 {
        append(&h, &w, 100 + n, Retention::Mandatory);
    }
    let row = row(&h, &w, &[0x21, 0], 1200);
    assert_eq!(
        w.prepare_capture(access(&h), &row, Retention::Mandatory, &clock(1200))
            .unwrap_err()
            .code(),
        "spool-full-escalate"
    );
    assert_eq!(w.replay(access(&h), 0, 64).unwrap().records.len(), 32);
}

#[test]
fn d03_pin_limit_ttl_exact_readback_and_owned_materialization() {
    let h = Harness::new();
    let w = open(&h, None);
    let observation = append(&h, &w, 0, Retention::OptionalHistory);
    let expected = w.read(access(&h), observation.id()).unwrap().unwrap();
    assert_eq!(
        expected.value.to_json(),
        "{\"type\":\"integer\",\"value\":\"7\"}"
    );
    assert_eq!(expected.raw_evidence, format!("{observation:?}"));
    let pins = (0..8)
        .map(|_| w.pin(access(&h), observation.id(), &clock(1000)).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        w.pin(access(&h), observation.id(), &clock(1000))
            .unwrap_err()
            .code(),
        "pin-full"
    );
    let checkpoint = w.checkpoint(access(&h)).unwrap();
    drop(w);
    let w = open(&h, Some(&checkpoint));
    assert_eq!(
        w.materialize(access(&h), &pins[0], &clock(35_999)).unwrap(),
        expected
    );
    assert_eq!(
        w.materialize(access(&h), &pins[0], &clock(36_000))
            .unwrap_err()
            .code(),
        "pin-expired"
    );
    assert_eq!(
        w.materialize(access(&h), &pins[0], &clock(999))
            .unwrap_err()
            .code(),
        "clock-ambiguous"
    );
    let mut uncertain = clock(1100);
    uncertain.continuity = observation::time::Continuity::WallOrSuspendAmbiguous;
    assert_eq!(
        w.materialize(access(&h), &pins[0], &uncertain)
            .unwrap_err()
            .code(),
        "clock-ambiguous"
    );
    let owned = w.materialize(access(&h), &pins[1], &clock(1100)).unwrap();
    w.release_pin(access(&h), &pins[1]).unwrap();
    assert_eq!(owned, expected);
    assert_eq!(
        w.materialize(access(&h), &pins[1], &clock(1100))
            .unwrap_err()
            .code(),
        "pin-not-held"
    );
    let fresh = w.pin(access(&h), observation.id(), &clock(36_000)).unwrap();
    assert_ne!(fresh, pins[0]);
    assert_eq!(fresh.expires_ms(), 71_000);
}

#[test]
fn d04_eviction_spares_pins_current_and_unsettled_mandatory_records() {
    let h = Harness::new();
    let w = open(&h, None);
    w.select_binding(access(&h), &h.context).unwrap();
    let mandatory = append(&h, &w, 0, Retention::Mandatory);
    let held = append(&h, &w, 1, Retention::OptionalHistory);
    let pin = w.pin(access(&h), held.id(), &clock(1001)).unwrap();
    let mut latest = held.clone();
    for n in 2..12 {
        latest = append(&h, &w, n, Retention::OptionalHistory);
    }
    assert_eq!(w.evict(access(&h), &clock(1100)).unwrap(), 8);
    assert!(w.read(access(&h), mandatory.id()).unwrap().is_some());
    assert_eq!(
        w.materialize(access(&h), &pin, &clock(1100)).unwrap().id,
        *held.id()
    );
    assert_eq!(
        w.current(access(&h), &key()).unwrap().unwrap().id,
        *latest.id()
    );
    w.settle(access(&h), mandatory.id()).unwrap();
    w.release_pin(access(&h), &pin).unwrap();
    assert_eq!(w.evict(access(&h), &clock(1100)).unwrap(), 2);
    assert!(w.read(access(&h), mandatory.id()).unwrap().is_none());
    assert!(w.read(access(&h), held.id()).unwrap().is_none());
}

#[test]
fn d05_receipt_expiry_cannot_re_admit_still_valid_stale_ticket() {
    let h = Harness::new();
    let w = open(&h, None);
    let row = row(&h, &w, &[0x21, 7], 1000);
    let ticket = capture(&h, &w, &row, Retention::OptionalHistory, 1000);
    // 64 later journal revisions within the *same* 35s admission lifetime.
    // Expire replay defense by actual owner operations, not raw DB deletion.
    for _ in 0..33 {
        let pin = w.pin(access(&h), row.id(), &clock(1000)).unwrap();
        w.release_pin(access(&h), &pin).unwrap();
    }
    let before = w.checkpoint(access(&h)).unwrap();
    assert!(matches!(
        w.reconcile_capture(access(&h), &ticket).unwrap(),
        MutationOutcome::Unknown { .. }
    ));
    assert!(matches!(
        w.reconcile_saved_capture(access(&h), ticket.reconciliation_bytes())
            .unwrap(),
        MutationOutcome::Unknown { .. }
    ));
    let retry = w.submit_capture(access(&h), &ticket, &clock(1001)).unwrap();
    assert!(
        !matches!(retry, MutationOutcome::Committed { .. }),
        "{retry:?}"
    );
    assert_eq!(w.checkpoint(access(&h)).unwrap(), before);
    assert_eq!(w.replay(access(&h), 0, 64).unwrap().records.len(), 1);
    assert_eq!(
        w.submit_capture(access(&h), &ticket, &clock(36_000))
            .unwrap_err()
            .code(),
        "capture-expired"
    );
    assert_eq!(
        w.read(access(&h), row.id())
            .unwrap()
            .unwrap()
            .dependent_value()
            .unwrap_err()
            .code(),
        "replayed-evidence-not-fresh"
    );
    assert_eq!(
        sql(
            &h,
            "SELECT count(*) FROM storage_receipts WHERE operation GLOB 'obw:ticket:*';"
        ),
        vec![vec!["64"]]
    );
}

#[test]
fn d06_interrupted_append_and_lost_response_reconcile_same_identity() {
    let h = Harness::new();
    let w = open(&h, None);
    let row = row(&h, &w, &[0x21, 7], 1000);
    let ticket = w
        .prepare_capture(access(&h), &row, Retention::OptionalHistory, &clock(1000))
        .unwrap();
    faults::inject(&h.scratch.db(), Fault::BeforeCommit);
    assert!(matches!(
        w.submit_capture(access(&h), &ticket, &clock(1000)).unwrap(),
        MutationOutcome::NotCommitted { .. }
    ));
    assert!(w.read(access(&h), row.id()).unwrap().is_none());
    assert_eq!(w.checkpoint(access(&h)).unwrap().next, 0);
    faults::inject(&h.scratch.db(), Fault::LostResponse);
    assert!(matches!(
        w.submit_capture(access(&h), &ticket, &clock(1000)).unwrap(),
        MutationOutcome::Unknown { .. }
    ));
    let saved = ticket.reconciliation_bytes().to_string();
    committed(w.reconcile_capture(access(&h), &ticket).unwrap());
    committed(w.submit_capture(access(&h), &ticket, &clock(1001)).unwrap());
    w.reconcile_observation(access(&h), &row).unwrap();
    let conflicting = h
        .pending(
            &bytes(&[0x21, 8], 1000),
            &h.context,
            Codec::Scalar,
            unit(),
            1000,
        )
        .identify(row.id().clone(), row.incarnation().clone())
        .unwrap();
    assert_eq!(
        w.reconcile_observation(access(&h), &conflicting)
            .unwrap_err()
            .code(),
        "identity-conflict"
    );
    assert_eq!(w.checkpoint(access(&h)).unwrap().next, 1);
    assert_eq!(w.replay(access(&h), 0, 64).unwrap().records.len(), 1);
    let checkpoint = w.checkpoint(access(&h)).unwrap();
    drop(ticket);
    drop(w);
    let w = open(&h, Some(&checkpoint));
    committed(w.reconcile_saved_capture(access(&h), &saved).unwrap());
    let changed = saved.replace("obw-synthetic-v1", "obw-synthetic-v0");
    assert!(matches!(
        w.reconcile_saved_capture(access(&h), &changed).unwrap(),
        MutationOutcome::Conflict { .. }
    ));
    assert_eq!(w.checkpoint(access(&h)).unwrap().next, 1);
}

#[test]
fn d02_byte_reserve_and_d04_eviction_byte_batch_are_independent_of_slots() {
    let h = Harness::new();
    // Payload ceiling raised only for this isolated byte-budget fixture; E02
    // spool/reserve/eviction limits themselves remain the exact approved values.
    let mut bounds = StoreBounds::tiny();
    bounds.max_value_bytes = 256 * 1024;
    let store = SqliteStore::open(
        &h.scratch.db(),
        ConnectionSettings::local_wal_full(),
        bounds,
    )
    .unwrap()
    .0;
    let w = Window::open_synthetic(
        store,
        access(&h),
        fixture::scope(),
        ProducerId::parse("sensor-sat-producer").unwrap(),
        incarnation("process-b"),
        None,
    )
    .unwrap();
    let large = vec![0; 25_000]; // invalid synthetic bytes: preserve raw, refuse dependent use.
    let mut admitted = 0;
    let mut refusal = None;
    for n in 0..32 {
        let sample = row(&h, &w, &large, 1000 + n);
        match w.prepare_capture(
            access(&h),
            &sample,
            Retention::OptionalHistory,
            &clock(1000 + n),
        ) {
            Ok(ticket) => {
                committed(
                    w.submit_capture(access(&h), &ticket, &clock(1000 + n))
                        .unwrap(),
                );
                admitted += 1;
            }
            Err(error) => {
                refusal = Some(error.code());
                break;
            }
        }
    }
    assert_eq!(refusal, Some("mandatory-reserve"));
    assert!(admitted < 28);
    let used: usize = sql(
        &h,
        "SELECT sum(length(CAST(value_json AS BLOB))) FROM observations;",
    )[0][0]
        .parse()
        .unwrap();
    assert!(used <= 2 * 1024 * 1024 - 256 * 1024);
    let required = row(&h, &w, &large, 1100);
    capture(&h, &w, &required, Retention::Mandatory, 1100);
    let before: usize = sql(
        &h,
        "SELECT sum(length(CAST(value_json AS BLOB))) FROM observations;",
    )[0][0]
        .parse()
        .unwrap();
    let removed = w.evict(access(&h), &clock(1200)).unwrap();
    let after: usize = sql(
        &h,
        "SELECT sum(length(CAST(value_json AS BLOB))) FROM observations;",
    )[0][0]
        .parse()
        .unwrap();
    assert!(removed > 0 && removed < 8);
    assert!(before - after <= 512 * 1024);
    assert!(w.read(access(&h), required.id()).unwrap().is_some());
}

#[test]
fn competing_capture_tickets_cannot_spend_the_same_last_slot() {
    let h = Harness::new();
    let w = open(&h, None);
    for n in 0..27 {
        append(&h, &w, n, Retention::OptionalHistory);
    }
    let one = row(&h, &w, &[0x21, 1], 1100);
    let two = row(&h, &w, &[0x21, 2], 1100);
    assert_eq!(one.id(), two.id());
    let a = w
        .prepare_capture(access(&h), &one, Retention::OptionalHistory, &clock(1100))
        .unwrap();
    let b = w
        .prepare_capture(access(&h), &two, Retention::OptionalHistory, &clock(1100))
        .unwrap();
    std::thread::scope(|scope| {
        let first = scope.spawn(|| w.submit_capture(access(&h), &a, &clock(1100)).unwrap());
        let second = scope.spawn(|| w.submit_capture(access(&h), &b, &clock(1100)).unwrap());
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|r| matches!(r, MutationOutcome::Committed { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|r| matches!(r, MutationOutcome::Conflict { .. }))
                .count(),
            1
        );
    });
    assert_eq!(w.replay(access(&h), 0, 64).unwrap().records.len(), 28);
}

#[test]
fn d07_intact_restart_and_stale_checkpoint_mint_fresh_before_emission() {
    let h = Harness::new();
    let w = open(&h, None);
    let stale = w.checkpoint(access(&h)).unwrap();
    let old = append(&h, &w, 0, Retention::OptionalHistory);
    let intact = w.checkpoint(access(&h)).unwrap();
    let second = open(&h, Some(&intact));
    assert_eq!(second.checkpoint(access(&h)).unwrap(), intact);
    assert_eq!(w.checkpoint(access(&h)).unwrap_err().code(), "stale-owner");
    let resumed = open(&h, Some(&stale));
    let fresh = resumed.checkpoint(access(&h)).unwrap();
    assert_ne!(fresh.generation, intact.generation);
    assert_eq!(fresh.next, 1);
    assert_eq!(
        second.checkpoint(access(&h)).unwrap_err().code(),
        "stale-owner"
    );
    let new = append(&h, &resumed, 1, Retention::OptionalHistory);
    assert_ne!(old.id(), new.id());
    assert_eq!(
        resumed.read(access(&h), old.id()).unwrap().unwrap().id,
        *old.id()
    );
    let reset = open(&h, None);
    assert_ne!(
        reset.checkpoint(access(&h)).unwrap().generation,
        fresh.generation
    );
}

#[test]
fn d08_synthetic_space_failure_never_reports_capture_or_advances_identity() {
    let h = Harness::new();
    let initial = open(&h, None);
    drop(initial);
    let mut bounds = StoreBounds::tiny();
    bounds.max_db_bytes = 1;
    let store = SqliteStore::open(
        &h.scratch.db(),
        ConnectionSettings::local_wal_full(),
        bounds,
    )
    .unwrap()
    .0;
    // A failing startup cannot publish an owner/producer as ready either.
    let result = Window::open_synthetic(
        store,
        access(&h),
        fixture::scope(),
        ProducerId::parse("sensor-sat-producer").unwrap(),
        incarnation("process-b"),
        None,
    );
    assert_eq!(result.err().unwrap().code(), "maintenance-required");
    let mut bounds = StoreBounds::tiny();
    bounds.max_value_bytes = 1024;
    let store = SqliteStore::open(
        &h.scratch.db(),
        ConnectionSettings::local_wal_full(),
        bounds,
    )
    .unwrap()
    .0;
    let w = Window::open_synthetic(
        store,
        access(&h),
        fixture::scope(),
        ProducerId::parse("sensor-sat-producer").unwrap(),
        incarnation("process-b"),
        None,
    )
    .unwrap();
    let row = row(&h, &w, &[0x21, 7], 1000);
    let ticket = w
        .prepare_capture(access(&h), &row, Retention::OptionalHistory, &clock(1000))
        .unwrap();
    match w.submit_capture(access(&h), &ticket, &clock(1000)).unwrap() {
        MutationOutcome::NotCommitted { error, .. } => assert_eq!(error.code(), "value-too-large"),
        result => panic!("pre-write payload refusal required: {result:?}"),
    }
    // SQL admission is rechecked after prepare, not only at service open.
    h.registry
        .store()
        .exec_script("PRAGMA user_version=9;")
        .unwrap();
    let result = w.submit_capture(access(&h), &ticket, &clock(1000));
    assert!(!matches!(result, Ok(MutationOutcome::Committed { .. })));
    assert!(std::process::Command::new("sqlite3")
        .arg(h.scratch.db())
        .arg("PRAGMA user_version=1;")
        .status()
        .unwrap()
        .success());
    assert_eq!(w.checkpoint(access(&h)).unwrap().next, 0);
    assert!(w.read(access(&h), row.id()).unwrap().is_none());
}

#[test]
fn d09_accepted_and_sealed_content_survives_observation_custody() {
    let mut f = fixture::Fixture::new();
    let (accepted_store, sealed) = support::publish(&mut f, "pr03b", "synthetic SAT");
    let pending = support::prepare(
        &mut f,
        &accepted_store,
        &sealed,
        "pr03b-accept",
        accept::AcceptedRevision::new(0).unwrap(),
    );
    let accepted = accepted_store.submit(&pending, &f.seals).unwrap();
    let before = f
        .registry
        .store()
        .exec_script("SELECT hex(value_json) FROM outbox ORDER BY id;")
        .unwrap();
    let a = Access {
        gate: &f.gate,
        credential: Some(&f.credentials.reviewer),
    };
    let w = Window::open_synthetic(
        f.registry.store().try_clone().unwrap(),
        a,
        fixture::scope(),
        ProducerId::parse("sensor-sat-producer").unwrap(),
        incarnation("process-b"),
        None,
    )
    .unwrap();
    let h = Harness::new();
    for n in 0..12 {
        let sample = w
            .identify(
                a,
                h.pending(
                    &bytes(&[0x21, 7], 1000 + n),
                    &h.context,
                    Codec::Scalar,
                    unit(),
                    1000 + n,
                ),
            )
            .unwrap();
        let ticket = w
            .prepare_capture(a, &sample, Retention::OptionalHistory, &clock(1000 + n))
            .unwrap();
        committed(w.submit_capture(a, &ticket, &clock(1000 + n)).unwrap());
    }
    assert_eq!(w.evict(a, &clock(1100)).unwrap(), 8);
    let checkpoint = w.checkpoint(a).unwrap();
    drop(w);
    let _w = Window::open_synthetic(
        f.registry.store().try_clone().unwrap(),
        a,
        fixture::scope(),
        ProducerId::parse("sensor-sat-producer").unwrap(),
        incarnation("process-c"),
        Some(&checkpoint),
    )
    .unwrap();
    assert_eq!(
        f.registry
            .store()
            .exec_script("SELECT hex(value_json) FROM outbox ORDER BY id;")
            .unwrap(),
        before
    );
    let reopened = support::reopen(&f);
    assert_eq!(
        reopened
            .current(&fixture::scope())
            .unwrap()
            .unwrap()
            .revision,
        accepted.revision
    );
    assert_eq!(reopened.status(&sealed).unwrap(), accept::Stage::Accepted);
    assert!(reopened
        .sealed(sealed.staged(), sealed.identity(), &f.seals)
        .is_ok());
}

#[path = "observation_cases/window_boundaries.rs"]
mod window_boundaries;
