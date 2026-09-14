//! D09-adjacent socket-free composition of a declared COV loss snapshot with
//! the actual PR03B read/custody owner. No production store or new gap semantics.
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
use observation::{identity::ProducerId, normalize::Codec, window::*};
use observation_support::{bytes, clock, incarnation, unit, Harness};
use runtime::bacnet::cov::{Coverage, Loss};

#[test]
fn cov_declared_loss_reuses_pr03b_reads_without_tombstones_or_repairing_history() {
    let h = Harness::new();
    let access = Access { gate: &h.gate, credential: Some(&h.credentials.reviewer) };
    let w = Window::open_synthetic(
        h.registry.store().try_clone().unwrap(),
        access,
        fixture::scope(),
        ProducerId::parse("sensor-sat-producer").unwrap(),
        incarnation("cov-read-fixture"),
        None,
    )
    .unwrap();
    let mut ids = Vec::new();
    for ms in [1000, 1001] {
        let raw = bytes(&[0x21, 7], ms);
        let row = w.identify(access, h.pending(&raw, &h.context, Codec::Scalar, unit(), ms)).unwrap();
        ids.push(row.id().clone());
        let ticket = w.prepare_capture(access, &row, Retention::OptionalHistory, &clock(ms)).unwrap();
        assert!(matches!(
            w.submit_capture(access, &ticket, &clock(ms)).unwrap(),
            storage::sqlite::MutationOutcome::Committed { .. }
        ));
    }
    assert_ne!(ids[0], ids[1], "equal newly observed values have different identities");
    let checkpoint = w.checkpoint(access).unwrap();
    let before = w.replay(access, 0, 64).unwrap();
    // Snapshot of the independently exercised overflow/Lagged receiver path.
    let coverage = Coverage {
        changes: 1,
        last: Loss::Lagged(8),
        revalidation_due: false,
        unobserved_interval: true,
        subscribed: true,
    };
    let recovered = coverage.read_retained(|| w.replay(access, 0, 64)).unwrap();
    assert_eq!(recovered.coverage, coverage);
    assert_eq!(recovered.evidence, before);
    assert!(recovered.evidence.gaps.is_empty());
    assert_eq!(w.checkpoint(access).unwrap(), checkpoint, "coverage does not allocate positions");
    assert_eq!(
        recovered.evidence.records[0].dependent_value().unwrap_err().code(),
        "replayed-evidence-not-fresh"
    );

    // Deliberate missing-durable-row fault in this isolated temp store. This is
    // outside the guarded-writer model, NOT what Lagged(n) does. No production
    // path synthesizes a missing durable position from a channel loss count.
    h.registry.store().exec_script("DELETE FROM observations WHERE seq=0;").unwrap();
    let failure = coverage.read_retained(|| w.replay(access, 0, 1)).unwrap_err();
    assert_eq!(failure.code(), "unaccounted-history-gap");
    assert_eq!(w.replay(access, 1, 1).unwrap().records, before.records[1..]);
    let gaps = h.registry.store().exec_script("SELECT COUNT(*) FROM gaps;").unwrap();
    assert_eq!(gaps, vec![vec!["0".to_string()]]);
}
