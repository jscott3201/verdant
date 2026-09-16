//! M02-PR10 frozen action/capability manifest, HARNESS-ONLY.
//!
//! Follows the `tests/gate_cases/manifest.rs` pattern: hardcoded literals
//! plus an independent field decoder, never encoder output. The gate
//! composes per-feature owner suites; the map below records the exact
//! composition without duplicating their logic.
#![allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "../src/storage/mod.rs"]
mod storage;
#[path = "../src/access/mod.rs"]
mod access;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "../src/seal/mod.rs"]
mod seal;
#[path = "../src/accept/mod.rs"]
mod accept;
#[path = "../src/api/mod.rs"]
mod api;
#[path = "../src/binding/mod.rs"]
mod binding;
#[path = "../src/runtime/mod.rs"]
mod runtime;
#[path = "../src/observation/mod.rs"]
mod observation;
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "../src/action_preview/mod.rs"]
mod action_preview;
#[path = "../src/action_journal/mod.rs"]
mod action_journal;
#[path = "../src/action_manifest/mod.rs"]
mod action_manifest;

use action_journal::Journal;
use domain::scope::TrustedScope;
use std::sync::atomic::{AtomicU64, Ordering};
use storage::{ConnectionSettings, StoreBounds};

/// Frozen manifest literal: object/priority/units/range/tolerance/duration/
/// deadline/retries/rate/release, harness-only scope, denial, no-auto-enable,
/// mandatory-vs-optional reserves. Independent of the product encoder.
const MANIFEST_22: &str = "verdant-action-manifest-v1|scope-a|ahu-1|av2:pv85|p8|degC|20.0-24.0|tol0.1|900s|5s|r0|rate6|verdant-preview-v1|priority-8-masks-9-16-masked-by-1-7|loopback-directed-unicast|denied-never-reaches-peer|no-auto-enable|essential64:history1|null-relinquish|unavailable-feedback|uncertain-not-resend";

/// Independent test decoder: pipe-separated fields, exact count, no product oracle.
fn fields(raw: &str) -> Vec<&str> {
    raw.split('|').collect()
}

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "verdant-m02-pr10-manifest-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&dir).expect("isolated scratch");
        Self(dir)
    }
    fn db(&self) -> std::path::PathBuf {
        self.0.join("store.db")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("cleanup scratch");
    }
}

#[test]
fn frozen_action_manifest_matches_hardcoded_literal() {
    assert_eq!(action_manifest::ACTION_MANIFEST_FORMAT, "verdant-action-manifest-v1");
    assert_eq!(action_manifest::FIELD_COUNT, 21);
    // Product bytes equal the independent literal, never the reverse.
    assert_eq!(action_manifest::canonical_bytes(), MANIFEST_22);
    let parts = fields(MANIFEST_22);
    assert_eq!(parts.len(), 21);
    assert_eq!(
        &parts[..13],
        [
            "verdant-action-manifest-v1", "scope-a", "ahu-1", "av2:pv85", "p8", "degC",
            "20.0-24.0", "tol0.1", "900s", "5s", "r0", "rate6", "verdant-preview-v1",
        ]
    );
    assert_eq!(parts[13], "priority-8-masks-9-16-masked-by-1-7");
    assert_eq!(parts[14], "loopback-directed-unicast");
    assert_eq!(parts[15], "denied-never-reaches-peer");
    assert_eq!(parts[16], "no-auto-enable");
    assert_eq!(parts[17], "essential64:history1");
    assert_eq!(&parts[18..], ["null-relinquish", "unavailable-feedback", "uncertain-not-resend"]);
    // Product decoder agrees with the literal field by field.
    let decoded = action_manifest::decode(MANIFEST_22).expect("frozen decodes");
    assert_eq!(decoded.scope(), "scope-a");
    assert_eq!(decoded.priority(), 8);
    assert_eq!(decoded.duration_secs(), 900);
    assert_eq!(decoded.deadline_secs(), 5);
    assert_eq!(decoded.retries(), 0);
    assert_eq!(decoded.rate_per_hour(), 6);
    assert_eq!(action_manifest::decode(&action_manifest::canonical_bytes()).expect("round"), decoded);
    // Planning reserves are checked arithmetic, never wrapping or host quotas.
    assert_eq!(action_manifest::max_actions_per_day().expect("daily"), 144);
    assert_eq!(action_manifest::duration_ms().expect("ms"), 900_000);
    assert!(action_manifest::BOUNDARY.contains("harness-only"));
    assert!(action_manifest::BOUNDARY.contains("no-auto-enable"));
    assert!(action_manifest::BOUNDARY.contains("integration-only"));
    assert_eq!(TrustedScope::parse("scope-a").expect("scope").as_str(), "scope-a");
    println!("M02_PR10_MANIFEST frozen=verbatim fields=21 scope=harness-only reserves=essential64:history1");
}

#[test]
fn manifest_mutations_refuse_with_stable_codes() {
    assert_eq!(action_manifest::decode("short|row").unwrap_err().code(), "manifest-field-count");
    let long = format!("{MANIFEST_22}|extra");
    assert_eq!(action_manifest::decode(&long).unwrap_err().code(), "manifest-field-count");
    // Each mutated field refuses; the error never widens the profile.
    for (index, replacement) in [
        (1, "scope-b"), (3, "av2:pv86"), (4, "p2"), (5, "percent"),
        (6, "18.0-26.0"), (8, "600s"), (10, "r1"), (11, "rate60"),
        (14, "facility-route"), (15, "denied-sometimes"), (16, "auto-enable"),
        (17, "essential64:history64"), (18, "hold-last"), (20, "resend-on-timeout"),
    ] {
        let mut parts = fields(MANIFEST_22).into_iter().map(str::to_owned).collect::<Vec<_>>();
        parts[index] = replacement.to_owned();
        let err = action_manifest::decode(&parts.join("|")).unwrap_err();
        assert!(
            matches!(err.code(), "manifest-field-mismatch" | "manifest-invalid" | "manifest-number"),
            "field {index} mutated to {replacement}: {}",
            err.code()
        );
    }
    assert_eq!(action_manifest::ManifestPriority::new(2).unwrap_err().code(), "manifest-invalid");
    assert_eq!(action_manifest::ManifestScope::parse("scope-b").unwrap_err().code(), "manifest-invalid");
    // Exhaustive error codes stay stable.
    assert_eq!(action_manifest::ManifestError::Invalid("x").code(), "manifest-invalid");
    assert_eq!(
        action_manifest::ManifestError::FieldCount { expected: 21, found: 1 }.code(),
        "manifest-field-count"
    );
    assert_eq!(action_manifest::ManifestError::FieldMismatch { index: 0 }.code(), "manifest-field-mismatch");
    assert_eq!(action_manifest::ManifestError::Number { field: "rate" }.code(), "manifest-number");
    println!("M02_PR10_MANIFEST mutations=refused codes=stable widening=never");
}

#[test]
fn manifest_reserves_match_live_journal() {
    let scratch = Scratch::new();
    let (journal, _rx) = Journal::open(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("writer open");
    assert_eq!(journal.essential_capacity(), 64);
    assert_eq!(journal.history_capacity(), 1);
    assert_ne!(journal.essential_capacity(), journal.history_capacity());
    assert_eq!(action_manifest::reserves_note(), "essential64:history1");
    assert_eq!(fields(MANIFEST_22)[17], action_manifest::reserves_note());
    println!("M02_PR10_MANIFEST essential=64 history=1 separate=true");
}

/// Gate composition map: per-feature owner suites ship their own tests; the
/// gate asserts each leg's journey shape only. A map is NOT execution
/// evidence; the full suite must execute those suites.
const COMPOSED: &[(&str, &str, &str)] = &[
    ("observation-cov-loss", "tests/observation_window.rs", "d01_slow_subscriber_recovers_or_reads_durable_explicit_tombstones"),
    ("bounded-modbus", "tests/modbus_live.rs", "modbus_fc01_direct_coils_exact_bits_and_no_wrong_read_route"),
    ("preview", "tests/m02_pr05_preview.rs", "permitted_human_proposal_is_revision_bound_information"),
    ("admission", "tests/m02_pr06_admission.rs", "same_key_same_payload_retry_reconciles"),
    ("dispatch", "tests/m02_pr07_dispatch.rs", "dispatch_confirmed_separates_protocol_readbacks_feedback"),
    ("expiry-release", "tests/m02_pr08_expiry_release.rs", "active_expiry_refuses_new_set_allows_cancel_or_null"),
    ("publication", "tests/m02_pr09_publication.rs", "barrier_races_ordered_preview_admission_journal_send_publication"),
    ("recovery", "tests/m02_pr11_recovery.rs", "forced_exit_after_commit_is_unknown_persists_for_reconcile"),
    ("custody", "tests/m02_pr12_custody.rs", "expired_contractor_transfer_narrow_new_admission"),
    ("mandatory-reserve-a06", "tests/runtime_cases/cases.rs", "a06_optional_saturation_preserves_mandatory_reservations"),
    ("mandatory-reserve-b07", "tests/bacnet_cases/lifecycle.rs", "b07_shared_saturation_preserves_mandatory_slots"),
    ("slow-unrelated-a08", "tests/runtime_cases/cases.rs", "a08_slow_unrelated_native_job_cannot_hold_handoff_hostage"),
    ("slow-peer", "tests/m02_pr09_publication.rs", "slow_unrelated_native_publication_does_not_hold_controller_hostage"),
];

#[test]
fn composed_owner_suites_exist_for_every_leg() {
    let mut legs = std::collections::BTreeSet::new();
    for &(leg, file, case) in COMPOSED {
        assert!(legs.insert(leg), "duplicate leg {leg}");
        let source = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file))
            .unwrap_or_else(|_| panic!("owner file missing: {file}"));
        assert!(source.contains(&format!("#[test]\nfn {case}(")) || source.contains(&format!("#[tokio::test(flavor = \"current_thread\")]\nasync fn {case}(")), "mapped test missing: {file}::{case}");
        println!("M02_PR10_COMPOSED leg={leg} owner={file}::{case} execution=required-full-suite");
    }
    assert_eq!(legs.len(), 13);
    println!("M02_PR10_COMPOSED gate=composes-per-feature-tests duplicates=none");
}
