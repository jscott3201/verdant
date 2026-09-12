//! M01-PR06 offline vocabulary conversion boundaries.
//!
//! Pure offline checks over synthetic fixtures only (no network, no stores,
//! no native lifecycle). The curated site mirrors the domain `tiny_site`
//! shape (one AHU, two VAVs with duplicate label `VAV`, one shared SAT
//! sensor). Classification refusals are diagnostics (which class, why out of
//! scope, pinned-profile reference), never a claim about universal coverage
//! and never a judgment that an unmapped import is a reviewed semantic fault.

#[allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;

#[allow(dead_code)]
#[path = "../src/semantics/mod.rs"]
mod semantics;

use domain::ids::BindingRevision;
use domain::values::{Decimal, OpMode, Value};
use semantics::convert::{
    apply, convert, mode_of, ApplyOutcome, BindingSet, ExternalItem, ExternalSite,
};
use semantics::profile::{
    Profile, VerdantKind, PINNED_PROFILE_ID, PINNED_SUBSET_JSON, SUPPORTED_AHU_CLASS,
    SUPPORTED_SAT_CLASS, SUPPORTED_VAV_CLASS, VERDANT_NAMESPACE,
};

fn decimal_value(raw: &str) -> Value {
    Value::Decimal(Decimal::parse(raw).expect("frozen decimal is valid"))
}

fn positive_site() -> ExternalSite {
    let items = vec![
        ExternalItem::parse(
            "ext-ahu-1",
            SUPPORTED_AHU_CLASS,
            "ahu-1",
            "AHU",
            "degC",
            decimal_value("21.50"),
        )
        .expect("frozen AHU item is valid"),
        ExternalItem::parse(
            "ext-vav-101",
            SUPPORTED_VAV_CLASS,
            "vav-101",
            "VAV",
            "L/s",
            Value::Integer(9_007_199_254_740_993),
        )
        .expect("frozen VAV item is valid"),
        ExternalItem::parse(
            "ext-vav-102",
            SUPPORTED_VAV_CLASS,
            "vav-102",
            "VAV",
            "L/s",
            Value::Integer(0),
        )
        .expect("frozen second VAV item is valid"),
        ExternalItem::parse(
            "ext-sat-1",
            SUPPORTED_SAT_CLASS,
            "sensor-sat-1",
            "SAT",
            "degC",
            Value::Missing,
        )
        .expect("frozen sensor item is valid"),
    ];
    ExternalSite::new(items).expect("frozen positive site is valid")
}

fn shuffled_positive_site() -> ExternalSite {
    let items = vec![
        ExternalItem::parse(
            "ext-sat-1",
            SUPPORTED_SAT_CLASS,
            "sensor-sat-1",
            "SAT",
            "degC",
            Value::Missing,
        )
        .expect("frozen sensor item is valid"),
        ExternalItem::parse(
            "ext-vav-102",
            SUPPORTED_VAV_CLASS,
            "vav-102",
            "VAV",
            "L/s",
            Value::Integer(0),
        )
        .expect("frozen second VAV item is valid"),
        ExternalItem::parse(
            "ext-ahu-1",
            SUPPORTED_AHU_CLASS,
            "ahu-1",
            "AHU",
            "degC",
            decimal_value("21.50"),
        )
        .expect("frozen AHU item is valid"),
        ExternalItem::parse(
            "ext-vav-101",
            SUPPORTED_VAV_CLASS,
            "vav-101",
            "VAV",
            "L/s",
            Value::Integer(9_007_199_254_740_993),
        )
        .expect("frozen VAV item is valid"),
    ];
    ExternalSite::new(items).expect("shuffled site is valid")
}

// ---------------------------------------------------------------------------
// Deterministic positive conversion with record and manifest.
// ---------------------------------------------------------------------------

#[test]
fn positive_conversion_is_deterministic_with_manifest() {
    let profile = Profile::pinned();
    let site = positive_site();
    let shuffled = shuffled_positive_site();

    let first = convert(&site, &profile).expect("positive converts");
    let second = convert(&shuffled, &profile).expect("shuffled converts");

    assert_eq!(first.record().profile_id(), PINNED_PROFILE_ID);
    assert_eq!(first.record().profile_id(), profile.id());
    assert_eq!(first.bindings().len(), 4);
    assert_eq!(second.bindings().len(), 4);

    // Deterministic ordering: different input order yields byte-identical
    // outputs (sorted by slot/source key, never caller order).
    assert_eq!(
        first.record().to_json(),
        second.record().to_json(),
        "record must be byte-identical on repeat"
    );
    assert_eq!(
        first.to_json(),
        second.to_json(),
        "conversion must be byte-identical on repeat"
    );

    // Per-item outcomes in deterministic slot order with frozen outcome text.
    let slots: Vec<&str> = first
        .record()
        .items()
        .iter()
        .map(|item| item.verdant_slot())
        .collect();
    assert_eq!(
        slots,
        vec!["ahu-1", "sensor-sat-1", "vav-101", "vav-102"],
        "items sorted by verdant slot"
    );
    for item in first.record().items() {
        assert_eq!(item.outcome(), "mapped");
    }

    // Bindings sorted by slot with expected kinds.
    let bindings = first.bindings();
    assert_eq!(bindings[0].verdant_id().as_str(), "ahu-1");
    assert_eq!(bindings[0].kind(), VerdantKind::Ahu);
    assert_eq!(bindings[1].verdant_id().as_str(), "sensor-sat-1");
    assert_eq!(bindings[1].kind(), VerdantKind::SensorSat);
    assert_eq!(bindings[2].verdant_id().as_str(), "vav-101");
    assert_eq!(bindings[2].kind(), VerdantKind::Vav);
    assert_eq!(bindings[3].verdant_id().as_str(), "vav-102");
    assert_eq!(bindings[3].kind(), VerdantKind::Vav);

    // Duplicate labels preserved as text, never aliased as identity.
    assert_eq!(bindings[2].label(), "VAV");
    assert_eq!(bindings[3].label(), "VAV");
    assert_eq!(bindings[2].label(), bindings[3].label());
    assert_ne!(bindings[2].verdant_id(), bindings[3].verdant_id());

    // Trusted fields preserved verbatim (field-by-field, plus digests below).
    assert_eq!(bindings[0].unit().as_str(), "degC");
    assert_eq!(bindings[0].value(), &decimal_value("21.50"));
    assert_eq!(bindings[1].value(), &Value::Missing);
    assert_eq!(bindings[2].value(), &Value::Integer(9_007_199_254_740_993));
    assert_eq!(bindings[3].value(), &Value::Integer(0));

    // Digests travel with the record.
    assert_eq!(first.record().input_digest(), site.input_digest());
    assert_eq!(first.record().content_digest(), site.content_digest());
    assert_eq!(first.record().input_digest().len(), 16);
    assert_eq!(first.record().content_digest().len(), 16);
}

// ---------------------------------------------------------------------------
// Independent literals (hardcoded, never encoder output).
// ---------------------------------------------------------------------------

#[test]
fn independent_binding_and_outcome_literals() {
    // Fully independent literals for one AHU binding and outcome.
    let expected_binding = "{\"external_class\":\"brick:AHU\",\"kind\":\"ahu\",\"label\":\"AHU\",\"source_key\":\"ext-ahu-1\",\"unit\":\"degC\",\"value\":{\"type\":\"decimal\",\"value\":\"21.50\"},\"verdant_id\":\"ahu-1\",\"verdant_namespace\":\"verdant:v1\"}";
    let expected_outcome = "{\"external_class\":\"brick:AHU\",\"outcome\":\"mapped\",\"source_key\":\"ext-ahu-1\",\"verdant_kind\":\"ahu\",\"verdant_slot\":\"ahu-1\"}";

    let profile = Profile::pinned();
    let site = positive_site();
    let conversion = convert(&site, &profile).expect("positive converts");
    let ahu = conversion
        .bindings()
        .iter()
        .find(|binding| binding.verdant_id().as_str() == "ahu-1")
        .expect("AHU binding present");
    assert_eq!(ahu.to_json(), expected_binding);
    let outcome = conversion
        .record()
        .items()
        .iter()
        .find(|item| item.verdant_slot() == "ahu-1")
        .expect("AHU outcome present");
    assert_eq!(outcome.to_json(), expected_outcome);

    // Record shape is frozen (field order plus profile literal).
    let record_json = conversion.record().to_json();
    assert!(
        record_json.starts_with("{\"content_digest\":\""),
        "record field order frozen: {record_json}"
    );
    assert!(
        record_json.contains("\"profile\":\"verdant-pinned-brick-223p-rec-v1\""),
        "record carries the pinned profile: {record_json}"
    );
    assert!(
        record_json.contains(expected_outcome),
        "record embeds the frozen outcome: {record_json}"
    );
}

// ---------------------------------------------------------------------------
// No-op preserves the existing binding revision.
// ---------------------------------------------------------------------------

#[test]
fn noop_preserves_binding_revision() {
    let profile = Profile::pinned();
    let site = positive_site();
    let conversion = convert(&site, &profile).expect("positive converts");
    let current = BindingSet::from_conversion(&conversion, BindingRevision::new(7));

    let outcome = apply(&site, &profile, &current).expect("noop applies");
    assert!(outcome.is_noop());
    assert_eq!(outcome.record().input_digest(), site.input_digest());
    match outcome {
        ApplyOutcome::Noop { record } => {
            assert_eq!(record.input_digest(), current.input_digest());
            assert_eq!(record.content_digest(), current.content_digest());
            assert_eq!(record.profile_id(), current.profile_id());
        }
        ApplyOutcome::Applied { .. } => panic!("identical input must be a no-op"),
    }

    // Revision untouched and bindings unchanged (shuffled input is still a
    // no-op because digests are order-independent).
    let shuffled = shuffled_positive_site();
    let again = apply(&shuffled, &profile, &current).expect("shuffled noop");
    assert!(again.is_noop());
    assert_eq!(current.revision(), BindingRevision::new(7));

    // New content bumps by one (checked, deterministic).
    let mut changed_items: Vec<ExternalItem> = Vec::new();
    for item in site.items() {
        if item.verdant_slot().as_str() == "ahu-1" {
            changed_items.push(
                ExternalItem::parse(
                    item.source_key(),
                    item.external_class(),
                    item.verdant_slot().as_str(),
                    "AHU-renamed",
                    item.unit().as_str(),
                    item.value().clone(),
                )
                .expect("renamed label parses"),
            );
        } else {
            changed_items.push(item.clone());
        }
    }
    let changed = ExternalSite::new(changed_items).expect("changed site is valid");
    let applied = apply(&changed, &profile, &current).expect("changed applies");
    match applied {
        ApplyOutcome::Noop { .. } => panic!("changed input must apply"),
        ApplyOutcome::Applied { record: _, next } => {
            assert_eq!(next.revision(), BindingRevision::new(8));
            assert_eq!(next.bindings().len(), 4);
        }
    }
}

// ---------------------------------------------------------------------------
// Supported-but-out-of-scenario refusal before any write.
// ---------------------------------------------------------------------------

#[test]
fn out_of_scenario_refused_before_any_write_with_diagnostics() {
    let profile = Profile::pinned();
    let items = vec![
        ExternalItem::parse(
            "ext-ahu-1",
            SUPPORTED_AHU_CLASS,
            "ahu-1",
            "AHU",
            "degC",
            decimal_value("21.50"),
        )
        .expect("AHU parses"),
        ExternalItem::parse(
            "ext-chiller-1",
            "brick:Chiller",
            "ahu-1",
            "Chiller",
            "degC",
            decimal_value("7.00"),
        )
        .expect("chiller parses syntactically; refusal happens at convert"),
    ];
    let site = ExternalSite::new(items).expect("site parses");
    let err = convert(&site, &profile).unwrap_err();
    assert_eq!(err.code(), "out-of-scenario");
    let text = err.to_string();
    assert!(text.contains("brick:Chiller"), "{text}");
    assert!(text.contains(PINNED_PROFILE_ID), "{text}");
    assert!(
        text.contains("tiny_site scenario") || text.contains("tiny_site"),
        "{text}"
    );

    // Independent literal for the failure rendering.
    let expected = "{\"code\":\"out-of-scenario\",\"class\":\"brick:Chiller\",\"profile\":\"verdant-pinned-brick-223p-rec-v1\",\"reason\":\"known Brick class but outside tiny_site scenario for this profile (v1 covers only AHU, VAV and SAT sensor)\"}";
    assert_eq!(err.to_json(), expected);

    // Before any write by construction: the error carries no bindings and the
    // valid prefix alone still converts (refusal is due to the bad class).
    let valid = positive_site();
    convert(&valid, &profile).expect("valid prefix converts without the bad class");
}

// ---------------------------------------------------------------------------
// Applied conversion never changes trusted content or its digest.
// ---------------------------------------------------------------------------

#[test]
fn applied_conversion_preserves_trusted_content_digest() {
    let profile = Profile::pinned();
    let site = positive_site();
    let conversion = convert(&site, &profile).expect("positive converts");

    // Content digest preserved verbatim from input through the record.
    assert_eq!(conversion.record().content_digest(), site.content_digest());

    // Field-by-field preservation for every binding.
    for binding in conversion.bindings() {
        let input = site
            .items()
            .iter()
            .find(|item| item.source_key() == binding.source_key())
            .expect("source present");
        assert_eq!(input.verdant_slot(), binding.verdant_id());
        assert_eq!(input.unit(), binding.unit());
        assert_eq!(input.value(), binding.value());
        assert_eq!(input.external_class(), binding.external_class());
    }

    // Labels are not content: same trusted content with different labels
    // shares the content digest but differs in the input digest.
    let relabeled = ExternalSite::new(vec![
        ExternalItem::parse(
            "ext-ahu-1",
            SUPPORTED_AHU_CLASS,
            "ahu-1",
            "AHU-roof",
            "degC",
            decimal_value("21.50"),
        )
        .expect("relabeled parses"),
        ExternalItem::parse(
            "ext-vav-101",
            SUPPORTED_VAV_CLASS,
            "vav-101",
            "VAV-north",
            "L/s",
            Value::Integer(9_007_199_254_740_993),
        )
        .expect("relabeled parses"),
        ExternalItem::parse(
            "ext-vav-102",
            SUPPORTED_VAV_CLASS,
            "vav-102",
            "VAV-south",
            "L/s",
            Value::Integer(0),
        )
        .expect("relabeled parses"),
        ExternalItem::parse(
            "ext-sat-1",
            SUPPORTED_SAT_CLASS,
            "sensor-sat-1",
            "SAT-roof",
            "degC",
            Value::Missing,
        )
        .expect("relabeled parses"),
    ])
    .expect("relabeled site is valid");
    assert_eq!(relabeled.content_digest(), site.content_digest());
    assert_ne!(relabeled.input_digest(), site.input_digest());

    // BindingSet preserves the same digests.
    let bound = BindingSet::from_conversion(&conversion, BindingRevision::new(1));
    assert_eq!(bound.content_digest(), site.content_digest());
    assert_eq!(bound.input_digest(), site.input_digest());
    assert_eq!(bound.profile_id(), PINNED_PROFILE_ID);
}

// ---------------------------------------------------------------------------
// Collision names both candidates without a global merge.
// ---------------------------------------------------------------------------

#[test]
fn collision_names_both_without_merge() {
    let profile = Profile::pinned();
    // Two candidates, one slot; source keys deliberately unsorted so the
    // diagnostic must sort them for determinism.
    let items = vec![
        ExternalItem::parse(
            "ext-vav-b",
            SUPPORTED_VAV_CLASS,
            "vav-101",
            "VAV",
            "L/s",
            Value::Integer(1),
        )
        .expect("second claimant parses"),
        ExternalItem::parse(
            "ext-vav-a",
            SUPPORTED_VAV_CLASS,
            "vav-101",
            "VAV",
            "L/s",
            Value::Integer(2),
        )
        .expect("first claimant parses"),
    ];
    let site = ExternalSite::new(items).expect("collision site parses");
    let err = convert(&site, &profile).unwrap_err();
    assert_eq!(err.code(), "collision");
    let text = err.to_string();
    assert!(text.contains("vav-101"), "{text}");
    assert!(text.contains("ext-vav-a"), "{text}");
    assert!(text.contains("ext-vav-b"), "{text}");
    assert!(text.contains("no merge"), "{text}");

    // Independent literal (candidates sorted for determinism).
    let expected = "{\"code\":\"collision\",\"candidates\":[\"ext-vav-a\",\"ext-vav-b\"],\"profile\":\"verdant-pinned-brick-223p-rec-v1\",\"slot\":\"vav-101\"}";
    assert_eq!(err.to_json(), expected);

    // No silent winner: a single claimant for the same slot converts.
    let single = ExternalSite::new(vec![ExternalItem::parse(
        "ext-vav-a",
        SUPPORTED_VAV_CLASS,
        "vav-101",
        "VAV",
        "L/s",
        Value::Integer(2),
    )
    .expect("single parses")])
    .expect("single site is valid");
    let ok = convert(&single, &profile).expect("single claimant converts");
    assert_eq!(ok.bindings().len(), 1);
}

// ---------------------------------------------------------------------------
// Deterministic failure differential (same input plus profile, same bytes).
// ---------------------------------------------------------------------------

#[test]
fn failure_differential_is_deterministic() {
    let profile = Profile::pinned();

    // Out-of-scenario differential.
    let bad_once = ExternalSite::new(vec![ExternalItem::parse(
        "ext-boiler-1",
        "brick:Boiler",
        "ahu-1",
        "Boiler",
        "degC",
        decimal_value("60.00"),
    )
    .expect("boiler parses")])
    .expect("bad site parses");
    let bad_twice = ExternalSite::new(vec![ExternalItem::parse(
        "ext-boiler-1",
        "brick:Boiler",
        "ahu-1",
        "Boiler",
        "degC",
        decimal_value("60.00"),
    )
    .expect("boiler parses")])
    .expect("bad site parses");
    let first = convert(&bad_once, &profile).unwrap_err();
    let second = convert(&bad_twice, &profile).unwrap_err();
    assert_eq!(first.to_json(), second.to_json());
    assert_eq!(first.to_string(), second.to_string());
    assert_eq!(first.code(), "out-of-scenario");

    // Collision differential.
    let collision_once = ExternalSite::new(vec![
        ExternalItem::parse(
            "ext-vav-a",
            SUPPORTED_VAV_CLASS,
            "vav-101",
            "VAV",
            "L/s",
            Value::Integer(1),
        )
        .expect("claimant parses"),
        ExternalItem::parse(
            "ext-vav-b",
            SUPPORTED_VAV_CLASS,
            "vav-101",
            "VAV",
            "L/s",
            Value::Integer(1),
        )
        .expect("claimant parses"),
    ])
    .expect("collision site parses");
    let collision_twice = ExternalSite::new(vec![
        ExternalItem::parse(
            "ext-vav-b",
            SUPPORTED_VAV_CLASS,
            "vav-101",
            "VAV",
            "L/s",
            Value::Integer(1),
        )
        .expect("claimant parses"),
        ExternalItem::parse(
            "ext-vav-a",
            SUPPORTED_VAV_CLASS,
            "vav-101",
            "VAV",
            "L/s",
            Value::Integer(1),
        )
        .expect("claimant parses"),
    ])
    .expect("collision site parses");
    let first = convert(&collision_once, &profile).unwrap_err();
    let second = convert(&collision_twice, &profile).unwrap_err();
    assert_eq!(first.to_json(), second.to_json());
    assert_eq!(first.code(), "collision");

    // Unknown-class differential with an independent literal.
    let unknown = ExternalSite::new(vec![ExternalItem::parse(
        "ext-x-1",
        "brick:Not-A-Real-Class",
        "ahu-1",
        "X",
        "degC",
        decimal_value("1.00"),
    )
    .expect("unknown parses")])
    .expect("unknown site parses");
    let err = convert(&unknown, &profile).unwrap_err();
    assert_eq!(err.code(), "unknown-class");
    let expected = "{\"code\":\"unknown-class\",\"class\":\"brick:Not-A-Real-Class\",\"profile\":\"verdant-pinned-brick-223p-rec-v1\"}";
    assert_eq!(err.to_json(), expected);
    let again = convert(&unknown, &profile).unwrap_err();
    assert_eq!(err.to_json(), again.to_json());
}

// ---------------------------------------------------------------------------
// Units, modes and slot discipline (PR02 consumption, preserved verbatim).
// ---------------------------------------------------------------------------

#[test]
fn units_modes_and_slots_are_preserved_with_typed_refusals() {
    let profile = Profile::pinned();

    // Unknown unit plus unknown mode round-trip as preserved unknowns, never
    // coerced (PR02-frozen behavior consumed, not forked).
    let turbo = OpMode::parse("turbo").expect("frozen unknown mode");
    assert!(turbo.is_unknown());
    let site = ExternalSite::new(vec![ExternalItem::parse(
        "ext-vav-101",
        SUPPORTED_VAV_CLASS,
        "vav-101",
        "VAV",
        "furlongs-per-fortnight",
        Value::Mode(turbo.clone()),
    )
    .expect("unknown unit and mode parse")])
    .expect("mode site is valid");
    let conversion = convert(&site, &profile).expect("mode converts");
    let binding = &conversion.bindings()[0];
    assert!(binding.unit().is_unknown());
    assert_eq!(binding.unit().as_str(), "furlongs-per-fortnight");
    assert_eq!(binding.value(), &Value::Mode(turbo.clone()));
    assert_eq!(mode_of(binding.value()), Some(&turbo));
    assert_eq!(conversion.record().content_digest(), site.content_digest());

    // Known mode stays known and mode_of reports it.
    let occupied = OpMode::parse("occupied").expect("known mode");
    assert!(!occupied.is_unknown());
    assert_eq!(mode_of(&Value::Mode(occupied.clone())), Some(&occupied));
    assert_eq!(mode_of(&Value::Bool(false)), None);
    assert_eq!(mode_of(&Value::Missing), None);

    // Slot-kind mismatch is a typed refusal naming class, kind, slot and
    // profile (independent literal).
    let mismatched = ExternalSite::new(vec![ExternalItem::parse(
        "ext-ahu-1",
        SUPPORTED_AHU_CLASS,
        "vav-101",
        "AHU",
        "degC",
        decimal_value("21.50"),
    )
    .expect("mismatched parses")])
    .expect("mismatched site parses");
    let err = convert(&mismatched, &profile).unwrap_err();
    assert_eq!(err.code(), "slot-mismatch");
    let expected = "{\"code\":\"slot-mismatch\",\"class\":\"brick:AHU\",\"kind\":\"ahu\",\"profile\":\"verdant-pinned-brick-223p-rec-v1\",\"slot\":\"vav-101\"}";
    assert_eq!(err.to_json(), expected);
}

// ---------------------------------------------------------------------------
// Malformed inputs refused (never panics).
// ---------------------------------------------------------------------------

#[test]
fn malformed_inputs_are_refused() {
    assert_eq!(
        ExternalSite::new(vec![]).unwrap_err().code(),
        "invalid-input"
    );
    // Duplicate source keys refused.
    let dup = ExternalSite::new(vec![
        ExternalItem::parse(
            "ext-dup",
            SUPPORTED_AHU_CLASS,
            "ahu-1",
            "AHU",
            "degC",
            decimal_value("1.00"),
        )
        .expect("first parses"),
        ExternalItem::parse(
            "ext-dup",
            SUPPORTED_VAV_CLASS,
            "vav-101",
            "VAV",
            "L/s",
            Value::Integer(1),
        )
        .expect("second parses"),
    ])
    .unwrap_err();
    assert_eq!(dup.code(), "invalid-input");

    // Bad characters, empty texts and invalid slots are refusals.
    assert_eq!(
        ExternalItem::parse(
            "bad key",
            SUPPORTED_AHU_CLASS,
            "ahu-1",
            "AHU",
            "degC",
            decimal_value("1.00"),
        )
        .unwrap_err()
        .code(),
        "invalid-input"
    );
    assert_eq!(
        ExternalItem::parse(
            "ext-1",
            SUPPORTED_AHU_CLASS,
            "AHU 1 (roof)",
            "AHU",
            "degC",
            decimal_value("1.00"),
        )
        .unwrap_err()
        .code(),
        "invalid-input"
    );
    assert_eq!(
        ExternalItem::parse(
            "ext-1",
            SUPPORTED_AHU_CLASS,
            "ahu-1",
            "",
            "degC",
            decimal_value("1.00"),
        )
        .unwrap_err()
        .code(),
        "invalid-input"
    );
    assert_eq!(
        ExternalItem::parse(
            "ext-1",
            SUPPORTED_AHU_CLASS,
            "ahu-1",
            "AHU",
            "",
            decimal_value("1.00"),
        )
        .unwrap_err()
        .code(),
        "invalid-input"
    );
}

// ---------------------------------------------------------------------------
// Pinned artifact provenance and scope.
// ---------------------------------------------------------------------------

#[test]
fn pinned_fixture_matches_profile() {
    assert_eq!(Profile::pinned().id(), PINNED_PROFILE_ID);
    assert_eq!(PINNED_PROFILE_ID, "verdant-pinned-brick-223p-rec-v1");
    assert_eq!(VERDANT_NAMESPACE, "verdant:v1");
    assert_eq!(Profile::pinned().namespace(), "verdant:v1");

    // Embedded artifact equals the checked-in file byte for byte (pinning).
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/semantics/pinned_subset.json");
    let on_disk = std::fs::read_to_string(&dir).expect("pinned_subset.json exists");
    assert_eq!(
        on_disk, PINNED_SUBSET_JSON,
        "embedded artifact and the file on disk must agree byte for byte"
    );

    // Provenance and scope are honest: offline, tiny shape only, broader
    // coverage explicitly out of scope, no fetch.
    for fragment in [
        "not fetched",
        "no network",
        "tiny_site shape",
        "ahu-1",
        "vav-101",
        "sensor-sat-1",
        "out of scope",
        SUPPORTED_AHU_CLASS,
        SUPPORTED_VAV_CLASS,
        SUPPORTED_SAT_CLASS,
        "brick:Chiller",
        "brick:Boiler",
        "brick:Meter",
        PINNED_PROFILE_ID,
        VERDANT_NAMESPACE,
    ] {
        assert!(
            on_disk.contains(fragment),
            "pinned fixture missing honest scope fragment '{fragment}'"
        );
    }

    // Profile constants agree with the fixture (no drift).
    let profile = Profile::pinned();
    assert!(profile.is_supported(SUPPORTED_AHU_CLASS));
    assert!(profile.is_supported(SUPPORTED_VAV_CLASS));
    assert!(profile.is_supported(SUPPORTED_SAT_CLASS));
    assert_eq!(VerdantKind::Ahu.as_str(), "ahu");
    assert_eq!(VerdantKind::Vav.as_str(), "vav");
    assert_eq!(VerdantKind::SensorSat.as_str(), "sensor-sat");
}
