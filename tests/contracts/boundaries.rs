//! Independent PR02 boundary fixtures: hardcoded JSON vs native values.
//!
//! Every `EXPECTED_*` string below is an independent literal, not encoder
//! output. Each test asserts both directions: `from_json(EXPECTED) == native`
//! and `native.to_json() == EXPECTED`. Whitespace-tolerant decoding is probed
//! with spaced variants. Refusal cases assert typed errors, never panics on
//! malformed input.

use crate::domain::clock::{BootId, MonotonicMark, TimeTriple, UnixMillis};
use crate::domain::fixture::{tiny_site, Relationship};
use crate::domain::ids::{
    AcquisitionStreamId, BindingRevision, InstalledId, OperationId, RuleActivationId,
    SourceGenerationId,
};
use crate::domain::outcomes::{OperationOutcome, RecordIdentity, Release};
use crate::domain::scope::{CredentialCeiling, TrustedScope};
use crate::domain::values::{Decimal, Diagnostic, OpMode, Unit, Value};

// ---------------------------------------------------------------------------
// Values: false vs zero vs missing vs invalid vs diagnostics, exact quantities.
// ---------------------------------------------------------------------------

#[test]
fn missing_is_explicit_not_zero_or_false() {
    let expected = "{\"type\":\"missing\"}";
    let native = Value::Missing;
    assert_eq!(native.to_json(), expected);
    assert_eq!(Value::from_json(expected).expect("decode"), native);
    assert!(native.is_missing());
    assert_ne!(native, Value::Bool(false));
    assert_ne!(native, Value::Integer(0));
}

#[test]
fn boolean_false_survives_as_value_not_absence() {
    let expected_false = "{\"type\":\"bool\",\"value\":false}";
    let expected_true = "{\"type\":\"bool\",\"value\":true}";
    assert_eq!(Value::Bool(false).to_json(), expected_false);
    assert_eq!(Value::Bool(true).to_json(), expected_true);
    assert_eq!(
        Value::from_json(expected_false).expect("decode"),
        Value::Bool(false)
    );
    // Whitespace tolerance: same meaning with spaces/newlines.
    assert_eq!(
        Value::from_json("{ \"type\" : \"bool\" , \"value\" : false }").expect("decode"),
        Value::Bool(false)
    );
}

#[test]
fn zero_integer_is_distinct_from_false() {
    let expected = "{\"type\":\"integer\",\"value\":\"0\"}";
    let native = Value::Integer(0);
    assert_eq!(native.to_json(), expected);
    assert_eq!(Value::from_json(expected).expect("decode"), native);
    assert_ne!(native, Value::Bool(false));
    assert_ne!(native, Value::Missing);
}

#[test]
fn large_integers_preserved_exactly_as_strings() {
    // 2^53 + 1: first integer above f64 exactness.
    let expected = "{\"type\":\"integer\",\"value\":\"9007199254740993\"}";
    let native = Value::Integer(9_007_199_254_740_993);
    assert_eq!(native.to_json(), expected);
    assert_eq!(Value::from_json(expected).expect("decode"), native);

    // i128 extremes survive without float rounding.
    for (raw, num) in [
        ("170141183460469231731687303715884105727", i128::MAX),
        ("-170141183460469231731687303715884105728", i128::MIN),
    ] {
        let expected = format!("{{\"type\":\"integer\",\"value\":\"{raw}\"}}");
        let native = Value::Integer(num);
        assert_eq!(native.to_json(), expected);
        assert_eq!(Value::from_json(&expected).expect("decode"), native);
    }
}

#[test]
fn decimals_preserve_exact_lexical_including_trailing_zero_and_negzero() {
    let expected = "{\"type\":\"decimal\",\"value\":\"21.50\"}";
    let native = Value::Decimal(Decimal::parse("21.50").expect("decimal"));
    assert_eq!(native.to_json(), expected);
    assert_eq!(Value::from_json(expected).expect("decode"), native);
    // Trailing zero matters: "21.50" != "21.5".
    assert_ne!(
        native,
        Value::Decimal(Decimal::parse("21.5").expect("decimal"))
    );

    let expected_negzero = "{\"type\":\"decimal\",\"value\":\"-0.0\"}";
    let native_negzero = Value::Decimal(Decimal::parse("-0.0").expect("decimal"));
    assert_eq!(native_negzero.to_json(), expected_negzero);
    assert_eq!(
        Value::from_json(expected_negzero).expect("decode"),
        native_negzero
    );
    assert_ne!(
        native_negzero,
        Value::Decimal(Decimal::parse("0.0").expect("decimal"))
    );
}

#[test]
fn diagnostic_non_finite_are_tagged_not_numbers() {
    for (expected, native) in [
        (
            "{\"type\":\"diagnostic\",\"kind\":\"+inf\"}",
            Value::Diagnostic(Diagnostic::PositiveInfinity),
        ),
        (
            "{\"type\":\"diagnostic\",\"kind\":\"-inf\"}",
            Value::Diagnostic(Diagnostic::NegativeInfinity),
        ),
        (
            "{\"type\":\"diagnostic\",\"kind\":\"nan\"}",
            Value::Diagnostic(Diagnostic::NotANumber),
        ),
        (
            "{\"type\":\"diagnostic\",\"kind\":\"invalid\",\"detail\":\"gated nan\"}",
            Value::Diagnostic(Diagnostic::Invalid("gated nan".to_string())),
        ),
    ] {
        assert_eq!(native.to_json(), expected);
        assert_eq!(Value::from_json(expected).expect("decode"), native);
    }
    // Ordinary JSON numbers are not valid Value encodings here.
    assert!(Value::from_json("NaN").is_err());
    assert!(Value::from_json("Infinity").is_err());
    assert!(Value::from_json("{\"type\":\"decimal\",\"value\":\"NaN\"}").is_err());
}

#[test]
fn unknown_enums_and_units_preserved_as_unknown() {
    // Unknown mode "turbo" round-trips as unknown, not coerced.
    let expected_mode = "{\"type\":\"mode\",\"value\":\"turbo\"}";
    let native_mode = Value::Mode(OpMode::parse("turbo").expect("unknown mode"));
    assert_eq!(native_mode.to_json(), expected_mode);
    assert_eq!(
        Value::from_json(expected_mode).expect("decode"),
        native_mode
    );
    match native_mode {
        Value::Mode(m) => assert!(m.is_unknown()),
        _ => panic!("expected mode value"),
    }

    // Known mode stays known.
    assert_eq!(
        Value::Mode(OpMode::parse("occupied").expect("known")).to_json(),
        "{\"type\":\"mode\",\"value\":\"occupied\"}"
    );

    // Unknown unit preserved via its own string encoding.
    let expected_unit = "\"furlongs-per-fortnight\"";
    let native_unit = Unit::parse("furlongs-per-fortnight").expect("unknown unit");
    assert!(native_unit.is_unknown());
    assert_eq!(native_unit.to_json(), expected_unit);
    assert_eq!(Unit::from_json(expected_unit).expect("decode"), native_unit);
    assert_eq!(Unit::parse("degC").expect("known").as_str(), "degC");
}

// ---------------------------------------------------------------------------
// Identities: installed vs business vs generation vs placeholders.
// ---------------------------------------------------------------------------

#[test]
fn identities_are_distinct_representations() {
    let installed = InstalledId::parse("ahu-1").expect("installed");
    let operation = OperationId::parse("op-1").expect("operation");
    let generation = SourceGenerationId::parse("gen-1").expect("generation");
    let stream = AcquisitionStreamId::parse("stream-1").expect("stream");
    let activation = RuleActivationId::parse("act-1").expect("activation");
    assert_eq!(installed.to_json(), "\"ahu-1\"");
    assert_eq!(operation.to_json(), "\"op-1\"");
    assert_eq!(generation.to_json(), "\"gen-1\"");
    assert_eq!(stream.to_json(), "\"stream-1\"");
    assert_eq!(activation.to_json(), "\"act-1\"");
    assert_eq!(
        InstalledId::from_json("\"ahu-1\"").expect("decode"),
        installed
    );
    // Business ids are not protocol request ids: text may look similar but the
    // type is distinct (no conversion exists; this is a compile-time property
    // exercised here by keeping the values in separate bindings).
    let business = OperationId::parse("req-9").expect("business text");
    assert_eq!(business.as_str(), "req-9");

    // Binding revision placeholder round-trips.
    assert_eq!(BindingRevision::PLACEHOLDER.to_json(), "\"0\"");
    assert_eq!(
        BindingRevision::from_json("\"0\"").expect("decode"),
        BindingRevision::PLACEHOLDER
    );
}

#[test]
fn labels_are_not_installed_identity() {
    // Display text with spaces/parentheses is refused as installed identity.
    assert!(InstalledId::parse("AHU 1 (roof)").is_err());
    assert!(InstalledId::parse("").is_err());
}

// ---------------------------------------------------------------------------
// Scope and ceiling: caller strings cannot manufacture trusted context.
// ---------------------------------------------------------------------------

#[test]
fn trusted_scope_and_ceiling_positive_paths() {
    let expected_scope = "{\"scope\":\"scope-a\"}";
    let scope = TrustedScope::parse("scope-a").expect("scope");
    assert_eq!(scope.to_json(), expected_scope);
    assert_eq!(
        TrustedScope::from_json(expected_scope).expect("decode"),
        scope
    );

    let expected_ceiling = "{\"scope\":\"scope-a\",\"ceiling\":\"2\"}";
    let ceiling = CredentialCeiling::new(scope, 2).expect("ceiling");
    assert_eq!(ceiling.to_json(), expected_ceiling);
    assert_eq!(
        CredentialCeiling::from_json(expected_ceiling).expect("decode"),
        ceiling
    );
}

#[test]
fn caller_strings_cannot_manufacture_trusted_context() {
    // Every refusal below is a typed error, not a fallback trusted value.
    assert!(TrustedScope::parse("").is_err());
    assert!(TrustedScope::parse("scope A").is_err());
    assert!(TrustedScope::parse("scope-a;admin").is_err());
    assert!(TrustedScope::from_json("{\"scope\":\"\"}").is_err());
    assert!(TrustedScope::from_json("{\"scope\":\"scope A\"}").is_err());
    assert!(TrustedScope::from_json("{}").is_err());
    assert!(TrustedScope::from_json("{\"scope\":\"scope-a\",\"extra\":\"1\"}").is_err());

    // Ceiling above the max is refused, never clamped.
    let scope = TrustedScope::parse("scope-a").expect("scope");
    assert!(CredentialCeiling::new(scope.clone(), 3).is_ok());
    assert!(CredentialCeiling::new(scope, 4).is_err());
    assert!(CredentialCeiling::from_json("{\"scope\":\"scope-a\",\"ceiling\":\"9\"}").is_err());
}

// ---------------------------------------------------------------------------
// Clock: checked order, boot-scoped monotonic, no Instant history.
// ---------------------------------------------------------------------------

#[test]
fn time_triple_preserves_order_and_refuses_impossible() {
    let expected = "{\"source_ms\":\"1700000000123\",\"receipt_ms\":\"1700000000456\",\"ingestion_ms\":\"1700000000789\"}";
    let triple = TimeTriple::new(
        UnixMillis::new(1_700_000_000_123),
        UnixMillis::new(1_700_000_000_456),
        UnixMillis::new(1_700_000_000_789),
    )
    .expect("triple");
    assert_eq!(triple.to_json(), expected);
    assert_eq!(TimeTriple::from_json(expected).expect("decode"), triple);

    // Receipt before source is impossible.
    assert!(TimeTriple::new(
        UnixMillis::new(200),
        UnixMillis::new(100),
        UnixMillis::new(300),
    )
    .is_err());
    // Independent JSON with impossible order is refused, not reordered.
    assert!(TimeTriple::from_json(
        "{\"source_ms\":\"200\",\"receipt_ms\":\"100\",\"ingestion_ms\":\"300\"}"
    )
    .is_err());
}

#[test]
fn monotonic_marks_are_boot_scoped_with_checked_elapsed() {
    let expected = "{\"boot\":\"boot-7\",\"nanos_since_boot\":\"1234567\"}";
    let mark = MonotonicMark::new(BootId::parse("boot-7").expect("boot"), 1_234_567);
    assert_eq!(mark.to_json(), expected);
    assert_eq!(MonotonicMark::from_json(expected).expect("decode"), mark);

    let start = MonotonicMark::new(BootId::parse("boot-7").expect("boot"), 1_000);
    let end = MonotonicMark::new(BootId::parse("boot-7").expect("boot"), 2_500);
    assert_eq!(
        end.elapsed_since(&start).expect("elapsed"),
        std::time::Duration::from_nanos(1_500)
    );
    // Impossible elapsed (end before start) is refused.
    assert!(start.elapsed_since(&end).is_err());
    // Cross-boot elapsed is refused, never silently subtracted.
    let other = MonotonicMark::new(BootId::parse("boot-8").expect("boot"), 2_500);
    assert!(other.elapsed_since(&start).is_err());
}

// ---------------------------------------------------------------------------
// Outcomes: commit / refusal-noncommit / conflict / unresolved, release.
// ---------------------------------------------------------------------------

#[test]
fn mutation_outcomes_distinguish_four_states() {
    let cases = [
        (
            "{\"status\":\"committed\",\"operation\":\"op-1\",\"detail\":\"applied\"}",
            "committed",
        ),
        (
            "{\"status\":\"refused\",\"operation\":\"op-2\",\"detail\":\"ceiling denied\"}",
            "refused",
        ),
        (
            "{\"status\":\"conflict\",\"operation\":\"op-3\",\"detail\":\"expected revision lost\"}",
            "conflict",
        ),
        (
            "{\"status\":\"unresolved\",\"operation\":\"op-4\",\"detail\":\"response lost; reconcile by op-4\"}",
            "unresolved",
        ),
    ];
    for (expected, status) in cases {
        let outcome = OperationOutcome::from_json(expected).expect("decode");
        assert_eq!(outcome.status(), status);
        assert_eq!(outcome.to_json(), expected);
        assert_eq!(
            OperationOutcome::from_json(&outcome.to_json()).expect("re-decode"),
            outcome
        );
    }

    // Unknown commit is NOT rollback and NOT refusal: the unresolved outcome
    // reports false for both committed and refused.
    let unresolved = OperationOutcome::from_json(
        "{\"status\":\"unresolved\",\"operation\":\"op-4\",\"detail\":\"response lost\"}",
    )
    .expect("decode");
    assert!(unresolved.is_unresolved());
    assert!(!unresolved.is_committed());
    assert!(!unresolved.is_refused());
    assert!(!unresolved.is_conflict());

    // No rollback status exists.
    assert!(OperationOutcome::from_json(
        "{\"status\":\"rolled-back\",\"operation\":\"op-1\",\"detail\":\"x\"}"
    )
    .is_err());
}

#[test]
fn release_is_explicit_operation_with_round_trip() {
    let expected = "{\"operation\":\"op-release-1\",\"target\":\"ahu-1\"}";
    let release = Release::new(
        OperationId::parse("op-release-1").expect("op"),
        InstalledId::parse("ahu-1").expect("ahu"),
    );
    assert_eq!(release.to_json(), expected);
    assert_eq!(Release::from_json(expected).expect("decode"), release);
    assert!(Release::from_json("{\"operation\":\"op-release-1\"}").is_err());
}

#[test]
fn restored_counters_do_not_reuse_identity_across_generations() {
    let old = RecordIdentity::new(SourceGenerationId::parse("gen-1").expect("gen"), 41);
    let same_seq_new_gen =
        RecordIdentity::new(SourceGenerationId::parse("gen-2").expect("gen"), 41);
    assert_ne!(old, same_seq_new_gen);
    assert!(!old.is_same_record(&same_seq_new_gen));

    let expected = "{\"generation\":\"gen-1\",\"seq\":\"41\"}";
    assert_eq!(old.to_json(), expected);
    assert_eq!(RecordIdentity::from_json(expected).expect("decode"), old);
}

// ---------------------------------------------------------------------------
// Fixture: two scopes, AHU + two VAVs, shared sensor, distinct relationships.
// ---------------------------------------------------------------------------

#[test]
fn tiny_site_holds_two_scopes_ahu_two_vavs_and_shared_sensor() {
    let site = tiny_site();
    assert_eq!(site.scopes[0].as_str(), "scope-a");
    assert_eq!(site.scopes[1].as_str(), "scope-b");
    assert_eq!(site.ahu.as_str(), "ahu-1");
    assert_eq!(site.vavs[0].as_str(), "vav-101");
    assert_eq!(site.vavs[1].as_str(), "vav-102");
    assert_eq!(site.shared_sensor.as_str(), "sensor-sat-1");
    assert_ne!(site.vavs[0], site.vavs[1]);
    assert_eq!(site.label_of(&site.vavs[0]), Some("VAV"));
    assert_eq!(site.label_of(&site.vavs[1]), Some("VAV"));
}

#[test]
fn tiny_site_relationships_keep_spatial_and_service_distinct() {
    let site = tiny_site();
    let mut spatial = 0;
    let mut service = 0;
    let mut sensing = 0;
    for rel in &site.relationships {
        match rel {
            Relationship::LocatedIn { .. } => spatial += 1,
            Relationship::ServedBy { .. } => service += 1,
            Relationship::ObservedBy { .. } => sensing += 1,
        }
    }
    assert!(spatial >= 3, "spatial edges present");
    assert_eq!(service, 2, "both VAVs served by the one AHU");
    assert_eq!(sensing, 3, "shared sensor observes AHU + two VAVs");
}

#[test]
fn tiny_site_readings_cover_exact_and_exceptional_values() {
    let site = tiny_site();
    let has = |pred: fn(&Value) -> bool| site.readings.iter().any(|r| pred(&r.value));
    assert!(has(|v| *v == Value::Integer(9_007_199_254_740_993)));
    assert!(has(
        |v| *v == Value::Decimal(Decimal::parse("21.50").expect("decimal"))
    ));
    assert!(has(|v| *v == Value::Integer(0)));
    assert!(has(|v| *v == Value::Bool(false)));
    assert!(has(|v| *v == Value::Missing));
    assert!(has(|v| matches!(
        v,
        Value::Diagnostic(Diagnostic::PositiveInfinity)
    )));
    assert!(has(|v| matches!(
        v,
        Value::Diagnostic(Diagnostic::NotANumber)
    )));
    assert!(site
        .readings
        .iter()
        .any(|r| r.unit == Unit::parse("furlongs-per-fortnight").expect("unknown")));
}

#[test]
fn independent_reading_fixture_decodes_to_expected_native() {
    // Fully independent literal: not produced by `to_json`.
    let expected = concat!(
        "{\"scope\":\"scope-a\",",
        "\"entity\":\"ahu-1\",",
        "\"sensor\":\"sensor-sat-1\",",
        "\"value\":{\"type\":\"decimal\",\"value\":\"21.50\"},",
        "\"unit\":\"degC\",",
        "\"source_ms\":\"1700000000123\",",
        "\"receipt_ms\":\"1700000000456\",",
        "\"ingestion_ms\":\"1700000000789\"}"
    );
    let reading = crate::domain::fixture::Reading::from_json(expected).expect("decode");
    assert_eq!(reading.scope.as_str(), "scope-a");
    assert_eq!(reading.entity.as_str(), "ahu-1");
    assert_eq!(reading.sensor.as_str(), "sensor-sat-1");
    assert_eq!(
        reading.value,
        Value::Decimal(Decimal::parse("21.50").expect("decimal"))
    );
    assert_eq!(reading.unit, Unit::parse("degC").expect("unit"));
    // Re-encoding yields the same canonical literal.
    assert_eq!(reading.to_json(), expected);

    // Unknown-unit reading preserves its label through the same path.
    let unknown = concat!(
        "{\"scope\":\"scope-b\",",
        "\"entity\":\"vav-101\",",
        "\"sensor\":\"sensor-sat-1\",",
        "\"value\":{\"type\":\"mode\",\"value\":\"turbo\"},",
        "\"unit\":\"furlongs-per-fortnight\",",
        "\"source_ms\":\"1700000000123\",",
        "\"receipt_ms\":\"1700000000456\",",
        "\"ingestion_ms\":\"1700000000789\"}"
    );
    let reading = crate::domain::fixture::Reading::from_json(unknown).expect("decode");
    assert_eq!(reading.unit.as_str(), "furlongs-per-fortnight");
    assert_eq!(reading.to_json(), unknown);
}

#[test]
fn all_fixture_readings_and_relationships_round_trip() {
    let site = tiny_site();
    for reading in &site.readings {
        let json = reading.to_json();
        assert_eq!(
            crate::domain::fixture::Reading::from_json(&json).expect("round-trip"),
            *reading
        );
    }
    for rel in &site.relationships {
        let json = rel.to_json();
        assert_eq!(Relationship::from_json(&json).expect("round-trip"), *rel);
    }
}
