//! R07 FIXED matrix: exact admission, PR02 preservation, and pure conversion.
#[allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;
#[allow(dead_code)]
#[path = "../src/semantics/mod.rs"]
mod semantics;

use domain::ids::BindingRevision;
use domain::values::{OpMode, Unit, Value};
use semantics::convert::{apply, convert, BindingSet, ExternalItem, ExternalSite, SemanticsError};
use semantics::profile::{Profile, PINNED_SUBSET_JSON, SUPPORTED_MODES, SUPPORTED_UNITS};

fn site(class: &str, slot: &str, label: &str, unit: &str, value: Value) -> ExternalSite {
    ExternalSite::new(vec![ExternalItem::parse(
        "ext-1", class, slot, label, unit, value,
    )
    .expect("syntactic fixture")])
    .expect("one candidate")
}

fn refused_token(input: &ExternalSite, what: &'static str, token: &str) {
    let profile = Profile::pinned();
    let original = input.clone();
    let good = site("brick:AHU", "ahu-1", "AHU", "degC", Value::Missing);
    let current = BindingSet::from_conversion(
        &convert(&good, &profile).expect("known input"),
        BindingRevision::new(7),
    );
    let before = current.to_json();
    let error = convert(input, &profile).expect_err("closed vocabulary refusal");
    let detail = format!("unsupported {what} '{token}' for profile 'verdant-pinned-brick-223p-rec-v1' (exact closed vocabulary)");
    assert_eq!(error, SemanticsError::InvalidInput { what, detail });
    // Independent JSON template, never built with the production error encoder.
    let expected = format!("{{\"code\":\"invalid-input\",\"detail\":\"unsupported {what} '{token}' for profile 'verdant-pinned-brick-223p-rec-v1' (exact closed vocabulary)\",\"what\":\"{what}\"}}");
    assert_eq!(error.to_json().as_bytes(), expected.as_bytes());
    assert_eq!(convert(input, &profile).unwrap_err().to_json(), expected);
    assert_eq!(apply(input, &profile, &current).unwrap_err(), error);
    assert_eq!(input, &original, "refusal must preserve caller input");
    assert_eq!(
        current.to_json(),
        before,
        "refusal cannot mutate bound state"
    );
    println!("FIXED {what}={token:?}: {expected}");
}

#[test]
fn fixed_unit_matrix_is_closed_without_changing_pr02_preservation() {
    assert_eq!(SUPPORTED_UNITS, ["degC", "percent", "Pa", "L/s"]);
    for token in ["degC", "percent", "Pa", "L/s"] {
        let input = site("brick:AHU", "ahu-1", "AHU", token, Value::Integer(0));
        let converted = convert(&input, &Profile::pinned()).expect("known unit");
        assert!(converted.bindings()[0].unit().is_known());
        assert_eq!(converted.bindings()[0].unit(), &Unit::parse(token).unwrap());
        assert_eq!(converted.bindings()[0].value(), &Value::Integer(0));
        assert_eq!(converted.record().content_digest(), input.content_digest());
        println!(
            "FIXED unit={token:?}: {}",
            converted.bindings()[0].to_json()
        );
    }
    for token in [
        "furlongs-per-fortnight",
        "DEGc",
        "pa",
        "l/S",
        "Percent",
        "celsius",
        "%",
        "degF",
        " degC",
        "degC ",
    ] {
        let parsed = Unit::parse(token).unwrap();
        assert!(parsed.is_unknown());
        assert_eq!(Unit::from_json(&parsed.to_json()).unwrap(), parsed);
        let input = site("brick:AHU", "ahu-1", "AHU", token, Value::Missing);
        assert_eq!(input.items()[0].unit(), &parsed);
        refused_token(&input, "unit", token);
    }
}

#[test]
fn fixed_mode_matrix_is_closed_without_inference_from_text() {
    assert_eq!(SUPPORTED_MODES, ["occupied", "unoccupied", "standby"]);
    for (token, mode) in [
        ("occupied", OpMode::Occupied),
        ("unoccupied", OpMode::Unoccupied),
        ("standby", OpMode::Standby),
    ] {
        let value = Value::Mode(mode);
        let input = site("brick:AHU", "ahu-1", "AHU", "degC", value.clone());
        let converted = convert(&input, &Profile::pinned()).expect("known mode");
        assert_eq!(converted.bindings()[0].value(), &value);
        assert_eq!(converted.record().content_digest(), input.content_digest());
        println!(
            "FIXED mode={token:?}: {}",
            converted.bindings()[0].to_json()
        );
    }
    for token in [
        "turbo",
        "Occupied",
        "UNOCCUPIED",
        "StandBy",
        "auto",
        "occupied ",
    ] {
        let mode = OpMode::parse(token).unwrap();
        assert!(mode.is_unknown());
        assert_eq!(OpMode::from_json(&mode.to_json()).unwrap(), mode);
        refused_token(
            &site("brick:AHU", "ahu-1", "AHU", "degC", Value::Mode(mode)),
            "mode",
            token,
        );
    }
    // A publicly representable unknown must not be silently promoted to known.
    refused_token(
        &site(
            "brick:AHU",
            "ahu-1",
            "AHU",
            "degC",
            Value::Mode(OpMode::Unknown("occupied".into())),
        ),
        "mode",
        "occupied",
    );
    let text = site(
        "brick:AHU",
        "ahu-1",
        "VAV",
        "degC",
        Value::Text("turbo".into()),
    );
    assert_eq!(
        convert(&text, &Profile::pinned()).unwrap().bindings()[0].value(),
        &Value::Text("turbo".into())
    );
}

#[test]
fn fixed_class_matrix_is_exact_and_labels_grant_nothing() {
    for (class, slot, kind) in [
        ("brick:AHU", "ahu-1", "ahu"),
        ("brick:VAV", "vav-101", "vav"),
        (
            "brick:Supply_Air_Temperature_Sensor",
            "sensor-sat-1",
            "sensor-sat",
        ),
    ] {
        let input = site(class, slot, "VAV", "degC", Value::Missing);
        let converted = convert(&input, &Profile::pinned()).unwrap();
        assert_eq!(converted.bindings()[0].kind().as_str(), kind);
        assert_eq!(converted.bindings()[0].label(), "VAV");
        println!(
            "FIXED class={class:?}: {}",
            converted.bindings()[0].to_json()
        );
    }
    for class in [
        "brick:ahu",
        "Brick:AHU",
        "brick:vav",
        "brick:supply_air_temperature_sensor",
        "brick:Air_Handling_Unit",
        "AHU",
        "VAV",
        "223p:AHU",
        "rec:AHU",
        "brick:Unknown",
    ] {
        let input = site(class, "ahu-1", "VAV", "degC", Value::Missing);
        let original = input.clone();
        let error = convert(&input, &Profile::pinned()).unwrap_err();
        let expected = format!("{{\"code\":\"unknown-class\",\"class\":\"{class}\",\"profile\":\"verdant-pinned-brick-223p-rec-v1\"}}");
        assert_eq!(error.code(), "unknown-class");
        assert_eq!(error.to_json(), expected);
        assert_eq!(input, original);
        println!("FIXED class={class:?}: {expected}");
    }
    for class in ["brick:Boiler", "brick:Chiller", "brick:Meter"] {
        let input = site(class, "ahu-1", "VAV", "degC", Value::Missing);
        let expected = format!("{{\"code\":\"out-of-scenario\",\"class\":\"{class}\",\"profile\":\"verdant-pinned-brick-223p-rec-v1\",\"reason\":\"known Brick class but outside tiny_site scenario for this profile (v1 covers only AHU, VAV and SAT sensor)\"}}");
        assert_eq!(
            convert(&input, &Profile::pinned()).unwrap_err().to_json(),
            expected
        );
    }
}

#[test]
fn ahu_9_is_a_prefix_match_not_proof_of_installation_and_conversion_is_pure() {
    let input = site("brick:AHU", "ahu-9", "VAV", "degC", Value::Missing);
    let original = input.clone();
    let profile = Profile::pinned();
    let conversion = convert(&input, &profile).unwrap();
    let expected = "{\"external_class\":\"brick:AHU\",\"kind\":\"ahu\",\"label\":\"VAV\",\"source_key\":\"ext-1\",\"unit\":\"degC\",\"value\":{\"type\":\"missing\"},\"verdant_id\":\"ahu-9\",\"verdant_namespace\":\"verdant:v1\"}";
    assert_eq!(conversion.bindings()[0].to_json(), expected);
    let current = BindingSet::from_conversion(&conversion, BindingRevision::new(7));
    let before = current.clone();
    assert!(apply(&input, &profile, &current).unwrap().is_noop());
    let changed = site("brick:AHU", "ahu-9", "AHU", "degC", Value::Missing);
    assert!(!apply(&changed, &profile, &current).unwrap().is_noop());
    assert_eq!(current, before);
    assert_eq!(input, original);
    assert_eq!(
        convert(&input, &profile).unwrap().to_json(),
        conversion.to_json()
    );
    assert_eq!(
        input.content_digest(),
        changed.content_digest(),
        "label is not identity/content"
    );
    println!("FIXED ahu-9: {expected}");
}

#[test]
fn pinned_vocabulary_artifact_agrees_with_independent_literals() {
    assert!(PINNED_SUBSET_JSON
        .contains("\"supported_units\": [\"degC\", \"percent\", \"Pa\", \"L/s\"]"));
    assert!(PINNED_SUBSET_JSON
        .contains("\"supported_modes\": [\"occupied\", \"unoccupied\", \"standby\"]"));
    assert!(PINNED_SUBSET_JSON.contains("not an installed-identity allowlist"));
    assert!(PINNED_SUBSET_JSON
        .contains("no case folding, synonyms, unit conversion or label inference"));
}

#[test]
fn vocabulary_refusal_order_is_deterministic_and_keeps_class_slot_precedence() {
    let profile = Profile::pinned();
    for (class, slot, code) in [
        ("brick:ahu", "ahu-1", "unknown-class"),
        ("brick:AHU", "vav-101", "slot-mismatch"),
    ] {
        let input = site(
            class,
            slot,
            "VAV",
            "DEGc",
            Value::Mode(OpMode::Unknown("turbo".into())),
        );
        assert_eq!(convert(&input, &profile).unwrap_err().code(), code);
    }
    let first =
        ExternalItem::parse("a", "brick:AHU", "ahu-1", "AHU", "pa", Value::Missing).unwrap();
    let second = ExternalItem::parse(
        "b",
        "brick:AHU",
        "ahu-2",
        "AHU",
        "degC",
        Value::Mode(OpMode::Unknown("turbo".into())),
    )
    .unwrap();
    let ordered = ExternalSite::new(vec![first.clone(), second.clone()]).unwrap();
    let reversed = ExternalSite::new(vec![second, first]).unwrap();
    refused_token(&ordered, "unit", "pa");
    assert_eq!(
        convert(&ordered, &profile).unwrap_err().to_json(),
        convert(&reversed, &profile).unwrap_err().to_json()
    );
}
