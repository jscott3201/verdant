use crate::domain::values::{Diagnostic, Unit, Value};
use crate::{observation::normalize::*, observation_support::*, runtime::bacnet::PropertyOutcome};

#[test]
fn codec_has_independent_tag_vectors_and_no_json_or_enum_guessing() {
    for input in [
        &[0x91, 1][..],
        &[0x81, 0],
        &[0x61, 1],
        &[0xd0],
        &[0xf0, 15],
        &[0x0e],
    ] {
        let decoded = decode(&PropertyOutcome::Value(input.into()), unit(), Codec::Scalar);
        assert!(matches!(decoded.quality, ValueQuality::Unknown { .. }));
        assert_eq!(decoded.suitability, Suitability::Refused(Refusal::Unsupported));
        assert_eq!(Refusal::Unsupported.code(), "unexpected-type");
    }
    let json = br#"{"type":"integer","value":"0"}"#;
    let decoded = decode(&PropertyOutcome::Value(json.to_vec()), unit(), Codec::Scalar);
    assert_ne!(decoded.value, Value::Integer(0));
    assert!(matches!(decoded.suitability, Suitability::Refused(_)));
    // Without the explicit decimal-text profile this remains text.
    let input = PropertyOutcome::Value(vec![0x75, 6, 0, b'2', b'1', b'.', b'5', b'0']);
    let decoded = decode(&input, unit(), Codec::Scalar);
    assert_eq!(decoded.value, Value::Text("21.50".into()));
    assert_eq!(decoded.suitability, Suitability::Refused(Refusal::Unsupported));
    assert!(matches!(
        decode(
            &PropertyOutcome::Value(vec![0x21, 0]),
            unit(),
            Codec::ExactDecimalText
        )
        .quality,
        ValueQuality::Unknown { .. }
    ));
}

#[test]
fn codec_unit_mapping_is_exact_known_four_with_explicit_provenance() {
    for (token, label) in [(62, "degC"), (98, "percent"), (53, "Pa"), (87, "L/s")] {
        let source = UnitProvenance::BacnetEngineeringUnits(token);
        let decoded = decode(
            &PropertyOutcome::Value(vec![0x21, 0]),
            source.clone(),
            Codec::Scalar,
        );
        assert_eq!(decoded.unit, Unit::parse(label).unwrap());
        assert_eq!(decoded.unit_provenance, source);
    }
    for token in [29, 95, 999, u32::MAX] {
        let decoded = decode(
            &PropertyOutcome::Value(vec![0x21, 0]),
            UnitProvenance::BacnetEngineeringUnits(token),
            Codec::Scalar,
        );
        assert_eq!(decoded.unit, Unit::Unknown(format!("bacnet-unit:{token}")));
        assert_eq!(decoded.suitability, Suitability::Refused(Refusal::UnknownUnit));
    }
    let decoded = decode(
        &PropertyOutcome::Value(vec![0x10]),
        UnitProvenance::Absent,
        Codec::Scalar,
    );
    assert_eq!(decoded.value, Value::Bool(false));
    assert_eq!(decoded.suitability, Suitability::Refused(Refusal::UnknownUnit));
}

#[test]
fn codec_transport_outcomes_remain_distinct_from_missing_and_value_quality() {
    for (outcome, expected) in [
        (
            PropertyOutcome::RemoteError { class: 2, code: 32 },
            TransportResult::RemoteError { class: 2, code: 32 },
        ),
        (PropertyOutcome::Reject(9), TransportResult::Reject(9)),
        (PropertyOutcome::Abort(10), TransportResult::Abort(10)),
        (PropertyOutcome::Timeout, TransportResult::Timeout),
        (PropertyOutcome::InvalidReply, TransportResult::InvalidReply),
        (PropertyOutcome::Oversized, TransportResult::Oversized),
        (PropertyOutcome::TransportFailure, TransportResult::Failure),
    ] {
        let decoded = decode(&outcome, unit(), Codec::Scalar);
        assert_eq!(decoded.transport, expected);
        assert_eq!(decoded.value, Value::Missing);
        assert_eq!(decoded.suitability, Suitability::Refused(Refusal::Transport));
    }
    let null = decode(&PropertyOutcome::Value(vec![0]), unit(), Codec::Scalar);
    assert_eq!(null.transport, TransportResult::ValueReturned);
    assert_eq!(null.quality, ValueQuality::Missing);
    assert_eq!(null.suitability, Suitability::Refused(Refusal::Missing));
}

#[test]
fn codec_lengths_numeric_limits_and_nonfinite_diagnostics_fail_closed() {
    for input in [
        vec![],
        vec![0x12],
        vec![0x10, 0],
        vec![0x20],
        vec![0x21, 0, 1],
        vec![0x55, 8, 0],
        vec![0x25, 4, 0, 0, 0, 0],
        vec![0x75, 254, 0, 6],
        vec![0x75, 255, 255, 255, 255, 255],
        vec![0; 513],
        vec![0x72, 0, 255],
    ] {
        let decoded = decode(&PropertyOutcome::Value(input), unit(), Codec::Scalar);
        assert_eq!(decoded.quality, ValueQuality::Invalid);
        assert_eq!(decoded.suitability, Suitability::Refused(Refusal::Invalid));
    }
    for (input, expected) in [
        (vec![0x44, 0x7f, 0x80, 0, 0], Diagnostic::PositiveInfinity),
        (vec![0x44, 0xff, 0x80, 0, 0], Diagnostic::NegativeInfinity),
        (vec![0x44, 0x7f, 0xc0, 0, 1], Diagnostic::NotANumber),
        (
            vec![0x55, 8, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0],
            Diagnostic::PositiveInfinity,
        ),
    ] {
        assert_eq!(
            decode(&PropertyOutcome::Value(input), unit(), Codec::Scalar).value,
            Value::Diagnostic(expected)
        );
    }
    let negative_zero = decode(
        &PropertyOutcome::Value(vec![0x44, 0x80, 0, 0, 0]),
        unit(),
        Codec::Scalar,
    );
    assert_eq!(
        negative_zero.value.to_json(),
        "{\"type\":\"decimal\",\"value\":\"-0.0\"}"
    );
    for text in ["NaN", "01", "1e3", "", "turbo"] {
        let mut input = vec![0x75, (text.len() + 1) as u8, 0];
        if text.len() < 4 {
            input = vec![0x70 | (text.len() + 1) as u8, 0];
        }
        input.extend_from_slice(text.as_bytes());
        assert_eq!(
            decode(&PropertyOutcome::Value(input), unit(), Codec::ExactDecimalText).quality,
            ValueQuality::Invalid
        );
    }
}

#[test]
fn codec_all_single_byte_inputs_are_bounded_and_never_panic() {
    for first in 0..=255 {
        let input = PropertyOutcome::Value(vec![first]);
        let decoded = decode(&input, unit(), Codec::Scalar);
        if !matches!(first, 0 | 0x10 | 0x11) {
            assert!(matches!(decoded.suitability, Suitability::Refused(_)));
        }
    }
}
