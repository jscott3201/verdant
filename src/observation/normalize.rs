//! Bounded scalar decoder for PR01B application-tag bytes, NOT domain Value JSON.
//! Tag layout follows the pinned rusty-bacnet 02dd371 encoding boundary. This is
//! a deliberately small synthetic profile, not general BACnet conformance.
use crate::domain::values::{Decimal, Diagnostic, KnownUnit, Unit, Value};
use crate::runtime::bacnet::{PropertyOutcome, MAX_VALUE_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Scalar,
    /// Explicit synthetic contract: application CharacterString, charset 0,
    /// contains an exact decimal lexical. Scalar never guesses this from text.
    ExactDecimalText,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitProvenance {
    SyntheticBinding(Unit),
    /// Explicit engineering-units property result, not inferred from value/tag.
    BacnetEngineeringUnits(u32),
    Absent,
}
impl UnitProvenance {
    pub fn unit(&self) -> Unit {
        match self {
            Self::SyntheticBinding(unit) => unit.clone(),
            // Pinned bacnet-types EngineeringUnits; no aliases or conversions.
            Self::BacnetEngineeringUnits(62) => Unit::Known(KnownUnit::DegC),
            Self::BacnetEngineeringUnits(98) => Unit::Known(KnownUnit::Percent),
            Self::BacnetEngineeringUnits(53) => Unit::Known(KnownUnit::Pascal),
            Self::BacnetEngineeringUnits(87) => Unit::Known(KnownUnit::LitresPerSecond),
            Self::BacnetEngineeringUnits(token) => Unit::Unknown(format!("bacnet-unit:{token}")),
            Self::Absent => Unit::Unknown("unit-not-supplied".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportResult {
    ValueReturned,
    RemoteError { class: u32, code: u32 },
    Reject(u8),
    Abort(u8),
    Timeout,
    InvalidReply,
    Oversized,
    Failure,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueQuality {
    Valid,
    Missing,
    Invalid,
    NonFinite,
    Unknown { detail: String },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Missing,
    Invalid,
    NonFinite,
    UnknownUnit,
    WrongUnit,
    Unsupported,
    Transport,
    NotFresh,
}
impl Refusal {
    /// Existing domain/semantic machine vocabulary; details remain separately
    /// typed so invalid values, unknown units and unsupported tags stay distinct.
    pub fn code(self) -> &'static str {
        match self {
            Self::Missing | Self::Invalid | Self::NonFinite => "invalid-value",
            Self::UnknownUnit => "invalid-input",
            Self::WrongUnit => "wrong-unit",
            Self::Unsupported | Self::Transport => "unexpected-type",
            Self::NotFresh => "impossible-elapsed",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suitability {
    /// Representation usable for a synthetic calculation, NEVER qualification.
    SyntheticValueOnly,
    Refused(Refusal),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub value: Value,
    pub unit: Unit,
    pub unit_provenance: UnitProvenance,
    pub codec: Codec,
    pub transport: TransportResult,
    pub quality: ValueQuality,
    pub suitability: Suitability,
}

pub fn decode(outcome: &PropertyOutcome, units: UnitProvenance, codec: Codec) -> Decoded {
    let transport = match outcome {
        PropertyOutcome::Value(_) => TransportResult::ValueReturned,
        PropertyOutcome::RemoteError { class, code } => TransportResult::RemoteError {
            class: *class,
            code: *code,
        },
        PropertyOutcome::Reject(reason) => TransportResult::Reject(*reason),
        PropertyOutcome::Abort(reason) => TransportResult::Abort(*reason),
        PropertyOutcome::Timeout => TransportResult::Timeout,
        PropertyOutcome::InvalidReply => TransportResult::InvalidReply,
        PropertyOutcome::Oversized => TransportResult::Oversized,
        PropertyOutcome::TransportFailure => TransportResult::Failure,
    };
    let (value, quality) = match outcome {
        PropertyOutcome::Value(bytes) => scalar(bytes, codec),
        _ => (Value::Missing, ValueQuality::Missing),
    };
    let unit = units.unit();
    let refusal = if transport != TransportResult::ValueReturned {
        Some(Refusal::Transport)
    } else {
        match &quality {
            ValueQuality::Missing => Some(Refusal::Missing),
            ValueQuality::Invalid => Some(Refusal::Invalid),
            ValueQuality::NonFinite => Some(Refusal::NonFinite),
            ValueQuality::Unknown { .. } => Some(Refusal::Unsupported),
            ValueQuality::Valid if unit.is_unknown() => Some(Refusal::UnknownUnit),
            ValueQuality::Valid if matches!(value, Value::Text(_)) => Some(Refusal::Unsupported),
            ValueQuality::Valid => None,
        }
    };
    Decoded {
        value,
        unit,
        unit_provenance: units,
        codec,
        transport,
        quality,
        suitability: refusal.map_or(Suitability::SyntheticValueOnly, Suitability::Refused),
    }
}

fn invalid(reason: &str) -> (Value, ValueQuality) {
    (
        Value::Diagnostic(Diagnostic::Invalid(reason.into())),
        ValueQuality::Invalid,
    )
}
fn unknown(reason: &str) -> (Value, ValueQuality) {
    (
        Value::Diagnostic(Diagnostic::Invalid(reason.into())),
        ValueQuality::Unknown {
            detail: reason.into(),
        },
    )
}
fn decimal(text: &str) -> (Value, ValueQuality) {
    match Decimal::parse(text) {
        Ok(value) => (Value::Decimal(value), ValueQuality::Valid),
        Err(_) => invalid("decimal outside exact lexical profile; original bytes retained"),
    }
}
fn real(value: f64, lexical: String) -> (Value, ValueQuality) {
    if value.is_finite() {
        if value == 0.0 && value.is_sign_negative() {
            decimal("-0.0")
        } else {
            decimal(&lexical)
        }
    } else {
        let diagnostic = if value.is_nan() {
            Diagnostic::NotANumber
        } else if value.is_sign_negative() {
            Diagnostic::NegativeInfinity
        } else {
            Diagnostic::PositiveInfinity
        };
        (Value::Diagnostic(diagnostic), ValueQuality::NonFinite)
    }
}

fn scalar(bytes: &[u8], codec: Codec) -> (Value, ValueQuality) {
    if bytes.is_empty() || bytes.len() > MAX_VALUE_BYTES {
        return invalid("empty or oversized application value");
    }
    let first = bytes[0];
    let tag = first >> 4;
    let lvt = first & 7;
    if first & 8 != 0 || tag >= 13 {
        return unknown("unsupported context/extended/reserved application tag");
    }
    if lvt > 5 {
        return invalid("reserved application length");
    }
    if codec == Codec::ExactDecimalText && tag != 7 {
        return unknown("exact decimal text profile requires CharacterString");
    }
    if tag == 1 {
        return if bytes.len() == 1 && lvt <= 1 {
            (Value::Bool(lvt == 1), ValueQuality::Valid)
        } else {
            invalid("boolean length/value")
        };
    }
    let (length, offset) = match lvt {
        0..=4 => (usize::from(lvt), 1),
        5 => match bytes.get(1) {
            Some(n @ 5..=253) => (usize::from(*n), 2),
            Some(254) if bytes.len() >= 4 => {
                let len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
                if len < 254 {
                    return invalid("noncanonical extended length");
                }
                (len, 4)
            }
            // Four-byte lengths cannot fit the PR01B 512-byte value bound.
            _ => return invalid("invalid or unbounded extended length"),
        },
        _ => return invalid("reserved length"),
    };
    if bytes.len() != offset + length {
        return invalid("scalar length/trailing bytes");
    }
    let body = &bytes[offset..];
    match tag {
        0 if body.is_empty() => (Value::Missing, ValueQuality::Missing),
        2 | 3 if (1..=8).contains(&body.len()) => {
            let mut number = if tag == 3 && body[0] & 128 != 0 { -1i128 } else { 0 };
            for byte in body {
                number = (number << 8) | i128::from(*byte);
            }
            (Value::Integer(number), ValueQuality::Valid)
        }
        4 if body.len() == 4 => {
            let value = f32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            // Protocol-resolution rendering, not an invented source lexical.
            real(f64::from(value), value.to_string())
        }
        5 if body.len() == 8 => {
            let value = f64::from_be_bytes([
                body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
            ]);
            real(value, value.to_string())
        }
        7 => {
            if body.first() != Some(&0) {
                return unknown("unsupported character encoding");
            }
            match std::str::from_utf8(&body[1..]) {
                Ok(text) if codec == Codec::ExactDecimalText => decimal(text),
                Ok(text) => (Value::Text(text.into()), ValueQuality::Valid),
                Err(_) => invalid("invalid UTF-8 character string"),
            }
        }
        0..=5 => invalid("invalid scalar width"),
        6 | 8..=12 => unknown("unsupported scalar tag/token; no mode or unit inference"),
        _ => unknown("unsupported tag"),
    }
}
