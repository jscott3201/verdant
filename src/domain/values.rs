//! Exact and diagnostic values.
//!
//! Finite consequential quantities keep their exact text: large integers as
//! `i128` (never rounded through `f64`) and decimals as their original
//! lexical form (see [`Decimal`]). `false`, `0`/`"0"`/`"0.0"`, missing,
//! invalid and tagged non-finite diagnostics are distinct (see [`Value`]).
//! Unknown enums/units are preserved as unknown, never coerced
//! (see [`Unit`], [`OpMode`]).
//!
//! Boundary rule (from the runtime contract): finite measurements are typed
//! values; missing is an explicit reason, not an invented sample;
//! non-finite computed diagnostics are tagged (`+inf`/`-inf`/`NaN`) with
//! source/gate context, not ordinary JSON numbers or silent healthy nulls;
//! requested relinquishment is an explicit operation ([`crate::outcomes::Release`]),
//! never inferred from missing JSON.
//!
//! No universal numeric framework: only the immediate examples are frozen.
//! Field values may legitimately use finite floats at protocol resolution;
//! PR02 does not convert all arithmetic to decimal.

use super::Error;

/// Maximum decimal lexical length (bytes; all decimal chars are ASCII).
pub const MAX_DECIMAL_LEN: usize = 64;

/// Exact decimal quantity preserving its lexical form.
///
/// `"21.50"` stays `"21.50"` (trailing zero kept); `"-0.0"` stays `"-0.0"`
/// and differs from `"0.0"`. Construction validates the grammar
/// `-?(0|[1-9][0-9]*)(\.[0-9]+)?`; non-finite words (`inf`/`nan`) are refused
/// here and belong in [`Diagnostic`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Decimal(String);

impl Decimal {
    /// Validate `raw` into an exact decimal.
    pub fn parse(raw: &str) -> Result<Decimal, Error> {
        if raw.is_empty() {
            return Err(Error::Empty { what: "decimal" });
        }
        if raw.len() > MAX_DECIMAL_LEN {
            return Err(Error::TooLong {
                what: "decimal",
                len: raw.len(),
                max: MAX_DECIMAL_LEN,
            });
        }
        if !is_decimal_lexical(raw) {
            return Err(Error::InvalidValue {
                what: "decimal",
                value: raw.to_string(),
            });
        }
        Ok(Decimal(raw.to_string()))
    }

    /// Borrow the exact lexical form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encode as `{"decimal":"21.50"}` is handled by [`Value`]; this helper
    /// encodes the bare quoted string for unit tests.
    #[cfg(test)]
    fn to_json_string(&self) -> String {
        super::json::quote(&self.0)
    }
}

fn is_decimal_lexical(raw: &str) -> bool {
    let body = raw.strip_prefix('-').unwrap_or(raw);
    if body.is_empty() {
        return false;
    }
    let (int_part, frac_part) = match body.find('.') {
        None => (body, None),
        Some(dot) => {
            let (int, frac_with_dot) = body.split_at(dot);
            // `frac_with_dot` starts with '.'; require at least one digit after.
            let frac = &frac_with_dot[1..];
            if frac.is_empty() {
                return false;
            }
            (int, Some(frac))
        }
    };
    if int_part.is_empty() {
        return false;
    }
    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // Canonical integers: "0" or non-zero without leading zeros.
    if int_part.len() > 1 && int_part.starts_with('0') {
        return false;
    }
    if let Some(frac) = frac_part {
        if frac.is_empty() || !frac.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

/// Tagged non-finite diagnostic or invalid-reason holder.
///
/// `+inf`/`-inf`/`NaN` are diagnostics, never ordinary values. `Invalid`
/// carries a human-readable reason and is distinct from missing
/// ([`Value::Missing`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Diagnostic {
    PositiveInfinity,
    NegativeInfinity,
    NotANumber,
    Invalid(String),
}

impl Diagnostic {
    /// Canonical kind string: `"+inf"`, `"-inf"`, `"nan"`, `"invalid"`.
    pub fn kind(&self) -> &'static str {
        match self {
            Diagnostic::PositiveInfinity => "+inf",
            Diagnostic::NegativeInfinity => "-inf",
            Diagnostic::NotANumber => "nan",
            Diagnostic::Invalid(_) => "invalid",
        }
    }

    /// Detail text for `Invalid`; empty for the non-finite kinds.
    pub fn detail(&self) -> &str {
        match self {
            Diagnostic::Invalid(detail) => detail,
            _ => "",
        }
    }

    /// Construct from kind + detail as they appear in JSON.
    pub fn from_parts(kind: &str, detail: Option<&str>) -> Result<Diagnostic, Error> {
        match kind {
            "+inf" => Ok(Diagnostic::PositiveInfinity),
            "-inf" => Ok(Diagnostic::NegativeInfinity),
            "nan" => Ok(Diagnostic::NotANumber),
            "invalid" => Ok(Diagnostic::Invalid(detail.unwrap_or("").to_string())),
            other => Err(Error::UnexpectedType {
                expected: "+inf/-inf/nan/invalid",
                got: other.to_string(),
            }),
        }
    }
}

/// Known display/engineering units for the frozen examples.
///
/// These are labels only; PR02 claims no ontology equivalence and no physics.
/// Unknown units (e.g. `"furlongs-per-fortnight"`) are preserved as
/// [`Unit::Unknown`], never coerced to a known unit and never blocking the
/// preservation round-trip (dependent calculations must still refuse them;
/// that refusal lives with the later consumer, not here).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KnownUnit {
    DegC,
    Percent,
    Pascal,
    LitresPerSecond,
}

impl KnownUnit {
    fn parse(raw: &str) -> Option<KnownUnit> {
        match raw {
            "degC" => Some(KnownUnit::DegC),
            "percent" => Some(KnownUnit::Percent),
            "Pa" => Some(KnownUnit::Pascal),
            "L/s" => Some(KnownUnit::LitresPerSecond),
            _ => None,
        }
    }
}

/// Unit that preserves unknown values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Unit {
    Known(KnownUnit),
    Unknown(String),
}

impl Unit {
    /// Parse a unit label. Known labels become [`Unit::Known`]; any other
    /// non-empty label becomes [`Unit::Unknown`] (preserved, not coerced).
    /// Empty text is refused.
    pub fn parse(raw: &str) -> Result<Unit, Error> {
        if raw.is_empty() {
            return Err(Error::Empty { what: "unit" });
        }
        if raw.len() > 128 {
            return Err(Error::TooLong {
                what: "unit",
                len: raw.len(),
                max: 128,
            });
        }
        match KnownUnit::parse(raw) {
            Some(known) => Ok(Unit::Known(known)),
            None => Ok(Unit::Unknown(raw.to_string())),
        }
    }

    /// Borrow the canonical label text.
    pub fn as_str(&self) -> &str {
        match self {
            Unit::Known(known) => match known {
                KnownUnit::DegC => "degC",
                KnownUnit::Percent => "percent",
                KnownUnit::Pascal => "Pa",
                KnownUnit::LitresPerSecond => "L/s",
            },
            Unit::Unknown(raw) => raw,
        }
    }

    /// True for [`Unit::Known`].
    pub fn is_known(&self) -> bool {
        matches!(self, Unit::Known(_))
    }

    /// True for [`Unit::Unknown`].
    pub fn is_unknown(&self) -> bool {
        matches!(self, Unit::Unknown(_))
    }

    /// Encode as a JSON string.
    pub fn to_json(&self) -> String {
        super::json::quote(self.as_str())
    }

    /// Decode from a JSON string; preserves unknown labels.
    pub fn from_json(text: &str) -> Result<Unit, Error> {
        let raw = super::json::parse_string_literal(text).map_err(|e| Error::Json {
            message: format!("unit: {e}"),
        })?;
        Unit::parse(&raw)
    }
}

/// Operating mode example with unknown preservation.
///
/// Frozen known modes: `"occupied"`, `"unoccupied"`, `"standby"`. Any other
/// non-empty label (e.g. `"turbo"`) becomes [`OpMode::Unknown`] and round-trips
/// unchanged. Empty text is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OpMode {
    Occupied,
    Unoccupied,
    Standby,
    Unknown(String),
}

impl OpMode {
    /// Parse a mode label, preserving unknown values.
    pub fn parse(raw: &str) -> Result<OpMode, Error> {
        if raw.is_empty() {
            return Err(Error::Empty { what: "mode" });
        }
        if raw.len() > 128 {
            return Err(Error::TooLong {
                what: "mode",
                len: raw.len(),
                max: 128,
            });
        }
        match raw {
            "occupied" => Ok(OpMode::Occupied),
            "unoccupied" => Ok(OpMode::Unoccupied),
            "standby" => Ok(OpMode::Standby),
            _ => Ok(OpMode::Unknown(raw.to_string())),
        }
    }

    /// Borrow the canonical label.
    pub fn as_str(&self) -> &str {
        match self {
            OpMode::Occupied => "occupied",
            OpMode::Unoccupied => "unoccupied",
            OpMode::Standby => "standby",
            OpMode::Unknown(raw) => raw,
        }
    }

    /// True for [`OpMode::Unknown`].
    pub fn is_unknown(&self) -> bool {
        matches!(self, OpMode::Unknown(_))
    }

    /// Encode as a JSON string.
    pub fn to_json(&self) -> String {
        super::json::quote(self.as_str())
    }

    /// Decode from a JSON string; preserves unknown labels.
    pub fn from_json(text: &str) -> Result<OpMode, Error> {
        let raw = super::json::parse_string_literal(text).map_err(|e| Error::Json {
            message: format!("mode: {e}"),
        })?;
        OpMode::parse(&raw)
    }
}

/// Scalar value with explicit missing/invalid/diagnostic distinctions.
///
/// - `Missing` is an explicit absent reason, not `0`, `false`, `""` or `null`
///   smuggled in as a sample.
/// - `Bool(false)` and `Integer(0)`/`Decimal("0")` are legitimate values and
///   never erased by absence checks.
/// - `Diagnostic` holds tagged non-finite states and invalid reasons, never
///   ordinary JSON numbers.
/// - `Mode` holds the frozen operating-mode example (known + preserved unknown).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value {
    Missing,
    Bool(bool),
    Integer(i128),
    Decimal(Decimal),
    Text(String),
    Mode(OpMode),
    Diagnostic(Diagnostic),
}

impl Value {
    /// True for [`Value::Missing`].
    pub fn is_missing(&self) -> bool {
        matches!(self, Value::Missing)
    }

    /// Frozen JSON encoding (field order frozen, see module docs).
    ///
    /// - missing: `{"type":"missing"}`
    /// - bool: `{"type":"bool","value":false}`
    /// - integer: `{"type":"integer","value":"9007199254740993"}`
    /// - decimal: `{"type":"decimal","value":"21.50"}`
    /// - text: `{"type":"text","value":"..."}`
    /// - mode: `{"type":"mode","value":"turbo"}`
    /// - diagnostic: `{"type":"diagnostic","kind":"+inf"}`
    ///   or `{"type":"diagnostic","kind":"invalid","detail":"..."}`
    pub fn to_json(&self) -> String {
        match self {
            Value::Missing => "{\"type\":\"missing\"}".to_string(),
            Value::Bool(b) => format!(
                "{{\"type\":\"bool\",\"value\":{}}}",
                if *b { "true" } else { "false" }
            ),
            Value::Integer(n) => format!(
                "{{\"type\":\"integer\",\"value\":{}}}",
                super::json::quote(&n.to_string())
            ),
            Value::Decimal(d) => format!(
                "{{\"type\":\"decimal\",\"value\":{}}}",
                super::json::quote(d.as_str())
            ),
            Value::Text(s) => format!("{{\"type\":\"text\",\"value\":{}}}", super::json::quote(s)),
            Value::Mode(m) => format!(
                "{{\"type\":\"mode\",\"value\":{}}}",
                super::json::quote(m.as_str())
            ),
            Value::Diagnostic(d) => match d {
                Diagnostic::Invalid(detail) => format!(
                    "{{\"type\":\"diagnostic\",\"kind\":\"invalid\",\"detail\":{}}}",
                    super::json::quote(detail)
                ),
                _ => format!(
                    "{{\"type\":\"diagnostic\",\"kind\":{}}}",
                    super::json::quote(d.kind())
                ),
            },
        }
    }

    /// Decode from the frozen encoding; refuses malformed JSON, missing or
    /// unexpected fields, unknown `type` tags and invalid payloads.
    pub fn from_json(text: &str) -> Result<Value, Error> {
        let fields = super::json::parse_object(text)?;
        let kind = super::json::get_string(&fields, "type")?;
        match kind.as_str() {
            "missing" => {
                super::json::reject_unknown(&fields, &["type"])?;
                Ok(Value::Missing)
            }
            "bool" => {
                super::json::reject_unknown(&fields, &["type", "value"])?;
                let b = super::json::get_bool(&fields, "value")?;
                Ok(Value::Bool(b))
            }
            "integer" => {
                super::json::reject_unknown(&fields, &["type", "value"])?;
                let raw = super::json::get_string(&fields, "value")?;
                raw.parse::<i128>()
                    .map(Value::Integer)
                    .map_err(|_| Error::InvalidValue {
                        what: "integer",
                        value: raw,
                    })
            }
            "decimal" => {
                super::json::reject_unknown(&fields, &["type", "value"])?;
                let raw = super::json::get_string(&fields, "value")?;
                Ok(Value::Decimal(Decimal::parse(&raw)?))
            }
            "text" => {
                super::json::reject_unknown(&fields, &["type", "value"])?;
                let raw = super::json::get_string(&fields, "value")?;
                Ok(Value::Text(raw))
            }
            "mode" => {
                super::json::reject_unknown(&fields, &["type", "value"])?;
                let raw = super::json::get_string(&fields, "value")?;
                Ok(Value::Mode(OpMode::parse(&raw)?))
            }
            "diagnostic" => {
                let kind = super::json::get_string(&fields, "kind")?;
                match kind.as_str() {
                    "invalid" => {
                        super::json::reject_unknown(&fields, &["type", "kind", "detail"])?;
                        let detail = super::json::get_string(&fields, "detail")?;
                        Ok(Value::Diagnostic(Diagnostic::Invalid(detail)))
                    }
                    "+inf" | "-inf" | "nan" => {
                        super::json::reject_unknown(&fields, &["type", "kind"])?;
                        Ok(Value::Diagnostic(Diagnostic::from_parts(&kind, None)?))
                    }
                    other => Err(Error::UnexpectedType {
                        expected: "+inf/-inf/nan/invalid",
                        got: other.to_string(),
                    }),
                }
            }
            other => Err(Error::UnexpectedType {
                expected: "missing/bool/integer/decimal/text/mode/diagnostic",
                got: other.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_preserves_exact_lexical() {
        for raw in [
            "0",
            "-0",
            "21.50",
            "-0.0",
            "0.001",
            "123",
            "9007199254740993.25",
        ] {
            let d = Decimal::parse(raw).expect("valid decimal");
            assert_eq!(d.as_str(), raw);
            assert_eq!(d.to_json_string(), super::super::json::quote(raw));
        }
        // Trailing zeros and negative zero are preserved, not normalized.
        assert_ne!(
            Decimal::parse("21.50").expect("a"),
            Decimal::parse("21.5").expect("b")
        );
        assert_ne!(
            Decimal::parse("-0.0").expect("a"),
            Decimal::parse("0.0").expect("b")
        );
    }

    #[test]
    fn decimal_refuses_non_finite_and_malformed() {
        for bad in [
            "", "NaN", "inf", "+inf", "-inf", ".", "01", "-", "1.", ".5", "1e3",
        ] {
            assert!(Decimal::parse(bad).is_err(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn false_zero_missing_invalid_diagnostic_are_distinct() {
        let fals = Value::Bool(false);
        let zero_int = Value::Integer(0);
        let zero_dec = Value::Decimal(Decimal::parse("0").expect("zero"));
        let missing = Value::Missing;
        let invalid = Value::Diagnostic(Diagnostic::Invalid("bad wire".to_string()));
        let pinf = Value::Diagnostic(Diagnostic::PositiveInfinity);
        assert_ne!(fals, zero_int);
        assert_ne!(zero_int, zero_dec);
        assert_ne!(fals, missing);
        assert_ne!(missing, invalid);
        assert_ne!(invalid, pinf);
        assert!(missing.is_missing());
        assert!(!fals.is_missing());
        // Diagnostic kinds and details are observable for evidence.
        assert_eq!(Diagnostic::PositiveInfinity.kind(), "+inf");
        assert_eq!(Diagnostic::NegativeInfinity.kind(), "-inf");
        assert_eq!(Diagnostic::NotANumber.kind(), "nan");
        assert_eq!(
            Diagnostic::Invalid("bad wire".to_string()).kind(),
            "invalid"
        );
        match invalid {
            Value::Diagnostic(Diagnostic::Invalid(detail)) => assert_eq!(detail, "bad wire"),
            _ => panic!("expected invalid diagnostic"),
        }
        assert_eq!(Diagnostic::PositiveInfinity.detail(), "");
        assert_eq!(Diagnostic::Invalid("x".to_string()).detail(), "x");
    }

    #[test]
    fn large_integer_survives_without_float_rounding() {
        // 2^53 + 1: not exactly representable as f64.
        let big: i128 = 9_007_199_254_740_993;
        let value = Value::Integer(big);
        let json = value.to_json();
        assert_eq!(
            json,
            "{\"type\":\"integer\",\"value\":\"9007199254740993\"}"
        );
        assert_eq!(Value::from_json(&json).expect("decode"), value);
        // i128 extremes also survive as strings.
        for extreme in [i128::MAX, i128::MIN] {
            let v = Value::Integer(extreme);
            assert_eq!(Value::from_json(&v.to_json()).expect("decode"), v);
        }
    }

    #[test]
    fn value_json_round_trips_cover_boundary_table() {
        let cases: Vec<Value> = vec![
            Value::Missing,
            Value::Bool(false),
            Value::Bool(true),
            Value::Integer(0),
            Value::Integer(-5),
            Value::Decimal(Decimal::parse("21.50").expect("dec")),
            Value::Decimal(Decimal::parse("-0.0").expect("negzero")),
            Value::Text(String::new()),
            Value::Text("vav-101".to_string()),
            Value::Mode(OpMode::Occupied),
            Value::Mode(OpMode::parse("turbo").expect("unknown mode")),
            Value::Diagnostic(Diagnostic::PositiveInfinity),
            Value::Diagnostic(Diagnostic::NegativeInfinity),
            Value::Diagnostic(Diagnostic::NotANumber),
            Value::Diagnostic(Diagnostic::Invalid("gated nan".to_string())),
        ];
        for value in cases {
            let json = value.to_json();
            let back = Value::from_json(&json).expect("round-trip");
            assert_eq!(back, value, "round-trip failed for {json}");
        }
    }

    #[test]
    fn value_json_refuses_malformed_and_unknown_tags() {
        assert!(Value::from_json("{\"type\":\"quantum\"}").is_err());
        assert!(Value::from_json("{\"type\":\"bool\"}").is_err());
        assert!(Value::from_json("{\"type\":\"bool\",\"value\":\"false\"}").is_err());
        assert!(Value::from_json("{\"type\":\"integer\",\"value\":\"1.5\"}").is_err());
        assert!(Value::from_json("{\"type\":\"decimal\",\"value\":\"NaN\"}").is_err());
        assert!(Value::from_json("{\"type\":\"missing\",\"value\":\"x\"}").is_err());
        assert!(Value::from_json("not json").is_err());
    }

    #[test]
    fn unknown_units_and_modes_preserved_not_coerced() {
        let unit = Unit::parse("furlongs-per-fortnight").expect("unknown unit");
        assert!(unit.is_unknown());
        assert_eq!(unit.as_str(), "furlongs-per-fortnight");
        assert_eq!(Unit::from_json(&unit.to_json()).expect("round-trip"), unit);
        assert_eq!(Unit::parse("degC").expect("known").as_str(), "degC");
        assert!(Unit::parse("degC").expect("known").is_known());
        assert!(Unit::parse("").is_err());

        let mode = OpMode::parse("turbo").expect("unknown mode");
        assert!(mode.is_unknown());
        assert_eq!(mode.as_str(), "turbo");
        assert_eq!(
            OpMode::from_json(&mode.to_json()).expect("round-trip"),
            mode
        );
        assert_eq!(
            OpMode::parse("occupied").expect("known").as_str(),
            "occupied"
        );
        assert!(OpMode::parse("").is_err());
    }
}
