//! Tiny synthetic site fixture: two scopes, AHU + two VAVs, shared sensor.
//!
//! Synthetic only: no plant physics, no ontology equivalence claim. Display
//! labels are intentionally duplicated (`"VAV"` on both VAVs) to prove labels
//! are not installed identity. The shared sensor (`"sensor-sat-1"`) remains
//! one source observed by three entities. Spatial (`LocatedIn`) and service
//! (`ServedBy`) relationships are distinct kinds; sensing (`ObservedBy`) is a
//! third kind.
//!
//! Exact quantities (`9007199254740993`, `"21.50"`, `0`, `false`) sit
//! alongside exceptional ones (missing, `+inf`/`-inf`/`NaN`, invalid,
//! unknown unit `"furlongs-per-fortnight"`, unknown mode `"turbo"`).

use super::clock::TimeTriple;
use super::clock::UnixMillis;
use super::ids::InstalledId;
use super::scope::TrustedScope;
use super::values::{Decimal, Diagnostic, OpMode, Unit, Value};
use super::Error;

/// Spatial vs service vs sensing relationships (distinct kinds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relationship {
    /// Spatial: equipment located in a scope.
    LocatedIn {
        entity: InstalledId,
        scope: TrustedScope,
    },
    /// Service: a VAV served by an AHU.
    ServedBy { vav: InstalledId, ahu: InstalledId },
    /// Sensing: an entity observed by a sensor source.
    ObservedBy {
        entity: InstalledId,
        sensor: InstalledId,
    },
}

impl Relationship {
    /// Frozen JSON encoding with a `kind` tag.
    pub fn to_json(&self) -> String {
        match self {
            Relationship::LocatedIn { entity, scope } => format!(
                "{{\"kind\":\"located-in\",\"entity\":{},\"scope\":{}}}",
                super::json::quote(entity.as_str()),
                super::json::quote(scope.as_str())
            ),
            Relationship::ServedBy { vav, ahu } => format!(
                "{{\"kind\":\"served-by\",\"vav\":{},\"ahu\":{}}}",
                super::json::quote(vav.as_str()),
                super::json::quote(ahu.as_str())
            ),
            Relationship::ObservedBy { entity, sensor } => format!(
                "{{\"kind\":\"observed-by\",\"entity\":{},\"sensor\":{}}}",
                super::json::quote(entity.as_str()),
                super::json::quote(sensor.as_str())
            ),
        }
    }

    /// Decode from the frozen encoding.
    pub fn from_json(text: &str) -> Result<Relationship, Error> {
        let fields = super::json::parse_object(text)?;
        let kind = super::json::get_string(&fields, "kind")?;
        match kind.as_str() {
            "located-in" => {
                super::json::reject_unknown(&fields, &["kind", "entity", "scope"])?;
                let entity = InstalledId::parse(&super::json::get_string(&fields, "entity")?)?;
                let scope = TrustedScope::parse(&super::json::get_string(&fields, "scope")?)?;
                Ok(Relationship::LocatedIn { entity, scope })
            }
            "served-by" => {
                super::json::reject_unknown(&fields, &["kind", "vav", "ahu"])?;
                let vav = InstalledId::parse(&super::json::get_string(&fields, "vav")?)?;
                let ahu = InstalledId::parse(&super::json::get_string(&fields, "ahu")?)?;
                Ok(Relationship::ServedBy { vav, ahu })
            }
            "observed-by" => {
                super::json::reject_unknown(&fields, &["kind", "entity", "sensor"])?;
                let entity = InstalledId::parse(&super::json::get_string(&fields, "entity")?)?;
                let sensor = InstalledId::parse(&super::json::get_string(&fields, "sensor")?)?;
                Ok(Relationship::ObservedBy { entity, sensor })
            }
            other => Err(Error::UnexpectedType {
                expected: "located-in/served-by/observed-by",
                got: other.to_string(),
            }),
        }
    }
}

/// One sensor reading with its scope, entity, source, value, unit and times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading {
    /// Trusted scope of the reading.
    pub scope: TrustedScope,
    /// Installed equipment the reading describes.
    pub entity: InstalledId,
    /// Installed sensor source (shared sensor appears on several readings).
    pub sensor: InstalledId,
    /// Scalar value (exact, missing, or diagnostic).
    pub value: Value,
    /// Engineering unit (known or preserved unknown).
    pub unit: Unit,
    /// Source/receipt/ingestion triple.
    pub times: TimeTriple,
}

impl Reading {
    /// Frozen JSON encoding (field order frozen). `value` is the nested
    /// [`Value`] object; `unit` is a string; times are strings.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"scope\":{},\"entity\":{},\"sensor\":{},\"value\":{},\"unit\":{},\"source_ms\":{},\"receipt_ms\":{},\"ingestion_ms\":{}}}",
            super::json::quote(self.scope.as_str()),
            super::json::quote(self.entity.as_str()),
            super::json::quote(self.sensor.as_str()),
            self.value.to_json(),
            super::json::quote(self.unit.as_str()),
            super::json::quote(&self.times.source().as_millis().to_string()),
            super::json::quote(&self.times.receipt().as_millis().to_string()),
            super::json::quote(&self.times.ingestion().as_millis().to_string()),
        )
    }

    /// Decode from the frozen encoding; refuses malformed JSON,
    /// missing/unexpected fields and invalid nested values.
    pub fn from_json(text: &str) -> Result<Reading, Error> {
        let fields = super::json::parse_object(text)?;
        super::json::reject_unknown(
            &fields,
            &[
                "scope",
                "entity",
                "sensor",
                "value",
                "unit",
                "source_ms",
                "receipt_ms",
                "ingestion_ms",
            ],
        )?;
        let scope = TrustedScope::parse(&super::json::get_string(&fields, "scope")?)?;
        let entity = InstalledId::parse(&super::json::get_string(&fields, "entity")?)?;
        let sensor = InstalledId::parse(&super::json::get_string(&fields, "sensor")?)?;
        let value_json = fields
            .get("value")
            .ok_or(Error::MissingField { field: "value" })?;
        let value_text = super::json::stringify(value_json);
        let value = Value::from_json(&value_text)?;
        let unit = Unit::parse(&super::json::get_string(&fields, "unit")?)?;
        let parse_millis = |name: &'static str| -> Result<i64, Error> {
            let raw = super::json::get_string(&fields, name)?;
            raw.parse::<i64>().map_err(|_| Error::InvalidValue {
                what: "unix-millis",
                value: raw,
            })
        };
        let times = TimeTriple::new(
            UnixMillis::new(parse_millis("source_ms")?),
            UnixMillis::new(parse_millis("receipt_ms")?),
            UnixMillis::new(parse_millis("ingestion_ms")?),
        )?;
        Ok(Reading {
            scope,
            entity,
            sensor,
            value,
            unit,
            times,
        })
    }
}

/// Tiny synthetic site: two scopes, one AHU, two VAVs, one shared sensor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TinySite {
    /// Exactly two scopes: `scope-a`, `scope-b`.
    pub scopes: [TrustedScope; 2],
    /// Installed AHU: `ahu-1`.
    pub ahu: InstalledId,
    /// Installed VAVs: `vav-101`, `vav-102` (distinct ids, duplicate label).
    pub vavs: [InstalledId; 2],
    /// Shared sensor source: `sensor-sat-1` (one source, three observers).
    pub shared_sensor: InstalledId,
    /// Duplicate display labels proving labels are not identity.
    /// Both VAVs carry `"VAV"`; the AHU carries `"AHU"`.
    pub labels: Vec<(InstalledId, String)>,
    /// Distinct spatial/service/sensing relationships.
    pub relationships: Vec<Relationship>,
    /// Exact + exceptional readings.
    pub readings: Vec<Reading>,
}

impl TinySite {
    /// Display label for an installed id in this fixture (duplicated `"VAV"`).
    pub fn label_of(&self, id: &InstalledId) -> Option<&str> {
        self.labels
            .iter()
            .find(|(candidate, _)| candidate == id)
            .map(|(_, label)| label.as_str())
    }
}

/// Build the frozen tiny site.
///
/// All ids/labels are frozen constants known to be valid; an invalid constant
/// is an internal programming error (explicit `expect` with the invariant),
/// never malformed caller input.
pub fn tiny_site() -> TinySite {
    fn scope(raw: &str) -> TrustedScope {
        TrustedScope::parse(raw).expect("frozen fixture scope is valid")
    }
    fn installed(raw: &str) -> InstalledId {
        InstalledId::parse(raw).expect("frozen fixture installed id is valid")
    }
    fn triple(source: i64, receipt: i64, ingestion: i64) -> TimeTriple {
        TimeTriple::new(
            UnixMillis::new(source),
            UnixMillis::new(receipt),
            UnixMillis::new(ingestion),
        )
        .expect("frozen fixture times are ordered")
    }
    fn decimal(raw: &str) -> Value {
        Value::Decimal(Decimal::parse(raw).expect("frozen fixture decimal is valid"))
    }

    let scopes = [scope("scope-a"), scope("scope-b")];
    let ahu = installed("ahu-1");
    let vavs = [installed("vav-101"), installed("vav-102")];
    let shared_sensor = installed("sensor-sat-1");

    let labels = vec![
        (ahu.clone(), "AHU".to_string()),
        (vavs[0].clone(), "VAV".to_string()),
        (vavs[1].clone(), "VAV".to_string()),
        (shared_sensor.clone(), "SAT".to_string()),
    ];

    let relationships = vec![
        // Spatial: each entity located in a scope (distinct scopes).
        Relationship::LocatedIn {
            entity: ahu.clone(),
            scope: scopes[0].clone(),
        },
        Relationship::LocatedIn {
            entity: vavs[0].clone(),
            scope: scopes[0].clone(),
        },
        Relationship::LocatedIn {
            entity: vavs[1].clone(),
            scope: scopes[1].clone(),
        },
        // Service: both VAVs served by the one AHU.
        Relationship::ServedBy {
            vav: vavs[0].clone(),
            ahu: ahu.clone(),
        },
        Relationship::ServedBy {
            vav: vavs[1].clone(),
            ahu: ahu.clone(),
        },
        // Sensing: one shared sensor observed by all three entities.
        Relationship::ObservedBy {
            entity: ahu.clone(),
            sensor: shared_sensor.clone(),
        },
        Relationship::ObservedBy {
            entity: vavs[0].clone(),
            sensor: shared_sensor.clone(),
        },
        Relationship::ObservedBy {
            entity: vavs[1].clone(),
            sensor: shared_sensor.clone(),
        },
    ];

    let base_times = triple(1_700_000_000_123, 1_700_000_000_456, 1_700_000_000_789);
    let readings = vec![
        // Exact decimal supply temperature on the AHU (known unit).
        Reading {
            scope: scopes[0].clone(),
            entity: ahu.clone(),
            sensor: shared_sensor.clone(),
            value: decimal("21.50"),
            unit: Unit::parse("degC").expect("frozen unit valid"),
            times: base_times,
        },
        // Large integer counter above f64 exactness (shared sensor).
        Reading {
            scope: scopes[0].clone(),
            entity: vavs[0].clone(),
            sensor: shared_sensor.clone(),
            value: Value::Integer(9_007_199_254_740_993),
            unit: Unit::parse("L/s").expect("frozen unit valid"),
            times: base_times,
        },
        // Zero integer vs false boolean (distinct).
        Reading {
            scope: scopes[1].clone(),
            entity: vavs[1].clone(),
            sensor: shared_sensor.clone(),
            value: Value::Integer(0),
            unit: Unit::parse("L/s").expect("frozen unit valid"),
            times: base_times,
        },
        Reading {
            scope: scopes[1].clone(),
            entity: vavs[1].clone(),
            sensor: shared_sensor.clone(),
            value: Value::Bool(false),
            unit: Unit::parse("percent").expect("frozen unit valid"),
            times: base_times,
        },
        // Missing quantity (explicit, not zero/false).
        Reading {
            scope: scopes[0].clone(),
            entity: vavs[0].clone(),
            sensor: shared_sensor.clone(),
            value: Value::Missing,
            unit: Unit::parse("degC").expect("frozen unit valid"),
            times: base_times,
        },
        // Tagged non-finite diagnostics (never ordinary numbers).
        Reading {
            scope: scopes[0].clone(),
            entity: ahu.clone(),
            sensor: shared_sensor.clone(),
            value: Value::Diagnostic(Diagnostic::PositiveInfinity),
            unit: Unit::parse("Pa").expect("frozen unit valid"),
            times: base_times,
        },
        Reading {
            scope: scopes[1].clone(),
            entity: vavs[1].clone(),
            sensor: shared_sensor.clone(),
            value: Value::Diagnostic(Diagnostic::NotANumber),
            unit: Unit::parse("Pa").expect("frozen unit valid"),
            times: base_times,
        },
        // Unknown unit + unknown mode preserved (not coerced).
        Reading {
            scope: scopes[1].clone(),
            entity: vavs[0].clone(),
            sensor: shared_sensor.clone(),
            value: Value::Mode(OpMode::parse("turbo").expect("frozen unknown mode")),
            unit: Unit::parse("furlongs-per-fortnight").expect("frozen unknown unit"),
            times: base_times,
        },
    ];

    TinySite {
        scopes,
        ahu,
        vavs,
        shared_sensor,
        labels,
        relationships,
        readings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiny_site_has_two_scopes_ahu_two_vavs_and_shared_sensor() {
        let site = tiny_site();
        assert_eq!(site.scopes[0].as_str(), "scope-a");
        assert_eq!(site.scopes[1].as_str(), "scope-b");
        assert_eq!(site.ahu.as_str(), "ahu-1");
        assert_eq!(site.vavs[0].as_str(), "vav-101");
        assert_eq!(site.vavs[1].as_str(), "vav-102");
        assert_eq!(site.shared_sensor.as_str(), "sensor-sat-1");
        assert_ne!(site.vavs[0], site.vavs[1]);
    }

    #[test]
    fn duplicate_labels_are_not_identity() {
        let site = tiny_site();
        assert_eq!(site.label_of(&site.vavs[0]), Some("VAV"));
        assert_eq!(site.label_of(&site.vavs[1]), Some("VAV"));
        // Same label, different installed identities.
        assert_eq!(site.label_of(&site.vavs[0]), site.label_of(&site.vavs[1]));
        assert_ne!(site.vavs[0], site.vavs[1]);
    }

    #[test]
    fn spatial_and_service_relationships_are_distinct_kinds() {
        let site = tiny_site();
        let mut saw_spatial = false;
        let mut saw_service = false;
        let mut saw_sensing = false;
        for rel in &site.relationships {
            match rel {
                Relationship::LocatedIn { .. } => saw_spatial = true,
                Relationship::ServedBy { .. } => saw_service = true,
                Relationship::ObservedBy { .. } => saw_sensing = true,
            }
        }
        assert!(saw_spatial && saw_service && saw_sensing);
        // Shared sensor observes three entities but remains one source.
        let shared_uses = site
            .relationships
            .iter()
            .filter(|rel| matches!(rel, Relationship::ObservedBy { sensor, .. } if sensor == &site.shared_sensor))
            .count();
        assert_eq!(shared_uses, 3);
        // Both VAVs served by the one AHU.
        let served = site
            .relationships
            .iter()
            .filter(|rel| matches!(rel, Relationship::ServedBy { ahu, .. } if ahu == &site.ahu))
            .count();
        assert_eq!(served, 2);
    }

    #[test]
    fn fixture_holds_exact_and_exceptional_values() {
        let site = tiny_site();
        assert!(site
            .readings
            .iter()
            .any(|r| r.value == Value::Integer(9_007_199_254_740_993)));
        assert!(site
            .readings
            .iter()
            .any(|r| r.value == Value::Decimal(Decimal::parse("21.50").expect("decimal"))));
        assert!(site.readings.iter().any(|r| r.value == Value::Integer(0)));
        assert!(site.readings.iter().any(|r| r.value == Value::Bool(false)));
        assert!(site.readings.iter().any(|r| r.value == Value::Missing));
        assert!(site
            .readings
            .iter()
            .any(|r| matches!(r.value, Value::Diagnostic(Diagnostic::PositiveInfinity))));
        assert!(site
            .readings
            .iter()
            .any(|r| matches!(r.value, Value::Diagnostic(Diagnostic::NotANumber))));
        assert!(site
            .readings
            .iter()
            .any(|r| r.unit == Unit::parse("furlongs-per-fortnight").expect("unknown unit")));
    }

    #[test]
    fn reading_and_relationship_json_round_trips() {
        let site = tiny_site();
        for reading in &site.readings {
            let json = reading.to_json();
            let back = Reading::from_json(&json).expect("reading round-trip");
            assert_eq!(&back, reading, "failed for {json}");
        }
        for rel in &site.relationships {
            let json = rel.to_json();
            let back = Relationship::from_json(&json).expect("relationship round-trip");
            assert_eq!(&back, rel, "failed for {json}");
        }
        assert!(Reading::from_json("{\"scope\":\"scope-a\"}").is_err());
    }
}
