//! Closed S01 source matrix. No calls to convert/apply, stores or native owners.
//! An ancestry path is a derived report, NOT a new RDF assertion. Inverses,
//! equivalents, labels and SHACL text are original data, never executable rules.
use super::ledger::{json, Fact, Kind};
use super::parse::{Document, Error, Object, Result, IMPORTS, TYPE};
use super::recipe::{self, Artifact, Catalog, ImportAction, BRICK, QK31, QUDT32, S223, UNIT31};

pub const B: &str = "https://brickschema.org/schema/Brick#";
pub const S: &str = "http://data.ashrae.org/standard223#";
pub const R: &str = "https://w3id.org/rec#";
pub const U: &str = "http://qudt.org/vocab/unit/";
pub const Q: &str = "http://qudt.org/vocab/quantitykind/";
pub const HAS_QK: &str = "http://qudt.org/schema/qudt/hasQuantityKind";
const OWL_CLASS: &str = "http://www.w3.org/2002/07/owl#Class";
const RDFS_CLASS: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const OWL_PROPERTY: &str = "http://www.w3.org/2002/07/owl#ObjectProperty";
const RDF_PROPERTY: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#Property";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub artifact: &'static str,
    pub iri: String,
    pub kind: &'static str,
    pub direction: &'static str,
}
impl Row {
    pub fn to_json(&self) -> String {
        format!("{{\"artifact\":{},\"iri\":{},\"kind\":{},\"direction\":{},\"status\":\"mapped\",\"evidence\":\"parser-only\"}}",
            json(self.artifact), json(&self.iri), json(self.kind), json(self.direction))
    }
}

/// These are explicit mappings, not recognition by suffix, label or ancestry.
/// Supporting a superclass does not admit unknown subclasses or aliases.
pub fn supported(source: &str, iri: &str) -> Result<Row> {
    for (artifact, namespace, local, _, direction) in specifications() {
        if source == artifact && iri == format!("{namespace}{local}") {
            return Ok(Row {
                artifact,
                iri: iri.into(),
                kind: if direction.is_empty() {
                    "class"
                } else {
                    "relation"
                },
                direction,
            });
        }
    }
    Err(Error::Unsupported(format!("{source}: {iri}")))
}

type Spec = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);
fn specifications() -> Vec<Spec> {
    let mut out = Vec::new();
    for local in [
        "AHU",
        "VAV",
        "Supply_Air_Temperature_Sensor",
        "Air_Temperature_Sensor",
        "Temperature_Sensor",
        "Sensor",
        "Equipment",
        "HVAC_Equipment",
    ] {
        out.push((BRICK, B, local, OWL_CLASS, ""));
    }
    for local in [
        "Equipment",
        "Sensor",
        "ObservableProperty",
        "QuantifiableObservableProperty",
    ] {
        out.push((
            S223,
            S,
            local,
            "http://data.ashrae.org/standard223#Class",
            "",
        ));
    }
    for local in ["Room", "Space"] {
        out.push((BRICK, R, local, RDFS_CLASS, ""));
    }
    out.extend([
        (
            BRICK,
            B,
            "hasPoint",
            OWL_PROPERTY,
            "subject telemetry-owner -> object point",
        ),
        (
            BRICK,
            B,
            "isPointOf",
            OWL_PROPERTY,
            "subject point -> object telemetry-owner",
        ),
        (
            BRICK,
            B,
            "feeds",
            OWL_PROPERTY,
            "subject upstream -> object downstream",
        ),
        (
            BRICK,
            B,
            "hasLocation",
            OWL_PROPERTY,
            "subject entity -> object location; not service",
        ),
        (
            BRICK,
            R,
            "locatedIn",
            OWL_PROPERTY,
            "subject entity -> object location; not service",
        ),
        (
            BRICK,
            R,
            "hasPoint",
            OWL_PROPERTY,
            "subject telemetry-owner -> object point",
        ),
        (
            S223,
            S,
            "observes",
            RDF_PROPERTY,
            "subject Sensor -> object ObservableProperty",
        ),
        (
            S223,
            S,
            "hasProperty",
            RDF_PROPERTY,
            "subject Concept -> object Property",
        ),
        (
            S223,
            S,
            "connectsTo",
            RDF_PROPERTY,
            "subject Connection -> object Connectable; flow subject to object",
        ),
    ]);
    out
}

/// Explicit edition-qualified mapping. Equal unversioned IRIs do NOT establish
/// equivalent definitions across releases. Both assertions must exist separately.
/// PA maps to ForcePerArea here: neither release asserts PA hasQuantityKind
/// Pressure. Pressure's applicableUnit assertion is not silently inverted.
pub const UNIT_MAPPINGS: &[(&str, &str, &str)] = &[
    ("degC", "DEG_C", "Temperature"),
    ("percent", "PERCENT", "DimensionlessRatio"),
    ("Pa", "PA", "ForcePerArea"),
    ("L/s", "L-PER-SEC", "VolumeFlowRate"),
];
pub fn unit_mapping(source: &str, token: &str) -> Result<(String, String)> {
    if source != UNIT31 && source != QUDT32 {
        return Err(Error::Unsupported(format!("unit context {source}")));
    }
    UNIT_MAPPINGS
        .iter()
        .find(|(t, _, _)| *t == token)
        .map(|(_, u, q)| (format!("{U}{u}"), format!("{Q}{q}")))
        .ok_or_else(|| Error::Unsupported(format!("unit token {token}")))
}

#[derive(Debug)]
pub struct Report {
    pub rows: Vec<Row>,
    pub ledger: Vec<Fact>,
}
impl Report {
    pub fn extract(catalog: &Catalog) -> Result<Self> {
        let mut report = Self {
            rows: Vec::new(),
            ledger: Vec::new(),
        };
        for (source, ns, local, declared_type, direction) in specifications() {
            let iri = format!("{ns}{local}");
            let pin = recipe::artifact(source)?;
            let doc = catalog.document(source)?;
            if !doc.has(&iri, TYPE, declared_type) {
                return Err(Error::Missing(iri));
            }
            report.rows.push(supported(source, &iri)?);
            report.originals(pin, doc, &iri);
            if direction.is_empty() {
                for (ancestor, path) in doc.ancestry(&iri)? {
                    // Include *each* supporting edge subject as original evidence.
                    for subject in &path {
                        report.originals(pin, doc, subject);
                    }
                    report.ledger.push(Fact::new(
                        pin,
                        &iri,
                        "urn:verdant:s01:ancestry-path",
                        Object::Iri(ancestor),
                        Kind::Derived,
                        "explicit-ancestry-path",
                        path.join(" -> "),
                    ));
                }
            } else {
                report.ledger.push(Fact::new(pin, &iri, "urn:verdant:s01:direction",
                    Object::Literal(direction.into()), Kind::Derived, "direction-mapping",
                    "manual mapping of source description; preserve endpoints; no inverse assertion"));
            }
        }
        for source in [UNIT31, QUDT32] {
            let pin = recipe::artifact(source)?;
            let doc = catalog.document(source)?;
            let quantity_source = if source == UNIT31 { QK31 } else { QUDT32 };
            for (token, _, _) in UNIT_MAPPINGS {
                let (unit, quantity) = unit_mapping(source, token)?;
                if !doc.has(&unit, HAS_QK, &quantity) {
                    return Err(Error::Missing(format!("{source}: {unit} -> {quantity}")));
                }
                if !catalog.document(quantity_source)?.has(
                    &quantity,
                    TYPE,
                    "http://qudt.org/schema/qudt/QuantityKind",
                ) {
                    return Err(Error::Missing(format!("{quantity_source}: {quantity}")));
                }
                report.originals(pin, doc, &unit);
                report.originals(
                    recipe::artifact(quantity_source)?,
                    catalog.document(quantity_source)?,
                    &quantity,
                );
                report.rows.push(Row {
                    artifact: source,
                    iri: unit.clone(),
                    kind: "unit",
                    direction: "unit -> quantitykind; no numeric conversion",
                });
                report.rows.push(Row {
                    artifact: quantity_source,
                    iri: quantity.clone(),
                    kind: "quantitykind",
                    direction: "",
                });
                report.ledger.push(Fact::new(pin, &unit, "urn:verdant:s01:unit-token",
                    Object::Literal(token.to_string()), Kind::Derived, "edition-qualified-unit-mapping",
                    format!("{quantity}; same token explicitly mapped in 3.1.0 and 3.2.1 separately; not cross-version equivalence or substitution")));
            }
        }
        for pin in recipe::ARTIFACTS {
            let doc = catalog.document(pin.name)?;
            report.originals(pin, doc, pin.ontology);
            for (subject, predicate, object) in doc.facts() {
                if predicate != IMPORTS {
                    continue;
                }
                let iri = object
                    .iri()
                    .ok_or_else(|| Error::Unsupported("literal import".into()))?;
                report.ledger.push(Fact::new(
                    pin,
                    subject,
                    predicate,
                    object.clone(),
                    Kind::Original,
                    "source-assertion",
                    "explicit in artifact; not upstream authoring-history evidence",
                ));
                let (action, reason) = recipe::import_action(pin.name, iri)?;
                let kind = match action {
                    ImportAction::Refuse => Kind::Refusal,
                    ImportAction::Include(_)
                    | ImportAction::Backreference
                    | ImportAction::LabelsOnly => Kind::Derived,
                };
                report.ledger.push(Fact::new(
                    pin,
                    subject,
                    "urn:verdant:s01:import-disposition",
                    object.clone(),
                    kind,
                    "minimal-include-catalog",
                    reason,
                ));
            }
        }
        // Stable order and deduplication independent of caller file order or
        // parser-generated blank IDs (blank IDs never enter this ledger).
        report
            .rows
            .sort_by(|a, b| (a.artifact, &a.iri).cmp(&(b.artifact, &b.iri)));
        report.rows.dedup();
        report.ledger.sort_by_cached_key(Fact::to_json);
        report.ledger.dedup();
        Ok(report)
    }
    fn originals(&mut self, pin: &Artifact, doc: &Document, subject: &str) {
        for (s, p, o) in doc.facts().filter(|(s, _, _)| *s == subject) {
            self.ledger.push(Fact::new(
                pin,
                s,
                p,
                o.clone(),
                Kind::Original,
                "source-assertion",
                "explicit in artifact; not upstream authoring-history evidence",
            ));
        }
    }
}
