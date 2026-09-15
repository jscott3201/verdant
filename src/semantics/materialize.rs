//! F02-S02 disposable-fixture native mapping, NOT an activated store service.
//!
//! Native writes are exercised ONLY by tests in isolated temporary directories,
//! through `NativeHandle::execute` with `NativeSettings::local()`. No startup,
//! CLI, SQLite, migration, seal, acceptance or observed-qualification join.
//! This module emits/reconciles GQL; it does not acquire filesystem authority.
//! The execution closure preserves the existing semantics-only compilation seam.
//!
//! S01 Row/Fact data is borrowed unchanged. Selected term evidence is retained
//! verbatim, never executed as inverses, equivalents, labels or rules. Derived
//! ancestry-path reports are excluded: no transitive-closure bytes are written.
//! InstalledId, TrustedScope, Relationship and Value are the existing domain
//! types, not a second identity model. Location and logical-property nodes use
//! separate roles; neither invents another installed equipment identity.
//!
//! Reconciliation requires one exclusive fixture caller, not concurrent imports.
//! Each INSERT is an implicit native commit. A native error may leave a committed
//! prefix; retrying the same plan checks that prefix before filling missing rows.
//! This is not an atomic batch, durable application import receipt or S03 seal.
use super::ledger::{json, Fact, Kind};
use super::matrix::{self, Report, Row};
use super::parse::{Object, TYPE};
use super::recipe::{self, BRICK, S223};
use crate::domain::fixture::{tiny_site, Relationship, TinySite};
use crate::domain::ids::InstalledId;
use crate::domain::scope::TrustedScope;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    UnsupportedMeaning(String),
    SourceEvidence(String),
    OutsideFixture,
    CrossScope,
    Conflict,
    StatementLimit,
    Execution { code: String, detail: String },
    UnexpectedOutcome,
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedMeaning(_) => "s02-unsupported-meaning",
            Self::SourceEvidence(_) => "s02-source-evidence",
            Self::OutsideFixture => "s02-outside-fixture",
            Self::CrossScope => "s02-cross-scope",
            Self::Conflict => "s02-conflict",
            Self::StatementLimit => "s02-statement-limit",
            Self::Execution { .. } => "s02-native-execution",
            Self::UnexpectedOutcome => "s02-unexpected-outcome",
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {self:?}", self.code())
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, Eq)]
struct Step {
    identity: String,
    exact: String,
    insert: String,
}

/// Fully preflighted frozen-site statements; nodes precede edges. The callback
/// returns ExecReport.row_count (Some for reads, None for committed writes).
#[derive(Debug)]
pub struct Plan {
    steps: BTreeMap<String, Step>,
}
impl Plan {
    /// Only explicitly requested relations are written. In particular the tiny
    /// site's cross-scope service/sensing links are NOT silently projected into
    /// another scope: requesting them refuses the whole plan before execution.
    pub fn tiny_site(
        source: &Report,
        relations: &[(&Relationship, &Row)],
        observes: Option<&Row>,
        max_statement_bytes: usize,
    ) -> Result<Self> {
        let site = tiny_site();
        let mut plan = Self { steps: BTreeMap::new() };
        for (id, iri) in [
            (&site.ahu, "https://brickschema.org/schema/Brick#AHU"),
            (&site.vavs[0], "https://brickschema.org/schema/Brick#VAV"),
            (&site.vavs[1], "https://brickschema.org/schema/Brick#VAV"),
            (&site.shared_sensor, "https://brickschema.org/schema/Brick#Supply_Air_Temperature_Sensor"),
        ] {
            let scope = scope_of(&site, id)?;
            let values: Vec<_> = site.readings.iter()
                .filter(|r| &r.entity == id && &r.scope == scope)
                .map(|r| r.value.to_json()).collect();
            plan.node(source, scope, "installed", id.as_str(),
                required(source, BRICK, iri)?, site.label_of(id).ok_or(Error::OutsideFixture)?,
                &format!("[{}]", values.join(",")))?;
        }
        for scope in &site.scopes {
            plan.node(source, scope, "location", "", required(source, BRICK,
                "https://w3id.org/rec#Room")?, scope.as_str(), "[]")?;
        }
        // One logical property for the shared source, not one per consuming VAV.
        // The sensor's fixture scope is its first (AHU) reading's scope. The
        // later cross-scope synthetic readings do not grant reference authority.
        plan.node(source, scope_of(&site, &site.shared_sensor)?, "property",
            site.shared_sensor.as_str(), required(source, S223,
                "http://data.ashrae.org/standard223#QuantifiableObservableProperty")?,
            "shared supply air temperature", "[]")?;

        for (relation, row) in relations {
            validate_row(source, row)?;
            let (from, to, target_role, scope) = match relation {
                Relationship::LocatedIn { entity, scope } => {
                    if scope_of(&site, entity)? != scope { return Err(Error::CrossScope); }
                    if !matches!(row.iri.as_str(),
                        "https://brickschema.org/schema/Brick#hasLocation" | "https://w3id.org/rec#locatedIn") {
                        return Err(Error::UnsupportedMeaning(row.iri.clone()));
                    }
                    (entity.as_str(), "", "location", scope)
                }
                Relationship::ServedBy { vav, ahu } => {
                    let scope = same_scope(&site, ahu, vav)?;
                    if row.iri != "https://brickschema.org/schema/Brick#feeds" {
                        return Err(Error::UnsupportedMeaning(row.iri.clone()));
                    }
                    (ahu.as_str(), vav.as_str(), "installed", scope)
                }
                Relationship::ObservedBy { entity, sensor } => {
                    let scope = same_scope(&site, entity, sensor)?;
                    match row.iri.as_str() {
                        "https://brickschema.org/schema/Brick#hasPoint" =>
                            (entity.as_str(), sensor.as_str(), "installed", scope),
                        "https://brickschema.org/schema/Brick#isPointOf" =>
                            (sensor.as_str(), entity.as_str(), "installed", scope),
                        _ => return Err(Error::UnsupportedMeaning(row.iri.clone())),
                    }
                }
            };
            if !site.relationships.contains(relation) { return Err(Error::OutsideFixture); }
            plan.edge(source, scope, from, to, target_role, row)?;
        }
        if let Some(row) = observes {
            validate_row(source, row)?;
            if row.iri != "http://data.ashrae.org/standard223#observes" {
                return Err(Error::UnsupportedMeaning(row.iri.clone()));
            }
            plan.edge(source, scope_of(&site, &site.shared_sensor)?,
                site.shared_sensor.as_str(), site.shared_sensor.as_str(), "property", row)?;
        }
        if plan.steps.values().any(|step| [&step.identity, &step.exact, &step.insert]
            .iter().any(|s| s.len() > max_statement_bytes)) {
            return Err(Error::StatementLimit);
        }
        Ok(plan)
    }

    /// Refuse duplicate or differing existing identities before writing anything.
    /// Successful return counts newly inserted records, not unique scenarios.
    /// Errors from the native adapter remain typed and retain its original code.
    pub fn reconcile(
        &self,
        mut execute: impl FnMut(&str) -> Result<Option<usize>>,
    ) -> Result<usize> {
        let mut missing = Vec::new();
        for step in self.steps.values() {
            match execute(&step.identity)? {
                Some(0) => missing.push(step),
                Some(1) => {
                    if execute(&step.exact)? != Some(1) { return Err(Error::Conflict); }
                }
                Some(_) => return Err(Error::Conflict),
                None => return Err(Error::UnexpectedOutcome),
            }
        }
        for step in &missing {
            if execute(&step.insert)?.is_some() { return Err(Error::UnexpectedOutcome); }
            if execute(&step.identity)? != Some(1) || execute(&step.exact)? != Some(1) {
                return Err(Error::Conflict);
            }
        }
        Ok(missing.len())
    }

    fn node(&mut self, source: &Report, scope: &TrustedScope, role: &str,
        installed: &str, row: &Row, label: &str, values: &str) -> Result<()> {
        let key = node_key(scope, role, installed);
        let mut props = evidence(source, row)?;
        props.extend([
            ("key", key.clone()), ("scope", scope.as_str().into()),
            ("role", role.into()), ("installed_id", installed.into()),
            ("type_iri", row.iri.clone()), ("label", label.into()),
            ("values_json", values.into()),
        ]);
        self.add(format!("0:{key}"), Step {
            identity: format!("MATCH (n:S02Node) WHERE n.key = {} RETURN n", json(&key)),
            exact: format!("MATCH (n:S02Node) WHERE {} RETURN n", predicates("n", &props)),
            insert: format!("INSERT (:S02Node {{{}}})", properties(&props)),
        })
    }

    fn edge(&mut self, source: &Report, scope: &TrustedScope, from: &str,
        to: &str, target_role: &str, row: &Row) -> Result<()> {
        let a = node_key(scope, "installed", from);
        let b = node_key(scope, target_role, to);
        let key = format!("{a}|{}|{b}", row.iri);
        let mut props = evidence(source, row)?;
        props.extend([("key", key.clone()), ("scope", scope.as_str().into()),
            ("iri", row.iri.clone()), ("direction", row.direction.into())]);
        let endpoints = format!("a.key = {} AND b.key = {}", json(&a), json(&b));
        self.add(format!("1:{key}"), Step {
            identity: format!("MATCH ()-[e:S02Relation]->() WHERE e.key = {} RETURN e", json(&key)),
            exact: format!("MATCH (a:S02Node)-[e:S02Relation]->(b:S02Node) WHERE {endpoints} AND {} RETURN e", predicates("e", &props)),
            insert: format!("MATCH (a:S02Node), (b:S02Node) WHERE {endpoints} INSERT (a)-[:S02Relation {{{}}}]->(b)", properties(&props)),
        })
    }

    fn add(&mut self, key: String, step: Step) -> Result<()> {
        if let Some(prior) = self.steps.get(&key) {
            if prior != &step { return Err(Error::Conflict); }
        } else {
            self.steps.insert(key, step);
        }
        Ok(())
    }
}

fn scope_of<'a>(site: &'a TinySite, id: &InstalledId) -> Result<&'a TrustedScope> {
    if id == &site.shared_sensor {
        return site.readings.first().map(|r| &r.scope).ok_or(Error::OutsideFixture);
    }
    for relationship in &site.relationships {
        match relationship {
            Relationship::LocatedIn { entity, scope } if entity == id => return Ok(scope),
            Relationship::LocatedIn { .. } | Relationship::ServedBy { .. }
                | Relationship::ObservedBy { .. } => {}
        }
    }
    Err(Error::OutsideFixture)
}
fn same_scope<'a>(site: &'a TinySite, a: &InstalledId, b: &InstalledId) -> Result<&'a TrustedScope> {
    let scope = scope_of(site, a)?;
    if scope != scope_of(site, b)? { return Err(Error::CrossScope); }
    Ok(scope)
}
fn node_key(scope: &TrustedScope, role: &str, installed: &str) -> String {
    format!("{}|{role}|{installed}", scope.as_str())
}
fn required<'a>(source: &'a Report, artifact: &str, iri: &str) -> Result<&'a Row> {
    source.rows.iter().find(|r| r.artifact == artifact && r.iri == iri)
        .ok_or_else(|| Error::UnsupportedMeaning(iri.into()))
}
fn validate_row(source: &Report, row: &Row) -> Result<()> {
    let canonical = matrix::supported(row.artifact, &row.iri)
        .map_err(|_| Error::UnsupportedMeaning(row.iri.clone()))?;
    if row != &canonical || !source.rows.contains(row) {
        return Err(Error::UnsupportedMeaning(row.iri.clone()));
    }
    Ok(())
}
fn evidence(source: &Report, row: &Row) -> Result<Vec<(&'static str, String)>> {
    validate_row(source, row)?;
    let pin = recipe::artifact(row.artifact)
        .map_err(|_| Error::SourceEvidence(row.iri.clone()))?;
    let facts: Vec<&Fact> = source.ledger.iter()
        .filter(|f| f.artifact == row.artifact && f.subject == row.iri
            && f.predicate != "urn:verdant:s01:ancestry-path").collect();
    let declared = match (row.artifact, row.kind, row.iri.starts_with(matrix::R)) {
        (BRICK, "class", false) => "http://www.w3.org/2002/07/owl#Class",
        (BRICK, "class", true) => "http://www.w3.org/2000/01/rdf-schema#Class",
        (S223, "class", _) => "http://data.ashrae.org/standard223#Class",
        (BRICK, "relation", _) => "http://www.w3.org/2002/07/owl#ObjectProperty",
        (S223, "relation", _) => "http://www.w3.org/1999/02/22-rdf-syntax-ns#Property",
        _ => return Err(Error::UnsupportedMeaning(row.iri.clone())),
    };
    if facts.iter().any(|f| f.sha256 != pin.sha256 || f.provenance != pin.provenance)
        || !facts.iter().any(|f| f.kind == Kind::Original && f.predicate == TYPE
            && f.object == Object::Iri(declared.into())) {
        return Err(Error::SourceEvidence(row.iri.clone()));
    }
    let mut encoded: Vec<_> = facts.iter().map(|f| f.to_json()).collect();
    encoded.sort();
    encoded.dedup();
    Ok(vec![("artifact", pin.name.into()), ("sha256", pin.sha256.into()),
        ("facts_json", format!("[{}]", encoded.join(","))),
        ("evidence", "synthetic-native; not observed-qualified".into())])
}
fn properties(props: &[(&str, String)]) -> String {
    props.iter().map(|(key, value)| format!("{key}: {}", json(value)))
        .collect::<Vec<_>>().join(", ")
}
fn predicates(variable: &str, props: &[(&str, String)]) -> String {
    props.iter().map(|(key, value)| format!("{variable}.{key} = {}", json(value)))
        .collect::<Vec<_>>().join(" AND ")
}
