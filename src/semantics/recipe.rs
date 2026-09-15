//! F02-S01 recipe v1. Source-profile extraction, NOT native materialization.
//! Pinned bytes, strict sync Turtle; manual bounded checks, never a SHACL engine.
use super::parse::{self, Document, Error, Result, ONTOLOGY, TYPE, VERSION};
use std::collections::{BTreeMap, BTreeSet};

pub const RECIPE_ID: &str = "verdant-f02-s01-v1";
pub const PARSER: &str =
    "oxttl=0.2.4;default-features=false;sync;lenient=false;base=none;rdf-12=false";
pub const MAX_CATALOG_BYTES: usize = 16_000_000;
pub const REMOTE_IMPORT_FETCH: bool = false;
pub const ARBITRARY_IMPORTED_RULE_EXECUTION: bool = false;
pub const EVIDENCE: &str = "parser-only; mapped; not observed-qualified; no native materialization";
pub const BRICK: &str = "Brick.ttl";
pub const S223: &str = "223p.ttl";
pub const QK31: &str = "qk-3.1.0.ttl";
pub const UNIT31: &str = "unit-3.1.0.ttl";
pub const QUDT32: &str = "qudt-all-3.2.1.ttl";

#[derive(Debug, Clone, Copy)]
pub struct Artifact {
    pub name: &'static str,
    pub bytes: usize,
    pub sha256: &'static str,
    pub url: &'static str,
    pub ontology: &'static str,
    pub provenance: &'static str,
}
/// Program s01-lock-manifest §§1/8.2 + ratification. URLs are provenance,
/// never dereferenced by product code. Full TTL files stay outside git.
pub const ARTIFACTS: &[Artifact] = &[
    Artifact { name: BRICK, bytes: 1749633,
        sha256: "b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7",
        url: "https://github.com/BrickSchema/Brick/releases/download/v1.4.4/Brick.ttl",
        ontology: "https://brickschema.org/schema/1.4/Brick",
        provenance: "Brick v1.4.4; tag 4b5be60d27f9b4d96fe477f45513fa71afebe684; release 216036536; asset 251163888; generated distribution; embedded REC 4.0" },
    Artifact { name: S223, bytes: 536776,
        sha256: "47bdad8925032c84e750e46b3649d102f4e41190c8161df3c9efa3265009b0e0",
        url: "https://raw.githubusercontent.com/open223/open223.info/97656845cab16183e64e9611c94f40a6fad95226/223p.ttl",
        ontology: "http://data.ashrae.org/standard223/1.0/model/all",
        provenance: "open223 97656845cab16183e64e9611c94f40a6fad95226; blob fcc29f7bc88df4188a35992c1ef9104d1cbe4297; v1.0.0-2026; community snapshot, not official-publication qualification" },
    Artifact { name: "bacnet.ttl", bytes: 1317004,
        sha256: "b51a240c3ea883f06034cc9d90fff2d1b7187ed8e7526407af24f2370f7eb948",
        url: "https://raw.githubusercontent.com/BrickSchema/Brick/4b5be60d27f9b4d96fe477f45513fa71afebe684/support/bacnet.ttl",
        ontology: "http://data.ashrae.org/bacnet/2020", provenance: "Brick 4b5be60 support copy; ontology IRI is not a working download URL" },
    Artifact { name: QK31, bytes: 1759877,
        sha256: "f774eaa7608b45c1ec443bde7e60c890e5d0a3bba7a1fa03ce658658be41a07b",
        url: "https://raw.githubusercontent.com/BrickSchema/Brick/4b5be60d27f9b4d96fe477f45513fa71afebe684/support/VOCAB_QUDT-QUANTITY-KINDS-ALL.ttl",
        ontology: "http://qudt.org/3.1.0/vocab/quantitykind", provenance: "Brick 4b5be60 substituted QUDT 3.1.0 bytes; never raw version templates" },
    Artifact { name: UNIT31, bytes: 2901259,
        sha256: "d940c1f9cf1f49139207a20019849e1e79ac3e0156a3c0ea1d715890cf1e91e9",
        url: "https://raw.githubusercontent.com/BrickSchema/Brick/4b5be60d27f9b4d96fe477f45513fa71afebe684/support/VOCAB_QUDT-UNITS-ALL.ttl",
        ontology: "http://qudt.org/3.1.0/vocab/unit", provenance: "Brick 4b5be60 substituted QUDT 3.1.0 bytes; never substitute 3.2.1" },
    Artifact { name: "ref-schema.ttl", bytes: 11876,
        sha256: "43da7c7eefa6eaf5eca3d37b036856c34f5d1da2a172a578a7868571c49a11e7",
        url: "https://raw.githubusercontent.com/BrickSchema/Brick/4b5be60d27f9b4d96fe477f45513fa71afebe684/support/ref-schema.ttl",
        ontology: "https://brickschema.org/schema/Brick/ref", provenance: "Brick 4b5be60 support/ref-schema.ttl" },
    Artifact { name: "recimports-brick.ttl", bytes: 4069,
        sha256: "58cebae4623e2718c302f207f25d1970b0e28f9ac191502fe48598d00e422983",
        url: "https://raw.githubusercontent.com/BrickSchema/Brick/4b5be60d27f9b4d96fe477f45513fa71afebe684/support/recimports.ttl",
        ontology: "https://w3id.org/rec/recimports",
        provenance: "Brick 4b5be60; identical to REC 352187a7dea0a73a40893ead8ba5cda6f7e181e3 Source/SHACL/RealEstateCore/recimports.ttl; embedded REC, not floating main" },
    Artifact { name: "dash.ttl", bytes: 94738,
        sha256: "01a32d725a0093910d17596102dc38a0ead231fa9d8ebed0bb433abfb705ebf4",
        url: "https://datashapes.org/dash.ttl", ontology: "http://datashapes.org/dash",
        provenance: "singleton; Last-Modified 2022-05-27; ETag 17212-5dff5b6515f9a; hash authoritative; shapes data only" },
    Artifact { name: "recpatches.ttl", bytes: 67039,
        sha256: "1cccf9440410e344439ca891bd4f89a6491a65df0486c7d56e736925caa578a0",
        url: "https://raw.githubusercontent.com/BrickSchema/Brick/4b5be60d27f9b4d96fe477f45513fa71afebe684/bricksrc/recpatches.ttl",
        ontology: "https://w3id.org/rec/brickpatches",
        provenance: "ratified Brick-side 1.4 patches; REC-side 1.3 variant refused; patches are data, not executed" },
    Artifact { name: QUDT32, bytes: 6725499,
        sha256: "2540751c232cc8a012211b12752e334385af320fd96be389f2d3b55af09af8d6",
        url: "https://qudt.org/3.2.1/shacl/qudt-all", ontology: "http://qudt.org/3.2.1/shacl/qudt-all",
        provenance: "QUDT version-path bundle 3.2.1; SHA authoritative; no commit pin available; never substitute for Brick 3.1.0" },
    Artifact { name: "shacl.ttl", bytes: 52899,
        sha256: "0e5d8aea0eab98a072d4a02faaee1ee914ec99eab2ca473429726faed4a13f69",
        url: "https://www.w3.org/ns/shacl.ttl", ontology: "http://www.w3.org/ns/shacl#",
        provenance: "W3C singleton; Last-Modified 2025-09-03; hash authoritative; shapes as data, never executed" },
];

pub struct Input<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
}
#[derive(Debug)]
pub struct Catalog {
    documents: BTreeMap<&'static str, Document>,
}
impl Catalog {
    /// Validates the entire supplied set before parsing any artifact. No caller
    /// supplied source URL, digest, import resolver or executable is accepted.
    pub fn load(inputs: &[Input<'_>]) -> Result<Self> {
        if inputs.len() > ARTIFACTS.len() {
            return Err(Error::Limit("artifact count"));
        }
        let mut seen = BTreeSet::new();
        let mut total = 0usize;
        for input in inputs {
            let pin = artifact(input.name)?;
            if !seen.insert(input.name) {
                return Err(Error::Duplicate(input.name.into()));
            }
            parse::preflight(input.bytes)?;
            total = total
                .checked_add(input.bytes.len())
                .ok_or(Error::Limit("catalog bytes"))?;
            if total > MAX_CATALOG_BYTES {
                return Err(Error::Limit("catalog bytes"));
            }
            if input.bytes.len() != pin.bytes {
                return Err(Error::Digest(pin.name.into()));
            }
        }
        for pin in ARTIFACTS {
            if !seen.contains(pin.name) {
                return Err(Error::Missing(pin.name.into()));
            }
        }
        if parse::sha256(b"abc")?
            != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        {
            return Err(Error::HashTool);
        }
        for input in inputs {
            if parse::sha256(input.bytes)? != artifact(input.name)?.sha256 {
                return Err(Error::Digest(input.name.into()));
            }
        }
        let mut documents = BTreeMap::new();
        for input in inputs {
            let pin = artifact(input.name)?;
            let document = Document::parse(input.bytes)?;
            if !document.has(pin.ontology, TYPE, ONTOLOGY) {
                return Err(Error::Missing(format!("{} ontology", pin.name)));
            }
            documents.insert(pin.name, document);
        }
        let out = Self { documents };
        out.check_imports()?;
        Ok(out)
    }
    pub fn document(&self, name: &str) -> Result<&Document> {
        self.documents
            .get(name)
            .ok_or_else(|| Error::Missing(name.into()))
    }
    fn check_imports(&self) -> Result<()> {
        let mut owners = BTreeMap::new();
        let mut edges = BTreeMap::new();
        for (name, doc) in &self.documents {
            for (s, p, o) in doc.facts() {
                if p == TYPE && o.iri() == Some(ONTOLOGY) {
                    let versions: Vec<_> = doc.objects(s, VERSION).cloned().collect();
                    if let Some(prior) = owners.insert(s, versions.clone()) {
                        if prior != versions {
                            return Err(Error::Duplicate(s.into()));
                        }
                    }
                }
            }
            let mut targets = Vec::new();
            for iri in doc.imports() {
                if let ImportAction::Include(target) = import_action(name, iri)?.0 {
                    self.document(target)?;
                    targets.push(target.to_string());
                }
            }
            edges.insert(name.to_string(), targets);
        }
        check_cycles(&edges)
    }
}
pub fn artifact(name: &str) -> Result<&'static Artifact> {
    ARTIFACTS
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| Error::Remote(name.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportAction {
    Include(&'static str),
    Backreference,
    Refuse,
    LabelsOnly,
}
/// Closed per-source allowlist, not suffix matching or a generic resolver.
/// Excluded imports cannot contribute identity, ancestry, dimensions or rules.
pub fn import_action(source: &str, iri: &str) -> Result<(ImportAction, &'static str)> {
    use ImportAction::*;
    let result = match (source, iri) {
        (BRICK, "http://data.ashrae.org/bacnet/2020") => (Include("bacnet.ttl"), "pinned support data"),
        (BRICK, "http://qudt.org/3.1.0/vocab/quantitykind") => (Include(QK31), "Brick quantitykind context is 3.1.0 only"),
        (BRICK, "http://qudt.org/3.1.0/vocab/unit") => (Include(UNIT31), "Brick unit context is 3.1.0 only"),
        (BRICK, "https://brickschema.org/schema/Brick/ref") => (Include("ref-schema.ttl"), "pinned reference data"),
        (BRICK, "https://w3id.org/rec/recimports") => (Include("recimports-brick.ttl"), "traced REC descriptor"),
        (BRICK, "http://datashapes.org/dash") => (Include("dash.ttl"), "shapes as inert data"),
        (BRICK, "https://w3id.org/rec/brickpatches") => (Include("recpatches.ttl"), "ratified Brick-side patch data"),
        (S223, "http://qudt.org/3.2.1/shacl/qudt-all") => (Include(QUDT32), "223 quantitykind/unit context is 3.2.1 only"),
        (S223 | "dash.ttl" | QUDT32, "http://www.w3.org/ns/shacl#") => (Include("shacl.ttl"), "data only; manual checks, no SHACL evaluation"),
        (UNIT31, "http://qudt.org/3.1.0/vocab/quantitykind") => (Include(QK31), "exact 3.1.0 unit-to-quantitykind assertions"),
        (BRICK | "recpatches.ttl", "https://brickschema.org/schema/1.4/Brick")
        | ("recimports-brick.ttl" | "recpatches.ttl", "https://w3id.org/rec") =>
            (Backreference, "already embedded in locked Brick; catalog reference, never recursively expanded"),
        (QK31 | UNIT31, "http://qudt.org/3.1.0/schema/facade/qudt") =>
            (Refuse, "minimal include: no facade definitions needed for exact predicate extraction; no schema entailment"),
        (QK31, "http://qudt.org/3.1.0/vocab/dimensionvector") =>
            (Refuse, "minimal include: matrix cites no dimension vectors; dimensional reasoning excluded"),
        (UNIT31, "http://qudt.org/3.1.0/vocab/prefix") =>
            (Refuse, "minimal include: matrix cites no prefix definitions; no prefix scaling"),
        (UNIT31, "http://qudt.org/3.1.0/vocab/sou") => (Refuse, "systems-of-units interpretation excluded"),
        (QUDT32, "http://www.linkedmodel.org/schema/vaem") => (Refuse, "VAEM metadata vocabulary interpretation excluded"),
        (QUDT32, "http://www.w3.org/2004/02/skos/core") =>
            (LabelsOnly, "inline prefLabel/altLabel literals only; no imported SKOS identity or inference"),
        _ => return Err(Error::Remote(format!("{source}: {iri}"))),
    };
    Ok(result)
}

/// Import expansion rejects cycles. The *specific* pinned embedded references
/// above are not expansion edges; this is not a general cycle exemption.
pub fn check_cycles(edges: &BTreeMap<String, Vec<String>>) -> Result<()> {
    if edges.len() > 32 {
        return Err(Error::Limit("import nodes"));
    }
    fn visit(
        node: &str,
        edges: &BTreeMap<String, Vec<String>>,
        active: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
    ) -> Result<()> {
        if active.contains(node) {
            return Err(Error::Cycle(node.into()));
        }
        if done.contains(node) {
            return Ok(());
        }
        if active.len() >= 32 {
            return Err(Error::Limit("import depth"));
        }
        let targets = edges.get(node).ok_or_else(|| Error::Missing(node.into()))?;
        if targets.len() > 32 {
            return Err(Error::Limit("import edges"));
        }
        active.insert(node.into());
        for target in targets {
            visit(target, edges, active, done)?;
        }
        active.remove(node);
        done.insert(node.into());
        Ok(())
    }
    let mut done = BTreeSet::new();
    for node in edges.keys() {
        visit(node, edges, &mut BTreeSet::new(), &mut done)?;
    }
    Ok(())
}
