//! S01 parser evidence ONLY. Sync Turtle defaults, no fetch or rule execution.
//! A Document is unverified syntax/extraction, NOT a locked source or native graph.
//! Blank-node shapes are parsed/count-bounded but never traversed or executed.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const MAX_BYTES: usize = 7_000_000;
pub const MAX_TRIPLES: usize = 300_000;
pub const MAX_FACTS: usize = 150_000;
pub const MAX_TERM_BYTES: usize = 65_536;
pub const MAX_DEPTH: usize = 32;
pub const MAX_ANCESTORS: usize = 256;
pub const TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
pub const SUBCLASS: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
pub const IMPORTS: &str = "http://www.w3.org/2002/07/owl#imports";
pub const ONTOLOGY: &str = "http://www.w3.org/2002/07/owl#Ontology";
pub const VERSION: &str = "http://www.w3.org/2002/07/owl#versionInfo";
pub const VERSION_IRI: &str = "http://www.w3.org/2002/07/owl#versionIRI";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Empty,
    Placeholder,
    Limit(&'static str),
    Syntax,
    Missing(String),
    Remote(String),
    Duplicate(String),
    Digest(String),
    Cycle(String),
    Unsupported(String),
    HashTool,
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "s01-empty",
            Self::Placeholder => "s01-placeholder",
            Self::Limit(_) => "s01-limit",
            Self::Syntax => "s01-turtle-syntax",
            Self::Missing(_) => "s01-missing",
            Self::Remote(_) => "s01-unexpected-remote",
            Self::Duplicate(_) => "s01-duplicate",
            Self::Digest(_) => "s01-digest-mismatch",
            Self::Cycle(_) => "s01-cycle",
            Self::Unsupported(_) => "s01-unsupported",
            Self::HashTool => "s01-sha256-unavailable",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Objects retain RDF kind: literals are N-Triples lexical forms including
/// language/datatype; IRIs are full strings. No local-name or label identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Object {
    Iri(String),
    Literal(String),
}
impl Object {
    pub fn iri(&self) -> Option<&str> {
        match self {
            Self::Iri(s) => Some(s),
            Self::Literal(_) => None,
        }
    }
    pub fn lexical(&self) -> &str {
        match self {
            Self::Iri(s) | Self::Literal(s) => s,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    facts: BTreeMap<(String, String), BTreeSet<Object>>,
    triples: usize,
}
impl Document {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        preflight(bytes)?;
        let mut out = Self {
            facts: BTreeMap::new(),
            triples: 0,
        };
        let mut facts = 0;
        for triple in oxttl::TurtleParser::new().for_slice(bytes) {
            let triple = triple.map_err(|_| Error::Syntax)?;
            out.triples += 1;
            if out.triples > MAX_TRIPLES {
                return Err(Error::Limit("triples"));
            }
            // These are serializer outputs from the typed parser, not a second
            // Turtle parser. Avoid exposing a new direct oxrdf dependency.
            let subject = triple.subject.to_string();
            let object = triple.object.to_string();
            let predicate = triple.predicate.as_str();
            if subject.len() > MAX_TERM_BYTES
                || object.len() > MAX_TERM_BYTES
                || predicate.len() > MAX_TERM_BYTES
            {
                return Err(Error::Limit("term bytes"));
            }
            if predicate == IMPORTS
                && (!triple.subject.is_named_node() || !triple.object.is_named_node())
            {
                return Err(Error::Unsupported("import requires named IRIs".into()));
            }
            if !triple.subject.is_named_node()
                || triple.object.is_blank_node()
                || !retained(predicate)
            {
                continue;
            }
            let subject = serialized_iri(&subject)?;
            let object = if triple.object.is_named_node() {
                Object::Iri(serialized_iri(&object)?)
            } else {
                Object::Literal(object)
            };
            if out
                .facts
                .entry((subject, predicate.into()))
                .or_default()
                .insert(object)
            {
                facts += 1;
                if facts > MAX_FACTS {
                    return Err(Error::Limit("retained facts"));
                }
            }
        }
        if out.triples == 0 {
            return Err(Error::Empty);
        }
        for ((subject, predicate), objects) in &out.facts {
            if (predicate == VERSION || predicate == VERSION_IRI) && objects.len() != 1 {
                return Err(Error::Duplicate(subject.clone()));
            }
            if predicate == IMPORTS && objects.iter().any(|o| o.iri().is_none()) {
                return Err(Error::Unsupported("literal import".into()));
            }
        }
        if out.imports().len() > 32 {
            return Err(Error::Limit("imports"));
        }
        Ok(out)
    }
    pub fn triples(&self) -> usize {
        self.triples
    }
    pub fn objects(&self, subject: &str, predicate: &str) -> impl Iterator<Item = &Object> {
        self.facts
            .get(&(subject.into(), predicate.into()))
            .into_iter()
            .flatten()
    }
    pub fn has(&self, subject: &str, predicate: &str, object: &str) -> bool {
        self.objects(subject, predicate)
            .any(|o| o.iri() == Some(object))
    }
    pub fn imports(&self) -> BTreeSet<&str> {
        self.facts
            .iter()
            .filter(|((_, p), _)| p == IMPORTS)
            .flat_map(|(_, os)| os.iter().filter_map(Object::iri))
            .collect()
    }
    pub fn facts(&self) -> impl Iterator<Item = (&str, &str, &Object)> {
        self.facts
            .iter()
            .flat_map(|((s, p), os)| os.iter().map(move |o| (s.as_str(), p.as_str(), o)))
    }
    /// Read-only path evidence, not insertion of entailed types. Only explicit
    /// rdfs:subClassOf IRIs; no equivalents, restrictions, tags or SHACL rules.
    pub fn ancestry(&self, subject: &str) -> Result<BTreeMap<String, Vec<String>>> {
        let mut paths = BTreeMap::new();
        self.walk(subject, &mut vec![subject.into()], &mut paths)?;
        Ok(paths)
    }
    fn walk(
        &self,
        subject: &str,
        path: &mut Vec<String>,
        paths: &mut BTreeMap<String, Vec<String>>,
    ) -> Result<()> {
        for parent in self.objects(subject, SUBCLASS).filter_map(Object::iri) {
            if path.iter().any(|s| s == parent) {
                return Err(Error::Cycle(parent.into()));
            }
            if path.len() >= MAX_DEPTH {
                return Err(Error::Limit("ancestry depth"));
            }
            if paths.contains_key(parent) {
                continue;
            }
            if paths.len() >= MAX_ANCESTORS {
                return Err(Error::Limit("ancestors"));
            }
            path.push(parent.into());
            paths.insert(parent.into(), path.clone());
            self.walk(parent, path, paths)?;
            path.pop();
        }
        Ok(())
    }
}

fn serialized_iri(value: &str) -> Result<String> {
    value
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .map(str::to_owned)
        .ok_or(Error::Syntax)
}
fn retained(p: &str) -> bool {
    [
        TYPE,
        SUBCLASS,
        IMPORTS,
        VERSION,
        VERSION_IRI,
        "http://www.w3.org/2002/07/owl#inverseOf",
        "http://www.w3.org/2002/07/owl#equivalentClass",
        "http://www.w3.org/2002/07/owl#equivalentProperty",
        "http://www.w3.org/2000/01/rdf-schema#subPropertyOf",
        "http://www.w3.org/2000/01/rdf-schema#label",
        "http://www.w3.org/2000/01/rdf-schema#comment",
        "http://www.w3.org/2004/02/skos/core#definition",
        "http://www.w3.org/2004/02/skos/core#prefLabel",
        "http://www.w3.org/2004/02/skos/core#altLabel",
        "http://purl.org/dc/terms/license",
        "http://purl.org/dc/terms/rights",
        "http://purl.org/dc/terms/rightsHolder",
        "https://brickschema.org/schema/Brick#hasQuantity",
        "http://qudt.org/schema/qudt/hasQuantityKind",
        "http://qudt.org/schema/qudt/applicableUnit",
    ]
    .contains(&p)
}
pub fn preflight(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Limit("artifact bytes"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Syntax)?;
    if text.trim().is_empty() {
        return Err(Error::Empty);
    }
    // Editorial vaem:todo and the real unit symbol "TBD" are data, not
    // integrity placeholders. Unsubstituted upstream templates are refused.
    if text.contains("$$QUDT_VERSION$$")
        || text.trim() == "TODO"
        || text.trim().eq_ignore_ascii_case("placeholder")
    {
        return Err(Error::Placeholder);
    }
    Ok(())
}

/// Same fixed system SHA-256 mechanism as the sealing owner, but a separate
/// 7 MB input budget: S01 must not change the seal's custody/interface limits.
/// Caller supplies bytes, never a command, argv, path or asserted digest.
/// Bounded output, one supervised child, all pipe workers joined on every path.
pub fn sha256(bytes: &[u8]) -> Result<String> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Limit("hash bytes"));
    }
    let mut child = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| Error::HashTool)?;
    let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let (Some(mut input), Some(output), Some(errors)) = pipes else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::HashTool);
    };
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || input.write_all(bytes));
        let reader = scope.spawn(move || bounded_output(output));
        let stderr = scope.spawn(move || bounded_output(errors));
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Ok(s),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Ok(None) | Err(_) => break Err(Error::HashTool),
            }
        };
        if status.is_err() {
            let _ = child.kill();
        }
        let reaped = child.wait();
        let written = writer.join();
        let output = reader.join();
        let errors = stderr.join();
        let status = status?;
        reaped.map_err(|_| Error::HashTool)?;
        written
            .map_err(|_| Error::HashTool)?
            .map_err(|_| Error::HashTool)?;
        let output = output.map_err(|_| Error::HashTool)??;
        let errors = errors.map_err(|_| Error::HashTool)??;
        if !status.success() || !errors.is_empty() {
            return Err(Error::HashTool);
        }
        let text = std::str::from_utf8(&output).map_err(|_| Error::HashTool)?;
        let hex = text.strip_suffix("  -\n").ok_or(Error::HashTool)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::HashTool);
        }
        Ok(hex.into())
    })
}
fn bounded_output(mut reader: impl Read) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0; 512];
    let mut overflow = false;
    loop {
        let n = reader.read(&mut chunk).map_err(|_| Error::HashTool)?;
        if n == 0 {
            break;
        }
        if out.len() + n <= 512 {
            out.extend_from_slice(&chunk[..n]);
        } else {
            overflow = true;
        }
    }
    if overflow {
        Err(Error::HashTool)
    } else {
        Ok(out)
    }
}
