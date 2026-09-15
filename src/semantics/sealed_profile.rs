//! F02-S03 additive profile content, not a new seal or acceptance format.
//!
//! The caller wraps each payload with `ContentNode::new(payload, findings)` and
//! stages its `Value::Text` through the normal outbox insert path. ALL returned
//! rows must be seal roots alongside the effective configuration. SealStore owns
//! authentication, revision admission, immutable publication and finite custody.
//! No CLI wiring, acquisition, automatic activation or qualification lives here.
//!
//! Like S02, callbacks preserve the semantics-only compilation seam. Statement
//! capture runs Plan's actual reconciliation protocol against a recording adapter,
//! never a native handle. Statements are inert evidence, not replay instructions.
//! Reconstruction consumes explicitly supplied bytes; URLs are provenance only.
use super::ledger::{json, Fact};
use super::materialize::{self, Plan};
use super::matrix::Report;
use super::parse;
use super::recipe::{self, Artifact, Catalog, Input};
use crate::domain::ids::OperationId;
use std::collections::BTreeMap;
use std::fmt;

const FORMAT: &str = "verdant-f02-s03-v1";
const FRAMING: &str = "valid-structural-not-qualified;synthetic-fnv1a64-not-authority";
// A stricter S03 payload bound, NOT a change to seal's 262144-byte closure bound.
// Leaves room for JSON/content framing, findings and effective configuration.
pub const MAX_PAYLOAD_BYTES: usize = 98_304;
pub const CHUNK_BYTES: usize = 8_192;

#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Limit,
    LedgerDigestMismatch,
    MeaningMismatch,
    Source(parse::Error),
    Plan(materialize::Error),
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "s03-invalid",
            Self::Limit => "s03-limit",
            Self::LedgerDigestMismatch => "s03-ledger-digest-mismatch",
            Self::MeaningMismatch => "s03-meaning-mismatch",
            Self::Source(e) => e.code(),
            Self::Plan(e) => e.code(),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {self:?}", self.code())
    }
}
impl std::error::Error for Error {}
impl From<parse::Error> for Error {
    fn from(error: parse::Error) -> Self { Self::Source(error) }
}
impl From<materialize::Error> for Error {
    fn from(error: materialize::Error) -> Self { Self::Plan(error) }
}
pub type Result<T> = std::result::Result<T, Error>;

/// Availability is separate from durable Accepted/Activated history. A failure
/// must block new use, not delete, downgrade or rewrite the accepted event.
#[derive(Debug)]
pub enum Availability {
    Available,
    Unavailable(Error),
}
impl Availability {
    pub fn require(self) -> Result<()> {
        match self {
            Self::Available => Ok(()),
            Self::Unavailable(error) => Err(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    bytes: String,
    ledger_digest: String,
}
impl Profile {
    /// Report::extract supplies real evidence; a caller-constructed Report is
    /// only a claim until reconstruction succeeds against Catalog::load pins.
    pub fn capture(report: &Report, plan: &Plan) -> Result<Self> {
        let digest = ledger_digest(report)?;
        let mut rows: Vec<_> = report.rows.iter().map(|r| format!(
            "{{\"artifact\":{},\"iri\":{},\"kind\":{},\"direction\":{}}}",
            json(r.artifact), json(&r.iri), json(r.kind), json(r.direction))).collect();
        rows.sort();
        rows.dedup();
        let steps = capture_steps(plan)?;
        let bytes = frame(&[FORMAT, recipe::RECIPE_ID, FRAMING, &pins_json(), &digest,
            &format!("[{}]", rows.join(",")), &steps]);
        if bytes.len() > MAX_PAYLOAD_BYTES { return Err(Error::Limit); }
        Ok(Self { bytes, ledger_digest: digest })
    }
    pub fn canonical_bytes(&self) -> &str { &self.bytes }
    pub fn ledger_digest(&self) -> &str { &self.ledger_digest }
    /// Check a scratch reconstruction's canonical ledger bytes without parsing
    /// or normalizing them. Available here means ledger integrity ONLY; source
    /// preflight, exact represented meaning and seal custody are separate checks.
    pub fn ledger_status(&self, bytes: &[u8]) -> Availability {
        let checked = checked_hash(bytes).and_then(|digest| {
            if digest == self.ledger_digest { Ok(()) }
            else { Err(Error::LedgerDigestMismatch) }
        });
        match checked {
            Ok(()) => Availability::Available,
            Err(error) => Availability::Unavailable(error),
        }
    }
    /// Decode verifies the complete sealed pin record, not just its names.
    pub fn pins(&self) -> &'static [Artifact] { recipe::ARTIFACTS }

    /// Deterministic UTF-8 chunks; sequence order is significant. Never split a
    /// codepoint. These are payloads, not ContentNode or Value JSON encodings.
    pub fn payloads(&self) -> Vec<&str> {
        let mut rest = self.bytes.as_str();
        let mut result = Vec::new();
        while !rest.is_empty() {
            let mut end = CHUNK_BYTES.min(rest.len());
            while !rest.is_char_boundary(end) { end -= 1; }
            result.push(&rest[..end]);
            rest = &rest[end..];
        }
        result
    }
    /// Read only after the owning seal has verified the same rows as roots.
    /// A decoded profile is not a publication credential or availability grant.
    pub fn from_payloads(payloads: &[&str]) -> Result<Self> {
        if payloads.is_empty() || payloads.len() > MAX_PAYLOAD_BYTES / CHUNK_BYTES + 1 {
            return Err(Error::Limit);
        }
        let mut bytes = String::new();
        for payload in payloads {
            if payload.is_empty() || payload.len() > CHUNK_BYTES
                || bytes.len().saturating_add(payload.len()) > MAX_PAYLOAD_BYTES {
                return Err(Error::Limit);
            }
            bytes.push_str(payload);
        }
        let fields = unframe(&bytes, 7)?;
        if fields.len() != 7 || fields[0] != FORMAT || fields[1] != recipe::RECIPE_ID
            || fields[2] != FRAMING || fields[3] != pins_json()
            || fields[4].len() != 64 || !fields[4].bytes().all(|c|
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err(Error::Invalid("profile format/pins/digest"));
        }
        let ledger_digest = fields[4].into();
        let result = Self { bytes, ledger_digest };
        if result.payloads() != payloads { return Err(Error::Invalid("chunk boundaries")); }
        Ok(result)
    }
    /// The adapter must use ContentNode + normal insert, and return each RowKey.
    /// This is additive staging, not an atomic batch or retry API: on error the
    /// caller retains/reconciles store tickets; a committed prefix is NOT a seal.
    /// Invalid namespaces refuse before calling the adapter, hence before writes.
    pub fn stage<K, E: From<Error>>(&self, operation: &OperationId,
        mut insert: impl FnMut(&OperationId, u64, &str) -> std::result::Result<K, E>,
    ) -> std::result::Result<Vec<K>, E> {
        if !operation.as_str().starts_with("profile-") {
            return Err(Error::Invalid("profile operation namespace").into());
        }
        self.payloads().iter().enumerate()
            .map(|(i, payload)| insert(operation, (i + 1) as u64, payload)).collect()
    }
    /// Digest includes ancestry-path facts; S02's native exclusion is unrelated.
    /// Exact matrix and Plan comparison also prevents using a different meaning
    /// with an unchanged ledger. This performs no native execution or mutation.
    pub fn verify_report(&self, report: &Report, plan: &Plan) -> Result<()> {
        if ledger_digest(report)? != self.ledger_digest {
            return Err(Error::LedgerDigestMismatch);
        }
        if Self::capture(report, plan)?.bytes != self.bytes {
            return Err(Error::MeaningMismatch);
        }
        Ok(())
    }
    pub fn reconstruct(&self, inputs: &[Input<'_>],
        make_plan: impl FnOnce(&Report) -> std::result::Result<Plan, materialize::Error>,
    ) -> Result<Report> {
        let report = Report::extract(&Catalog::load(inputs)?)?;
        self.verify_report(&report, &make_plan(&report)?)?;
        Ok(report)
    }
    /// Call in addition to SealStore's current availability check, immediately
    /// before displaying an Available status or admitting new acceptance/use.
    /// Finite seal custody is NOT a promise that a URL remains downloadable.
    pub fn status(&self, inputs: &[Input<'_>],
        make_plan: impl FnOnce(&Report) -> std::result::Result<Plan, materialize::Error>,
    ) -> Availability {
        match self.reconstruct(inputs, make_plan) {
            Ok(_) => Availability::Available,
            Err(error) => Availability::Unavailable(error),
        }
    }
}

/// Canonical ledger = sorted, deduplicated exact Fact::to_json strings
/// concatenated with NO separator, no array brackets, no trailing newline.
/// This is unambiguous adjacent JSON objects, not JSON reserialization.
pub fn ledger_digest(report: &Report) -> Result<String> {
    let mut facts: Vec<_> = report.ledger.iter().map(Fact::to_json).collect();
    facts.sort();
    facts.dedup();
    let mut bytes = String::new();
    for fact in facts {
        if bytes.len().saturating_add(fact.len()) > parse::MAX_BYTES { return Err(Error::Limit); }
        bytes.push_str(&fact);
    }
    checked_hash(bytes.as_bytes())
}
fn checked_hash(bytes: &[u8]) -> Result<String> {
    if parse::sha256(b"abc")?
        != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
        return Err(parse::Error::HashTool.into());
    }
    Ok(parse::sha256(bytes)?)
}

fn pins_json() -> String {
    let mut pins: Vec<_> = recipe::ARTIFACTS.iter().map(|pin| format!(
        "{{\"name\":{},\"bytes\":{},\"sha256\":{},\"provenance\":{},\"url\":{}}}",
        json(pin.name), pin.bytes, json(pin.sha256), json(pin.provenance), json(pin.url))).collect();
    pins.sort();
    pins.dedup();
    format!("[{}]", pins.join(","))
}

fn capture_steps(plan: &Plan) -> Result<String> {
    // First emulate an already-exact store to capture identity/exact pairs.
    let mut reads = Vec::new();
    let count = plan.reconcile(|query| { reads.push(query.to_string()); Ok(Some(1)) })?;
    if count != 0 || reads.len() % 2 != 0 { return Err(Error::Invalid("plan read protocol")); }
    let n = reads.len() / 2;
    let mut inserts = Vec::new();
    let mut call = 0;
    // Then emulate an empty store: all identity reads, followed by one committed
    // insert + identity/exact readback per step. Verify every callback position;
    // a changed S02 protocol fails closed rather than silently losing evidence.
    let count = plan.reconcile(|query| {
        let at = call;
        call += 1;
        if at < n {
            if reads.get(at * 2).map(String::as_str) != Some(query) {
                return Err(materialize::Error::UnexpectedOutcome);
            }
            return Ok(Some(0));
        }
        let step = (at - n) / 3;
        match (at - n) % 3 {
            0 => { inserts.push(query.to_string()); Ok(None) }
            position => {
                if reads.get(step * 2 + position - 1).map(String::as_str) != Some(query) {
                    return Err(materialize::Error::UnexpectedOutcome);
                }
                Ok(Some(1))
            }
        }
    })?;
    if count != n || inserts.len() != n || call != n * 4 {
        return Err(Error::Invalid("plan insert protocol"));
    }
    // Exact/insert repeat large facts_json literals, including across installed
    // nodes of the same class. Intern literal and intervening text segments ONCE.
    // This is lossless byte factoring, not GQL interpretation or fact filtering.
    // Concatenating dictionary[index] in order restores every original statement.
    let triples: Vec<_> = reads.chunks_exact(2).zip(inserts)
        .map(|(pair, insert)| [pair[0].clone(), pair[1].clone(), insert]).collect();
    let parts: Vec<_> = triples.iter().map(|triple| triple.iter()
        .map(|text| segments(text)).collect::<Result<Vec<_>>>()).collect::<Result<_>>()?;
    let mut dictionary: Vec<_> = parts.iter().flatten().flatten().copied().collect();
    dictionary.sort();
    dictionary.dedup();
    let indices: BTreeMap<_, _> = dictionary.iter().enumerate().map(|(i, s)| (*s, i)).collect();
    let mut steps = Vec::new();
    for triple in parts {
        let fields: Vec<_> = ["identity", "exact", "insert"].iter().zip(triple).map(|(key, parts)| {
            let numbers: Result<Vec<_>> = parts.iter().map(|s| indices.get(s)
                .map(|i| i.to_string()).ok_or(Error::Invalid("statement dictionary"))).collect();
            Ok(format!("{}:[{}]", json(key), numbers?.join(",")))
        }).collect::<Result<_>>()?;
        steps.push(format!("{{{}}}", fields.join(",")));
    }
    steps.sort();
    steps.dedup();
    Ok(format!("{{\"dictionary\":[{}],\"steps\":[{}]}}",
        dictionary.iter().map(|s| json(s)).collect::<Vec<_>>().join(","), steps.join(",")))
}

fn segments(text: &str) -> Result<Vec<&str>> {
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut result = Vec::new();
    for (at, byte) in text.bytes().enumerate() {
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' {
                result.push(&text[start..=at]);
                start = at + 1;
                quoted = false;
            }
        } else if byte == b'"' {
            if at > start { result.push(&text[start..at]); }
            start = at;
            quoted = true;
        }
    }
    if quoted { return Err(Error::Invalid("unterminated statement literal")); }
    if start < text.len() { result.push(&text[start..]); }
    Ok(result)
}

// Private S03 framing only. Does not replace or alter seal canonical/decode.
fn frame(fields: &[&str]) -> String {
    fields.iter().map(|s| format!("{}:{s}", s.len())).collect()
}
fn unframe(mut raw: &str, limit: usize) -> Result<Vec<&str>> {
    let mut fields = Vec::new();
    while !raw.is_empty() {
        if fields.len() == limit { return Err(Error::Invalid("field count")); }
        let (number, rest) = raw.split_once(':').ok_or(Error::Invalid("field length"))?;
        let length: usize = number.parse().map_err(|_| Error::Invalid("field length"))?;
        if length.to_string() != number || length > rest.len() || !rest.is_char_boundary(length) {
            return Err(Error::Invalid("field boundary"));
        }
        fields.push(&rest[..length]);
        raw = &rest[length..];
    }
    Ok(fields)
}
