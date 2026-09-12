use super::{
    codec, Digest, Result, SealError, Sha256, MAX_ARTIFACT_BYTES, MAX_CLOSURE_BYTES, MAX_DEPTH,
    MAX_NODES,
};
use crate::binding::{self, BindingStatus, Finding};
use crate::domain::{
    ids::{BindingRevision, OperationId},
    scope::TrustedScope,
    values::Value,
};
use crate::native::NativeHandle;
use crate::storage::sqlite::SqliteStore;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RowKey {
    operation: OperationId,
    sequence: u64,
}
impl RowKey {
    pub fn new(operation: OperationId, sequence: u64) -> Result<Self> {
        if sequence == 0 {
            return Err(SealError::Invalid("row sequence"));
        }
        Ok(Self {
            operation,
            sequence,
        })
    }
    pub(super) fn encode(&self) -> String {
        codec::encode(&[self.operation.as_str().into(), self.sequence.to_string()])
    }
    pub(super) fn decode(raw: &str) -> Result<Self> {
        let f = codec::decode(raw, 512, 2)?;
        if f.len() != 2 {
            return Err(SealError::Invalid("row key"));
        }
        Self::new(
            OperationId::parse(&f[0]).map_err(|_| SealError::Invalid("row operation"))?,
            codec::number(&f[1])?,
        )
    }
    fn predicate(&self) -> String {
        format!(
            "operation={} AND seq={}",
            binding::sql_quote(self.operation.as_str()),
            binding::sql_quote(&self.sequence.to_string())
        )
    }
}

/// Structural application content, persisted by the caller via the existing
/// outbox API. Nested references live in the durable bytes, not an out-of-band
/// caller graph. It cannot carry qualification or authorize anything.
#[derive(Debug, Clone)]
pub struct ContentNode {
    payload: String,
    children: Vec<RowKey>,
}
impl ContentNode {
    pub fn new(payload: String, mut children: Vec<RowKey>) -> Result<Self> {
        if payload.len() > 16_384 || children.len() > MAX_NODES {
            return Err(SealError::Limit("content node"));
        }
        children.sort();
        children.dedup();
        Ok(Self { payload, children })
    }
    pub fn value(&self) -> Value {
        Value::Text(codec::encode(&[
            "verdant-content-v1".into(),
            "valid-structural".into(),
            self.payload.clone(),
            codec::encode(&self.children.iter().map(RowKey::encode).collect::<Vec<_>>()),
        ]))
    }
    fn children(raw: &str) -> Result<Vec<RowKey>> {
        let f = codec::decode(raw, MAX_CLOSURE_BYTES, 4)?;
        if f.len() != 4 || f[0] != "verdant-content-v1" {
            return Err(SealError::Invalid("content node format"));
        }
        if f[1] != "valid-structural" {
            return Err(SealError::Status(f[1].clone()));
        }
        if f[2].len() > 16_384 {
            return Err(SealError::Limit("content payload"));
        }
        codec::decode(&f[3], MAX_CLOSURE_BYTES, MAX_NODES)?
            .iter()
            .map(|s| RowKey::decode(s))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RowRef {
    pub key: RowKey,
    pub digest: Digest,
    pub bytes: usize,
}
impl RowRef {
    pub fn encode(&self) -> String {
        codec::encode(&[
            self.key.encode(),
            self.digest.as_str().into(),
            self.bytes.to_string(),
        ])
    }
    pub fn decode(raw: &str) -> Result<Self> {
        let f = codec::decode(raw, 1024, 3)?;
        if f.len() != 3 {
            return Err(SealError::Invalid("row reference"));
        }
        Ok(Self {
            key: RowKey::decode(&f[0])?,
            digest: Digest::parse(&f[1])?,
            bytes: codec::number(&f[2])?,
        })
    }
}

/// Exact manifest + snapshot capture from a checkpoint returned by this owner.
/// The snapshot's Selene digest is recorded as native integrity metadata, not
/// assumed to be SHA-256. Application byte verification always uses SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeRef {
    store: String,
    generation: u64,
    manifest_digest: Digest,
    manifest_bytes: usize,
    snapshot_digest: Digest,
    snapshot_bytes: usize,
    selene_digest: String,
}
impl NativeRef {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }
    pub fn manifest_bytes(&self) -> usize {
        self.manifest_bytes
    }
    pub fn capture(native: &NativeHandle, sha: &Sha256) -> Result<Self> {
        let _guard = native.custody_lock()?;
        let report = native.checkpoint()?.completed()?;
        let dir = std::fs::canonicalize(native.dir())?;
        let manifest =
            read_artifact(&dir.join(format!("MANIFEST-{:020}.control", report.generation)))?;
        let snapshot =
            read_artifact(&dir.join(format!("SNAPSHOT-{:020}.logical", report.generation)))?;
        if snapshot.len() as u64 != report.bytes {
            return Err(SealError::Changed("checkpoint snapshot length".into()));
        }
        Ok(Self {
            store: dir
                .to_str()
                .ok_or(SealError::Invalid("native path UTF-8"))?
                .into(),
            generation: report.generation,
            manifest_digest: sha.hash(&manifest)?,
            manifest_bytes: manifest.len(),
            snapshot_digest: sha.hash(&snapshot)?,
            snapshot_bytes: snapshot.len(),
            selene_digest: report.digest_hex,
        })
    }
    pub(super) fn verify(&self, native: &NativeHandle, sha: &Sha256) -> Result<()> {
        let dir = std::fs::canonicalize(native.dir())?;
        if dir.to_str() != Some(self.store.as_str()) {
            return Err(SealError::Conflict(
                "native reference belongs to another store".into(),
            ));
        }
        for (name, digest, bytes) in [
            (
                format!("MANIFEST-{:020}.control", self.generation),
                &self.manifest_digest,
                self.manifest_bytes,
            ),
            (
                format!("SNAPSHOT-{:020}.logical", self.generation),
                &self.snapshot_digest,
                self.snapshot_bytes,
            ),
        ] {
            let actual = read_artifact(&dir.join(&name))?;
            if actual.len() != bytes || sha.hash(&actual)? != *digest {
                return Err(SealError::Changed(name));
            }
        }
        Ok(())
    }
    pub(super) fn encode(&self) -> String {
        codec::encode(&[
            self.store.clone(),
            self.generation.to_string(),
            self.manifest_digest.as_str().into(),
            self.manifest_bytes.to_string(),
            self.snapshot_digest.as_str().into(),
            self.snapshot_bytes.to_string(),
            self.selene_digest.clone(),
        ])
    }
    pub(super) fn decode(raw: &str) -> Result<Self> {
        let f = codec::decode(raw, 8192, 7)?;
        if f.len() != 7 {
            return Err(SealError::Invalid("native reference"));
        }
        let result = Self {
            store: f[0].clone(),
            generation: codec::number(&f[1])?,
            manifest_digest: Digest::parse(&f[2])?,
            manifest_bytes: codec::number(&f[3])?,
            snapshot_digest: Digest::parse(&f[4])?,
            snapshot_bytes: codec::number(&f[5])?,
            selene_digest: Digest::parse(&f[6])?.as_str().into(),
        };
        if result.generation == 0
            || result.manifest_bytes > MAX_ARTIFACT_BYTES
            || result.snapshot_bytes > MAX_ARTIFACT_BYTES
        {
            return Err(SealError::Limit("native reference"));
        }
        Ok(result)
    }
}
fn read_artifact(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SealError::Missing(path.display().to_string())
        } else {
            e.into()
        }
    })?;
    if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES as u64 {
        return Err(SealError::Limit("regular native artifact bytes"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_ARTIFACT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(SealError::Limit("native artifact bytes"));
    }
    Ok(bytes)
}

pub(super) struct Closure {
    pub rows: Vec<RowRef>,
    pub findings: Vec<String>,
    pub guard: String,
}
pub(super) fn closure(
    store: &SqliteStore,
    sha: &Sha256,
    roots: &[RowKey],
    scope: &TrustedScope,
) -> Result<Closure> {
    let mut walk = Walker {
        store,
        sha,
        scope,
        visiting: BTreeSet::new(),
        rows: BTreeMap::new(),
        findings: BTreeSet::new(),
        bytes: 0,
        edges: 0,
        guard: "1".into(),
    };
    for root in roots {
        walk.visit(root, 0)?;
    }
    if walk.findings.is_empty() {
        return Err(SealError::Invalid(
            "seal needs a durable valid binding finding",
        ));
    }
    Ok(Closure {
        rows: walk.rows.into_values().collect(),
        findings: walk.findings.into_iter().collect(),
        guard: walk.guard,
    })
}
struct Walker<'a> {
    store: &'a SqliteStore,
    sha: &'a Sha256,
    scope: &'a TrustedScope,
    visiting: BTreeSet<RowKey>,
    rows: BTreeMap<RowKey, RowRef>,
    findings: BTreeSet<String>,
    bytes: usize,
    edges: usize,
    guard: String,
}
const COLUMNS: [&str; 11] = [
    "operation",
    "seq",
    "entity",
    "sensor",
    "value_json",
    "unit",
    "source_ms",
    "receipt_ms",
    "ingestion_ms",
    "generation",
    "id",
];
impl Walker<'_> {
    fn visit(&mut self, key: &RowKey, depth: usize) -> Result<()> {
        self.edges += 1;
        if depth > MAX_DEPTH || self.edges > MAX_NODES * 4 {
            return Err(SealError::Limit("closure depth/work"));
        }
        if self.visiting.contains(key) {
            return Err(SealError::Cycle);
        }
        if self.rows.contains_key(key) {
            return Ok(());
        }
        if self.rows.len() + self.visiting.len() >= MAX_NODES {
            return Err(SealError::Limit("closure nodes"));
        }
        self.visiting.insert(key.clone());
        let columns = COLUMNS
            .iter()
            .map(|s| format!("quote({s})"))
            .collect::<Vec<_>>()
            .join(",");
        let rows = self.store.exec_script(&format!(
            "SELECT {columns} FROM outbox WHERE {} LIMIT 2;",
            key.predicate()
        ))?;
        let [row] = rows.as_slice() else {
            return Err(if rows.is_empty() {
                SealError::Missing(key.encode())
            } else {
                SealError::Conflict("ambiguous row address".into())
            });
        };
        if row.len() != COLUMNS.len() {
            return Err(SealError::Invalid("source row width"));
        }
        let values: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, raw)| {
                if COLUMNS[i] == "id" {
                    Ok(raw.clone())
                } else {
                    binding::unquote_column(raw)?.ok_or(SealError::Invalid("NULL source column"))
                }
            })
            .collect::<Result<_>>()?;
        // Physical SQLite id is used for the admission guard, not semantic bytes.
        let canonical = codec::encode(&values[..10]);
        self.bytes = self
            .bytes
            .checked_add(canonical.len())
            .ok_or(SealError::Limit("closure bytes"))?;
        if self.bytes > MAX_CLOSURE_BYTES {
            return Err(SealError::Limit("closure bytes"));
        }
        let Value::Text(raw) =
            Value::from_json(&values[4]).map_err(|_| SealError::Invalid("source value"))?
        else {
            return Err(SealError::Invalid("source text required"));
        };
        let children = if key.operation.as_str() == binding::OP_FINDING_TEXT {
            self.findings
                .insert(finding_fingerprint(&raw, self.scope, self.sha)?);
            Vec::new()
        } else {
            ContentNode::children(&raw)?
        };
        self.guard.push_str(&format!(
            " AND (SELECT COUNT(*) FROM outbox WHERE {})=1 AND EXISTS(SELECT 1 FROM outbox WHERE ",
            key.predicate()
        ));
        self.guard.push_str(
            &COLUMNS
                .iter()
                .zip(&values)
                .map(|(column, value)| format!("{column}={}", binding::sql_quote(value)))
                .collect::<Vec<_>>()
                .join(" AND "),
        );
        self.guard.push(')');
        for child in children {
            self.visit(&child, depth + 1)?;
        }
        self.visiting.remove(key);
        self.rows.insert(
            key.clone(),
            RowRef {
                key: key.clone(),
                digest: self.sha.hash(canonical.as_bytes())?,
                bytes: canonical.len(),
            },
        );
        Ok(())
    }
}

fn finding_fingerprint(raw: &str, scope: &TrustedScope, sha: &Sha256) -> Result<String> {
    let map = binding::split_descriptor(raw)?;
    let get = |k| binding::require_field(&map, k).map_err(SealError::from);
    if get("v")? != "2" || get("kind")? != "finding" {
        return Err(SealError::Invalid("finding descriptor version"));
    }
    let canonical = get("binding")?;
    let parts = canonical.split('\x1f').collect::<Vec<_>>();
    if parts.len() != 14 || parts[0] != "binding-canonical-v2" {
        return Err(SealError::Invalid("binding canonical version"));
    }
    let names = [
        "endpoint",
        "eclass",
        "escope",
        "equipment",
        "property",
        "pscope",
        "source",
        "unit",
        "mode",
        "requested",
        "effective",
        "feedback",
        "status",
    ];
    let fields = names
        .iter()
        .zip(&parts[1..])
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let proposed = binding::history::decode_propose(&fields)?;
    match proposed.status() {
        BindingStatus::Valid => {}
        BindingStatus::Imported => return Err(SealError::Status("imported".into())),
        BindingStatus::ObservedQualified => {
            return Err(SealError::Status(
                "observed-qualified has no supporting evidence".into(),
            ))
        }
    }
    let checked = binding::propose(
        proposed.endpoint().clone(),
        proposed.endpoint_class(),
        proposed.endpoint_scope().clone(),
        proposed.point_equipment().clone(),
        proposed.point_property().clone(),
        proposed.point_scope().clone(),
        proposed.source().clone(),
        proposed.unit(),
        proposed.endpoint_class(),
        proposed.unit().clone(),
        proposed.mode().cloned(),
        proposed.requested(),
        proposed.effective(),
        proposed.feedback(),
    )?;
    if checked != proposed || proposed.point_scope() != scope {
        return Err(SealError::Invalid("finding structure/scope"));
    }
    let cap = crate::access::CapabilityName::parse(&get("capability")?)?;
    let issuer = crate::access::IssuerId::parse(&get("issuer")?)?;
    let actor_scope =
        TrustedScope::parse(&get("scope")?).map_err(|_| SealError::Invalid("actor scope"))?;
    let capgen: u32 = codec::number(&get("capgen")?)?;
    if capgen == 0 || actor_scope != *scope {
        return Err(SealError::Invalid("actor reference"));
    }
    let actor = format!(
        "capability={};scope={};capgen={capgen};issuer={}",
        binding::pct_encode(cap.as_str()),
        binding::pct_encode(scope.as_str()),
        binding::pct_encode(issuer.as_str())
    );
    let generation: u32 = codec::number(&get("generation")?)?;
    if generation == 0 || generation != codec::number::<u32>(&get("revision")?)? {
        return Err(SealError::Invalid("finding generation"));
    }
    let finding = Finding::for_binding(&proposed, BindingRevision::new(generation), &actor);
    if get("fid")? != finding.id().as_str()
        || get("digest")? != finding.digest()
        || get("summary")? != finding.summary()
    {
        return Err(SealError::Changed("finding fingerprint/actor join".into()));
    }
    Ok(codec::encode(&[
        finding.id().as_str().into(),
        generation.to_string(),
        actor,
        "synthetic-fnv1a64-not-authority".into(),
        finding.digest().into(),
        "binding-canonical-v2-sha256".into(),
        sha.hash(canonical.as_bytes())?.as_str().into(),
    ]))
}
