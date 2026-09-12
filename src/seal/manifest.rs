use super::{
    codec,
    references::{self, RowRef},
    Digest, NativeRef, Result, RowKey, SealError, Sha256, MAX_MANIFEST_BYTES, MAX_NATIVE_REFS,
    MAX_NODES,
};
use crate::domain::{ids::BindingRevision, scope::TrustedScope};
use crate::native::NativeHandle;
use crate::storage::sqlite::SqliteStore;

/// Small INERT execution references. No executable is launched, host contacted,
/// or binary attestation inferred. Exact caller release/host strings are retained
/// alongside the actual compiled target/compiler and the pinned Selene revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRef {
    binary: String,
    host: String,
}
impl RuntimeRef {
    pub fn new(binary: &str, host: &str) -> Result<Self> {
        Ok(Self {
            binary: codec::text(binary)?,
            host: codec::text(host)?,
        })
    }
    fn encode(&self) -> String {
        codec::encode(&[
            self.binary.clone(),
            self.host.clone(),
            env!("CARGO_PKG_VERSION").into(),
            env!("VERDANT_RUSTC_VERSION").into(),
            env!("VERDANT_BUILD_TARGET").into(),
            crate::native::SELENE_REV.into(),
        ])
    }
}

/// A draft is mutable caller intent; no identity or retention promise exists.
/// Operation identity is supplied separately so content idempotence does not
/// depend on a retry attempt ID, timestamp, or outbox physical row id.
#[derive(Debug, Clone)]
pub struct Draft {
    pub(super) revision: BindingRevision,
    pub(super) scope: TrustedScope,
    runtime: RuntimeRef,
    roots: Vec<RowKey>,
    native: Vec<NativeRef>,
}
impl Draft {
    pub fn new(
        revision: BindingRevision,
        scope: TrustedScope,
        runtime: RuntimeRef,
        mut roots: Vec<RowKey>,
        mut native: Vec<NativeRef>,
    ) -> Result<Self> {
        if revision.as_u32() == 0 || roots.is_empty() || native.is_empty() {
            return Err(SealError::Invalid(
                "nonempty revision, findings and native references required",
            ));
        }
        if roots.len() > MAX_NODES || native.len() > MAX_NATIVE_REFS {
            return Err(SealError::Limit("draft references"));
        }
        roots.sort();
        roots.dedup();
        native.sort();
        native.dedup();
        Ok(Self {
            revision,
            scope,
            runtime,
            roots,
            native,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub(super) scope: TrustedScope,
    revision: u32,
    runtime: String,
    publisher: String,
    hash_tool: String,
    pub(super) roots: Vec<RowKey>,
    rows: Vec<RowRef>,
    findings: Vec<String>,
    pub(super) native: Vec<NativeRef>,
}
impl Manifest {
    pub(super) fn stage(
        draft: &Draft,
        publisher: String,
        store: &SqliteStore,
        native: &NativeHandle,
        sha: &Sha256,
    ) -> Result<(Self, String)> {
        let closure = references::closure(store, sha, &draft.roots, &draft.scope)?;
        for reference in &draft.native {
            reference.verify(native, sha)?;
        }
        let result = Self {
            scope: draft.scope.clone(),
            revision: draft.revision.as_u32(),
            runtime: draft.runtime.encode(),
            publisher,
            hash_tool: sha.reference(),
            roots: draft.roots.clone(),
            rows: closure.rows,
            findings: closure.findings,
            native: draft.native.clone(),
        };
        if result.canonical_bytes().len() > MAX_MANIFEST_BYTES {
            return Err(SealError::Limit("manifest bytes"));
        }
        Ok((result, closure.guard))
    }
    /// Domain/version fields are part of the digest, not side metadata. R07 did
    /// not define a converter release API; this application reference explicitly
    /// versions that frozen converter contract, without changing its source.
    pub fn canonical_bytes(&self) -> String {
        codec::encode(&[
            "verdant-seal-v1".into(),
            "valid-structural-not-qualified".into(),
            self.scope.as_str().into(),
            self.revision.to_string(),
            crate::storage::SCHEMA_GENERATION.to_string(),
            crate::semantics::profile::PINNED_PROFILE_ID.into(),
            "verdant-converter-r07-v1".into(),
            self.runtime.clone(),
            self.publisher.clone(),
            self.hash_tool.clone(),
            codec::encode(&self.roots.iter().map(RowKey::encode).collect::<Vec<_>>()),
            codec::encode(&self.rows.iter().map(RowRef::encode).collect::<Vec<_>>()),
            codec::encode(&self.findings),
            codec::encode(
                &self
                    .native
                    .iter()
                    .map(NativeRef::encode)
                    .collect::<Vec<_>>(),
            ),
        ])
    }
    pub fn identity(&self, sha: &Sha256) -> Result<Digest> {
        sha.hash(self.canonical_bytes().as_bytes())
    }
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }
    pub fn native_refs(&self) -> &[NativeRef] {
        &self.native
    }
    pub fn finding_fingerprints(&self) -> &[String] {
        &self.findings
    }
    /// Seals cannot be edited in place. A changed draft must be sealed anew.
    pub fn replace(&mut self, _draft: Draft) -> Result<()> {
        Err(SealError::SealedMutation)
    }
    pub(super) fn verify(
        &self,
        store: &SqliteStore,
        native: &NativeHandle,
        sha: &Sha256,
    ) -> Result<()> {
        let closure = references::closure(store, sha, &self.roots, &self.scope)?;
        if closure.rows != self.rows || closure.findings != self.findings {
            return Err(SealError::Changed("durable row/reference closure".into()));
        }
        for reference in &self.native {
            reference.verify(native, sha)?;
        }
        Ok(())
    }
    pub(super) fn decode(raw: &str) -> Result<Self> {
        let f = codec::decode(raw, MAX_MANIFEST_BYTES, 14)?;
        if f.len() != 14
            || f[0] != "verdant-seal-v1"
            || f[1] != "valid-structural-not-qualified"
            || f[4] != crate::storage::SCHEMA_GENERATION.to_string()
            || f[5] != crate::semantics::profile::PINNED_PROFILE_ID
            || f[6] != "verdant-converter-r07-v1"
        {
            return Err(SealError::Invalid("manifest version/status"));
        }
        let scope = TrustedScope::parse(&f[2]).map_err(|_| SealError::Invalid("manifest scope"))?;
        let revision = codec::number(&f[3])?;
        let runtime = codec::decode(&f[7], 2048, 6)?;
        if runtime.len() != 6 || runtime[5] != crate::native::SELENE_REV || revision == 0 {
            return Err(SealError::Invalid("manifest execution/version refs"));
        }
        for text in &runtime {
            codec::text(text)?;
        }
        let roots = codec::decode(&f[10], MAX_MANIFEST_BYTES, MAX_NODES)?
            .iter()
            .map(|s| RowKey::decode(s))
            .collect::<Result<Vec<_>>>()?;
        let rows = codec::decode(&f[11], MAX_MANIFEST_BYTES, MAX_NODES)?
            .iter()
            .map(|s| RowRef::decode(s))
            .collect::<Result<Vec<_>>>()?;
        let findings = codec::decode(&f[12], MAX_MANIFEST_BYTES, MAX_NODES)?;
        let native = codec::decode(&f[13], MAX_MANIFEST_BYTES, MAX_NATIVE_REFS)?
            .iter()
            .map(|s| NativeRef::decode(s))
            .collect::<Result<Vec<_>>>()?;
        if roots.is_empty() || findings.is_empty() || native.is_empty() || rows.is_empty() {
            return Err(SealError::Invalid("empty seal closure"));
        }
        let result = Self {
            scope,
            revision,
            runtime: f[7].clone(),
            publisher: f[8].clone(),
            hash_tool: f[9].clone(),
            roots,
            rows,
            findings,
            native,
        };
        if result.canonical_bytes() != raw {
            return Err(SealError::Invalid("noncanonical manifest"));
        }
        Ok(result)
    }
}
