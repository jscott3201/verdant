use super::{codec, effective::check_environment, store, EffectiveConfig, Error, Result, Stage};
use crate::binding;
use crate::domain::{ids::OperationId, values::Value};
use crate::seal::{ContentNode, Digest, Manifest, RowKey, SealStore};
use crate::storage::sqlite::SqliteStore;

/// Durable but unapproved intent. Creating this row grants no publish authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    pub(super) operation: OperationId,
    pub(super) config: EffectiveConfig,
    pub(super) value_json: String,
}
impl Staged {
    pub fn stage(&self) -> Stage {
        Stage::Staged
    }
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }
    pub fn config(&self) -> &EffectiveConfig {
        &self.config
    }
    pub fn root(&self) -> Result<RowKey> {
        Ok(RowKey::new(self.operation.clone(), 1)?)
    }
    pub(super) fn guard(&self) -> String {
        format!("(SELECT COUNT(*) FROM outbox WHERE operation={})=1 AND EXISTS(SELECT 1 FROM outbox WHERE operation={} AND seq='1' AND value_json={})",
            binding::sql_quote(self.operation.as_str()), binding::sql_quote(self.operation.as_str()), binding::sql_quote(&self.value_json))
    }
}

/// Seal-owned publication, not acceptance, activation or reusable authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub(super) staged: Staged,
    pub(super) identity: Digest,
    pub(super) manifest: Manifest,
}
impl Sealed {
    pub fn stage(&self) -> Stage {
        Stage::Sealed
    }
    pub fn identity(&self) -> &Digest {
        &self.identity
    }
    pub fn config(&self) -> &EffectiveConfig {
        &self.staged.config
    }
    pub fn staged(&self) -> &Staged {
        &self.staged
    }
    pub(super) fn verify(&self, store: &SqliteStore, seals: &SealStore) -> Result<()> {
        let checked = check_seal(store, &self.staged, &self.identity, seals)?;
        if checked != self.manifest {
            return Err(Error::Conflict("seal bytes changed".into()));
        }
        Ok(())
    }
    pub(super) fn guard(&self) -> String {
        let raw = codec::encode(&[
            "seal-row-v1".into(),
            self.identity.as_str().into(),
            self.manifest.canonical_bytes(),
        ]);
        let release = codec::encode(&["seal-release-v1".into(), self.identity.as_str().into()]);
        format!("({}) AND (SELECT COUNT(*) FROM outbox WHERE operation='seal-revision-v1' AND value_json={})=1 AND NOT EXISTS(SELECT 1 FROM outbox WHERE operation='seal-release-v1' AND value_json={})",
            self.staged.guard(), binding::sql_quote(&Value::Text(raw).to_json()), binding::sql_quote(&Value::Text(release).to_json()))
    }
}

impl store::AcceptanceStore {
    /// Stage immutable bytes under an explicit operation ID. A changed draft
    /// needs a new ID; same-ID changed bytes conflict via the existing receipt.
    /// Staging is non-authoritative: publication still requires the seal writer.
    pub fn stage(
        &self,
        operation: &OperationId,
        config: EffectiveConfig,
        findings: Vec<RowKey>,
    ) -> Result<Staged> {
        check_environment()?;
        stage_operation(operation)?;
        let value = ContentNode::new(config.canonical_bytes(), findings)?.value();
        let value_json = value.to_json();
        let staged = Staged {
            operation: operation.clone(),
            config,
            value_json,
        };
        let condition = format!(
            "NOT EXISTS(SELECT 1 FROM outbox WHERE operation={})",
            binding::sql_quote(operation.as_str())
        );
        let body = store::insert_row(
            operation.as_str(),
            "accept-config",
            "accept-staged",
            &staged.value_json,
            1,
            "",
        );
        let pending = self
            .store
            .prepare_guarded_batch(&condition, &body, staged.value_json.len())?
            .with_operation(operation.clone());
        let outcome = self.store.submit(&pending);
        let outcome = match outcome {
            crate::storage::sqlite::MutationOutcome::Unknown { .. } => {
                self.store.reconcile(&pending)
            }
            other => other,
        };
        store::committed_row(outcome)?;
        Ok(staged)
    }

    pub fn read_staged(&self, operation: &OperationId) -> Result<Staged> {
        read_staged(&self.store, operation)
    }

    /// Consume an actual seal, never a caller-manufactured SealCommit struct.
    /// The manifest must name this staged row as a root, include its exact
    /// content, and carry matching approvals for every effective binding.
    pub fn sealed(&self, staged: &Staged, identity: &Digest, seals: &SealStore) -> Result<Sealed> {
        check_environment()?;
        let manifest = check_seal(&self.store, staged, identity, seals)?;
        Ok(Sealed {
            staged: staged.clone(),
            identity: identity.clone(),
            manifest,
        })
    }
}

fn stage_operation(operation: &OperationId) -> Result<()> {
    if !operation.as_str().starts_with("accept-stage-") {
        return Err(Error::Invalid("staging operation namespace"));
    }
    Ok(())
}
fn read_staged(store: &SqliteStore, operation: &OperationId) -> Result<Staged> {
    stage_operation(operation)?;
    let rows = store.exec_script(&format!(
        "SELECT quote(value_json),seq,entity,sensor FROM outbox WHERE operation={} LIMIT 2;",
        binding::sql_quote(operation.as_str())
    ))?;
    let [row] = rows.as_slice() else {
        return Err(Error::Invalid("missing/ambiguous staged row"));
    };
    if row.len() != 4 || row[1] != "1" || row[2] != "accept-config" || row[3] != "accept-staged" {
        return Err(Error::Invalid("staged row columns"));
    }
    let value_json = binding::unquote_column(&row[0])?.ok_or(Error::Invalid("NULL stage"))?;
    let content = codec::decode(&codec::text_json(&value_json)?, 262_144, 4)?;
    if content.len() != 4 || content[0] != "verdant-content-v1" || content[1] != "valid-structural"
    {
        return Err(Error::Invalid("staged content version/status"));
    }
    let config = EffectiveConfig::decode(&content[2])?;
    Ok(Staged {
        operation: operation.clone(),
        config,
        value_json,
    })
}

fn check_seal(
    store: &SqliteStore,
    staged: &Staged,
    identity: &Digest,
    seals: &SealStore,
) -> Result<Manifest> {
    if read_staged(store, &staged.operation)? != *staged {
        return Err(Error::Conflict("staged bytes differ".into()));
    }
    // Exact seal availability, with seal's existing nonqueueing custody guard.
    // No acceptance lock is held while this verifies native/durable content.
    let manifest = seals.capture_simulation(identity).map_err(Error::Blocked)?;
    let f = codec::decode(
        &manifest.canonical_bytes(),
        crate::seal::MAX_MANIFEST_BYTES,
        14,
    )?;
    if f.len() != 14
        || f[0] != "verdant-seal-v1"
        || f[1] != "valid-structural-not-qualified"
        || f[2] != staged.config.scope().as_str()
        || f[3] != staged.config.binding_revision().as_u32().to_string()
    {
        return Err(Error::Invalid("seal scope/revision/status"));
    }
    let roots = codec::decode(
        &f[10],
        crate::seal::MAX_MANIFEST_BYTES,
        crate::seal::MAX_NODES,
    )?;
    let root = codec::encode(&[staged.operation.as_str().into(), "1".into()]);
    if !roots.contains(&root) {
        return Err(Error::Conflict(
            "seal does not publish effective config root".into(),
        ));
    }
    // Frozen PR22 fingerprint framing includes a SHA-256 of the FULL binding
    // canonical bytes. FNV, an old target's approval, or matching labels cannot
    // satisfy this join. The fact's actor/generation must be the cited one too.
    let fingerprints = manifest
        .finding_fingerprints()
        .iter()
        .map(|raw| codec::decode(raw, 4096, 7))
        .collect::<Result<Vec<_>>>()?;
    for entry in staged.config.entries().values() {
        let digest = entry.fingerprint(seals.hash_tool())?;
        if !fingerprints.iter().any(|p| {
            p.len() == 7
                && p[3] == "synthetic-fnv1a64-not-authority"
                && p[5] == "binding-canonical-v2-sha256"
                && p[6] == digest.as_str()
                && staged.config.facts().iter().any(|fact| {
                    fact.id() == p[0]
                        && fact.generation().to_string() == p[1]
                        && fact.actor() == p[2]
                        && fact.digest() == p[4]
                })
        }) {
            return Err(Error::ApprovalMismatch);
        }
    }
    // Prove the SealStore and this acceptance store share the publication.
    let sealed = Sealed {
        staged: staged.clone(),
        identity: identity.clone(),
        manifest: manifest.clone(),
    };
    let rows = store.exec_script(&format!(
        "SELECT CASE WHEN ({}) THEN 1 ELSE 0 END;",
        sealed.guard()
    ))?;
    if rows != vec![vec!["1".to_string()]] {
        return Err(Error::Conflict("publication is foreign or released".into()));
    }
    Ok(manifest)
}
