use super::{
    codec, Digest, Draft, Manifest, Result, SealError, Sha256, MAX_HISTORY, MAX_LIVE_SEALS,
    MAX_MANIFEST_BYTES,
};
use crate::access::{AccessGate, Credential};
use crate::binding::{self, BindingRegistry, BindingRole};
use crate::domain::{ids::OperationId, values::Value};
use crate::native::{CustodyGuard, CustodyPlan, NativeHandle};
use crate::storage::sqlite::{MutationOutcome, SqliteStore};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const SEAL: &str = "seal-revision-v1";
const RELEASE: &str = "seal-release-v1";
const HISTORY_PREDICATE: &str = "operation IN ('seal-revision-v1','seal-release-v1')";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealCommit {
    pub identity: Digest,
    pub row_id: i64,
    pub manifest: Manifest,
    /// True when R03's operation receipt, not the submit response, established commit.
    pub reconciled: bool,
}

/// One application owner per native handle family. Native clones retain the
/// guard after this value drops; raw reopen requires recovering it from sidecar.
pub struct SealStore {
    store: SqliteStore,
    native: NativeHandle,
    sha: Sha256,
    guard: Arc<dyn CustodyGuard>,
}
impl SealStore {
    pub fn open(store: SqliteStore, native: NativeHandle) -> Result<Self> {
        let sha = Sha256::open()?;
        let marker = native.custody_path()?;
        let pair = codec::encode(&[
            "verdant-custody-v1".into(),
            canonical_path(store.db_path())?,
            canonical_path(native.dir())?,
        ]);
        let mut slot = native.custody_lock()?;
        if slot.is_installed() {
            return Err(SealError::Conflict(
                "application guard already attached to this native owner".into(),
            ));
        }
        History::read(&store, &sha)?;
        // Reconstruct custody, not activation. Availability is checked at seal
        // and before capture/activation, so an operator can still authenticate
        // an explicit release when a retained source has become unavailable.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
        {
            Ok(mut file) => {
                file.write_all(pair.as_bytes())?;
                file.sync_all()?;
                std::fs::File::open(
                    marker
                        .parent()
                        .ok_or(SealError::Invalid("custody parent"))?,
                )?
                .sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_marker(&marker, &pair)?
            }
            Err(e) => return Err(e.into()),
        }
        let guard: Arc<dyn CustodyGuard> = Arc::new(ApplicationGuard {
            store: store.try_clone()?,
            sha: sha.clone(),
            marker,
            pair,
        });
        slot.install(Arc::clone(&guard))?;
        drop(slot);
        Ok(Self {
            store,
            native,
            sha,
            guard,
        })
    }
    pub fn hash_tool(&self) -> &Sha256 {
        &self.sha
    }

    /// Stage all bytes and joins before dispatch. The caller retains `operation`
    /// and draft across uncertainty. No accepted/local state is advanced before a
    /// receipt proves commit. A content duplicate under another operation adds
    /// only an alias receipt, never another durable seal row.
    pub fn seal(
        &self,
        operation: &OperationId,
        draft: &Draft,
        registry: &mut BindingRegistry,
        gate: &AccessGate,
        credential: &Credential,
    ) -> Result<SealCommit> {
        let slot = self.native.custody_lock()?;
        self.require_guard(&slot)?;
        self.same_database(registry, gate)?;
        registry.replay_full()?;
        // Capture access history before authentication; the R06 writer guard
        // checks every consulted byte plus expiry in the SQLite transaction.
        let authority =
            registry.authority(gate, Some(credential), &draft.scope, BindingRole::Drive)?;
        let actor = authority.report.actor();
        let publisher = format!(
            "capability={};scope={};capgen={};issuer={}",
            binding::pct_encode(actor.capability()),
            binding::pct_encode(actor.ceiling().scope().as_str()),
            actor.cap_generation(),
            binding::pct_encode(actor.issuer())
        );
        let (manifest, references_guard) =
            Manifest::stage(draft, publisher, &self.store, &self.native, &self.sha)?;
        let identity = manifest.identity(&self.sha)?;
        if let Some(committed) = self.reconcile_inner(operation, &identity)? {
            return Ok(committed);
        }
        let history = History::read(&self.store, &self.sha)?;
        if let Some(existing) = history.seals.get(&identity) {
            if history.released.contains(&identity) {
                return Err(SealError::Released);
            }
            if existing.manifest != manifest {
                return Err(SealError::Conflict(
                    "digest collision: manifest bytes differ".into(),
                ));
            }
            // A new operation alias still needs an R03 receipt, but never a
            // second durable seal row. A TEMP row supplies the existing row ID
            // to the frozen guarded-batch response shape (last_insert_rowid).
            let body = format!("{}CREATE TEMP TABLE seal_alias(id INTEGER PRIMARY KEY); INSERT INTO seal_alias VALUES ({});", expiry_guard(authority.report.actor().policy().expires_at().map(|t| t.as_millis())), existing.row_id);
            let condition = format!(
                "({}) AND ({references_guard}) AND {}",
                authority.guard,
                history.guard()
            );
            let ticket = self
                .store
                .prepare_guarded_batch(&condition, &body, 0)?
                .with_operation(operation.clone());
            let (outcome, reconciled) = match self.store.submit(&ticket) {
                MutationOutcome::Unknown { .. } => (self.store.reconcile(&ticket), true),
                other => (other, false),
            };
            let row_id = committed_row(outcome)?;
            return Ok(SealCommit {
                reconciled,
                ..self.read_commit(row_id, &identity)?
            });
        }
        registry.require_revision(draft.revision)?;
        if history.live().count() >= MAX_LIVE_SEALS {
            return Err(SealError::Limit("live seal custody"));
        }
        let raw = codec::encode(&[
            "seal-row-v1".into(),
            identity.as_str().into(),
            manifest.canonical_bytes(),
        ]);
        let condition = format!(
            "({}) AND ({references_guard}) AND ({})",
            authority.guard, registry.guard
        );
        let body = self.row_body(
            &history,
            SEAL,
            identity.as_str(),
            &raw,
            authority
                .report
                .actor()
                .policy()
                .expires_at()
                .map(|t| t.as_millis()),
        )?;
        let condition = format!("({condition}) AND {}", history.guard());
        let ticket = self
            .store
            .prepare_guarded_batch(&condition, &body, Value::Text(raw).to_json().len())?
            .with_operation(operation.clone());
        #[cfg(test)]
        at_boundary();
        let first = self.store.submit(&ticket);
        let (outcome, reconciled) = match first {
            MutationOutcome::Unknown { .. } => (self.store.reconcile(&ticket), true),
            other => (other, false),
        };
        let row_id = committed_row(outcome)?;
        let result = self.read_commit(row_id, &identity)?;
        // Availability is checked again before acceptance. A committed-but-now
        // missing source is not reported as noncommit; operation recovery remains.
        result
            .manifest
            .verify(&self.store, &self.native, &self.sha)?;
        Ok(SealCommit {
            reconciled,
            ..result
        })
    }

    /// Read-only, operation-identity recovery. It is not permission to activate
    /// or to dispatch another operation. An absent receipt is known noncommit at
    /// the R03 writer barrier, never inferred from a timeout.
    pub fn reconcile(
        &self,
        operation: &OperationId,
        identity: &Digest,
    ) -> Result<Option<SealCommit>> {
        let slot = self.native.custody_lock()?;
        self.require_guard(&slot)?;
        self.reconcile_inner(operation, identity)
    }
    fn reconcile_inner(
        &self,
        operation: &OperationId,
        identity: &Digest,
    ) -> Result<Option<SealCommit>> {
        match self.store.reconcile_operation(operation) {
            MutationOutcome::NotCommitted { .. } => Ok(None),
            other => {
                let id = committed_row(other)?;
                let mut seal = self.read_commit(id, identity)?;
                seal.reconciled = true;
                Ok(Some(seal))
            }
        }
    }
    fn read_commit(&self, row_id: i64, identity: &Digest) -> Result<SealCommit> {
        let history = History::read(&self.store, &self.sha)?;
        let seal = history
            .seals
            .get(identity)
            .filter(|s| s.row_id == row_id)
            .ok_or_else(|| {
                SealError::Conflict("operation receipt does not identify these seal bytes".into())
            })?;
        Ok(seal.clone())
    }

    /// Availability + capture simulation only: no archive or live native graph
    /// activation. Rechecks every durable row and artifact immediately before
    /// returning the immutable manifest, with pruning excluded throughout.
    pub fn capture_simulation(&self, identity: &Digest) -> Result<Manifest> {
        let slot = self.native.custody_lock()?;
        self.require_guard(&slot)?;
        let history = History::read(&self.store, &self.sha)?;
        if history.released.contains(identity) {
            return Err(SealError::Released);
        }
        let seal = history
            .seals
            .get(identity)
            .ok_or_else(|| SealError::Missing(identity.as_str().into()))?;
        seal.manifest.verify(&self.store, &self.native, &self.sha)?;
        Ok(seal.manifest.clone())
    }
    pub fn check_before_activation(&self, identity: &Digest) -> Result<Manifest> {
        self.capture_simulation(identity)
    }

    /// Explicit end of finite custody, not seal mutation or deletion. Release is
    /// additive and authenticated with live publish authority; released identities
    /// cannot be reactivated/resealed. Choose a new context for a new publication.
    pub fn release(
        &self,
        operation: &OperationId,
        identity: &Digest,
        registry: &mut BindingRegistry,
        gate: &AccessGate,
        credential: &Credential,
    ) -> Result<()> {
        let slot = self.native.custody_lock()?;
        self.require_guard(&slot)?;
        self.same_database(registry, gate)?;
        let history = History::read(&self.store, &self.sha)?;
        let seal = history
            .seals
            .get(identity)
            .ok_or_else(|| SealError::Missing(identity.as_str().into()))?;
        let authority = registry.authority(
            gate,
            Some(credential),
            &seal.manifest.scope,
            BindingRole::Drive,
        )?;
        if history.released.contains(identity) {
            return Ok(());
        }
        let raw = codec::encode(&["seal-release-v1".into(), identity.as_str().into()]);
        let body = self.row_body(
            &history,
            RELEASE,
            identity.as_str(),
            &raw,
            authority
                .report
                .actor()
                .policy()
                .expires_at()
                .map(|t| t.as_millis()),
        )?;
        let condition = format!("({}) AND {}", authority.guard, history.guard());
        let ticket = self
            .store
            .prepare_guarded_batch(&condition, &body, raw.len())?
            .with_operation(operation.clone());
        let outcome = match self.store.submit(&ticket) {
            MutationOutcome::Unknown { .. } => self.store.reconcile(&ticket),
            other => other,
        };
        committed_row(outcome)?;
        Ok(())
    }

    fn require_guard(&self, slot: &crate::native::CustodyAccess<'_>) -> Result<()> {
        if !slot.matches(&self.guard) {
            return Err(SealError::Conflict(
                "application custody guard bypass refused".into(),
            ));
        }
        let pair = codec::encode(&[
            "verdant-custody-v1".into(),
            canonical_path(self.store.db_path())?,
            canonical_path(self.native.dir())?,
        ]);
        verify_marker(&self.native.custody_path()?, &pair)?;
        Ok(())
    }
    fn same_database(&self, registry: &BindingRegistry, gate: &AccessGate) -> Result<()> {
        let own = canonical_path(self.store.db_path())?;
        if own != canonical_path(registry.store().db_path())?
            || own != canonical_path(gate.db_path())?
        {
            return Err(SealError::Conflict(
                "seal, binding and authority require the same database".into(),
            ));
        }
        Ok(())
    }
    fn row_body(
        &self,
        history: &History,
        operation: &str,
        identity: &str,
        raw: &str,
        expiry: Option<i64>,
    ) -> Result<String> {
        if history.count >= MAX_HISTORY {
            return Err(SealError::Limit(
                "seal history; explicit operator lifecycle required",
            ));
        }
        let value = Value::Text(raw.into()).to_json();
        if value.len() > self.store.bounds().max_value_bytes {
            return Err(SealError::Limit("seal row bytes"));
        }
        let mut sql = expiry_guard(expiry);
        // Outbox identity is the seal, not a fabricated equipment observation.
        // Zero timestamps are inert placeholders, never a field-time claim.
        sql.push_str(&format!("INSERT INTO outbox(operation,entity,sensor,value_json,unit,source_ms,receipt_ms,ingestion_ms,generation,seq,status,claimed_by,created_nanos) VALUES ({},{},'seal-manifest',{},'count','0','0','0','gen-1','{}','queued',NULL,'0');", binding::sql_quote(operation), binding::sql_quote(&format!("seal-{identity}")), binding::sql_quote(&value), history.count + 1));
        Ok(sql)
    }
}

fn expiry_guard(expiry: Option<i64>) -> String {
    match expiry {
        Some(expiry) => format!("CREATE TEMP TABLE seal_live(ok INTEGER NOT NULL CHECK(ok=1)); INSERT INTO seal_live VALUES(CASE WHEN CAST(unixepoch('subsec')*1000 AS INTEGER)<{expiry} THEN 1 ELSE 0 END); "),
        None => String::new(),
    }
}

struct History {
    count: usize,
    seals: BTreeMap<Digest, SealCommit>,
    released: BTreeSet<Digest>,
}
impl History {
    fn read(store: &SqliteStore, sha: &Sha256) -> Result<Self> {
        let rows = store.exec_script(&format!("SELECT id, operation, quote(value_json), seq FROM outbox WHERE {HISTORY_PREDICATE} ORDER BY id LIMIT {};", MAX_HISTORY + 1))?;
        if rows.len() > MAX_HISTORY {
            return Err(SealError::Limit("seal history"));
        }
        let mut result = Self {
            count: rows.len(),
            seals: BTreeMap::new(),
            released: BTreeSet::new(),
        };
        for (index, row) in rows.iter().enumerate() {
            if row.len() != 4 || codec::number::<usize>(&row[3])? != index + 1 {
                return Err(SealError::Invalid("seal history sequence"));
            }
            let id: i64 = codec::number(&row[0])?;
            let json =
                binding::unquote_column(&row[2])?.ok_or(SealError::Invalid("NULL seal row"))?;
            let Value::Text(raw) =
                Value::from_json(&json).map_err(|_| SealError::Invalid("seal JSON"))?
            else {
                return Err(SealError::Invalid("seal row text"));
            };
            let f = codec::decode(&raw, MAX_MANIFEST_BYTES + 256, 3)?;
            match row[1].as_str() {
                SEAL if f.len() == 3 && f[0] == "seal-row-v1" => {
                    let identity = Digest::parse(&f[1])?;
                    let manifest = Manifest::decode(&f[2])?;
                    if manifest.identity(sha)? != identity {
                        return Err(SealError::Changed("seal manifest digest".into()));
                    }
                    if result
                        .seals
                        .insert(
                            identity.clone(),
                            SealCommit {
                                identity,
                                row_id: id,
                                manifest,
                                reconciled: false,
                            },
                        )
                        .is_some()
                    {
                        return Err(SealError::Invalid("duplicate seal identity"));
                    }
                }
                RELEASE if f.len() == 2 && f[0] == "seal-release-v1" => {
                    let identity = Digest::parse(&f[1])?;
                    if !result.seals.contains_key(&identity) || !result.released.insert(identity) {
                        return Err(SealError::Invalid("release identity"));
                    }
                }
                _ => return Err(SealError::Invalid("seal history kind")),
            }
        }
        if result.live().count() > MAX_LIVE_SEALS {
            return Err(SealError::Limit("live custody"));
        }
        Ok(result)
    }
    fn live(&self) -> impl Iterator<Item = &SealCommit> {
        self.seals
            .iter()
            .filter(|(id, _)| !self.released.contains(*id))
            .map(|(_, seal)| seal)
    }
    fn guard(&self) -> String {
        format!(
            "(SELECT COUNT(*) FROM outbox WHERE {HISTORY_PREDICATE})={}",
            self.count
        )
    }
}
struct ApplicationGuard {
    store: SqliteStore,
    sha: Sha256,
    marker: PathBuf,
    pair: String,
}
impl CustodyGuard for ApplicationGuard {
    fn check_prune(&self) -> std::result::Result<(), CustodyPlan> {
        let state = verify_marker(&self.marker, &self.pair)
            .and_then(|()| History::read(&self.store, &self.sha));
        let history = state.map_err(|e| CustodyPlan {
            live_seals: Vec::new(),
            generations: Vec::new(),
            checkpoint: None,
            detail: format!("application custody unavailable: {e}"),
        })?;
        let live = history.live().collect::<Vec<_>>();
        if live.is_empty() {
            return Ok(());
        }
        let generations = live
            .iter()
            .flat_map(|s| s.manifest.native.iter().map(|n| n.generation()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Err(CustodyPlan { live_seals: live.iter().map(|s| s.identity.as_str().into()).collect(), generations, checkpoint: None, detail: "live application seals retain native bytes; release explicitly before any native prune (conservative whole-pass refusal)".into() })
    }
}
fn verify_marker(path: &Path, expected: &str) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > 8192 {
        return Err(SealError::Invalid("custody sidecar"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(8193)
        .read_to_end(&mut bytes)?;
    if bytes != expected.as_bytes() {
        return Err(SealError::Conflict(
            "custody sidecar belongs to another application store or is incomplete".into(),
        ));
    }
    Ok(())
}
fn canonical_path(path: &Path) -> Result<String> {
    Ok(std::fs::canonicalize(path)?
        .to_str()
        .ok_or(SealError::Invalid("store path UTF-8"))?
        .into())
}
fn committed_row(outcome: MutationOutcome) -> Result<i64> {
    match outcome {
        MutationOutcome::Committed { rows, .. } => rows
            .first()
            .and_then(|r| r.first())
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|id| *id > 0)
            .ok_or(SealError::Invalid("receipt row id")),
        MutationOutcome::NotCommitted { error, .. } => Err(error.into()),
        MutationOutcome::Conflict { detail, .. } => Err(SealError::Conflict(detail)),
        MutationOutcome::Unknown { operation, detail } => {
            Err(SealError::Unknown { operation, detail })
        }
    }
}

#[cfg(test)]
thread_local! { static BOUNDARY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None); }
#[cfg(test)]
pub(crate) fn on_boundary(hook: impl FnOnce() + 'static) {
    BOUNDARY.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}
#[cfg(test)]
fn at_boundary() {
    if let Some(hook) = BOUNDARY.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}
