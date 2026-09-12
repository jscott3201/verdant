//! Per-operation durable join. Pure proposals carry no permission; every new
//! effect re-resolves registry truth and authenticates at the owning boundary.
//! Receipts, row insertion, sequence and revision advance in one transaction.
use super::authority::{actor_fields, Authority};
use super::*;
use crate::access::{AccessGate, Credential};
use crate::domain::ids::{BindingRevision, InstalledId, OperationId};
use crate::storage::sqlite::{MutationOutcome, PreparedMutation};
use crate::storage::StorageError;
use std::sync::atomic::{AtomicU64, Ordering};

/// Immutable intent. Persist the operation ID and these inputs before dispatch.
/// A retry is the same operation, not another call to the new-work convenience API.
#[derive(Debug, Clone)]
pub struct PendingProposal {
    operation: OperationId,
    revision: BindingRevision,
    binding: ProposedBinding,
}
impl PendingProposal {
    pub fn new(operation: OperationId, revision: BindingRevision, binding: ProposedBinding) -> Self {
        Self { operation, revision, binding }
    }
    pub fn operation(&self) -> &OperationId { &self.operation }
    pub fn input_revision(&self) -> BindingRevision { self.revision }
    pub fn binding(&self) -> &ProposedBinding { &self.binding }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalCommit {
    pub operation: OperationId,
    pub row_id: i64,
    pub revision: BindingRevision,
    pub binding: ProposedBinding,
}

impl BindingRegistry {
    pub(crate) fn require_revision(&self, revision: BindingRevision) -> Result<(), BindingError> {
        if self.revision != revision {
            return Err(conflict(format!("input revision {} differs from current {}; re-resolve inputs", revision.as_u32(), self.revision.as_u32())));
        }
        Ok(())
    }

    /// Submit a pure proposal or import at an explicit revision. A pending
    /// proposal loses to any intervening evolution; it is never silently rebased.
    pub fn submit_proposal(
        &mut self, gate: &AccessGate, credential: Option<&Credential>, pending: &PendingProposal,
    ) -> Result<ProposalCommit, BindingError> {
        if let Some(commit) = self.reconcile_proposal(pending)? { return Ok(commit); }
        self.require_revision(pending.revision)?;
        self.resolve(&pending.binding)?;
        let authority = self.authority(gate, credential, pending.binding.point_scope(), pending.binding.requested())?;
        let descriptor = format!("{};operation={};revision={};{}", proposal_descriptor(&pending.binding), pct_encode(pending.operation.as_str()), pending.revision.as_u32(), actor_fields(authority.report.actor()));
        let ticket = self.prepare_row(&pending.operation, OP_PROPOSE_TEXT, pending.binding.point_equipment(), &descriptor, Some(&authority))?;
        at_boundary();
        let row_id = submitted(self.store.submit(&ticket))?;
        // No local evolution before commit. A refresh failure is not a noncommit:
        // the caller still owns the operation identity and can reconcile it.
        self.replay().map_err(|e| BindingError::MutationUnknown { operation: pending.operation.clone(), detail: format!("committed; refresh failed: {e}") })?;
        Ok(ProposalCommit { operation: pending.operation.clone(), row_id, revision: BindingRevision::new(pending.revision.as_u32() + 1), binding: pending.binding.clone() })
    }

    /// Receipt-only recovery. This never dispatches work and never authorizes a
    /// dependent mutation. Later operations must resolve live truth again.
    pub fn reconcile_proposal(&mut self, pending: &PendingProposal) -> Result<Option<ProposalCommit>, BindingError> {
        self.replay()?;
        let outcome = self.store.reconcile_operation(&pending.operation);
        let row_id = match outcome {
            MutationOutcome::NotCommitted { .. } => return Ok(None),
            other => submitted(other)?,
        };
        let map = self.committed_descriptor(row_id, &pending.operation, OP_PROPOSE_TEXT)?;
        let binding = super::history::decode_propose(&map)?;
        let revision = stored_revision(&map)?;
        if binding != pending.binding || revision != pending.revision {
            return Err(conflict("operation identity reused with different proposal inputs"));
        }
        let next = revision.as_u32().checked_add(1).ok_or_else(|| conflict("revision overflow"))?;
        Ok(Some(ProposalCommit { operation: pending.operation.clone(), row_id, revision: BindingRevision::new(next), binding }))
    }

    /// New-work convenience API. For retryable emission use the explicit ID API.
    pub fn emit_finding(&mut self, gate: &AccessGate, binding: &ProposedBinding, credential: &Credential) -> Result<Finding, BindingError> {
        self.replay()?;
        self.emit_finding_operation(&operation_id()?, self.revision, gate, binding, credential)
    }

    /// The citable pair remains (id, generation), with generation equal to the
    /// binding revision. Authentication is joined here, not at proposal creation.
    pub fn emit_finding_operation(
        &mut self, operation: &OperationId, revision: BindingRevision,
        gate: &AccessGate, binding: &ProposedBinding, credential: &Credential,
    ) -> Result<Finding, BindingError> {
        self.replay()?;
        match self.store.reconcile_operation(operation) {
            MutationOutcome::NotCommitted { .. } => {}
            other => {
                let id = submitted(other)?;
                let map = self.committed_descriptor(id, operation, OP_FINDING_TEXT)?;
                if stored_revision(&map)? != revision || require_field(&map, "binding")? != binding.canonical_bytes() {
                    return Err(conflict("operation identity reused with different finding inputs"));
                }
                let fid = require_field(&map, "fid")?;
                return self.findings.iter().find(|finding| finding.id().as_str() == fid && finding.generation() == revision.as_u32()).cloned().ok_or_else(|| conflict("receipt has no replayed finding"));
            }
        }
        self.require_revision(revision)?;
        self.resolve(binding)?;
        if !self.bindings.contains(binding) { return Err(conflict("finding requires a durable proposal at current truth")); }
        let authority = self.authority(gate, Some(credential), binding.point_scope(), binding.requested())?;
        let actor = actor_fields(authority.report.actor());
        let finding = Finding::for_binding(binding, revision, &actor);
        let descriptor = format!(
            "v=2;kind=finding;operation={};fid={};generation={};revision={};digest={};summary={};{};equipment={};property={};binding={}",
            pct_encode(operation.as_str()), pct_encode(finding.id().as_str()), finding.generation(), revision.as_u32(), pct_encode(finding.digest()), pct_encode(finding.summary()), actor, pct_encode(binding.point_equipment().as_str()), pct_encode(binding.point_property().as_str()), pct_encode(&binding.canonical_bytes()));
        let ticket = self.prepare_row(operation, OP_FINDING_TEXT, binding.point_equipment(), &descriptor, Some(&authority))?;
        at_boundary();
        submitted(self.store.submit(&ticket))?;
        self.replay().map_err(|e| BindingError::MutationUnknown { operation: operation.clone(), detail: format!("committed; refresh failed: {e}") })?;
        Ok(finding)
    }

    fn resolve(&self, binding: &ProposedBinding) -> Result<(), BindingError> {
        let equipment = binding.point_equipment().as_str();
        if self.retired.contains(equipment) { return Err(conflict("equipment is retired; cached binding cannot be used")); }
        if self.reassessment.contains(equipment) {
            return Err(BindingError::NeedsReassessment { id: equipment.into(), address: binding.endpoint().as_str().into(), detail: "replacement requires fresh qualification".into() });
        }
        let key = format!("{equipment}:{}", binding.point_property().as_str());
        let point = self.points.get(&key).ok_or_else(|| BindingError::InvalidRecord { detail: format!("unknown point '{key}'") })?;
        if binding.point_scope() != point.scope() { return Err(conflict("point scope changed; re-resolve proposal")); }
        if binding.status() == BindingStatus::ObservedQualified { return Err(conflict("static proposal cannot claim observed qualification")); }
        propose(binding.endpoint().clone(), binding.endpoint_class(), binding.endpoint_scope().clone(), binding.point_equipment().clone(), binding.point_property().clone(), point.scope().clone(), binding.source().clone(), point.unit(), point.endpoint_class(), binding.unit().clone(), binding.mode().cloned(), binding.requested(), binding.effective(), binding.feedback())?;
        Ok(())
    }

    pub(crate) fn write_record(&mut self, kind: &str, entity: &InstalledId, descriptor: &str) -> Result<(), BindingError> {
        let operation = operation_id()?;
        let descriptor = format!("{descriptor};operation={};revision={}", operation.as_str(), self.revision.as_u32());
        let pending = self.prepare_row(&operation, kind, entity, &descriptor, None)?;
        at_boundary();
        submitted(self.store.submit(&pending))?;
        self.sequence += 1; // acknowledged durable sequence, never a reservation
        Ok(())
    }

    fn prepare_row(&self, operation: &OperationId, kind: &str, entity: &InstalledId, descriptor: &str, authority: Option<&Authority>) -> Result<PreparedMutation, BindingError> {
        let seq = self.sequence.checked_add(1).ok_or_else(|| conflict("sequence overflow"))?;
        if kind != OP_FINDING_TEXT && self.revision.as_u32() == u32::MAX { return Err(conflict("revision overflow")); }
        let value = crate::domain::values::Value::Text(descriptor.into()).to_json();
        let mut guard = self.guard.clone();
        let mut body = String::new();
        if let Some(authority) = authority {
            guard.push_str(&format!(" AND ({})", authority.guard));
            if let Some(expiry) = authority.report.actor().policy().expires_at() {
                body.push_str(&format!("CREATE TEMP TABLE binding_live(ok INTEGER NOT NULL CONSTRAINT binding_guard_live CHECK(ok=1)); INSERT INTO binding_live VALUES(CASE WHEN CAST(unixepoch('subsec')*1000 AS INTEGER)<{} THEN 1 ELSE 0 END); ", expiry.as_millis()));
            }
        }
        let times = synthetic_times();
        // Mark first so last_insert_rowid is the outbox ID returned in receipt.
        // Build nanoseconds from integer seconds/milliseconds at SQL execution;
        // casting a floating subsecond epoch directly to TEXT emits exponents.
        body.push_str(&format!(
            "INSERT INTO derived_marks(entity, dirty, checked_generation) VALUES ({entity},1,0) ON CONFLICT(entity) DO UPDATE SET dirty=1; INSERT INTO outbox(operation,entity,sensor,value_json,unit,source_ms,receipt_ms,ingestion_ms,generation,seq,status,claimed_by,created_nanos) VALUES ({kind},{entity},{sensor},{value},{unit},'{source}','{receipt}','{ingestion}','gen-1','{seq}','queued',NULL,CAST(unixepoch()*1000000000 + CAST(substr(strftime('%f','now'),4,3) AS INTEGER)*1000000 AS TEXT));",
            entity=sql_quote(entity.as_str()), kind=sql_quote(kind), sensor=sql_quote(BINDING_SENSOR_TEXT), value=sql_quote(&value), unit=sql_quote(BINDING_UNIT_TEXT), source=times.source().as_millis(), receipt=times.receipt().as_millis(), ingestion=times.ingestion().as_millis()));
        self.store.prepare_guarded_batch(&guard, &body, value.len()).map(|ticket| ticket.with_operation(operation.clone())).map_err(BindingError::Store)
    }

    fn committed_descriptor(&self, row_id: i64, operation: &OperationId, kind: &str) -> Result<BTreeMap<String, String>, BindingError> {
        let rows = self.store.exec_script(&format!("SELECT quote(value_json) FROM outbox WHERE id={row_id} AND operation={};", sql_quote(kind))).map_err(BindingError::Store)?;
        let raw = match rows.as_slice() {
            [row] if row.len() == 1 => unquote_column(&row[0])?.ok_or_else(|| conflict("NULL committed descriptor"))?,
            _ => return Err(conflict("operation receipt does not identify a binding row")),
        };
        let crate::domain::values::Value::Text(descriptor) = crate::domain::values::Value::from_json(&raw).map_err(|e| conflict(e.to_string()))? else { return Err(conflict("committed descriptor is not text")); };
        let map = split_descriptor(&descriptor)?;
        if require_field(&map, "v")? != "2" || require_field(&map, "operation")? != operation.as_str() { return Err(conflict("operation receipt/descriptor mismatch")); }
        Ok(map)
    }
}

fn submitted(outcome: MutationOutcome) -> Result<i64, BindingError> {
    match outcome {
        MutationOutcome::Committed { rows, .. } => rows.first().and_then(|r| r.first()).and_then(|s| s.parse::<i64>().ok()).filter(|id| *id > 0).ok_or_else(|| conflict("receipt row identity invalid")),
        MutationOutcome::NotCommitted { error: StorageError::SqliteFailure { detail }, .. } if detail.contains("CHECK constraint failed: access_guard_unchanged") => Err(conflict("registry or authority changed at mutation boundary")),
        MutationOutcome::NotCommitted { error: StorageError::SqliteFailure { detail }, .. } if detail.contains("CHECK constraint failed: binding_guard_live") => Err(BindingError::capability_denied("credential expired at mutation boundary".into(), "expired-credential")),
        MutationOutcome::NotCommitted { error, .. } => Err(BindingError::Store(error)),
        MutationOutcome::Conflict { detail, .. } => Err(conflict(detail)),
        MutationOutcome::Unknown { operation, detail } => Err(BindingError::MutationUnknown { operation, detail }),
    }
}
fn conflict(detail: impl Into<String>) -> BindingError { BindingError::Conflict { detail: detail.into() } }
pub(crate) fn stored_revision(map: &BTreeMap<String, String>) -> Result<BindingRevision, BindingError> {
    require_field(map, "revision")?.parse::<u32>().map(BindingRevision::new).map_err(|_| BindingError::InvalidRecord { detail: "stored revision unreadable".into() })
}
pub(crate) fn operation_id() -> Result<OperationId, BindingError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| conflict(e.to_string()))?.as_nanos();
    OperationId::parse(&format!("binding-{}-{time}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst))).map_err(|e| conflict(e.to_string()))
}
fn proposal_descriptor(binding: &ProposedBinding) -> String {
    format!("v=2;kind=propose;endpoint={};eclass={};escope={};equipment={};property={};pscope={};source={};unit={};mode={};requested={};effective={};feedback={};status={}",
        pct_encode(binding.endpoint().as_str()), binding.endpoint_class().as_str(), pct_encode(binding.endpoint_scope().as_str()), pct_encode(binding.point_equipment().as_str()), pct_encode(binding.point_property().as_str()), pct_encode(binding.point_scope().as_str()), pct_encode(binding.source().as_str()), pct_encode(binding.unit().as_str()), binding.mode().map(|m| m.as_str()).unwrap_or("-"), binding.requested().as_str(), binding.effective().as_str(), binding.feedback().as_str(), binding.status().as_str())
}

// Deterministic boundary injection, absent from product builds. One operation,
// current thread, no runner, global environment, or shared fixture mutation.
#[cfg(test)]
thread_local! { static BOUNDARY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None); }
#[cfg(test)]
pub(crate) fn on_boundary(hook: impl FnOnce() + 'static) { BOUNDARY.with(|slot| *slot.borrow_mut() = Some(Box::new(hook))); }
fn at_boundary() {
    #[cfg(test)]
    if let Some(hook) = BOUNDARY.with(|slot| slot.borrow_mut().take()) { hook(); }
}
