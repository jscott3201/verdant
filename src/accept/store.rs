use super::{
    codec, effective::check_environment, AcceptedRevision, Error, Result, Sealed, Stage,
    MAX_ACCEPTED,
};
use crate::access::{AccessGate, Credential};
use crate::binding::{self, BindingRegistry, BindingRole};
use crate::domain::{ids::OperationId, scope::TrustedScope, values::Value};
use crate::seal::{Digest, SealStore};
use crate::storage::sqlite::{MutationOutcome, PreparedMutation, SqliteStore};

const EVENT: &str = "accept-revision-v1";

/// Persist this identity before dispatch. It carries no authority and can be
/// reconstructed for read-only recovery after losing the caller/process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceRequest {
    operation: OperationId,
    expected: AcceptedRevision,
    scope: TrustedScope,
    staged_operation: OperationId,
    seal: Digest,
}
impl AcceptanceRequest {
    pub fn new(
        operation: OperationId,
        expected: AcceptedRevision,
        scope: TrustedScope,
        staged_operation: OperationId,
        seal: Digest,
    ) -> Self {
        Self {
            operation,
            expected,
            scope,
            staged_operation,
            seal,
        }
    }
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }
    pub fn expected(&self) -> AcceptedRevision {
        self.expected
    }
    pub fn seal(&self) -> &Digest {
        &self.seal
    }
}

#[derive(Debug, Clone)]
pub struct PendingAcceptance {
    request: AcceptanceRequest,
    ticket: PreparedMutation,
    sealed: Sealed,
}
impl PendingAcceptance {
    pub fn request(&self) -> &AcceptanceRequest {
        &self.request
    }
}

/// This durable event IS the accepted revision. There is no separate pointer
/// to advance or roll back and hence no event/state partial-commit window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub row_id: i64,
    pub revision: AcceptedRevision,
    pub request: AcceptanceRequest,
    pub actor_reference: String,
    pub reconciled: bool,
}
impl Accepted {
    pub fn stage(&self) -> Stage {
        Stage::Accepted
    }
}

pub struct AcceptanceStore {
    pub(super) store: SqliteStore,
}
impl AcceptanceStore {
    /// Store admission remains storage-owned; this wrapper creates no native
    /// owner, directory, worker, lock or schema. History is checked when read.
    pub fn new(store: SqliteStore) -> Self {
        Self { store }
    }

    pub fn current(&self, scope: &TrustedScope) -> Result<Option<Accepted>> {
        Ok(self.history(scope)?.pop())
    }

    /// Each publication remains inspectable even after a newer acceptance.
    /// Accepted does NOT mean available/activated; missing content cannot erase
    /// the event. Fresh acceptance separately checks seal availability.
    pub fn status(&self, sealed: &Sealed) -> Result<Stage> {
        if self.history(sealed.config().scope())?.iter().any(|a| {
            a.request.seal == sealed.identity
                && a.request.staged_operation == sealed.staged.operation
        }) {
            Ok(Stage::Accepted)
        } else {
            Ok(Stage::Sealed)
        }
    }

    /// No fake activation or qualification. Slice B must supply its own checked
    /// coordination contract before these transitions can be implemented.
    pub fn transition(&self, _accepted: &Accepted, requested: Stage) -> Result<()> {
        match requested {
            Stage::Activated | Stage::Qualified => Err(Error::NotYet { requested }),
            Stage::Staged | Stage::Sealed | Stage::Accepted => {
                Err(Error::Invalid("use stage/sealed/prepare APIs"))
            }
        }
    }

    /// All long reads happen before the SQLite writer transaction. The ticket
    /// contains exact authority/binding/publication guards, not a cached grant.
    /// Two prepared contenders may share expected; exactly one conditional
    /// insert wins. Zero inserted rows trips a typed conflict BEFORE a receipt.
    pub fn prepare(
        &self,
        operation: OperationId,
        expected: AcceptedRevision,
        sealed: &Sealed,
        seals: &SealStore,
        registry: &mut BindingRegistry,
        gate: &AccessGate,
        credential: &Credential,
    ) -> Result<PendingAcceptance> {
        check_environment()?;
        expected.next()?;
        if std::fs::canonicalize(self.store.db_path())?
            != std::fs::canonicalize(registry.store().db_path())?
        {
            return Err(Error::Conflict(
                "acceptance and binding stores differ".into(),
            ));
        }
        registry.replay_full()?;
        registry.require_revision(sealed.config().binding_revision())?;
        if gate.bootstrap_reason()? != sealed.config().bootstrap_reason() {
            return Err(Error::Conflict(
                "bootstrap source does not match publication".into(),
            ));
        }
        // Replay the accepted chain before deriving any mutation. Do not use a
        // truncated window or infer an initial revision from failed reads.
        self.history(sealed.config().scope())?;
        sealed.verify(&self.store, seals)?;
        let authority = registry.authority(
            gate,
            Some(credential),
            sealed.config().scope(),
            BindingRole::Drive,
        )?;
        let actor = authority.report.actor();
        let actor_reference = format!(
            "capability={};scope={};capgen={};issuer={}",
            binding::pct_encode(actor.capability()),
            binding::pct_encode(actor.ceiling().scope().as_str()),
            actor.cap_generation(),
            binding::pct_encode(actor.issuer())
        );
        let request = AcceptanceRequest::new(
            operation,
            expected,
            sealed.config().scope().clone(),
            sealed.staged.operation.clone(),
            sealed.identity.clone(),
        );
        let raw = event_bytes(&request, &actor_reference)?;
        let json = Value::Text(raw).to_json();
        let condition = format!(
            "({}) AND ({}) AND ({})",
            authority.guard,
            registry.guard,
            sealed.guard()
        );
        let mut body = String::new();
        if let Some(expiry) = actor.policy().expires_at() {
            body.push_str(&format!("INSERT INTO access_guard VALUES(CASE WHEN CAST(unixepoch('subsec')*1000 AS INTEGER)<{} THEN 1 ELSE 0 END);", expiry.as_millis()));
        }
        // TEMP-only result/alias tables preserve last_insert_rowid for the
        // frozen storage response shape. The changes() check observes the
        // CONDITIONAL EVENT INSERT, not a later housekeeping statement.
        body.push_str("CREATE TEMP TABLE accept_result(id INTEGER);");
        let cas = format!(
            " WHERE (SELECT COUNT(*) FROM outbox WHERE {})={}",
            predicate(&request.scope),
            expected.get()
        );
        body.push_str(&insert_row(
            EVENT,
            &entity(&request.scope),
            "accept-event",
            &json,
            expected.next()?.get() as u64,
            &cas,
        ));
        body.push_str("INSERT INTO accept_result SELECT last_insert_rowid() WHERE changes()=1; CREATE TEMP TABLE accept_changed(ok INTEGER NOT NULL CONSTRAINT accept_expected_changed CHECK(ok=1)); INSERT INTO accept_changed SELECT CASE WHEN (SELECT COUNT(*) FROM accept_result)=1 THEN 1 ELSE 0 END; CREATE TEMP TABLE accept_alias(id INTEGER PRIMARY KEY); INSERT INTO accept_alias SELECT id FROM accept_result;");
        let ticket = self
            .store
            .prepare_guarded_batch(&condition, &body, json.len())?
            .with_operation(request.operation.clone());
        Ok(PendingAcceptance {
            request,
            ticket,
            sealed: sealed.clone(),
        })
    }

    pub fn submit(&self, pending: &PendingAcceptance, seals: &SealStore) -> Result<Accepted> {
        check_environment()?;
        // Only read/reconcile an existing receipt. Never rebuild, retry with a
        // new identity, or roll back after a lost response or missing artifact.
        match self.store.reconcile(&pending.ticket) {
            MutationOutcome::NotCommitted { .. } => {}
            outcome => {
                let row_id = committed_row(outcome)?;
                return self.read_commit(&pending.request, row_id, true);
            }
        }
        pending.sealed.verify(&self.store, seals)?;
        #[cfg(test)]
        at_boundary();
        let (outcome, reconciled) = match self.store.submit(&pending.ticket) {
            MutationOutcome::Unknown { .. } => (self.store.reconcile(&pending.ticket), true),
            other => (other, false),
        };
        let row_id = committed_row(outcome)?;
        self.read_commit(&pending.request, row_id, reconciled)
            .map_err(|error| match error {
                Error::Conflict(_) => error,
                other => Error::Unknown {
                    operation: pending.request.operation.clone(),
                    detail: format!("committed event; read failed: {other}"),
                },
            })
    }

    /// Read-only operation recovery, including after caller cancellation. An
    /// absent receipt is only absence at this writer barrier; join dispatchers.
    pub fn reconcile(&self, request: &AcceptanceRequest) -> Result<Option<Accepted>> {
        match self.store.reconcile_operation(&request.operation) {
            MutationOutcome::NotCommitted { .. } => Ok(None),
            outcome => {
                let row_id = committed_row(outcome)?;
                Ok(Some(self.read_commit(request, row_id, true)?))
            }
        }
    }

    fn read_commit(
        &self,
        request: &AcceptanceRequest,
        row_id: i64,
        reconciled: bool,
    ) -> Result<Accepted> {
        let mut found = self
            .history(&request.scope)?
            .into_iter()
            .find(|a| a.row_id == row_id)
            .ok_or_else(|| Error::Conflict("receipt does not identify an accepted event".into()))?;
        if found.request != *request {
            return Err(Error::Conflict(
                "operation identity reused with different acceptance".into(),
            ));
        }
        found.reconciled = reconciled;
        Ok(found)
    }

    fn history(&self, scope: &TrustedScope) -> Result<Vec<Accepted>> {
        let rows = self.store.exec_script(&format!(
            "SELECT id,quote(value_json),seq,sensor FROM outbox WHERE {} ORDER BY id LIMIT {};",
            predicate(scope),
            MAX_ACCEPTED + 1
        ))?;
        if rows.len() > MAX_ACCEPTED as usize {
            return Err(Error::Limit("accepted history"));
        }
        let mut history = Vec::new();
        let mut operations = std::collections::BTreeSet::new();
        for (index, row) in rows.iter().enumerate() {
            if row.len() != 4 || row[2] != (index + 1).to_string() || row[3] != "accept-event" {
                return Err(Error::Invalid("accepted sequence/columns"));
            }
            let row_id = codec::number::<i64>(&row[0])?;
            let json =
                binding::unquote_column(&row[1])?.ok_or(Error::Invalid("NULL accepted event"))?;
            let raw = codec::text_json(&json)?;
            let f = codec::decode(&raw, 8192, 9)?;
            if f.len() != 9
                || f[0] != "verdant-accepted-v1"
                || f[4] != scope.as_str()
                || f[8] != "accepted"
                || f[2] != index.to_string()
                || f[3] != row[2]
                || row_id <= 0
                || !operations.insert(f[1].clone())
            {
                return Err(Error::Invalid("accepted event chain"));
            }
            let operation =
                OperationId::parse(&f[1]).map_err(|_| Error::Invalid("event operation"))?;
            let staged_operation =
                OperationId::parse(&f[5]).map_err(|_| Error::Invalid("event stage"))?;
            let request = AcceptanceRequest::new(
                operation,
                AcceptedRevision::new(index as u32)?,
                scope.clone(),
                staged_operation,
                Digest::parse(&f[6])?,
            );
            if event_bytes(&request, &f[7])? != raw {
                return Err(Error::Invalid("noncanonical accepted event"));
            }
            history.push(Accepted {
                row_id,
                revision: request.expected.next()?,
                request,
                actor_reference: f[7].clone(),
                reconciled: false,
            });
        }
        Ok(history)
    }
}

fn event_bytes(request: &AcceptanceRequest, actor: &str) -> Result<String> {
    Ok(codec::encode(&[
        "verdant-accepted-v1".into(),
        request.operation.as_str().into(),
        request.expected.get().to_string(),
        request.expected.next()?.get().to_string(),
        request.scope.as_str().into(),
        request.staged_operation.as_str().into(),
        request.seal.as_str().into(),
        actor.into(),
        "accepted".into(),
    ]))
}
fn entity(scope: &TrustedScope) -> String {
    format!("accept-{}", scope.as_str())
}
fn predicate(scope: &TrustedScope) -> String {
    format!(
        "operation='{EVENT}' AND entity={}",
        binding::sql_quote(&entity(scope))
    )
}
pub(super) fn insert_row(
    operation: &str,
    entity: &str,
    sensor: &str,
    json: &str,
    seq: u64,
    condition: &str,
) -> String {
    format!("INSERT INTO outbox(operation,entity,sensor,value_json,unit,source_ms,receipt_ms,ingestion_ms,generation,seq,status,claimed_by,created_nanos) SELECT {},{},{},{},'count','0','0','0','gen-1','{seq}','queued',NULL,'0'{condition};",
        binding::sql_quote(operation), binding::sql_quote(entity), binding::sql_quote(sensor), binding::sql_quote(json))
}
pub(super) fn committed_row(outcome: MutationOutcome) -> Result<i64> {
    match outcome {
        MutationOutcome::Committed { rows, .. } => {
            if rows.get(1).is_some_and(|r| r == &vec!["0".to_string()]) {
                return Err(Error::Conflict("zero affected rows".into()));
            }
            if rows.len() != 2 || rows[1] != vec!["1".to_string()] {
                return Err(Error::Invalid("accept receipt shape"));
            }
            rows[0]
                .first()
                .and_then(|s| s.parse().ok())
                .filter(|n| *n > 0)
                .ok_or(Error::Invalid("accept receipt row"))
        }
        MutationOutcome::NotCommitted {
            error: crate::storage::StorageError::SqliteFailure { detail },
            ..
        } if detail.contains("CHECK constraint failed: accept_expected_changed") => Err(
            Error::Conflict("zero affected rows: expected accepted revision lost".into()),
        ),
        MutationOutcome::NotCommitted {
            error: crate::storage::StorageError::SqliteFailure { detail },
            ..
        } if detail.contains("CHECK constraint failed: access_guard_unchanged") => Err(
            Error::Conflict("authority, binding or publication changed".into()),
        ),
        MutationOutcome::NotCommitted { error, .. } => Err(error.into()),
        MutationOutcome::Conflict { detail, .. } => Err(Error::Conflict(detail)),
        MutationOutcome::Unknown { operation, detail } => Err(Error::Unknown { operation, detail }),
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
