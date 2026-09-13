//! The last checked event is the durable active pointer: one event + receipt,
//! never a pointer/event split commit. Generations count activations, independently
//! of accepted revisions (which may be skipped). Both are bounded by MAX_ACCEPTED.
//!
//! Lock order: read/reconcile -> verify exact seal under seal's fail-fast custody
//! -> release custody -> SQLite CAS. No native I/O or user callback in the writer
//! transaction. Seal release racing verification is checked again by the SQL
//! publication guard. Guarded custody prevents pruning unreleased content; raw
//! filesystem/DB tampering is outside that model. No native mutation is dispatched.
use super::{
    codec, effective::check_environment, store, AcceptanceRequest, AcceptanceStore,
    Accepted, AcceptedRevision, Error, Result, Sealed, Stage, MAX_ACCEPTED,
};
use crate::binding;
use crate::domain::{ids::OperationId, scope::TrustedScope, values::Value};
use crate::seal::{Digest, SealStore};
use crate::storage::sqlite::{MutationOutcome, PreparedMutation};

const EVENT: &str = "accept-active-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveGeneration(u32);
impl ActiveGeneration {
    pub const INITIAL: Self = Self(0);
    pub fn new(value: u32) -> Result<Self> {
        if value > MAX_ACCEPTED {
            return Err(Error::Limit("active generation"));
        }
        Ok(Self(value))
    }
    pub fn get(self) -> u32 {
        self.0
    }
    fn next(self) -> Result<Self> {
        Self::new(self.0.checked_add(1).ok_or(Error::Limit("active generation"))?)
    }
}

/// Retain before dispatch. Caller data is an identity, not proof of acceptance.
/// Restart retries must use this same request; a new operation is new contention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationRequest {
    operation: OperationId,
    expected: ActiveGeneration,
    acceptance: AcceptanceRequest,
}
impl ActivationRequest {
    pub fn new(
        operation: OperationId,
        expected: ActiveGeneration,
        acceptance: AcceptanceRequest,
    ) -> Self {
        Self { operation, expected, acceptance }
    }
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }
    pub fn expected(&self) -> ActiveGeneration {
        self.expected
    }
    pub fn acceptance(&self) -> &AcceptanceRequest {
        &self.acceptance
    }
}

#[derive(Debug, Clone)]
pub struct PendingActivation {
    request: ActivationRequest,
    sealed: Sealed,
    ticket: PreparedMutation,
}
impl PendingActivation {
    pub fn request(&self) -> &ActivationRequest {
        &self.request
    }
}

/// Historical commit evidence, not a lease on availability or qualification.
/// A returned record can be superseded immediately after its linearization point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activated {
    row_id: i64,
    generation: ActiveGeneration,
    revision: AcceptedRevision,
    request: ActivationRequest,
    reconciled: bool,
}
impl Activated {
    pub fn row_id(&self) -> i64 { self.row_id }
    pub fn generation(&self) -> ActiveGeneration { self.generation }
    pub fn revision(&self) -> AcceptedRevision { self.revision }
    pub fn request(&self) -> &ActivationRequest { &self.request }
    pub fn reconciled(&self) -> bool { self.reconciled }
    pub fn stage(&self) -> Stage { Stage::Activated }
}

impl AcceptanceStore {
    /// Internal coordinator state only. Does not establish current availability;
    /// no reader/service or native lifecycle is activated by inspecting a pointer.
    pub fn active(&self, scope: &TrustedScope) -> Result<Option<Activated>> {
        Ok(self.activation_history(scope)?.pop())
    }

    /// Activate only the current accepted publication, never a newest-file guess.
    /// Same-operation replay has zero new effects. Historical recovery is separate:
    /// re-dispatching a superseded committed request refuses rather than rolling back.
    pub fn activate(&self, request: &ActivationRequest, seals: &SealStore) -> Result<Activated> {
        check_environment()?;
        if let Some(committed) = self.reconcile_activation(request)? {
            self.check_activation_order(request, Some(committed.row_id))?;
            self.activation_seal(request, seals)?;
            return Ok(committed);
        }
        let pending = self.prepare_activation(request.clone(), seals)?;
        self.submit_activation(&pending, seals)
    }

    pub fn prepare_activation(
        &self,
        request: ActivationRequest,
        seals: &SealStore,
    ) -> Result<PendingActivation> {
        check_environment()?;
        request.expected.next()?;
        let accepted = self.check_activation_order(&request, None)?;
        let sealed = self.activation_seal(&request, seals)?;
        let json = Value::Text(event_bytes(&request)?).to_json();
        let accepted_json = Value::Text(store::event_bytes(
            &accepted.request, &accepted.actor_reference,
        )?).to_json();
        // CAS covers exactly this scope's active and accepted chains, not the
        // mutable global binding revision or unrelated model edits.
        let current_acceptance = format!(
            "(SELECT COUNT(*) FROM outbox WHERE {})={} AND EXISTS(SELECT 1 FROM outbox WHERE id={} AND value_json={})",
            store::predicate(request.acceptance.scope()), accepted.revision.get(),
            accepted.row_id, binding::sql_quote(&accepted_json),
        );
        let mut body = String::new();
        body.push_str(&guard_sql("activation_generation", &format!(
            "(SELECT COUNT(*) FROM outbox WHERE {})={}",
            predicate(request.acceptance.scope()), request.expected.get(),
        )));
        body.push_str(&guard_sql("activation_acceptance", &current_acceptance));
        body.push_str(&guard_sql("activation_publication", &sealed.guard()));
        body.push_str(&store::insert_row(
            EVENT, &entity(request.acceptance.scope()), "activation-event", &json,
            request.expected.next()?.get() as u64, "",
        ));
        let ticket = self.store.prepare_guarded_batch("1", &body, json.len())?
            .with_operation(request.operation.clone());
        Ok(PendingActivation { request, sealed, ticket })
    }

    pub fn submit_activation(&self, pending: &PendingActivation, seals: &SealStore) -> Result<Activated> {
        check_environment()?;
        match self.store.reconcile(&pending.ticket) {
            MutationOutcome::NotCommitted { .. } => {}
            outcome => {
                let committed = self.read_activation_commit(
                    &pending.request, store::committed_row(outcome)?, true,
                )?;
                self.check_activation_order(&pending.request, Some(committed.row_id))?;
                self.verify_activation_seal(&pending.request, &pending.sealed, seals)?;
                return Ok(committed);
            }
        }
        self.check_activation_order(&pending.request, None)?;
        self.verify_activation_seal(&pending.request, &pending.sealed, seals)?;
        #[cfg(test)]
        at_boundary(); // NO lock held: deterministic race/interruption seam.
        let (outcome, reconciled) = match self.store.submit(&pending.ticket) {
            MutationOutcome::Unknown { .. } => (self.store.reconcile(&pending.ticket), true),
            other => (other, false),
        };
        let row = match outcome {
            MutationOutcome::NotCommitted {
                error: crate::storage::StorageError::SqliteFailure { detail }, ..
            } if detail.contains("CHECK constraint failed: activation_generation") => {
                // The CAS definitely did not commit. A failed diagnostic read
                // still propagates, never manufactures a current generation.
                let current = self.active(pending.request.acceptance.scope())?
                    .map_or(ActiveGeneration::INITIAL, |a| a.generation);
                return Err(Error::StaleGeneration { expected: pending.request.expected, current });
            }
            MutationOutcome::NotCommitted {
                error: crate::storage::StorageError::SqliteFailure { detail }, ..
            } if detail.contains("CHECK constraint failed: activation_acceptance") => {
                // Several predicates may have lost. Prefer the current active
                // generation diagnosis even if SQLite reported acceptance last.
                self.check_activation_order(&pending.request, None)?;
                return Err(self.superseded(&pending.request)?);
            }
            MutationOutcome::NotCommitted {
                error: crate::storage::StorageError::SqliteFailure { detail }, ..
            } if detail.contains("CHECK constraint failed: activation_publication") => {
                self.check_activation_order(&pending.request, None)?;
                return Err(blocked(&pending.request, crate::seal::SealError::Conflict(
                    "publication changed during activation admission".into(),
                )));
            }
            other => store::committed_row(other)?,
        };
        self.read_activation_commit(&pending.request, row, reconciled)
            .map_err(|error| Error::Unknown {
                operation: pending.request.operation.clone(),
                detail: format!("committed activation; read failed: {error}"),
            })
    }

    /// Read-only historical recovery; not authority to reapply an old pointer.
    /// An absent receipt is final only after stopping/joining its dispatchers.
    pub fn reconcile_activation(&self, request: &ActivationRequest) -> Result<Option<Activated>> {
        match self.store.reconcile_operation(&request.operation) {
            MutationOutcome::NotCommitted { .. } => Ok(None),
            outcome => Ok(Some(self.read_activation_commit(
                request, store::committed_row(outcome)?, true,
            )?)),
        }
    }

    fn read_activation_commit(&self, request: &ActivationRequest, row: i64, reconciled: bool) -> Result<Activated> {
        let mut found = self.activation_history(request.acceptance.scope())?.into_iter()
            .find(|a| a.row_id == row)
            .ok_or_else(|| Error::Conflict("receipt does not identify an activation".into()))?;
        if found.request != *request {
            return Err(Error::Conflict("operation identity reused with different activation".into()));
        }
        found.reconciled = reconciled;
        Ok(found)
    }

    fn check_activation_order(&self, request: &ActivationRequest, replay: Option<i64>) -> Result<Accepted> {
        let active = self.active(request.acceptance.scope())?;
        let generation = active.as_ref().map_or(ActiveGeneration::INITIAL, |a| a.generation);
        if !active.as_ref().is_some_and(|a| Some(a.row_id) == replay && a.request == *request)
            && request.expected != generation
        {
            return Err(Error::StaleGeneration { expected: request.expected, current: generation });
        }
        let current = self.current(request.acceptance.scope())?
            .ok_or(Error::Invalid("activation requires committed acceptance"))?;
        if current.request != request.acceptance {
            return Err(Error::Superseded {
                requested: request.acceptance.expected().next()?, current: current.revision,
            });
        }
        if replay.is_none() && active.is_some_and(|a| a.revision == current.revision) {
            return Err(Error::Conflict("already active; reconcile original operation".into()));
        }
        Ok(current)
    }

    fn superseded(&self, request: &ActivationRequest) -> Result<Error> {
        let current = self.current(request.acceptance.scope())?
            .ok_or(Error::Invalid("missing accepted history"))?;
        Ok(Error::Superseded {
            requested: request.acceptance.expected().next()?, current: current.revision,
        })
    }

    fn activation_seal(&self, request: &ActivationRequest, seals: &SealStore) -> Result<Sealed> {
        let staged = self.read_staged(request.acceptance.staged_operation())
            .map_err(|e| map_blocked(request, e))?;
        self.sealed(&staged, request.acceptance.seal(), seals)
            .map_err(|e| map_blocked(request, e))
    }
    fn verify_activation_seal(&self, request: &ActivationRequest, sealed: &Sealed, seals: &SealStore) -> Result<()> {
        sealed.verify(&self.store, seals).map_err(|e| map_blocked(request, e))
    }

    fn activation_history(&self, scope: &TrustedScope) -> Result<Vec<Activated>> {
        // Read active rows FIRST: an acceptance committed concurrently can only
        // extend the subsequent accepted read, not make a valid join disappear.
        let rows = self.store.exec_script(&format!(
            "SELECT id,quote(value_json),seq,sensor FROM outbox WHERE {} ORDER BY id LIMIT {};",
            predicate(scope), MAX_ACCEPTED + 1,
        ))?;
        if rows.len() > MAX_ACCEPTED as usize { return Err(Error::Limit("activation history")); }
        let accepted = self.history(scope)?;
        let mut history = Vec::new();
        let mut operations = std::collections::BTreeSet::new();
        let mut revision = 0;
        for (index, row) in rows.iter().enumerate() {
            if row.len() != 4 || row[2] != (index + 1).to_string() || row[3] != "activation-event" {
                return Err(Error::Invalid("activation sequence/columns"));
            }
            let row_id = codec::number::<i64>(&row[0])?;
            let json = binding::unquote_column(&row[1])?.ok_or(Error::Invalid("NULL activation"))?;
            let raw = codec::text_json(&json)?;
            let fields = codec::decode(&raw, 8192, 11)?;
            if fields.len() != 11 || fields[0] != "verdant-active-v1" || fields[4] != scope.as_str()
                || fields[2] != index.to_string() || fields[3] != row[2]
                || fields[10] != "activated" || row_id <= 0 || !operations.insert(fields[1].clone())
            { return Err(Error::Invalid("activation event chain")); }
            let parse_op = |s: &str| OperationId::parse(s).map_err(|_| Error::Invalid("activation operation"));
            let acceptance = AcceptanceRequest::new(
                parse_op(&fields[5])?, AcceptedRevision::new(codec::number(&fields[6])?)?,
                scope.clone(), parse_op(&fields[8])?, Digest::parse(&fields[9])?,
            );
            let target = acceptance.expected().next()?;
            if fields[7] != target.get().to_string() || target.get() <= revision
                || !accepted.iter().any(|a| a.request == acceptance && a.row_id < row_id)
            { return Err(Error::Invalid("activation accepted join/order")); }
            let request = ActivationRequest::new(parse_op(&fields[1])?, ActiveGeneration::new(index as u32)?, acceptance);
            if event_bytes(&request)? != raw { return Err(Error::Invalid("noncanonical activation")); }
            revision = target.get();
            history.push(Activated {
                row_id, generation: request.expected.next()?, revision: target, request, reconciled: false,
            });
        }
        Ok(history)
    }
}

fn event_bytes(request: &ActivationRequest) -> Result<String> {
    Ok(codec::encode(&[
        "verdant-active-v1".into(), request.operation.as_str().into(),
        request.expected.get().to_string(), request.expected.next()?.get().to_string(),
        request.acceptance.scope().as_str().into(), request.acceptance.operation().as_str().into(),
        request.acceptance.expected().get().to_string(), request.acceptance.expected().next()?.get().to_string(),
        request.acceptance.staged_operation().as_str().into(), request.acceptance.seal().as_str().into(),
        "activated".into(),
    ]))
}
fn entity(scope: &TrustedScope) -> String { format!("active-{}", scope.as_str()) }
fn predicate(scope: &TrustedScope) -> String {
    format!("operation='{EVENT}' AND entity={}", binding::sql_quote(&entity(scope)))
}
fn guard_sql(name: &str, condition: &str) -> String {
    format!("CREATE TEMP TABLE {name}(ok INTEGER NOT NULL CONSTRAINT {name} CHECK(ok=1)); INSERT INTO {name} VALUES(CASE WHEN ({condition}) THEN 1 ELSE 0 END);")
}
fn blocked(request: &ActivationRequest, cause: crate::seal::SealError) -> Error {
    Error::ActivationBlocked { scope: request.acceptance.scope().clone(), seal: request.acceptance.seal().clone(), cause }
}
fn map_blocked(request: &ActivationRequest, error: Error) -> Error {
    match error {
        Error::Blocked(cause) => blocked(request, cause),
        Error::Invalid("missing/ambiguous staged row") => blocked(request,
            crate::seal::SealError::Missing("accepted staged root".into())),
        other => other,
    }
}

#[cfg(test)]
thread_local! { static BOUNDARY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None); }
#[cfg(test)]
pub(crate) fn on_activation_boundary(hook: impl FnOnce() + 'static) {
    BOUNDARY.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}
#[cfg(test)]
fn at_boundary() {
    if let Some(hook) = BOUNDARY.with(|slot| slot.borrow_mut().take()) { hook(); }
}
