use super::{journal::*, *};
use crate::accept::{
    AcceptanceRequest, Accepted, AcceptedRevision, EffectiveConfig, Entry, ImpactDiff, Staged,
};
use crate::binding::{self, sql_quote as quote};
use crate::seal::{ContentNode, Digest, NativeRef, RowKey, RuntimeRef, SealCommit};

/// Explicit durable reference. A missing row is a diagnostic, never an omitted
/// child. Conversion to the existing seal RowKey retains its validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reference {
    pub operation: OperationId,
    pub sequence: u64,
}
impl Reference {
    pub fn new(operation: OperationId, sequence: u64) -> Result<Self> {
        RowKey::new(operation.clone(), sequence)?;
        Ok(Self {
            operation,
            sequence,
        })
    }
    pub(super) fn row(&self) -> Result<RowKey> {
        Ok(RowKey::new(self.operation.clone(), self.sequence)?)
    }
    pub(super) fn name(&self) -> String {
        format!("content:{}:{}", self.operation.as_str(), self.sequence)
    }
}

/// Immutable, resolved inputs to a retry. Obtain configuration through resolve;
/// keep this value rather than silently resolving new provenance under an old ID.
#[derive(Debug, Clone)]
pub struct DraftContent {
    pub(super) config: EffectiveConfig,
    findings: Vec<Reference>,
}
impl DraftContent {
    /// Accept already resolved immutable owner inputs without exposing aggregate
    /// owner provenance through the reader API. Construction grants no authority.
    pub fn new(config: EffectiveConfig, findings: Vec<Reference>) -> Result<Self> {
        let result = Self { config, findings };
        result.bytes()?;
        Ok(result)
    }
    fn roots(&self) -> Result<Vec<RowKey>> {
        self.findings.iter().map(Reference::row).collect()
    }
    fn bytes(&self) -> Result<String> {
        Ok(
            ContentNode::new(self.config.canonical_bytes(), self.roots()?)?
                .value()
                .to_json(),
        )
    }
}
#[derive(Debug, Clone)]
pub struct DraftRevision {
    pub operation: OperationId,
    pub draft: OperationId,
    pub author: String,
    pub(super) staged: Staged,
}
impl DraftRevision {
    pub fn staged_operation(&self) -> &OperationId {
        self.staged.operation()
    }
    pub fn binding_revision(&self) -> crate::domain::ids::BindingRevision {
        self.staged.config().binding_revision()
    }
    pub fn entry_count(&self) -> usize {
        self.staged.config().entries().len()
    }
}

/// Inert execution reference and explicitly captured content, not an executable
/// command. No path/host is launched or granted authority by this structure.
#[derive(Debug, Clone)]
pub struct Publication {
    pub binary: String,
    pub host: String,
    pub native: Vec<NativeRef>,
}
impl Publication {
    fn signature(&self) -> Result<String> {
        RuntimeRef::new(&self.binary, &self.host)?;
        if self.native.is_empty() || self.native.len() > crate::seal::MAX_NATIVE_REFS {
            return Err(Error::Invalid("explicit native content required"));
        }
        let mut refs = self
            .native
            .iter()
            .map(|n| {
                encode(&[
                    n.generation().to_string(),
                    n.manifest_digest().as_str().into(),
                    n.manifest_bytes().to_string(),
                ])
            })
            .collect::<Vec<_>>();
        refs.sort();
        refs.dedup();
        // Manifest bytes identify the captured snapshot. The seal owner still
        // verifies every actual reference (including owning path) on dispatch.
        Ok(encode(&[
            self.binary.clone(),
            self.host.clone(),
            encode(&refs),
        ]))
    }
}

impl Api<'_> {
    pub fn resolve(
        &mut self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        domain: Vec<Entry>,
        intent: Vec<Entry>,
        findings: Vec<Reference>,
    ) -> Result<DraftContent> {
        self.authenticate(credential, scope, true)?;
        let config =
            EffectiveConfig::resolve(self.gate, self.registry, scope.clone(), domain, intent)?;
        DraftContent::new(config, findings)
    }

    pub fn draft(
        &mut self,
        credential: Option<&Credential>,
        op: &OperationId,
        content: &DraftContent,
    ) -> Result<DraftRevision> {
        self.write_draft(credential, op, None, content)
    }

    /// Edits append a new immutable staged snapshot, never overwrite a staged or
    /// sealed row. The original draft identity is stable; parent is a CAS token.
    pub fn edit(
        &mut self,
        credential: Option<&Credential>,
        op: &OperationId,
        parent: &OperationId,
        content: &DraftContent,
    ) -> Result<(DraftRevision, ImpactDiff)> {
        let old = self.read(credential, content.config.scope(), parent)?;
        let impact = content.config.impact_from(old.staged.config());
        Ok((
            self.write_draft(credential, op, Some(&old), content)?,
            impact,
        ))
    }

    fn write_draft(
        &mut self,
        credential: Option<&Credential>,
        op: &OperationId,
        old: Option<&DraftRevision>,
        content: &DraftContent,
    ) -> Result<DraftRevision> {
        let scope = content.config.scope();
        self.authenticate(credential, scope, true)?;
        let credential = self.credential(credential)?;
        let subject = old.map_or(op, |d| &d.draft);
        let event = self.remember(
            credential,
            scope,
            op,
            if old.is_some() {
                Kind::Edit
            } else {
                Kind::Draft
            },
            subject,
            old.map(|d| &d.operation),
            content.bytes()?,
            false,
        )?;
        let stage_op = child("accept-stage", op)?;
        if self.effect_row(&stage_op)?.is_none() {
            self.dispatchable(&event)?;
            #[cfg(test)]
            at_draft_boundary();
            // Staging is explicitly non-authoritative. Its access-joined API
            // intent is already durable; an interrupted second commit is pending.
            self.accepted
                .stage(&stage_op, content.config.clone(), content.roots()?)?;
        }
        self.read(Some(credential), scope, op)
    }

    pub fn read(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
    ) -> Result<DraftRevision> {
        self.authenticate(credential, scope, false)?;
        let intent = self.intent(scope, op)?;
        self.read_revision(&intent)
    }
    pub(super) fn read_revision(&self, intent: &Intent) -> Result<DraftRevision> {
        if !matches!(intent.kind, Kind::Draft | Kind::Edit) {
            return Err(Error::Invalid("not a draft revision"));
        }
        let stage_op = child("accept-stage", &intent.operation)?;
        let row = self.effect_row(&stage_op)?.ok_or_else(|| {
            Error::Missing(format!("pending-stage:{}", intent.operation.as_str()))
        })?;
        let rows = self.registry.store().exec_script(&format!(
            "SELECT id FROM outbox WHERE id={row} AND operation={} AND value_json={};",
            quote(stage_op.as_str()),
            quote(&intent.request)
        ))?;
        if rows != vec![vec![row.to_string()]] {
            return Err(Error::Conflict("staged bytes/intent mismatch"));
        }
        let staged = self.accepted.read_staged(&stage_op)?;
        if staged.config().scope() != &intent.scope {
            return Err(Error::Conflict("staged scope differs"));
        }
        Ok(DraftRevision {
            operation: intent.operation.clone(),
            draft: intent.subject.clone(),
            author: intent.actor.clone(),
            staged,
        })
    }

    pub fn seal(
        &mut self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
        revision: &OperationId,
        publication: &Publication,
    ) -> Result<SealCommit> {
        self.authenticate(credential, scope, true)?;
        let credential = self.credential(credential)?;
        let draft = self.read(Some(credential), scope, revision)?;
        let intent = self.remember(
            credential,
            scope,
            op,
            Kind::Seal,
            &draft.draft,
            Some(revision),
            publication.signature()?,
            false,
        )?;
        if let Some(commit) = self.seal_effect(&intent)? {
            return Ok(commit);
        }
        self.dispatchable(&intent)?;
        let seal_draft = crate::seal::Draft::new(
            draft.staged.config().binding_revision(),
            scope.clone(),
            RuntimeRef::new(&publication.binary, &publication.host)?,
            vec![draft.staged.root()?],
            publication.native.clone(),
        )?;
        Ok(self.seals.seal(
            &child("api-effect", op)?,
            &seal_draft,
            self.registry,
            self.gate,
            credential,
        )?)
    }

    pub(super) fn seal_effect(&self, intent: &Intent) -> Result<Option<SealCommit>> {
        if intent.kind != Kind::Seal {
            return Err(Error::Invalid("not a seal operation"));
        }
        let operation = child("api-effect", &intent.operation)?;
        let Some(row) = self.effect_row(&operation)? else {
            return Ok(None);
        };
        // Read the identity from the receipt's exact row, not newest content or
        // user text. SealStore replays and verifies its own format/digest below.
        let rows = self.registry.store().exec_script(&format!(
            "SELECT quote(value_json) FROM outbox WHERE id={row} AND operation='seal-revision-v1';"
        ))?;
        let [columns] = rows.as_slice() else {
            return Err(Error::Conflict("seal receipt row kind"));
        };
        let [raw] = columns.as_slice() else {
            return Err(Error::Invalid("seal receipt columns"));
        };
        let fields = decode(&text_column(raw)?, crate::seal::MAX_MANIFEST_BYTES + 256, 3)?;
        if fields.len() != 3 || fields[0] != "seal-row-v1" {
            return Err(Error::Invalid("seal row framing"));
        }
        Ok(self
            .seals
            .reconcile(&operation, &Digest::parse(&fields[1])?)?)
    }

    /// Durably prepares cancellable acceptance intent without dispatching its
    /// effect. No cached credential or PendingAcceptance grants a later write.
    pub fn prepare_accept(
        &mut self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
        seal_operation: &OperationId,
        expected: AcceptedRevision,
    ) -> Result<AcceptanceRequest> {
        self.authenticate(credential, scope, true)?;
        let credential = self.credential(credential)?;
        let sealed_intent = self.intent(scope, seal_operation)?;
        let seal = self
            .seal_effect(&sealed_intent)?
            .ok_or_else(|| Error::Missing("pending-seal".into()))?;
        let revision = sealed_intent
            .parent
            .as_ref()
            .ok_or(Error::Invalid("seal parent"))?;
        let request = AcceptanceRequest::new(
            child("api-effect", op)?,
            expected,
            scope.clone(),
            child("accept-stage", revision)?,
            seal.identity,
        );
        self.remember(
            credential,
            scope,
            op,
            Kind::Accept,
            &sealed_intent.subject,
            Some(seal_operation),
            acceptance_bytes(&request),
            false,
        )?;
        Ok(request)
    }

    pub fn accept(
        &mut self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
        seal_operation: &OperationId,
        expected: AcceptedRevision,
    ) -> Result<Accepted> {
        self.prepare_accept(credential, scope, op, seal_operation, expected)?;
        self.submit_accept(credential, scope, op)
    }

    pub fn submit_accept(
        &mut self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
    ) -> Result<Accepted> {
        self.authenticate(credential, scope, true)?;
        let credential = self.credential(credential)?;
        let intent = self.intent(scope, op)?;
        let request = acceptance_request(&intent)?;
        if let Some(accepted) = self.accepted.reconcile(&request)? {
            return Ok(accepted);
        }
        self.dispatchable(&intent)?;
        let staged = self.accepted.read_staged(request.staged_operation())?;
        let sealed = self.accepted.sealed(&staged, request.seal(), self.seals)?;
        let pending = self.accepted.prepare(
            request.operation().clone(),
            request.expected(),
            &sealed,
            self.seals,
            self.registry,
            self.gate,
            credential,
        )?;
        Ok(self.accepted.submit(&pending, self.seals)?)
    }

    /// Resolves the named `finding:<key>` prerequisite through its existing
    /// owner. A fresh edit/resolve then records the new fact/reference; no raw DB
    /// edit, approval fabrication, or automatic qualification is involved.
    pub fn record_finding(
        &mut self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
        revision: &OperationId,
        key: &str,
    ) -> Result<Reference> {
        self.authenticate(credential, scope, true)?;
        let credential = self.credential(credential)?;
        let draft = self.read(Some(credential), scope, revision)?;
        let entry = draft
            .staged
            .config()
            .entries()
            .get(key)
            .ok_or_else(|| Error::Missing(format!("entry:{key}")))?;
        let input = encode(&[
            revision.as_str().into(),
            key.into(),
            entry.binding().canonical_bytes(),
            draft
                .staged
                .config()
                .binding_revision()
                .as_u32()
                .to_string(),
        ]);
        let intent = self.remember(
            credential,
            scope,
            op,
            Kind::Finding,
            &draft.draft,
            Some(revision),
            input,
            false,
        )?;
        let effect = child("api-effect", op)?;
        if self.effect_row(&effect)?.is_none() {
            self.dispatchable(&intent)?;
            self.registry.emit_finding_operation(
                &effect,
                draft.staged.config().binding_revision(),
                self.gate,
                entry.binding(),
                credential,
            )?;
        }
        let row = self
            .effect_row(&effect)?
            .ok_or_else(|| Error::Missing("finding receipt".into()))?;
        let rows = self.registry.store().exec_script(&format!(
            "SELECT seq FROM outbox WHERE id={row} AND operation='binding-finding';"
        ))?;
        let [columns] = rows.as_slice() else {
            return Err(Error::Conflict("finding receipt row"));
        };
        let [seq] = columns.as_slice() else {
            return Err(Error::Invalid("finding columns"));
        };
        Reference::new(
            OperationId::parse(binding::OP_FINDING_TEXT)
                .map_err(|_| Error::Invalid("finding kind"))?,
            number(seq)?,
        )
    }
}
pub(super) fn acceptance_bytes(request: &AcceptanceRequest) -> String {
    encode(&[
        request.expected().get().to_string(),
        request.staged_operation().as_str().into(),
        request.seal().as_str().into(),
    ])
}
pub(super) fn acceptance_request(intent: &Intent) -> Result<AcceptanceRequest> {
    if intent.kind != Kind::Accept {
        return Err(Error::Invalid("not an acceptance operation"));
    }
    let f = decode(&intent.request, 512, 3)?;
    if f.len() != 3 {
        return Err(Error::Invalid("acceptance input"));
    }
    Ok(AcceptanceRequest::new(
        child("api-effect", &intent.operation)?,
        AcceptedRevision::new(number(&f[0])?)?,
        intent.scope.clone(),
        OperationId::parse(&f[1]).map_err(|_| Error::Invalid("staged operation"))?,
        Digest::parse(&f[2])?,
    ))
}

#[cfg(test)]
thread_local! { static DRAFT_BOUNDARY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None); }
#[cfg(test)]
pub(crate) fn on_draft_boundary(hook: impl FnOnce() + 'static) {
    DRAFT_BOUNDARY.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}
#[cfg(test)]
fn at_draft_boundary() {
    if let Some(hook) = DRAFT_BOUNDARY.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}
