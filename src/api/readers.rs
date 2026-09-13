use super::{journal::*, operations::acceptance_request, *};
use crate::accept::{Accepted, Activated, Entry};
use crate::binding::{self, sql_quote as quote};
use crate::domain::values::Value;

pub const MAX_PAGE: usize = 64;
/// Explicit pages, no default/unbounded overload. Offset is a bounded window,
/// not a consistent snapshot lease; use returned immutable operation identities.
#[derive(Debug, Clone, Copy)]
pub struct PageRequest {
    offset: usize,
    size: usize,
}
impl PageRequest {
    pub fn new(offset: usize, size: usize) -> Result<Self> {
        if size == 0 || size > MAX_PAGE || offset > MAX_WORK || offset.checked_add(size).is_none() {
            return Err(Error::Limit("page requires size 1..=64 and offset 0..=256"));
        }
        Ok(Self { offset, size })
    }
}
#[derive(Debug)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<PageRequest>,
}
pub(super) fn page<T>(items: Vec<T>, request: PageRequest) -> Page<T> {
    let total = items.len();
    let end = request.offset + request.size;
    Page {
        items: items
            .into_iter()
            .skip(request.offset)
            .take(request.size)
            .collect(),
        next: if end < total {
            Some(PageRequest {
                offset: end,
                size: request.size,
            })
        } else {
            None
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Diagnostic {
    MissingContent { reference: String },
    MissingFinding { prerequisite: String },
    Unqualified { key: String, status: String },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    Unsupported,
    Pending,
    Unavailable {
        code: &'static str,
        detail: String,
    },
    /// Available bytes or an active event cannot establish operational readiness.
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    NoAcceptance,
    Available,
    Unavailable { code: &'static str, detail: String },
}
#[derive(Debug)]
pub struct ScopeStatus {
    pub accepted: Option<Accepted>,
    pub active: Option<Activated>,
    pub accepted_content: Availability,
    pub active_content: Option<Availability>,
    pub operational: Readiness,
    pub field_authority: Readiness,
    pub qualification: Readiness,
}
#[derive(Debug)]
pub struct WorkStatus {
    pub operation: OperationId,
    pub intent_row: i64,
    pub author: String,
    pub cancel_requested: bool,
    /// None is not a rollback assertion. Recovery effects have access-owned
    /// identities; their caller verifies the issued/successor credential on retry.
    pub effect_row: Option<i64>,
    pub effect_known: bool,
}

/// Original seal intent identity, never an identity invented by a read/retry.
/// Pending includes canceled intents: neither cancellation nor intent is a seal.
#[derive(Debug)]
pub enum SealLookup {
    Committed {
        operation: OperationId,
        commit: crate::seal::SealCommit,
    },
    Pending {
        operation: OperationId,
    },
}

impl Api<'_> {
    /// Authenticated, read-only lookup by draft or one of its revision IDs.
    /// Returns the original operation and receipt-verified commit, or explicit
    /// pending intent. Missing draft/stage/seal is `api-missing-content`;
    /// malformed history, unavailable content and reconciliation errors propagate.
    /// This does not dispatch pending work, grant publication, or refresh content.
    pub fn sealed(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        revision: &OperationId,
    ) -> Result<SealLookup> {
        let draft = self.read(credential, scope, revision)?;
        let intent = self.intents(scope)?.into_iter()
            .find(|i| i.kind == Kind::Seal && i.subject == draft.draft)
            .ok_or_else(|| Error::Missing(format!("seal:{}", draft.draft.as_str())))?;
        Ok(match self.seal_effect(&intent)? {
            Some(commit) => SealLookup::Committed {
                operation: intent.operation,
                commit,
            },
            None => SealLookup::Pending {
                operation: intent.operation,
            },
        })
    }

    pub fn status(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
    ) -> Result<ScopeStatus> {
        self.authenticate(credential, scope, false)?;
        // Active first, then accepted: a concurrent acceptance can only extend
        // the history. These reads are evidence, not a readiness lease.
        let active = self.accepted.active(scope)?;
        let accepted = self.accepted.current(scope)?;
        let accepted_content = match &accepted {
            None => Availability::NoAcceptance,
            Some(a) => match self
                .accepted
                .read_staged(a.request.staged_operation())
                .and_then(|staged| self.accepted.sealed(&staged, a.request.seal(), self.seals))
            {
                Ok(_) => Availability::Available,
                Err(e) => Availability::Unavailable {
                    code: e.code(),
                    detail: e.to_string(),
                },
            },
        };
        let active_content = active.as_ref().map(|active| {
            let request = active.request().acceptance();
            match self
                .accepted
                .read_staged(request.staged_operation())
                .and_then(|staged| self.accepted.sealed(&staged, request.seal(), self.seals))
            {
                Ok(_) => Availability::Available,
                Err(e) => Availability::Unavailable {
                    code: e.code(),
                    detail: e.to_string(),
                },
            }
        });
        let operational = match &accepted_content {
            Availability::NoAcceptance => Readiness::Pending,
            Availability::Available => Readiness::Unknown,
            Availability::Unavailable { code, detail } => Readiness::Unavailable {
                code,
                detail: detail.clone(),
            },
        };
        let operational = match &active_content {
            Some(Availability::Unavailable { code, detail }) => Readiness::Unavailable {
                code,
                detail: detail.clone(),
            },
            Some(Availability::NoAcceptance | Availability::Available) | None => operational,
        };
        Ok(ScopeStatus {
            accepted,
            active,
            accepted_content,
            active_content,
            operational,
            field_authority: Readiness::Unsupported,
            qualification: Readiness::Unsupported,
        })
    }

    /// Read exact accepted bytes independently of live availability. Status
    /// retains the accepted event if these bytes have become unavailable.
    pub fn read_accepted(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        request: PageRequest,
    ) -> Result<Option<Page<Entry>>> {
        self.authenticate(credential, scope, false)?;
        self.accepted
            .current(scope)?
            .map(|a| {
                let staged = self.accepted.read_staged(a.request.staged_operation())?;
                Ok(page(
                    staged.config().entries().values().cloned().collect(),
                    request,
                ))
            })
            .transpose()
    }
    pub fn read_active(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        request: PageRequest,
    ) -> Result<Option<Page<Entry>>> {
        self.authenticate(credential, scope, false)?;
        self.accepted
            .active(scope)?
            .map(|a| {
                let staged = self
                    .accepted
                    .read_staged(a.request().acceptance().staged_operation())?;
                Ok(page(
                    staged.config().entries().values().cloned().collect(),
                    request,
                ))
            })
            .transpose()
    }

    pub fn entries(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
        request: PageRequest,
    ) -> Result<Page<Entry>> {
        let draft = self.read(credential, scope, op)?;
        Ok(page(
            draft.staged.config().entries().values().cloned().collect(),
            request,
        ))
    }

    pub fn work(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
    ) -> Result<WorkStatus> {
        self.authenticate(credential, scope, false)?;
        self.work_status(&self.intent(scope, op)?)
    }
    pub fn operations(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        request: PageRequest,
    ) -> Result<Page<WorkStatus>> {
        self.authenticate(credential, scope, false)?;
        let selected = page(self.intents(scope)?, request);
        Ok(Page {
            items: selected
                .items
                .iter()
                .map(|i| self.work_status(i))
                .collect::<Result<_>>()?,
            next: selected.next,
        })
    }
    fn work_status(&self, intent: &Intent) -> Result<WorkStatus> {
        let (effect_row, effect_known) = match intent.kind {
            Kind::Draft | Kind::Edit => {
                let row = self.effect_row(&child("accept-stage", &intent.operation)?)?;
                if row.is_some() {
                    self.read_revision(intent)?;
                }
                (row, true)
            }
            Kind::Seal => (self.seal_effect(intent)?.map(|s| s.row_id), true),
            Kind::Accept => (
                self.accepted
                    .reconcile(&acceptance_request(intent)?)?
                    .map(|a| a.row_id),
                true,
            ),
            Kind::Finding => (
                self.effect_row(&child("api-effect", &intent.operation)?)?,
                true,
            ),
            Kind::Provision | Kind::Recover | Kind::Rotate => (None, false),
        };
        Ok(WorkStatus {
            operation: intent.operation.clone(),
            intent_row: intent.row_id,
            author: intent.actor.clone(),
            cancel_requested: self.cancelled(intent)?,
            effect_row,
            effect_known,
        })
    }

    /// Reports every explicitly referenced missing row and every unqualified
    /// entry, with bounded pagination. Structural approval is not qualification.
    pub fn validate(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
        request: PageRequest,
    ) -> Result<Page<Diagnostic>> {
        let draft = self.read(credential, scope, op)?;
        let intent = self.intent(scope, op)?;
        let Value::Text(content) =
            Value::from_json(&intent.request).map_err(|_| Error::Invalid("draft JSON"))?
        else {
            return Err(Error::Invalid("draft content"));
        };
        let fields = decode(&content, 65_536, 4)?;
        if fields.len() != 4 || fields[0] != "verdant-content-v1" || fields[1] != "valid-structural"
        {
            return Err(Error::Invalid("draft content framing"));
        }
        let mut diagnostics = Vec::new();
        let mut findings = Vec::new();
        for raw in decode(&fields[3], 65_536, crate::seal::MAX_NODES)? {
            let parts = decode(&raw, 512, 2)?;
            if parts.len() != 2 {
                return Err(Error::Invalid("content reference framing"));
            }
            let reference = Reference::new(
                OperationId::parse(&parts[0]).map_err(|_| Error::Invalid("content operation"))?,
                number(&parts[1])?,
            )?;
            let rows = self.registry.store().exec_script(&format!(
                "SELECT quote(value_json) FROM outbox WHERE operation={} AND seq={} LIMIT 2;",
                quote(reference.operation.as_str()),
                quote(&reference.sequence.to_string())
            ))?;
            match rows.as_slice() {
                [] => diagnostics.push(Diagnostic::MissingContent {
                    reference: reference.name(),
                }),
                [row] if row.len() == 1 => {
                    // A config's approval list is a list of finding rows, not a
                    // silent recursive search through arbitrary caller content.
                    if reference.operation.as_str() != binding::OP_FINDING_TEXT {
                        return Err(Error::Invalid("configuration approval must name a finding"));
                    }
                    findings.push(binding::split_descriptor(&text_column(&row[0])?)?);
                }
                _ => return Err(Error::Conflict("ambiguous content reference")),
            }
        }
        for entry in draft.staged.config().entries().values() {
            let approved = findings.iter().any(|f| {
                f.get("binding") == Some(&entry.binding().canonical_bytes())
                    && draft.staged.config().facts().iter().any(|fact| {
                        f.get("fid").is_some_and(|id| id == fact.id())
                            && f.get("generation") == Some(&fact.generation().to_string())
                            && f.get("digest").is_some_and(|d| d == fact.digest())
                            && binding::split_descriptor(fact.actor()).is_ok_and(|actor| {
                                ["capability", "scope", "capgen", "issuer"]
                                    .iter()
                                    .all(|key| {
                                        actor
                                            .get(*key)
                                            .is_some_and(|value| f.get(*key) == Some(value))
                                    })
                            })
                    })
            });
            if !approved {
                diagnostics.push(Diagnostic::MissingFinding {
                    prerequisite: format!("finding:{}", entry.key().as_str()),
                });
            }
            // No API operation can establish observed qualification, including a
            // caller-provided status-bearing import. Always make the gap explicit.
            diagnostics.push(Diagnostic::Unqualified {
                key: entry.key().as_str().into(),
                status: entry.binding().status().as_str().into(),
            });
        }
        if diagnostics.len() > MAX_WORK {
            return Err(Error::Limit("validation diagnostics"));
        }
        Ok(page(diagnostics, request))
    }
}
