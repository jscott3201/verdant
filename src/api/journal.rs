//! API-owned intent records only. No access/binding/seal/accept row is rewritten.
use super::*;
use crate::binding::{self, sql_quote as quote};
use crate::domain::values::Value;
use crate::storage::sqlite::MutationOutcome;

pub(super) const MAX_WORK: usize = 256;
const EVENT: &str = "api-intent-v1";
const CANCEL: &str = "api-cancel-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Draft,
    Edit,
    Seal,
    Accept,
    Finding,
    Provision,
    Recover,
    Rotate,
}
impl Kind {
    fn text(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Edit => "edit",
            Self::Seal => "seal",
            Self::Accept => "accept",
            Self::Finding => "finding",
            Self::Provision => "provision",
            Self::Recover => "recover",
            Self::Rotate => "rotate",
        }
    }
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "draft" => Ok(Self::Draft),
            "edit" => Ok(Self::Edit),
            "seal" => Ok(Self::Seal),
            "accept" => Ok(Self::Accept),
            "finding" => Ok(Self::Finding),
            "provision" => Ok(Self::Provision),
            "recover" => Ok(Self::Recover),
            "rotate" => Ok(Self::Rotate),
            _ => Err(Error::Invalid("API intent kind")),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct Intent {
    pub row_id: i64,
    pub operation: OperationId,
    pub scope: TrustedScope,
    pub kind: Kind,
    pub subject: OperationId,
    pub parent: Option<OperationId>,
    pub request: String,
    pub actor: String,
}
impl Intent {
    fn bytes(&self) -> String {
        encode(&[
            "verdant-api-v1".into(),
            self.operation.as_str().into(),
            self.scope.as_str().into(),
            self.kind.text().into(),
            self.subject.as_str().into(),
            self.parent.as_ref().map_or("", OperationId::as_str).into(),
            self.request.clone(),
            self.actor.clone(),
        ])
    }
    fn decode(row: &[String]) -> Result<Self> {
        if row.len() != 2 {
            return Err(Error::Invalid("API intent columns"));
        }
        let f = decode(&text_column(&row[1])?, 65_536, 8)?;
        if f.len() != 8 || f[0] != "verdant-api-v1" {
            return Err(Error::Invalid("API intent version"));
        }
        let result = Self {
            row_id: number(&row[0])?,
            operation: operation(&f[1])?,
            scope: TrustedScope::parse(&f[2]).map_err(|_| Error::Invalid("API intent scope"))?,
            kind: Kind::parse(&f[3])?,
            subject: operation(&f[4])?,
            parent: if f[5].is_empty() {
                None
            } else {
                Some(operation(&f[5])?)
            },
            request: f[6].clone(),
            actor: f[7].clone(),
        };
        if result.row_id <= 0 || result.bytes() != text_column(&row[1])? {
            return Err(Error::Invalid("API intent canonical bytes"));
        }
        Ok(result)
    }
}

impl Api<'_> {
    pub(super) fn intents(&self, scope: &TrustedScope) -> Result<Vec<Intent>> {
        let rows = self.registry.store().exec_script(&format!(
            "SELECT id,quote(value_json) FROM outbox WHERE operation='{EVENT}' AND entity={} ORDER BY id LIMIT {};",
            quote(scope.as_str()), MAX_WORK + 1))?;
        if rows.len() > MAX_WORK {
            return Err(Error::Limit("API scope history"));
        }
        let mut seen = std::collections::BTreeSet::new();
        rows.iter()
            .map(|row| {
                let intent = Intent::decode(row)?;
                if &intent.scope != scope || !seen.insert(intent.operation.clone()) {
                    return Err(Error::Invalid("API scope/operation join"));
                }
                Ok(intent)
            })
            .collect()
    }

    pub(super) fn intent(&self, scope: &TrustedScope, op: &OperationId) -> Result<Intent> {
        self.intents(scope)?
            .into_iter()
            .find(|i| &i.operation == op)
            .ok_or_else(|| Error::Missing(format!("operation:{}", op.as_str())))
    }

    /// Authenticate before reconciliation too. Original authorship is retained,
    /// not replaced by the actor performing a permitted read/retry.
    pub(super) fn remember(
        &mut self,
        credential: &Credential,
        scope: &TrustedScope,
        op: &OperationId,
        kind: Kind,
        subject: &OperationId,
        parent: Option<&OperationId>,
        request: String,
        recovery: bool,
    ) -> Result<Intent> {
        operation(op.as_str())?;
        let history = self.intents(scope)?;
        let authority = self.registry.authority(
            self.gate,
            Some(credential),
            scope,
            if recovery {
                BindingRole::Sense
            } else {
                BindingRole::Drive
            },
        )?;
        if let Some(old) = history.iter().find(|i| &i.operation == op) {
            if old.kind != kind
                || &old.subject != subject
                || old.parent.as_ref() != parent
                || old.request != request
            {
                return Err(Error::Conflict(
                    "operation identity reused with changed input",
                ));
            }
            return Ok(old.clone());
        }
        if history.len() == MAX_WORK {
            return Err(Error::Limit("API scope history"));
        }
        if matches!(kind, Kind::Edit | Kind::Seal) {
            let previous = parent.ok_or(Error::Invalid("draft parent"))?;
            let latest = history
                .iter()
                .rev()
                .find(|i| &i.subject == subject && matches!(i.kind, Kind::Draft | Kind::Edit))
                .ok_or_else(|| Error::Missing("draft parent".into()))?;
            if &latest.operation != previous {
                return Err(Error::Conflict("stale draft revision"));
            }
            // A persisted seal intent freezes before dispatch, including a lost
            // response. Canceling it never edits/unseals published bytes.
            if history
                .iter()
                .any(|i| &i.subject == subject && i.kind == Kind::Seal)
            {
                return Err(Error::SealedMutation);
            }
        }
        let intent = Intent {
            row_id: 0,
            operation: op.clone(),
            scope: scope.clone(),
            kind,
            subject: subject.clone(),
            parent: parent.cloned(),
            request,
            actor: actor_text(authority.report.actor()),
        };
        let value = Value::Text(intent.bytes()).to_json();
        let condition = format!("({}) AND (SELECT COUNT(*) FROM outbox WHERE operation='{EVENT}' AND entity={})={} AND NOT EXISTS(SELECT 1 FROM storage_receipts WHERE operation={})",
            authority.guard, quote(scope.as_str()), history.len(), quote(&format!("api-journal-{}", op.as_str())));
        let expiry = authority
            .report
            .actor()
            .policy()
            .expires_at()
            .map(|t| t.as_millis());
        let row = self.append(
            &child("api-journal", op)?,
            EVENT,
            scope,
            &value,
            &condition,
            expiry,
        )?;
        Ok(Intent {
            row_id: row,
            ..intent
        })
    }

    fn append(
        &self,
        op: &OperationId,
        kind: &str,
        scope: &TrustedScope,
        value: &str,
        condition: &str,
        expiry: Option<i64>,
    ) -> Result<i64> {
        let mut sql = String::new();
        if let Some(end) = expiry {
            sql.push_str(&format!("CREATE TEMP TABLE api_live(ok INTEGER NOT NULL CHECK(ok=1)); INSERT INTO api_live VALUES(CASE WHEN CAST(unixepoch('subsec')*1000 AS INTEGER)<{end} THEN 1 ELSE 0 END);"));
        }
        sql.push_str(&format!("INSERT INTO outbox(operation,entity,sensor,value_json,unit,source_ms,receipt_ms,ingestion_ms,generation,seq,status,claimed_by,created_nanos) VALUES ({},{},'api-intent',{},'count','0','0','0','gen-1','1','queued',NULL,'0');",
            quote(kind), quote(scope.as_str()), quote(value)));
        let ticket = self
            .registry
            .store()
            .prepare_guarded_batch(condition, &sql, value.len())?
            .with_operation(op.clone());
        let outcome = match self.registry.store().submit(&ticket) {
            MutationOutcome::Unknown { .. } => self.registry.store().reconcile(&ticket),
            other => other,
        };
        row_outcome(outcome)?.ok_or(Error::Conflict("intent not committed"))
    }

    pub(super) fn cancelled(&self, intent: &Intent) -> Result<bool> {
        let value = Value::Text(intent.operation.as_str().into()).to_json();
        let rows = self.registry.store().exec_script(&format!("SELECT id FROM outbox WHERE operation='{CANCEL}' AND entity={} AND value_json={} LIMIT 2;", quote(intent.scope.as_str()), quote(&value)))?;
        if rows.len() > 1 {
            return Err(Error::Invalid("duplicate cancellation"));
        }
        Ok(!rows.is_empty())
    }

    /// Stops future dispatch by this API, not rollback of a committed effect.
    /// The synchronous borrow ensures there is no API dispatcher left to join.
    pub fn cancel(
        &mut self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
    ) -> Result<()> {
        self.authenticate(credential, scope, true)?;
        let intent = self.intent(scope, op)?;
        if self.cancelled(&intent)? {
            return Ok(());
        }
        let authority =
            self.registry
                .authority(self.gate, credential, scope, BindingRole::Drive)?;
        let value = Value::Text(op.as_str().into()).to_json();
        self.append(
            &child("api-cancel", op)?,
            CANCEL,
            scope,
            &value,
            &authority.guard,
            authority
                .report
                .actor()
                .policy()
                .expires_at()
                .map(|t| t.as_millis()),
        )?;
        Ok(())
    }

    pub(super) fn dispatchable(&self, intent: &Intent) -> Result<()> {
        if self.cancelled(intent)? {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
    pub(super) fn effect_row(&self, op: &OperationId) -> Result<Option<i64>> {
        row_outcome(self.registry.store().reconcile_operation(op))
    }
}

pub(super) fn row_outcome(outcome: MutationOutcome) -> Result<Option<i64>> {
    match outcome {
        MutationOutcome::Committed { rows, .. } => {
            let row = rows
                .first()
                .and_then(|r| r.first())
                .ok_or(Error::Invalid("receipt row"))?;
            let row: i64 = number(row)?;
            if row <= 0 {
                return Err(Error::Invalid("receipt row"));
            }
            Ok(Some(row))
        }
        MutationOutcome::NotCommitted { error, .. } => {
            // Only the receipt barrier's explicit absence is noncommit. Other
            // errors are never converted to missing history or permission.
            if matches!(&error, crate::storage::StorageError::SqliteFailure { detail } if detail == "no receipt at writer barrier")
            {
                Ok(None)
            } else {
                Err(error.into())
            }
        }
        MutationOutcome::Conflict { .. } => Err(Error::Conflict("operation receipt conflict")),
        MutationOutcome::Unknown { operation, detail } => Err(Error::Unknown { operation, detail }),
    }
}
pub(super) fn actor_text(actor: &ActorContext) -> String {
    format!(
        "capability={};scope={};capgen={};issuer={}",
        binding::pct_encode(actor.capability()),
        binding::pct_encode(actor.ceiling().scope().as_str()),
        actor.cap_generation(),
        binding::pct_encode(actor.issuer())
    )
}
pub(super) fn operation(raw: &str) -> Result<OperationId> {
    if !raw.starts_with("api-") || raw.len() > 80 {
        return Err(Error::Invalid("API operation namespace/length"));
    }
    OperationId::parse(raw).map_err(|_| Error::Invalid("API operation"))
}
pub(super) fn child(prefix: &str, op: &OperationId) -> Result<OperationId> {
    operation(op.as_str())?;
    OperationId::parse(&format!("{prefix}-{}", op.as_str()))
        .map_err(|_| Error::Invalid("child operation"))
}
pub(super) fn encode(fields: &[String]) -> String {
    fields.iter().map(|s| format!("{}:{s}", s.len())).collect()
}
pub(super) fn decode(raw: &str, bytes: usize, fields: usize) -> Result<Vec<String>> {
    if raw.len() > bytes {
        return Err(Error::Limit("API encoded bytes"));
    }
    let mut rest = raw;
    let mut result = Vec::new();
    while !rest.is_empty() {
        if result.len() == fields {
            return Err(Error::Limit("API encoded fields"));
        }
        let (n, body) = rest.split_once(':').ok_or(Error::Invalid("API framing"))?;
        let n: usize = number(n)?;
        result.push(
            body.get(..n)
                .ok_or(Error::Invalid("API field boundary"))?
                .into(),
        );
        rest = body.get(n..).ok_or(Error::Invalid("API field boundary"))?;
    }
    Ok(result)
}
pub(super) fn number<T: std::str::FromStr + ToString>(raw: &str) -> Result<T> {
    let n: T = raw.parse().map_err(|_| Error::Invalid("API integer"))?;
    if n.to_string() != raw {
        return Err(Error::Invalid("API canonical integer"));
    }
    Ok(n)
}
pub(super) fn text_column(raw: &str) -> Result<String> {
    let json = binding::unquote_column(raw)?.ok_or(Error::Invalid("NULL API content"))?;
    match Value::from_json(&json).map_err(|_| Error::Invalid("API JSON"))? {
        Value::Text(raw) => Ok(raw),
        _ => Err(Error::Invalid("API content type")),
    }
}
