//! Join a fresh access report to a binding write, never treat the report as a
//! reusable permission. Access owns credential interpretation. The opaque access
//! history guard only detects change between authentication and writer admission.
use super::*;
use crate::access::{AccessGate, ActorContext, Credential, EnterReport};
use crate::domain::scope::TrustedScope;

pub(crate) struct Authority {
    pub report: EnterReport,
    pub guard: String,
}

impl BindingRegistry {
    pub(crate) fn authority(
        &self, gate: &AccessGate, credential: Option<&Credential>,
        scope: &TrustedScope, requested: BindingRole,
    ) -> Result<Authority, BindingError> {
        let path = |p: &std::path::Path| std::fs::canonicalize(p).map_err(|e| BindingError::InvalidRecord { detail: e.to_string() });
        if path(self.store.db_path())? != path(gate.db_path())? {
            return Err(BindingError::Conflict { detail: "access and binding must share the owning database".into() });
        }
        // Capture before authentication. Every byte consulted by access must
        // still exist when the binding row is written. No binding code decodes
        // keys, roles, policies, generations, or revocation records.
        let limit = u64::from(gate.store().bounds().max_replay_rows) + 1;
        let rows = self.store.exec_script(&format!(
            "SELECT id, quote(operation), quote(entity), quote(value_json) FROM outbox WHERE operation LIKE 'access-%' ORDER BY id LIMIT {limit};"
        )).map_err(BindingError::Store)?;
        if rows.len() as u64 == limit {
            return Err(BindingError::InvalidRecord { detail: "access history exceeds authentication horizon".into() });
        }
        let mut guard = format!("(SELECT COUNT(*) FROM outbox WHERE operation LIKE 'access-%')={}", rows.len());
        for row in rows {
            if row.len() != 4 { return Err(BindingError::InvalidRecord { detail: "access snapshot requires four columns".into() }); }
            let id: i64 = row[0].parse().map_err(|_| BindingError::InvalidRecord { detail: "invalid access row identity".into() })?;
            let text = |i: usize| unquote_column(&row[i])?.ok_or_else(|| BindingError::InvalidRecord { detail: "NULL access snapshot field".into() });
            guard.push_str(&format!(" AND EXISTS(SELECT 1 FROM outbox WHERE id={id} AND operation={} AND entity={} AND value_json={})", sql_quote(&text(1)?), sql_quote(&text(2)?), sql_quote(&text(3)?)));
        }
        let report = match requested {
            BindingRole::Sense => gate.enter_review(credential, scope),
            BindingRole::Drive => gate.enter_publish(credential, scope),
        }.map_err(|error| {
            let code = error.code();
            let detail = error.to_string();
            match error {
                crate::access::AccessError::ScopeDenied { expected, presented } => BindingError::ScopeDenied { expected, presented },
                crate::access::AccessError::CeilingExceeded { .. } | crate::access::AccessError::RoleDenied { .. } => BindingError::WrongRole { requested: requested.as_str().into(), detail },
                _ => BindingError::capability_denied(detail, code),
            }
        })?;
        Ok(Authority { report, guard })
    }
}

/// Reference bytes contain neither key identity, raw key, nor key fingerprint.
pub(crate) fn actor_fields(actor: &ActorContext) -> String {
    format!("capability={};scope={};capgen={};issuer={}", pct_encode(actor.capability()), pct_encode(actor.ceiling().scope().as_str()), actor.cap_generation(), pct_encode(actor.issuer()))
}

pub(crate) fn stored_actor(map: &std::collections::BTreeMap<String, String>) -> Result<String, BindingError> {
    let cap = require_field(map, "capability")?;
    let scope = require_field(map, "scope")?;
    let generation = require_field(map, "capgen")?;
    let issuer = require_field(map, "issuer")?;
    let bad = || BindingError::InvalidRecord { detail: "invalid stored actor reference".into() };
    crate::access::CapabilityName::parse(&cap).map_err(|_| bad())?;
    TrustedScope::parse(&scope).map_err(|_| bad())?;
    crate::access::IssuerId::parse(&issuer).map_err(|_| bad())?;
    let generation: u32 = generation.parse().map_err(|_| bad())?;
    if generation == 0 || map.contains_key("fp") || map.contains_key("key") || map.contains_key("key_id") { return Err(bad()); }
    Ok(format!("capability={};scope={};capgen={generation};issuer={}", pct_encode(&cap), pct_encode(&scope), pct_encode(&issuer)))
}
