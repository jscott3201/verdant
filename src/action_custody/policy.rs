//! Pure custody decision table: no I/O, no locks, no network, no SQL.
//!
//! Each function maps already-observed inputs (an explicit hold set, an
//! inspection scope pair, a revocation read, a transfer-narrow request, or a
//! cleanup name) to a verdict. All durable, frozen-profile, and transport
//! checks stay delegated to the owning modules in [`super::custody`]; this
//! table never re-derives them. Every match is exhaustive so a new variant
//! breaks the build, not behavior.

use super::{CustodyError, Result};
use std::collections::BTreeMap;

/// Scoped-hold kind. Both variants block only the held scope; neither
/// escalates to other scopes, generations, or protected priorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldKind {
    /// Active maintenance hold on the scope.
    Active,
    /// Masked-intent hold: a masked intent is still held on its own
    /// generation; masking never escalates and never authorizes protected
    /// priorities.
    Masked,
}

impl HoldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active-hold",
            Self::Masked => "masked-hold",
        }
    }
}

/// One explicit scoped hold: the held scope plus its kind and reason.
/// Constructed ONLY by an explicit operator call; never automatic, never a
/// physical lockout. Pending rows are kept, never erased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyHold {
    scope: String,
    kind: HoldKind,
    reason: String,
}

impl CustodyHold {
    /// Explicit operator hold of one scope. Scope and reason are required;
    /// empty, over-long, control-character, or sentinel values are refused,
    /// never defaulted.
    pub fn hold(scope: &str, kind: HoldKind, reason: &str) -> Result<Self> {
        let scope = check_scope_token(scope)?;
        if reason.is_empty() || reason.len() > 256 {
            return Err(CustodyError::Invalid("hold reason 1..=256"));
        }
        if reason.chars().any(char::is_control) {
            return Err(CustodyError::Invalid("hold reason control"));
        }
        Ok(Self { scope, kind, reason: reason.to_string() })
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn kind(&self) -> HoldKind {
        self.kind
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// True only for the exact held scope. Comparison is exact; a hold never
    /// widens to other scopes.
    pub fn holds(&self, scope: &str) -> bool {
        self.scope == scope
    }
}

fn check_scope_token(raw: &str) -> Result<String> {
    if raw.is_empty() || raw.len() > 128 {
        return Err(CustodyError::InvalidDetail {
            what: "hold scope",
            detail: "expects 1..=128 chars".to_string(),
        });
    }
    let ok = raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
    if !ok {
        return Err(CustodyError::InvalidDetail {
            what: "hold scope",
            detail: "alphanumeric plus -_./: only".to_string(),
        });
    }
    if raw.contains('\x1f') || raw.contains('\n') || raw.contains('\r') {
        return Err(CustodyError::InvalidDetail {
            what: "hold scope",
            detail: "framing characters refused".to_string(),
        });
    }
    if raw == "VERDANT_BEGIN" || raw == "VERDANT_DATA" || raw == "VERDANT_END" {
        return Err(CustodyError::InvalidDetail {
            what: "hold scope",
            detail: "sentinel refused".to_string(),
        });
    }
    Ok(raw.to_string())
}

/// Explicit in-memory hold set. Holds are per-scope only; there is no
/// `release_all`, no all-slot reset, and no building-wide lock. A held scope
/// blocks new handoffs on that scope while other scopes proceed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeHolds {
    held: BTreeMap<String, CustodyHold>,
}

impl ScopeHolds {
    pub fn new() -> Self {
        Self { held: BTreeMap::new() }
    }

    /// Hold one scope explicitly. Idempotent for the same scope (replaces the
    /// prior hold for that scope); never touches other scopes and never
    /// erases pending rows.
    pub fn hold(&mut self, scope: &str, kind: HoldKind, reason: &str) -> Result<()> {
        let hold = CustodyHold::hold(scope, kind, reason)?;
        self.held.insert(hold.scope().to_string(), hold);
        Ok(())
    }

    /// Release one scope explicitly. Idempotent: releasing an unheld scope
    /// succeeds without effect. There is deliberately no `release_all`.
    pub fn release(&mut self, scope: &str) -> Result<()> {
        if scope.is_empty() || scope.len() > 128 {
            return Err(CustodyError::Invalid("release scope 1..=128"));
        }
        self.held.remove(scope);
        Ok(())
    }

    /// True only when the exact scope is held.
    pub fn is_held(&self, scope: &str) -> bool {
        self.held.contains_key(scope)
    }

    /// Number of held scopes (for evidence; bounded by caller input).
    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Block new handoffs on a held scope. Other scopes proceed. Pending rows
    /// are kept; this gate never erases.
    pub fn check_not_held(&self, scope: &str) -> Result<()> {
        match self.held.get(scope) {
            None => Ok(()),
            Some(hold) => Err(CustodyError::Held {
                scope: scope.to_string(),
                detail: format!(
                    "{} '{}' blocks new handoffs, pending rows kept: {}",
                    hold.kind().as_str(),
                    hold.scope(),
                    hold.reason(),
                ),
            }),
        }
    }
}

/// Inspection visibility: a journal row is visible to a query only when its
/// scope exactly equals the queried scope. Cross-scope callers see nothing,
/// never another scope's row.
pub fn inspection_visible(row_scope: &str, query_scope: &str) -> bool {
    row_scope == query_scope
}

/// Pre-handoff revocation ordering: a revocation read before the handoff
/// prevents send. Callers perform the long revocation read
/// (`AccessGate::is_revoked` / `enter_publish`) before any ticket and pass
/// the observed boolean here; no I/O happens in this gate.
pub fn check_pre_handoff_not_revoked(is_revoked: bool, actor: &str) -> Result<()> {
    match is_revoked {
        false => Ok(()),
        true => Err(CustodyError::Revoked {
            detail: format!("credential for '{actor}' revoked before handoff; send prevented"),
        }),
    }
}

/// Transfer-narrow gate (TRANSFER NARROW): expired-actor obligations move to
/// an active permitted role via NEW admission only. All inputs are
/// already-observed: the old and new operation identities, the old and new
/// actor names, whether the old actor is excluded, and whether the new actor
/// is an active permitted role. Never rewrites actor/operation/attempt in
/// place; never broadens authority automatically; never orphans without
/// owner.
pub fn check_transfer_narrow(
    old_operation: &str,
    new_operation: &str,
    old_actor: &str,
    new_actor: &str,
    old_excluded: bool,
    new_is_permitted: bool,
) -> Result<()> {
    if old_operation.is_empty()
        || new_operation.is_empty()
        || old_actor.is_empty()
        || new_actor.is_empty()
    {
        return Err(CustodyError::Invalid("transfer identities non-empty"));
    }
    if old_operation.len() > 128 || new_operation.len() > 128 {
        return Err(CustodyError::Invalid("transfer operation length"));
    }
    if old_actor.len() > 128 || new_actor.len() > 128 {
        return Err(CustodyError::Invalid("transfer actor length"));
    }
    if old_operation == new_operation {
        return Err(CustodyError::Transfer {
            detail: "transfer requires a NEW admission OperationId; never rewrite operation in place".to_string(),
        });
    }
    if old_actor == new_actor {
        return Err(CustodyError::Transfer {
            detail: "transfer requires a distinct active actor; never rewrite actor in place".to_string(),
        });
    }
    if !old_excluded {
        return Err(CustodyError::Transfer {
            detail: "transfer requires exclusion of the old actor; old obligations keep old IDs until excluded".to_string(),
        });
    }
    if !new_is_permitted {
        return Err(CustodyError::Transfer {
            detail: "transfer requires an active permitted role; never broaden authority automatically, never orphan without owner".to_string(),
        });
    }
    Ok(())
}

/// Constrained-cleanup gate (CONSTRAINED): only explicit cancel of an
/// unattempted generation and admitted-NULL release exist as authorized
/// cleanup. Every other requested cleanup — including LOTO/emergency-stop
/// labeling, all-slot reset, actor-history deletion, broad permission
/// grants, and any notification/work/MCP bypass — is refused with limits
/// plus escalation, never promised release.
pub fn authorize_constrained_cleanup(request: &str) -> Result<()> {
    match request {
        "cancel-unattempted" | "admitted-null-release" => Ok(()),
        "loto" | "emergency-stop" | "all-slot-reset" | "delete-actor-history" | "broad-grant"
        | "notify-bypass" | "work-bypass" | "mcp-bypass" => Err(CustodyError::Constrained {
            detail: format!(
                "constrained cleanup refuses '{request}': no LOTO/emergency-stop labeling, no all-slot reset, no actor-history deletion, no broad grants, no notification/work/MCP bypass; escalate to owner via qualified recovery"
            ),
        }),
        _ => Err(CustodyError::Invalid("unknown cleanup request")),
    }
}

/// Equal slot values are never ownership proof. This function exists so the
/// rule is callable and testable; it always reports `false`.
pub fn slot_value_proves_ownership() -> bool {
    false
}

/// Checked successor generation. Overflow refuses instead of wrapping.
pub fn next_generation(expected: u32) -> Result<u32> {
    expected
        .checked_add(1)
        .ok_or(CustodyError::Invalid("target generation overflow"))
}
