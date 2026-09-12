//! Authentication facts, not caller-constructed scope/role assertions.
use super::*;

/// Persisted issuance policy. Constructing a policy requests authority; only
/// an authenticated administrator can grant it, within its own persisted bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityPolicy {
    pub(super) scopes: Vec<TrustedScope>,
    pub(super) admin_ceiling: Option<u8>,
    pub(super) expires_at_ms: Option<i64>,
}

impl CapabilityPolicy {
    /// No administrative privilege. `None` is an explicit non-expiring policy.
    pub fn entry_only(expires_at: Option<UnixMillis>) -> Self {
        Self {
            scopes: Vec::new(),
            admin_ceiling: None,
            expires_at_ms: expires_at.map(|t| t.as_millis()),
        }
    }

    /// Request bounded administrative privilege; no wildcard or implicit scopes.
    pub fn administrator(
        scopes: Vec<TrustedScope>,
        ceiling: u8,
        expires_at: Option<UnixMillis>,
    ) -> Result<Self, AccessError> {
        if scopes.is_empty() || scopes.len() > 16 || ceiling > MAX_CEILING_LEVEL {
            return Err(AccessError::InvalidInput {
                what: "policy",
                detail: "admin policy requires 1..=16 scopes and a bounded ceiling".into(),
            });
        }
        let mut unique = scopes.iter().map(TrustedScope::as_str).collect::<Vec<_>>();
        unique.sort_unstable();
        unique.dedup();
        if unique.len() != scopes.len() {
            return Err(AccessError::InvalidInput {
                what: "policy",
                detail: "duplicate administrative scope".into(),
            });
        }
        Ok(Self {
            scopes,
            admin_ceiling: Some(ceiling),
            expires_at_ms: expires_at.map(|t| t.as_millis()),
        })
    }

    pub fn administrative_scopes(&self) -> &[TrustedScope] {
        &self.scopes
    }
    pub fn administrative_ceiling(&self) -> Option<u8> {
        self.admin_ceiling
    }
    pub fn expires_at(&self) -> Option<UnixMillis> {
        self.expires_at_ms.map(UnixMillis::new)
    }

    pub(super) fn require_live(&self, now: i64) -> Result<(), AccessError> {
        if let Some(end) = self.expires_at_ms {
            if now >= end {
                return Err(AccessError::ExpiredCredential { expires_at_ms: end });
            }
        }
        Ok(())
    }

    pub(super) fn authorize(
        &self,
        bound: &CredentialCeiling,
        child: &Self,
    ) -> Result<(), AccessError> {
        let have = self
            .admin_ceiling
            .ok_or(AccessError::AdministrationDenied)?;
        if !self.scopes.contains(bound.scope()) {
            return Err(AccessError::ScopeDenied {
                expected: self
                    .scopes
                    .iter()
                    .map(TrustedScope::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                presented: bound.scope().as_str().into(),
            });
        }
        if bound.level() > have {
            return Err(AccessError::CeilingExceeded {
                have,
                required: bound.level(),
            });
        }
        if child
            .admin_ceiling
            .is_some_and(|level| level > have || level > bound.level())
            || child
                .scopes
                .iter()
                .any(|scope| !self.scopes.contains(scope))
            || self
                .expires_at_ms
                .is_some_and(|end| child.expires_at_ms.is_none_or(|child_end| child_end > end))
        {
            return Err(AccessError::PolicyDenied {
                detail: "delegation exceeds administrator policy or requested ceiling".into(),
            });
        }
        Ok(())
    }
}

/// Stable authenticated actor references for downstream joins. Fields and
/// construction are access-private; parsing a scope/issuer/role cannot mint one.
/// This is evidence at authentication time, NOT a reusable mutation permission.
/// Mutations always authenticate the credential again and guard the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorContext {
    row: IssueRow,
    bound: CredentialCeiling,
    role: RoleKind,
}

impl ActorContext {
    pub(super) fn from_checked(row: IssueRow) -> Result<Self, AccessError> {
        let scope = TrustedScope::parse(&row.scope).map_err(|e| invalid(e.to_string()))?;
        let bound =
            CredentialCeiling::new(scope, row.ceiling).map_err(|e| invalid(e.to_string()))?;
        let role = RoleKind::parse(&row.role).map_err(|e| invalid(e.to_string()))?;
        Ok(Self { row, bound, role })
    }
    pub fn user(&self) -> &str {
        &self.row.user
    }
    pub fn issuer(&self) -> &str {
        &self.row.issuer
    }
    pub fn capability(&self) -> &str {
        &self.row.cap
    }
    pub fn key_id(&self) -> &str {
        &self.row.key_id
    }
    pub fn cap_generation(&self) -> u32 {
        self.row.capgen
    }
    pub fn ceiling(&self) -> &CredentialCeiling {
        &self.bound
    }
    pub fn role(&self) -> RoleKind {
        self.role
    }
    pub fn policy(&self) -> &CapabilityPolicy {
        &self.row.policy
    }

    pub(super) fn report(self) -> EnterReport {
        EnterReport {
            capability: self.row.cap.clone(),
            scope: self.row.scope.clone(),
            ceiling: self.row.ceiling,
            role: self.row.role.clone(),
            cap_generation: self.row.capgen,
            actor: self,
        }
    }
}

pub(super) fn invalid(detail: impl Into<String>) -> AccessError {
    AccessError::InvalidRecord {
        detail: detail.into(),
    }
}

pub(super) fn now_ms() -> Result<i64, AccessError> {
    #[cfg(test)]
    if let Some(now) = testing::now() {
        return Ok(now);
    }
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid("clock precedes Unix epoch"))?;
    i64::try_from(time.as_millis()).map_err(|_| invalid("clock exceeds supported timestamp"))
}
