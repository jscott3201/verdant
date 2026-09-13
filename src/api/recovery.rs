//! Synthetic installation recovery only. Delegation is enforced by access's
//! persisted scope/ceiling policy, not host identity, a caller scope assertion,
//! or an API-local administrator secret. No key is stored in the API journal.
use super::{journal::*, *};
use crate::access::{
    CapabilityName, CapabilityPolicy, DisplayLabel, KeyId, Reason, RoleKind, SyntheticKey,
};

pub(super) const PREFIX: &str = "api-recovery-";

/// Closed recovery vocabulary: no policy, role, field command, SQL, shell, or
/// requested target scope can be supplied. Scope is authenticated separately.
pub enum RecoveryAction<'a> {
    /// A new entry-only synthetic publisher identity in this same scope. This
    /// does not overwrite access bootstrap markers or resurrect revoked keys.
    Rebootstrap { replacement: &'a Credential },
    /// Rotate this recovery account itself; policy is carried by access intact.
    Rotate {
        key_id: &'a KeyId,
        key: &'a SyntheticKey,
    },
}

impl Api<'_> {
    pub fn provision_recovery(
        &mut self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
        key_id: &KeyId,
        key: &SyntheticKey,
    ) -> Result<Credential> {
        let actor = self.authenticate(credential, scope, true)?;
        let owner = self.credential(credential)?;
        if actor.policy().administrative_ceiling().is_none() {
            return Err(crate::access::AccessError::AdministrationDenied.into());
        }
        if !actor.policy().administrative_scopes().contains(scope)
            || actor
                .policy()
                .administrative_ceiling()
                .is_none_or(|ceiling| ceiling < 2)
            || actor.policy().expires_at().is_some()
        {
            return Err(Error::RecoveryRestricted);
        }
        // The access bootstrap record and the verified scoped administrative
        // credential together are the proof. A reason string alone proves nothing.
        self.gate.bootstrap_reason()?;
        let name = CapabilityName::parse(&format!("{PREFIX}{}", scope.as_str()))?;
        let candidate = Credential::new(name, key_id.clone(), key.clone());
        let input = credential_input(&candidate);
        let event = self.remember(owner, scope, op, Kind::Provision, op, None, input, false)?;
        match self.gate.authenticate(Some(&candidate), scope) {
            Ok(actor) => {
                check_recovery(&actor, scope)?;
                if self.gate.issue_reason(candidate.capability())? != reason(op)?.as_str() {
                    return Err(Error::Conflict(
                        "recovery account belongs to another provision operation",
                    ));
                }
                return Ok(candidate);
            }
            Err(crate::access::AccessError::UnknownCapability { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        self.dispatchable(&event)?;
        Ok(self.gate.issue_with_policy(
            candidate.capability(),
            scope,
            2,
            RoleKind::Reviewer,
            key_id,
            key,
            owner,
            &reason(op)?,
            &DisplayLabel::parse("synthetic installation recovery")?,
            &CapabilityPolicy::administrator(vec![scope.clone()], 2, None)?,
        )?)
    }

    pub fn recover(
        &mut self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        op: &OperationId,
        action: RecoveryAction<'_>,
    ) -> Result<Credential> {
        let current = self.credential(credential)?;
        self.gate.bootstrap_reason()?;
        match action {
            RecoveryAction::Rebootstrap { replacement } => {
                let actor = self.gate.authenticate(Some(current), scope)?;
                check_recovery(&actor, scope)?;
                if replacement.capability().as_str().starts_with(PREFIX) {
                    return Err(Error::RecoveryRestricted);
                }
                let event = self.remember(
                    current,
                    scope,
                    op,
                    Kind::Recover,
                    op,
                    None,
                    credential_input(replacement),
                    true,
                )?;
                match self.gate.authenticate(Some(replacement), scope) {
                    Ok(child) => {
                        // A coincidentally existing credential is not recovery.
                        if child.role() != RoleKind::Publisher
                            || child.ceiling().level() != 2
                            || child.policy() != &CapabilityPolicy::entry_only(None)
                            || self.gate.issue_reason(replacement.capability())?
                                != reason(op)?.as_str()
                        {
                            return Err(Error::Conflict(
                                "replacement is not this recovery operation",
                            ));
                        }
                        return Ok(replacement.clone());
                    }
                    Err(crate::access::AccessError::UnknownCapability { .. }) => {}
                    Err(e) => return Err(e.into()),
                }
                self.dispatchable(&event)?;
                Ok(self.gate.issue(
                    replacement.capability(),
                    scope,
                    2,
                    RoleKind::Publisher,
                    replacement.key_id(),
                    replacement.key(),
                    current,
                    &reason(op)?,
                    &DisplayLabel::parse("synthetic recovered scope publisher")?,
                )?)
            }
            RecoveryAction::Rotate { key_id, key } => {
                let successor =
                    Credential::new(current.capability().clone(), key_id.clone(), key.clone());
                let input = encode(&[
                    current.capability().as_str().into(),
                    current.key_id().as_str().into(),
                    credential_input(&successor),
                ]);
                let (proof, completed) = match self.gate.authenticate(Some(current), scope) {
                    Ok(actor) => {
                        check_recovery(&actor, scope)?;
                        (current, false)
                    }
                    Err(original) => {
                        let old = self.intent(scope, op)?;
                        if old.kind != Kind::Rotate || old.request != input {
                            return Err(original.into());
                        }
                        let actor = self.gate.authenticate(Some(&successor), scope)?;
                        check_recovery(&actor, scope)?;
                        if self.gate.issue_reason(current.capability())? != reason(op)?.as_str()
                            || !self
                                .gate
                                .is_revoked(current.capability(), current.key_id())?
                        {
                            return Err(Error::Conflict(
                                "rotation successor does not prove this operation",
                            ));
                        }
                        (&successor, true)
                    }
                };
                let event = self.remember(proof, scope, op, Kind::Rotate, op, None, input, true)?;
                if completed {
                    return Ok(successor);
                }
                self.dispatchable(&event)?;
                Ok(self.gate.rotate(current, key_id, key, &reason(op)?)?)
            }
        }
    }
}
fn credential_input(credential: &Credential) -> String {
    // FNV is the existing synthetic verifier, not crypto or authority. Raw key
    // bytes never enter intent, diagnostics, SQL, or actor references.
    encode(&[
        credential.capability().as_str().into(),
        credential.key_id().as_str().into(),
        credential.key().fingerprint(),
    ])
}
fn reason(op: &OperationId) -> Result<Reason> {
    Ok(Reason::parse(&format!(
        "PR09 synthetic recovery operation {}",
        op.as_str()
    ))?)
}
fn check_recovery(actor: &ActorContext, scope: &TrustedScope) -> Result<()> {
    if actor.capability() != format!("{PREFIX}{}", scope.as_str())
        || actor.role() != RoleKind::Reviewer
        || actor.ceiling().level() != 2
        || actor.policy().administrative_scopes() != [scope.clone()]
        || actor.policy().administrative_ceiling() != Some(2)
        || actor.policy().expires_at().is_some()
    {
        return Err(Error::RecoveryRestricted);
    }
    Ok(())
}
