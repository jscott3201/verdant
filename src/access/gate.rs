//! Access mutations are optimistic guarded batches, never check-then-insert.
use super::context::{invalid, now_ms};
use super::state::State;
use super::*;
use crate::storage::sqlite::{MutationOutcome, PreparedMutation};

/// Direct-entry gate. Opening a store never creates an administrative credential.
#[derive(Debug)]
pub struct AccessGate {
    store: SqliteStore,
    issuer: IssuerId,
    user: UserId,
}

impl AccessGate {
    /// The only bootstrap-authority path. Marker, reviewer and publisher are
    /// one transaction; concurrent callers get one winner, never partial keys.
    /// Publisher's explicit synthetic admin policy covers scope-a/scope-b up to 2.
    pub fn bootstrap(
        db_path: &Path,
        settings: ConnectionSettings,
        bounds: StoreBounds,
        reason: &Reason,
    ) -> Result<(Self, BootstrapCredentials), AccessError> {
        let gate = Self::open(db_path, settings, bounds)?;
        let state = State::read(&gate.store)?;
        if state.count != 0 {
            return Err(already_bootstrapped());
        }
        let uniq = BOOTSTRAP_SEQ.fetch_add(1, Ordering::SeqCst);
        let credential = |cap: &str, id: &str| -> Result<Credential, AccessError> {
            Ok(Credential::new(
                CapabilityName::parse(cap)?,
                KeyId::parse(id)?,
                SyntheticKey::parse(&format!(
                    "synthetic-bootstrap-{}-{uniq}-{cap}",
                    std::process::id()
                ))?,
            ))
        };
        let creds = BootstrapCredentials {
            reviewer: credential(REVIEWER_CAP_TEXT, REVIEWER_KEY_TEXT)?,
            publisher: credential(PUBLISHER_CAP_TEXT, PUBLISHER_KEY_TEXT)?,
        };
        let marker = BootstrapRow {
            user: gate.user.as_str().into(),
            issuer: gate.issuer.as_str().into(),
            reason: reason.as_str().into(),
            generation: ACCESS_SCHEMA_GENERATION,
        };
        let scopes = vec![
            TrustedScope::parse("scope-a").map_err(|e| invalid(e.to_string()))?,
            TrustedScope::parse("scope-b").map_err(|e| invalid(e.to_string()))?,
        ];
        let reviewer = gate.issue_row(
            &creds.reviewer,
            &scopes[0],
            1,
            RoleKind::Reviewer,
            reason,
            &DisplayLabel::parse(SYNTHETIC_LABEL_TEXT)?,
            CapabilityPolicy::entry_only(None),
        );
        let publisher = gate.issue_row(
            &creds.publisher,
            &scopes[0],
            2,
            RoleKind::Publisher,
            reason,
            &DisplayLabel::parse(SYNTHETIC_LABEL_TEXT)?,
            CapabilityPolicy::administrator(scopes.clone(), 2, None)?,
        );
        let pending = gate.batch(
            &state,
            &[
                (
                    OP_BOOTSTRAP_TEXT,
                    gate.user.as_str(),
                    encode_bootstrap(&marker),
                ),
                (OP_ISSUE_TEXT, &reviewer.cap, encode_issue(&reviewer)),
                (OP_ISSUE_TEXT, &publisher.cap, encode_issue(&publisher)),
            ],
            None,
        )?;
        #[cfg(test)]
        testing::at(db_path, "bootstrap");
        match gate.submit(&pending) {
            Err(AccessError::Store(StorageError::Conflict { .. })) => {
                return Err(already_bootstrapped())
            }
            result => result?,
        }
        Ok((gate, creds))
    }

    /// Open/reopen storage without issuing keys, repairing policy, or a fallback.
    /// Empty/corrupt access state is refused by authentication, not silently filled.
    pub fn open(
        db_path: &Path,
        settings: ConnectionSettings,
        bounds: StoreBounds,
    ) -> Result<Self, AccessError> {
        assert_eq!(
            ACCESS_SCHEMA_GENERATION, SCHEMA_GENERATION,
            "access is bound to the PR03 0001 baseline"
        );
        let (store, _) =
            SqliteStore::open(db_path, settings, bounds).map_err(AccessError::Store)?;
        Ok(Self {
            store,
            issuer: frozen_issuer(),
            user: frozen_user(),
        })
    }

    pub fn store(&self) -> &SqliteStore {
        &self.store
    }
    pub fn db_path(&self) -> &Path {
        self.store.db_path()
    }
    /// Identity only: this value cannot authorize issuance.
    pub fn issuer(&self) -> &IssuerId {
        &self.issuer
    }
    pub fn user(&self) -> &UserId {
        &self.user
    }

    /// Issue an entry-only capability. The administrator credential is checked
    /// against its persisted scope/ceiling policy, not the caller's issuer text.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        capability: &CapabilityName,
        scope: &TrustedScope,
        ceiling: u8,
        role: RoleKind,
        key_id: &KeyId,
        key: &SyntheticKey,
        administrator: &Credential,
        reason: &Reason,
        label: &DisplayLabel,
    ) -> Result<Credential, AccessError> {
        self.issue_with_policy(
            capability,
            scope,
            ceiling,
            role,
            key_id,
            key,
            administrator,
            reason,
            label,
            &CapabilityPolicy::entry_only(None),
        )
    }

    /// Explicit expiry and administrative delegation. Every requested fact is
    /// bounded by the administrator; rotation carries these facts forward.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_with_policy(
        &self,
        capability: &CapabilityName,
        scope: &TrustedScope,
        ceiling: u8,
        role: RoleKind,
        key_id: &KeyId,
        key: &SyntheticKey,
        administrator: &Credential,
        reason: &Reason,
        label: &DisplayLabel,
        policy: &CapabilityPolicy,
    ) -> Result<Credential, AccessError> {
        let state = State::read(&self.store)?;
        let admin = state.checked(administrator, None, false)?;
        let bound = CredentialCeiling::new(scope.clone(), ceiling).map_err(|e| {
            AccessError::InvalidInput {
                what: "ceiling",
                detail: e.to_string(),
            }
        })?;
        admin.policy.authorize(&bound, policy)?;
        policy.require_live(now_ms()?)?;
        if state
            .issues
            .iter()
            .any(|row| row.cap == capability.as_str())
        {
            return Err(already_bootstrapped());
        }
        let credential = Credential::new(capability.clone(), key_id.clone(), key.clone());
        let row = self.issue_row(
            &credential,
            scope,
            ceiling,
            role,
            reason,
            label,
            policy.clone(),
        );
        let expires = earliest(admin.policy.expires_at_ms, policy.expires_at_ms);
        let pending = self.batch(
            &state,
            &[(OP_ISSUE_TEXT, &row.cap, encode_issue(&row))],
            expires,
        )?;
        #[cfg(test)]
        testing::at(self.db_path(), "issue");
        self.submit(&pending)?;
        Ok(credential)
    }

    /// Old-key revoke and successor issue commit together, guarded by the exact
    /// generation/policy/revocation snapshot. Losers never issue a second successor.
    pub fn rotate(
        &self,
        current: &Credential,
        new_key_id: &KeyId,
        new_key: &SyntheticKey,
        reason: &Reason,
    ) -> Result<Credential, AccessError> {
        let state = State::read(&self.store)?;
        let mut row = state.checked(current, None, true)?;
        let next = row
            .capgen
            .checked_add(1)
            .ok_or_else(|| AccessError::GenerationOverflow {
                capability: row.cap.clone(),
            })?;
        if state
            .issues
            .iter()
            .any(|r| r.cap == row.cap && r.key_id == new_key_id.as_str())
        {
            return Err(AccessError::InvalidInput {
                what: "key-id",
                detail: "rotation requires a fresh key identity".into(),
            });
        }
        let revoke = self.revoke_row(&row, reason);
        row.capgen = next;
        row.key_id = new_key_id.as_str().into();
        row.key_fp = new_key.fingerprint();
        row.reason = reason.as_str().into();
        let pending = self.batch(
            &state,
            &[
                (OP_REVOKE_TEXT, &row.cap, encode_revoke(&revoke)),
                (OP_ISSUE_TEXT, &row.cap, encode_issue(&row)),
            ],
            row.policy.expires_at_ms,
        )?;
        #[cfg(test)]
        testing::at(self.db_path(), "rotate");
        self.submit(&pending)?;
        Ok(Credential::new(
            current.capability.clone(),
            new_key_id.clone(),
            new_key.clone(),
        ))
    }

    /// Recorded self-revocation, revalidated at the same boundary as its write.
    pub fn revoke(&self, current: &Credential, reason: &Reason) -> Result<(), AccessError> {
        let state = State::read(&self.store)?;
        let row = state.checked(current, None, false)?;
        let revoke = self.revoke_row(&row, reason);
        let pending = self.batch(
            &state,
            &[(OP_REVOKE_TEXT, &row.cap, encode_revoke(&revoke))],
            row.policy.expires_at_ms,
        )?;
        #[cfg(test)]
        testing::at(self.db_path(), "revoke");
        self.submit(&pending)
    }

    /// Authenticate into an access-constructed actor snapshot. No raw key is
    /// exposed in the result. An actor snapshot cannot authorize a later mutation.
    pub fn authenticate(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
    ) -> Result<ActorContext, AccessError> {
        let credential = match credential {
            Some(credential) => credential,
            None => {
                eprintln!("verdant access refuses anonymous entry [anonymous-denied] (named ceiling/key required; local-only)");
                return Err(AccessError::AnonymousDenied {
                    detail: "anonymous entry is refused; present a named capability credential"
                        .into(),
                });
            }
        };
        ActorContext::from_checked(State::read(&self.store)?.checked(
            credential,
            Some(scope),
            false,
        )?)
    }

    pub fn enter_review(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
    ) -> Result<EnterReport, AccessError> {
        self.enter(credential, scope, RoleKind::Reviewer)
    }
    pub fn enter_publish(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
    ) -> Result<EnterReport, AccessError> {
        self.enter(credential, scope, RoleKind::Publisher)
    }
    fn enter(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        required: RoleKind,
    ) -> Result<EnterReport, AccessError> {
        let actor = self.authenticate(credential, scope)?;
        let level = match required {
            RoleKind::Reviewer => REQUIRED_REVIEW_CEILING,
            RoleKind::Publisher => REQUIRED_PUBLISH_CEILING,
        };
        if actor.ceiling().level() < level {
            return Err(AccessError::CeilingExceeded {
                have: actor.ceiling().level(),
                required: level,
            });
        }
        match (actor.role(), required) {
            (RoleKind::Publisher, RoleKind::Reviewer)
            | (RoleKind::Publisher, RoleKind::Publisher)
            | (RoleKind::Reviewer, RoleKind::Reviewer) => {}
            (RoleKind::Reviewer, RoleKind::Publisher) => {
                return Err(AccessError::RoleDenied {
                    have: "reviewer".into(),
                    required: "publisher".into(),
                })
            }
        }
        Ok(actor.report())
    }

    pub fn is_revoked(
        &self,
        capability: &CapabilityName,
        key_id: &KeyId,
    ) -> Result<bool, AccessError> {
        Ok(State::read(&self.store)?
            .revokes
            .iter()
            .any(|r| r.cap == capability.as_str() && r.key_id == key_id.as_str()))
    }
    pub fn bootstrap_reason(&self) -> Result<String, AccessError> {
        let state = State::read(&self.store)?;
        state.require_bootstrapped()?;
        Ok(state.bootstraps[0].reason.clone())
    }
    pub fn label_of(&self, capability: &CapabilityName) -> Result<String, AccessError> {
        Ok(State::read(&self.store)?
            .latest(capability.as_str())?
            .label
            .clone())
    }
    pub fn issue_reason(&self, capability: &CapabilityName) -> Result<String, AccessError> {
        Ok(State::read(&self.store)?
            .latest(capability.as_str())?
            .reason
            .clone())
    }
    pub fn revocation_reason(
        &self,
        capability: &CapabilityName,
        key_id: &KeyId,
    ) -> Result<Option<String>, AccessError> {
        Ok(State::read(&self.store)?
            .revokes
            .iter()
            .find(|r| r.cap == capability.as_str() && r.key_id == key_id.as_str())
            .map(|r| r.reason.clone()))
    }
    pub fn admission_count(&self) -> Result<u64, AccessError> {
        Ok(State::read(&self.store)?.count as u64)
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_row(
        &self,
        credential: &Credential,
        scope: &TrustedScope,
        ceiling: u8,
        role: RoleKind,
        reason: &Reason,
        label: &DisplayLabel,
        policy: CapabilityPolicy,
    ) -> IssueRow {
        IssueRow {
            cap: credential.capability.as_str().into(),
            scope: scope.as_str().into(),
            ceiling,
            role: role.as_str().into(),
            key_id: credential.key_id.as_str().into(),
            key_fp: credential.key.fingerprint(),
            issuer: self.issuer.as_str().into(),
            capgen: 1,
            user: self.user.as_str().into(),
            reason: reason.as_str().into(),
            label: label.as_str().into(),
            policy,
        }
    }
    fn revoke_row(&self, row: &IssueRow, reason: &Reason) -> RevokeRow {
        RevokeRow {
            cap: row.cap.clone(),
            key_id: row.key_id.clone(),
            capgen: row.capgen,
            issuer: self.issuer.as_str().into(),
            reason: reason.as_str().into(),
        }
    }

    fn batch(
        &self,
        state: &State,
        records: &[(&str, &str, String)],
        expires: Option<i64>,
    ) -> Result<PreparedMutation, AccessError> {
        let mut body = String::new();
        if let Some(end) = expires {
            body.push_str(&format!("CREATE TEMP TABLE access_live(ok INTEGER NOT NULL CONSTRAINT access_guard_live CHECK(ok=1)); INSERT INTO access_live VALUES(CASE WHEN CAST(unixepoch('subsec') * 1000 AS INTEGER) < {end} THEN 1 ELSE 0 END); "));
        }
        let mut payload_bytes = 0usize;
        for (index, (operation, entity, descriptor)) in records.iter().enumerate() {
            OperationId::parse(operation).map_err(|e| invalid(e.to_string()))?;
            InstalledId::parse(entity).map_err(|e| invalid(e.to_string()))?;
            let value = Value::Text(descriptor.clone()).to_json();
            payload_bytes = payload_bytes
                .checked_add(value.len())
                .ok_or_else(|| invalid("batch size overflow"))?;
            let times = synthetic_times();
            let record = synthetic_record((state.count + index + 1) as u64);
            body.push_str(&format!(
                "INSERT INTO outbox(operation, entity, sensor, value_json, unit, source_ms, receipt_ms, ingestion_ms, generation, seq, status, claimed_by, created_nanos) VALUES ({op}, {entity}, {sensor}, {value}, {unit}, '{source}', '{receipt}', '{ingestion}', {generation}, '{seq}', 'queued', NULL, CAST(unixepoch('subsec') * 1000000000 AS TEXT)); INSERT INTO derived_marks(entity, dirty, checked_generation) VALUES ({entity}, 1, 0) ON CONFLICT(entity) DO UPDATE SET dirty=1; ",
                op=sql_quote(operation), entity=sql_quote(entity), sensor=sql_quote(frozen_sensor().as_str()), value=sql_quote(&value), unit=sql_quote(access_unit().as_str()),
                source=times.source().as_millis(), receipt=times.receipt().as_millis(), ingestion=times.ingestion().as_millis(), generation=sql_quote(record.generation().as_str()), seq=record.seq()));
            #[cfg(test)]
            if *operation == OP_BOOTSTRAP_TEXT {
                body.push_str(testing::after_marker(self.db_path()));
            }
        }
        self.store
            .prepare_guarded_batch(&state.guard, &body, payload_bytes)
            .map_err(AccessError::Store)
    }

    fn submit(&self, pending: &PreparedMutation) -> Result<(), AccessError> {
        match self.store.submit(pending) {
            MutationOutcome::Committed { .. } => Ok(()),
            MutationOutcome::NotCommitted {
                error: StorageError::SqliteFailure { detail },
                ..
            } if detail.contains("CHECK constraint failed: access_guard_unchanged") => {
                Err(AccessError::Store(StorageError::Conflict {
                    detail: "access state changed at mutation boundary".into(),
                }))
            }
            MutationOutcome::NotCommitted {
                error: StorageError::SqliteFailure { detail },
                ..
            } if detail.contains("CHECK constraint failed: access_guard_live") => {
                Err(AccessError::PolicyDenied {
                    detail: "credential expired at mutation boundary".into(),
                })
            }
            MutationOutcome::NotCommitted { error, .. } => Err(AccessError::Store(error)),
            MutationOutcome::Conflict { detail, .. } => {
                Err(AccessError::Store(StorageError::Conflict { detail }))
            }
            MutationOutcome::Unknown { operation, detail } => {
                Err(AccessError::MutationUnknown { operation, detail })
            }
        }
    }
}

fn already_bootstrapped() -> AccessError {
    AccessError::AlreadyBootstrapped {
        detail: "admission identity already exists; never overwrite or re-bootstrap".into(),
    }
}
fn earliest(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}
