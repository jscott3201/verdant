//! One bounded snapshot supplies both authentication and an exact SQL guard.
//! The guard compares all authorization-bearing bytes under BEGIN IMMEDIATE;
//! any intervening issue/revoke/policy edit invalidates the entire mutation.
use super::context::{invalid, now_ms};
use super::*;

pub(super) struct State {
    pub issues: Vec<IssueRow>,
    pub revokes: Vec<RevokeRow>,
    pub bootstraps: Vec<BootstrapRow>,
    pub count: usize,
    pub guard: String,
}

impl State {
    pub fn read(store: &SqliteStore) -> Result<Self, AccessError> {
        let limit = u64::from(store.bounds().max_replay_rows) + 1;
        let rows = store.exec_script(&format!(
            "SELECT id, quote(operation), quote(entity), quote(value_json) FROM outbox WHERE operation LIKE 'access-%' ORDER BY id LIMIT {limit};"
        )).map_err(AccessError::Store)?;
        if rows.len() > store.bounds().max_replay_rows as usize {
            return Err(invalid(
                "access history exceeds bounded replay horizon; no truncated authorization",
            ));
        }
        let mut state = Self {
            issues: Vec::new(),
            revokes: Vec::new(),
            bootstraps: Vec::new(),
            count: rows.len(),
            guard: format!(
                "(SELECT COUNT(*) FROM outbox WHERE operation LIKE 'access-%') = {}",
                rows.len()
            ),
        };
        for cols in rows {
            if cols.len() != 4 {
                return Err(invalid("admission scan requires four columns"));
            }
            let id: i64 = cols[0]
                .parse()
                .map_err(|_| invalid("admission id unreadable"))?;
            let text =
                |i: usize| unquote_column(&cols[i])?.ok_or_else(|| invalid("NULL admission field"));
            let operation = text(1)?;
            let entity = text(2)?;
            let value_json = text(3)?;
            let Value::Text(descriptor) =
                Value::from_json(&value_json).map_err(|e| invalid(e.to_string()))?
            else {
                return Err(invalid("admission value is not text"));
            };
            let (kind, fields) = decode_descriptor(&descriptor)?;
            let anchor = match (operation.as_str(), kind.as_str()) {
                (OP_BOOTSTRAP_TEXT, "bootstrap") => {
                    let row = decode_bootstrap(&fields)?;
                    let anchor = row.user.clone();
                    state.bootstraps.push(row);
                    anchor
                }
                (OP_ISSUE_TEXT, "issue") => {
                    let row = decode_issue(&fields)?;
                    if state.issues.iter().any(|r| {
                        r.cap == row.cap && (r.capgen == row.capgen || r.key_id == row.key_id)
                    }) {
                        return Err(invalid("duplicate capability generation or key identity"));
                    }
                    let anchor = row.cap.clone();
                    state.issues.push(row);
                    anchor
                }
                (OP_REVOKE_TEXT, "revoke") => {
                    let row = decode_revoke(&fields)?;
                    let anchor = row.cap.clone();
                    state.revokes.push(row);
                    anchor
                }
                _ => return Err(invalid("admission operation/kind mismatch")),
            };
            if anchor != entity {
                return Err(invalid("admission entity/descriptor mismatch"));
            }
            state.guard.push_str(&format!(" AND EXISTS(SELECT 1 FROM outbox WHERE id={id} AND operation={} AND entity={} AND value_json={})",
                sql_quote(&operation), sql_quote(&entity), sql_quote(&value_json)));
        }
        Ok(state)
    }

    pub fn require_bootstrapped(&self) -> Result<(), AccessError> {
        if self.count == 0 {
            return Err(AccessError::NotBootstrapped {
                detail: "no admission records; bootstrap first".into(),
            });
        }
        if self.bootstraps.len() != 1
            || self.bootstraps[0].user != SYNTHETIC_USER_TEXT
            || self.bootstraps[0].issuer != BOOTSTRAP_ISSUER_TEXT
            || ![REVIEWER_CAP_TEXT, PUBLISHER_CAP_TEXT]
                .iter()
                .all(|cap| self.issues.iter().any(|row| row.cap == *cap))
        {
            return Err(invalid(
                "incomplete or inconsistent bootstrap; no fallback minting",
            ));
        }
        Ok(())
    }

    pub fn latest(&self, cap: &str) -> Result<&IssueRow, AccessError> {
        self.issues
            .iter()
            .filter(|r| r.cap == cap)
            .max_by_key(|r| r.capgen)
            .ok_or_else(|| AccessError::UnknownCapability {
                capability: cap.into(),
            })
    }

    pub fn checked(
        &self,
        cred: &Credential,
        scope: Option<&TrustedScope>,
        rotating: bool,
    ) -> Result<IssueRow, AccessError> {
        self.require_bootstrapped()?;
        let latest = self.latest(cred.capability.as_str())?;
        let matched = self
            .issues
            .iter()
            .find(|r| r.cap == cred.capability.as_str() && r.key_id == cred.key_id.as_str())
            .ok_or_else(|| AccessError::ForgedCredential {
                detail: "key was never issued for this capability".into(),
            })?;
        if matched.issuer != BOOTSTRAP_ISSUER_TEXT {
            return Err(AccessError::UnknownIssuer {
                issuer: matched.issuer.clone(),
            });
        }
        if matched.user != SYNTHETIC_USER_TEXT {
            return Err(invalid("issued user does not match bootstrap identity"));
        }
        if matched.key_fp != cred.key.fingerprint() {
            return Err(AccessError::ForgedCredential {
                detail: "key material does not match the issued fingerprint".into(),
            });
        }
        if let Some(scope) = scope {
            if scope.as_str() != matched.scope {
                return Err(AccessError::ScopeDenied {
                    expected: matched.scope.clone(),
                    presented: scope.as_str().into(),
                });
            }
        }
        // Rotation reports a concurrent winner as stale. Entry retains its
        // revoked-first diagnostic. Both facts come from this same snapshot.
        let stale = || AccessError::StaleGeneration {
            capability: matched.cap.clone(),
            presented: matched.capgen,
            current: latest.capgen,
        };
        if rotating && matched.capgen != latest.capgen {
            return Err(stale());
        }
        if self
            .revokes
            .iter()
            .any(|r| r.cap == matched.cap && r.key_id == matched.key_id)
        {
            return Err(AccessError::RevokedCredential {
                capability: matched.cap.clone(),
                key: matched.key_id.clone(),
            });
        }
        if matched.capgen != latest.capgen {
            return Err(stale());
        }
        matched.policy.require_live(now_ms()?)?;
        Ok(matched.clone())
    }
}
