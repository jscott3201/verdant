//! Pure publication decision table: no I/O, no locks, no network, no SQL.
//!
//! Each function maps already-observed inputs (an [`ImpactDiff`], explicit
//! operator exclusion, revocation reads, retirement reads, or per-target
//! keys) to a verdict. All durable, frozen-profile, and transport checks
//! stay delegated to the owning modules in [`super::publication`]; this
//! table never re-derives them. Every match is exhaustive so a new variant
//! breaks the build, not behavior.

use super::{PublicationError, Result};
use crate::accept::ImpactDiff;

/// Whole-publication impact gate. Cosmetic (label-only) edits preserve
/// unaffected state; any material route/target/unit/role/slot/policy/
/// binding/facts/provenance change blocks the affected new handoffs until
/// the new publication is accepted and activated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImpactGate {
    /// Only cosmetic (label-only) differences: unaffected handoffs proceed.
    Preserved,
    /// Material differences: the affected new handoff is blocked.
    Blocked { detail: String },
}

impl ImpactGate {
    pub fn is_preserved(&self) -> bool {
        match self {
            Self::Preserved => true,
            Self::Blocked { .. } => false,
        }
    }

    pub fn require_preserved(&self) -> Result<()> {
        match self {
            Self::Preserved => Ok(()),
            Self::Blocked { detail } => Err(PublicationError::Blocked {
                detail: detail.clone(),
            }),
        }
    }
}

/// Assess a whole-publication diff: cosmetic-only (same bindings, labels may
/// differ, no added/removed/invalidated keys, no provenance change) preserves;
/// anything else blocks until accepted.
pub fn assess_impact(diff: &ImpactDiff) -> ImpactGate {
    if diff.added.is_empty()
        && diff.removed.is_empty()
        && diff.invalidated.is_empty()
        && !diff.provenance_changed
    {
        ImpactGate::Preserved
    } else {
        ImpactGate::Blocked {
            detail: format!(
                "material change blocks new handoffs until accepted: added={} removed={} invalidated={} provenance_changed={}",
                diff.added.len(),
                diff.removed.len(),
                diff.invalidated.len(),
                diff.provenance_changed,
            ),
        }
    }
}

/// Assess one target within a whole-publication diff. An unaffected target
/// (in `preserved`, optionally also in `cosmetic`, absent from
/// added/removed/invalidated, and no publication-wide provenance change)
/// stays preserved even when another target is blocked.
pub fn assess_target_impact(diff: &ImpactDiff, target: &str) -> ImpactGate {
    if target.is_empty() {
        return ImpactGate::Blocked {
            detail: "empty target key never identifies an unaffected handoff".to_string(),
        };
    }
    if diff.added.contains(target)
        || diff.removed.contains(target)
        || diff.invalidated.contains(target)
        || diff.provenance_changed
    {
        return ImpactGate::Blocked {
            detail: format!(
                "target '{target}' affected by material change; block until accepted"
            ),
        };
    }
    if diff.preserved.contains(target) {
        ImpactGate::Preserved
    } else {
        ImpactGate::Blocked {
            detail: format!("target '{target}' not in preserved set; block until accepted"),
        }
    }
}

/// Manual old-writer exclusion for takeover. Constructed ONLY by an explicit
/// operator call with a validated reason; independently effective once
/// present. Never file-lock/heartbeat/replica-count/generation/lost-hub
/// fencing. Never automatic: no `Default`, no `From<String>`, no background
/// task. The durable CAS behind it is the existing revocation rows plus
/// generation advance plus binding retire, already guarded by the owning
/// tickets — this value is the explicit operator gate checked pre-handoff
/// alongside content/generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OldWriterExclusion {
    operator: String,
    excluded_actor: String,
    reason: String,
}

impl OldWriterExclusion {
    /// Explicit operator exclusion of one named old writer. All three fields
    /// are required; empty, over-long, control-character, or sentinel values
    /// are refused, never defaulted.
    pub fn exclude(operator: &str, excluded_actor: &str, reason: &str) -> Result<Self> {
        let operator = check_token("operator", operator)?;
        let excluded_actor = check_token("excluded actor", excluded_actor)?;
        if reason.is_empty() || reason.len() > 256 {
            return Err(PublicationError::Invalid("exclusion reason 1..=256"));
        }
        if reason.chars().any(char::is_control) {
            return Err(PublicationError::Invalid("exclusion reason control"));
        }
        Ok(Self { operator, excluded_actor, reason: reason.to_string() })
    }

    pub fn operator(&self) -> &str {
        &self.operator
    }
    pub fn excluded_actor(&self) -> &str {
        &self.excluded_actor
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// True only for the exact named old writer. Comparison is exact;
    /// exclusion never widens to other actors.
    pub fn excludes(&self, actor: &str) -> bool {
        self.excluded_actor == actor
    }
}

fn check_token(what: &'static str, raw: &str) -> Result<String> {
    if raw.is_empty() || raw.len() > 128 {
        return Err(PublicationError::InvalidDetail {
            what,
            detail: "expects 1..=128 chars".to_string(),
        });
    }
    let ok = raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
    if !ok {
        return Err(PublicationError::InvalidDetail {
            what,
            detail: "alphanumeric plus -_./: only".to_string(),
        });
    }
    if raw.contains('\x1f') || raw.contains('\n') || raw.contains('\r') {
        return Err(PublicationError::InvalidDetail {
            what,
            detail: "framing characters refused".to_string(),
        });
    }
    if raw == "VERDANT_BEGIN" || raw == "VERDANT_DATA" || raw == "VERDANT_END" {
        return Err(PublicationError::InvalidDetail {
            what,
            detail: "sentinel refused".to_string(),
        });
    }
    Ok(raw.to_string())
}

/// Independently effective exclusion check, run pre-handoff alongside
/// content/generation. `None` means no takeover is active and excludes
/// nothing; `Some` refuses exactly its named old writer even when every
/// other check would pass. Never automatic, never widened.
pub fn check_not_excluded(exclusion: Option<&OldWriterExclusion>, actor: &str) -> Result<()> {
    match exclusion {
        None => Ok(()),
        Some(gate) => {
            if gate.excludes(actor) {
                Err(PublicationError::Excluded {
                    detail: format!(
                        "old writer '{actor}' excluded by '{}': {}",
                        gate.operator(),
                        gate.reason(),
                    ),
                })
            } else {
                Ok(())
            }
        }
    }
}

/// Pre-handoff revocation ordering: a revocation read before the handoff
/// prevents send. Callers perform the long revocation read
/// (`AccessGate::is_revoked` / `enter_publish`) before any ticket and pass
/// the observed boolean here; no I/O happens in this gate.
pub fn check_pre_handoff_not_revoked(is_revoked: bool, actor: &str) -> Result<()> {
    match is_revoked {
        false => Ok(()),
        true => Err(PublicationError::Revoked {
            detail: format!("credential for '{actor}' revoked before handoff; send prevented"),
        }),
    }
}

/// Old-target pin for replacement hardware: an already-attempted obligation
/// stays attached to its old physical target. Pure: callers supply the
/// admitted equipment plus the attempted replacement equipment.
pub fn require_same_equipment(admitted_equipment: &str, attempted_equipment: &str) -> Result<()> {
    if admitted_equipment.is_empty() || attempted_equipment.is_empty() {
        return Err(PublicationError::Invalid("equipment identity"));
    }
    if admitted_equipment == attempted_equipment {
        Ok(())
    } else {
        Err(PublicationError::Pinned {
            detail: format!(
                "old obligation pinned to '{admitted_equipment}'; release cannot target replacement '{attempted_equipment}'"
            ),
        })
    }
}

/// Replacement-address gate from already-observed retirement reads. A reused
/// address (`is_retired` on the old id, or `needs_reassessment` on the new
/// id) plus a binding-revision mismatch refuses the new handoff until fresh
/// qualification/acceptance. Pure: callers supply the registry reads.
pub fn check_replacement_gate(
    is_retired: bool,
    needs_reassessment: bool,
    admitted_binding_revision: u32,
    current_binding_revision: u32,
) -> Result<()> {
    if is_retired || needs_reassessment {
        if admitted_binding_revision != current_binding_revision {
            return Err(PublicationError::Pinned {
                detail: format!(
                    "reused address needs fresh qualification/acceptance: admitted binding revision {admitted_binding_revision} != current {current_binding_revision}"
                ),
            });
        }
        return Err(PublicationError::Pinned {
            detail: "reused address needs fresh qualification/acceptance even at equal revisions".to_string(),
        });
    }
    if admitted_binding_revision != current_binding_revision {
        return Err(PublicationError::Blocked {
            detail: format!(
                "binding revision changed since admission: admitted {admitted_binding_revision} != current {current_binding_revision}; block until accepted"
            ),
        });
    }
    Ok(())
}

/// Checked successor generation for publication bookkeeping. Overflow
/// refuses instead of wrapping.
pub fn next_generation(expected: u32) -> Result<u32> {
    expected.checked_add(1).ok_or(PublicationError::Invalid("target generation overflow"))
}

/// Per-target isolation key: the slow-scope shape. Guards are per
/// `(scope, equipment)` pair only; there is never a building-wide lock, so
/// a slow unrelated native publication cannot hold every controller
/// transaction hostage. Pure key construction for evidence, not a lock.
pub fn target_scope_key(scope: &str, equipment: &str) -> Result<String> {
    if scope.is_empty() || equipment.is_empty() {
        return Err(PublicationError::Invalid("scope/equipment identity"));
    }
    if scope.len() > 128 || equipment.len() > 128 {
        return Err(PublicationError::Invalid("scope/equipment length"));
    }
    Ok(format!("{scope}\x1f{equipment}"))
}

/// True when the two per-target keys name different physical targets and
/// therefore share no per-target guard.
pub fn is_unrelated_target(first: &str, second: &str) -> bool {
    first != second
}
