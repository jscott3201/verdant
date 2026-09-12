//! Mutation outcomes, explicit release and restored-counter guards.
//!
//! [`OperationOutcome`] distinguishes four states:
//!
//! - `Committed`: the mutation is known to have committed.
//! - `Refused`: the mutation is known *not* to have committed (explicit
//!   refusal reason; non-commit).
//! - `Conflict`: a competing revision/payload won; the caller must reconcile
//!   (zero affected rows is a conflict, not a success).
//! - `Unresolved`: the commit state is unknown (e.g. lost response). This is
//!   **not** rollback and **not** refusal: treating it as either would invent
//!   knowledge. Reconciliation uses the original [`crate::ids::OperationId`].
//!
//! [`Release`] is an explicit operation with its own identity and JSON
//! round-trip, not an optional value default and not inferred from missing
//! JSON or an observed NULL. There is intentionally no `Default` for
//! [`Release`].
//!
//! [`RecordIdentity`] guards restored counters: the generation is part of
//! identity, so a restored counter from a different generation never silently
//! identifies a different new record as an old one.

use super::ids::{InstalledId, OperationId, SourceGenerationId};
use super::Error;

/// Mutation outcome with explicit unknown handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationOutcome {
    Committed {
        operation: OperationId,
        detail: String,
    },
    Refused {
        operation: OperationId,
        reason: String,
    },
    Conflict {
        operation: OperationId,
        detail: String,
    },
    Unresolved {
        operation: OperationId,
        detail: String,
    },
}

impl OperationOutcome {
    /// True only for known commits.
    pub fn is_committed(&self) -> bool {
        matches!(self, OperationOutcome::Committed { .. })
    }

    /// True only for known refusals (explicit non-commit).
    pub fn is_refused(&self) -> bool {
        matches!(self, OperationOutcome::Refused { .. })
    }

    /// True only for conflicts.
    pub fn is_conflict(&self) -> bool {
        matches!(self, OperationOutcome::Conflict { .. })
    }

    /// True only for unresolved (unknown commit) outcomes.
    ///
    /// Unresolved is neither committed nor refused: see [`Self::is_committed`]
    /// and [`Self::is_refused`]. There is no `is_rolled_back`: unknown commit
    /// is not rollback.
    pub fn is_unresolved(&self) -> bool {
        matches!(self, OperationOutcome::Unresolved { .. })
    }

    /// Borrow the operation identity.
    pub fn operation(&self) -> &OperationId {
        match self {
            OperationOutcome::Committed { operation, .. }
            | OperationOutcome::Refused { operation, .. }
            | OperationOutcome::Conflict { operation, .. }
            | OperationOutcome::Unresolved { operation, .. } => operation,
        }
    }

    /// Frozen status string: `"committed"`, `"refused"`, `"conflict"`,
    /// `"unresolved"`.
    pub fn status(&self) -> &'static str {
        match self {
            OperationOutcome::Committed { .. } => "committed",
            OperationOutcome::Refused { .. } => "refused",
            OperationOutcome::Conflict { .. } => "conflict",
            OperationOutcome::Unresolved { .. } => "unresolved",
        }
    }

    /// Frozen JSON encoding (field order frozen):
    /// `{"status":"committed","operation":"op-1","detail":"..."}`.
    /// Refusals use the same `detail` key carrying the reason.
    pub fn to_json(&self) -> String {
        let (status, operation, detail) = match self {
            OperationOutcome::Committed { operation, detail } => {
                ("committed", operation.as_str(), detail.as_str())
            }
            OperationOutcome::Refused { operation, reason } => {
                ("refused", operation.as_str(), reason.as_str())
            }
            OperationOutcome::Conflict { operation, detail } => {
                ("conflict", operation.as_str(), detail.as_str())
            }
            OperationOutcome::Unresolved { operation, detail } => {
                ("unresolved", operation.as_str(), detail.as_str())
            }
        };
        format!(
            "{{\"status\":{},\"operation\":{},\"detail\":{}}}",
            super::json::quote(status),
            super::json::quote(operation),
            super::json::quote(detail)
        )
    }

    /// Decode from the frozen encoding; refuses malformed JSON,
    /// missing/unexpected fields, unknown statuses and invalid operation ids.
    pub fn from_json(text: &str) -> Result<OperationOutcome, Error> {
        let fields = super::json::parse_object(text)?;
        super::json::reject_unknown(&fields, &["status", "operation", "detail"])?;
        let status = super::json::get_string(&fields, "status")?;
        let operation_raw = super::json::get_string(&fields, "operation")?;
        let detail = super::json::get_string(&fields, "detail")?;
        let operation = OperationId::parse(&operation_raw)?;
        match status.as_str() {
            "committed" => Ok(OperationOutcome::Committed { operation, detail }),
            "refused" => Ok(OperationOutcome::Refused {
                operation,
                reason: detail,
            }),
            "conflict" => Ok(OperationOutcome::Conflict { operation, detail }),
            "unresolved" => Ok(OperationOutcome::Unresolved { operation, detail }),
            other => Err(Error::UnexpectedType {
                expected: "committed/refused/conflict/unresolved",
                got: other.to_string(),
            }),
        }
    }
}

/// Explicit release operation.
///
/// A release checks its intended target and request generation (checked by the
/// later writer owner; PR02 freezes the representation). It is constructed
/// explicitly via [`Release::new`] and round-trips through JSON; it is never
/// a `Default` value and never inferred from missing data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    operation: OperationId,
    target: InstalledId,
}

impl Release {
    /// Construct an explicit release of `target` under a fresh `operation`
    /// identity.
    pub fn new(operation: OperationId, target: InstalledId) -> Release {
        Release { operation, target }
    }

    /// Borrow the release operation identity.
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// Borrow the release target.
    pub fn target(&self) -> &InstalledId {
        &self.target
    }

    /// Frozen JSON encoding (field order frozen):
    /// `{"operation":"op-release-1","target":"ahu-1"}`.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"operation\":{},\"target\":{}}}",
            super::json::quote(self.operation.as_str()),
            super::json::quote(self.target.as_str())
        )
    }

    /// Decode from the frozen encoding; refuses malformed JSON,
    /// missing/unexpected fields and invalid ids.
    pub fn from_json(text: &str) -> Result<Release, Error> {
        let fields = super::json::parse_object(text)?;
        super::json::reject_unknown(&fields, &["operation", "target"])?;
        let operation_raw = super::json::get_string(&fields, "operation")?;
        let target_raw = super::json::get_string(&fields, "target")?;
        Ok(Release {
            operation: OperationId::parse(&operation_raw)?,
            target: InstalledId::parse(&target_raw)?,
        })
    }
}

/// Record identity coupling a source generation to a sequence counter.
///
/// Equality includes the generation: `RecordIdentity { generation: A, seq: 1 }`
/// never equals `RecordIdentity { generation: B, seq: 1 }`. A producer
/// restored from an older snapshot must reconcile a fresh generation before
/// new emission; old retained records keep their original ids. This type is
/// the representation guard: comparing only `seq` would silently identify a
/// different new record as an old one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordIdentity {
    generation: SourceGenerationId,
    seq: u64,
}

impl RecordIdentity {
    /// Construct a record identity in `generation` at sequence `seq`.
    pub fn new(generation: SourceGenerationId, seq: u64) -> RecordIdentity {
        RecordIdentity { generation, seq }
    }

    /// Borrow the generation.
    pub fn generation(&self) -> &SourceGenerationId {
        &self.generation
    }

    /// Borrow the sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// True only when both generation and sequence match.
    ///
    /// This is the same as `==`, spelled out so call sites cannot
    /// accidentally compare only the sequence.
    pub fn is_same_record(&self, other: &RecordIdentity) -> bool {
        self == other
    }

    /// Frozen JSON encoding (field order frozen):
    /// `{"generation":"gen-1","seq":"41"}` (sequence as a JSON string for
    /// exactness).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"generation\":{},\"seq\":{}}}",
            super::json::quote(self.generation.as_str()),
            super::json::quote(&self.seq.to_string())
        )
    }

    /// Decode from the frozen encoding; refuses malformed JSON,
    /// missing/unexpected fields and invalid generation/sequence text.
    pub fn from_json(text: &str) -> Result<RecordIdentity, Error> {
        let fields = super::json::parse_object(text)?;
        super::json::reject_unknown(&fields, &["generation", "seq"])?;
        let generation_raw = super::json::get_string(&fields, "generation")?;
        let seq_raw = super::json::get_string(&fields, "seq")?;
        let generation = SourceGenerationId::parse(&generation_raw)?;
        let seq: u64 = seq_raw.parse::<u64>().map_err(|_| Error::InvalidValue {
            what: "record-seq",
            value: seq_raw.clone(),
        })?;
        Ok(RecordIdentity::new(generation, seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(id: &str) -> OperationId {
        OperationId::parse(id).expect("operation id")
    }

    #[test]
    fn outcomes_are_four_distinct_states() {
        let committed = OperationOutcome::Committed {
            operation: operation("op-1"),
            detail: "applied".to_string(),
        };
        let refused = OperationOutcome::Refused {
            operation: operation("op-1"),
            reason: "ceiling denied".to_string(),
        };
        let conflict = OperationOutcome::Conflict {
            operation: operation("op-1"),
            detail: "expected revision lost".to_string(),
        };
        let unresolved = OperationOutcome::Unresolved {
            operation: operation("op-1"),
            detail: "response lost".to_string(),
        };
        assert!(committed.is_committed());
        assert!(!committed.is_refused());
        assert!(!committed.is_unresolved());
        assert!(refused.is_refused());
        assert!(!refused.is_committed());
        assert!(conflict.is_conflict());
        assert!(unresolved.is_unresolved());
        // Unknown commit is NOT a commit and NOT a refusal (and there is no
        // rollback query to misuse it as).
        assert!(!unresolved.is_committed());
        assert!(!unresolved.is_refused());
        assert!(!unresolved.is_conflict());
        assert_eq!(committed.status(), "committed");
        assert_eq!(refused.status(), "refused");
        assert_eq!(conflict.status(), "conflict");
        assert_eq!(unresolved.status(), "unresolved");
        // Same operation id across outcomes: reconciliation key is preserved.
        assert_eq!(committed.operation(), unresolved.operation());
    }

    #[test]
    fn outcome_json_round_trips() {
        let cases = vec![
            OperationOutcome::Committed {
                operation: operation("op-1"),
                detail: "applied".to_string(),
            },
            OperationOutcome::Refused {
                operation: operation("op-2"),
                reason: "ceiling denied".to_string(),
            },
            OperationOutcome::Conflict {
                operation: operation("op-3"),
                detail: "zero affected rows".to_string(),
            },
            OperationOutcome::Unresolved {
                operation: operation("op-4"),
                detail: "response lost; reconcile by op-4".to_string(),
            },
        ];
        for outcome in cases {
            let json = outcome.to_json();
            let back = OperationOutcome::from_json(&json).expect("round-trip");
            assert_eq!(back, outcome, "round-trip failed for {json}");
        }
        assert!(OperationOutcome::from_json(
            "{\"status\":\"rolled-back\",\"operation\":\"op-1\",\"detail\":\"x\"}"
        )
        .is_err());
        assert!(OperationOutcome::from_json("{\"status\":\"committed\"}").is_err());
    }

    #[test]
    fn release_is_explicit_with_round_trip() {
        let release = Release::new(
            operation("op-release-1"),
            InstalledId::parse("ahu-1").expect("ahu"),
        );
        assert_eq!(release.operation().as_str(), "op-release-1");
        assert_eq!(release.target().as_str(), "ahu-1");
        assert_eq!(
            release.to_json(),
            "{\"operation\":\"op-release-1\",\"target\":\"ahu-1\"}"
        );
        assert_eq!(
            Release::from_json("{\"operation\":\"op-release-1\",\"target\":\"ahu-1\"}")
                .expect("decode"),
            release
        );
        assert!(Release::from_json("{\"operation\":\"op-release-1\"}").is_err());
        // No Default impl exists by design: this would fail to compile if added.
        // `fn assert_no_default<T>() where T: Default {}` is intentionally not
        // instantiated for Release.
    }

    #[test]
    fn restored_counters_do_not_reuse_identity_across_generations() {
        let gen_a = SourceGenerationId::parse("gen-1").expect("gen-a");
        let gen_b = SourceGenerationId::parse("gen-2").expect("gen-b");
        let old = RecordIdentity::new(gen_a, 41);
        let restored_same_seq_new_gen = RecordIdentity::new(gen_b, 41);
        assert_eq!(old.generation().as_str(), "gen-1");
        assert_eq!(old.seq(), 41);
        assert_eq!(restored_same_seq_new_gen.generation().as_str(), "gen-2");
        // Same sequence, different generation: different records.
        assert_ne!(old, restored_same_seq_new_gen);
        assert!(!old.is_same_record(&restored_same_seq_new_gen));
        // Same generation and sequence: same record.
        let same = RecordIdentity::new(SourceGenerationId::parse("gen-1").expect("gen"), 41);
        assert_eq!(old, same);
        assert!(old.is_same_record(&same));
        // JSON preserves the generation, so restore cannot silently drop it.
        let json = old.to_json();
        assert_eq!(json, "{\"generation\":\"gen-1\",\"seq\":\"41\"}");
        assert_eq!(RecordIdentity::from_json(&json).expect("decode"), old);
        assert_ne!(
            RecordIdentity::from_json(&restored_same_seq_new_gen.to_json()).expect("decode"),
            old
        );
    }
}
