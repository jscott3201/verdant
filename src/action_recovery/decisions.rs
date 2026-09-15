//! Pure recovery decision table: no I/O, no locks, no network, no SQL.
//!
//! Each function maps already-observed inputs (existing outcome, expiry,
//! freshness, protocol, generation, identity, or boolean gates) to a verdict.
//! All durable, frozen-profile, and transport checks stay delegated to the
//! owning modules in [`super::reconcile`]; this table never re-derives them.
//! Every match is exhaustive so a new variant breaks the build, not behavior.

use super::{RecoveryError, Result};
use crate::action_dispatch::ProtocolResult;
use crate::action_expiry::ExpiryState;
use crate::domain::outcomes::RecordIdentity;
use crate::observation::time::Freshness;
use crate::storage::sqlite::MutationOutcome;

/// Commit-boundary verdict for a forced exit around the handoff.
///
/// `NotCommitted` is known rollback before COMMIT dispatch: nothing was
/// admitted and the caller may retry as new work. `UnknownNeedsReconcile`
/// is a forced exit after commit dispatch (or a lost response): the commit
/// state is unknown, the original identities persist, and the caller must
/// reconcile those identities rather than resend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitVerdict {
    Committed,
    NotCommitted,
    UnknownNeedsReconcile,
    ConflictNeedsReconcile,
}

/// Classify a storage mutation outcome without touching durable state.
pub fn classify_commit(outcome: &MutationOutcome) -> CommitVerdict {
    match outcome {
        MutationOutcome::Committed { .. } => CommitVerdict::Committed,
        MutationOutcome::NotCommitted { .. } => CommitVerdict::NotCommitted,
        MutationOutcome::Unknown { .. } => CommitVerdict::UnknownNeedsReconcile,
        MutationOutcome::Conflict { .. } => CommitVerdict::ConflictNeedsReconcile,
    }
}

/// Caller-cancellation verdict. A cooperative cancel never proves the owner
/// stopped: the caller must join/reap the owned lower-layer work or report
/// the run as unresolved. Dropping a handle detaches it; it does not stop it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelVerdict {
    /// Cancel observed before handoff completion; no script, no capture.
    CancelledBeforeHandoff,
    /// Cancel requested but the owned task is still running: join/reap it
    /// (harness stop accounting) or report unresolved. Absence is not
    /// permission.
    NeedsJoinOrReap,
    /// Owned work was joined/reaped and the stop was observed.
    JoinedStopped,
}

/// Pure cancellation classification from two observed booleans.
pub fn classify_cancellation(cancel_requested: bool, owner_joined: bool) -> CancelVerdict {
    match (cancel_requested, owner_joined) {
        (false, _) => CancelVerdict::JoinedStopped,
        (true, true) => CancelVerdict::JoinedStopped,
        (true, false) => CancelVerdict::NeedsJoinOrReap,
    }
}

/// Peer-acceptance verdict. Only a confirmed wire outcome counts as peer
/// acceptance. Every other protocol outcome — including remote errors,
/// rejects, aborts, timeouts, invalid replies, and transport failures — is
/// NOT acceptance: the result stays UNKNOWN-or-definitive-error for
/// reconcile, and the caller must never resend on uncertainty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAcceptance {
    Accepted,
    NotAcceptedNeedsReconcile,
}

/// Classify a protocol result for recovery. Timeout and any abort map to
/// `NotAcceptedNeedsReconcile` with the `uncertain-not-resend` policy; remote
/// errors and rejects are definitive peer answers (still with readbacks)
/// but never acceptance unless confirmed.
pub fn classify_peer_protocol(protocol: &ProtocolResult) -> PeerAcceptance {
    match protocol {
        ProtocolResult::Confirmed => PeerAcceptance::Accepted,
        ProtocolResult::RemoteError { .. }
        | ProtocolResult::Reject(_)
        | ProtocolResult::Abort(_)
        | ProtocolResult::Timeout
        | ProtocolResult::InvalidReply
        | ProtocolResult::TransportFailure => PeerAcceptance::NotAcceptedNeedsReconcile,
    }
}

/// Journal/peer ordering verdict. The journal result must never precede peer
/// acceptance: an admitted row proves intent was journaled, never that the
/// peer accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderingVerdict {
    JournalMayFollowPeer,
    JournalMustNotPrecedePeer,
}

/// Pure ordering gate: journal announcement may follow only an accepted peer.
pub fn check_peer_accepted_before_journal(
    peer_accepted: bool,
    journal_announced: bool,
) -> Result<OrderingVerdict> {
    match (peer_accepted, journal_announced) {
        (true, _) => Ok(OrderingVerdict::JournalMayFollowPeer),
        (false, false) => Ok(OrderingVerdict::JournalMustNotPrecedePeer),
        (false, true) => Err(RecoveryError::Conflict {
            detail: "journal result must never precede peer acceptance; reconcile peer first".to_string(),
        }),
    }
}

/// Later-conflicting-request verdict. Later requests that conflict with a
/// retained generation wait or require the qualified recovery procedure
/// (reconcile peer state plus transport ownership first). Quiescence claimed
/// from a dropped handle or an expired lease is refused: absence is not
/// permission. Retained actions are never replayed as new work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictWait {
    Wait,
    QualifiedRecoveryRequired,
}

/// How the caller claims the old owner went quiet. Only an observed
/// join/reap counts; handle drops and lease expiries prove nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiescenceClaim {
    ObservedJoin,
    HandleDropped,
    LeaseExpired,
}

/// Decide what a later conflicting request must do. Pure: all inputs are
/// caller-observed booleans plus the quiescence claim.
pub fn assess_conflicting_request(
    peer_reconciled: bool,
    transport_owned: bool,
    qualified_recovery_done: bool,
    quiescence: QuiescenceClaim,
) -> Result<ConflictWait> {
    match quiescence {
        QuiescenceClaim::HandleDropped | QuiescenceClaim::LeaseExpired => {
            Err(RecoveryError::Conflict {
                detail: "no quiescence from dropped handles or expired leases; reconcile peer state and transport ownership first".to_string(),
            })
        }
        QuiescenceClaim::ObservedJoin => match (peer_reconciled, transport_owned) {
            (false, _) | (_, false) => Ok(ConflictWait::Wait),
            (true, true) => {
                if qualified_recovery_done {
                    Ok(ConflictWait::QualifiedRecoveryRequired)
                } else {
                    Ok(ConflictWait::Wait)
                }
            }
        },
    }
}

/// Restored-backup verdict. REFUSE STALE: a restored old journal never
/// overwrites newer state. Same-ID-different-content and wrong-store both
/// refuse as conflict; a stale generation refuses as stale; only an exact
/// ledger match preserves intact state. Old obligations keep their old IDs;
/// new emission needs a new producer generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupVerdict {
    IntactPreserve,
    ConflictSameIdDifferentContent,
    StaleGenerationRefuse,
    WrongStoreConflict,
}

/// Pure backup classification from observed comparisons. No file I/O here;
/// callers supply the comparisons from durable reads.
pub fn verify_backup(
    store_identity_matches: bool,
    same_id_content_matches: bool,
    restored_generation: u32,
    current_generation: u32,
) -> BackupVerdict {
    if !store_identity_matches {
        return BackupVerdict::WrongStoreConflict;
    }
    if !same_id_content_matches {
        return BackupVerdict::ConflictSameIdDifferentContent;
    }
    let stale = restored_generation != current_generation;
    if stale {
        BackupVerdict::StaleGenerationRefuse
    } else {
        BackupVerdict::IntactPreserve
    }
}

/// Map a backup verdict to a typed refusal or to intact preservation.
pub fn require_intact_backup(verdict: BackupVerdict) -> Result<()> {
    match verdict {
        BackupVerdict::IntactPreserve => Ok(()),
        BackupVerdict::ConflictSameIdDifferentContent => Err(RecoveryError::Conflict {
            detail: "restored journal reuses an operation identity with different content".to_string(),
        }),
        BackupVerdict::StaleGenerationRefuse => Err(RecoveryError::Conflict {
            detail: "restored journal generation is stale; REFUSE STALE, keep old obligations with old IDs".to_string(),
        }),
        BackupVerdict::WrongStoreConflict => Err(RecoveryError::Conflict {
            detail: "restored journal belongs to a different store".to_string(),
        }),
    }
}

/// Map an exact stale-generation comparison to the typed stale refusal.
/// Checked ordering only; no wrapping and no guessing.
pub fn require_current_generation(expected: u32, current: u32) -> Result<()> {
    if expected == current {
        Ok(())
    } else {
        Err(RecoveryError::StaleGeneration { expected, current })
    }
}

/// Subsequent-observation verdict. Preservation is by full
/// [`RecordIdentity`] equality (generation plus sequence). Comparing only
/// the sequence, or treating equal slot values as ownership proof, is
/// refused by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationVerdict {
    SameRecord,
    DifferentRecord,
}

/// Full-identity comparison. Thin delegation to [`RecordIdentity`]; never a
/// sequence-only comparison.
pub fn classify_observation(expected: &RecordIdentity, found: &RecordIdentity) -> ObservationVerdict {
    if expected.is_same_record(found) {
        ObservationVerdict::SameRecord
    } else {
        ObservationVerdict::DifferentRecord
    }
}

/// Require the full identity to match before treating a later observation as
/// the same record. A restored counter from a different generation never
/// silently identifies a new record as an old one.
pub fn require_same_record(expected: &RecordIdentity, found: &RecordIdentity) -> Result<()> {
    match classify_observation(expected, found) {
        ObservationVerdict::SameRecord => Ok(()),
        ObservationVerdict::DifferentRecord => Err(RecoveryError::Conflict {
            detail: "observation identity differs (generation is part of identity); seq alone never identifies".to_string(),
        }),
    }
}

/// Equal slot values are never ownership proof. This function exists so the
/// rule is callable and testable; it always reports `false`.
pub fn slot_value_proves_ownership() -> bool {
    false
}

/// Clock-gate verdict helper: combine the already-assessed expiry and
/// freshness inputs into the SET/cancel/NULL decision without re-deriving
/// either assessment. Delegates the frozen 900s/5s horizon to the existing
/// expiry gate.
pub fn decide_set_allowed_from_assessed(
    expiry: &ExpiryState,
    freshness: Freshness,
) -> Result<()> {
    crate::action_expiry::decide_set_allowed(expiry, freshness).map_err(RecoveryError::from)
}
