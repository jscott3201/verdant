//! Slice-A lossless admission identity (factored from `mod.rs` to respect the
//! 700-line cap; `mod.rs` stays the owning writer, this module holds pure
//! helpers plus the additive 0005 ensure).
//!
//! Lossless identity: exact binary32 `wire_bits`, explicit `set` vs `release`
//! kind, release admission flag plus authorized release target. Presentation
//! `{:.4}` text stays display-only; handoffs compare identity, not rounded
//! text. Legacy 0004 rows (new columns NULL) remain readable via reconcile
//! but refuse for new handoffs as `admission-stale-payload` (no backfill).
//!
//! Pre/post generation note (traced, not ±1): `expected_generation` is the
//! pre-admission token observed before the CAS; `target_generation` is the
//! post-admission value (`expected + 1`, checked). Dispatch `verify_generation`
//! requires `Current.current_generation == expected` (no intervening admission),
//! not `target`. Replacement/release tracing lives with activation (see
//! publication); do not adjust by ±1 without that trace.
//!
//! TODO(SliceB-deferred, not in this PR): full durable lifecycle (attempt
//! progression, terminal/unresolved states, bounded outstanding, lost wake-up
//! recovery beyond identity), owned 6/hour enforcement, durable custody
//! predecessor link + target-equivalence.
//! failing-sketch: `Journal::admit` would need `attempt_state` transitions
//! (`admitted -> dispatched -> terminal`) with bounded outstanding and custody
//! link; sketch omitted here to avoid half-implementation.

use crate::accept::AcceptedRevision;
use crate::access::{RoleKind, REQUIRED_PUBLISH_CEILING};
use crate::action_preview::{Preview, DEADLINE_SECS, DURATION_SECS, PREVIEW_FORMAT, RATE_MAX_PER_HOUR};
use crate::binding;
use crate::domain::ids::{BindingRevision, InstalledId, OperationId};
use crate::domain::scope::TrustedScope;
use crate::runtime::bacnet::APDU_RETRIES;
use crate::storage::sqlite::{MutationOutcome, SqliteStore};
use crate::storage::{StorageError, MIGRATION_0005_SQL};
use super::{Result, WriterError};

/// Lossless action kind persisted for every Slice-A admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Set,
    Release,
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Release => "release",
        }
    }
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "set" => Some(Self::Set),
            "release" => Some(Self::Release),
            _ => None,
        }
    }
    pub fn from_preview(preview: &Preview) -> Self {
        if preview.release_admitted() {
            Self::Release
        } else {
            Self::Set
        }
    }
}

/// Lossless identity derived read-only from a preview (never re-derives).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub wire_bits: u32,
    pub kind: ActionKind,
    pub release_admitted: bool,
    pub release_target: InstalledId,
}

impl Identity {
    pub fn from_preview(preview: &Preview) -> Self {
        Self {
            wire_bits: preview.encoded().wire_bits(),
            kind: ActionKind::from_preview(preview),
            release_admitted: preview.release_admitted(),
            release_target: preview.release_target().clone(),
        }
    }
    pub fn identity_string(&self, preview: &Preview) -> String {
        preview.identity_bytes()
    }
}

pub(crate) fn check_ceiling(ceiling: u8, role: RoleKind) -> Result<()> {
    match role {
        RoleKind::Publisher => {
            if ceiling < REQUIRED_PUBLISH_CEILING {
                return Err(WriterError::Ceiling {
                    have: ceiling,
                    required: REQUIRED_PUBLISH_CEILING,
                });
            }
            Ok(())
        }
        RoleKind::Reviewer => Err(WriterError::Ceiling {
            have: ceiling,
            required: REQUIRED_PUBLISH_CEILING,
        }),
    }
}

pub(crate) fn check_actor(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Err(WriterError::Invalid("empty actor"));
    }
    if raw.len() > 128 {
        return Err(WriterError::Invalid("actor too long"));
    }
    let ok = raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
    if !ok {
        return Err(WriterError::Invalid("actor characters"));
    }
    if raw.contains('\x1f') || raw.contains('\n') || raw.contains('\r') {
        return Err(WriterError::Invalid("actor framing"));
    }
    if raw == "VERDANT_BEGIN" || raw == "VERDANT_DATA" || raw == "VERDANT_END" {
        return Err(WriterError::Invalid("actor sentinel"));
    }
    Ok(raw.to_string())
}

pub(crate) fn check_preview(preview: &Preview) -> Result<()> {
    if preview.format() != PREVIEW_FORMAT {
        return Err(WriterError::Invalid("preview format"));
    }
    if preview.is_reservation() || preview.is_dispatch() || preview.is_qualified() {
        return Err(WriterError::Invalid("preview is information only"));
    }
    if preview.timing().apdu_retries() != APDU_RETRIES {
        return Err(WriterError::Invalid("apdu_retries frozen"));
    }
    if preview.timing().duration_secs() != DURATION_SECS {
        return Err(WriterError::Invalid("duration 15min"));
    }
    if preview.timing().deadline_secs() != DEADLINE_SECS {
        return Err(WriterError::Invalid("deadline 5s"));
    }
    if preview.timing().rate_per_hour() != RATE_MAX_PER_HOUR {
        return Err(WriterError::Invalid("rate bound"));
    }
    // Lossless kind coherence: a release preview must admit NULL, a SET
    // preview must not. Swapped-kind handoffs refuse downstream as well.
    if preview.release_admitted() != matches!(ActionKind::from_preview(preview), ActionKind::Release) {
        return Err(WriterError::Invalid("release admission/kind mismatch"));
    }
    Ok(())
}

pub(crate) fn map_submit_error(error: StorageError) -> WriterError {
    match error {
        StorageError::SqliteFailure { ref detail }
            if detail.contains("UNIQUE constraint failed: action_journal.operation") =>
        {
            WriterError::Conflict {
                detail: "journal operation already recorded with this store".to_string(),
            }
        }
        StorageError::Conflict { detail } => WriterError::Conflict { detail },
        other => WriterError::Storage(other),
    }
}

/// Additive 0005 ensure: validate 0004 ledger then apply 0005 once. Preserves
/// `user_version=1`; never rewrites 0004; no backfill (legacy NULLs stay).
/// Slice-B: a 0006 ledger already contains 0005, so it is accepted as done.
pub(crate) fn ensure_0005(store: &SqliteStore) -> Result<()> {
    let rows = store.exec_script("SELECT generation FROM schema_migrations ORDER BY generation;")?;
    let generations: Vec<String> = rows.into_iter().filter_map(|r| r.into_iter().next()).collect();
    if generations == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string()]
        || generations == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string(), "6".to_string()] {
        return Ok(());
    }
    if generations != vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string()] {
        return Err(WriterError::Invalid("unsupported ledger for 0005 upgrade"));
    }
    let ticket = store.prepare_guarded_batch("1", MIGRATION_0005_SQL, MIGRATION_0005_SQL.len())?;
    match store.submit(&ticket) {
        MutationOutcome::Committed { .. } => Ok(()),
        MutationOutcome::NotCommitted { error, .. } => {
            let again = store.exec_script("SELECT generation FROM schema_migrations ORDER BY generation;")?;
            let again: Vec<String> = again.into_iter().filter_map(|r| r.into_iter().next()).collect();
            if again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string()]
                || again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string(), "6".to_string()] {
                Ok(())
            } else {
                Err(map_submit_error(error))
            }
        }
        MutationOutcome::Conflict { detail, .. } => {
            let again = store.exec_script("SELECT generation FROM schema_migrations ORDER BY generation;")?;
            let again: Vec<String> = again.into_iter().filter_map(|r| r.into_iter().next()).collect();
            if again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string()]
                || again == vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string(), "5".to_string(), "6".to_string()] {
                Ok(())
            } else {
                Err(WriterError::Conflict { detail })
            }
        }
        MutationOutcome::Unknown { operation, detail } => {
            Err(WriterError::Unknown { operation, detail })
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn admission_body_v2(
    operation: &OperationId,
    scope: &TrustedScope,
    equipment: &InstalledId,
    binding_revision: BindingRevision,
    accepted_revision: AcceptedRevision,
    expected_generation: u32,
    target_generation: u32,
    payload: &str,
    deadline_secs: u64,
    ceiling: u8,
    actor: &str,
    attempt: &OperationId,
    identity: &Identity,
    predecessor: Option<&OperationId>,
) -> String {
    let scope_q = binding::sql_quote(scope.as_str());
    let equip_q = binding::sql_quote(equipment.as_str());
    let op_q = binding::sql_quote(operation.as_str());
    let payload_q = binding::sql_quote(payload);
    let actor_q = binding::sql_quote(actor);
    let attempt_q = binding::sql_quote(attempt.as_str());
    let release_target_q = binding::sql_quote(identity.release_target.as_str());
    let binding_rev = binding_revision.as_u32();
    let accepted_rev = accepted_revision.get();
    let expected = expected_generation;
    let target = target_generation;
    let deadline = deadline_secs;
    let wire_bits = identity.wire_bits;
    let kind_q = binding::sql_quote(identity.kind.as_str());
    let rel_adm: u32 = u8::from(identity.release_admitted).into();
    let mut body = String::new();
    body.push_str(&format!(
        "CREATE TEMP TABLE admission_generation(ok INTEGER NOT NULL CONSTRAINT admission_generation CHECK(ok=1)); INSERT INTO admission_generation VALUES(CASE WHEN ((SELECT COALESCE((SELECT current_generation FROM action_targets WHERE scope={scope_q} AND equipment={equip_q}), 0)) = {expected}) THEN 1 ELSE 0 END);"
    ));
    // Owned 6/hour SET accounting (Slice B): enforced here under the writer
    // lock, anchored to durable `created`. Releases skip the guard (exempt).
    if identity.kind == ActionKind::Set {
        body.push_str(&super::rate::rate_guard_sql(scope, equipment));
    }
    body.push_str(&format!(
        "INSERT INTO action_journal(operation, scope, equipment, binding_revision, accepted_revision, expected_generation, target_generation, payload, deadline_secs, ceiling, actor, attempt, state, created, wire_bits, action_kind, release_admitted, release_target) VALUES ({op_q}, {scope_q}, {equip_q}, {binding_rev}, {accepted_rev}, {expected}, {target}, {payload_q}, {deadline}, {ceiling}, {actor_q}, {attempt_q}, 'admitted', CAST(strftime('%s','now') AS INTEGER), {wire_bits}, {kind_q}, {rel_adm}, {release_target_q});"
    ));
    body.push_str(&format!(
        "INSERT INTO action_targets(scope, equipment, current_generation) VALUES ({scope_q}, {equip_q}, {target}) ON CONFLICT(scope, equipment) DO UPDATE SET current_generation=excluded.current_generation;"
    ));
    // Durable lifecycle row plus predecessor obligation link in the same batch.
    body.push_str(&super::lifecycle::lifecycle_insert_sql(operation, attempt, predecessor));
    body
}

/// Parse nullable new-column text (`NULL`/empty => None) from the CLI envelope.
pub(crate) fn parse_nullable(raw: &str) -> Option<String> {
    if raw == "NULL" || raw.is_empty() {
        None
    } else if raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2 {
        // CLI `quote()`-wrapped text (release_target travels quoted).
        let inner = &raw[1..raw.len() - 1];
        Some(inner.replace("''", "'"))
    } else {
        Some(raw.to_string())
    }
}
