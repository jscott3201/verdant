//! M01-PR07 binding history replay: rebuild registry state from `binding-*`
//! outbox rows.
//!
//! Replay is deterministic (`ORDER BY id`) and additive: retired records
//! stay readable, reassessment is re-derived from retired addresses, and
//! findings are rebuilt from their stored citable fields (no digest is
//! recomputed on replay; the stored record is the cited one).

use super::error::BindingError;
use super::proposal::{BindingRole, Feedback, ProposedBinding};
use super::records::{
    EndpointAddress, EndpointClass, EquipmentKind, EquipmentRecord, PointRecord, PropertyName,
    SourceRecord, SpaceRecord,
};
use super::registry::BindingRegistry;
use super::registry::{
    OP_EQUIPMENT_TEXT, OP_FINDING_TEXT, OP_POINT_TEXT, OP_PROPOSE_TEXT, OP_RETIRE_TEXT,
    OP_SOURCE_TEXT, OP_SPACE_TEXT,
};
use super::{require_field, split_descriptor, sql_quote, unquote_column};
use crate::domain::ids::{BindingRevision, InstalledId};
use crate::domain::scope::TrustedScope;
use crate::domain::values::Unit;
use std::collections::BTreeMap;

impl BindingRegistry {
    /// Explicitly full reconstruction. Never clamped to the observation horizon;
    /// storage transport limits refuse rather than returning partial truth.
    pub fn replay_full(&mut self) -> Result<(), BindingError> { self.replay() }

    pub(crate) fn replay(&mut self) -> Result<(), BindingError> {
        let rows = self.read_descriptors()?;
        self.equipment.clear();
        self.spaces.clear();
        self.sources.clear();
        self.points.clear();
        self.bindings.clear();
        self.findings.clear();
        self.retired.clear();
        self.retired_addrs.clear();
        self.reassessment.clear();
        self.revision = BindingRevision::PLACEHOLDER;
        self.sequence = 0;
        self.guard = format!("(SELECT COUNT(*) FROM outbox WHERE operation LIKE 'binding-%')={}", rows.len());
        let mut count = 0u64;
        for row in rows {
            let (operation, descriptor) = (&row.operation, &row.descriptor);
            if row.sequence != count + 1 { return Err(BindingError::InvalidRecord { detail: "binding history has a duplicate or missing sequence".into() }); }
            self.guard.push_str(&format!(" AND EXISTS(SELECT 1 FROM outbox WHERE id={} AND operation={} AND entity={} AND value_json={} AND seq={})", row.id, sql_quote(operation), sql_quote(&row.entity), sql_quote(&row.value_json), sql_quote(&row.sequence.to_string())));
            let map = split_descriptor(&descriptor)?;
            let version = require_field(&map, "v")?;
            if version != "2" {
                return Err(BindingError::InvalidRecord {
                    detail: format!("unsupported binding descriptor version '{version}'"),
                });
            }
            if super::writer::stored_revision(&map)? != self.revision {
                return Err(BindingError::InvalidRecord { detail: "binding row revision does not match durable predecessor".into() });
            }
            let kind = require_field(&map, "kind")?;
            match (operation.as_str(), kind.as_str()) {
                (OP_EQUIPMENT_TEXT, "equipment") => self.replay_equipment(&map)?,
                (OP_SPACE_TEXT, "space") => self.replay_space(&map)?,
                (OP_SOURCE_TEXT, "source") => self.replay_source(&map)?,
                (OP_POINT_TEXT, "point") => self.replay_point(&map)?,
                (OP_PROPOSE_TEXT, "propose") => self.replay_propose(&map)?,
                (OP_RETIRE_TEXT, "retire") => self.replay_retire(&map)?,
                (OP_FINDING_TEXT, "finding") => self.replay_finding(&map)?,
                _ => {
                    return Err(BindingError::InvalidRecord {
                        detail: format!("unexpected binding operation '{operation}' kind '{kind}'"),
                    })
                }
            }
            count = count.saturating_add(1);
        }
        self.sequence = count;
        Ok(())
    }

    pub(crate) fn replay_equipment(
        &mut self,
        map: &BTreeMap<String, String>,
    ) -> Result<(), BindingError> {
        let id = require_field(map, "id")?;
        let ekind = require_field(map, "ekind")?;
        let scope = require_field(map, "scope")?;
        let label = require_field(map, "label")?;
        let address = require_field(map, "address")?;
        let kind = EquipmentKind::parse(&ekind)?;
        let scope = TrustedScope::parse(&scope).map_err(|e| BindingError::InvalidRecord {
            detail: format!("stored equipment scope invalid: {e}"),
        })?;
        let record = EquipmentRecord::parse(&id, kind, scope, &label, &address)?;
        if self.retired_addrs.contains(record.address().as_str()) {
            self.reassessment.insert(id.clone());
        }
        self.equipment.insert(id, record);
        self.bump_revision();
        Ok(())
    }

    pub(crate) fn replay_space(
        &mut self,
        map: &BTreeMap<String, String>,
    ) -> Result<(), BindingError> {
        let id = require_field(map, "id")?;
        let scope = require_field(map, "scope")?;
        let label = require_field(map, "label")?;
        let scope = TrustedScope::parse(&scope).map_err(|e| BindingError::InvalidRecord {
            detail: format!("stored space scope invalid: {e}"),
        })?;
        let record = SpaceRecord::parse(&id, scope, &label)?;
        self.spaces.insert(id, record);
        self.bump_revision();
        Ok(())
    }

    pub(crate) fn replay_source(
        &mut self,
        map: &BTreeMap<String, String>,
    ) -> Result<(), BindingError> {
        let id = require_field(map, "id")?;
        let scope = require_field(map, "scope")?;
        let label = require_field(map, "label")?;
        let scope = TrustedScope::parse(&scope).map_err(|e| BindingError::InvalidRecord {
            detail: format!("stored source scope invalid: {e}"),
        })?;
        let record = SourceRecord::parse(&id, scope, &label)?;
        self.sources.insert(id, record);
        self.bump_revision();
        Ok(())
    }

    pub(crate) fn replay_point(
        &mut self,
        map: &BTreeMap<String, String>,
    ) -> Result<(), BindingError> {
        let equipment = require_field(map, "equipment")?;
        let property = require_field(map, "property")?;
        let scope = require_field(map, "scope")?;
        let unit = require_field(map, "unit")?;
        let eclass = require_field(map, "eclass")?;
        let scope = TrustedScope::parse(&scope).map_err(|e| BindingError::InvalidRecord {
            detail: format!("stored point scope invalid: {e}"),
        })?;
        let class = EndpointClass::parse(&eclass)?;
        let record = PointRecord::parse(&equipment, &property, scope, &unit, class)?;
        self.points
            .insert(format!("{equipment}:{property}"), record);
        self.bump_revision();
        Ok(())
    }

    pub(crate) fn replay_propose(
        &mut self,
        map: &BTreeMap<String, String>,
    ) -> Result<(), BindingError> {
        super::authority::stored_actor(map)?;
        let binding = decode_propose(map)?;
        self.bindings.push(binding);
        self.bump_revision();
        Ok(())
    }

    pub(crate) fn replay_retire(
        &mut self,
        map: &BTreeMap<String, String>,
    ) -> Result<(), BindingError> {
        let id = require_field(map, "id")?;
        let address = require_field(map, "address")?;
        let _reason = require_field(map, "reason")?;
        self.retired.insert(id);
        self.retired_addrs.insert(address);
        self.bump_revision();
        Ok(())
    }

    pub(crate) fn replay_finding(
        &mut self,
        map: &BTreeMap<String, String>,
    ) -> Result<(), BindingError> {
        let bad = |detail: String| BindingError::InvalidRecord { detail };
        let fid_raw = require_field(map, "fid")?;
        let fid = super::findings::FindingId::parse(&fid_raw)
            .map_err(|e| bad(format!("stored finding id invalid: {e}")))?;
        let generation_raw = require_field(map, "generation")?;
        let generation: u32 = generation_raw
            .parse::<u32>()
            .map_err(|_| bad(format!("finding generation unreadable: '{generation_raw}'")))?;
        let revision_raw = require_field(map, "revision")?;
        let revision: u32 = revision_raw
            .parse::<u32>()
            .map_err(|_| bad(format!("finding revision unreadable: '{revision_raw}'")))?;
        let digest = require_field(map, "digest")?;
        if digest.is_empty() {
            return Err(bad("stored finding digest must not be empty".to_string()));
        }
        let summary = require_field(map, "summary")?;
        if summary.is_empty() {
            return Err(bad("stored finding summary must not be empty".to_string()));
        }
        let actor = super::authority::stored_actor(map)?;
        if generation != revision { return Err(bad("finding generation differs from revision".into())); }
        let _equipment = require_field(map, "equipment")?;
        let _property = require_field(map, "property")?;
        let finding = super::findings::Finding::from_stored(
            fid,
            generation,
            BindingRevision::new(revision),
            digest,
            summary,
            actor,
        );
        self.findings.push(finding);
        Ok(())
    }

    pub(crate) fn read_descriptors(&self) -> Result<Vec<HistoryRow>, BindingError> {
        let script = format!(
            "SELECT quote(operation), quote(entity), quote(value_json), id, seq FROM outbox WHERE operation LIKE {} ORDER BY id;",
            sql_quote("binding-%")
        );
        let rows = self
            .store
            .exec_script(&script)
            .map_err(BindingError::Store)?;
        decode_rows(rows)
    }

    /// Bounded observation, not a registry suitable for authorization. Returns
    /// newest rows since `since`, in durable order. Any omitted history makes
    /// `stale` explicit. An empty/expired window is a typed refusal.
    /// An incoherent horizon/output budget is `InvalidInput` before any read;
    /// the requested horizon is checked before the `max_replay_rows` clamp.
    pub fn replay_window(&self, since: crate::domain::clock::UnixMillis, horizon: u32) -> Result<ReplayWindow, BindingError> {
        read_window(&self.store, since, horizon)
    }

    /// Observe history without first constructing a full registry. This is the
    /// bounded entry point even when full reconstruction exceeds transport limits.
    /// Incoherent row budgets are `InvalidInput` before opening storage (including
    /// any child spawn). Byte limits, retries and data-dependent storage reports
    /// remain subject to the storage execution backstop, not a success guarantee.
    pub fn open_window(
        path: &std::path::Path, settings: crate::storage::ConnectionSettings,
        bounds: crate::storage::StoreBounds, since: crate::domain::clock::UnixMillis,
        horizon: u32,
    ) -> Result<ReplayWindow, BindingError> {
        admit_window(&bounds, horizon, true)?;
        #[cfg(test)]
        WINDOW_IO.with(|counts| { let (opens, reads) = counts.get(); counts.set((opens + 1, reads)); });
        let (store, _) = crate::storage::sqlite::SqliteStore::open(path, settings, bounds).map_err(BindingError::Store)?;
        read_window(&store, since, horizon)
    }
}

fn admit_window(bounds: &crate::storage::StoreBounds, horizon: u32, opening: bool) -> Result<(), BindingError> {
    if horizon == 0 { return Err(BindingError::InvalidInput { what: "replay horizon", detail: "horizon must be nonzero".into() }); }
    // Exact no-retry row inequality for the current R03 CLI encoding:
    // horizon + 33 <= max_output_rows; open additionally requires 63 <= cap.
    // Each encoded history record is one stdout line; COUNT is a sixth column,
    // not a separate row, so no lookahead row is needed to determine staleness.
    // Product read overhead: configure 3 + BEGIN 1 + validate 16 + settings 9
    // + journal_mode 2 + query_only 1 + body end marker 1 = 33 stdout lines.
    // validate = version 2 + six schema objects/marker 7 + ledger 3 + app 2
    // + identity 2 = 16 (0001 predecessor: 2 + 5 + 2 + 2 = 11).
    // The largest fixed open operation is the supported 0001 upgrade:
    // 3 + 1 + 11 + 9 + 1 + 11 + 1 + 16 + 9 + 1 = 63. Current open is 56;
    // fresh initialization is 32. These are protocol counts, not spare budget.
    // Use the product contract even under the shorter test corruption envelope.
    let required = (u64::from(horizon) + 33).max(if opening { 63 } else { 0 });
    if u128::from(required) > bounds.max_output_rows as u128 {
        return Err(BindingError::InvalidInput {
            what: "replay output budget",
            detail: format!("horizon {horizon} requires {required} output rows including protocol; max_output_rows is {}", bounds.max_output_rows),
        });
    }
    Ok(())
}

// Per-thread boundary counters, absent from product builds. They measure calls
// into storage, so admission-refusal tests cannot mistake a mid-read cap for one.
#[cfg(test)]
thread_local! { static WINDOW_IO: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) }; }
#[cfg(test)]
pub(crate) fn window_io_counts() -> (u64, u64) { WINDOW_IO.with(|counts| counts.get()) }

fn read_window(store: &crate::storage::sqlite::SqliteStore, since: crate::domain::clock::UnixMillis, horizon: u32) -> Result<ReplayWindow, BindingError> {
        admit_window(store.bounds(), horizon, false)?;
        let effective = horizon.min(store.bounds().max_replay_rows);
        if effective == 0 { return Err(BindingError::EmptyWindow); }
        // Timestamp validation, count and window share one read transaction.
        // Canonical i64 text must survive the INTEGER/TEXT round trip exactly:
        // SQLite's permissive cast alone accepts prefixes and clamps overflow.
        // Validate all binding rows so time/horizon exclusion cannot hide damage.
        // On corruption return one sentinel INSTEAD of history, preserving the
        // admitted horizon + 33 row budget even for an otherwise empty window.
        #[cfg(test)]
        WINDOW_IO.with(|counts| { let (opens, reads) = counts.get(); counts.set((opens, reads + 1)); });
        let raw = store.exec_script(&format!(
            "WITH validity AS (
                SELECT NOT EXISTS(SELECT 1 FROM outbox WHERE operation LIKE 'binding-%'
                    AND (typeof(created_nanos) != 'text' OR created_nanos != CAST(CAST(created_nanos AS INTEGER) AS TEXT))) AS ok
            ), recent AS (
                SELECT quote(operation),quote(entity),quote(value_json),id,seq,(SELECT COUNT(*) FROM outbox WHERE operation LIKE 'binding-%')
                FROM outbox WHERE operation LIKE 'binding-%' AND (SELECT ok FROM validity)
                    AND CAST(created_nanos AS INTEGER)/1000000>={}
                ORDER BY id DESC LIMIT {effective}
            ) SELECT * FROM recent
            UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,'invalid-created-nanos' WHERE NOT (SELECT ok FROM validity);", since.as_millis()
        )).map_err(BindingError::Store)?;
        if raw.first().and_then(|row| row.get(5)).is_some_and(|value| value == "invalid-created-nanos") {
            return Err(BindingError::InvalidRecord { detail: "created_nanos must be canonical integer text in the i64 range".into() });
        }
        if raw.is_empty() { return Err(BindingError::EmptyWindow); }
        let total: u64 = raw[0].get(5).and_then(|s| s.parse().ok()).ok_or_else(|| BindingError::InvalidRecord { detail: "window count invalid".into() })?;
        let mut rows = decode_rows(raw.into_iter().map(|mut row| { row.pop(); row }).collect())?;
        rows.reverse();
        let stale = total > rows.len() as u64;
        Ok(ReplayWindow { rows, stale })
}

/// Historical bytes only: not a trusted actor, permission, or complete registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    pub id: i64,
    pub sequence: u64,
    pub operation: String,
    pub entity: String,
    pub descriptor: String,
    pub(crate) value_json: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWindow {
    pub rows: Vec<HistoryRow>,
    pub stale: bool,
}

fn decode_rows(rows: Vec<Vec<String>>) -> Result<Vec<HistoryRow>, BindingError> {
        let mut out = Vec::new();
        for cols in &rows {
            if cols.len() != 5 {
                return Err(BindingError::InvalidRecord {
                    detail: format!("binding scan row has {} columns, expected 5", cols.len()),
                });
            }
            let operation =
                unquote_column(&cols[0])?.ok_or_else(|| BindingError::InvalidRecord {
                    detail: "binding operation is NULL".to_string(),
                })?;
            match operation.as_str() {
                OP_EQUIPMENT_TEXT | OP_SPACE_TEXT | OP_SOURCE_TEXT | OP_POINT_TEXT
                | OP_PROPOSE_TEXT | OP_RETIRE_TEXT | OP_FINDING_TEXT => {}
                _ => {
                    return Err(BindingError::InvalidRecord {
                        detail: format!("unexpected binding operation '{operation}'"),
                    })
                }
            }
            let value_json =
                unquote_column(&cols[2])?.ok_or_else(|| BindingError::InvalidRecord {
                    detail: "binding value is NULL".to_string(),
                })?;
            let value = crate::domain::values::Value::from_json(&value_json).map_err(|e| {
                BindingError::InvalidRecord {
                    detail: format!("binding value invalid: {e}"),
                }
            })?;
            let entity = unquote_column(&cols[1])?.ok_or_else(|| BindingError::InvalidRecord { detail: "binding entity is NULL".into() })?;
            let id = cols[3].parse::<i64>().ok().filter(|n| *n > 0).ok_or_else(|| BindingError::InvalidRecord { detail: "binding row identity invalid".into() })?;
            let sequence = cols[4].parse::<u64>().map_err(|_| BindingError::InvalidRecord { detail: "binding sequence invalid".into() })?;
            match value {
                crate::domain::values::Value::Text(descriptor) => out.push(HistoryRow { id, sequence, operation, entity, descriptor, value_json }),
                _ => {
                    return Err(BindingError::InvalidRecord {
                        detail: "binding value is not text".to_string(),
                    })
                }
            }
        }
        Ok(out)
}

pub(crate) fn decode_propose(
    map: &BTreeMap<String, String>,
) -> Result<ProposedBinding, BindingError> {
    let bad = |detail: String| BindingError::InvalidRecord { detail };
    let endpoint = EndpointAddress::parse(&require_field(map, "endpoint")?)?;
    let eclass = EndpointClass::parse(&require_field(map, "eclass")?)?;
    let escope = TrustedScope::parse(&require_field(map, "escope")?)
        .map_err(|e| bad(format!("stored propose endpoint scope invalid: {e}")))?;
    let equipment = InstalledId::parse(&require_field(map, "equipment")?)
        .map_err(|e| bad(format!("stored propose equipment invalid: {e}")))?;
    let property = PropertyName::parse(&require_field(map, "property")?)?;
    let pscope = TrustedScope::parse(&require_field(map, "pscope")?)
        .map_err(|e| bad(format!("stored propose point scope invalid: {e}")))?;
    let source = InstalledId::parse(&require_field(map, "source")?)
        .map_err(|e| bad(format!("stored propose source invalid: {e}")))?;
    let unit = Unit::parse(&require_field(map, "unit")?)
        .map_err(|e| bad(format!("stored propose unit invalid: {e}")))?;
    let mode_raw = require_field(map, "mode")?;
    let mode = if mode_raw == "-" {
        None
    } else {
        Some(
            crate::domain::values::OpMode::parse(&mode_raw)
                .map_err(|e| bad(format!("stored propose mode invalid: {e}")))?,
        )
    };
    let requested = BindingRole::parse(&require_field(map, "requested")?)
        .map_err(|e| bad(format!("stored propose requested invalid: {e}")))?;
    let effective = BindingRole::parse(&require_field(map, "effective")?)
        .map_err(|e| bad(format!("stored propose effective invalid: {e}")))?;
    let feedback_raw = require_field(map, "feedback")?;
    let feedback = Feedback::parse(&feedback_raw)
        .map_err(|e| bad(format!("stored propose feedback invalid: {e}")))?;
    let status_raw = require_field(map, "status")?;
    let status = match status_raw.as_str() {
        "imported" => super::proposal::BindingStatus::Imported,
        "valid" => super::proposal::BindingStatus::Valid,
        "observed-qualified" => super::proposal::BindingStatus::ObservedQualified,
        _ => {
            return Err(bad(format!(
                "stored propose status invalid: '{status_raw}'"
            )))
        }
    };
    Ok(ProposedBinding::from_import(
        endpoint, eclass, escope, equipment, property, pscope, source, unit, mode, requested,
        effective, feedback, status,
    ))
}
