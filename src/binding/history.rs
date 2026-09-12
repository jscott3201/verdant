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
    pub(crate) fn replay(&mut self) -> Result<(), BindingError> {
        let rows = self.read_descriptors()?;
        let mut count = 0u64;
        for (operation, descriptor) in rows {
            let map = split_descriptor(&descriptor)?;
            let version = require_field(&map, "v")?;
            if version != "1" {
                return Err(BindingError::InvalidRecord {
                    detail: format!("unsupported binding descriptor version '{version}'"),
                });
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
        self.next_seq = count.saturating_add(1).max(1);
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
        let fp = require_field(map, "fp")?;
        if fp.is_empty() {
            return Err(bad(
                "stored finding fingerprint must not be empty".to_string()
            ));
        }
        let _equipment = require_field(map, "equipment")?;
        let _property = require_field(map, "property")?;
        let finding = super::findings::Finding::from_stored(
            fid,
            generation,
            BindingRevision::new(revision),
            digest,
            summary,
            fp,
        );
        self.findings.push(finding);
        Ok(())
    }

    pub(crate) fn read_descriptors(&self) -> Result<Vec<(String, String)>, BindingError> {
        let script = format!(
            "SELECT quote(operation), quote(entity), quote(value_json) FROM outbox WHERE operation LIKE {} ORDER BY id;",
            sql_quote("binding-%")
        );
        let rows = self
            .store
            .exec_script(&script)
            .map_err(BindingError::Store)?;
        let mut out = Vec::new();
        for cols in &rows {
            if cols.len() != 3 {
                return Err(BindingError::InvalidRecord {
                    detail: format!("binding scan row has {} columns, expected 3", cols.len()),
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
            match value {
                crate::domain::values::Value::Text(descriptor) => out.push((operation, descriptor)),
                _ => {
                    return Err(BindingError::InvalidRecord {
                        detail: "binding value is not text".to_string(),
                    })
                }
            }
        }
        Ok(out)
    }
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
