//! M01-PR07 binding registry: scoped records plus capability-gated proposals.
//!
//! The registry is the owned PR07 writer: in-memory maps plus durable
//! `binding-*` rows in the PR03 0001 `outbox` (PR04 pattern, no new
//! migration). History is additive and never overwritten: retired records
//! stay readable, reassessment is derived from history, and findings are
//! content-addressed for PR11 seals. Replay lives in [`super::history`].
//!
//! Capability gating consumes PR04 [`AccessGate`](crate::access::AccessGate)
//! entry points: `Sense` proposals require `enter_review`, `Drive`
//! proposals require `enter_publish`. Scope, ceiling, role and revocation
//! are all fail-closed; cross-scope links grant nothing.
//! [`is_revoked`](crate::access::AccessGate::is_revoked) remains the offline
//! revocation-verification path (tests assert it).

use super::error::BindingError;
use super::findings::{capability_fingerprint, Finding};
use super::proposal::{propose, BindingRole, Feedback, ProposedBinding};
use super::records::{
    EndpointAddress, EndpointClass, EquipmentKind, EquipmentRecord, PointRecord, PropertyName,
    SourceRecord, SpaceRecord,
};
use super::{assert_schema_generation, insert_binding_row, pct_encode};
use crate::domain::ids::{BindingRevision, InstalledId};
use crate::domain::scope::TrustedScope;
use crate::domain::values::Unit;
use crate::storage::sqlite::SqliteStore;
use crate::storage::{ConnectionSettings, StoreBounds};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Binding schema generation: bound to the PR03 0001 baseline, always 1.
pub const BINDING_SCHEMA_GENERATION: u32 = 1;
/// Fixed unit tag for all binding rows (safe: no envelope poison bytes).
pub const BINDING_UNIT_TEXT: &str = "binding-event";
/// Shared synthetic sensor for all binding rows (fixture sensor).
pub const BINDING_SENSOR_TEXT: &str = "sensor-sat-1";
/// Reserved outbox operations for binding records (additive, never merged).
pub const OP_EQUIPMENT_TEXT: &str = "binding-equipment";
/// Reserved outbox operations for binding records (additive, never merged).
pub const OP_SPACE_TEXT: &str = "binding-space";
/// Reserved outbox operations for binding records (additive, never merged).
pub const OP_SOURCE_TEXT: &str = "binding-source";
/// Reserved outbox operations for binding records (additive, never merged).
pub const OP_POINT_TEXT: &str = "binding-point";
/// Reserved outbox operations for binding records (additive, never merged).
pub const OP_PROPOSE_TEXT: &str = "binding-propose";
/// Reserved outbox operations for binding records (additive, never merged).
pub const OP_RETIRE_TEXT: &str = "binding-retire";
/// Reserved outbox operations for binding records (additive, never merged).
pub const OP_FINDING_TEXT: &str = "binding-finding";

/// Durable binding registry: scoped records plus capability-gated proposals.
///
/// Retired records stay readable; reassessment is derived from history (a
/// new id at a retired address needs fresh qualification). The revision
/// starts at `0` (PR02 placeholder) and bumps by one on each record,
/// proposal or retirement; findings cite the current revision as their
/// generation.
pub struct BindingRegistry {
    pub(crate) store: SqliteStore,
    pub(crate) revision: BindingRevision,
    pub(crate) next_seq: u64,
    pub(crate) equipment: BTreeMap<String, EquipmentRecord>,
    pub(crate) spaces: BTreeMap<String, SpaceRecord>,
    pub(crate) sources: BTreeMap<String, SourceRecord>,
    pub(crate) points: BTreeMap<String, PointRecord>,
    pub(crate) bindings: Vec<ProposedBinding>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) retired: BTreeSet<String>,
    pub(crate) retired_addrs: BTreeSet<String>,
    pub(crate) reassessment: BTreeSet<String>,
}

impl BindingRegistry {
    /// Open (or freshly initialize) the binding registry at `db_path`.
    ///
    /// Reuses the PR03 0001 `outbox` with reserved `binding-*` operations;
    /// no new migration. Existing `access-*` rows coexist untouched.
    pub fn open(
        db_path: &Path,
        settings: ConnectionSettings,
        bounds: StoreBounds,
    ) -> Result<BindingRegistry, BindingError> {
        assert_schema_generation();
        let _ = BINDING_SCHEMA_GENERATION;
        let (store, _) =
            SqliteStore::open(db_path, settings, bounds).map_err(BindingError::Store)?;
        let mut registry = BindingRegistry {
            store,
            revision: BindingRevision::PLACEHOLDER,
            next_seq: 1,
            equipment: BTreeMap::new(),
            spaces: BTreeMap::new(),
            sources: BTreeMap::new(),
            points: BTreeMap::new(),
            bindings: Vec::new(),
            findings: Vec::new(),
            retired: BTreeSet::new(),
            retired_addrs: BTreeSet::new(),
            reassessment: BTreeSet::new(),
        };
        registry.replay()?;
        Ok(registry)
    }

    /// Borrow the binding revision (bumps on record/propose/retire).
    pub fn revision(&self) -> BindingRevision {
        self.revision
    }

    /// Borrow the underlying PR03 store (for offline verification reads).
    pub fn store(&self) -> &SqliteStore {
        &self.store
    }

    /// Borrow all proposed bindings in proposal order.
    pub fn bindings(&self) -> &[ProposedBinding] {
        &self.bindings
    }

    /// Borrow all emitted findings in emission order.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Read one equipment record, including retired ones (history retained).
    pub fn equipment(&self, id: &str) -> Option<&EquipmentRecord> {
        self.equipment.get(id)
    }

    /// True when `id` is retired.
    pub fn is_retired(&self, id: &str) -> bool {
        self.retired.contains(id)
    }

    /// True when `id` reuses a retired address and needs fresh qualification.
    pub fn needs_reassessment(&self, id: &str) -> bool {
        self.reassessment.contains(id)
    }

    /// Record scoped equipment. Duplicate installed identities are refused;
    /// duplicate labels are allowed. A new id at a retired address is
    /// recorded but flagged as needing reassessment.
    pub fn record_equipment(
        &mut self,
        id: &str,
        kind: EquipmentKind,
        scope: TrustedScope,
        label: &str,
        address: &str,
    ) -> Result<(), BindingError> {
        if self.equipment.contains_key(id)
            || self.spaces.contains_key(id)
            || self.sources.contains_key(id)
        {
            return Err(BindingError::DuplicateIdentity {
                id: id.to_string(),
                detail: "installed identity already recorded with different labels; labels are not identity"
                    .to_string(),
            });
        }
        let record = EquipmentRecord::parse(id, kind, scope.clone(), label, address)?;
        let entity = record.id().clone();
        let descriptor = format!(
            "v=1;kind=equipment;id={};ekind={};scope={};label={};address={}",
            pct_encode(record.id().as_str()),
            pct_encode(record.kind().as_str()),
            pct_encode(record.scope().as_str()),
            pct_encode(record.label()),
            pct_encode(record.address().as_str()),
        );
        let seq = self.claim_seq();
        insert_binding_row(&self.store, OP_EQUIPMENT_TEXT, &entity, &descriptor, seq)?;
        if self.retired_addrs.contains(record.address().as_str()) {
            self.reassessment.insert(id.to_string());
        }
        self.equipment.insert(id.to_string(), record);
        self.bump_revision();
        Ok(())
    }

    /// Record a scoped space.
    pub fn record_space(
        &mut self,
        id: &str,
        scope: TrustedScope,
        label: &str,
    ) -> Result<(), BindingError> {
        if self.equipment.contains_key(id)
            || self.spaces.contains_key(id)
            || self.sources.contains_key(id)
        {
            return Err(BindingError::DuplicateIdentity {
                id: id.to_string(),
                detail: "installed identity already recorded; labels are not identity".to_string(),
            });
        }
        let record = SpaceRecord::parse(id, scope.clone(), label)?;
        let entity = record.id().clone();
        let descriptor = format!(
            "v=1;kind=space;id={};scope={};label={}",
            pct_encode(record.id().as_str()),
            pct_encode(record.scope().as_str()),
            pct_encode(record.label()),
        );
        let seq = self.claim_seq();
        insert_binding_row(&self.store, OP_SPACE_TEXT, &entity, &descriptor, seq)?;
        self.spaces.insert(id.to_string(), record);
        self.bump_revision();
        Ok(())
    }

    /// Record a scoped source (e.g. shared `sensor-sat-1`). One source may
    /// back several bindings; sharing never merges identities.
    pub fn record_source(
        &mut self,
        id: &str,
        scope: TrustedScope,
        label: &str,
    ) -> Result<(), BindingError> {
        if self.equipment.contains_key(id)
            || self.spaces.contains_key(id)
            || self.sources.contains_key(id)
        {
            return Err(BindingError::DuplicateIdentity {
                id: id.to_string(),
                detail: "installed identity already recorded; labels are not identity".to_string(),
            });
        }
        let record = SourceRecord::parse(id, scope.clone(), label)?;
        let entity = record.id().clone();
        let descriptor = format!(
            "v=1;kind=source;id={};scope={};label={}",
            pct_encode(record.id().as_str()),
            pct_encode(record.scope().as_str()),
            pct_encode(record.label()),
        );
        let seq = self.claim_seq();
        insert_binding_row(&self.store, OP_SOURCE_TEXT, &entity, &descriptor, seq)?;
        self.sources.insert(id.to_string(), record);
        self.bump_revision();
        Ok(())
    }

    /// Record a property point on installed equipment with its expected unit
    /// and endpoint class.
    pub fn record_point(
        &mut self,
        equipment: &str,
        property: &str,
        scope: TrustedScope,
        unit_text: &str,
        endpoint_class: EndpointClass,
    ) -> Result<(), BindingError> {
        let key = format!("{equipment}:{property}");
        if self.points.contains_key(&key) {
            return Err(BindingError::DuplicateIdentity {
                id: key.clone(),
                detail: "point already recorded for this equipment and property".to_string(),
            });
        }
        let record = PointRecord::parse(
            equipment,
            property,
            scope.clone(),
            unit_text,
            endpoint_class,
        )?;
        let entity = record.equipment().clone();
        let descriptor = format!(
            "v=1;kind=point;equipment={};property={};scope={};unit={};eclass={}",
            pct_encode(record.equipment().as_str()),
            pct_encode(record.property().as_str()),
            pct_encode(record.scope().as_str()),
            pct_encode(record.unit().as_str()),
            pct_encode(record.endpoint_class().as_str()),
        );
        let seq = self.claim_seq();
        insert_binding_row(&self.store, OP_POINT_TEXT, &entity, &descriptor, seq)?;
        self.points.insert(key, record);
        self.bump_revision();
        Ok(())
    }

    /// Retire an equipment record. The record stays readable; the address
    /// joins the reassessment set so a later record at the same address
    /// needs fresh qualification.
    pub fn retire(&mut self, id: &str, reason: &str) -> Result<(), BindingError> {
        let record = self
            .equipment
            .get(id)
            .ok_or_else(|| BindingError::InvalidRecord {
                detail: format!("cannot retire unknown equipment '{id}'"),
            })?;
        if reason.is_empty() {
            return Err(BindingError::InvalidInput {
                what: "reason",
                detail: "retire reason must not be empty".to_string(),
            });
        }
        if self.retired.contains(id) {
            return Err(BindingError::InvalidRecord {
                detail: format!("equipment '{id}' is already retired"),
            });
        }
        let entity = record.id().clone();
        let address = record.address().as_str().to_string();
        let descriptor = format!(
            "v=1;kind=retire;id={};address={};reason={}",
            pct_encode(id),
            pct_encode(&address),
            pct_encode(reason),
        );
        let seq = self.claim_seq();
        insert_binding_row(&self.store, OP_RETIRE_TEXT, &entity, &descriptor, seq)?;
        self.retired.insert(id.to_string());
        self.retired_addrs.insert(address);
        self.bump_revision();
        Ok(())
    }

    /// Capability-gated proposal: structural checks plus PR04 entry.
    ///
    /// `Sense` requires `enter_review`; `Drive` requires `enter_publish`
    /// in the point scope. Cross-scope attempts are refused and grant
    /// nothing. Reassessment-gated equipment is refused with
    /// `needs-reassessment` (old history retained, fresh qualification is
    /// a later concern).
    #[allow(clippy::too_many_arguments)]
    pub fn propose_with_credential(
        &mut self,
        gate: &crate::access::AccessGate,
        credential: Option<&crate::access::Credential>,
        endpoint_address: &str,
        endpoint_class: EndpointClass,
        endpoint_scope: TrustedScope,
        point_equipment: &str,
        point_property: &str,
        source_text: &str,
        unit: Unit,
        mode: Option<crate::domain::values::OpMode>,
        requested: BindingRole,
        effective: BindingRole,
        feedback: Feedback,
    ) -> Result<ProposedBinding, BindingError> {
        let key = format!("{point_equipment}:{point_property}");
        let point = self
            .points
            .get(&key)
            .ok_or_else(|| BindingError::InvalidRecord {
                detail: format!("unknown point '{key}'; record the point before proposing"),
            })?;
        let expected_unit = point.unit().clone();
        let expected_class = point.endpoint_class();
        let point_scope = point.scope().clone();
        if self.reassessment.contains(point_equipment) {
            let addr = self
                .equipment
                .get(point_equipment)
                .map(|r| r.address().as_str().to_string())
                .unwrap_or_default();
            return Err(BindingError::NeedsReassessment {
                id: point_equipment.to_string(),
                address: addr,
                detail: "replacement at a retired address needs fresh qualification; old history retained, not overwritten"
                    .to_string(),
            });
        }
        let endpoint = EndpointAddress::parse(endpoint_address)?;
        let equipment_id =
            InstalledId::parse(point_equipment).map_err(|e| BindingError::InvalidInput {
                what: "installed-id",
                detail: format!(
                    "invalid installed id '{point_equipment}': {e} [{}]",
                    e.code()
                ),
            })?;
        let property = PropertyName::parse(point_property)?;
        let source = InstalledId::parse(source_text).map_err(|e| BindingError::InvalidInput {
            what: "installed-id",
            detail: format!("invalid source id '{source_text}': {e} [{}]", e.code()),
        })?;
        let binding = propose(
            endpoint,
            endpoint_class,
            endpoint_scope.clone(),
            equipment_id,
            property,
            point_scope.clone(),
            source,
            &expected_unit,
            expected_class,
            unit,
            mode,
            requested,
            effective,
            feedback,
        )?;
        Self::check_capability(gate, credential, &point_scope, requested)?;
        let entity = binding.point_equipment().clone();
        let mode_text = binding.mode().map(|m| m.as_str()).unwrap_or("-");
        let descriptor = format!(
            "v=1;kind=propose;endpoint={};eclass={};escope={};equipment={};property={};pscope={};source={};unit={};mode={};requested={};effective={};feedback={};status={}",
            pct_encode(binding.endpoint().as_str()),
            pct_encode(binding.endpoint_class().as_str()),
            pct_encode(binding.endpoint_scope().as_str()),
            pct_encode(binding.point_equipment().as_str()),
            pct_encode(binding.point_property().as_str()),
            pct_encode(binding.point_scope().as_str()),
            pct_encode(binding.source().as_str()),
            pct_encode(binding.unit().as_str()),
            pct_encode(mode_text),
            pct_encode(binding.requested().as_str()),
            pct_encode(binding.effective().as_str()),
            pct_encode(binding.feedback().as_str()),
            pct_encode(binding.status().as_str()),
        );
        let seq = self.claim_seq();
        insert_binding_row(&self.store, OP_PROPOSE_TEXT, &entity, &descriptor, seq)?;
        self.bindings.push(binding.clone());
        self.bump_revision();
        Ok(binding)
    }

    /// Capability-gated import of one PR06 conversion binding.
    ///
    /// The conversion unit/value/label are preserved verbatim; structural
    /// and capability checks run as in
    /// [`propose_with_credential`](Self::propose_with_credential). Success
    /// persists the imported binding (`imported`, not `valid`).
    #[allow(clippy::too_many_arguments)]
    pub fn import_with_credential(
        &mut self,
        gate: &crate::access::AccessGate,
        credential: Option<&crate::access::Credential>,
        conversion: &crate::semantics::convert::Binding,
        endpoint_address: &str,
        endpoint_class: EndpointClass,
        endpoint_scope: TrustedScope,
        point_property: &str,
        point_scope: TrustedScope,
        source_text: &str,
        expected_point_unit: &Unit,
        expected_point_class: EndpointClass,
        requested: BindingRole,
        effective: BindingRole,
        feedback: Feedback,
    ) -> Result<ProposedBinding, BindingError> {
        let imported = super::import::import_binding(
            conversion,
            endpoint_address,
            endpoint_class,
            endpoint_scope.clone(),
            point_property,
            point_scope.clone(),
            source_text,
            expected_point_unit,
            expected_point_class,
            requested,
            effective,
            feedback,
        )?;
        if self.reassessment.contains(conversion.verdant_id().as_str()) {
            return Err(BindingError::NeedsReassessment {
                id: conversion.verdant_id().as_str().to_string(),
                address: endpoint_address.to_string(),
                detail: "replacement at a retired address needs fresh qualification".to_string(),
            });
        }
        Self::check_capability(gate, credential, &point_scope, requested)?;
        let entity = imported.point_equipment().clone();
        let mode_text = imported.mode().map(|m| m.as_str()).unwrap_or("-");
        let descriptor = format!(
            "v=1;kind=propose;endpoint={};eclass={};escope={};equipment={};property={};pscope={};source={};unit={};mode={};requested={};effective={};feedback={};status={}",
            pct_encode(imported.endpoint().as_str()),
            pct_encode(imported.endpoint_class().as_str()),
            pct_encode(imported.endpoint_scope().as_str()),
            pct_encode(imported.point_equipment().as_str()),
            pct_encode(imported.point_property().as_str()),
            pct_encode(imported.point_scope().as_str()),
            pct_encode(imported.source().as_str()),
            pct_encode(imported.unit().as_str()),
            pct_encode(mode_text),
            pct_encode(imported.requested().as_str()),
            pct_encode(imported.effective().as_str()),
            pct_encode(imported.feedback().as_str()),
            pct_encode(imported.status().as_str()),
        );
        let seq = self.claim_seq();
        insert_binding_row(&self.store, OP_PROPOSE_TEXT, &entity, &descriptor, seq)?;
        self.bindings.push(imported.clone());
        self.bump_revision();
        Ok(imported)
    }

    /// Emit the stable prerequisite finding for `binding`, scoped to
    /// `credential`. The `(id, generation)` pair is what PR11 seals cite.
    pub fn emit_finding(
        &mut self,
        binding: &ProposedBinding,
        credential: &crate::access::Credential,
    ) -> Result<Finding, BindingError> {
        let fp = capability_fingerprint(credential);
        let finding = Finding::for_binding(binding, self.revision, &fp);
        let entity = binding.point_equipment().clone();
        let descriptor = format!(
            "v=1;kind=finding;fid={};generation={};revision={};digest={};summary={};fp={};equipment={};property={}",
            pct_encode(finding.id().as_str()),
            finding.generation(),
            finding.binding_revision().as_u32(),
            pct_encode(finding.digest()),
            pct_encode(finding.summary()),
            pct_encode(finding.capability_fingerprint_text()),
            pct_encode(binding.point_equipment().as_str()),
            pct_encode(binding.point_property().as_str()),
        );
        let seq = self.claim_seq();
        insert_binding_row(&self.store, OP_FINDING_TEXT, &entity, &descriptor, seq)?;
        self.findings.push(finding.clone());
        Ok(finding)
    }

    fn check_capability(
        gate: &crate::access::AccessGate,
        credential: Option<&crate::access::Credential>,
        scope: &TrustedScope,
        requested: BindingRole,
    ) -> Result<(), BindingError> {
        let entered = match requested {
            BindingRole::Sense => gate.enter_review(credential, scope),
            BindingRole::Drive => gate.enter_publish(credential, scope),
        };
        match entered {
            Ok(_) => Ok(()),
            Err(e) => {
                let code = e.code().to_string();
                let detail = e.to_string();
                match e {
                    crate::access::AccessError::ScopeDenied {
                        expected,
                        presented,
                    } => Err(BindingError::ScopeDenied {
                        expected,
                        presented,
                    }),
                    crate::access::AccessError::CeilingExceeded { .. }
                    | crate::access::AccessError::RoleDenied { .. } => {
                        Err(BindingError::WrongRole {
                            requested: requested.as_str().to_string(),
                            detail: format!("capability cannot cover role: {detail} [{code}]"),
                        })
                    }
                    _ => Err(BindingError::capability_denied(detail, &code)),
                }
            }
        }
    }

    pub(crate) fn claim_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1).max(1);
        if self.next_seq == 1 {
            self.next_seq = 2;
        }
        seq
    }

    pub(crate) fn bump_revision(&mut self) {
        let next = self.revision.as_u32().saturating_add(1);
        self.revision = BindingRevision::new(next);
    }
}
