//! M01-PR07 scoped records: equipment, spaces, sources, points, endpoints.
//!
//! Representation only (no capability, no qualification, no actuation). All
//! identities are PR02 [`InstalledId`](crate::domain::ids::InstalledId) or
//! [`TrustedScope`](crate::domain::scope::TrustedScope) values consumed, never
//! redefined. Labels travel as text and never grant identity: duplicate
//! labels are allowed, duplicate installed identities are refused by the
//! registry (see `super::registry`).
//!
//! Endpoint classification ([`EndpointClass`]) keeps service (`served-by`)
//! and location (`located-in`) distinct, mirroring the domain fixture. A
//! binding that confuses them is refused with `endpoint-confusion`.

use super::error::BindingError;
use crate::domain::ids::InstalledId;
use crate::domain::scope::TrustedScope;
use crate::domain::values::Unit;

/// Maximum label length in bytes.
pub const MAX_LABEL_LEN: usize = 128;
/// Maximum endpoint-address / property length in bytes.
pub const MAX_TOKEN_LEN: usize = 128;

fn validate_token(kind: &'static str, raw: &str) -> Result<(), BindingError> {
    if raw.is_empty() {
        return Err(BindingError::InvalidInput {
            what: kind,
            detail: "value must not be empty".to_string(),
        });
    }
    if raw.len() > MAX_TOKEN_LEN {
        return Err(BindingError::InvalidInput {
            what: kind,
            detail: format!("value is {} chars; maximum is {MAX_TOKEN_LEN}", raw.len()),
        });
    }
    let ok = raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
    if !ok {
        return Err(BindingError::InvalidInput {
            what: kind,
            detail: format!("value has unsupported characters: '{raw}'"),
        });
    }
    Ok(())
}

fn validate_label(raw: &str) -> Result<(), BindingError> {
    if raw.is_empty() {
        return Err(BindingError::InvalidInput {
            what: "label",
            detail: "label must not be empty".to_string(),
        });
    }
    if raw.len() > MAX_LABEL_LEN {
        return Err(BindingError::InvalidInput {
            what: "label",
            detail: format!("label is {} chars; maximum is {MAX_LABEL_LEN}", raw.len()),
        });
    }
    if raw.contains('\0') {
        return Err(BindingError::InvalidInput {
            what: "label",
            detail: "label must not contain NUL".to_string(),
        });
    }
    Ok(())
}

/// Equipment kind for the tiny_site shape. Exhaustive so new kinds break
/// the build, not behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EquipmentKind {
    Ahu,
    Vav,
}

impl EquipmentKind {
    /// Parse `ahu` / `vav` (exact, case-sensitive).
    pub fn parse(raw: &str) -> Result<EquipmentKind, BindingError> {
        match raw {
            "ahu" => Ok(EquipmentKind::Ahu),
            "vav" => Ok(EquipmentKind::Vav),
            _ => Err(BindingError::InvalidInput {
                what: "equipment-kind",
                detail: format!("unknown equipment kind '{raw}'; expected ahu/vav"),
            }),
        }
    }

    /// Canonical kind text.
    pub fn as_str(self) -> &'static str {
        match self {
            EquipmentKind::Ahu => "ahu",
            EquipmentKind::Vav => "vav",
        }
    }
}

/// Endpoint classification: service vs location. Exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointClass {
    /// Service relationship (`served-by`): a VAV served by an AHU.
    Service,
    /// Location relationship (`located-in`): equipment located in a scope.
    Location,
}

impl EndpointClass {
    /// Parse `service` / `location` (exact, case-sensitive).
    pub fn parse(raw: &str) -> Result<EndpointClass, BindingError> {
        match raw {
            "service" => Ok(EndpointClass::Service),
            "location" => Ok(EndpointClass::Location),
            _ => Err(BindingError::InvalidInput {
                what: "endpoint-class",
                detail: format!("unknown endpoint class '{raw}'; expected service/location"),
            }),
        }
    }

    /// Canonical class text.
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointClass::Service => "service",
            EndpointClass::Location => "location",
        }
    }
}

/// Field-bus endpoint address (e.g. `mstp://vav-101`). Validated text, not
/// permission: an address alone never authorizes actuation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointAddress(String);

impl EndpointAddress {
    /// Validate caller text into an endpoint address.
    pub fn parse(raw: &str) -> Result<EndpointAddress, BindingError> {
        validate_token("endpoint-address", raw)?;
        Ok(EndpointAddress(raw.to_string()))
    }

    /// Borrow the canonical text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Property name (e.g. `supply-air-temp`, `airflow`, `damper`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PropertyName(String);

impl PropertyName {
    /// Validate caller text into a property name.
    pub fn parse(raw: &str) -> Result<PropertyName, BindingError> {
        validate_token("property", raw)?;
        Ok(PropertyName(raw.to_string()))
    }

    /// Borrow the canonical text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Display label: explicitly NOT identity. Duplicates are expected (both
/// VAVs may carry `VAV`, like the domain fixture).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordLabel(String);

impl RecordLabel {
    /// Validate caller text into a display label (duplicates allowed).
    pub fn parse(raw: &str) -> Result<RecordLabel, BindingError> {
        validate_label(raw)?;
        Ok(RecordLabel(raw.to_string()))
    }

    /// Borrow the label text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Scoped equipment record (e.g. `ahu-1`, `vav-101`, `vav-102`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquipmentRecord {
    id: InstalledId,
    kind: EquipmentKind,
    scope: TrustedScope,
    label: String,
    address: EndpointAddress,
}

impl EquipmentRecord {
    /// Validate caller parts into a scoped equipment record.
    pub fn parse(
        id: &str,
        kind: EquipmentKind,
        scope: TrustedScope,
        label: &str,
        address: &str,
    ) -> Result<EquipmentRecord, BindingError> {
        let parsed_id = InstalledId::parse(id).map_err(|e| BindingError::InvalidInput {
            what: "installed-id",
            detail: format!("invalid installed id '{id}': {e} [{}]", e.code()),
        })?;
        validate_label(label)?;
        let parsed_address = EndpointAddress::parse(address)?;
        Ok(EquipmentRecord {
            id: parsed_id,
            kind,
            scope,
            label: label.to_string(),
            address: parsed_address,
        })
    }

    /// Borrow the installed identity.
    pub fn id(&self) -> &InstalledId {
        &self.id
    }

    /// Borrow the equipment kind.
    pub fn kind(&self) -> EquipmentKind {
        self.kind
    }

    /// Borrow the trusted scope.
    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }

    /// Borrow the display label (text only, never identity).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Borrow the endpoint address.
    pub fn address(&self) -> &EndpointAddress {
        &self.address
    }
}

/// Scoped space record (e.g. `space-a-1` in `scope-a`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceRecord {
    id: InstalledId,
    scope: TrustedScope,
    label: String,
}

impl SpaceRecord {
    /// Validate caller parts into a scoped space record.
    pub fn parse(id: &str, scope: TrustedScope, label: &str) -> Result<SpaceRecord, BindingError> {
        let parsed_id = InstalledId::parse(id).map_err(|e| BindingError::InvalidInput {
            what: "installed-id",
            detail: format!("invalid installed id '{id}': {e} [{}]", e.code()),
        })?;
        validate_label(label)?;
        Ok(SpaceRecord {
            id: parsed_id,
            scope,
            label: label.to_string(),
        })
    }

    /// Borrow the installed identity.
    pub fn id(&self) -> &InstalledId {
        &self.id
    }

    /// Borrow the trusted scope.
    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }

    /// Borrow the display label.
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Scoped source record (e.g. shared `sensor-sat-1`). One source may back
/// several bindings; sharing never merges installed identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRecord {
    id: InstalledId,
    scope: TrustedScope,
    label: String,
}

impl SourceRecord {
    /// Validate caller parts into a scoped source record.
    pub fn parse(id: &str, scope: TrustedScope, label: &str) -> Result<SourceRecord, BindingError> {
        let parsed_id = InstalledId::parse(id).map_err(|e| BindingError::InvalidInput {
            what: "installed-id",
            detail: format!("invalid installed id '{id}': {e} [{}]", e.code()),
        })?;
        validate_label(label)?;
        Ok(SourceRecord {
            id: parsed_id,
            scope,
            label: label.to_string(),
        })
    }

    /// Borrow the installed identity.
    pub fn id(&self) -> &InstalledId {
        &self.id
    }

    /// Borrow the trusted scope.
    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }

    /// Borrow the display label.
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Property point on installed equipment: the bindable target.
///
/// The point pins the expected engineering [`Unit`] and the expected
/// [`EndpointClass`]. A proposed binding must present the same unit and
/// class; mismatches are typed refusals (`wrong-unit`,
/// `endpoint-confusion`), never silent coercion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointRecord {
    equipment: InstalledId,
    property: PropertyName,
    scope: TrustedScope,
    unit: Unit,
    endpoint_class: EndpointClass,
}

impl PointRecord {
    /// Validate caller parts into a property point.
    pub fn parse(
        equipment: &str,
        property: &str,
        scope: TrustedScope,
        unit_text: &str,
        endpoint_class: EndpointClass,
    ) -> Result<PointRecord, BindingError> {
        let parsed_equipment =
            InstalledId::parse(equipment).map_err(|e| BindingError::InvalidInput {
                what: "installed-id",
                detail: format!("invalid installed id '{equipment}': {e} [{}]", e.code()),
            })?;
        let parsed_property = PropertyName::parse(property)?;
        let parsed_unit = Unit::parse(unit_text).map_err(|e| BindingError::InvalidInput {
            what: "unit",
            detail: format!("invalid unit '{unit_text}': {e} [{}]", e.code()),
        })?;
        Ok(PointRecord {
            equipment: parsed_equipment,
            property: parsed_property,
            scope,
            unit: parsed_unit,
            endpoint_class,
        })
    }

    /// Borrow the equipment identity.
    pub fn equipment(&self) -> &InstalledId {
        &self.equipment
    }

    /// Borrow the property name.
    pub fn property(&self) -> &PropertyName {
        &self.property
    }

    /// Borrow the trusted scope.
    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }

    /// Borrow the expected unit.
    pub fn unit(&self) -> &Unit {
        &self.unit
    }

    /// Borrow the expected endpoint class.
    pub fn endpoint_class(&self) -> EndpointClass {
        self.endpoint_class
    }
}
