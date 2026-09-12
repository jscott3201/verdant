//! M01-PR07 proposed bindings: endpoint-to-point with roles and statuses.
//!
//! A proposed binding maps one field-bus [`EndpointAddress`](super::records::EndpointAddress)
//! to one [`PointRecord`](super::records::PointRecord) with an explicit
//! [`Unit`](crate::domain::values::Unit), an explicit enum
//! ([`OpMode`](crate::domain::values::OpMode) when the value carries one),
//! and requested / effective / feedback roles.
//!
//! Statuses are kept separate:
//!
//! * `imported` — arrived via a PR06 conversion outcome, mapped verbatim.
//! * `valid` — passed structural checks (shape, units, roles, endpoint
//!   class, scope agreement). Structural validity is NOT sensing or
//!   actuation qualification.
//! * `observed-qualified` — evidence-backed qualification. No static
//!   validation in this slice may claim it; the variant exists so tests can
//!   assert its absence. Qualification is a later concern.
//!
//! Bindings never authorize actuation: a native actuatable class or a
//! protocol address alone is not permission. There is no `authorize` method
//! on any binding type by design.

use super::error::BindingError;
use super::records::{EndpointAddress, EndpointClass, PropertyName};
use crate::domain::ids::InstalledId;
use crate::domain::scope::TrustedScope;
use crate::domain::values::{OpMode, Unit};

/// Binding role: what the binding is requested/effective for. Exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindingRole {
    /// Sensing (review-grade): observable without actuation.
    Sense,
    /// Driving (publish-grade): would actuate under a later authority.
    Drive,
}

impl BindingRole {
    /// Parse `sense` / `drive` (exact, case-sensitive).
    pub fn parse(raw: &str) -> Result<BindingRole, BindingError> {
        match raw {
            "sense" => Ok(BindingRole::Sense),
            "drive" => Ok(BindingRole::Drive),
            _ => Err(BindingError::InvalidInput {
                what: "binding-role",
                detail: format!("unknown binding role '{raw}'; expected sense/drive"),
            }),
        }
    }

    /// Canonical role text.
    pub fn as_str(self) -> &'static str {
        match self {
            BindingRole::Sense => "sense",
            BindingRole::Drive => "drive",
        }
    }
}

/// Feedback specification. `Ambiguous` is representable so callers can name
/// the failure, but [`propose`] always refuses it (`ambiguous-feedback`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Feedback {
    /// No feedback path declared.
    Absent,
    /// Exactly one feedback role.
    Single(BindingRole),
    /// More than one feedback role (never silently resolved).
    Ambiguous,
}

impl Feedback {
    /// Parse `absent` / `sense` / `drive` / `ambiguous` (exact).
    /// `sense+drive` is the frozen ambiguous alias.
    pub fn parse(raw: &str) -> Result<Feedback, BindingError> {
        match raw {
            "absent" => Ok(Feedback::Absent),
            "sense" => Ok(Feedback::Single(BindingRole::Sense)),
            "drive" => Ok(Feedback::Single(BindingRole::Drive)),
            "ambiguous" | "sense+drive" => Ok(Feedback::Ambiguous),
            _ => Err(BindingError::InvalidInput {
                what: "feedback",
                detail: format!("unknown feedback '{raw}'; expected absent/sense/drive/ambiguous"),
            }),
        }
    }

    /// Canonical feedback text.
    pub fn as_str(self) -> &'static str {
        match self {
            Feedback::Absent => "absent",
            Feedback::Single(role) => role.as_str(),
            Feedback::Ambiguous => "ambiguous",
        }
    }

    /// True only for [`Feedback::Ambiguous`].
    pub fn is_ambiguous(self) -> bool {
        matches!(self, Feedback::Ambiguous)
    }
}

/// Binding lifecycle status. Exhaustive so new states break the build.
///
/// `ObservedQualified` has no public constructor in this slice: no static
/// validation may claim sensing/actuation qualification. Tests assert that
/// [`propose`] and the import path never yield it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindingStatus {
    /// Arrived via a PR06 conversion outcome (mapped verbatim).
    Imported,
    /// Passed structural checks (shape/units/roles/endpoint/scope).
    Valid,
    /// Evidence-backed qualification (later concern; unreachable here).
    ObservedQualified,
}

impl BindingStatus {
    /// Canonical status text.
    pub fn as_str(self) -> &'static str {
        match self {
            BindingStatus::Imported => "imported",
            BindingStatus::Valid => "valid",
            BindingStatus::ObservedQualified => "observed-qualified",
        }
    }

    /// True only for [`BindingStatus::ObservedQualified`].
    pub fn is_observed_qualified(self) -> bool {
        matches!(self, BindingStatus::ObservedQualified)
    }
}

/// Proposed binding: endpoint-to-point with explicit unit, enum, roles and
/// source. The `source` is the shared sensor (e.g. `sensor-sat-1`): one
/// source may back several bindings without merging installed identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedBinding {
    endpoint: EndpointAddress,
    endpoint_class: EndpointClass,
    endpoint_scope: TrustedScope,
    point_equipment: InstalledId,
    point_property: PropertyName,
    point_scope: TrustedScope,
    source: InstalledId,
    unit: Unit,
    mode: Option<OpMode>,
    requested: BindingRole,
    effective: BindingRole,
    feedback: Feedback,
    status: BindingStatus,
}

impl ProposedBinding {
    /// Borrow the endpoint address.
    pub fn endpoint(&self) -> &EndpointAddress {
        &self.endpoint
    }
    /// Borrow the endpoint class.
    pub fn endpoint_class(&self) -> EndpointClass {
        self.endpoint_class
    }
    /// Borrow the endpoint scope.
    pub fn endpoint_scope(&self) -> &TrustedScope {
        &self.endpoint_scope
    }
    /// Borrow the point equipment.
    pub fn point_equipment(&self) -> &InstalledId {
        &self.point_equipment
    }
    /// Borrow the point property.
    pub fn point_property(&self) -> &PropertyName {
        &self.point_property
    }
    /// Borrow the point scope.
    pub fn point_scope(&self) -> &TrustedScope {
        &self.point_scope
    }
    /// Borrow the shared source (one source may back several bindings).
    pub fn source(&self) -> &InstalledId {
        &self.source
    }
    /// Borrow the explicit unit.
    pub fn unit(&self) -> &Unit {
        &self.unit
    }
    /// Borrow the explicit enum, when the value carries one.
    pub fn mode(&self) -> Option<&OpMode> {
        self.mode.as_ref()
    }
    /// Borrow the requested role.
    pub fn requested(&self) -> BindingRole {
        self.requested
    }
    /// Borrow the effective role.
    pub fn effective(&self) -> BindingRole {
        self.effective
    }
    /// Borrow the feedback spec.
    pub fn feedback(&self) -> Feedback {
        self.feedback
    }
    /// Borrow the lifecycle status.
    pub fn status(&self) -> BindingStatus {
        self.status
    }

    /// Import-path constructor: same fields as [`propose`] but with an
    /// explicit status (import yields `Imported`). Only the import module
    /// calls this; structural checks already ran in the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn from_import(
        endpoint: EndpointAddress,
        endpoint_class: EndpointClass,
        endpoint_scope: TrustedScope,
        point_equipment: InstalledId,
        point_property: PropertyName,
        point_scope: TrustedScope,
        source: InstalledId,
        unit: Unit,
        mode: Option<OpMode>,
        requested: BindingRole,
        effective: BindingRole,
        feedback: Feedback,
        status: BindingStatus,
    ) -> ProposedBinding {
        ProposedBinding {
            endpoint,
            endpoint_class,
            endpoint_scope,
            point_equipment,
            point_property,
            point_scope,
            source,
            unit,
            mode,
            requested,
            effective,
            feedback,
            status,
        }
    }

    /// Canonical bytes for stable finding digests (field order frozen).
    pub fn canonical_bytes(&self) -> String {
        let mode_text = self.mode.as_ref().map(|m| m.as_str()).unwrap_or("-");
        format!(
            "{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}",
            self.endpoint.as_str(),
            self.endpoint_class.as_str(),
            self.endpoint_scope.as_str(),
            self.point_equipment.as_str(),
            self.point_property.as_str(),
            self.point_scope.as_str(),
            self.source.as_str(),
            self.unit.as_str(),
            mode_text,
            self.requested.as_str(),
            self.effective.as_str(),
            self.feedback.as_str(),
        )
    }
}

/// Pure structural proposal: no store, no capability check.
///
/// Checks, in frozen order: scope agreement, endpoint class, unit,
/// requested/effective agreement, feedback unambiguity. The first failure
/// wins deterministically. Success yields [`BindingStatus::Valid`]; this is
/// structural validity only, never sensing/actuation qualification.
#[allow(clippy::too_many_arguments)]
pub fn propose(
    endpoint: EndpointAddress,
    endpoint_class: EndpointClass,
    endpoint_scope: TrustedScope,
    point_equipment: InstalledId,
    point_property: PropertyName,
    point_scope: TrustedScope,
    source: InstalledId,
    expected_point_unit: &Unit,
    expected_point_class: EndpointClass,
    unit: Unit,
    mode: Option<OpMode>,
    requested: BindingRole,
    effective: BindingRole,
    feedback: Feedback,
) -> Result<ProposedBinding, BindingError> {
    if endpoint_scope.as_str() != point_scope.as_str() {
        return Err(BindingError::ScopeDenied {
            expected: endpoint_scope.as_str().to_string(),
            presented: point_scope.as_str().to_string(),
        });
    }
    if endpoint_class != expected_point_class {
        return Err(BindingError::EndpointConfusion {
            expected: expected_point_class.as_str().to_string(),
            presented: endpoint_class.as_str().to_string(),
        });
    }
    if unit.as_str() != expected_point_unit.as_str() {
        return Err(BindingError::WrongUnit {
            expected: expected_point_unit.as_str().to_string(),
            presented: unit.as_str().to_string(),
        });
    }
    if requested != effective {
        return Err(BindingError::WrongRole {
            requested: requested.as_str().to_string(),
            detail: format!(
                "requested '{}' does not match effective '{}' (no silent downgrade)",
                requested.as_str(),
                effective.as_str()
            ),
        });
    }
    if feedback.is_ambiguous() {
        return Err(BindingError::AmbiguousFeedback {
            detail: "feedback lists more than one role; disambiguate before proposing".to_string(),
        });
    }
    Ok(ProposedBinding {
        endpoint,
        endpoint_class,
        endpoint_scope,
        point_equipment,
        point_property,
        point_scope,
        source,
        unit,
        mode,
        requested,
        effective,
        feedback,
        status: BindingStatus::Valid,
    })
}
