//! M01-PR07 import of PR06 conversion outcomes into proposed bindings.
//!
//! Imported bindings arrive via PR06 conversion outcomes only: this module
//! maps [`Conversion`](crate::semantics::convert::Conversion) bindings
//! verbatim (unit, value/enum, label preserved) and never invents semantic
//! content. Out-of-scenario, unknown-class, collision and slot-mismatch
//! diagnostics surface as [`BindingError`] refusals with the PR06 cause
//! (class, slot, candidates, profile) preserved.
//!
//! Consumed, never redefined: [`BindingRevision`](crate::domain::ids::BindingRevision),
//! [`InstalledId`](crate::domain::ids::InstalledId),
//! [`Unit`](crate::domain::values::Unit),
//! [`OpMode`](crate::domain::values::OpMode),
//! [`Value`](crate::domain::values::Value),
//! [`ConversionRecord`](crate::semantics::convert::ConversionRecord) /
//! [`BindingSet`](crate::semantics::convert::BindingSet) shapes plus revision
//! semantics, and [`SemanticsError`](crate::semantics::convert::SemanticsError)
//! diagnostic codes.

use super::error::BindingError;
use super::proposal::{BindingRole, BindingStatus, Feedback, ProposedBinding};
use super::records::{EndpointAddress, EndpointClass, PropertyName};
use crate::domain::scope::TrustedScope;
use crate::domain::values::Unit;

/// Map one PR06 conversion [`Binding`](crate::semantics::convert::Binding)
/// into an imported proposed binding.
///
/// The conversion unit, value-enum and label are preserved verbatim; the
/// caller supplies the endpoint address/class/scopes, the point property,
/// the shared source, and the requested/effective/feedback roles.
/// Structural checks (scope, endpoint class, unit, roles, feedback) run
/// exactly as in [`propose`](super::proposal::propose); success yields
/// [`BindingStatus::Imported`] (not `Valid`: import is not validation).
#[allow(clippy::too_many_arguments)]
pub fn import_binding(
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
    let endpoint = EndpointAddress::parse(endpoint_address)?;
    let property = PropertyName::parse(point_property)?;
    let source = crate::domain::ids::InstalledId::parse(source_text).map_err(|e| {
        BindingError::InvalidInput {
            what: "installed-id",
            detail: format!("invalid source id '{source_text}': {e} [{}]", e.code()),
        }
    })?;
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
    if conversion.unit().as_str() != expected_point_unit.as_str() {
        return Err(BindingError::WrongUnit {
            expected: expected_point_unit.as_str().to_string(),
            presented: conversion.unit().as_str().to_string(),
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
            detail: "feedback lists more than one role; disambiguate before importing".to_string(),
        });
    }
    let mode = crate::semantics::convert::mode_of(conversion.value()).cloned();
    Ok(ImportedBinding::wrap(
        endpoint,
        endpoint_class,
        endpoint_scope,
        conversion.verdant_id().clone(),
        property,
        point_scope,
        source,
        conversion.unit().clone(),
        mode,
        requested,
        effective,
        feedback,
    ))
}

/// Map a PR06 [`SemanticsError`](crate::semantics::convert::SemanticsError)
/// into the matching [`BindingError`] import refusal, preserving class,
/// slot, candidates, reason and profile as the cause.
pub fn import_diagnostic(err: &crate::semantics::convert::SemanticsError) -> BindingError {
    match err {
        crate::semantics::convert::SemanticsError::InvalidInput { what, detail } => {
            BindingError::InvalidInput {
                what,
                detail: detail.clone(),
            }
        }
        crate::semantics::convert::SemanticsError::UnknownClass { class, profile } => {
            BindingError::ImportUnknownClass {
                class: class.clone(),
                profile: profile.clone(),
            }
        }
        crate::semantics::convert::SemanticsError::OutOfScenario {
            class,
            reason,
            profile,
        } => BindingError::ImportOutOfScenario {
            class: class.clone(),
            reason: reason.clone(),
            profile: profile.clone(),
        },
        crate::semantics::convert::SemanticsError::Collision {
            slot,
            candidates,
            profile,
        } => BindingError::ImportCollision {
            slot: slot.clone(),
            candidates: candidates.join(","),
            profile: profile.clone(),
        },
        crate::semantics::convert::SemanticsError::SlotMismatch {
            class,
            kind,
            slot,
            profile,
        } => BindingError::ImportSlotMismatch {
            class: class.clone(),
            kind: kind.clone(),
            slot: slot.clone(),
            profile: profile.clone(),
        },
        crate::semantics::convert::SemanticsError::RevisionOverflow { current, profile } => {
            BindingError::InvalidRecord {
                detail: format!("import revision overflow at {current} under profile '{profile}'"),
            }
        }
    }
}

/// Convert a site under a profile, mapping the first PR06 diagnostic into a
/// binding refusal with cause preserved. Success yields the PR06
/// [`Conversion`](crate::semantics::convert::Conversion) for
/// [`import_binding`] callers to map item by item.
pub fn import_site(
    site: &crate::semantics::convert::ExternalSite,
    profile: &crate::semantics::profile::Profile,
) -> Result<crate::semantics::convert::Conversion, BindingError> {
    crate::semantics::convert::convert(site, profile).map_err(|e| import_diagnostic(&e))
}

struct ImportedBinding;

impl ImportedBinding {
    #[allow(clippy::too_many_arguments)]
    fn wrap(
        endpoint: EndpointAddress,
        endpoint_class: EndpointClass,
        endpoint_scope: TrustedScope,
        point_equipment: crate::domain::ids::InstalledId,
        point_property: PropertyName,
        point_scope: TrustedScope,
        source: crate::domain::ids::InstalledId,
        unit: Unit,
        mode: Option<crate::domain::values::OpMode>,
        requested: BindingRole,
        effective: BindingRole,
        feedback: Feedback,
    ) -> ProposedBinding {
        ProposedBinding::from_import(
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
            BindingStatus::Imported,
        )
    }
}
