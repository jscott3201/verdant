//! M02-PR05 human action preview, SYNTHETIC-ONLY (core types).
//!
//! Versioned preview templates (`verdant-preview-v1`); see `preview.rs` for the
//! assembled [`Preview`]. This module performs no `WriteProperty` dispatch,
//! exposes no generic property-write API, never mutates
//! `ClientConfig`/`APDU_RETRIES`, and never touches transport injection.
//! Synthetic-only BACnet/IP direct unsegmented Analog Value `presentValue` on
//! `tiny_site` (`ahu-1`/`vav-101`, `scope-a`); commissioned priority 8;
//! protected 1-3 refused; `degC` only, `20.0..=24.0`, tolerance `0.1`.
#![allow(dead_code)]
#![allow(unused_imports)]

mod preview;
pub use preview::*;

use crate::accept::AcceptedRevision;
use crate::access::{RoleKind, REQUIRED_PUBLISH_CEILING};
use crate::binding::Finding;
use crate::domain::ids::{BindingRevision, InstalledId};
use crate::domain::scope::TrustedScope;
use crate::domain::values::Unit;

/// Versioned preview template format.
pub const PREVIEW_FORMAT: &str = "verdant-preview-v1";
/// Commissioned supervisory priority for this synthetic profile only.
pub const COMMISSIONED_PRIORITY: u8 = 8;
/// Protected priorities `1..=PROTECTED_MAX` are reserved and refused.
pub const PROTECTED_MAX: u8 = 3;
/// BACnet priority array bound.
pub const MAX_PRIORITY: u8 = 16;
/// Encoded degC range, inclusive.
pub const RANGE_MIN_C: f64 = 20.0;
/// Encoded degC range, inclusive.
pub const RANGE_MAX_C: f64 = 24.0;
/// Wire tolerance in degC.
pub const TOLERANCE_C: f64 = 0.1;
/// Preview duration: 15 minutes.
pub const DURATION_SECS: u64 = 900;
/// Dispatch deadline bound shown on the preview: 5 seconds.
pub const DEADLINE_SECS: u64 = 5;
/// Rate bound: at most this many previews per hour (synthetic planning).
pub const RATE_MAX_PER_HOUR: u32 = 6;
/// Precondition freshness horizon: 5 minutes.
pub const PRECONDITION_MAX_AGE_SECS: u64 = 300;
/// BACnet Analog Value object type.
pub const OBJECT_ANALOG_VALUE: u16 = 2;
/// BACnet `presentValue` property identifier.
pub const PROP_PRESENT_VALUE: u32 = 85;
/// Feedback status stated when no meaningful immediate physical feedback exists.
pub const FEEDBACK_UNAVAILABLE: &str = "unavailable-feedback";
/// Priority masking note shown on every permitted preview.
pub const MASK_NOTE: &str = "priority-8-masks-9-16-masked-by-1-7";
/// Timeout policy: uncertain after handoff, never permission to resend.
pub const TIMEOUT_POLICY: &str = "uncertain-not-resend";

/// Typed preview failure with a stable machine code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewError {
    Invalid(&'static str),
    AssistanceCeiling { have: u8, required: u8 },
    ProtectedPriority { priority: u8 },
    UnallocatedPriority { priority: u8 },
    Noncommandable { detail: &'static str },
    AmbiguousArray { index: u32 },
    StalePrecondition,
    WrongUnit { expected: String, presented: String },
    WireRange { requested: String, wire: String },
    DuplicateAlias { alias: String },
    RevisionMismatch { detail: &'static str },
    NullNotAdmitted,
    RateExceeded { used: u32, limit: u32 },
    SealOrder { detail: &'static str },
}

impl PreviewError {
    /// Stable machine-readable code asserted by tests.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "preview-invalid",
            Self::AssistanceCeiling { .. } => "ceiling-exceeded",
            Self::ProtectedPriority { .. } => "preview-protected-priority",
            Self::UnallocatedPriority { .. } => "preview-unallocated-priority",
            Self::Noncommandable { .. } => "preview-noncommandable",
            Self::AmbiguousArray { .. } => "preview-ambiguous-array",
            Self::StalePrecondition => "preview-stale-precondition",
            Self::WrongUnit { .. } => "wrong-unit",
            Self::WireRange { .. } => "preview-wire-range",
            Self::DuplicateAlias { .. } => "duplicate-identity",
            Self::RevisionMismatch { .. } => "preview-revision-mismatch",
            Self::NullNotAdmitted => "preview-null-not-admitted",
            Self::RateExceeded { .. } => "preview-rate-exceeded",
            Self::SealOrder { .. } => "preview-seal-order",
        }
    }
}

impl std::fmt::Display for PreviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "preview invalid: {detail}"),
            Self::AssistanceCeiling { have, required } => {
                write!(f, "assistance ceiling {have} below required {required}")
            }
            Self::ProtectedPriority { priority } => {
                write!(f, "protected priority {priority} reserved (1-3)")
            }
            Self::UnallocatedPriority { priority } => {
                write!(f, "unallocated priority {priority}; commissioned is 8")
            }
            Self::Noncommandable { detail } => write!(f, "noncommandable target: {detail}"),
            Self::AmbiguousArray { index } => {
                write!(f, "ambiguous array index {index}; presentValue is scalar")
            }
            Self::StalePrecondition => write!(f, "stale precondition"),
            Self::WrongUnit { expected, presented } => {
                write!(f, "wrong unit: expects '{expected}', presents '{presented}'")
            }
            Self::WireRange { requested, wire } => {
                write!(f, "wire value {wire} leaves range (requested {requested})")
            }
            Self::DuplicateAlias { alias } => write!(f, "duplicate alias '{alias}'"),
            Self::RevisionMismatch { detail } => write!(f, "revision mismatch: {detail}"),
            Self::NullNotAdmitted => write!(f, "encoded null only for admitted release"),
            Self::RateExceeded { used, limit } => {
                write!(f, "rate exceeded: {used} >= {limit}/hour")
            }
            Self::SealOrder { detail } => write!(f, "seal order refused: {detail}"),
        }
    }
}

impl std::error::Error for PreviewError {}

pub type Result<T> = std::result::Result<T, PreviewError>;

/// Validated BACnet priority for this synthetic profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priority(u8);

impl Priority {
    /// Validate `1..=16`; refuses 0 and values above 16, never clamps.
    pub fn new(value: u8) -> Result<Self> {
        if value == 0 || value > MAX_PRIORITY {
            return Err(PreviewError::Invalid("priority 1..=16"));
        }
        Ok(Self(value))
    }

    /// Explicit priority is required; `None` is an empty slot, not priority 8.
    pub fn from_option(value: Option<u8>) -> Result<Self> {
        match value {
            Some(priority) => Self::new(priority),
            None => Err(PreviewError::Invalid("empty priority slot")),
        }
    }

    /// Borrow the raw priority.
    pub fn get(self) -> u8 {
        self.0
    }

    /// Only 8 is commissioned here; `1..=3` refuse as protected.
    pub fn check_commissioned(self) -> Result<Self> {
        if self.0 <= PROTECTED_MAX {
            return Err(PreviewError::ProtectedPriority { priority: self.0 });
        }
        if self.0 != COMMISSIONED_PRIORITY {
            return Err(PreviewError::UnallocatedPriority { priority: self.0 });
        }
        Ok(self)
    }
}

/// Exact accepted target: scope, equipment, and the revision pair the preview
/// is bound to. Only the synthetic fixture is admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedTarget {
    scope: TrustedScope,
    equipment: InstalledId,
    binding_revision: BindingRevision,
    accepted_revision: AcceptedRevision,
}

impl AcceptedTarget {
    /// Admit only `scope-a` with `ahu-1`/`vav-101` (synthetic-only).
    pub fn new(
        scope: TrustedScope,
        equipment: InstalledId,
        binding_revision: BindingRevision,
        accepted_revision: AcceptedRevision,
    ) -> Result<Self> {
        if scope.as_str() != "scope-a" {
            return Err(PreviewError::Invalid("synthetic scope-a only"));
        }
        if equipment.as_str() != "ahu-1" && equipment.as_str() != "vav-101" {
            return Err(PreviewError::Invalid("synthetic ahu-1/vav-101 only"));
        }
        Ok(Self {
            scope,
            equipment,
            binding_revision,
            accepted_revision,
        })
    }

    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }
    pub fn equipment(&self) -> &InstalledId {
        &self.equipment
    }
    pub fn binding_revision(&self) -> BindingRevision {
        self.binding_revision
    }
    pub fn accepted_revision(&self) -> AcceptedRevision {
        self.accepted_revision
    }

    /// Bound to this exact revision pair; any other pair needs a new preview.
    pub fn require_current(
        &self,
        binding: BindingRevision,
        accepted: AcceptedRevision,
    ) -> Result<()> {
        if binding != self.binding_revision || accepted != self.accepted_revision {
            return Err(PreviewError::RevisionMismatch {
                detail: "preview revision-bound; re-preview at the new revision",
            });
        }
        Ok(())
    }

    /// Join to a stable finding: revision must equal the target revision.
    pub fn require_finding(&self, finding: &Finding) -> Result<()> {
        if finding.binding_revision() != self.binding_revision {
            return Err(PreviewError::RevisionMismatch {
                detail: "finding revision does not match preview target",
            });
        }
        Ok(())
    }
}

/// Commandable object identity: direct unsegmented Analog Value `presentValue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetObject {
    object_type: u16,
    property_id: u32,
    array_index: Option<u32>,
}

impl TargetObject {
    pub fn new(object_type: u16, property_id: u32, array_index: Option<u32>) -> Self {
        Self {
            object_type,
            property_id,
            array_index,
        }
    }

    /// Refuse every noncommandable object/property in this profile.
    pub fn check_commandable(self) -> Result<Self> {
        if self.object_type != OBJECT_ANALOG_VALUE {
            return Err(PreviewError::Noncommandable {
                detail: "synthetic Analog Value only",
            });
        }
        if self.property_id != PROP_PRESENT_VALUE {
            return Err(PreviewError::Noncommandable {
                detail: "synthetic presentValue only",
            });
        }
        Ok(self)
    }

    /// `presentValue` is scalar; any array index is ambiguous and refused.
    pub fn check_scalar(self) -> Result<Self> {
        match self.array_index {
            None => Ok(self),
            Some(index) => Err(PreviewError::AmbiguousArray { index }),
        }
    }

    pub fn object_type(self) -> u16 {
        self.object_type
    }
    pub fn property_id(self) -> u32 {
        self.property_id
    }
    pub fn array_index(self) -> Option<u32> {
        self.array_index
    }
}

/// Require exactly `degC` (case-sensitive); all others refuse `wrong-unit`.
pub fn check_unit(unit: &Unit) -> Result<()> {
    if unit.as_str() == "degC" {
        Ok(())
    } else {
        Err(PreviewError::WrongUnit {
            expected: "degC".to_string(),
            presented: unit.as_str().to_string(),
        })
    }
}

/// Encoded setpoint with wire confirmation and priority masking shown.
#[derive(Debug, Clone, PartialEq)]
pub struct EncodedSetpoint {
    requested_c: f64,
    wire_bits: u32,
    wire_c: f64,
    rounding_error: f64,
    mask_note: &'static str,
}

impl EncodedSetpoint {
    fn build(requested_c: f64, wire_c: f64) -> Result<Self> {
        if !requested_c.is_finite() || !wire_c.is_finite() {
            return Err(PreviewError::Invalid("finite setpoint"));
        }
        if !(RANGE_MIN_C..=RANGE_MAX_C).contains(&requested_c) {
            return Err(PreviewError::WireRange {
                requested: format!("{requested_c:.4}"),
                wire: format!("{wire_c:.4}"),
            });
        }
        if !(RANGE_MIN_C..=RANGE_MAX_C).contains(&wire_c) {
            return Err(PreviewError::WireRange {
                requested: format!("{requested_c:.4}"),
                wire: format!("{wire_c:.4}"),
            });
        }
        let rounding_error = (wire_c - requested_c).abs();
        if rounding_error > TOLERANCE_C {
            return Err(PreviewError::WireRange {
                requested: format!("{requested_c:.4}"),
                wire: format!("{wire_c:.4}"),
            });
        }
        let wire_bits = (wire_c as f32).to_bits();
        Ok(Self {
            requested_c,
            wire_bits,
            wire_c,
            rounding_error,
            mask_note: MASK_NOTE,
        })
    }

    /// Encode as BACnet Real (`f32`) and confirm range/tolerance still hold.
    pub fn new(requested_c: f64) -> Result<Self> {
        let wire_c = f64::from(requested_c as f32);
        Self::build(requested_c, wire_c)
    }

    /// Explicit wire value confirms rounding that leaves the range refuses.
    pub fn from_decoded(requested_c: f64, wire_c: f64) -> Result<Self> {
        Self::build(requested_c, wire_c)
    }

    pub fn requested_c(&self) -> f64 {
        self.requested_c
    }
    pub fn wire_c(&self) -> f64 {
        self.wire_c
    }
    pub fn wire_bits(&self) -> u32 {
        self.wire_bits
    }
    pub fn rounding_error(&self) -> f64 {
        self.rounding_error
    }
    pub fn mask_note(&self) -> &'static str {
        self.mask_note
    }
}

/// Duplicate aliases refuse `duplicate-identity`; comparison is exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasSet(Vec<String>);

impl AliasSet {
    pub fn new(aliases: &[&str]) -> Result<Self> {
        let mut seen = std::collections::BTreeSet::new();
        for alias in aliases {
            if alias.is_empty() {
                return Err(PreviewError::Invalid("empty alias"));
            }
            if !seen.insert((*alias).to_string()) {
                return Err(PreviewError::DuplicateAlias {
                    alias: (*alias).to_string(),
                });
            }
        }
        Ok(Self(seen.into_iter().collect()))
    }

    pub fn aliases(&self) -> &[String] {
        &self.0
    }
}

/// Human preview needs publish-grade assistance; reviewer-grade refuses.
pub fn check_access(ceiling: u8, role: RoleKind) -> Result<()> {
    match role {
        RoleKind::Publisher => {
            if ceiling < REQUIRED_PUBLISH_CEILING {
                return Err(PreviewError::AssistanceCeiling {
                    have: ceiling,
                    required: REQUIRED_PUBLISH_CEILING,
                });
            }
            Ok(())
        }
        RoleKind::Reviewer => Err(PreviewError::AssistanceCeiling {
            have: ceiling,
            required: REQUIRED_PUBLISH_CEILING,
        }),
    }
}
