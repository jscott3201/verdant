//! M01-PR07 binding typed failures with stable machine codes.
//!
//! Every refusal in this slice is a typed [`BindingError`]; matches stay
//! exhaustive so new variants break the build. `code()` is the stable
//! machine-readable string asserted by `tests/binding*.rs` and the PR11
//! handoff. Malformed input is refused, never panics.

use std::fmt;

/// Typed binding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    /// Caller text failed validation (never a panic).
    InvalidInput { what: &'static str, detail: String },
    /// A stored binding row failed to decode (fail closed).
    InvalidRecord { detail: String },
    /// Second record reuses an installed identity with different labels.
    DuplicateIdentity { id: String, detail: String },
    /// Binding unit does not match the point expectation.
    WrongUnit { expected: String, presented: String },
    /// Requested/effective role mismatch or insufficient capability role.
    WrongRole { requested: String, detail: String },
    /// Feedback role is ambiguous (never silently resolved).
    AmbiguousFeedback { detail: String },
    /// Endpoint scope and point scope differ, or the credential scope does
    /// not cover the binding scope. Cross-scope links grant nothing.
    ScopeDenied { expected: String, presented: String },
    /// New record reuses a retired address: fresh qualification required.
    NeedsReassessment {
        id: String,
        address: String,
        detail: String,
    },
    /// Endpoint service/location classification does not match the point.
    EndpointConfusion { expected: String, presented: String },
    /// PR06 class known but outside the pinned tiny_site scenario.
    ImportOutOfScenario {
        class: String,
        reason: String,
        profile: String,
    },
    /// PR06 class not recognized by the pinned profile.
    ImportUnknownClass { class: String, profile: String },
    /// PR06 collision: two candidates claim one Verdant slot (no merge).
    ImportCollision {
        slot: String,
        candidates: String,
        profile: String,
    },
    /// PR06 slot/kind prefix mismatch.
    ImportSlotMismatch {
        class: String,
        kind: String,
        slot: String,
        profile: String,
    },
    /// Capability check failed (revoked, forged, stale, ceiling/role detail
    /// preserved in `detail`; PR04 code preserved in `access_code`).
    CapabilityDenied { detail: String, access_code: String },
    /// A competing durable evolution or an operation/request mismatch won.
    Conflict { detail: String },
    /// Commit was not observed. Reconcile this identity; never create new work.
    MutationUnknown { operation: crate::domain::ids::OperationId, detail: String },
    /// No history is available in the requested observation window.
    EmptyWindow,
    /// Wrapped PR03 storage failure (code preserved).
    Store(crate::storage::StorageError),
}

impl BindingError {
    /// Stable machine-readable code for tests and evidence mapping.
    pub fn code(&self) -> &'static str {
        match self {
            BindingError::InvalidInput { .. } => "invalid-input",
            BindingError::InvalidRecord { .. } => "invalid-record",
            BindingError::DuplicateIdentity { .. } => "duplicate-identity",
            BindingError::WrongUnit { .. } => "wrong-unit",
            BindingError::WrongRole { .. } => "wrong-role",
            BindingError::AmbiguousFeedback { .. } => "ambiguous-feedback",
            BindingError::ScopeDenied { .. } => "scope-denied",
            BindingError::NeedsReassessment { .. } => "needs-reassessment",
            BindingError::EndpointConfusion { .. } => "endpoint-confusion",
            BindingError::ImportOutOfScenario { .. } => "import-out-of-scenario",
            BindingError::ImportUnknownClass { .. } => "import-unknown-class",
            BindingError::ImportCollision { .. } => "import-collision",
            BindingError::ImportSlotMismatch { .. } => "import-slot-mismatch",
            BindingError::CapabilityDenied { .. } => "capability-denied",
            BindingError::Conflict { .. } => "conflict",
            BindingError::MutationUnknown { .. } => "mutation-unknown",
            BindingError::EmptyWindow => "empty-window",
            BindingError::Store(inner) => inner.code(),
        }
    }

    /// Wrap an access denial, preserving the PR04 machine code.
    pub fn capability_denied(detail: String, access_code: &str) -> BindingError {
        BindingError::CapabilityDenied {
            detail,
            access_code: access_code.to_string(),
        }
    }
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindingError::InvalidInput { what, detail } => {
                write!(f, "invalid {what}: {detail}")
            }
            BindingError::InvalidRecord { detail } => {
                write!(f, "invalid binding record: {detail}")
            }
            BindingError::DuplicateIdentity { id, detail } => {
                write!(f, "duplicate installed identity '{id}': {detail}")
            }
            BindingError::WrongUnit {
                expected,
                presented,
            } => write!(
                f,
                "wrong unit: point expects '{expected}', binding presents '{presented}'"
            ),
            BindingError::WrongRole { requested, detail } => {
                write!(f, "wrong role: requested '{requested}': {detail}")
            }
            BindingError::AmbiguousFeedback { detail } => {
                write!(f, "ambiguous feedback: {detail}")
            }
            BindingError::ScopeDenied {
                expected,
                presented,
            } => write!(
                f,
                "scope denied: binding scope '{expected}' does not cover '{presented}' (cross-scope links grant nothing)"
            ),
            BindingError::NeedsReassessment { id, address, detail } => write!(
                f,
                "needs reassessment: record '{id}' at retired address '{address}': {detail}"
            ),
            BindingError::EndpointConfusion {
                expected,
                presented,
            } => write!(
                f,
                "endpoint confusion: point expects '{expected}' endpoint, binding presents '{presented}'"
            ),
            BindingError::ImportOutOfScenario {
                class,
                reason,
                profile,
            } => write!(
                f,
                "import refused (out-of-scenario): class '{class}' under profile '{profile}': {reason}"
            ),
            BindingError::ImportUnknownClass { class, profile } => write!(
                f,
                "import refused (unknown-class): class '{class}' under profile '{profile}'"
            ),
            BindingError::ImportCollision {
                slot,
                candidates,
                profile,
            } => write!(
                f,
                "import refused (collision): slot '{slot}' claimed by [{candidates}] under profile '{profile}' (no merge)"
            ),
            BindingError::ImportSlotMismatch {
                class,
                kind,
                slot,
                profile,
            } => write!(
                f,
                "import refused (slot-mismatch): class '{class}' (kind '{kind}') does not match slot '{slot}' under profile '{profile}'"
            ),
            BindingError::CapabilityDenied {
                detail,
                access_code,
            } => write!(f, "capability denied [{access_code}]: {detail}"),
            BindingError::Store(inner) => write!(f, "{inner}"),
            BindingError::Conflict { detail } => write!(f, "binding conflict: {detail}"),
            BindingError::MutationUnknown { operation, detail } => write!(f, "binding outcome UNKNOWN for {}; reconcile this operation: {detail}", operation.as_str()),
            BindingError::EmptyWindow => write!(f, "binding replay window is empty or expired"),
        }
    }
}

impl std::error::Error for BindingError {}
