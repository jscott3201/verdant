//! M01-PR02 shared domain: identities, values, times and operation outcomes.
//!
//! Immediate representation-level contracts for PR03 (stores), PR04 (access),
//! PR05 (native lifecycle) and PR06 (semantics converter). Std-only,
//! zero dependencies. No stream/recovery runtime, no authentication, no
//! stores/SQL, no native lifecycle, no field acquisition here.
//!
//! ## Frozen examples (representation only)
//!
//! - Scopes: `"scope-a"`, `"scope-b"` (see [`scope::TrustedScope`]).
//! - Installed equipment: `"ahu-1"`, `"vav-101"`, `"vav-102"`
//!   (see [`ids::InstalledId`]).
//! - Shared sensor: `"sensor-sat-1"` (one source, see [`fixture::tiny_site`]).
//! - Business operation: `"op-1"` (see [`ids::OperationId`]).
//! - Source generation: `"gen-1"` (see [`ids::SourceGenerationId`]).
//! - Acquisition stream (reserved placeholder): `"stream-1"`
//!   (see [`ids::AcquisitionStreamId`]).
//! - Rule activation (reserved placeholder): `"act-1"`
//!   (see [`ids::RuleActivationId`]).
//! - Binding revision placeholder: `0` (see [`ids::BindingRevision`]).
//!
//! Later owners implement actual restore/activation behavior. Any shared
//! change to these types must be listed explicitly in the delivery handoff
//! for integration review; do not widen this surface opportunistically.
//!
//! ## Boundaries honored here
//!
//! - Labels/addresses are not installed identity: [`ids::InstalledId`] is a
//!   validated newtype, distinct from operation/generation/stream/activation
//!   identities (see [`ids`] docs).
//! - Caller strings cannot manufacture trusted context: [`scope::TrustedScope`]
//!   and [`scope::CredentialCeiling`] have validated constructors only, no
//!   `From<String>`/`Default`.
//! - `std::time::Instant` is never serialized as portable history: only
//!   [`clock::MonotonicMark`] (`boot` + `nanos_since_boot`) is portable.
//! - `false` vs `0` vs missing vs invalid vs tagged non-finite diagnostics are
//!   distinct (see [`values::Value`]).
//! - Unknown enums/units are preserved as unknown, never coerced
//!   (see [`values::Unit`], [`values::OpMode`]).
//! - Mutation outcomes distinguish known commit / known refusal-noncommit /
//!   conflict / unresolved; unknown commit is **not** rollback
//!   (see [`outcomes::OperationOutcome`]).
//! - Release is an explicit operation with round-trip, not a value default
//!   (see [`outcomes::Release`]; no `Default` impl by design).
//! - Restored counters must not silently identify different new records as old
//!   ones: [`outcomes::RecordIdentity`] includes the generation in identity.
//!
//! No plant physics and no ontology equivalence claim (see [`fixture`]).

pub mod clock;
pub mod fixture;
pub mod ids;
pub mod outcomes;
pub mod scope;
pub mod values;

mod json;

use std::fmt;

/// Typed domain failure. Callers match variants; malformed input never panics.
///
/// `code()` returns a stable machine-readable code for tests and evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Required text was empty (`what` names the field/kind).
    Empty { what: &'static str },
    /// Text exceeded its bound.
    TooLong {
        what: &'static str,
        len: usize,
        max: usize,
    },
    /// Text contained characters outside the allowed set. `value` echoes the
    /// rejected input (never secret material; domain holds no secrets).
    BadChars { what: &'static str, value: String },
    /// Text was syntactically well-formed but semantically invalid.
    InvalidValue { what: &'static str, value: String },
    /// A required JSON/object field was absent.
    MissingField { field: &'static str },
    /// An unexpected field or type tag was present.
    UnexpectedField { field: String },
    /// A type tag or kind string was not the expected one.
    UnexpectedType { expected: &'static str, got: String },
    /// Wall-clock triple violated `source <= receipt <= ingestion`.
    ImpossibleOrder { detail: String },
    /// Monotonic elapsed calculation was impossible (`end < start`,
    /// overflow, or equivalent).
    ImpossibleElapsed { detail: String },
    /// Two monotonic marks came from different boots.
    BootMismatch { expected: String, got: String },
    /// Raw JSON text was malformed.
    Json { message: String },
}

impl Error {
    /// Stable machine-readable code for tests and evidence mapping.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Empty { .. } => "empty",
            Error::TooLong { .. } => "too-long",
            Error::BadChars { .. } => "bad-chars",
            Error::InvalidValue { .. } => "invalid-value",
            Error::MissingField { .. } => "missing-field",
            Error::UnexpectedField { .. } => "unexpected-field",
            Error::UnexpectedType { .. } => "unexpected-type",
            Error::ImpossibleOrder { .. } => "impossible-order",
            Error::ImpossibleElapsed { .. } => "impossible-elapsed",
            Error::BootMismatch { .. } => "boot-mismatch",
            Error::Json { .. } => "json",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Empty { what } => write!(f, "{what} must not be empty"),
            Error::TooLong { what, len, max } => {
                write!(f, "{what} is {len} chars; maximum is {max}")
            }
            Error::BadChars { what, value } => {
                write!(f, "{what} has unsupported characters: '{value}'")
            }
            Error::InvalidValue { what, value } => {
                write!(f, "{what} is invalid: '{value}'")
            }
            Error::MissingField { field } => write!(f, "missing required field '{field}'"),
            Error::UnexpectedField { field } => write!(f, "unexpected field '{field}'"),
            Error::UnexpectedType { expected, got } => {
                write!(f, "expected {expected}, got '{got}'")
            }
            Error::ImpossibleOrder { detail } => {
                write!(f, "impossible clock order: {detail}")
            }
            Error::ImpossibleElapsed { detail } => {
                write!(f, "impossible elapsed time: {detail}")
            }
            Error::BootMismatch { expected, got } => write!(
                f,
                "monotonic marks span different boots: expected '{expected}', got '{got}'"
            ),
            Error::Json { message } => write!(f, "invalid JSON: {message}"),
        }
    }
}

impl std::error::Error for Error {}
