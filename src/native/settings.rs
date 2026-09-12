//! Explicit native settings and tested resource ceilings.
//!
//! Selene owns its internal durability policy (format-2 exclusive; the facade
//! asserts identity instead of reconfiguring it), so [`NativeSettings`]
//! records what the *Verdant* side enforces: per-handle admission bounds and
//! pre-promise resource ceilings. Every bound is a value the operator can
//! read; enforcement is refusal with a typed [`crate::native::NativeError`],
//! never silent loss and never an attempted over-budget promise.

use super::error::NativeError;

/// Tested facade resource ceilings.
///
/// * `max_statement_bytes` — one GQL statement longer than this is refused
///   before it reaches Selene.
/// * `max_store_bytes` — any mutating/maintenance entry whose pre-measured
///   on-disk footprint already exceeds this is refused before it is
///   attempted (the footprint is disclosed in every [`crate::native::OpenReport`]).
/// * `max_inflight` — concurrent facade admissions past this are refused
///   with [`NativeError::Busy`] instead of queueing an unbounded stall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeBounds {
    /// Maximum accepted single-statement length in bytes.
    pub max_statement_bytes: usize,
    /// Maximum accepted pre-measured store footprint in bytes.
    pub max_store_bytes: u64,
    /// Maximum concurrent facade admissions per handle.
    pub max_inflight: u32,
}

impl NativeBounds {
    /// Conservative local defaults: statements stay small, the store ceiling
    /// sits far above any synthetic lifecycle traffic, and a handful of
    /// concurrent admissions may contend inside Selene's own serialization.
    pub fn local() -> NativeBounds {
        NativeBounds {
            max_statement_bytes: 16_384,
            max_store_bytes: 268_435_456,
            max_inflight: 8,
        }
    }

    /// Validate the ceilings; a zero/degenerate bound is a typed refusal,
    /// never a silent clamp.
    pub fn validate(&self) -> Result<(), NativeError> {
        if self.max_statement_bytes < 64 {
            return Err(NativeError::invalid_input(
                "max_statement_bytes",
                format!(
                    "must be at least 64 bytes, got {}",
                    self.max_statement_bytes
                ),
            ));
        }
        // Floor is deliberately small (512 bytes, below any real fresh
        // store): the ceiling must stay testable — a test reopens a
        // synthetic store with a tiny ceiling and asserts typed refusal
        // before promise. Production operators use MiB+ values.
        if self.max_store_bytes < 512 {
            return Err(NativeError::invalid_input(
                "max_store_bytes",
                format!("must be at least 512 bytes, got {}", self.max_store_bytes),
            ));
        }
        if self.max_inflight == 0 {
            return Err(NativeError::invalid_input(
                "max_inflight",
                "must be at least 1 (zero would refuse all work)".to_string(),
            ));
        }
        Ok(())
    }
}

/// Explicit per-handle native settings, recorded on every open report.
///
/// The single supported configuration is a strict lifecycle: create refuses
/// existing stores, open refuses unknown versions before activation, and
/// every admission is counted against [`NativeBounds`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeSettings {
    /// Tested resource ceilings enforced before promise.
    pub bounds: NativeBounds,
}

impl NativeSettings {
    /// The one supported local configuration.
    pub fn local() -> NativeSettings {
        NativeSettings {
            bounds: NativeBounds::local(),
        }
    }

    /// Validate the settings; refuses degenerate bounds with a typed error.
    pub fn validate(&self) -> Result<(), NativeError> {
        self.bounds.validate()
    }
}

impl std::fmt::Display for NativeSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "max_statement_bytes={} max_store_bytes={} max_inflight={}",
            self.bounds.max_statement_bytes, self.bounds.max_store_bytes, self.bounds.max_inflight
        )
    }
}
