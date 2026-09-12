//! Typed native-lifecycle failures with stable machine codes.
//!
//! Every failure a caller can observe from [`crate::native`] arrives here.
//! Malformed input, unknown versions, exhausted budgets and unavailable
//! durability are refused with a typed [`NativeError`]; nothing panics on an
//! input path. Matches over this enum stay exhaustive so a new variant breaks
//! the build, not behavior.

use std::fmt;

/// Typed native failure. Callers match variants; `code()` returns the stable
/// machine-readable code asserted by `tests/native_lifecycle.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeError {
    /// A caller argument failed facade-level validation (`what` names the
    /// argument; `detail` carries the reason, never secret material).
    InvalidInput { what: &'static str, detail: String },
    /// The directory holds a recognizable but unsupported native format or
    /// version (e.g. v1-era `SLDB`/`SLSN`/`SLMF`/`SLAU` headers found by the
    /// read-only legacy probe). Refused BEFORE activation: no handle is
    /// returned and the store is left untouched.
    UnsupportedFormat { detail: String },
    /// The store's profile/Unicode/collation identity differs from the
    /// running Selene build. Refused before activation, never migrated.
    Compatibility { detail: String },
    /// Strict create found an existing initialized store (or unpublished
    /// bootstrap artifacts). Never overwrites, never adopts foreign files.
    /// `dir` is the facade-supplied store path (reopen/retry authority);
    /// `detail` carries the Selene diagnostic.
    AlreadyInitialized { dir: String, detail: String },
    /// Open found no initialized format-2 store at the directory.
    /// `dir` is the facade-supplied store path; `detail` carries the Selene
    /// diagnostic.
    NotInitialized { dir: String, detail: String },
    /// Another owning database/session retains the store lock.
    Contention { detail: String },
    /// The facade admission gate is saturated (`max_inflight` reached). The
    /// work is refused promptly instead of queueing an unbounded stall.
    Busy { detail: String },
    /// A tested facade resource ceiling was exhausted (statement bytes or
    /// store bytes). Refused BEFORE the work is promised or attempted.
    ResourceLimit { detail: String },
    /// Observed store/maintenance capacity or a Selene resource budget exhausted.
    /// Operator action is required; not a host-global quota or disk-full proof.
    MaintenanceRequired { detail: String },
    /// Native durable filesystem mode is unavailable on this platform.
    UnsupportedPlatform { detail: String },
    /// CURRENT may select a complete new snapshot. Never retry blindly.
    CheckpointUncertain { detail: String },
    /// The owning handle is fenced after uncertainty: no more writes or
    /// checkpoints on this owner; drop every handle and reopen.
    Fenced { detail: String },
    /// A managed artifact failed integrity checks, is structurally corrupt,
    /// or is incomplete in a way no repair is authorized for.
    Integrity { detail: String },
    /// Native catalog/graph/value validation rejected the image, or lifecycle
    /// use was invalid (stale session reference, memory-only authority, ...).
    Semantic { detail: String },
    /// One GQL statement was rejected (parse, plan or execution failure).
    /// The mutation did not commit; the error carries the facade diagnostic.
    StatementRejected { detail: String },
    /// Native filesystem I/O outside the Selene envelope failed.
    Io { path: String, message: String },
    /// A Selene lifecycle failure with no narrower mapping. `phase` and
    /// `kind` carry the Selene [`selene_db::StoragePhase`]/[`selene_db::StorageErrorKind`]
    /// debug names so the handoff can classify it without guessing.
    Lifecycle {
        phase: String,
        kind: String,
        detail: String,
    },
}

impl NativeError {
    /// Stable machine-readable code for tests and evidence mapping.
    pub fn code(&self) -> &'static str {
        match self {
            NativeError::InvalidInput { .. } => "invalid-input",
            NativeError::UnsupportedFormat { .. } => "unsupported-format",
            NativeError::Compatibility { .. } => "compatibility-mismatch",
            NativeError::AlreadyInitialized { .. } => "already-initialized",
            NativeError::NotInitialized { .. } => "not-initialized",
            NativeError::Contention { .. } => "contention",
            NativeError::Busy { .. } => "busy",
            NativeError::ResourceLimit { .. } => "resource-limit",
            NativeError::MaintenanceRequired { .. } => "maintenance-required",
            NativeError::UnsupportedPlatform { .. } => "unsupported-platform",
            NativeError::CheckpointUncertain { .. } => "checkpoint-uncertain",
            NativeError::Fenced { .. } => "fenced",
            NativeError::Integrity { .. } => "integrity",
            NativeError::Semantic { .. } => "semantic",
            NativeError::StatementRejected { .. } => "statement-rejected",
            NativeError::Io { .. } => "io",
            NativeError::Lifecycle { .. } => "lifecycle",
        }
    }

    /// Refuse a caller argument with a typed error (never a panic).
    pub fn invalid_input(what: &'static str, detail: impl Into<String>) -> NativeError {
        NativeError::InvalidInput {
            what,
            detail: detail.into(),
        }
    }

    /// Map one Selene facade lifecycle failure onto the nearest variant.
    ///
    /// Version/identity refusals keep their dedicated variants so tests can
    /// assert refusal-before-activation precisely; anything unmapped stays a
    /// [`NativeError::Lifecycle`] with its Selene phase/kind names attached.
    ///
    /// `dir` is the facade-supplied store path and is recorded verbatim on
    /// [`NativeError::AlreadyInitialized`]/[`NativeError::NotInitialized`] so
    /// the path field stays a path (reopen/retry authority for M01-PR08+);
    /// the Selene Display diagnostic is preserved in `detail`, never in `dir`.
    pub fn from_storage_in(err: selene_db::StorageError, dir: &std::path::Path) -> NativeError {
        use selene_db::StorageErrorKind as K;
        let phase = format!("{:?}", err.phase);
        let kind_name = format!("{:?}", err.kind);
        let detail = format!("{err}");
        let dir_string = dir.display().to_string();
        match err.kind {
            K::UnsupportedFormat => NativeError::UnsupportedFormat { detail },
            K::Compatibility => NativeError::Compatibility { detail },
            K::AlreadyInitialized => NativeError::AlreadyInitialized {
                dir: dir_string,
                detail,
            },
            K::NotInitialized => NativeError::NotInitialized {
                dir: dir_string,
                detail,
            },
            K::Contention => NativeError::Contention { detail },
            K::ResourceLimit => NativeError::MaintenanceRequired { detail },
            K::Fenced => NativeError::Fenced { detail },
            K::MissingArtifact
            | K::InvalidArtifact
            | K::Integrity
            | K::Corruption
            | K::IncompleteTail
            | K::IncompleteRequired
            | K::DigestLineage
            | K::Lineage
            | K::SequenceGap
            | K::SequenceOverlap
            | K::ForeignStore
            | K::ForeignEpoch
            | K::ForeignSegment => NativeError::Integrity { detail },
            K::Semantic | K::NativeAdmission | K::InvalidState | K::InMemory => {
                NativeError::Semantic { detail }
            }
            K::Io => NativeError::Io { path: dir_string, message: detail },
            K::UnsupportedPlatform => NativeError::UnsupportedPlatform { detail },
            K::CheckpointUncertain => NativeError::CheckpointUncertain { detail },
            _ => NativeError::Lifecycle {
                phase,
                kind: kind_name,
                detail,
            },
        }
    }

    /// Map one Selene GQL statement failure onto [`NativeError::StatementRejected`].
    ///
    /// Reserved for `execute()`-time outcomes only. Activation-proof session
    /// failures and `init_lifecycle` catalog-Strict failures must use
    /// [`NativeError::from_activation`] so "not our lifecycle, quarantine" is
    /// never conflated with "bad statement, retry".
    pub fn from_statement(err: selene_db::Error) -> NativeError {
        NativeError::StatementRejected {
            detail: format!("execute/{:?} status={:?}: {err}", err.kind(), err.gqlstatus()),
        }
    }

    /// Map an activation-proof or lifecycle-bootstrap failure onto
    /// [`NativeError::Integrity`] with the Selene diagnostic attached.
    ///
    /// Used for the `open` activation proof (`session` on the expected
    /// `selene/memory/data` graph) and for `init_lifecycle` catalog-Strict
    /// failures. A foreign-but-valid format-2 store without the lifecycle
    /// graph is quarantine-class, never statement-rejected.
    pub fn from_activation(err: selene_db::Error) -> NativeError {
        NativeError::Integrity {
            detail: format!("lifecycle activation/{:?} status={:?} failed (not our lifecycle, quarantine): {err}", err.kind(), err.gqlstatus()),
        }
    }

    /// Narrow adapter for callers whose storage view governs. Do not turn
    /// integrity, uncertain publication, I/O or bad statements into exhaustion.
    pub fn storage_maintenance_error(&self) -> Option<crate::storage::StorageError> {
        match self {
            Self::MaintenanceRequired { detail } => Some(crate::storage::StorageError::MaintenanceRequired { detail: detail.clone() }),
            Self::InvalidInput { .. } | Self::UnsupportedFormat { .. }
            | Self::Compatibility { .. } | Self::AlreadyInitialized { .. }
            | Self::NotInitialized { .. } | Self::Contention { .. } | Self::Busy { .. }
            | Self::ResourceLimit { .. } | Self::UnsupportedPlatform { .. }
            | Self::CheckpointUncertain { .. } | Self::Fenced { .. }
            | Self::Integrity { .. } | Self::Semantic { .. } | Self::StatementRejected { .. }
            | Self::Io { .. } | Self::Lifecycle { .. } => None,
        }
    }
}

impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NativeError::InvalidInput { what, detail } => {
                write!(f, "invalid {what}: {detail}")
            }
            NativeError::UnsupportedFormat { detail } => {
                write!(
                    f,
                    "unsupported native format (refused before activation): {detail}"
                )
            }
            NativeError::Compatibility { detail } => {
                write!(
                    f,
                    "native store identity mismatch (refused, never migrated): {detail}"
                )
            }
            NativeError::AlreadyInitialized { dir, detail } => {
                write!(
                    f,
                    "native store already initialized (refusing to overwrite): {dir} ({detail})"
                )
            }
            NativeError::NotInitialized { dir, detail } => {
                write!(
                    f,
                    "no initialized native store (refusing to invent one): {dir} ({detail})"
                )
            }
            NativeError::Contention { detail } => {
                write!(f, "native store lock retained by another owner: {detail}")
            }
            NativeError::Busy { detail } => {
                write!(
                    f,
                    "native admission saturated (refused, not queued): {detail}"
                )
            }
            NativeError::ResourceLimit { detail } => {
                write!(
                    f,
                    "native resource ceiling exhausted (refused before promise): {detail}"
                )
            }
            NativeError::MaintenanceRequired { detail } => write!(f, "native maintenance required: {detail}"),
            NativeError::UnsupportedPlatform { detail } => write!(f, "native platform unsupported: {detail}"),
            NativeError::CheckpointUncertain { detail } => write!(f, "native checkpoint uncertain (drop all owners and inspect on reopen; never retry blindly): {detail}"),
            NativeError::Fenced { detail } => {
                write!(
                    f,
                    "native owner fenced after uncertainty (drop and reopen): {detail}"
                )
            }
            NativeError::Integrity { detail } => {
                write!(
                    f,
                    "native artifact integrity failure (no repair authorized): {detail}"
                )
            }
            NativeError::Semantic { detail } => {
                write!(f, "native semantic rejection: {detail}")
            }
            NativeError::StatementRejected { detail } => {
                write!(f, "native statement rejected (not committed): {detail}")
            }
            NativeError::Io { path, message } => {
                write!(f, "native io failure at '{path}': {message}")
            }
            NativeError::Lifecycle {
                phase,
                kind,
                detail,
            } => {
                write!(f, "native lifecycle failure [{phase}/{kind}]: {detail}")
            }
        }
    }
}

impl std::error::Error for NativeError {}
