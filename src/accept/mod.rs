//! M01-PR08A: effective configuration and staged/sealed/accepted transitions.
//!
//! Library-shaped module, deliberately not wired to the PR01 executable. Staging
//! records intent as a seal ContentNode; publishing that node remains seal-owned.
//! Acceptance is one SQLite event + receipt, NOT a native activation or 2PC.
//! Each scope has a bounded, additive accepted-revision chain (256 events).
//! No newest-file selection, rollback, merge, field authority or qualification.
//!
//! Bootstrap provenance comes from access, domain meaning from typed bindings,
//! temporary intent replaces only explicitly named entries, and observed-fact
//! provenance comes from durable findings. Those findings remain structural,
//! not observations. Published bytes cannot be overridden by the environment.
//! Fingerprints exclude labels/provenance but include every binding meaning field.
//!
//! Native availability is delegated to seal custody. This module holds no mutex
//! over hashing, authentication, native checks or SQLite calls. A release racing
//! admission loses the guarded transaction; external file/DB tampering remains
//! outside the existing trusted-parent/guarded-writer model. Receipts are retained;
//! stop/join dispatchers before treating a reconciliation absence as final.
#![allow(dead_code)]

mod codec;
mod effective;
mod publication;
mod store;

pub use effective::check_environment_names;
pub use effective::{EffectiveConfig, Entry, ImpactDiff, ObservedFact, SourceKind};
pub use publication::{Sealed, Staged};
#[cfg(test)]
pub(crate) use store::on_boundary;
pub use store::{AcceptanceRequest, AcceptanceStore, Accepted, PendingAcceptance};

use crate::domain::ids::OperationId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Staged,
    Sealed,
    Accepted,
    Activated,
    Qualified,
}
impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Sealed => "sealed",
            Self::Accepted => "accepted",
            Self::Activated => "activated",
            Self::Qualified => "qualified",
        }
    }
}

/// Acceptance revisions are independent of binding revisions and native epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedRevision(u32);
impl AcceptedRevision {
    pub const INITIAL: Self = Self(0);
    pub fn new(value: u32) -> Result<Self> {
        if value > MAX_ACCEPTED {
            return Err(Error::Limit("accepted revision"));
        }
        Ok(Self(value))
    }
    pub fn get(self) -> u32 {
        self.0
    }
    pub(super) fn next(self) -> Result<Self> {
        Self::new(
            self.0
                .checked_add(1)
                .ok_or(Error::Limit("accepted revision"))?,
        )
    }
}
pub const MAX_ACCEPTED: u32 = 256;

#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Limit(&'static str),
    Conflict(String),
    ApprovalMismatch,
    EnvironmentOverride,
    NotYet {
        requested: Stage,
    },
    /// Availability refusal does not erase an already committed acceptance.
    Blocked(crate::seal::SealError),
    Unknown {
        operation: OperationId,
        detail: String,
    },
    Storage(crate::storage::StorageError),
    Binding(crate::binding::BindingError),
    Access(crate::access::AccessError),
    Seal(crate::seal::SealError),
    Io(std::io::Error),
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "accept-invalid",
            Self::Limit(_) => "accept-limit",
            Self::Conflict(_) => "accept-conflict",
            Self::ApprovalMismatch => "accept-approval-mismatch",
            Self::EnvironmentOverride => "accept-environment-override",
            Self::NotYet { .. } => "accept-not-yet",
            Self::Blocked(_) => "accept-blocked",
            Self::Unknown { .. } => "accept-unknown",
            Self::Storage(e) => e.code(),
            Self::Binding(e) => e.code(),
            Self::Access(e) => e.code(),
            Self::Seal(e) => e.code(),
            Self::Io(_) => "accept-io",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}
impl std::error::Error for Error {}
impl From<crate::storage::StorageError> for Error {
    fn from(e: crate::storage::StorageError) -> Self {
        match e {
            crate::storage::StorageError::Conflict { detail } => Self::Conflict(detail),
            e => Self::Storage(e),
        }
    }
}
impl From<crate::binding::BindingError> for Error {
    fn from(e: crate::binding::BindingError) -> Self {
        Self::Binding(e)
    }
}
impl From<crate::access::AccessError> for Error {
    fn from(e: crate::access::AccessError) -> Self {
        Self::Access(e)
    }
}
impl From<crate::seal::SealError> for Error {
    fn from(e: crate::seal::SealError) -> Self {
        Self::Seal(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
pub type Result<T> = std::result::Result<T, Error>;
