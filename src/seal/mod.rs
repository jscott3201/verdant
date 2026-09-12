//! M01-PR11 application seals: immutable meaning, not qualification or authority.
//!
//! Format `verdant-seal-v1` is a UTF-8 length-prefixed sequence (decimal byte
//! length, colon, exact bytes), with fixed field order and sorted reference sets.
//! SHA-256 of those bytes identifies a seal. Existing FNV fingerprints remain
//! explicitly synthetic. Only structurally Valid binding findings are sealable;
//! Imported and ObservedQualified are refused. No observed evidence exists here.
//!
//! Persistence reuses additive SQLite outbox rows + R03 receipts, generation 1.
//! No schema migration, archive, GQL row API, checkpoint-as-version, automatic
//! activation, or distributed transaction. Native refs name exact immutable
//! manifest/snapshot bytes; filenames are derived locators, not authority.
//! Custody is scoped to one canonical SQLite/native pair: at most 32 live seals,
//! 256 history rows, 64 closure nodes, depth 16, 256 KiB closure bytes, 8 native
//! references per seal, 2 MiB per artifact. Exhaustion refuses before acceptance.
//! Prune/acceptance windows use non-queueing admission; contention returns Busy.
//! Native manifest/snapshot availability is not a restorable native archive or
//! a WAL/recovery closure: no native replay is promised by capture simulation.
//! System shasum and its runtime are trusted local tools, not sandboxed plugins.
//! Explicit authenticated release ends availability/capture eligibility; history
//! remains immutable. A missing guard/DB fails closed. Raw DB/filesystem tampering
//! is outside the guarded-writer/trusted-parent model (as in access/binding).
#![allow(dead_code)]
#![allow(unused_imports)]

mod codec;
mod digest;
mod manifest;
mod references;
mod store;

pub use digest::{Digest, Sha256};
pub use manifest::{Draft, Manifest, RuntimeRef};
pub use references::{ContentNode, NativeRef, RowKey};
#[cfg(test)]
pub(crate) use store::on_boundary;
pub use store::{SealCommit, SealStore};

pub const MAX_NODES: usize = 64;
pub const MAX_DEPTH: usize = 16;
pub const MAX_CLOSURE_BYTES: usize = 262_144;
pub const MAX_MANIFEST_BYTES: usize = 60_000;
pub const MAX_ARTIFACT_BYTES: usize = 2_097_152;
pub const MAX_NATIVE_REFS: usize = 8;
pub const MAX_LIVE_SEALS: usize = 32;
pub const MAX_HISTORY: usize = 256;

#[derive(Debug)]
pub enum SealError {
    Invalid(&'static str),
    Missing(String),
    Changed(String),
    Status(String),
    Cycle,
    Limit(&'static str),
    SealedMutation,
    Released,
    Conflict(String),
    Unknown {
        operation: crate::domain::ids::OperationId,
        detail: String,
    },
    HashTool(String),
    Io(std::io::Error),
    Storage(crate::storage::StorageError),
    Binding(crate::binding::BindingError),
    Access(crate::access::AccessError),
    Native(crate::native::NativeError),
}
impl SealError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "seal-invalid",
            Self::Missing(_) => "seal-missing-reference",
            Self::Changed(_) => "seal-reference-changed",
            Self::Status(_) => "seal-status-refused",
            Self::Cycle => "seal-reference-cycle",
            Self::Limit(_) => "seal-limit",
            Self::SealedMutation => "sealed-mutation",
            Self::Released => "seal-released",
            Self::Conflict(_) => "seal-conflict",
            Self::Unknown { .. } => "seal-unknown",
            Self::HashTool(_) => "seal-sha256-unavailable",
            Self::Io(_) => "seal-io",
            Self::Storage(e) => e.code(),
            Self::Binding(e) => e.code(),
            Self::Access(e) => e.code(),
            Self::Native(e) => e.code(),
        }
    }
}
impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}
impl std::error::Error for SealError {}
impl From<std::io::Error> for SealError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<crate::storage::StorageError> for SealError {
    fn from(e: crate::storage::StorageError) -> Self {
        Self::Storage(e)
    }
}
impl From<crate::binding::BindingError> for SealError {
    fn from(e: crate::binding::BindingError) -> Self {
        Self::Binding(e)
    }
}
impl From<crate::access::AccessError> for SealError {
    fn from(e: crate::access::AccessError) -> Self {
        Self::Access(e)
    }
}
impl From<crate::native::NativeError> for SealError {
    fn from(e: crate::native::NativeError) -> Self {
        Self::Native(e)
    }
}
pub type Result<T> = std::result::Result<T, SealError>;
