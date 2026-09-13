//! PR09A authenticated in-process setup. No opener, CLI, worker, or field authority.
//!
//! The integration owner lends existing access/binding/seal owners. API intent is
//! an additive outbox journal; effects still go through their existing owners.
//! Intent and effect are deliberately separate commits. A pending/canceled intent
//! is inspectable, never mistaken for a committed effect. Retain operation IDs
//! and immutable inputs; no timeout licenses a fresh operation. Calls are
//! synchronous and exclusively borrow this coordinator: cancellation is observed
//! between calls, not an assertion that an already dispatched effect was stopped.
#![allow(dead_code)] // Compiled API; executable verbs are explicitly deferred.
#![allow(unused_imports)] // Public surface is consumed by tests and later CLI wiring.

mod journal;
mod operations;
mod readers;
mod recovery;

#[cfg(test)]
pub(crate) use operations::on_draft_boundary;
pub use operations::{DraftContent, DraftRevision, Publication, Reference};
pub use readers::{
    Availability, Diagnostic, Page, PageRequest, Readiness, ScopeStatus, SealLookup, WorkStatus,
};
pub use recovery::RecoveryAction;

use crate::accept::AcceptanceStore;
use crate::access::{AccessGate, ActorContext, Credential};
use crate::binding::{BindingRegistry, BindingRole};
use crate::domain::{ids::OperationId, scope::TrustedScope};
use crate::seal::SealStore;

pub struct Api<'a> {
    gate: &'a AccessGate,
    registry: &'a mut BindingRegistry,
    seals: &'a SealStore,
    accepted: AcceptanceStore,
}
impl<'a> Api<'a> {
    /// Borrows admitted owners, never creates a competing writable opener.
    /// Merely constructing the facade grants no credential or native readiness.
    pub fn new(
        gate: &'a AccessGate,
        registry: &'a mut BindingRegistry,
        seals: &'a SealStore,
    ) -> Result<Self> {
        if std::fs::canonicalize(gate.db_path())?
            != std::fs::canonicalize(registry.store().db_path())?
        {
            return Err(Error::Conflict("access/binding owners differ"));
        }
        let accepted = AcceptanceStore::new(registry.store().try_clone()?);
        Ok(Self {
            gate,
            registry,
            seals,
            accepted,
        })
    }

    fn authenticate(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
        write: bool,
    ) -> Result<ActorContext> {
        let actor = self.gate.authenticate(credential, scope)?;
        if actor.capability().starts_with(recovery::PREFIX) {
            return Err(Error::RecoveryRestricted);
        }
        if write {
            self.gate.enter_publish(credential, scope)?;
        } else {
            self.gate.enter_review(credential, scope)?;
        }
        Ok(actor)
    }

    fn credential<'c>(&self, credential: Option<&'c Credential>) -> Result<&'c Credential> {
        credential.ok_or(Error::Unauthenticated)
    }
}

#[derive(Debug)]
pub enum Error {
    Unauthenticated,
    Invalid(&'static str),
    Limit(&'static str),
    Conflict(&'static str),
    Missing(String),
    SealedMutation,
    Cancelled,
    RecoveryRestricted,
    Unknown {
        operation: OperationId,
        detail: String,
    },
    Access(crate::access::AccessError),
    Binding(crate::binding::BindingError),
    Accept(crate::accept::Error),
    Seal(crate::seal::SealError),
    Storage(crate::storage::StorageError),
    Io(std::io::Error),
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated => "api-unauthenticated",
            Self::Invalid(_) => "api-invalid",
            Self::Limit(_) => "api-limit",
            Self::Conflict(_) => "api-conflict",
            Self::Missing(_) => "api-missing-content",
            Self::SealedMutation => "api-sealed-mutation",
            Self::Cancelled => "api-cancelled",
            Self::RecoveryRestricted => "api-recovery-restricted",
            Self::Unknown { .. } => "api-unknown",
            Self::Access(e) => e.code(),
            Self::Binding(e) => e.code(),
            Self::Accept(e) => e.code(),
            Self::Seal(e) => e.code(),
            Self::Storage(e) => e.code(),
            Self::Io(_) => "api-io",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}
impl std::error::Error for Error {}
macro_rules! source_error {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for Error {
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        }
    };
}
source_error!(crate::access::AccessError, Access);
source_error!(crate::binding::BindingError, Binding);
source_error!(crate::accept::Error, Accept);
source_error!(crate::seal::SealError, Seal);
source_error!(crate::storage::StorageError, Storage);
source_error!(std::io::Error, Io);
pub type Result<T> = std::result::Result<T, Error>;
