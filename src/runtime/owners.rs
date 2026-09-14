//! Composition only. No alternate SQL, lifecycle implementation or writable API.
use super::{Error, Result};
use crate::{
    accept::{AcceptanceStore, Accepted, Activated, EffectiveConfig},
    access::{AccessGate, Credential},
    api::{Api, PageRequest},
    binding::BindingRegistry,
    domain::scope::TrustedScope,
    native::{NativeHandle, NativeSettings},
    seal::SealStore,
    storage::{ConnectionSettings, StoreBounds},
};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Weak},
};

static OWNERS: Mutex<Vec<Weak<Lease>>> = Mutex::new(Vec::new());
/// In-process exclusivity, including jobs whose caller has gone away. Not a
/// distributed lease. Native's existing writer LOCK remains independently owned.
pub(super) struct Lease {
    pub db: PathBuf,
    pub native: PathBuf,
}
impl Lease {
    pub fn acquire(root: &Path) -> Result<Arc<Self>> {
        let db = std::fs::canonicalize(root.join("meaning.db"))?;
        let native = std::fs::canonicalize(root.join("native"))?;
        if !db.is_file() || !native.is_dir() {
            return Err(Error::Invalid("existing stores required"));
        }
        let mut leases = OWNERS.try_lock().map_err(|_| Error::OwnerBusy)?;
        leases.retain(|entry| entry.strong_count() != 0);
        if leases.iter().filter_map(Weak::upgrade).any(|entry| entry.db == db || entry.native == native) {
            return Err(Error::OwnerBusy);
        }
        if leases.len() >= 32 {
            return Err(Error::Invalid("fixture runtime owner cap"));
        }
        let lease = Arc::new(Self { db, native });
        leases.push(Arc::downgrade(&lease));
        Ok(lease)
    }
}

pub(super) struct Owners {
    pub gate: AccessGate,
    registry: Mutex<BindingRegistry>,
    pub accepted: AcceptanceStore,
    pub seals: SealStore,
    pub native: NativeHandle,
    pub lease: Arc<Lease>,
}
#[derive(Debug, Clone)]
pub(super) struct Selection {
    pub accepted: Accepted,
    pub active: Activated,
    pub config: EffectiveConfig,
}
impl Owners {
    pub fn open(lease: Arc<Lease>) -> Result<Arc<Self>> {
        // Supported openers only, once per runtime. They retain their existing
        // operational-open/custody behavior; no runtime application rows are written.
        let gate = AccessGate::open(&lease.db, ConnectionSettings::local_wal_full(), StoreBounds::tiny())?;
        let registry = BindingRegistry::open(&lease.db, ConnectionSettings::local_wal_full(), StoreBounds::tiny())?;
        let (native, _) = NativeHandle::open(&lease.native, NativeSettings::local())?;
        let seals = SealStore::open(registry.store().try_clone()?, native.clone())?;
        let accepted = AcceptanceStore::new(registry.store().try_clone()?);
        Ok(Arc::new(Self { gate, registry: Mutex::new(registry), accepted, seals, native, lease }))
    }

    pub fn select(&self, credential: &Credential, scope: &TrustedScope) -> Result<Selection> {
        // Access/private Api::authenticate is intentionally consumed through its
        // authenticated public readers, including recovery-key restrictions.
        let (accepted_entries, active_entries) = {
            let mut registry = self.registry.try_lock().map_err(|_| Error::OwnerBusy)?;
            let api = Api::new(&self.gate, &mut registry, &self.seals)?;
            let request = PageRequest::new(0, 64)?;
            let accepted = api.read_accepted(Some(credential), scope, request)?.ok_or(Error::NoAcceptance)?;
            let active = api.read_active(Some(credential), scope, request)?.ok_or(Error::NoActivation)?;
            if accepted.next.is_some() || active.next.is_some() {
                return Err(Error::Invalid("configuration page exceeds fixture bound"));
            }
            (accepted.items, active.items)
        }; // No registry lock during immutable native artifact verification.
        let active = self.accepted.active(scope)?.ok_or(Error::NoActivation)?;
        let accepted = self.accepted.current(scope)?.ok_or(Error::NoAcceptance)?;
        if active.request().acceptance() != &accepted.request {
            return Err(Error::Stale);
        }
        let staged = self.accepted.read_staged(accepted.request.staged_operation())?;
        let sealed = self.accepted.sealed(&staged, accepted.request.seal(), &self.seals)?;
        let config = sealed.config().clone();
        let exact: Vec<_> = config.entries().values().cloned().collect();
        if config.scope() != scope || accepted_entries != exact || active_entries != exact {
            return Err(Error::Stale);
        }
        let selected = Selection { accepted, active, config };
        self.check_generation(&selected, credential)?;
        Ok(selected)
    }

    /// Last-read check, not a lease fencing other processes. No transaction,
    /// native I/O or registry guard survives this call into the adapter.
    pub fn check_generation(&self, selected: &Selection, credential: &Credential) -> Result<()> {
        let scope = selected.config.scope();
        self.gate.enter_review(Some(credential), scope)?;
        let active = self.accepted.active(scope)?.ok_or(Error::NoActivation)?;
        let accepted = self.accepted.current(scope)?.ok_or(Error::NoAcceptance)?;
        if active.row_id() != selected.active.row_id()
            || active.request() != selected.active.request()
            || active.generation() != selected.active.generation()
            || accepted.request != selected.accepted.request
        {
            return Err(Error::Stale);
        }
        Ok(())
    }

    pub fn verify_content(&self, selected: &Selection) -> Result<()> {
        let staged = self.accepted.read_staged(selected.accepted.request.staged_operation())?;
        let sealed = self.accepted.sealed(&staged, selected.accepted.request.seal(), &self.seals)?;
        if sealed.config() != &selected.config {
            return Err(Error::Stale);
        }
        Ok(())
    }
}
