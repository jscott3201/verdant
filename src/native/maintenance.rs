//! Synthetic admission plans, exact Selene selections, and explicit cleanup debt.
//! No disk reservation, projected GQL-size claim, or host-global accounting.
use super::*;
use crate::native::report::{CheckpointOutcome, MaintenanceReport, PruneOutcome};
use crate::native::MaintenancePlan;

pub(super) struct CachedCheckpoint {
    report: CheckpointReport,
}

/// A locked application admission window. Callers can install once or prove
/// they are the installed owner, but cannot clear or replace the native guard.
pub(crate) struct CustodyAccess<'a> {
    slot: std::sync::MutexGuard<'a, Option<Arc<dyn super::super::CustodyGuard>>>,
}
impl CustodyAccess<'_> {
    pub(crate) fn is_installed(&self) -> bool { self.slot.is_some() }
    pub(crate) fn matches(&self, guard: &Arc<dyn super::super::CustodyGuard>) -> bool {
        self.slot.as_ref().is_some_and(|installed| Arc::ptr_eq(installed, guard))
    }
    pub(crate) fn install(&mut self, guard: Arc<dyn super::super::CustodyGuard>) -> Result<(), NativeError> {
        if self.slot.is_some() { return Err(NativeError::Custody { plan: custody_unavailable("application custody guard replacement refused") }); }
        *self.slot = Some(guard);
        Ok(())
    }
}

impl NativeHandle {
    /// Sibling sidecar, never a foreign file inside Selene's closed directory.
    /// Its presence requires application guard recovery even after raw reopen.
    /// Trusted parent/guarded writers are required; deleting it externally is
    /// tampering, not a supported way to release custody.
    pub(crate) fn custody_path(&self) -> Result<PathBuf, NativeError> {
        let dir = std::fs::canonicalize(&self.shared.dir).map_err(|e| NativeError::Io {
            path: self.shared.dir.display().to_string(), message: e.to_string(),
        })?;
        let name = dir.file_name().ok_or_else(|| NativeError::invalid_input("custody", "native root needs a parent"))?;
        let mut sidecar = std::ffi::OsString::from(".");
        sidecar.push(name);
        sidecar.push(".verdant-seal-custody-v1");
        Ok(dir.with_file_name(sidecar))
    }

    pub(crate) fn custody_lock(&self) -> Result<CustodyAccess<'_>, NativeError> {
        match self.shared.custody.try_lock() {
            Ok(slot) => Ok(CustodyAccess { slot }),
            Err(std::sync::TryLockError::WouldBlock) => Err(NativeError::Busy { detail: "application custody window active; refusing, not queueing".into() }),
            Err(std::sync::TryLockError::Poisoned(_)) => Err(NativeError::Custody { plan: custody_unavailable("application custody lock poisoned") }),
        }
    }

    fn maintenance_plan(&self) -> Result<MaintenancePlan, NativeError> {
        self.shared.settings.bounds.plan_maintenance(self.store_bytes()?)
    }

    /// Whole-directory regular-file bytes, including coordination/unmanaged
    /// files. Selene retention reports count its classified artifacts instead.
    pub fn store_bytes(&self) -> Result<u64, NativeError> {
        measure_store_bytes(&self.shared.dir).map_err(|message| NativeError::Io {
            path: self.shared.dir.display().to_string(), message,
        })
    }

    /// Checkpoint only inside the observed capacity plan. Repeated checkpoint
    /// on this owner at the same committed sequence reuses its exact selection,
    /// not a new generation with the same logical rows. Cache ownership never
    /// outlives this database; reopen still performs Selene's full validation.
    pub fn checkpoint(&self) -> Result<CheckpointOutcome, NativeError> {
        let _admission = self.shared.gate.try_enter()?;
        let mut cached = self.shared.checkpoint.lock().map_err(|_| NativeError::Lifecycle {
            phase: "Checkpoint".into(), kind: "OwnerLockPoisoned".into(),
            detail: "checkpoint owner poisoned; drop all handles and reopen".into(),
        })?;
        let plan = self.maintenance_plan()?;
        if !plan.admitted() {
            return Ok(CheckpointOutcome::RefusedExhausted { plan, detail: format!("checkpoint plan exhausted: {plan:?}") });
        }
        let db = self.clone_db()?;
        if let (Some(cached), Some(status)) = (cached.as_ref(), db.durable_status()) {
            let covered = cached.report.position;
            if !status.fenced && status.position.store == covered.store
                && status.position.epoch == covered.epoch
                && status.position.sequence == covered.sequence
            {
                // This status is the linearization point for a no-write pass.
                // A subsequent concurrent write invalidates reuse on the next call.
                let mut report = cached.report.clone();
                report.plan = plan;
                report.store_bytes_after = plan.store_bytes;
                return Ok(CheckpointOutcome::Completed(report));
            }
        }
        let outcome = match db.checkpoint().map_err(|e| NativeError::from_storage_in(e, &self.shared.dir)) {
            Ok(outcome) => outcome,
            Err(NativeError::MaintenanceRequired { detail }) => return Ok(CheckpointOutcome::RefusedExhausted { plan, detail }),
            Err(error) => return Err(error),
        };
        let report = CheckpointReport {
            plan,
            generation: outcome.generation,
            snapshot: outcome.snapshot,
            bytes: outcome.bytes,
            digest_hex: hex32(&outcome.digest),
            store_bytes_after: self.store_bytes()?,
            position: outcome.position,
            boundary_digest_hex: hex32(&outcome.boundary_digest),
        };
        *cached = Some(CachedCheckpoint { report: report.clone() });
        Ok(CheckpointOutcome::Completed(report))
    }

    /// Explicit retention only. Both reserves govern admission; partial cleanup
    /// is distinct from a completed (possibly zero-byte) reclaim pass.
    pub fn prune(&self) -> Result<PruneOutcome, NativeError> {
        let _admission = self.shared.gate.try_enter()?;
        let custody = self.custody_lock()?;
        let refusal = match custody.slot.as_ref() {
            Some(guard) => guard.check_prune().err(),
            None => match std::fs::symlink_metadata(self.custody_path()?) {
                Ok(_) => Some(custody_unavailable("seal sidecar present; reopen the application guard before pruning")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => Some(custody_unavailable("seal sidecar cannot be inspected")),
            },
        };
        if let Some(plan) = refusal { return Err(NativeError::Custody { plan }); }
        let plan = self.maintenance_plan()?;
        if !plan.admitted() {
            return Ok(PruneOutcome::RefusedExhausted { plan, detail: format!("prune plan exhausted: {plan:?}") });
        }
        let db = self.clone_db()?;
        let outcome = match db.prune().map_err(|e| NativeError::from_storage_in(e, &self.shared.dir)) {
            Ok(outcome) => outcome,
            Err(NativeError::MaintenanceRequired { detail }) => return Ok(PruneOutcome::RefusedExhausted { plan, detail }),
            Err(error) => return Err(error),
        };
        let report = PruneReport {
            plan,
            store_bytes_before: plan.store_bytes,
            store_bytes_after: self.store_bytes()?,
            removed_count: outcome.removed.len(),
            removed_bytes: outcome.removed.iter().map(|a| a.bytes).sum(),
            retained_bytes: outcome.retained.iter().map(|a| a.artifact.bytes).sum(),
            retained: outcome.retained.iter().map(|a| (a.artifact.name.clone(), format!("{:?}", a.reason))).collect(),
            cleanup_error: outcome.cleanup_error.map(|e| format!("{e:?}")),
        };
        Ok(if report.cleanup_error.is_some() { PruneOutcome::CleanupIncomplete(report) } else { PruneOutcome::Reclaimed(report) })
    }

    /// Checkpoint then prune, preserving a committed checkpoint if the second
    /// plan exhausts its budget. Neither refusal is an invented success report.
    pub fn maintain(&self) -> Result<MaintenanceOutcome, NativeError> {
        let checkpoint = match self.checkpoint()? {
            CheckpointOutcome::Completed(report) => report,
            CheckpointOutcome::RefusedExhausted { plan, detail } => return Ok(MaintenanceOutcome::RefusedExhausted { checkpoint: None, plan, detail }),
        };
        let prune = match self.prune() {
            Ok(prune) => prune,
            Err(NativeError::Custody { mut plan }) => {
                plan.checkpoint = Some(Box::new(checkpoint));
                return Err(NativeError::Custody { plan });
            }
            Err(error) => return Err(error),
        };
        match prune {
            PruneOutcome::Reclaimed(prune) => Ok(MaintenanceOutcome::Completed(MaintenanceReport { checkpoint, prune })),
            PruneOutcome::CleanupIncomplete(prune) => Ok(MaintenanceOutcome::CleanupIncomplete(MaintenanceReport { checkpoint, prune })),
            PruneOutcome::RefusedExhausted { plan, detail } => Ok(MaintenanceOutcome::RefusedExhausted { checkpoint: Some(checkpoint), plan, detail }),
        }
    }
}

fn custody_unavailable(detail: &str) -> super::super::CustodyPlan {
    super::super::CustodyPlan { live_seals: Vec::new(), generations: Vec::new(), detail: detail.into(), checkpoint: None }
}
