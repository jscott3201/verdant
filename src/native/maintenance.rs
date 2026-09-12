//! Synthetic admission plans, exact Selene selections, and explicit cleanup debt.
//! No disk reservation, projected GQL-size claim, or host-global accounting.
use super::*;
use crate::native::report::{CheckpointOutcome, MaintenanceReport, PruneOutcome};
use crate::native::MaintenancePlan;

pub(super) struct CachedCheckpoint {
    report: CheckpointReport,
}

impl NativeHandle {
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
        match self.prune()? {
            PruneOutcome::Reclaimed(prune) => Ok(MaintenanceOutcome::Completed(MaintenanceReport { checkpoint, prune })),
            PruneOutcome::CleanupIncomplete(prune) => Ok(MaintenanceOutcome::CleanupIncomplete(MaintenanceReport { checkpoint, prune })),
            PruneOutcome::RefusedExhausted { plan, detail } => Ok(MaintenanceOutcome::RefusedExhausted { checkpoint: Some(checkpoint), plan, detail }),
        }
    }
}
