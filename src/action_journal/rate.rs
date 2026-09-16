//! Slice-B owned 6/hour accounting and 5s deadline wall anchor.
//!
//! Factored from `mod.rs` to respect the 700-line cap; `mod.rs` stays the
//! owning writer. Rate is enforced in the guarded admission batch under the
//! single-writer lock, keyed by `(scope, equipment)` per wall-hour anchored
//! to durable `created` time (not in-memory counters, not helper estimates).
//! The pure `Timing::check_rate` helper stays advisory; this module is the
//! owner. Deadline is anchored to the same durable `created` wall: a delayed
//! queue plus a fresh `Instant` cannot renew the 5s window. Constrained
//! admitted-null-release/cancel-unattempted stay exempt so SET quota cannot
//! starve cleanup. Cross-boot/suspend ambiguity maps to indeterminate in the
//! expiry owner (SET refused, admitted NULL still permitted).

use crate::binding;
use crate::domain::ids::InstalledId;
use crate::domain::scope::TrustedScope;
use super::WriterError;

/// Owned rate limit: 6 SET/hour per `(scope, equipment)` wall-hour.
/// Mirrors `RATE_MAX_PER_HOUR` without re-deriving the preview profile.
pub const OWNED_RATE_MAX_PER_HOUR: u32 = crate::action_preview::RATE_MAX_PER_HOUR;
/// Owned dispatch deadline: 5s wall anchored to durable `created`.
pub const OWNED_DEADLINE_SECS: u64 = crate::action_preview::DEADLINE_SECS;
/// Owned wall-hour window in seconds (sliding 3600s anchored to `created`).
pub const RATE_WINDOW_SECS: i64 = 3600;

/// Rate-guard temp-table SQL for SET admissions only. Counts durable SET rows
/// (`action_kind='set'` plus legacy `NULL` conservatively as SET) for the
/// same `(scope, equipment)` with `created` inside the sliding wall-hour.
/// Releases skip this guard entirely (exempt capacity). Enforced under the
/// writer lock, so concurrent SETs serialize and the 7th refuses.
pub(crate) fn rate_guard_sql(scope: &TrustedScope, equipment: &InstalledId) -> String {
    let scope_q = binding::sql_quote(scope.as_str());
    let equip_q = binding::sql_quote(equipment.as_str());
    let limit = OWNED_RATE_MAX_PER_HOUR;
    format!("CREATE TEMP TABLE admission_rate(ok INTEGER NOT NULL CONSTRAINT admission_rate CHECK(ok=1)); INSERT INTO admission_rate VALUES(CASE WHEN ((SELECT COUNT(*) FROM action_journal WHERE scope={scope_q} AND equipment={equip_q} AND created >= CAST(strftime('%s','now') AS INTEGER)-{RATE_WINDOW_SECS} AND (action_kind='set' OR action_kind IS NULL))) < {limit} THEN 1 ELSE 0 END);")
}

/// Map a rate-guard CHECK failure to the owned rate error. The guard table
/// constraint is named `admission_rate`; generation-guard failures stay
/// stale-generation via the caller.
pub(crate) fn is_rate_guard_failure(detail: &str) -> bool {
    detail.contains("admission_rate")
}

/// Owned rate refusal: 7th SET in the wall-hour refuses here, not in the pure
/// helper. `used` is the durable count observed (6 when full), `limit` is 6.
pub(crate) fn rate_exceeded(used: u32) -> WriterError {
    WriterError::RateExceeded { used, limit: OWNED_RATE_MAX_PER_HOUR }
}

/// Pure wall-anchor check: `now_secs - created_secs` against the 5s deadline.
/// Rollback (`now < created`) is indeterminate (never a renewed window).
/// Returns `Ok(())` when inside the window, `Err` with elapsed/limit otherwise.
/// Enforcement lives in the Journal/dispatch owner; this stays pure.
pub fn check_deadline_wall(created_secs: i64, now_secs: i64) -> Result<(), WriterError> {
    let elapsed = now_secs
        .checked_sub(created_secs)
        .ok_or(WriterError::RateIndeterminate { reason: "wall-rollback" })?;
    if elapsed < 0 {
        return Err(WriterError::RateIndeterminate { reason: "wall-rollback" });
    }
    let elapsed_u = u64::try_from(elapsed).map_err(|_| WriterError::RateIndeterminate { reason: "wall-rollback" })?;
    if elapsed_u >= OWNED_DEADLINE_SECS {
        return Err(WriterError::DeadlineExceeded { elapsed_secs: elapsed_u, deadline_secs: OWNED_DEADLINE_SECS });
    }
    Ok(())
}

/// Current wall seconds via SQLite `strftime` (single source for anchor math
/// in tests; product admission uses the same expression in-batch).
pub(crate) fn now_wall_select() -> &'static str {
    "SELECT CAST(strftime('%s','now') AS INTEGER);"
}
