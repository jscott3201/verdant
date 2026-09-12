//! Native lifecycle reports: open/readiness/operation outcomes.
//!
//! Pure data shapes (no Selene calls): the next consumer (M01-PR08+) keys
//! readiness and version decisions off [`OpenReport`] and [`Readiness`].
//! Construction lives in [`crate::native::NativeHandle`]; the Selene rev and
//! format constants live in [`crate::native`].

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use super::settings::NativeSettings;

/// Closed (dropped) store authority: the directory plus the settings to
/// reopen it with. The writer lease is released only when every
/// [`crate::native::NativeHandle`] clone AND every session they minted is
/// dropped; this type is returned by handle close, after which no session
/// can still be alive inside the facade (sessions never escape a call).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedStore {
    /// Store directory (the only filesystem authority retained).
    pub dir: PathBuf,
    /// Settings to reopen with.
    pub settings: NativeSettings,
}

/// Exact open report: native format/channel/file identity + Selene rev.
///
/// Recorded at every successful create/open; the next consumer (M01-PR08+)
/// keys readiness and version decisions off this shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReport {
    /// Store directory as supplied.
    pub dir: String,
    /// Native format identity (`selene-format-2`).
    pub format_id: &'static str,
    /// Channel identity (control / WAL / snapshot / manifest / audit).
    pub channel: &'static str,
    /// Exact Selene `development` commit this validation qualified.
    pub selene_rev: &'static str,
    /// Selene facade crate version at that commit.
    pub selene_crate: &'static str,
    /// Instance storage mode (always `durable` here; memory builds never
    /// produce a report).
    pub mode: &'static str,
    /// Pre-sized mapping disclosed: measured on-disk footprint in bytes.
    pub store_bytes: u64,
    /// Durable commit position (Selene debug rendering; digest-qualified).
    pub position: String,
    /// Digest qualifying the durable boundary, lowercase hex.
    pub digest_hex: String,
    /// Whether uncertainty prohibits more writes/checkpoints on this owner.
    pub fenced: bool,
    /// Work performed by this instance's open (`None` after create).
    pub recovery: Option<RecoverySummary>,
    /// Settings this handle enforces.
    pub settings: NativeSettings,
}

impl fmt::Display for OpenReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "native {} {} rev={} mode={} store_bytes={} fenced={} settings=[{}]",
            self.format_id,
            self.channel,
            self.selene_rev,
            self.mode,
            self.store_bytes,
            self.fenced,
            self.settings
        )
    }
}

/// Observed recovery work for one open (Selene [`selene_db::RecoveryInfo`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverySummary {
    /// Snapshot load + isolated semantic reconstruction time.
    pub snapshot_elapsed: Duration,
    /// Retained-prefix verification + semantic suffix replay time.
    pub wal_elapsed: Duration,
    /// Native catalog validation + eager index/runtime rebuild time.
    pub rebuild_elapsed: Duration,
    /// Final complete-tail synchronization time.
    pub synchronize_elapsed: Duration,
    /// Verified prefix records.
    pub verified_prefix_records: u64,
    /// Whole suffix records semantically applied.
    pub replayed_suffix_records: u64,
    /// Retained registered indexes rebuilt before success was returned.
    pub rebuilt_indexes: usize,
}

/// Readiness + native presence for one handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    /// Ready for reads and writes.
    pub ready: bool,
    /// Useful reason: format id, rev, and what gates readiness.
    pub reason: String,
    /// Native format identity.
    pub format_id: &'static str,
    /// Exact Selene rev.
    pub selene_rev: &'static str,
    /// Instance storage mode.
    pub mode: &'static str,
    /// Fenced owners are never ready.
    pub fenced: bool,
}

/// One executed statement: committed outcome with no retained session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecReport {
    /// Statement length in bytes (the pre-checked ceiling input).
    pub statement_bytes: usize,
    /// Regular-result row count, when the outcome carries rows.
    pub row_count: Option<usize>,
    /// Committed graph change count, when the outcome is a write.
    pub changes: Option<usize>,
}

/// One checkpoint: the exact immutable selection Selene published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointReport {
    /// New immutable control manifest generation.
    pub generation: u64,
    /// Selected snapshot name (diagnostic only, not retention authority).
    pub snapshot: String,
    /// Complete snapshot file bytes.
    pub bytes: u64,
    /// Complete snapshot digest, lowercase hex.
    pub digest_hex: String,
    /// Store footprint after selection (disclosed, not promised).
    pub store_bytes_after: u64,
}

/// One prune: explicit retention only (checkpoint never auto-prunes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneReport {
    /// Artifacts unlinked with directory synchronization.
    pub removed_count: usize,
    /// Bytes reclaimed by removal.
    pub removed_bytes: u64,
    /// Artifacts retained (CURRENT, previous checkpoint, dependencies,
    /// active leases) with their retention reasons.
    pub retained: Vec<(String, String)>,
    /// Concrete cleanup failure, if planning succeeded but cleanup did not
    /// finish (partial progress is reported, never hidden).
    pub cleanup_error: Option<String>,
}

/// One maintenance pass: an explicit checkpoint followed by an explicit
/// prune. Evidence (committed rows) is preserved across the pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceOutcome {
    /// The checkpoint half of the pass.
    pub checkpoint: CheckpointReport,
    /// The prune half of the pass.
    pub prune: PruneReport,
}

/// Lowercase hex over a 32-byte digest (no helper crates on this side of
/// the boundary).
pub fn hex32(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Short hint pairing a durable position with its digest for readiness
/// reasons (diagnostic only; ordering decisions use the typed status).
pub trait PositionHint {
    /// Render `position#digest-prefix` for human-facing reasons.
    fn position_digest_hint(&self) -> String;
}

impl PositionHint for selene_db::DurableStatus {
    fn position_digest_hint(&self) -> String {
        format!(
            "{:?}#{}",
            self.position,
            hex32(&self.digest).get(..12).unwrap_or("????????????")
        )
    }
}
