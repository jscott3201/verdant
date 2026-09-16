//! M02-PR07 dispatch outcomes: protocol result, slot/PV readbacks, feedback.
//!
//! Separate times per property, never an atomic controller snapshot.
//! `source_time` stays `None`; no `ObservedQualified` is minted. One logical
//! call is audited against effective wire sends; effective retries stay `0`.
//!
//! Slice D no-receipt-after-restart rule (memory-only, no fabrication):
//! `SlotReadback`/`PvReadback` `receipt_wall`/`receipt_monotonic` are captured
//! via `receipt_now()` AFTER each read response arrives (response-correlated,
//! independent per property) and live only in the in-memory `Outcome`. No
//! receipt/outcome durable column exists (no `0007`); a reopened `Admitted`
//! exposes no receipt accessors. Fresh processes re-observe via read-only
//! `inspect_identical` (no second `WriteProperty`) with fresh `receipt_now`
//! times (never equal to pre-kill times) and `source_time` staying `None`.
//! Never copy old receipt times into a new outcome; never invent
//! `source_time`.

use super::{DISPATCH_FORMAT, FEEDBACK_STATUS};
use crate::action_journal::Admitted;
use crate::runtime::bacnet::APDU_RETRIES;
use std::time::{Instant, SystemTime};

/// Protocol result: the WriteProperty wire outcome alone, separate from
/// readbacks and feedback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolResult {
    Confirmed,
    RemoteError { class: u32, code: u32 },
    Reject(u8),
    Abort(u8),
    Timeout,
    InvalidReply,
    TransportFailure,
}

/// Slot readback: priority-array slot 8 value with its own receipt times.
/// Never labeled an atomic controller snapshot. `source_time` stays `None`
/// (never fabricated sensor time). `receipt_*` are response-correlated
/// (captured AFTER the read response arrives), not request-start; slot and PV
/// are independent (separate reads, separate times), never an atomic snapshot.
/// A delayed read proves `receipt_monotonic >= request_start`; tests assert it.
/// Per-readback validity is preserved: one known/other-invalid stays an
/// `Outcome` with one valid readback, never collapsed to generic `Invalid`.
/// Client stop/join evidence (harness `starts/stops/eofs`) stays separate
/// from cancellation ack or equipment release (see harness provenance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotReadback {
    value: Vec<u8>,
    receipt_wall: SystemTime,
    receipt_monotonic: Instant,
    valid: bool,
}

impl SlotReadback {
    pub fn new(value: Vec<u8>, receipt_wall: SystemTime, receipt_monotonic: Instant) -> Self {
        Self { value, receipt_wall, receipt_monotonic, valid: true }
    }
    /// Invalid readback: value is empty, `valid` is false; the other
    /// readback's known value is still preserved in the same `Outcome`.
    pub fn invalid(receipt_wall: SystemTime, receipt_monotonic: Instant) -> Self {
        Self { value: Vec::new(), receipt_wall, receipt_monotonic, valid: false }
    }
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    pub fn receipt_wall(&self) -> SystemTime {
        self.receipt_wall
    }
    pub fn receipt_monotonic(&self) -> Instant {
        self.receipt_monotonic
    }
    /// Per-readback validity: `true` for a decoded response, `false` for a
    /// transport/invalid reply preserved alongside the other known readback.
    pub fn is_valid(&self) -> bool {
        self.valid
    }
    pub fn source_time(&self) -> Option<SystemTime> {
        None
    }
    pub fn is_atomic_snapshot(&self) -> bool {
        false
    }
}

/// PV readback: effective `presentValue` with its own receipt times, separate
/// from the slot readback. Never atomic, never qualified. Same
/// response-correlated, independent, non-fabricated semantics as slot; see
/// above. Validity preserved per-readback; stop/join stays separate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PvReadback {
    value: Vec<u8>,
    receipt_wall: SystemTime,
    receipt_monotonic: Instant,
    valid: bool,
}

impl PvReadback {
    pub fn new(value: Vec<u8>, receipt_wall: SystemTime, receipt_monotonic: Instant) -> Self {
        Self { value, receipt_wall, receipt_monotonic, valid: true }
    }
    /// Invalid readback preserved alongside the known other readback.
    pub fn invalid(receipt_wall: SystemTime, receipt_monotonic: Instant) -> Self {
        Self { value: Vec::new(), receipt_wall, receipt_monotonic, valid: false }
    }
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    pub fn receipt_wall(&self) -> SystemTime {
        self.receipt_wall
    }
    pub fn receipt_monotonic(&self) -> Instant {
        self.receipt_monotonic
    }
    /// Per-readback validity (see slot).
    pub fn is_valid(&self) -> bool {
        self.valid
    }
    pub fn source_time(&self) -> Option<SystemTime> {
        None
    }
    pub fn is_atomic_snapshot(&self) -> bool {
        false
    }
    pub fn is_qualified(&self) -> bool {
        false
    }
}

/// Meaningful-feedback assessment: PV `unavailable-feedback` stated where no
/// meaningful immediate feedback exists. Never invents `source_time`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feedback {
    property: String,
    status: &'static str,
}

impl Feedback {
    pub fn unavailable() -> Self {
        Self { property: "presentValue".to_string(), status: FEEDBACK_STATUS }
    }
    pub fn property(&self) -> &str {
        &self.property
    }
    pub fn status(&self) -> &'static str {
        self.status
    }
    pub fn source_time(&self) -> Option<SystemTime> {
        None
    }
    pub fn is_meaningful(&self) -> bool {
        false
    }
}

/// Audit: one logical call versus effective wire sends. One call is not one
/// send by assumption; count the capture. Effective retries stay `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Audit {
    one_call: u32,
    effective_sends: u32,
    effective_retries: u8,
    apdu_retries: u8,
}

impl Audit {
    pub fn new(effective_sends: u32) -> Self {
        Self { one_call: 1, effective_sends, effective_retries: 0, apdu_retries: APDU_RETRIES }
    }
    pub fn one_call(&self) -> u32 {
        self.one_call
    }
    pub fn effective_sends(&self) -> u32 {
        self.effective_sends
    }
    pub fn effective_retries(&self) -> u8 {
        self.effective_retries
    }
    pub fn apdu_retries(&self) -> u8 {
        self.apdu_retries
    }
}

/// Controlled dispatch outcome: protocol result, separate slot/PV readbacks
/// with per-property times, unavailable feedback, audit, and retained
/// identities for reconciliation. `source_time` stays `None` throughout; no
/// `ObservedQualified` is minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    operation: String,
    attempt: String,
    scope: String,
    equipment: String,
    binding_revision: u32,
    accepted_revision: u32,
    target_generation: u32,
    protocol: ProtocolResult,
    slot: SlotReadback,
    pv: PvReadback,
    feedback: Feedback,
    audit: Audit,
}

impl Outcome {
    pub fn new(
        admitted: &Admitted,
        protocol: ProtocolResult,
        slot: SlotReadback,
        pv: PvReadback,
        feedback: Feedback,
        audit: Audit,
    ) -> Self {
        Self {
            operation: admitted.operation().as_str().to_string(),
            attempt: admitted.attempt().as_str().to_string(),
            scope: admitted.scope().as_str().to_string(),
            equipment: admitted.equipment().as_str().to_string(),
            binding_revision: admitted.binding_revision().as_u32(),
            accepted_revision: admitted.accepted_revision().get(),
            target_generation: admitted.target_generation(),
            protocol,
            slot,
            pv,
            feedback,
            audit,
        }
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn attempt(&self) -> &str {
        &self.attempt
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn equipment(&self) -> &str {
        &self.equipment
    }
    pub fn binding_revision(&self) -> u32 {
        self.binding_revision
    }
    pub fn accepted_revision(&self) -> u32 {
        self.accepted_revision
    }
    pub fn target_generation(&self) -> u32 {
        self.target_generation
    }
    pub fn protocol(&self) -> &ProtocolResult {
        &self.protocol
    }
    pub fn slot(&self) -> &SlotReadback {
        &self.slot
    }
    pub fn pv(&self) -> &PvReadback {
        &self.pv
    }
    pub fn feedback(&self) -> &Feedback {
        &self.feedback
    }
    pub fn audit(&self) -> Audit {
        self.audit
    }
    pub fn format(&self) -> &'static str {
        DISPATCH_FORMAT
    }
    pub fn is_dispatch(&self) -> bool {
        true
    }
    pub fn source_time(&self) -> Option<SystemTime> {
        None
    }
    pub fn is_qualified(&self) -> bool {
        false
    }
}
