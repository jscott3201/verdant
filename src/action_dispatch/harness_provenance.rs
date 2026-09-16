//! Harness provenance helpers (factored from `harness.rs` to respect the
//! 700-line cap; test-only). Preserves acknowledged vs possibly-emitted vs
//! not-attempted across cancel/deadline/readback paths.
//!
//! Rules (Slice A):
//! - Pre-handoff cancel/deadline with non-emission established (zero capture,
//!   peer table unchanged) is known not-attempted (`Cancelled`/`Deadline`).
//! - Post-ack cancel/deadline MUST NOT discard the acknowledged `Outcome`;
//!   the write was already confirmed, readbacks still produce an `Outcome`
//!   (possibly with per-readback invalid flags), never `Cancelled`.
//! - `Encoding + cancel` after a send is possibly-emitted (`Unknown`), not
//!   `Cancelled`; only pre-send (no packet) is `Cancelled`.
//! - Per-readback states preserved: one known/other-invalid stays an `Outcome`
//!   with `is_valid` flags, never collapsed to generic `Invalid`.
//! - `receipt_*` captured AFTER the response arrives (response-correlated),
//!   never request-start, never fabricated `source_time`; slot/PV independent.
//! - Client stop/join evidence (`starts/stops/eofs`) stays separate from
//!   cancellation ack or equipment release.
//!
//! Slice B delivered elsewhere (durable lifecycle in
//! `action_journal/lifecycle.rs`, bounded outstanding via
//! `Journal::outstanding_page`, custody link in `admission_body_v2`); this
//! module stays harness-only, no durable state. Slice C owns the
//! seal/joined/wall join; see `crate::action_joined`.

#[cfg(test)]
use super::{DispatchError, ProtocolResult};
#[cfg(test)]
use bacnet_types::error::Error as WireError;
#[cfg(test)]
use std::time::{Instant, SystemTime};

#[cfg(test)]
pub(crate) fn is_timeout_abort(error: &WireError) -> bool {
    match error {
        WireError::Abort { reason } => *reason == 10,
        WireError::Timeout(_) => true,
        _ => false,
    }
}

#[cfg(test)]
pub(crate) fn wire_kind(error: &WireError) -> ProtocolResult {
    match error {
        WireError::Protocol { class, code } => ProtocolResult::RemoteError { class: *class, code: *code },
        WireError::Reject { reason } => ProtocolResult::Reject(*reason),
        WireError::Abort { reason } => ProtocolResult::Abort(*reason),
        WireError::Timeout(_) => ProtocolResult::Timeout,
        WireError::Transport(_) => ProtocolResult::TransportFailure,
        WireError::Encoding(_)
        | WireError::Decoding { .. }
        | WireError::Segmentation(_)
        | WireError::BufferTooShort { .. }
        | WireError::InvalidTag(_)
        | WireError::OutOfRange(_)
        | WireError::RoutedPathTooLong { .. }
        | WireError::RoutedPathCapacityExceeded { .. } => ProtocolResult::InvalidReply,
    }
}

/// Fixed read-error mapping: timeout/abort stays `Unknown` (possibly-emitted,
/// reconcile, do not resend). Non-timeout transport/invalid replies are NOT
/// collapsed to generic `Invalid` discarding the acknowledged write; callers
/// preserve them as per-readback `invalid` flags inside an `Outcome` with the
/// confirmed protocol. This function is retained for pre-handoff paths only;
/// post-ack paths must use per-readback preservation (see `is_invalid_reply`).
#[cfg(test)]
pub(crate) fn map_read_error_pre_handoff(
    error: WireError,
    admitted_operation: &str,
    admitted_attempt: &str,
) -> DispatchError {
    if is_timeout_abort(&error) {
        DispatchError::Unknown {
            operation: admitted_operation.to_string(),
            attempt: admitted_attempt.to_string(),
            detail: "uncertain-not-resend: readback lost; reconcile, do not resend".to_string(),
        }
    } else {
        DispatchError::Invalid("readback invalid reply")
    }
}

#[cfg(test)]
pub(crate) fn is_invalid_reply(error: &WireError) -> bool {
    !is_timeout_abort(error)
}

/// Response-correlated receipt instant: call AFTER the read response arrives,
/// never before. Returns `(wall, monotonic)` for the just-completed readback.
#[cfg(test)]
pub(crate) fn receipt_now() -> (SystemTime, Instant) {
    (SystemTime::now(), Instant::now())
}

/// Whether any emission occurred (packet captured). Pre-handoff cancel is
/// known not-attempted ONLY when this is false AND the peer table is
/// unchanged; otherwise the outcome is possibly-emitted (`Unknown`).
#[cfg(test)]
pub(crate) fn emission_established(sent_count: u32) -> bool {
    sent_count > 0
}
