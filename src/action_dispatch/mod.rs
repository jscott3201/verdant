//! M02-PR07 controlled dispatch and observed outcomes, HARNESS-ONLY.
//!
//! Assigned writer: frozen `WriteProperty` to the admitted target/route with
//! explicit priority and encoded value; separate protocol result, slot/PV
//! readback and meaningful feedback; audit of effective retries; recheck of
//! current actor/ceiling, policy, binding, generation, value and deadline at
//! the local handoff boundary. Harness-only until complete M02 qualification:
//! no field authority, no facility route, no physical values.
//!
//! Frozen profile verbatim (explicit owner selection, not commissioned):
//! BACnet/IP Analog Value `presentValue` on `tiny_site` (`ahu-1`/`vav-101`,
//! `scope-a`); Analog Value instance 2, property 85; commissioned priority 8;
//! protected 1-3 refused; no empty slot; `degC` only, `20.0..=24.0`, tolerance
//! `0.1` wire-checked as `f32` Real; 15 minute duration, 5 second deadline,
//! `APDU_RETRIES(0)` frozen, rate 6/hour; PV `unavailable-feedback` stated
//! where no meaningful immediate feedback exists; `source_time` is always
//! `None`; BACnet NULL (`0x00`) only for an explicitly admitted release;
//! preview revision-bound (`is_reservation`/`is_dispatch`/`is_qualified` are
//! all false). Consumes [`Admitted`](crate::action_journal::Admitted) and
//! [`Preview`](crate::action_preview::Preview) read-only plus
//! `canonical_bytes`; never re-derives preview/journal logic, never mutates
//! `APDU_RETRIES`/`ClientConfig`, never touches transport injection.
//!
//! Lock order: preview reads (no lock) -> ceiling check (no lock) ->
//! content verification (no lock) -> test hook -> generation check (no lock)
//! -> adapter op with NO SQL guard and NO building-wide lock (per-target
//! frozen route only) -> recheck generation + cancellation. No network runs
//! under a SQL transaction. Per-target frozen route only; never a global
//! mutex. Synthetic budgets here are planning reserves, not host-global
//! quotas, power-loss/disk-full qualification, or real-time proof.
//!
//! Timeout after handoff is uncertain, never permission to resend, compensate,
//! or treat `ack == movement` (`uncertain-not-resend`). No exactly-once,
//! active-active, field-CAS, or revived-stack claims. No `ObservedQualified`
//! minting; no `source_time` invention; no `Freshness` upgrade. Preserved:
//! source/receipt/ingestion identity plus `SyntheticValueOnly` vs `Refused`.
//! Greenfield forward-only: no v1 descriptor conversion, no backfill, no
//! old-preview support, no migration rewrite, no deprecated aliases, no
//! compat shims. If existing code forces a shim that is pure tech debt, report
//! it as a finding instead of building it.
//!
//! Harness scope (E03 amendment, owner-selected): loopback-only
//! directed-unicast to named isolated peers with per-run capture proving no
//! off-host packet plus full stop/join/port-release cleanup. Exactly two
//! `127.0.0.1:0` UDP binds per run (ephemeral, printed by capture; forbids
//! `502`/`802`/`8080`/`47808` and fixed facility ports); directed-unicast
//! only (NPDU version 1, no route/network-message, `Original-Unicast-NPDU`
//! only); no broadcast/BBMD/foreign; no wildcard bind; no facility interface;
//! MBAP never as BACnet. Capture is instrumented socket boundaries only, never
//! host-wide pcap claims. Ordinary `verdant run` never constructs this
//! module's network path; the test-only harness owns both UDP binds.

#[cfg(test)]
pub(crate) mod harness;
#[cfg(test)]
pub(crate) mod harness_provenance;
pub mod lifecycle_decision;
pub mod outcome;
#[allow(unused_imports)]
pub use outcome::*;

use crate::accept::AcceptedRevision;
use crate::access::{RoleKind, REQUIRED_PUBLISH_CEILING};
use crate::action_journal::Admitted;
use crate::action_preview::{
    Preview, DEADLINE_SECS, DURATION_SECS, PREVIEW_FORMAT, RATE_MAX_PER_HOUR,
};
use crate::binding::BindingStatus;
use crate::domain::ids::{BindingRevision, InstalledId};
use crate::runtime::bacnet::APDU_RETRIES;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Dispatch wire-format tag (harness-only; no facility authority).
pub const DISPATCH_FORMAT: &str = "verdant-dispatch-v1";
/// Frozen Analog Value object type.
pub const FROZEN_OBJECT_TYPE: u16 = 2;
/// Frozen Analog Value instance (AV2).
pub const FROZEN_INSTANCE: u32 = 2;
/// Frozen `presentValue` property identifier (PV85).
pub const FROZEN_PROPERTY: u32 = 85;
/// Frozen priority-array property for slot readback (property 87).
pub const FROZEN_SLOT_PROPERTY: u32 = 87;
/// Frozen commissioned priority (P8).
pub const FROZEN_PRIORITY: u8 = 8;
/// Frozen degC range, inclusive.
pub const FROZEN_MIN_C: f64 = 20.0;
/// Frozen degC range, inclusive.
pub const FROZEN_MAX_C: f64 = 24.0;
/// Frozen wire tolerance in degC.
pub const FROZEN_TOL_C: f64 = 0.1;
/// Meaningful-feedback status when no immediate physical feedback exists.
pub const FEEDBACK_STATUS: &str = "unavailable-feedback";

/// Typed dispatch failure with a stable machine code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    Invalid(&'static str),
    InvalidDetail { what: &'static str, detail: String },
    Ceiling { have: u8, required: u8 },
    ScopeDenied { expected: String, presented: String },
    StaleGeneration { expected: u32, current: u32 },
    StalePayload { detail: String },
    RevisionMismatch { detail: String },
    Deadline,
    Cancelled,
    Unknown { operation: String, attempt: String, detail: String },
    NullNotAdmitted,
}

impl DispatchError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) | Self::InvalidDetail { .. } => "dispatch-invalid",
            Self::Ceiling { .. } => "ceiling-exceeded",
            Self::ScopeDenied { .. } => "dispatch-scope-denied",
            Self::StaleGeneration { .. } => "dispatch-stale-generation",
            Self::StalePayload { .. } => "dispatch-stale-payload",
            Self::RevisionMismatch { .. } => "dispatch-revision-mismatch",
            Self::Deadline => "dispatch-deadline",
            Self::Cancelled => "dispatch-cancelled",
            Self::Unknown { .. } => "dispatch-unknown",
            Self::NullNotAdmitted => "dispatch-null-not-admitted",
        }
    }
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "dispatch invalid: {detail}"),
            Self::InvalidDetail { what, detail } => write!(f, "dispatch invalid {what}: {detail}"),
            Self::Ceiling { have, required } => {
                write!(f, "assistance ceiling {have} below required {required}")
            }
            Self::ScopeDenied { expected, presented } => write!(
                f,
                "dispatch scope denied: '{expected}' does not cover '{presented}'"
            ),
            Self::StaleGeneration { expected, current } => write!(
                f,
                "dispatch stale generation: expected {expected}, current is {current}"
            ),
            Self::StalePayload { detail } => write!(f, "dispatch stale payload (0004 rounded, lossless required): {detail}"),
            Self::RevisionMismatch { detail } => write!(f, "dispatch revision mismatch: {detail}"),
            Self::Deadline => write!(f, "dispatch deadline elapsed before handoff completion"),
            Self::Cancelled => write!(f, "dispatch cancelled before handoff completion"),
            Self::Unknown { operation, attempt, detail } => write!(
                f,
                "dispatch outcome UNKNOWN for {operation}/{attempt}; reconcile these identities: {detail}"
            ),
            Self::NullNotAdmitted => write!(f, "encoded null only for admitted release"),
        }
    }
}

impl std::error::Error for DispatchError {}

pub type Result<T> = std::result::Result<T, DispatchError>;

/// Frozen loopback route: the admitted equipment bound to one ephemeral
/// `127.0.0.1` destination. Mutable discovery lookups never replace this
/// identity; admission owns this snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenRoute {
    realm: InstalledId,
    endpoint: String,
    addr: SocketAddrV4,
    mac: [u8; 6],
}

impl FrozenRoute {
    /// Parse `bacnet-ip://127.0.0.1:PORT` for `ahu-1`/`vav-101` only.
    /// Refuses non-loopback, wildcard, broadcast, multicast, unspecified,
    /// zero-port, privileged (`<1024`), service (`502`/`802`/`8080`/`47808`),
    /// and facility hosts. Never resolves DNS or routes.
    pub fn parse(realm: &str, endpoint: &str) -> Result<Self> {
        let realm_id = InstalledId::parse(realm)
            .map_err(|_| DispatchError::Invalid("frozen realm ahu-1/vav-101"))?;
        if realm != "ahu-1" && realm != "vav-101" {
            return Err(DispatchError::Invalid("synthetic ahu-1/vav-101 only"));
        }
        let addr_text = endpoint
            .strip_prefix("bacnet-ip://")
            .ok_or(DispatchError::Invalid("direct BACnet/IP destination required"))?;
        if addr_text.contains('/') || addr_text.contains("route") {
            return Err(DispatchError::Invalid("routed destination refused"));
        }
        let addr: SocketAddrV4 = addr_text
            .parse()
            .map_err(|_| DispatchError::Invalid("numeric direct destination required"))?;
        if *addr.ip() != Ipv4Addr::LOCALHOST {
            return Err(DispatchError::Invalid("loopback 127.0.0.1 only"));
        }
        let port = addr.port();
        if port < 1024 {
            return Err(DispatchError::Invalid("ephemeral fixture port required"));
        }
        if matches!(port, 502 | 802 | 8080 | 47808) {
            return Err(DispatchError::Invalid("service port forbidden"));
        }
        if endpoint.is_empty() || endpoint.len() > 256 {
            return Err(DispatchError::Invalid("binding plan strings"));
        }
        let [a, b, c, d] = addr.ip().octets();
        let [hi, lo] = port.to_be_bytes();
        Ok(Self {
            realm: realm_id,
            endpoint: endpoint.to_string(),
            addr,
            mac: [a, b, c, d, hi, lo],
        })
    }

    pub fn realm(&self) -> &InstalledId {
        &self.realm
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn socket_addr(&self) -> SocketAddrV4 {
        self.addr
    }
    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }
}

/// Current operator/binding/generation snapshot rechecked at the handoff
/// boundary. All values are caller-supplied current readings, compared
/// read-only against the admitted intent and preview.
#[derive(Debug, Clone)]
pub struct Current {
    actor: String,
    ceiling: u8,
    role: RoleKind,
    binding_revision: BindingRevision,
    accepted_revision: AcceptedRevision,
    binding_status: BindingStatus,
    current_generation: u32,
}

impl Current {
    pub fn new(
        actor: &str,
        ceiling: u8,
        role: RoleKind,
        binding_revision: BindingRevision,
        accepted_revision: AcceptedRevision,
        binding_status: BindingStatus,
        current_generation: u32,
    ) -> Result<Self> {
        if actor.is_empty() || actor.len() > 128 {
            return Err(DispatchError::Invalid("current actor length"));
        }
        let ok = actor
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
        if !ok {
            return Err(DispatchError::Invalid("current actor characters"));
        }
        Ok(Self {
            actor: actor.to_string(),
            ceiling,
            role,
            binding_revision,
            accepted_revision,
            binding_status,
            current_generation,
        })
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }
    pub fn ceiling(&self) -> u8 {
        self.ceiling
    }
    pub fn role(&self) -> RoleKind {
        self.role
    }
}

/// Cooperative cancellation checked at the handoff boundary, mirroring
/// `runtime/task::Cancellation` and `runtime/bacnet/fake.rs` deadline gates.
/// A refused handoff consumes no script and no capture.
#[derive(Debug, Default, Clone)]
pub struct DispatchCancel(std::sync::Arc<AtomicBool>);

impl DispatchCancel {
    pub fn new() -> Self {
        Self(std::sync::Arc::new(AtomicBool::new(false)))
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn check(&self, deadline: Instant) -> Result<()> {
        if Instant::now() >= deadline {
            return Err(DispatchError::Deadline);
        }
        if self.0.load(Ordering::SeqCst) {
            return Err(DispatchError::Cancelled);
        }
        Ok(())
    }
}

/// Frozen encoded write: Analog Value instance 2, presentValue 85, priority 8,
/// with either Real(`f32`) bytes or admitted NULL. No generic property-write
/// API exists; this is the only encodable write in this slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenWrite {
    object_type: u16,
    instance: u32,
    property: u32,
    priority: u8,
    value: Vec<u8>,
    wire_bits: Option<u32>,
    is_release: bool,
}

impl FrozenWrite {
    pub fn object_type(&self) -> u16 {
        self.object_type
    }
    pub fn instance(&self) -> u32 {
        self.instance
    }
    pub fn property(&self) -> u32 {
        self.property
    }
    pub fn priority(&self) -> u8 {
        self.priority
    }
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    pub fn wire_bits(&self) -> Option<u32> {
        self.wire_bits
    }
    pub fn is_release(&self) -> bool {
        self.is_release
    }
}

/// Encode `f32` Real application bytes (`0x44` + big-endian bits).
pub fn real_value_bytes(wire_bits: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(0x44);
    out.extend_from_slice(&wire_bits.to_be_bytes());
    out
}

/// BACnet NULL application bytes (`0x00`). Distinct from Real zero
/// (`0x44 0x00 0x00 0x00 0x00`) and from enumerated inactive.
pub fn null_value_bytes() -> Vec<u8> {
    vec![0x00]
}

/// Read-only frozen-preview gate. Compares preview fields to the frozen
/// profile without re-running `Preview::preview` construction.
pub(crate) fn check_frozen_preview(preview: &Preview) -> Result<()> {
    if preview.format() != PREVIEW_FORMAT {
        return Err(DispatchError::Invalid("preview format"));
    }
    if preview.is_reservation() || preview.is_dispatch() || preview.is_qualified() {
        return Err(DispatchError::Invalid("preview is information only"));
    }
    if preview.priority().get() != FROZEN_PRIORITY {
        return Err(DispatchError::Invalid("priority 8 commissioned"));
    }
    let object = preview.object();
    if object.object_type() != FROZEN_OBJECT_TYPE {
        return Err(DispatchError::Invalid("synthetic Analog Value only"));
    }
    if object.property_id() != FROZEN_PROPERTY {
        return Err(DispatchError::Invalid("synthetic presentValue only"));
    }
    if object.array_index().is_some() {
        return Err(DispatchError::Invalid("presentValue is scalar"));
    }
    if preview.unit().as_str() != "degC" {
        return Err(DispatchError::InvalidDetail {
            what: "unit",
            detail: format!("expects 'degC', presents '{}'", preview.unit().as_str()),
        });
    }
    let timing = preview.timing();
    if timing.duration_secs() != DURATION_SECS {
        return Err(DispatchError::Invalid("duration 15min"));
    }
    if timing.deadline_secs() != DEADLINE_SECS {
        return Err(DispatchError::Invalid("deadline 5s"));
    }
    if timing.apdu_retries() != APDU_RETRIES {
        return Err(DispatchError::Invalid("apdu_retries frozen"));
    }
    if timing.rate_per_hour() != RATE_MAX_PER_HOUR {
        return Err(DispatchError::Invalid("rate bound"));
    }
    let encoded = preview.encoded();
    if !(FROZEN_MIN_C..=FROZEN_MAX_C).contains(&encoded.requested_c()) {
        return Err(DispatchError::Invalid("setpoint range degC 20-24"));
    }
    if !(FROZEN_MIN_C..=FROZEN_MAX_C).contains(&encoded.wire_c()) {
        return Err(DispatchError::Invalid("wire range degC 20-24"));
    }
    if encoded.rounding_error() > FROZEN_TOL_C {
        return Err(DispatchError::Invalid("wire tolerance 0.1"));
    }
    if encoded.wire_bits() != (encoded.wire_c() as f32).to_bits() {
        return Err(DispatchError::Invalid("wire bits f32"));
    }
    if preview.feedback().status() != FEEDBACK_STATUS {
        return Err(DispatchError::Invalid("feedback unavailable"));
    }
    if preview.feedback().source_time().is_some() {
        return Err(DispatchError::Invalid("source_time None"));
    }
    Ok(())
}

fn check_ceiling(ceiling: u8, role: RoleKind) -> Result<()> {
    match role {
        RoleKind::Publisher => {
            if ceiling < REQUIRED_PUBLISH_CEILING {
                return Err(DispatchError::Ceiling {
                    have: ceiling,
                    required: REQUIRED_PUBLISH_CEILING,
                });
            }
            Ok(())
        }
        RoleKind::Reviewer => Err(DispatchError::Ceiling {
            have: ceiling,
            required: REQUIRED_PUBLISH_CEILING,
        }),
    }
}

fn check_binding_status(status: &BindingStatus) -> Result<()> {
    match status {
        BindingStatus::Imported => Ok(()),
        BindingStatus::Valid => Ok(()),
        BindingStatus::ObservedQualified => {
            Err(DispatchError::Invalid("no observed qualification here"))
        }
    }
}

/// Verify content before the handoff: actor/ceiling/policy/binding/value.
/// No SQL guard, no building-wide lock, no network yet.
/// Lossless Slice-A: presentation `{:.4}` equality is necessary but not
/// sufficient; exact `wire_bits`, explicit kind and release target must also
/// match. Legacy 0004 rows (no identity) refuse as stale-payload here while
/// staying readable via journal reconcile (no backfill).
pub(crate) fn verify_content(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
) -> Result<()> {
    // Compatibility: 0004 rounded payloads refuse for new handoffs.
    if admitted.is_legacy() {
        return Err(DispatchError::StalePayload {
            detail: "0004 rounded payload lacks lossless wire_bits/kind/target; re-admit with 0005 identity".to_string(),
        });
    }
    check_ceiling(current.ceiling(), current.role())?;
    check_ceiling(admitted.ceiling(), current.role())?;
    if current.actor() != admitted.actor() {
        return Err(DispatchError::Invalid("actor changed since admission"));
    }
    if admitted.scope().as_str() != preview.target().scope().as_str() {
        return Err(DispatchError::ScopeDenied {
            expected: preview.target().scope().as_str().to_string(),
            presented: admitted.scope().as_str().to_string(),
        });
    }
    if admitted.equipment().as_str() != preview.target().equipment().as_str() {
        return Err(DispatchError::Invalid("equipment changed since preview"));
    }
    if route.realm().as_str() != admitted.equipment().as_str() {
        return Err(DispatchError::Invalid("frozen route realm mismatch"));
    }
    if admitted.binding_revision() != preview.target().binding_revision() {
        return Err(DispatchError::RevisionMismatch {
            detail: "binding revision changed since preview".to_string(),
        });
    }
    if admitted.accepted_revision() != preview.target().accepted_revision() {
        return Err(DispatchError::RevisionMismatch {
            detail: "accepted revision changed since preview".to_string(),
        });
    }
    if current.binding_revision != admitted.binding_revision() {
        return Err(DispatchError::RevisionMismatch {
            detail: "binding revision not current".to_string(),
        });
    }
    if current.accepted_revision != admitted.accepted_revision() {
        return Err(DispatchError::RevisionMismatch {
            detail: "accepted revision not current".to_string(),
        });
    }
    check_binding_status(&current.binding_status)?;
    if admitted.payload() != preview.canonical_bytes() {
        return Err(DispatchError::Invalid("admitted payload differs from preview"));
    }
    // Lossless identity: distinct binary32 sharing `{:.4}` text MUST NOT match.
    if admitted.wire_bits() != Some(preview.encoded().wire_bits()) {
        return Err(DispatchError::Invalid("wire identity mismatch: distinct binary32 sharing rounded text"));
    }
    if admitted.action_kind().map(|k| k.as_str()) != Some(preview.action_kind()) {
        return Err(DispatchError::Invalid("action kind mismatch: SET cannot authorize release and vice versa"));
    }
    if admitted.release_admitted() != Some(preview.release_admitted()) {
        return Err(DispatchError::Invalid("release admission mismatch: swapped preview"));
    }
    if admitted.release_target().map(|t| t.as_str()) != Some(preview.release_target().as_str()) {
        return Err(DispatchError::Invalid("release target changed since admission"));
    }
    if admitted.deadline_secs() != DEADLINE_SECS {
        return Err(DispatchError::Invalid("deadline 5s"));
    }
    Ok(())
}

/// Identical retry predicate: same presentation plus exact bits/kind/target.
/// Identical retries are authorized outcome inspection (read-only readbacks,
/// no new WriteProperty), not a new physical attempt. Swapped kind/target or
/// distinct bits with equal text are NOT identical and refuse upstream.
pub fn is_identical_retry(admitted: &Admitted, preview: &Preview) -> bool {
    if admitted.is_legacy() {
        return false;
    }
    admitted.payload() == preview.canonical_bytes()
        && admitted.wire_bits() == Some(preview.encoded().wire_bits())
        && admitted.action_kind().map(|k| k.as_str()) == Some(preview.action_kind())
        && admitted.release_admitted() == Some(preview.release_admitted())
        && admitted.release_target().map(|t| t.as_str()) == Some(preview.release_target().as_str())
}

pub(crate) fn verify_generation(admitted: &Admitted, current: &Current) -> Result<()> {
    // Pre/post generation (traced, not ±1): `expected` is the pre-admission
    // token observed before the CAS; `target = expected + 1` is the
    // post-admission value stored in `action_targets`. Handoff requires
    // `Current == expected` (no intervening admission), not `target`.
    // Replacement/release tracing lives with activation; do not adjust by ±1
    // without that trace.
    if current.current_generation != admitted.expected_generation() {
        return Err(DispatchError::StaleGeneration {
            expected: admitted.expected_generation(),
            current: current.current_generation,
        });
    }
    let target = admitted
        .expected_generation()
        .checked_add(1)
        .ok_or(DispatchError::Invalid("target generation overflow"))?;
    if target != admitted.target_generation() {
        return Err(DispatchError::Invalid("journal generation order"));
    }
    Ok(())
}

/// Prepare a frozen setpoint write: recheck actor/ceiling/policy/binding/
/// generation/value/deadline at the local handoff boundary, then encode ONLY
/// AV2/PV85/P8 Real(`f32`). The final no-I/O gate (`cancel.check`) runs after
/// encoding so refused work consumes no script and no capture.
/// SET-only: a release admission (kind `release`) refuses here; use
/// `prepare_release` with the identical release preview instead (swapped-kind
/// barrier, not a preview-only decision).
/// `pub(crate)`: product and gate callers must use the joined path
/// (`crate::action_joined::authorize_joined_setpoint`); raw preparation
/// bypasses the seal/activation/wall barriers. Binary-only, no external consumers.
pub(crate) fn prepare_setpoint(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
) -> Result<FrozenWrite> {
    crate::action_dispatch::lifecycle_decision::check_lifecycle_for_dispatch(admitted)?;
    check_frozen_preview(preview)?;
    verify_content(admitted, preview, current, route)?;
    verify_generation(admitted, current)?;
    // Authorize→transport anchor: re-verify the durable deadline wall here so
    // `execute_setpoint` (which funnels through this prepare) refuses an
    // expired anchor with zero capture even with a fresh Instant/Current.
    crate::action_dispatch::lifecycle_decision::verify_durable_wall_for_set(admitted)?;
    if admitted.action_kind().map(|k| k.as_str()) != Some("set") {
        return Err(DispatchError::Invalid("SET admission required: release admission cannot authorize SET via swapped preview"));
    }
    if preview.action_kind() != "set" {
        return Err(DispatchError::Invalid("SET preview required: release preview cannot authorize SET"));
    }
    cancel.check(deadline)?;
    let encoded = preview.encoded();
    // Wire coherence: preview bits must equal admitted bits (distinct binary32
    // sharing `{:.4}` text already refused in `verify_content`; re-assert the
    // exact bits carried on the wire).
    if admitted.wire_bits() != Some(encoded.wire_bits()) {
        return Err(DispatchError::Invalid("wire bits differ from admitted identity"));
    }
    let value = real_value_bytes(encoded.wire_bits());
    let write = FrozenWrite {
        object_type: FROZEN_OBJECT_TYPE,
        instance: FROZEN_INSTANCE,
        property: FROZEN_PROPERTY,
        priority: FROZEN_PRIORITY,
        value,
        wire_bits: Some(encoded.wire_bits()),
        is_release: false,
    };
    cancel.check(deadline)?;
    Ok(write)
}

/// Prepare a frozen release (NULL relinquish at P8). Encoded NULL only for an
/// explicitly admitted release; otherwise `NullNotAdmitted`. NULL, Real zero,
/// and enumerated inactive remain distinct by construction.
/// Swapped-kind barrier lives in `verify_content` (SET vs release kinds must
/// match); non-admitted NULL (SET kind via release path) stays
/// `NullNotAdmitted` via `null_wire`, preserving existing refusal. Release
/// target change refuses in `verify_content` (no retargeting).
/// `pub(crate)`: use the joined release path; raw bypasses seal/activation/wall.
pub(crate) fn prepare_release(
    admitted: &Admitted,
    preview: &Preview,
    current: &Current,
    route: &FrozenRoute,
    cancel: &DispatchCancel,
    deadline: Instant,
) -> Result<FrozenWrite> {
    crate::action_dispatch::lifecycle_decision::check_lifecycle_for_dispatch(admitted)?;
    check_frozen_preview(preview)?;
    verify_content(admitted, preview, current, route)?;
    verify_generation(admitted, current)?;
    cancel.check(deadline)?;
    let value = preview
        .release()
        .null_wire()
        .map_err(|_| DispatchError::NullNotAdmitted)?;
    if value != vec![0x00] {
        return Err(DispatchError::Invalid("null wire 0x00"));
    }
    let write = FrozenWrite {
        object_type: FROZEN_OBJECT_TYPE,
        instance: FROZEN_INSTANCE,
        property: FROZEN_PROPERTY,
        priority: FROZEN_PRIORITY,
        value,
        wire_bits: None,
        is_release: true,
    };
    cancel.check(deadline)?;
    Ok(write)
}

/// Recheck generation + cancellation after the adapter op, with NO SQL guard.
/// Mirrors `runtime/mod.rs dispatch_next` post-handoff recheck.
pub fn recheck_after_handoff(
    admitted: &Admitted,
    current: &Current,
    cancel: &DispatchCancel,
    deadline: Instant,
) -> Result<()> {
    verify_generation(admitted, current)?;
    cancel.check(deadline)?;
    Ok(())
}

/// Helpers retained for unit coverage without network.
pub fn frozen_route_for_test(realm: &str, endpoint: &str) -> Result<FrozenRoute> {
    FrozenRoute::parse(realm, endpoint)
}
