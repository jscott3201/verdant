//! M02-PR05 preview assembly: timing, feedback, release, seal order.
//!
//! Revision-bound information, not a reservation and not dispatch. Ordinary
//! runtime dispatch remains disabled. Feedback is PV/`presentValue` readback
//! with `unavailable-feedback` stated, never an invented `source_time`.
use super::{
    AcceptedTarget, AliasSet, EncodedSetpoint, PreviewError, Priority, Result, TargetObject,
    FEEDBACK_UNAVAILABLE, MASK_NOTE, PRECONDITION_MAX_AGE_SECS, PREVIEW_FORMAT, TIMEOUT_POLICY,
    DEADLINE_SECS, DURATION_SECS, RATE_MAX_PER_HOUR,
};
use crate::binding::BindingStatus;
use crate::domain::ids::{BindingRevision, InstalledId};
use crate::domain::scope::TrustedScope;
use crate::domain::values::Unit;
use crate::observation::normalize::{Refusal, Suitability};
use crate::observation::time::{ClockReading, Freshness, FreshnessPolicy, TimeEvidence};
use crate::runtime::bacnet::APDU_RETRIES;
use crate::semantics::materialize::Plan;
use crate::semantics::matrix::Report;
use crate::semantics::sealed_profile::{self, Profile};
use crate::{accept::AcceptedRevision, access::RoleKind};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Precondition age shown on the preview; stale preconditions refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Precondition {
    observed_at: SystemTime,
    now: SystemTime,
}

impl Precondition {
    pub fn new(observed_at: SystemTime, now: SystemTime) -> Result<Self> {
        if now < observed_at {
            return Err(PreviewError::Invalid("precondition clock order"));
        }
        Ok(Self { observed_at, now })
    }

    /// Age in whole seconds.
    pub fn age_secs(self) -> u64 {
        self.now
            .duration_since(self.observed_at)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Refuse when older than [`PRECONDITION_MAX_AGE_SECS`].
    pub fn check_fresh(self) -> Result<Self> {
        if self.age_secs() > PRECONDITION_MAX_AGE_SECS {
            return Err(PreviewError::StalePrecondition);
        }
        Ok(self)
    }
}

/// Assess D07 time/freshness; non-`Fresh` refuses. Never qualification.
pub fn check_freshness(
    policy: &FreshnessPolicy,
    evidence: &TimeEvidence,
    now: &ClockReading,
) -> Result<Freshness> {
    let assessed = policy.assess(evidence, now);
    match assessed {
        Freshness::Fresh => Ok(assessed),
        Freshness::Stale => Err(PreviewError::StalePrecondition),
        Freshness::Unknown => Err(PreviewError::StalePrecondition),
    }
}

/// Only `SyntheticValueOnly` is usable; every refusal stays refused.
pub fn check_suitability(suitability: Suitability) -> Result<Suitability> {
    match suitability {
        Suitability::SyntheticValueOnly => Ok(suitability),
        Suitability::Refused(reason) => match reason {
            Refusal::WrongUnit => Err(PreviewError::WrongUnit {
                expected: "degC".to_string(),
                presented: "refused-unit".to_string(),
            }),
            Refusal::Missing
            | Refusal::Invalid
            | Refusal::NonFinite
            | Refusal::UnknownUnit
            | Refusal::Unsupported
            | Refusal::Transport
            | Refusal::NotFresh => Err(PreviewError::Invalid("unsuitable value")),
        },
    }
}

/// PV/`presentValue` readback with `unavailable-feedback`; `source_time` None.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackPlan {
    property: String,
    status: &'static str,
    source_time: Option<SystemTime>,
}

impl FeedbackPlan {
    pub fn pv_readback() -> Self {
        Self {
            property: "presentValue".to_string(),
            status: FEEDBACK_UNAVAILABLE,
            source_time: None,
        }
    }

    pub fn property(&self) -> &str {
        &self.property
    }
    pub fn status(&self) -> &'static str {
        self.status
    }
    pub fn source_time(&self) -> Option<SystemTime> {
        self.source_time
    }
}

/// Priority-array observation where supported; observation is not ownership.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PriorityArrayView {
    priority: u8,
    present_value: Option<f64>,
    relinquish_default: f64,
}

impl PriorityArrayView {
    pub fn new(priority: Priority, present_value: Option<f64>, relinquish_default: f64) -> Self {
        Self {
            priority: priority.get(),
            present_value,
            relinquish_default,
        }
    }

    pub fn priority(self) -> u8 {
        self.priority
    }
    pub fn present_value(self) -> Option<f64> {
        self.present_value
    }
    pub fn relinquish_default(self) -> f64 {
        self.relinquish_default
    }
    pub fn capability(self) -> &'static str {
        "supervisory"
    }
    pub fn observes_not_owns(self) -> bool {
        true
    }
    pub fn is_ownership(self) -> bool {
        false
    }
}

/// Release and uncertainty: explicit NULL relinquishment; original-target
/// cleanup survives replacement/revocation/offboarding; timeout after handoff
/// is uncertain, never permission to resend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePlan {
    target: InstalledId,
    admitted: bool,
}

impl ReleasePlan {
    pub fn new(target: InstalledId, admitted: bool) -> Self {
        Self { target, admitted }
    }

    pub fn target(&self) -> &InstalledId {
        &self.target
    }
    /// Whether this preview authorizes a NULL release. Presentation
    /// (`on_expiry`) is constant; this flag is lossless identity, not display.
    pub fn admitted(&self) -> bool {
        self.admitted
    }
    pub fn on_expiry(&self) -> &'static str {
        "null-relinquish"
    }
    pub fn survives_replacement(&self) -> bool {
        true
    }
    pub fn survives_revocation(&self) -> bool {
        true
    }
    pub fn survives_offboarding(&self) -> bool {
        true
    }
    pub fn timeout_policy(&self) -> &'static str {
        TIMEOUT_POLICY
    }
    pub fn allows_resend_after_timeout(&self) -> bool {
        false
    }

    /// Encoded BACnet NULL (`0x00`) only for an explicitly admitted release.
    pub fn null_wire(&self) -> Result<Vec<u8>> {
        if self.admitted {
            Ok(vec![0x00])
        } else {
            Err(PreviewError::NullNotAdmitted)
        }
    }
}

/// Timing and transport freeze shown on the preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    duration_secs: u64,
    deadline_secs: u64,
    apdu_retries: u8,
    rate_per_hour: u32,
}

impl Timing {
    /// Exact synthetic values; `apdu_retries` must equal frozen `APDU_RETRIES`.
    pub fn new(
        duration_secs: u64,
        deadline_secs: u64,
        apdu_retries: u8,
        rate_per_hour: u32,
    ) -> Result<Self> {
        if duration_secs != DURATION_SECS {
            return Err(PreviewError::Invalid("duration 15min"));
        }
        if deadline_secs != DEADLINE_SECS {
            return Err(PreviewError::Invalid("deadline 5s"));
        }
        if apdu_retries != APDU_RETRIES {
            return Err(PreviewError::Invalid("apdu_retries frozen"));
        }
        if rate_per_hour == 0 || rate_per_hour > RATE_MAX_PER_HOUR {
            return Err(PreviewError::Invalid("rate bound"));
        }
        Ok(Self {
            duration_secs,
            deadline_secs,
            apdu_retries,
            rate_per_hour,
        })
    }

    /// The frozen synthetic timing.
    pub fn synthetic() -> Self {
        Self {
            duration_secs: DURATION_SECS,
            deadline_secs: DEADLINE_SECS,
            apdu_retries: APDU_RETRIES,
            rate_per_hour: RATE_MAX_PER_HOUR,
        }
    }

    pub fn duration_secs(self) -> u64 {
        self.duration_secs
    }
    pub fn deadline_secs(self) -> u64 {
        self.deadline_secs
    }
    pub fn apdu_retries(self) -> u8 {
        self.apdu_retries
    }
    pub fn rate_per_hour(self) -> u32 {
        self.rate_per_hour
    }

    /// Rate-bounded preview: refuses when `used >= rate_per_hour`.
    pub fn check_rate(self, used: u32) -> Result<()> {
        if used >= self.rate_per_hour {
            return Err(PreviewError::RateExceeded {
                used,
                limit: self.rate_per_hour,
            });
        }
        Ok(())
    }
}

/// S03-ordered seal evidence: custody, then decode, then reconstruct.
/// `ledger_status` alone never yields availability.
///
/// Two paths share the ordered flags:
/// - marker path (`check_custody`/`decode`/`reconstruct` with no args) sets
///   the ordered Booleans only. It satisfies [`Self::availability`] for
///   historical preview construction, but carries no verified proof and
///   MUST refuse at the joined handoff (see [`Self::is_verified`]).
/// - real-owner join (`check_custody_with`/`decode_with`/`reconstruct_with`)
///   calls the S03 owners (custody/root-membership via
///   `Profile::ledger_status`, decode via `Profile::from_payloads`,
///   reconstruct via `Profile::verify_report`) and threads the source
///   ledger bytes through the seal into [`Preview::preview`]. Only this
///   path yields [`Self::is_verified`] and may pass the joined handoff.
///   Real `s03-*` codes surface via `From<sealed_profile::Error>`, never
///   collapsed into `preview-seal-order`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealOrder {
    custody: bool,
    decoded: bool,
    reconstructed: bool,
    profile: Option<Profile>,
    ledger: Option<Vec<u8>>,
    verified: bool,
}

impl SealOrder {
    pub fn new() -> Self {
        Self {
            custody: false,
            decoded: false,
            reconstructed: false,
            profile: None,
            ledger: None,
            verified: false,
        }
    }

    /// Marker custody (no proof). Ordered only; not verified for handoff.
    pub fn check_custody(&mut self) -> Result<()> {
        self.custody = true;
        Ok(())
    }

    /// Marker decode only after custody. Ordered only; not verified.
    pub fn decode(&mut self) -> Result<()> {
        if !self.custody {
            return Err(PreviewError::SealOrder {
                detail: "decode before custody",
            });
        }
        self.decoded = true;
        Ok(())
    }

    /// Marker reconstruct only after decode. Ordered only; not verified.
    pub fn reconstruct(&mut self) -> Result<()> {
        if !self.custody || !self.decoded {
            return Err(PreviewError::SealOrder {
                detail: "reconstruct before decode",
            });
        }
        self.reconstructed = true;
        Ok(())
    }

    /// Real-owner custody/root membership: the supplied ledger bytes must be
    /// the profile's ledger roots (`Profile::ledger_status` Available).
    /// Stores the profile plus source bytes for the decode join.
    pub fn check_custody_with(&mut self, profile: &Profile, ledger_bytes: &[u8]) -> Result<()> {
        profile.ledger_status(ledger_bytes).require()?;
        self.custody = true;
        self.profile = Some(profile.clone());
        self.ledger = Some(ledger_bytes.to_vec());
        Ok(())
    }

    /// Real-owner decode only after real custody: `Profile::from_payloads`
    /// must succeed and identify the custody profile (digest match).
    pub fn decode_with(&mut self, payloads: &[&str]) -> Result<()> {
        if !self.custody || self.profile.is_none() {
            return Err(PreviewError::SealOrder {
                detail: "decode requires real custody",
            });
        }
        let decoded = Profile::from_payloads(payloads)?;
        match &self.profile {
            Some(held) if held == &decoded => {}
            Some(_) => {
                return Err(PreviewError::from(
                    sealed_profile::Error::LedgerDigestMismatch,
                ));
            }
            None => {
                return Err(PreviewError::SealOrder {
                    detail: "decode requires real custody",
                });
            }
        }
        self.decoded = true;
        Ok(())
    }

    /// Real-owner reconstruct only after real decode: the stored profile
    /// must verify against the supplied report/plan
    /// (`Profile::verify_report`: digest then meaning). Marks verified.
    pub fn reconstruct_with(&mut self, report: &Report, plan: &Plan) -> Result<()> {
        if !self.custody || !self.decoded {
            return Err(PreviewError::SealOrder {
                detail: "reconstruct before decode",
            });
        }
        let profile = self.profile.as_ref().ok_or(PreviewError::SealOrder {
            detail: "reconstruct requires decoded profile",
        })?;
        profile.verify_report(report, plan)?;
        self.reconstructed = true;
        self.verified = true;
        Ok(())
    }

    /// Whether the full real-owner chain verified (custody + decode +
    /// reconstruct through the S03 owners with ledger bytes held). Only
    /// verified seals may pass the joined handoff; marker-only seals refuse there.
    pub fn is_verified(&self) -> bool {
        self.verified && self.custody && self.decoded && self.reconstructed && self.ledger.is_some()
    }

    /// Verified ledger digest for evidence (None for marker seals).
    pub fn ledger_digest(&self) -> Option<&str> {
        self.profile.as_ref().map(|p| p.ledger_digest())
    }

    /// Available only after the full ordered chain (marker or verified).
    /// Preview construction accepts either; the joined handoff additionally
    /// requires [`Self::is_verified`].
    pub fn availability(&self) -> Result<()> {
        if self.custody && self.decoded && self.reconstructed {
            Ok(())
        } else {
            Err(PreviewError::SealOrder {
                detail: "seal-custody/decode/reconstruct order required",
            })
        }
    }

    /// Verified availability for the joined handoff: ordered chain PLUS
    /// real-owner verification. Marker-only Booleans refuse here with
    /// `preview-seal-order` (or the preserved `s03-*` from the join).
    pub fn verified_availability(&self) -> Result<()> {
        self.availability()?;
        if self.is_verified() {
            Ok(())
        } else {
            Err(PreviewError::SealOrder {
                detail: "marker seal without real S03 custody/decode/reconstruct proof; joined handoff refused",
            })
        }
    }

    /// `ledger_status` alone never yields availability.
    pub fn ledger_only(&self) -> Result<()> {
        Err(PreviewError::SealOrder {
            detail: "ledger_status alone is insufficient",
        })
    }
}

impl Default for SealOrder {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode through the real S03 decoder; no independent manifest parser exists.
pub fn decode_profile(payloads: &[&str]) -> std::result::Result<Profile, sealed_profile::Error> {
    Profile::from_payloads(payloads)
}

/// Versioned human-action preview: revision-bound information, not dispatch.
#[derive(Debug, Clone, PartialEq)]
pub struct Preview {
    target: AcceptedTarget,
    priority: Priority,
    object: TargetObject,
    unit: Unit,
    encoded: EncodedSetpoint,
    timing: Timing,
    precondition_age_secs: u64,
    feedback: FeedbackPlan,
    array: PriorityArrayView,
    release: ReleasePlan,
    /// Whether the authoring seal carried the real S03 verified join
    /// (custody + decode + reconstruct through the S03 owners). Threaded
    /// from `SealOrder::is_verified` at preview time; frozen
    /// `canonical_bytes`/`identity_bytes` are unchanged (seal proof gates
    /// the joined handoff, never the payload text). Marker previews stay
    /// constructible but refuse at the joined handoff.
    seal_verified: bool,
    /// Verified S03 ledger digest when sealed-verified, else None.
    /// Source bytes (ledger) are threaded via the seal into preview;
    /// the digest is evidence only, never payload identity.
    seal_ledger_digest: Option<String>,
}

impl Preview {
    /// Frozen-order checks: access, target, binding status (never
    /// `ObservedQualified`), priority, commandable object, scalar array, unit,
    /// encoded range/wire/tolerance, aliases, precondition, seal order.
    #[allow(clippy::too_many_arguments)]
    pub fn preview(
        scope: TrustedScope,
        equipment: InstalledId,
        binding_revision: BindingRevision,
        accepted_revision: AcceptedRevision,
        binding_status: BindingStatus,
        ceiling: u8,
        role: RoleKind,
        priority: Option<u8>,
        object_type: u16,
        property_id: u32,
        array_index: Option<u32>,
        unit: Unit,
        requested_c: f64,
        wire_override: Option<f64>,
        aliases: &[&str],
        precondition: Precondition,
        seal: &SealOrder,
        release_target: InstalledId,
        release_admitted: bool,
    ) -> Result<Self> {
        super::check_access(ceiling, role)?;
        let target =
            AcceptedTarget::new(scope, equipment, binding_revision, accepted_revision)?;
        match binding_status {
            BindingStatus::Imported => {}
            BindingStatus::Valid => {}
            BindingStatus::ObservedQualified => {
                return Err(PreviewError::Invalid("no observed qualification here"));
            }
        }
        let priority = Priority::from_option(priority)?.check_commissioned()?;
        let object = TargetObject::new(object_type, property_id, array_index)
            .check_commandable()?
            .check_scalar()?;
        super::check_unit(&unit)?;
        let encoded = match wire_override {
            None => EncodedSetpoint::new(requested_c)?,
            Some(wire) => EncodedSetpoint::from_decoded(requested_c, wire)?,
        };
        let _aliases = AliasSet::new(aliases)?;
        precondition.check_fresh()?;
        seal.availability()?;
        // Source bytes are threaded via the seal: a verified seal carries
        // the S03 ledger digest into the preview for the joined handoff.
        // Marker seals thread nothing (None) and refuse there.
        let seal_verified = seal.is_verified();
        let seal_ledger_digest = seal.ledger_digest().filter(|_| seal.ledger.is_some()).map(str::to_string);
        let timing = Timing::synthetic();
        let feedback = FeedbackPlan::pv_readback();
        let array = PriorityArrayView::new(priority, Some(encoded.wire_c()), encoded.wire_c());
        let release = ReleasePlan::new(release_target, release_admitted);
        Ok(Self {
            target,
            priority,
            object,
            unit,
            encoded,
            timing,
            precondition_age_secs: precondition.age_secs(),
            feedback,
            array,
            release,
            seal_verified,
            seal_ledger_digest,
        })
    }

    pub fn format(&self) -> &'static str {
        PREVIEW_FORMAT
    }
    pub fn target(&self) -> &AcceptedTarget {
        &self.target
    }
    pub fn priority(&self) -> Priority {
        self.priority
    }
    pub fn object(&self) -> TargetObject {
        self.object
    }
    pub fn unit(&self) -> &Unit {
        &self.unit
    }
    pub fn encoded(&self) -> &EncodedSetpoint {
        &self.encoded
    }
    pub fn timing(&self) -> Timing {
        self.timing
    }
    pub fn precondition_age_secs(&self) -> u64 {
        self.precondition_age_secs
    }
    pub fn feedback(&self) -> &FeedbackPlan {
        &self.feedback
    }
    pub fn array(&self) -> PriorityArrayView {
        self.array
    }
    pub fn release(&self) -> &ReleasePlan {
        &self.release
    }

    /// Previews never reserve budget and never dispatch.
    pub fn is_reservation(&self) -> bool {
        false
    }
    pub fn is_dispatch(&self) -> bool {
        false
    }
    /// Freshness never becomes observed qualification here.
    pub fn is_qualified(&self) -> bool {
        false
    }

    /// Deterministic canonical bytes (field order frozen) for evidence.
    /// PRESENTATION-ONLY: `{:.4}` text plus constant `on_expiry` intentionally
    /// omit lossless identity. Distinct binary32 values sharing 4-decimal text
    /// (e.g. 22.00001 vs 22.00002) MUST NOT reconcile as same payload; use
    /// [`Self::identity_bytes`] plus journal wire_bits/kind/target for handoffs.
    pub fn canonical_bytes(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|p{}|av{}:pv{}|{}|{:.4}|{}|{}s|{}s|r{}|age{}|{}|{}",
            PREVIEW_FORMAT,
            self.target.scope().as_str(),
            self.target.equipment().as_str(),
            self.target.binding_revision().as_u32(),
            self.target.accepted_revision().get(),
            self.priority.get(),
            self.object.object_type(),
            self.object.property_id(),
            self.unit.as_str(),
            self.encoded.wire_c(),
            MASK_NOTE,
            self.timing.duration_secs(),
            self.timing.deadline_secs(),
            self.timing.apdu_retries(),
            self.precondition_age_secs,
            self.feedback.status(),
            self.release.on_expiry(),
        )
    }

    /// Lossless action kind: `release` when a NULL release is explicitly
    /// admitted, otherwise `set`. Distinct from presentation `on_expiry`.
    pub fn action_kind(&self) -> &'static str {
        if self.release.admitted() {
            "release"
        } else {
            "set"
        }
    }

    /// Authorized release target for this preview (obligation reference).
    /// SET previews still carry the preview release target; journal persists
    /// it so a later target change refuses instead of retargeting.
    pub fn release_target(&self) -> &InstalledId {
        self.release.target()
    }

    /// Whether this preview admits a NULL release (lossless, not display).
    pub fn release_admitted(&self) -> bool {
        self.release.admitted()
    }

    /// Whether the authoring seal carried the real S03 verified join.
    /// The joined handoff requires true; marker previews refuse there.
    pub fn seal_verified(&self) -> bool {
        self.seal_verified
    }

    /// Verified S03 ledger digest threaded via the seal, if verified.
    pub fn seal_ledger_digest(&self) -> Option<&str> {
        self.seal_ledger_digest.as_deref()
    }

    /// Lossless identity for admission/handoff comparison (field order frozen).
    /// Presentation `canonical_bytes` plus exact `wire_bits` (binary32, not
    /// `{:.4}`), explicit kind (`set` vs `release`), release admission flag
    /// and authorized release target. Two previews with equal presentation
    /// but different bits/kind/target have different identity and MUST NOT
    /// reconcile. Identical retries (equal identity) are authorized outcome
    /// inspection, not a new physical attempt (Slice B delivered: durable
    /// lifecycle in `action_journal/lifecycle.rs`, owned rate in
    /// `action_journal/rate.rs`, custody link via `admission_body_v2`).
    pub fn identity_bytes(&self) -> String {
        format!(
            "{}|bits{:08X}|kind:{}|rel:{}:{}|{}",
            PREVIEW_FORMAT,
            self.encoded.wire_bits(),
            self.action_kind(),
            u8::from(self.release.admitted()),
            self.release.target().as_str(),
            self.canonical_bytes(),
        )
    }
}

/// Millis since the Unix epoch for synthetic test clocks.
pub fn synthetic_time(millis: i64) -> SystemTime {
    if millis >= 0 {
        UNIX_EPOCH + Duration::from_millis(millis as u64)
    } else {
        UNIX_EPOCH - Duration::from_millis(millis.unsigned_abs())
    }
}
