//! M01-PR06 deterministic offline vocabulary conversion.
//!
//! Pure offline mapping from the pinned curated subset (see
//! [`crate::profile`]) into the Verdant namespace (`verdant:v1`). Std-only,
//! zero dependencies, no network, no stores, no native lifecycle, no field
//! acquisition. Conversion is pure (`&` inputs only): refusals happen before
//! any write by construction, and there is no global merge (collisions are
//! diagnostics, never silent winners).
//!
//! Consumes PR02 representation only: [`BindingRevision`], [`InstalledId`],
//! [`Unit`], [`OpMode`] and [`Value`]. No domain semantics are redefined.
//!
//! Revision semantics (PR07 consumes this): [`BindingSet::from_conversion`]
//! starts at `1` for the first applied conversion (`0` remains the PR02
//! placeholder). [`apply`] bumps by one only when profile, input digest or
//! content digest differs; identical input under the same profile is a
//! [`ApplyOutcome::Noop`] with the revision untouched.
//!
//! Content-hash discipline: [`ExternalSite::content_digest`] and the record
//! content digest cover only trusted semantic content
//! (`verdant_slot`, `unit`, `value`) sorted by slot. Labels and external
//! source keys travel as text but never enter the content hash (labels are
//! not identity, like the domain fixture). [`convert`] preserves trusted
//! fields verbatim; tests assert field equality plus digest equality.
//!
//! Determinism: every ordering is sorted (`source_key` for input hashing,
//! `verdant_slot` for bindings and the record, candidates for collisions).
//! No `HashMap` iteration, no time, no randomness. Same input plus same
//! profile yields byte-identical records and byte-identical failure JSON.
//!
//! ```ignore
//! # use verdant_semantics_convert::{ExternalItem, ExternalSite, convert};
//! # use verdant_semantics_profile::Profile;
//! # use verdant_domain_values::{Unit, Value, Decimal};
//! # // Crate names are illustrative; real tests wire via path.
//! let profile = Profile::pinned();
//! let item = ExternalItem::parse(
//!     "ext-ahu-1",
//!     "brick:AHU",
//!     "ahu-1",
//!     "AHU",
//!     "degC",
//!     Value::Decimal(Decimal::parse("21.50").expect("frozen decimal is valid")),
//! )
//! .expect("frozen positive item is valid");
//! let site = ExternalSite::new(vec![item]).expect("single item site is valid");
//! let conversion = convert(&site, &profile).expect("positive converts");
//! assert_eq!(conversion.record().profile_id(), profile.id());
//! ```

use super::profile::{ClassDecision, Profile, VerdantKind};
use crate::domain::ids::{BindingRevision, InstalledId};
use crate::domain::values::{OpMode, Unit, Value};
use std::collections::BTreeMap;
use std::fmt;

/// Maximum source-key length in bytes (all allowed chars are ASCII).
pub const MAX_SOURCE_KEY_LEN: usize = 128;
/// Maximum external-class length in bytes (all allowed chars are ASCII).
pub const MAX_CLASS_LEN: usize = 128;
/// Maximum display-label length in bytes.
pub const MAX_LABEL_LEN: usize = 128;

fn quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn validate_token(kind: &'static str, raw: &str, max: usize) -> Result<(), SemanticsError> {
    if raw.is_empty() {
        return Err(SemanticsError::InvalidInput {
            what: kind,
            detail: "value must not be empty".to_string(),
        });
    }
    if raw.len() > max {
        return Err(SemanticsError::InvalidInput {
            what: kind,
            detail: format!("value is {} chars; maximum is {max}", raw.len()),
        });
    }
    let ok = raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
    if !ok {
        return Err(SemanticsError::InvalidInput {
            what: kind,
            detail: format!("value has unsupported characters: '{raw}'"),
        });
    }
    Ok(())
}

fn validate_label(raw: &str) -> Result<(), SemanticsError> {
    if raw.is_empty() {
        return Err(SemanticsError::InvalidInput {
            what: "label",
            detail: "label must not be empty".to_string(),
        });
    }
    if raw.len() > MAX_LABEL_LEN {
        return Err(SemanticsError::InvalidInput {
            what: "label",
            detail: format!("label is {} chars; maximum is {MAX_LABEL_LEN}", raw.len()),
        });
    }
    if raw.contains('\0') {
        return Err(SemanticsError::InvalidInput {
            what: "label",
            detail: "label must not contain NUL".to_string(),
        });
    }
    Ok(())
}

/// Typed semantics failure with stable machine codes.
///
/// Matches stay exhaustive so new variants break the build. `to_json` is the
/// deterministic failure rendering used by the failure-differential test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticsError {
    /// Caller text failed validation (never a panic).
    InvalidInput { what: &'static str, detail: String },
    /// Class not recognized by the pinned profile.
    UnknownClass { class: String, profile: String },
    /// Known vocabulary but outside the tiny_site scenario for the profile.
    OutOfScenario {
        class: String,
        reason: String,
        profile: String,
    },
    /// Class maps to a kind but the slot prefix does not match.
    SlotMismatch {
        class: String,
        kind: String,
        slot: String,
        profile: String,
    },
    /// Two or more candidates claim one Verdant slot (no merge).
    Collision {
        slot: String,
        candidates: Vec<String>,
        profile: String,
    },
    /// Revision bump would overflow `u32`.
    RevisionOverflow { current: u32, profile: String },
}

impl SemanticsError {
    /// Stable machine-readable code for tests and evidence mapping.
    pub fn code(&self) -> &'static str {
        match self {
            SemanticsError::InvalidInput { .. } => "invalid-input",
            SemanticsError::UnknownClass { .. } => "unknown-class",
            SemanticsError::OutOfScenario { .. } => "out-of-scenario",
            SemanticsError::SlotMismatch { .. } => "slot-mismatch",
            SemanticsError::Collision { .. } => "collision",
            SemanticsError::RevisionOverflow { .. } => "revision-overflow",
        }
    }

    /// Deterministic JSON rendering (field order frozen, candidates sorted).
    pub fn to_json(&self) -> String {
        match self {
            SemanticsError::InvalidInput { what, detail } => format!(
                "{{\"code\":\"invalid-input\",\"detail\":{},\"what\":{}}}",
                quote(detail),
                quote(what)
            ),
            SemanticsError::UnknownClass { class, profile } => format!(
                "{{\"code\":\"unknown-class\",\"class\":{},\"profile\":{}}}",
                quote(class),
                quote(profile)
            ),
            SemanticsError::OutOfScenario {
                class,
                reason,
                profile,
            } => format!(
                "{{\"code\":\"out-of-scenario\",\"class\":{},\"profile\":{},\"reason\":{}}}",
                quote(class),
                quote(profile),
                quote(reason)
            ),
            SemanticsError::SlotMismatch {
                class,
                kind,
                slot,
                profile,
            } => format!(
                "{{\"code\":\"slot-mismatch\",\"class\":{},\"kind\":{},\"profile\":{},\"slot\":{}}}",
                quote(class),
                quote(kind),
                quote(profile),
                quote(slot)
            ),
            SemanticsError::Collision {
                slot,
                candidates,
                profile,
            } => {
                let mut sorted = candidates.clone();
                sorted.sort();
                let mut list = String::from("[");
                let mut first = true;
                for candidate in &sorted {
                    if !first {
                        list.push(',');
                    }
                    first = false;
                    list.push_str(&quote(candidate));
                }
                list.push(']');
                format!(
                    "{{\"code\":\"collision\",\"candidates\":{list},\"profile\":{},\"slot\":{}}}",
                    quote(profile),
                    quote(slot)
                )
            }
            SemanticsError::RevisionOverflow { current, profile } => format!(
                "{{\"code\":\"revision-overflow\",\"current\":{},\"profile\":{}}}",
                quote(&current.to_string()),
                quote(profile)
            ),
        }
    }
}

impl fmt::Display for SemanticsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SemanticsError::InvalidInput { what, detail } => {
                write!(f, "invalid {what}: {detail}")
            }
            SemanticsError::UnknownClass { class, profile } => {
                write!(f, "unknown class '{class}' for profile '{profile}'")
            }
            SemanticsError::OutOfScenario {
                class,
                reason,
                profile,
            } => write!(
                f,
                "out-of-scenario class '{class}' for profile '{profile}': {reason}"
            ),
            SemanticsError::SlotMismatch {
                class,
                kind,
                slot,
                profile,
            } => write!(
                f,
                "slot mismatch: class '{class}' maps to kind '{kind}' but slot '{slot}' does not match for profile '{profile}'"
            ),
            SemanticsError::Collision {
                slot,
                candidates,
                profile,
            } => {
                let mut sorted = candidates.clone();
                sorted.sort();
                write!(
                    f,
                    "collision: slot '{slot}' claimed by {} for profile '{profile}' (no merge)",
                    sorted.join(", ")
                )
            }
            SemanticsError::RevisionOverflow { current, profile } => write!(
                f,
                "revision overflow: current {current} cannot bump for profile '{profile}'"
            ),
        }
    }
}

impl std::error::Error for SemanticsError {}

/// Borrow the mode of a value when it carries one.
///
/// This is the explicit [`OpMode`] consumption point: `Value::Mode` holds the
/// frozen operating-mode example (known plus preserved unknown). All other
/// value kinds carry no mode.
pub fn mode_of(value: &Value) -> Option<&OpMode> {
    match value {
        Value::Missing => None,
        Value::Bool(_) => None,
        Value::Integer(_) => None,
        Value::Decimal(_) => None,
        Value::Text(_) => None,
        Value::Mode(mode) => Some(mode),
        Value::Diagnostic(_) => None,
    }
}

/// One external candidate: validated syntax, classification deferred to
/// [`convert`] so out-of-scenario and unknown classes parse here and refuse
/// there with classification diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalItem {
    source_key: String,
    external_class: String,
    verdant_slot: InstalledId,
    label: String,
    unit: Unit,
    value: Value,
}

impl ExternalItem {
    /// Validate caller text into a candidate.
    ///
    /// Refuses empty, over-long or out-of-alphabet source keys, classes and
    /// slots, empty labels, and invalid units with a typed error; never
    /// panics. Classification (supported vs out-of-scenario vs unknown) and
    /// slot-kind consistency are checked by [`convert`], not here.
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        source_key: &str,
        external_class: &str,
        verdant_slot: &str,
        label: &str,
        unit_text: &str,
        value: Value,
    ) -> Result<ExternalItem, SemanticsError> {
        validate_token("source-key", source_key, MAX_SOURCE_KEY_LEN)?;
        validate_token("external-class", external_class, MAX_CLASS_LEN)?;
        let slot = InstalledId::parse(verdant_slot).map_err(|e| SemanticsError::InvalidInput {
            what: "verdant-slot",
            detail: format!("invalid installed id '{verdant_slot}': {e} [{}]", e.code()),
        })?;
        validate_label(label)?;
        let unit = Unit::parse(unit_text).map_err(|e| SemanticsError::InvalidInput {
            what: "unit",
            detail: format!("invalid unit '{unit_text}': {e} [{}]", e.code()),
        })?;
        Ok(ExternalItem {
            source_key: source_key.to_string(),
            external_class: external_class.to_string(),
            verdant_slot: slot,
            label: label.to_string(),
            unit,
            value,
        })
    }

    /// Borrow the external source key.
    pub fn source_key(&self) -> &str {
        &self.source_key
    }

    /// Borrow the external class text.
    pub fn external_class(&self) -> &str {
        &self.external_class
    }

    /// Borrow the desired Verdant slot.
    pub fn verdant_slot(&self) -> &InstalledId {
        &self.verdant_slot
    }

    /// Borrow the display label (text only, never identity).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Borrow the engineering unit (preserved verbatim through conversion).
    pub fn unit(&self) -> &Unit {
        &self.unit
    }

    /// Borrow the representative value (preserved verbatim).
    pub fn value(&self) -> &Value {
        &self.value
    }
}

/// Curated external site: the tiny_site-shaped candidate set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSite {
    items: Vec<ExternalItem>,
}

impl ExternalSite {
    /// Bundle validated candidates into a site.
    ///
    /// Refuses an empty set and duplicate source keys (deterministic: the
    /// first duplicate in sorted order is named); never panics.
    pub fn new(items: Vec<ExternalItem>) -> Result<ExternalSite, SemanticsError> {
        if items.is_empty() {
            return Err(SemanticsError::InvalidInput {
                what: "site",
                detail: "site must contain at least one candidate".to_string(),
            });
        }
        let mut keys: Vec<&str> = items.iter().map(|item| item.source_key()).collect();
        keys.sort();
        for window in keys.windows(2) {
            if window[0] == window[1] {
                return Err(SemanticsError::InvalidInput {
                    what: "source-key",
                    detail: format!("duplicate source key '{}'", window[0]),
                });
            }
        }
        Ok(ExternalSite { items })
    }

    /// Borrow the candidates in caller order.
    pub fn items(&self) -> &[ExternalItem] {
        &self.items
    }

    fn sorted_by_source_key(&self) -> Vec<&ExternalItem> {
        let mut refs: Vec<&ExternalItem> = self.items.iter().collect();
        refs.sort_by(|a, b| a.source_key().cmp(b.source_key()));
        refs
    }

    fn canonical_input_bytes(&self) -> String {
        let mut out = String::new();
        let mut first = true;
        for item in self.sorted_by_source_key() {
            if !first {
                out.push('\n');
            }
            first = false;
            out.push_str(item.source_key());
            out.push('\x1f');
            out.push_str(item.external_class());
            out.push('\x1f');
            out.push_str(item.verdant_slot().as_str());
            out.push('\x1f');
            out.push_str(item.label());
            out.push('\x1f');
            out.push_str(item.unit().as_str());
            out.push('\x1f');
            out.push_str(&item.value().to_json());
        }
        out
    }

    /// Deterministic input digest (FNV-1a hex over canonical input bytes
    /// sorted by source key). Used for no-op detection and the record.
    pub fn input_digest(&self) -> String {
        fnv1a_hex(self.canonical_input_bytes().as_bytes())
    }

    fn canonical_content_bytes(&self) -> String {
        let mut refs: Vec<&ExternalItem> = self.items.iter().collect();
        refs.sort_by(|a, b| a.verdant_slot().as_str().cmp(b.verdant_slot().as_str()));
        let mut out = String::new();
        let mut first = true;
        for item in refs {
            if !first {
                out.push('\n');
            }
            first = false;
            out.push_str(item.verdant_slot().as_str());
            out.push('\x1f');
            out.push_str(item.unit().as_str());
            out.push('\x1f');
            out.push_str(&item.value().to_json());
        }
        out
    }

    /// Content digest over trusted semantic content only
    /// (`verdant_slot`, `unit`, `value` sorted by slot). Labels, source keys
    /// and external class aliases never enter this hash. Preserved verbatim
    /// through [`convert`].
    pub fn content_digest(&self) -> String {
        fnv1a_hex(self.canonical_content_bytes().as_bytes())
    }
}

/// One Verdant binding: the converted namespace entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    verdant_id: InstalledId,
    kind: VerdantKind,
    source_key: String,
    external_class: String,
    label: String,
    unit: Unit,
    value: Value,
}

impl Binding {
    /// Borrow the Verdant installed identity.
    pub fn verdant_id(&self) -> &InstalledId {
        &self.verdant_id
    }

    /// Borrow the Verdant kind.
    pub fn kind(&self) -> VerdantKind {
        self.kind
    }

    /// Borrow the source key that produced this binding.
    pub fn source_key(&self) -> &str {
        &self.source_key
    }

    /// Borrow the external class that mapped here.
    pub fn external_class(&self) -> &str {
        &self.external_class
    }

    /// Borrow the display label (text only, never identity).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Borrow the preserved unit.
    pub fn unit(&self) -> &Unit {
        &self.unit
    }

    /// Borrow the preserved value.
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Frozen JSON encoding (field order frozen; value is nested).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"external_class\":{},\"kind\":{},\"label\":{},\"source_key\":{},\"unit\":{},\"value\":{},\"verdant_id\":{},\"verdant_namespace\":{}}}",
            quote(&self.external_class),
            quote(self.kind.as_str()),
            quote(&self.label),
            quote(&self.source_key),
            quote(self.unit.as_str()),
            self.value.to_json(),
            quote(self.verdant_id.as_str()),
            quote(super::profile::VERDANT_NAMESPACE),
        )
    }
}

/// Per-item outcome in the conversion record (deterministic order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemOutcome {
    source_key: String,
    external_class: String,
    verdant_slot: String,
    kind: VerdantKind,
    outcome: &'static str,
}

impl ItemOutcome {
    /// Borrow the source key.
    pub fn source_key(&self) -> &str {
        &self.source_key
    }

    /// Borrow the external class.
    pub fn external_class(&self) -> &str {
        &self.external_class
    }

    /// Borrow the Verdant slot.
    pub fn verdant_slot(&self) -> &str {
        &self.verdant_slot
    }

    /// Borrow the mapped kind.
    pub fn kind(&self) -> VerdantKind {
        self.kind
    }

    /// Borrow the outcome text (`mapped` for every successful item in v1).
    pub fn outcome(&self) -> &str {
        self.outcome
    }

    /// Frozen JSON encoding (field order frozen).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"external_class\":{},\"outcome\":{},\"source_key\":{},\"verdant_kind\":{},\"verdant_slot\":{}}}",
            quote(&self.external_class),
            quote(self.outcome),
            quote(&self.source_key),
            quote(self.kind.as_str()),
            quote(&self.verdant_slot),
        )
    }
}

/// Conversion record and manifest (PR07 consumes this shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversionRecord {
    profile_id: String,
    input_digest: String,
    content_digest: String,
    items: Vec<ItemOutcome>,
}

impl ConversionRecord {
    /// Borrow the profile identifier.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Borrow the input digest.
    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    /// Borrow the content digest (preserved trusted hash).
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Borrow the per-item outcomes in deterministic slot order.
    pub fn items(&self) -> &[ItemOutcome] {
        &self.items
    }

    /// Frozen JSON encoding (field order frozen; items sorted by slot).
    pub fn to_json(&self) -> String {
        let mut items_json = String::from("[");
        let mut first = true;
        for item in &self.items {
            if !first {
                items_json.push(',');
            }
            first = false;
            items_json.push_str(&item.to_json());
        }
        items_json.push(']');
        format!(
            "{{\"content_digest\":{},\"input_digest\":{},\"items\":{items_json},\"profile\":{}}}",
            quote(&self.content_digest),
            quote(&self.input_digest),
            quote(&self.profile_id),
        )
    }
}

/// Successful conversion: record plus bindings (both sorted by slot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversion {
    record: ConversionRecord,
    bindings: Vec<Binding>,
}

impl Conversion {
    /// Borrow the conversion record and manifest.
    pub fn record(&self) -> &ConversionRecord {
        &self.record
    }

    /// Borrow the bindings in deterministic slot order.
    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// Frozen JSON encoding (`record` plus `bindings`, both deterministic).
    pub fn to_json(&self) -> String {
        let mut bindings_json = String::from("[");
        let mut first = true;
        for binding in &self.bindings {
            if !first {
                bindings_json.push(',');
            }
            first = false;
            bindings_json.push_str(&binding.to_json());
        }
        bindings_json.push(']');
        format!(
            "{{\"bindings\":{bindings_json},\"record\":{}}}",
            self.record.to_json()
        )
    }
}

/// Bound state carrying the semantic revision (PR07 consumes revision
/// semantics plus the record shape and unmapped-class diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingSet {
    revision: BindingRevision,
    profile_id: String,
    input_digest: String,
    content_digest: String,
    bindings: Vec<Binding>,
}

impl BindingSet {
    /// Wrap a conversion at an explicit revision (first applied is `1`;
    /// `0` remains the PR02 placeholder and never appears here by default).
    pub fn from_conversion(conversion: &Conversion, revision: BindingRevision) -> BindingSet {
        BindingSet {
            revision,
            profile_id: conversion.record().profile_id().to_string(),
            input_digest: conversion.record().input_digest().to_string(),
            content_digest: conversion.record().content_digest().to_string(),
            bindings: conversion.bindings().to_vec(),
        }
    }

    /// Borrow the binding revision.
    pub fn revision(&self) -> BindingRevision {
        self.revision
    }

    /// Borrow the profile identifier.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Borrow the input digest.
    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    /// Borrow the content digest.
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Borrow the bindings in deterministic slot order.
    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// Frozen JSON encoding (field order frozen; revision as a string).
    pub fn to_json(&self) -> String {
        let mut bindings_json = String::from("[");
        let mut first = true;
        for binding in &self.bindings {
            if !first {
                bindings_json.push(',');
            }
            first = false;
            bindings_json.push_str(&binding.to_json());
        }
        bindings_json.push(']');
        format!(
            "{{\"bindings\":{bindings_json},\"content_digest\":{},\"input_digest\":{},\"profile\":{},\"revision\":{}}}",
            quote(&self.content_digest),
            quote(&self.input_digest),
            quote(&self.profile_id),
            quote(&self.revision.as_u32().to_string()),
        )
    }
}

/// Application of a conversion to bound state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Input already current: revision untouched, no new bindings.
    Noop { record: ConversionRecord },
    /// New content: revision bumped by one with the new bindings.
    Applied {
        record: ConversionRecord,
        next: BindingSet,
    },
}

impl ApplyOutcome {
    /// Borrow the conversion record for either outcome.
    pub fn record(&self) -> &ConversionRecord {
        match self {
            ApplyOutcome::Noop { record } => record,
            ApplyOutcome::Applied { record, .. } => record,
        }
    }

    /// True only for no-ops.
    pub fn is_noop(&self) -> bool {
        match self {
            ApplyOutcome::Noop { .. } => true,
            ApplyOutcome::Applied { .. } => false,
        }
    }
}

/// Deterministically convert the supported subset into the Verdant namespace.
///
/// Pure and offline: takes `&` inputs, produces owned outputs, writes
/// nothing. Order of checks is frozen for deterministic failures:
/// classification (supported vs out-of-scenario vs unknown), then slot-kind
/// consistency, then collision. The first failure in sorted source-key order
/// wins, so the same input plus the same profile always yields the same
/// failure bytes.
pub fn convert(site: &ExternalSite, profile: &Profile) -> Result<Conversion, SemanticsError> {
    let profile_id = profile.id().to_string();
    let mut ordered: Vec<&ExternalItem> = site.items().iter().collect();
    ordered.sort_by(|a, b| a.source_key().cmp(b.source_key()));

    let mut classified: Vec<(&ExternalItem, VerdantKind)> = Vec::with_capacity(ordered.len());
    for item in ordered {
        let decision = profile.classify(item.external_class());
        match decision {
            ClassDecision::Supported(kind) => {
                if !item.verdant_slot().as_str().starts_with(kind.slot_prefix()) {
                    return Err(SemanticsError::SlotMismatch {
                        class: item.external_class().to_string(),
                        kind: kind.as_str().to_string(),
                        slot: item.verdant_slot().as_str().to_string(),
                        profile: profile_id,
                    });
                }
                classified.push((item, kind));
            }
            ClassDecision::OutOfScenario { reason } => {
                return Err(SemanticsError::OutOfScenario {
                    class: item.external_class().to_string(),
                    reason: reason.to_string(),
                    profile: profile_id,
                });
            }
            ClassDecision::Unknown => {
                return Err(SemanticsError::UnknownClass {
                    class: item.external_class().to_string(),
                    profile: profile_id,
                });
            }
        }
    }

    let mut by_slot: BTreeMap<&str, Vec<&ExternalItem>> = BTreeMap::new();
    for (item, _) in &classified {
        by_slot
            .entry(item.verdant_slot().as_str())
            .or_default()
            .push(*item);
    }
    for (slot, claimants) in &by_slot {
        if claimants.len() > 1 {
            let mut candidates: Vec<String> = claimants
                .iter()
                .map(|item| item.source_key().to_string())
                .collect();
            candidates.sort();
            return Err(SemanticsError::Collision {
                slot: (*slot).to_string(),
                candidates,
                profile: profile_id,
            });
        }
    }

    let mut bindings: Vec<Binding> = classified
        .iter()
        .map(|(item, kind)| Binding {
            verdant_id: item.verdant_slot().clone(),
            kind: *kind,
            source_key: item.source_key().to_string(),
            external_class: item.external_class().to_string(),
            label: item.label().to_string(),
            unit: item.unit().clone(),
            value: item.value().clone(),
        })
        .collect();
    bindings.sort_by(|a, b| a.verdant_id().as_str().cmp(b.verdant_id().as_str()));

    let mut outcomes: Vec<ItemOutcome> = classified
        .iter()
        .map(|(item, kind)| ItemOutcome {
            source_key: item.source_key().to_string(),
            external_class: item.external_class().to_string(),
            verdant_slot: item.verdant_slot().as_str().to_string(),
            kind: *kind,
            outcome: "mapped",
        })
        .collect();
    outcomes.sort_by(|a, b| a.verdant_slot().cmp(b.verdant_slot()));

    let input_digest = site.input_digest();
    let mut content_lines: Vec<String> = Vec::with_capacity(bindings.len());
    for binding in &bindings {
        content_lines.push(format!(
            "{}\x1f{}\x1f{}",
            binding.verdant_id().as_str(),
            binding.unit().as_str(),
            binding.value().to_json()
        ));
    }
    content_lines.sort();
    let content_digest = fnv1a_hex(content_lines.join("\n").as_bytes());
    let site_content = site.content_digest();
    debug_assert_eq!(content_digest, site_content);

    let record = ConversionRecord {
        profile_id,
        input_digest,
        content_digest,
        items: outcomes,
    };
    Ok(Conversion { record, bindings })
}

/// Apply a site to bound state with revision discipline.
///
/// Pure: `current` is borrowed and never mutated. Convert first (same
/// deterministic failures as [`convert`]); when profile, input digest and
/// content digest all match, the outcome is [`ApplyOutcome::Noop`] with the
/// revision untouched. Otherwise the revision bumps by one (checked; overflow
/// is a typed refusal).
pub fn apply(
    site: &ExternalSite,
    profile: &Profile,
    current: &BindingSet,
) -> Result<ApplyOutcome, SemanticsError> {
    let conversion = convert(site, profile)?;
    let record = conversion.record().clone();
    if record.profile_id() == current.profile_id()
        && record.input_digest() == current.input_digest()
        && record.content_digest() == current.content_digest()
    {
        return Ok(ApplyOutcome::Noop { record });
    }
    let bumped = current.revision().as_u32().checked_add(1).ok_or_else(|| {
        SemanticsError::RevisionOverflow {
            current: current.revision().as_u32(),
            profile: profile.id().to_string(),
        }
    })?;
    let next = BindingSet {
        revision: BindingRevision::new(bumped),
        profile_id: record.profile_id().to_string(),
        input_digest: record.input_digest().to_string(),
        content_digest: record.content_digest().to_string(),
        bindings: conversion.bindings().to_vec(),
    };
    Ok(ApplyOutcome::Applied { record, next })
}
