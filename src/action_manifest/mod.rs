//! M02-PR10 frozen action/capability manifest, HARNESS-ONLY, read-only.
//!
//! A small frozen manifest for UI and later MCP control-state readers: the
//! synthetic profile (object/priority/units/range/tolerance/duration/
//! deadline/retries/rate/release), the harness-only scope (loopback
//! directed-unicast, no facility route), `denied-never-reaches-peer`,
//! `no-auto-enable` (gate success never enables uncommissioned devices),
//! and the mandatory-vs-optional reserves (`essential64:history1`).
//!
//! Read-only data only: no I/O, no locks, no network, no SQL, no mutation.
//! Canonical bytes are built from the owning product constants so profile
//! drift breaks the build; the gate test pins the same bytes as a hardcoded
//! literal decoded by an independent splitter, never encoder output.
#![allow(dead_code)]

use crate::action_journal::HISTORY_CAPACITY;
use crate::action_preview::{
    COMMISSIONED_PRIORITY, DEADLINE_SECS, DURATION_SECS, FEEDBACK_UNAVAILABLE, MASK_NOTE,
    MAX_PRIORITY, PREVIEW_FORMAT, PROTECTED_MAX, RANGE_MAX_C, RANGE_MIN_C, RATE_MAX_PER_HOUR,
    TIMEOUT_POLICY, TOLERANCE_C,
};
use crate::domain::scope::TrustedScope;
use crate::runtime::bacnet::APDU_RETRIES;
use crate::storage::StoreBounds;

/// Versioned manifest tag (policy data only; no wire).
pub const ACTION_MANIFEST_FORMAT: &str = "verdant-action-manifest-v1";
/// Harness-only synthetic scope; no facility route exists in this profile.
pub const SCOPE: &str = "scope-a";
/// Frozen synthetic equipment identity.
pub const EQUIPMENT: &str = "ahu-1";
/// Frozen object: Analog Value instance 2, `presentValue` property 85.
pub const OBJECT: &str = "av2:pv85";
/// Frozen commissioned priority tag.
pub const PRIORITY_TAG: &str = "p8";
/// Harness-only transport: loopback directed-unicast, never a facility route.
pub const TRANSPORT: &str = "loopback-directed-unicast";
/// Refused operations never reach the peer; captures stay empty.
pub const DENIAL: &str = "denied-never-reaches-peer";
/// Gate success never enables uncommissioned devices.
pub const ENABLEMENT: &str = "no-auto-enable";
/// Integration-only boundary: no conformance, calibrated physics, user
/// release, field authorization, or auto-enable claims.
pub const BOUNDARY: &str = "harness-only; loopback directed-unicast; no facility route; denied-never-reaches-peer; no-auto-enable; integration-only, no conformance/physics/field-authorization claims";
/// Exact pipe-separated field count of [`canonical_bytes`].
pub const FIELD_COUNT: usize = 21;

/// Mandatory-vs-optional reserves: essential journal capacity beside the
/// independent optional-history capacity. Built from the owning bounds so a
/// changed reserve breaks the literal instead of silently drifting.
pub fn reserves_note() -> String {
    format!(
        "essential{}:history{}",
        StoreBounds::tiny().max_tasks,
        HISTORY_CAPACITY
    )
}

/// Frozen canonical bytes, built only from owning product constants.
pub fn canonical_bytes() -> String {
    format!(
        "{ACTION_MANIFEST_FORMAT}|{SCOPE}|{EQUIPMENT}|{OBJECT}|{PRIORITY_TAG}|degC|{RANGE_MIN_C:.1}-{RANGE_MAX_C:.1}|tol{TOLERANCE_C:.1}|{DURATION_SECS}s|{DEADLINE_SECS}s|r{APDU_RETRIES}|rate{RATE_MAX_PER_HOUR}|{PREVIEW_FORMAT}|{MASK_NOTE}|{TRANSPORT}|{DENIAL}|{ENABLEMENT}|{}|null-relinquish|{FEEDBACK_UNAVAILABLE}|{TIMEOUT_POLICY}",
        reserves_note(),
    )
}

/// Typed manifest failure with a stable machine code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    Invalid(&'static str),
    FieldCount { expected: usize, found: usize },
    FieldMismatch { index: usize },
    Number { field: &'static str },
}

impl ManifestError {
    /// Stable machine-readable code asserted by tests.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "manifest-invalid",
            Self::FieldCount { .. } => "manifest-field-count",
            Self::FieldMismatch { .. } => "manifest-field-mismatch",
            Self::Number { .. } => "manifest-number",
        }
    }
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "action manifest invalid: {detail}"),
            Self::FieldCount { expected, found } => {
                write!(f, "action manifest fields {found} != {expected}")
            }
            Self::FieldMismatch { index } => {
                write!(f, "action manifest field {index} differs from frozen profile")
            }
            Self::Number { field } => write!(f, "action manifest number unparsable: {field}"),
        }
    }
}

impl std::error::Error for ManifestError {}

pub type Result<T> = std::result::Result<T, ManifestError>;

/// Validated harness scope: only the frozen `scope-a` is admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestScope(TrustedScope);

impl ManifestScope {
    pub fn parse(raw: &str) -> Result<Self> {
        let scope = TrustedScope::parse(raw).map_err(|_| ManifestError::Invalid("scope"))?;
        if scope.as_str() != SCOPE {
            return Err(ManifestError::Invalid("non-harness scope"));
        }
        Ok(Self(scope))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Validated commissioned priority: exactly the frozen supervisory slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestPriority(u8);

impl ManifestPriority {
    pub fn new(raw: u8) -> Result<Self> {
        if raw != COMMISSIONED_PRIORITY {
            return Err(ManifestError::Invalid("non-commissioned priority"));
        }
        Ok(Self(raw))
    }

    pub fn parse(tag: &str) -> Result<Self> {
        let raw = tag
            .strip_prefix('p')
            .and_then(|digits| digits.parse::<u8>().ok())
            .ok_or(ManifestError::Number { field: "priority" })?;
        Self::new(raw)
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

fn parse_suffixed(raw: &str, suffix: &str, field: &'static str) -> Result<u64> {
    raw.strip_suffix(suffix)
        .and_then(|digits| digits.parse::<u64>().ok())
        .ok_or(ManifestError::Number { field })
}

/// Decoded frozen manifest with typed numeric views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedManifest {
    scope: ManifestScope,
    priority: ManifestPriority,
    duration_secs: u64,
    deadline_secs: u64,
    retries: u8,
    rate_per_hour: u32,
}

impl DecodedManifest {
    pub fn scope(&self) -> &str {
        self.scope.as_str()
    }

    pub fn priority(&self) -> u8 {
        self.priority.get()
    }

    pub fn duration_secs(&self) -> u64 {
        self.duration_secs
    }

    pub fn deadline_secs(&self) -> u64 {
        self.deadline_secs
    }

    pub fn retries(&self) -> u8 {
        self.retries
    }

    pub fn rate_per_hour(&self) -> u32 {
        self.rate_per_hour
    }
}

/// Decode and validate frozen canonical bytes. Field order and literals must
/// match [`canonical_bytes`] exactly; protected priorities, wider ranges, or
/// facility scopes refuse instead of widening.
pub fn decode(raw: &str) -> Result<DecodedManifest> {
    let fields: Vec<&str> = raw.split('|').collect();
    if fields.len() != FIELD_COUNT {
        return Err(ManifestError::FieldCount {
            expected: FIELD_COUNT,
            found: fields.len(),
        });
    }
    let expected = canonical_bytes();
    let want: Vec<&str> = expected.split('|').collect();
    for (index, (got, want)) in fields.iter().zip(want.iter()).enumerate() {
        if got != want {
            return Err(ManifestError::FieldMismatch { index });
        }
    }
    let scope = ManifestScope::parse(fields[1])?;
    if fields[2] != EQUIPMENT {
        return Err(ManifestError::FieldMismatch { index: 2 });
    }
    let priority = ManifestPriority::parse(fields[4])?;
    if priority.get() <= PROTECTED_MAX || priority.get() > MAX_PRIORITY {
        return Err(ManifestError::Invalid("priority outside commissioned slot"));
    }
    let duration_secs = parse_suffixed(fields[8], "s", "duration")?;
    if duration_secs != DURATION_SECS {
        return Err(ManifestError::FieldMismatch { index: 8 });
    }
    let deadline_secs = parse_suffixed(fields[9], "s", "deadline")?;
    if deadline_secs != DEADLINE_SECS {
        return Err(ManifestError::FieldMismatch { index: 9 });
    }
    let retries = fields[10]
        .strip_prefix('r')
        .and_then(|digits| digits.parse::<u8>().ok())
        .ok_or(ManifestError::Number { field: "retries" })?;
    if retries != APDU_RETRIES {
        return Err(ManifestError::FieldMismatch { index: 10 });
    }
    let rate_per_hour = fields[11]
        .strip_prefix("rate")
        .and_then(|digits| digits.parse::<u32>().ok())
        .ok_or(ManifestError::Number { field: "rate" })?;
    if rate_per_hour != RATE_MAX_PER_HOUR {
        return Err(ManifestError::FieldMismatch { index: 11 });
    }
    Ok(DecodedManifest {
        scope,
        priority,
        duration_secs,
        deadline_secs,
        retries,
        rate_per_hour,
    })
}

/// Synthetic planning budget: at most this many actions per day. Checked
/// arithmetic refuses overflow instead of wrapping; a planning reserve, not
/// a host-global quota.
pub fn max_actions_per_day() -> Result<u32> {
    RATE_MAX_PER_HOUR
        .checked_mul(24)
        .ok_or(ManifestError::Invalid("rate overflow"))
}

/// Intent lifetime in milliseconds. Checked arithmetic, never wrapping.
pub fn duration_ms() -> Result<u64> {
    DURATION_SECS
        .checked_mul(1000)
        .ok_or(ManifestError::Invalid("duration overflow"))
}
