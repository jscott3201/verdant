//! M01-PR04 named capability ceilings and direct-entry access.
//!
//! Synthetic bootstrap, scope-limited ceiling-bound issuance, rotation and
//! revocation with reason, and fail-closed direct entry. Std-only, zero
//! dependencies (D02 freeze holds: no new crates; SQLite is driven through the
//! PR03 [`crate::storage`] envelope over the system `sqlite3` CLI).
//!
//! ## Synthetic actors only (D04 local-only)
//!
//! One synthetic user (`synthetic-operator-1`) with two named capabilities
//! (`reviewer-1`, `publisher-1`). Both capabilities carry the same display
//! label (`synthetic`) to prove labels are not identity: equal labels, distinct
//! [`CapabilityName`] identities, distinct privileges. Labels travel as text and
//! never grant entry; only the named ceiling/key does.
//!
//! Static separation is least-privilege: a reviewer credential reviews but
//! cannot publish (typed `role-denied` / `ceiling-exceeded`); a publisher
//! credential publishes (and may review). Every enter path (`enter_review`,
//! `enter_publish`) checks the named ceiling/key, scope, role, issuer and
//! revocation; there is no unchecked path. Anonymous (`None`) credential and
//! any remote listener bind are refused loudly (`anonymous-denied`,
//! `listener-refused`) with an `eprintln!` log carrying the refusal code.
//!
//! ## Admission records live in 0001 tables (no 0002 migration)
//!
//! Migration decision: `0002` is NOT created. Admission, rotation and
//! revocation records live in the PR03 0001 `outbox` table as additive rows
//! with reserved operations (`access-bootstrap`, `access-issue`,
//! `access-revoke`), a fixed unit (`access-event`), the shared synthetic
//! sensor (`sensor-sat-1`), and a `Value::Text` descriptor (`v=1;kind=...`
//! with percent-encoding for `%;=` and control bytes). This preserves the
//! PR03 reservation test (exactly one numbered migration), keeps
//! `SCHEMA_GENERATION == 1` for every statement, and needs no storage
//! semantics change. A future slice that outgrows the outbox (for example,
//! horizon-bounded replay past `max_replay_rows`) must reserve `0002` through
//! the integration owner; applied migrations are never rewritten.
//!
//! Change record (integration §2 style):
//!
//! ```text
//! backend + owner .....: sqlite / M01-PR04 (access admission log)
//! predecessors ........: 0001_init (consumed, not forked; no new migration)
//! fresh-install .......: PR03 0001 apply + user_version = 1, then first-run
//!                         access bootstrap (refused when rows already exist)
//! supported upgrade ...: none in this slice (generation stays 0001)
//! queued-msg compat ...: access rows are additive outbox rows; duplicates
//!                         tolerated + counted, never merged (same as PR03)
//! lock / space needs ..: same envelope as PR03 (WAL + FULL-sync + 5 s busy
//!                         timeout, bounded retries); temp DBs in OS temp dirs
//! interruption outcome : uncommitted inserts never survive; partial bootstrap
//!                         leaves visible rows and requires operator reset
//!                         (delete the synthetic DB); re-bootstrap never
//!                         silently overwrites (typed already-bootstrapped)
//! read / write policy .: every admission read/write runs inside the verified
//!                         PR03 envelope (generation + durability re-read
//!                         in-band); unknown generation refused, never skipped
//! rollback boundary ...: no schema change; data rollback is explicit per-row
//!                         (revocation is a new recorded statement, not a
//!                         delete); applied migrations never rewritten
//! ```
//!
//! ## Offline-notary revocation
//!
//! Revocation is a recorded statement (`access-revoke` row with capability +
//! key + generation + reason + issuer) verifiable by reading the database file
//! through [`AccessGate::is_revoked`] without any live server or listener.
//! Revoked credentials fail closed on all enter paths. Rotation records a
//! revoke for the old key plus an issue for the new key (bumped generation)
//! under one reason; the old key then fails as revoked/stale.
//!
//! ## Secrets (synthetic only)
//!
//! Key material ([`SyntheticKey`]) is opaque, redacted in every `Debug`
//! rendering (length-only), best-effort zeroized on drop, and never written to
//! the store: only the FNV-1a fingerprint (synthetic-only, not a cryptographic
//! claim) is recorded. No recovery flow exists: losing a key leaves no API to
//! retrieve it. Tests use `synthetic-` prefixed fixtures only.
//!
//! ## Sealed paths
//!
//! Access flows take only the database path. Sealed config/artifact paths are
//! never opened for writing through any access path; tests assert a sealed
//! fixture is byte-identical before and after all flows.
//!
//! ## PR07 handoff
//!
//! The PR07 binding consumes: [`AccessGate::enter_review`] and
//! [`AccessGate::enter_publish`] as the capability-check entry points (named
//! ceiling/key + scope + role + revocation, all fail-closed), ceiling
//! semantics (`REQUIRED_REVIEW_CEILING` / `REQUIRED_PUBLISH_CEILING` against
//! the issued [`CredentialCeiling`] level), and
//! [`AccessGate::is_revoked`] as the offline revocation-verification path
//! (file reads only, no server).

use crate::domain::clock::{TimeTriple, UnixMillis};
use crate::domain::ids::{InstalledId, OperationId, SourceGenerationId};
use crate::domain::outcomes::RecordIdentity;
use crate::domain::scope::{CredentialCeiling, TrustedScope, MAX_CEILING_LEVEL};
use crate::domain::values::{Unit, Value};
use crate::storage::sqlite::SqliteStore;
use crate::storage::{ConnectionSettings, StorageError, StoreBounds, SCHEMA_GENERATION};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Access schema generation: bound to the PR03 0001 baseline, always 1 here.
pub const ACCESS_SCHEMA_GENERATION: u32 = 1;
/// Trusted synthetic bootstrap issuer (frozen example).
pub const BOOTSTRAP_ISSUER_TEXT: &str = "bootstrap-issuer-1";
/// Single synthetic user (frozen example; labels are not identity).
pub const SYNTHETIC_USER_TEXT: &str = "synthetic-operator-1";
/// Frozen synthetic reviewer capability name.
pub const REVIEWER_CAP_TEXT: &str = "reviewer-1";
/// Frozen synthetic publisher capability name.
pub const PUBLISHER_CAP_TEXT: &str = "publisher-1";
/// Frozen reviewer key id (gen 1).
pub const REVIEWER_KEY_TEXT: &str = "key-reviewer-1";
/// Frozen publisher key id (gen 1).
pub const PUBLISHER_KEY_TEXT: &str = "key-publisher-1";
/// Duplicate display label shared by both bootstrap capabilities.
pub const SYNTHETIC_LABEL_TEXT: &str = "synthetic";
/// Shared synthetic sensor for all admission rows (fixture sensor).
pub const SYNTHETIC_SENSOR_TEXT: &str = "sensor-sat-1";
/// Fixed unit tag for all admission rows (safe: no envelope poison bytes).
pub const ACCESS_UNIT_TEXT: &str = "access-event";
/// Reserved outbox operation for the bootstrap marker.
pub const OP_BOOTSTRAP_TEXT: &str = "access-bootstrap";
/// Reserved outbox operation for issuance rows (bootstrap + later + rotate).
pub const OP_ISSUE_TEXT: &str = "access-issue";
/// Reserved outbox operation for revocation rows (explicit + rotate).
pub const OP_REVOKE_TEXT: &str = "access-revoke";
/// Maximum reason length in bytes (all reason chars are ASCII-encodable).
pub const MAX_REASON_LEN: usize = 256;
/// Maximum display-label length in bytes.
pub const MAX_LABEL_LEN: usize = 128;
/// Maximum synthetic key length in bytes.
pub const MAX_KEY_LEN: usize = 256;
/// Ceiling required to review.
pub const REQUIRED_REVIEW_CEILING: u8 = 1;
/// Ceiling required to publish.
pub const REQUIRED_PUBLISH_CEILING: u8 = 2;

static BOOTSTRAP_SEQ: AtomicU64 = AtomicU64::new(0);

fn validate_token_text(kind: &'static str, raw: &str) -> Result<(), AccessError> {
    if raw.is_empty() {
        return Err(AccessError::InvalidInput {
            what: kind,
            detail: "value must not be empty".to_string(),
        });
    }
    if raw.len() > 128 {
        return Err(AccessError::InvalidInput {
            what: kind,
            detail: format!("value is {} chars; maximum is 128", raw.len()),
        });
    }
    let ok = raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
    if !ok {
        return Err(AccessError::InvalidInput {
            what: kind,
            detail: format!("value has unsupported characters: '{raw}'"),
        });
    }
    Ok(())
}

macro_rules! define_access_id {
    ($name:ident, $kind:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Validated construction from the canonical text form.
            pub fn parse(raw: &str) -> Result<Self, AccessError> {
                validate_token_text($kind, raw)?;
                Ok(Self(raw.to_string()))
            }

            /// Borrow the canonical text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

define_access_id!(
    CapabilityName,
    "capability-name",
    "Named capability identity (e.g. `reviewer-1`). Distinct from labels: equal labels never alias names."
);
define_access_id!(
    KeyId,
    "key-id",
    "Synthetic key identity (e.g. `key-reviewer-1`). The raw key never leaves the caller; only the fingerprint is recorded."
);
define_access_id!(
    UserId,
    "user-id",
    "Single synthetic user identity (e.g. `synthetic-operator-1`)."
);
define_access_id!(
    IssuerId,
    "issuer-id",
    "Synthetic mint issuer (only `bootstrap-issuer-1` is trusted)."
);

/// Validated reason text (non-empty, bounded, synthetic only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason(String);

impl Reason {
    /// Validate caller text into a recorded reason.
    pub fn parse(raw: &str) -> Result<Reason, AccessError> {
        if raw.is_empty() {
            return Err(AccessError::InvalidInput {
                what: "reason",
                detail: "reason must not be empty".to_string(),
            });
        }
        if raw.len() > MAX_REASON_LEN {
            return Err(AccessError::InvalidInput {
                what: "reason",
                detail: format!("reason is {} chars; maximum is {MAX_REASON_LEN}", raw.len()),
            });
        }
        if raw.contains('\0') {
            return Err(AccessError::InvalidInput {
                what: "reason",
                detail: "reason must not contain NUL".to_string(),
            });
        }
        Ok(Reason(raw.to_string()))
    }

    /// Borrow the reason text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Display label: explicitly NOT identity. Duplicates are expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayLabel(String);

impl DisplayLabel {
    /// Validate caller text into a display label (duplicates allowed).
    pub fn parse(raw: &str) -> Result<DisplayLabel, AccessError> {
        if raw.is_empty() {
            return Err(AccessError::InvalidInput {
                what: "label",
                detail: "label must not be empty".to_string(),
            });
        }
        if raw.len() > MAX_LABEL_LEN {
            return Err(AccessError::InvalidInput {
                what: "label",
                detail: format!("label is {} chars; maximum is {MAX_LABEL_LEN}", raw.len()),
            });
        }
        if raw.contains('\0') {
            return Err(AccessError::InvalidInput {
                what: "label",
                detail: "label must not contain NUL".to_string(),
            });
        }
        Ok(DisplayLabel(raw.to_string()))
    }

    /// Borrow the label text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Synthetic least-privilege roles. Exhaustive so new roles break the build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleKind {
    Reviewer,
    Publisher,
}

impl RoleKind {
    /// Parse `reviewer` / `publisher` (exact, case-sensitive).
    pub fn parse(raw: &str) -> Result<RoleKind, AccessError> {
        match raw {
            "reviewer" => Ok(RoleKind::Reviewer),
            "publisher" => Ok(RoleKind::Publisher),
            _ => Err(AccessError::InvalidInput {
                what: "role",
                detail: format!("unknown role '{raw}'; expected reviewer/publisher"),
            }),
        }
    }

    /// Canonical role text.
    pub fn as_str(self) -> &'static str {
        match self {
            RoleKind::Reviewer => "reviewer",
            RoleKind::Publisher => "publisher",
        }
    }
}

/// Opaque synthetic key. Redacted in `Debug`, zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct SyntheticKey(String);

impl SyntheticKey {
    /// Validate synthetic key material (`synthetic-` prefix, bounded).
    pub fn parse(raw: &str) -> Result<SyntheticKey, AccessError> {
        if raw.is_empty() {
            return Err(AccessError::InvalidInput {
                what: "key",
                detail: "key must not be empty".to_string(),
            });
        }
        if raw.len() > MAX_KEY_LEN {
            return Err(AccessError::InvalidInput {
                what: "key",
                detail: format!("key is {} chars; maximum is {MAX_KEY_LEN}", raw.len()),
            });
        }
        if !raw.starts_with("synthetic-") {
            return Err(AccessError::InvalidInput {
                what: "key",
                detail: "only synthetic test keys (prefix `synthetic-`) are accepted".to_string(),
            });
        }
        Ok(SyntheticKey(raw.to_string()))
    }

    /// Length-only accessor for logs (value never logged).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when empty (never true for parsed keys; used by tests).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Synthetic-only fingerprint (FNV-1a 64, hex). This is the value
    /// recorded in the store; the raw key is never stored.
    pub fn fingerprint(&self) -> String {
        fingerprint_str(&self.0)
    }
}

impl fmt::Debug for SyntheticKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SyntheticKey(<redacted, {} chars>)", self.0.len())
    }
}

impl Drop for SyntheticKey {
    fn drop(&mut self) {
        unsafe {
            let bytes = self.0.as_bytes_mut();
            for b in bytes.iter_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

/// Presented credential: named capability + key identity + secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    capability: CapabilityName,
    key_id: KeyId,
    key: SyntheticKey,
}

impl Credential {
    /// Bundle already-validated parts (no re-validation; parts carry it).
    pub fn new(capability: CapabilityName, key_id: KeyId, key: SyntheticKey) -> Credential {
        Credential {
            capability,
            key_id,
            key,
        }
    }

    /// Borrow the capability name.
    pub fn capability(&self) -> &CapabilityName {
        &self.capability
    }

    /// Borrow the key id.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Borrow the secret (callers must not log it).
    pub fn key(&self) -> &SyntheticKey {
        &self.key
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Credential(capability={}, key_id={}, key=<redacted, {} chars>)",
            self.capability.as_str(),
            self.key_id.as_str(),
            self.key.len()
        )
    }
}

/// Successful entry report (no secret material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterReport {
    /// Capability that entered.
    pub capability: String,
    /// Scope the entry was granted in.
    pub scope: String,
    /// Issued ceiling level.
    pub ceiling: u8,
    /// Issued role.
    pub role: String,
    /// Capability generation at entry.
    pub cap_generation: u32,
}

/// Bootstrap credentials (raw keys are returned once; there is no recovery).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapCredentials {
    /// Reviewer credential (scope-a, ceiling 1).
    pub reviewer: Credential,
    /// Publisher credential (scope-a, ceiling 2).
    pub publisher: Credential,
}

/// Typed access failure with stable machine codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessError {
    /// Re-bootstrap after established state (never silent overwrite).
    AlreadyBootstrapped { detail: String },
    /// Entry before any bootstrap.
    NotBootstrapped { detail: String },
    /// Capability name has no issuance record.
    UnknownCapability { capability: String },
    /// Issuer is not the trusted bootstrap issuer.
    UnknownIssuer { issuer: String },
    /// Key id unknown for the capability or fingerprint mismatch.
    ForgedCredential { detail: String },
    /// Requested scope differs from the issued scope.
    ScopeDenied { expected: String, presented: String },
    /// Issued ceiling below the operation requirement.
    CeilingExceeded { have: u8, required: u8 },
    /// Issued role below the operation requirement.
    RoleDenied { have: String, required: String },
    /// Key is revoked (fail closed on all paths).
    RevokedCredential { capability: String, key: String },
    /// Presented generation is not the latest for the capability.
    StaleGeneration {
        capability: String,
        presented: u32,
        current: u32,
    },
    /// Anonymous (missing credential) entry attempt.
    AnonymousDenied { detail: String },
    /// Remote listener bind requested (local-only per D04).
    ListenerRefused { detail: String },
    /// Caller argument failed access-level validation.
    InvalidInput { what: &'static str, detail: String },
    /// A stored admission row failed to decode (fail closed).
    InvalidRecord { detail: String },
    /// Wrapped PR03 storage failure (code preserved).
    Store(StorageError),
}

impl AccessError {
    /// Stable machine-readable code for tests and evidence mapping.
    pub fn code(&self) -> &'static str {
        match self {
            AccessError::AlreadyBootstrapped { .. } => "already-bootstrapped",
            AccessError::NotBootstrapped { .. } => "not-bootstrapped",
            AccessError::UnknownCapability { .. } => "unknown-capability",
            AccessError::UnknownIssuer { .. } => "unknown-issuer",
            AccessError::ForgedCredential { .. } => "forged-credential",
            AccessError::ScopeDenied { .. } => "scope-denied",
            AccessError::CeilingExceeded { .. } => "ceiling-exceeded",
            AccessError::RoleDenied { .. } => "role-denied",
            AccessError::RevokedCredential { .. } => "revoked-credential",
            AccessError::StaleGeneration { .. } => "stale-generation",
            AccessError::AnonymousDenied { .. } => "anonymous-denied",
            AccessError::ListenerRefused { .. } => "listener-refused",
            AccessError::InvalidInput { .. } => "invalid-input",
            AccessError::InvalidRecord { .. } => "invalid-record",
            AccessError::Store(inner) => inner.code(),
        }
    }
}

impl fmt::Display for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessError::AlreadyBootstrapped { detail } => {
                write!(f, "already bootstrapped: {detail}")
            }
            AccessError::NotBootstrapped { detail } => {
                write!(f, "not bootstrapped: {detail}")
            }
            AccessError::UnknownCapability { capability } => {
                write!(f, "unknown capability '{capability}'")
            }
            AccessError::UnknownIssuer { issuer } => {
                write!(f, "unknown issuer '{issuer}'")
            }
            AccessError::ForgedCredential { detail } => {
                write!(f, "forged credential: {detail}")
            }
            AccessError::ScopeDenied {
                expected,
                presented,
            } => write!(
                f,
                "scope denied: issued for '{expected}', presented '{presented}'"
            ),
            AccessError::CeilingExceeded { have, required } => write!(
                f,
                "ceiling exceeded: issued level {have}, operation requires {required}"
            ),
            AccessError::RoleDenied { have, required } => write!(
                f,
                "role denied: issued '{have}', operation requires '{required}'"
            ),
            AccessError::RevokedCredential { capability, key } => write!(
                f,
                "revoked credential: capability '{capability}' key '{key}' is revoked"
            ),
            AccessError::StaleGeneration {
                capability,
                presented,
                current,
            } => write!(
                f,
                "stale generation: capability '{capability}' presented gen {presented}, current gen {current}"
            ),
            AccessError::AnonymousDenied { detail } => {
                write!(f, "anonymous denied: {detail}")
            }
            AccessError::ListenerRefused { detail } => {
                write!(f, "remote listener refused: {detail}")
            }
            AccessError::InvalidInput { what, detail } => {
                write!(f, "invalid {what}: {detail}")
            }
            AccessError::InvalidRecord { detail } => {
                write!(f, "invalid admission record: {detail}")
            }
            AccessError::Store(inner) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for AccessError {}

/// Refuse any remote listener bind (local-only per D04). `None` (omitted
/// setting) starts no listener and is allowed; `Some(addr)` is a loud refusal.
pub fn refuse_remote_listener(bind: Option<&str>) -> Result<(), AccessError> {
    match bind {
        None => Ok(()),
        Some(addr) => {
            eprintln!(
                "verdant refuses remote listener '{addr}' [listener-refused] (local-only; no anonymous remote listener per D04)"
            );
            Err(AccessError::ListenerRefused {
                detail: format!("remote listener '{addr}' is not supported (local-only)"),
            })
        }
    }
}

fn fingerprint_str(raw: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in raw.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn pct_encode(raw: &str) -> String {
    // Byte-oriented so multi-byte UTF-8 round-trips exactly: ASCII
    // specials are escaped, printable ASCII passes through, and every
    // other byte (non-ASCII UTF-8 bytes, controls, DEL) is %XX-encoded.
    // The encoded form is therefore ASCII-only.
    let mut out = String::with_capacity(raw.len());
    for &b in raw.as_bytes() {
        match b {
            b'%' => out.push_str("%25"),
            b';' => out.push_str("%3B"),
            b'=' => out.push_str("%3D"),
            b'\n' => out.push_str("%0A"),
            b'\r' => out.push_str("%0D"),
            0x1F => out.push_str("%1F"),
            0x20..=0x7E => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn pct_decode(raw: &str) -> Result<String, AccessError> {
    // Byte-oriented inverse of pct_encode: collect decoded bytes first so
    // multi-byte UTF-8 sequences reassemble exactly, then validate UTF-8
    // fail-closed (stored-row corruption never yields mojibake). Byte
    // slicing avoids panics on crafted inputs that split UTF-8 boundaries.
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(AccessError::InvalidRecord {
                    detail: format!("truncated percent escape in '{raw}'"),
                });
            }
            let hex_bytes = &bytes[i + 1..i + 3];
            let hex = std::str::from_utf8(hex_bytes).map_err(|_| AccessError::InvalidRecord {
                detail: format!("invalid percent escape in '{raw}'"),
            })?;
            let byte = u8::from_str_radix(hex, 16).map_err(|_| AccessError::InvalidRecord {
                detail: format!("invalid percent escape '%{hex}' in '{raw}'"),
            })?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| AccessError::InvalidRecord {
        detail: format!("admission field is not valid UTF-8 in '{raw}'"),
    })
}

fn synthetic_times() -> TimeTriple {
    // Frozen synthetic triple (same shape as storage tests); an invalid
    // constant is an internal programming error, never caller input.
    TimeTriple::new(
        UnixMillis::new(1_700_000_000_123),
        UnixMillis::new(1_700_000_000_456),
        UnixMillis::new(1_700_000_000_789),
    )
    .expect("frozen synthetic times are ordered")
}

fn synthetic_record(seq: u64) -> RecordIdentity {
    // Frozen source generation for admission ordering; not the capability
    // generation (which lives inside the descriptor as capgen).
    RecordIdentity::new(
        SourceGenerationId::parse("gen-1").expect("frozen admission generation is valid"),
        seq,
    )
}

fn frozen_issuer() -> IssuerId {
    IssuerId::parse(BOOTSTRAP_ISSUER_TEXT).expect("frozen bootstrap issuer is valid")
}

fn frozen_user() -> UserId {
    UserId::parse(SYNTHETIC_USER_TEXT).expect("frozen synthetic user is valid")
}

fn frozen_sensor() -> InstalledId {
    InstalledId::parse(SYNTHETIC_SENSOR_TEXT).expect("frozen synthetic sensor is valid")
}

fn access_unit() -> Unit {
    Unit::parse(ACCESS_UNIT_TEXT).expect("frozen access unit is valid")
}

fn unquote_column(raw: &str) -> Result<Option<String>, AccessError> {
    if raw == "NULL" {
        return Ok(None);
    }
    let inner = raw
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .ok_or_else(|| AccessError::InvalidRecord {
            detail: format!("quoted admission column malformed: '{raw}'"),
        })?;
    Ok(Some(inner.replace("''", "'")))
}

fn sql_quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('\'');
    for ch in raw.chars() {
        if ch == '\'' {
            out.push_str("''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IssueRow {
    cap: String,
    scope: String,
    ceiling: u8,
    role: String,
    key_id: String,
    key_fp: String,
    issuer: String,
    capgen: u32,
    user: String,
    reason: String,
    label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RevokeRow {
    cap: String,
    key_id: String,
    capgen: u32,
    issuer: String,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootstrapRow {
    user: String,
    issuer: String,
    reason: String,
    generation: u32,
}

fn encode_issue(row: &IssueRow) -> String {
    format!(
        "v=1;kind=issue;cap={};scope={};ceiling={};role={};key={};keyfp={};issuer={};capgen={};user={};reason={};label={}",
        pct_encode(&row.cap),
        pct_encode(&row.scope),
        row.ceiling,
        pct_encode(&row.role),
        pct_encode(&row.key_id),
        pct_encode(&row.key_fp),
        pct_encode(&row.issuer),
        row.capgen,
        pct_encode(&row.user),
        pct_encode(&row.reason),
        pct_encode(&row.label),
    )
}

fn encode_revoke(row: &RevokeRow) -> String {
    format!(
        "v=1;kind=revoke;cap={};key={};capgen={};issuer={};reason={}",
        pct_encode(&row.cap),
        pct_encode(&row.key_id),
        row.capgen,
        pct_encode(&row.issuer),
        pct_encode(&row.reason),
    )
}

fn encode_bootstrap(row: &BootstrapRow) -> String {
    format!(
        "v=1;kind=bootstrap;user={};issuer={};reason={};generation={}",
        pct_encode(&row.user),
        pct_encode(&row.issuer),
        pct_encode(&row.reason),
        row.generation,
    )
}

fn split_descriptor(raw: &str) -> Result<BTreeMap<String, String>, AccessError> {
    let mut map = BTreeMap::new();
    for part in raw.split(';') {
        let eq = part.find('=').ok_or_else(|| AccessError::InvalidRecord {
            detail: format!("admission descriptor part without '=': '{part}'"),
        })?;
        let key = part[..eq].to_string();
        let encoded = &part[eq + 1..];
        if key.is_empty() {
            return Err(AccessError::InvalidRecord {
                detail: "admission descriptor has an empty key".to_string(),
            });
        }
        if map.insert(key.clone(), pct_decode(encoded)?).is_some() {
            return Err(AccessError::InvalidRecord {
                detail: format!("admission descriptor duplicates key '{key}'"),
            });
        }
    }
    Ok(map)
}

fn require_field(map: &BTreeMap<String, String>, key: &'static str) -> Result<String, AccessError> {
    map.get(key)
        .cloned()
        .ok_or_else(|| AccessError::InvalidRecord {
            detail: format!("admission descriptor missing field '{key}'"),
        })
}

fn reject_unknown_fields(
    map: &BTreeMap<String, String>,
    allowed: &[&str],
) -> Result<(), AccessError> {
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(AccessError::InvalidRecord {
                detail: format!("admission descriptor has unexpected field '{key}'"),
            });
        }
    }
    Ok(())
}

fn decode_descriptor(raw: &str) -> Result<(String, BTreeMap<String, String>), AccessError> {
    let map = split_descriptor(raw)?;
    let version = require_field(&map, "v")?;
    if version != "1" {
        return Err(AccessError::InvalidRecord {
            detail: format!("unsupported admission descriptor version '{version}'"),
        });
    }
    let kind = require_field(&map, "kind")?;
    match kind.as_str() {
        "bootstrap" => {
            reject_unknown_fields(
                &map,
                &["v", "kind", "user", "issuer", "reason", "generation"],
            )?;
        }
        "issue" => {
            reject_unknown_fields(
                &map,
                &[
                    "v", "kind", "cap", "scope", "ceiling", "role", "key", "keyfp", "issuer",
                    "capgen", "user", "reason", "label",
                ],
            )?;
        }
        "revoke" => {
            reject_unknown_fields(
                &map,
                &["v", "kind", "cap", "key", "capgen", "issuer", "reason"],
            )?;
        }
        _ => {
            return Err(AccessError::InvalidRecord {
                detail: format!("unknown admission kind '{kind}'"),
            })
        }
    }
    Ok((kind, map))
}

fn decode_issue(map: &BTreeMap<String, String>) -> Result<IssueRow, AccessError> {
    let bad = |detail: String| AccessError::InvalidRecord { detail };
    let cap = require_field(map, "cap")?;
    let scope = require_field(map, "scope")?;
    let ceiling_raw = require_field(map, "ceiling")?;
    let ceiling: u8 = ceiling_raw
        .parse::<u8>()
        .map_err(|_| bad(format!("issue ceiling unreadable: '{ceiling_raw}'")))?;
    if ceiling > MAX_CEILING_LEVEL {
        return Err(bad(format!(
            "issue ceiling {ceiling} exceeds max {MAX_CEILING_LEVEL}"
        )));
    }
    // Validate scope/role text through the domain constructors so corrupt
    // rows fail closed with the same alphabet rules as issuance.
    TrustedScope::parse(&scope)
        .map_err(|e| bad(format!("issue scope invalid: {e} [{}]", e.code())))?;
    let role = require_field(map, "role")?;
    RoleKind::parse(&role).map_err(|e| bad(format!("issue role invalid: {e}")))?;
    let key_id = require_field(map, "key")?;
    validate_token_text("key-id", &key_id).map_err(|e| bad(format!("issue key id: {e}")))?;
    CapabilityName::parse(&cap).map_err(|e| bad(format!("issue capability: {e}")))?;
    let key_fp = require_field(map, "keyfp")?;
    if key_fp.is_empty() || key_fp.len() > 64 {
        return Err(bad(
            "issue key fingerprint has an unexpected shape".to_string()
        ));
    }
    let issuer = require_field(map, "issuer")?;
    IssuerId::parse(&issuer).map_err(|e| bad(format!("issue issuer: {e}")))?;
    let capgen_raw = require_field(map, "capgen")?;
    let capgen: u32 = capgen_raw
        .parse::<u32>()
        .map_err(|_| bad(format!("issue capgen unreadable: '{capgen_raw}'")))?;
    if capgen == 0 {
        return Err(bad("issue capgen must be at least 1".to_string()));
    }
    let user = require_field(map, "user")?;
    UserId::parse(&user).map_err(|e| bad(format!("issue user: {e}")))?;
    let reason = require_field(map, "reason")?;
    if reason.is_empty() {
        return Err(bad("issue reason must not be empty".to_string()));
    }
    let label = require_field(map, "label")?;
    if label.is_empty() {
        return Err(bad("issue label must not be empty".to_string()));
    }
    Ok(IssueRow {
        cap,
        scope,
        ceiling,
        role,
        key_id,
        key_fp,
        issuer,
        capgen,
        user,
        reason,
        label,
    })
}

fn decode_revoke(map: &BTreeMap<String, String>) -> Result<RevokeRow, AccessError> {
    let bad = |detail: String| AccessError::InvalidRecord { detail };
    let cap = require_field(map, "cap")?;
    CapabilityName::parse(&cap).map_err(|e| bad(format!("revoke capability: {e}")))?;
    let key_id = require_field(map, "key")?;
    validate_token_text("key-id", &key_id).map_err(|e| bad(format!("revoke key id: {e}")))?;
    let capgen_raw = require_field(map, "capgen")?;
    let capgen: u32 = capgen_raw
        .parse::<u32>()
        .map_err(|_| bad(format!("revoke capgen unreadable: '{capgen_raw}'")))?;
    if capgen == 0 {
        return Err(bad("revoke capgen must be at least 1".to_string()));
    }
    let issuer = require_field(map, "issuer")?;
    IssuerId::parse(&issuer).map_err(|e| bad(format!("revoke issuer: {e}")))?;
    let reason = require_field(map, "reason")?;
    if reason.is_empty() {
        return Err(bad("revoke reason must not be empty".to_string()));
    }
    Ok(RevokeRow {
        cap,
        key_id,
        capgen,
        issuer,
        reason,
    })
}

fn decode_bootstrap(map: &BTreeMap<String, String>) -> Result<BootstrapRow, AccessError> {
    let bad = |detail: String| AccessError::InvalidRecord { detail };
    let user = require_field(map, "user")?;
    UserId::parse(&user).map_err(|e| bad(format!("bootstrap user: {e}")))?;
    let issuer = require_field(map, "issuer")?;
    IssuerId::parse(&issuer).map_err(|e| bad(format!("bootstrap issuer: {e}")))?;
    let reason = require_field(map, "reason")?;
    if reason.is_empty() {
        return Err(bad("bootstrap reason must not be empty".to_string()));
    }
    let gen_raw = require_field(map, "generation")?;
    let generation: u32 = gen_raw
        .parse::<u32>()
        .map_err(|_| bad(format!("bootstrap generation unreadable: '{gen_raw}'")))?;
    if generation != ACCESS_SCHEMA_GENERATION {
        return Err(bad(format!(
            "bootstrap generation {generation} is not {ACCESS_SCHEMA_GENERATION}"
        )));
    }
    Ok(BootstrapRow {
        user,
        issuer,
        reason,
        generation,
    })
}

/// Direct-entry gate: the PR07 binding entry point for capability checks.
#[derive(Debug)]
pub struct AccessGate {
    store: SqliteStore,
    issuer: IssuerId,
    user: UserId,
    next_seq: AtomicU64,
}

impl AccessGate {
    /// First-run synthetic bootstrap: mints reviewer + publisher for the
    /// single synthetic user, recorded with `reason`. Refuses when any
    /// admission row already exists (typed, never silent overwrite).
    pub fn bootstrap(
        db_path: &Path,
        settings: ConnectionSettings,
        bounds: StoreBounds,
        reason: &Reason,
    ) -> Result<(AccessGate, BootstrapCredentials), AccessError> {
        assert_schema_generation();
        let (store, _) =
            SqliteStore::open(db_path, settings, bounds).map_err(AccessError::Store)?;
        if access_row_count(&store)? > 0 {
            return Err(AccessError::AlreadyBootstrapped {
                detail: "admission records already exist; re-bootstrap is refused".to_string(),
            });
        }
        let issuer = frozen_issuer();
        let user = frozen_user();
        let mut seq = access_row_count(&store)?.saturating_add(1).max(1);

        let marker = BootstrapRow {
            user: user.as_str().to_string(),
            issuer: issuer.as_str().to_string(),
            reason: reason.as_str().to_string(),
            generation: ACCESS_SCHEMA_GENERATION,
        };
        insert_admission(
            &store,
            OP_BOOTSTRAP_TEXT,
            &marker_reason_entity(&user),
            &encode_bootstrap(&marker),
            seq,
        )?;
        seq += 1;

        let uniq = BOOTSTRAP_SEQ.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let reviewer_key_raw = format!("synthetic-bootstrap-{pid}-{uniq}-reviewer-1");
        let publisher_key_raw = format!("synthetic-bootstrap-{pid}-{uniq}-publisher-1");
        let reviewer_key =
            SyntheticKey::parse(&reviewer_key_raw).map_err(|e| AccessError::InvalidRecord {
                detail: format!("frozen bootstrap reviewer key invalid: {e}"),
            })?;
        let publisher_key =
            SyntheticKey::parse(&publisher_key_raw).map_err(|e| AccessError::InvalidRecord {
                detail: format!("frozen bootstrap publisher key invalid: {e}"),
            })?;
        let reviewer_cap =
            CapabilityName::parse(REVIEWER_CAP_TEXT).expect("frozen reviewer name is valid");
        let publisher_cap =
            CapabilityName::parse(PUBLISHER_CAP_TEXT).expect("frozen publisher name is valid");
        let reviewer_key_id =
            KeyId::parse(REVIEWER_KEY_TEXT).expect("frozen reviewer key id is valid");
        let publisher_key_id =
            KeyId::parse(PUBLISHER_KEY_TEXT).expect("frozen publisher key id is valid");
        let scope_a = TrustedScope::parse("scope-a").expect("frozen bootstrap scope is valid");
        let label = SYNTHETIC_LABEL_TEXT;

        let reviewer_issue = IssueRow {
            cap: reviewer_cap.as_str().to_string(),
            scope: scope_a.as_str().to_string(),
            ceiling: REQUIRED_REVIEW_CEILING,
            role: RoleKind::Reviewer.as_str().to_string(),
            key_id: reviewer_key_id.as_str().to_string(),
            key_fp: reviewer_key.fingerprint(),
            issuer: issuer.as_str().to_string(),
            capgen: 1,
            user: user.as_str().to_string(),
            reason: reason.as_str().to_string(),
            label: label.to_string(),
        };
        insert_admission(
            &store,
            OP_ISSUE_TEXT,
            &reviewer_cap,
            &encode_issue(&reviewer_issue),
            seq,
        )?;
        seq += 1;
        let publisher_issue = IssueRow {
            cap: publisher_cap.as_str().to_string(),
            scope: scope_a.as_str().to_string(),
            ceiling: REQUIRED_PUBLISH_CEILING,
            role: RoleKind::Publisher.as_str().to_string(),
            key_id: publisher_key_id.as_str().to_string(),
            key_fp: publisher_key.fingerprint(),
            issuer: issuer.as_str().to_string(),
            capgen: 1,
            user: user.as_str().to_string(),
            reason: reason.as_str().to_string(),
            label: label.to_string(),
        };
        insert_admission(
            &store,
            OP_ISSUE_TEXT,
            &publisher_cap,
            &encode_issue(&publisher_issue),
            seq,
        )?;
        seq += 1;

        let gate = AccessGate {
            store,
            issuer,
            user,
            next_seq: AtomicU64::new(seq),
        };
        let creds = BootstrapCredentials {
            reviewer: Credential::new(reviewer_cap, reviewer_key_id, reviewer_key),
            publisher: Credential::new(publisher_cap, publisher_key_id, publisher_key),
        };
        Ok((gate, creds))
    }

    /// Open an existing database (generation checked; bootstrap presence is
    /// checked per operation so missing bootstrap fails closed at entry).
    pub fn open(
        db_path: &Path,
        settings: ConnectionSettings,
        bounds: StoreBounds,
    ) -> Result<AccessGate, AccessError> {
        assert_schema_generation();
        let (store, _) =
            SqliteStore::open(db_path, settings, bounds).map_err(AccessError::Store)?;
        let start = outbox_count(&store)?.saturating_add(1).max(1);
        Ok(AccessGate {
            store,
            issuer: frozen_issuer(),
            user: frozen_user(),
            next_seq: AtomicU64::new(start),
        })
    }

    /// Borrow the underlying PR03 store (for offline verification reads and
    /// forgery-probe tests that need direct envelope access).
    pub fn store(&self) -> &SqliteStore {
        &self.store
    }

    /// Database path (synthetic temp paths in tests; never a repo path).
    pub fn db_path(&self) -> &Path {
        self.store.db_path()
    }

    /// Trusted bootstrap issuer identity.
    pub fn issuer(&self) -> &IssuerId {
        &self.issuer
    }

    /// Single synthetic user identity.
    pub fn user(&self) -> &UserId {
        &self.user
    }

    /// Scope-limited, ceiling-bound issuance of a new named capability.
    /// The capability name must be fresh (existing names rotate, never
    /// overwrite); the issuer must be the trusted bootstrap issuer.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        capability: &CapabilityName,
        scope: &TrustedScope,
        ceiling: u8,
        role: RoleKind,
        key_id: &KeyId,
        key: &SyntheticKey,
        issuer: &IssuerId,
        reason: &Reason,
        label: &DisplayLabel,
    ) -> Result<Credential, AccessError> {
        self.require_bootstrapped()?;
        if ceiling > MAX_CEILING_LEVEL {
            return Err(AccessError::InvalidInput {
                what: "ceiling",
                detail: format!("ceiling {ceiling} exceeds max {MAX_CEILING_LEVEL}"),
            });
        }
        if issuer != &self.issuer {
            return Err(AccessError::UnknownIssuer {
                issuer: issuer.as_str().to_string(),
            });
        }
        // Validate the ceiling through the domain constructor as well so the
        // bound travels with its scope (no silent re-targeting).
        let _ = CredentialCeiling::new(scope.clone(), ceiling).map_err(|e| {
            AccessError::InvalidInput {
                what: "ceiling",
                detail: format!("credential ceiling invalid: {e}"),
            }
        })?;
        if self.find_issue(capability.as_str())?.is_some() {
            return Err(AccessError::AlreadyBootstrapped {
                detail: format!(
                    "capability '{}' already issued; use rotation, not re-issuance",
                    capability.as_str()
                ),
            });
        }
        let row = IssueRow {
            cap: capability.as_str().to_string(),
            scope: scope.as_str().to_string(),
            ceiling,
            role: role.as_str().to_string(),
            key_id: key_id.as_str().to_string(),
            key_fp: key.fingerprint(),
            issuer: issuer.as_str().to_string(),
            capgen: 1,
            user: self.user.as_str().to_string(),
            reason: reason.as_str().to_string(),
            label: label.as_str().to_string(),
        };
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        insert_admission(
            &self.store,
            OP_ISSUE_TEXT,
            capability,
            &encode_issue(&row),
            seq,
        )?;
        Ok(Credential::new(
            capability.clone(),
            key_id.clone(),
            key.clone(),
        ))
    }

    /// Rotation with reason: revokes the presented key and issues a new key
    /// for the same capability at the next generation. The old key fails
    /// closed afterwards (revoked + stale).
    pub fn rotate(
        &self,
        current: &Credential,
        new_key_id: &KeyId,
        new_key: &SyntheticKey,
        reason: &Reason,
    ) -> Result<Credential, AccessError> {
        let checked = self.check_credential(current, None)?;
        // Fail closed like the enter paths: a revoked or stale credential
        // must not rotate into a valid successor (no gen inflation, no
        // revocation void, no holder DoS). No writes happen on refusal.
        self.require_not_revoked(&checked)?;
        self.require_current_generation(&checked)?;
        let next_gen = checked.max_gen + 1;
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let revoke = RevokeRow {
            cap: current.capability.as_str().to_string(),
            key_id: current.key_id.as_str().to_string(),
            capgen: checked.matched.capgen,
            issuer: self.issuer.as_str().to_string(),
            reason: reason.as_str().to_string(),
        };
        insert_admission(
            &self.store,
            OP_REVOKE_TEXT,
            &current.capability,
            &encode_revoke(&revoke),
            seq,
        )?;
        let seq2 = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let issue = IssueRow {
            cap: checked.matched.cap.clone(),
            scope: checked.matched.scope.clone(),
            ceiling: checked.matched.ceiling,
            role: checked.matched.role.clone(),
            key_id: new_key_id.as_str().to_string(),
            key_fp: new_key.fingerprint(),
            issuer: self.issuer.as_str().to_string(),
            capgen: next_gen,
            user: self.user.as_str().to_string(),
            reason: reason.as_str().to_string(),
            label: checked.matched.label.clone(),
        };
        // The entity column carries the capability name; the key id travels
        // inside the descriptor (sensor stays the shared synthetic sensor).
        let cap_name = CapabilityName::parse(&checked.matched.cap).map_err(|e| {
            AccessError::InvalidRecord {
                detail: format!("stored capability name invalid: {e}"),
            }
        })?;
        insert_admission(
            &self.store,
            OP_ISSUE_TEXT,
            &cap_name,
            &encode_issue(&issue),
            seq2,
        )?;
        Ok(Credential::new(
            cap_name,
            new_key_id.clone(),
            new_key.clone(),
        ))
    }

    /// Explicit revocation with reason (offline-notary statement). Afterwards
    /// the credential fails closed on all enter paths.
    pub fn revoke(&self, current: &Credential, reason: &Reason) -> Result<(), AccessError> {
        let checked = self.check_credential(current, None)?;
        if self.is_revoked(&checked.matched_cap()?, &checked.matched_key()?)? {
            return Err(AccessError::RevokedCredential {
                capability: current.capability.as_str().to_string(),
                key: current.key_id.as_str().to_string(),
            });
        }
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let revoke = RevokeRow {
            cap: current.capability.as_str().to_string(),
            key_id: current.key_id.as_str().to_string(),
            capgen: checked.matched.capgen,
            issuer: self.issuer.as_str().to_string(),
            reason: reason.as_str().to_string(),
        };
        insert_admission(
            &self.store,
            OP_REVOKE_TEXT,
            &current.capability,
            &encode_revoke(&revoke),
            seq,
        )?;
        Ok(())
    }

    /// Review entry: named ceiling/key + scope + role + revocation, all
    /// fail-closed. `None` credential is an explicit anonymous refusal.
    pub fn enter_review(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
    ) -> Result<EnterReport, AccessError> {
        let cred = Self::require_credential(credential)?;
        let checked = self.check_credential(cred, Some(scope))?;
        // Revocation and staleness fail closed before ceiling/role so a
        // revoked key reports revoked on every path.
        self.require_not_revoked(&checked)?;
        self.require_current_generation(&checked)?;
        if checked.matched.ceiling < REQUIRED_REVIEW_CEILING {
            return Err(AccessError::CeilingExceeded {
                have: checked.matched.ceiling,
                required: REQUIRED_REVIEW_CEILING,
            });
        }
        match checked.role_kind()? {
            RoleKind::Reviewer | RoleKind::Publisher => {}
        }
        Ok(checked.enter_report())
    }

    /// Publish entry: reviewer credentials cannot publish (role + ceiling).
    /// `None` credential is an explicit anonymous refusal.
    pub fn enter_publish(
        &self,
        credential: Option<&Credential>,
        scope: &TrustedScope,
    ) -> Result<EnterReport, AccessError> {
        let cred = Self::require_credential(credential)?;
        let checked = self.check_credential(cred, Some(scope))?;
        // Revocation and staleness fail closed before ceiling/role so a
        // revoked key reports revoked on every path.
        self.require_not_revoked(&checked)?;
        self.require_current_generation(&checked)?;
        if checked.matched.ceiling < REQUIRED_PUBLISH_CEILING {
            return Err(AccessError::CeilingExceeded {
                have: checked.matched.ceiling,
                required: REQUIRED_PUBLISH_CEILING,
            });
        }
        match checked.role_kind()? {
            RoleKind::Publisher => {}
            RoleKind::Reviewer => {
                return Err(AccessError::RoleDenied {
                    have: RoleKind::Reviewer.as_str().to_string(),
                    required: RoleKind::Publisher.as_str().to_string(),
                })
            }
        }
        Ok(checked.enter_report())
    }

    /// Offline revocation verification (file reads only, no live server).
    /// This is the PR07 revocation-verification path.
    pub fn is_revoked(
        &self,
        capability: &CapabilityName,
        key_id: &KeyId,
    ) -> Result<bool, AccessError> {
        let revokes = self.read_revokes()?;
        Ok(revokes
            .iter()
            .any(|r| r.cap == capability.as_str() && r.key_id == key_id.as_str()))
    }

    /// Recorded bootstrap reason (admission evidence).
    pub fn bootstrap_reason(&self) -> Result<String, AccessError> {
        let rows = self.read_bootstraps()?;
        rows.first()
            .map(|r| r.reason.clone())
            .ok_or_else(|| AccessError::NotBootstrapped {
                detail: "no bootstrap admission record".to_string(),
            })
    }

    /// Recorded display label for a capability (labels are not identity).
    pub fn label_of(&self, capability: &CapabilityName) -> Result<String, AccessError> {
        let issues = self.read_issues()?;
        issues
            .iter()
            .filter(|r| r.cap == capability.as_str())
            .max_by_key(|r| r.capgen)
            .map(|r| r.label.clone())
            .ok_or_else(|| AccessError::UnknownCapability {
                capability: capability.as_str().to_string(),
            })
    }

    /// Recorded issuance reason for a capability (latest generation).
    pub fn issue_reason(&self, capability: &CapabilityName) -> Result<String, AccessError> {
        let issues = self.read_issues()?;
        issues
            .iter()
            .filter(|r| r.cap == capability.as_str())
            .max_by_key(|r| r.capgen)
            .map(|r| r.reason.clone())
            .ok_or_else(|| AccessError::UnknownCapability {
                capability: capability.as_str().to_string(),
            })
    }

    /// Recorded revocation reason for a key, if revoked.
    pub fn revocation_reason(
        &self,
        capability: &CapabilityName,
        key_id: &KeyId,
    ) -> Result<Option<String>, AccessError> {
        let revokes = self.read_revokes()?;
        Ok(revokes
            .iter()
            .find(|r| r.cap == capability.as_str() && r.key_id == key_id.as_str())
            .map(|r| r.reason.clone()))
    }

    /// Number of admission rows (bootstrap + issues + revokes, all statuses).
    pub fn admission_count(&self) -> Result<u64, AccessError> {
        access_row_count(&self.store)
    }

    fn require_credential(credential: Option<&Credential>) -> Result<&Credential, AccessError> {
        match credential {
            Some(cred) => Ok(cred),
            None => {
                eprintln!(
                    "verdant access refuses anonymous entry [anonymous-denied] (named ceiling/key required; local-only)"
                );
                Err(AccessError::AnonymousDenied {
                    detail: "anonymous entry is refused; present a named capability credential"
                        .to_string(),
                })
            }
        }
    }

    fn require_bootstrapped(&self) -> Result<(), AccessError> {
        if access_row_count(&self.store)? == 0 {
            return Err(AccessError::NotBootstrapped {
                detail: "no admission records; bootstrap first".to_string(),
            });
        }
        Ok(())
    }

    fn find_issue(&self, cap: &str) -> Result<Option<IssueRow>, AccessError> {
        let issues = self.read_issues()?;
        Ok(issues.into_iter().find(|r| r.cap == cap))
    }

    fn check_credential(
        &self,
        cred: &Credential,
        scope: Option<&TrustedScope>,
    ) -> Result<CheckedCredential, AccessError> {
        self.require_bootstrapped()?;
        let issues = self.read_issues()?;
        let mut for_cap: Vec<IssueRow> = issues
            .into_iter()
            .filter(|r| r.cap == cred.capability.as_str())
            .collect();
        if for_cap.is_empty() {
            return Err(AccessError::UnknownCapability {
                capability: cred.capability.as_str().to_string(),
            });
        }
        for_cap.sort_by_key(|r| r.capgen);
        let max_gen = for_cap.iter().map(|r| r.capgen).max().unwrap_or(1);
        let matched = for_cap
            .iter()
            .find(|r| r.key_id == cred.key_id.as_str())
            .cloned()
            .ok_or_else(|| AccessError::ForgedCredential {
                detail: format!(
                    "key '{}' was never issued for capability '{}'",
                    cred.key_id.as_str(),
                    cred.capability.as_str()
                ),
            })?;
        if matched.issuer != self.issuer.as_str() {
            return Err(AccessError::UnknownIssuer {
                issuer: matched.issuer.clone(),
            });
        }
        if matched.key_fp != cred.key.fingerprint() {
            return Err(AccessError::ForgedCredential {
                detail: format!(
                    "key material does not match the issued fingerprint for capability '{}'",
                    cred.capability.as_str()
                ),
            });
        }
        if let Some(want) = scope {
            if matched.scope != want.as_str() {
                return Err(AccessError::ScopeDenied {
                    expected: matched.scope.clone(),
                    presented: want.as_str().to_string(),
                });
            }
        }
        Ok(CheckedCredential { matched, max_gen })
    }

    fn require_not_revoked(&self, checked: &CheckedCredential) -> Result<(), AccessError> {
        let revokes = self.read_revokes()?;
        let hit = revokes
            .iter()
            .any(|r| r.cap == checked.matched.cap && r.key_id == checked.matched.key_id);
        if hit {
            return Err(AccessError::RevokedCredential {
                capability: checked.matched.cap.clone(),
                key: checked.matched.key_id.clone(),
            });
        }
        Ok(())
    }

    fn require_current_generation(&self, checked: &CheckedCredential) -> Result<(), AccessError> {
        if checked.matched.capgen != checked.max_gen {
            return Err(AccessError::StaleGeneration {
                capability: checked.matched.cap.clone(),
                presented: checked.matched.capgen,
                current: checked.max_gen,
            });
        }
        Ok(())
    }

    fn read_issues(&self) -> Result<Vec<IssueRow>, AccessError> {
        let mut out = Vec::new();
        for (_, descriptor) in self.read_descriptors()? {
            let (kind, map) = decode_descriptor(&descriptor)?;
            match kind.as_str() {
                "issue" => out.push(decode_issue(&map)?),
                "bootstrap" | "revoke" => {}
                _ => {
                    return Err(AccessError::InvalidRecord {
                        detail: format!("unknown admission kind '{kind}'"),
                    })
                }
            }
        }
        Ok(out)
    }

    fn read_revokes(&self) -> Result<Vec<RevokeRow>, AccessError> {
        let mut out = Vec::new();
        for (_, descriptor) in self.read_descriptors()? {
            let (kind, map) = decode_descriptor(&descriptor)?;
            match kind.as_str() {
                "revoke" => out.push(decode_revoke(&map)?),
                "bootstrap" | "issue" => {}
                _ => {
                    return Err(AccessError::InvalidRecord {
                        detail: format!("unknown admission kind '{kind}'"),
                    })
                }
            }
        }
        Ok(out)
    }

    fn read_bootstraps(&self) -> Result<Vec<BootstrapRow>, AccessError> {
        let mut out = Vec::new();
        for (_, descriptor) in self.read_descriptors()? {
            let (kind, map) = decode_descriptor(&descriptor)?;
            match kind.as_str() {
                "bootstrap" => out.push(decode_bootstrap(&map)?),
                "issue" | "revoke" => {}
                _ => {
                    return Err(AccessError::InvalidRecord {
                        detail: format!("unknown admission kind '{kind}'"),
                    })
                }
            }
        }
        Ok(out)
    }

    /// Read all admission descriptors (all outbox statuses, fail closed on
    /// corrupt rows). Returns `(operation, descriptor)` pairs.
    fn read_descriptors(&self) -> Result<Vec<(String, String)>, AccessError> {
        let script = format!(
            "SELECT quote(operation), quote(entity), quote(value_json) FROM outbox WHERE operation LIKE {} ORDER BY id;",
            sql_quote("access-%")
        );
        let rows = self
            .store
            .exec_script(&script)
            .map_err(AccessError::Store)?;
        let mut out = Vec::new();
        for cols in &rows {
            if cols.len() != 3 {
                return Err(AccessError::InvalidRecord {
                    detail: format!("admission scan row has {} columns, expected 3", cols.len()),
                });
            }
            let operation =
                unquote_column(&cols[0])?.ok_or_else(|| AccessError::InvalidRecord {
                    detail: "admission operation is NULL".to_string(),
                })?;
            match operation.as_str() {
                OP_BOOTSTRAP_TEXT | OP_ISSUE_TEXT | OP_REVOKE_TEXT => {}
                _ => {
                    return Err(AccessError::InvalidRecord {
                        detail: format!("unexpected admission operation '{operation}'"),
                    })
                }
            }
            let value_json =
                unquote_column(&cols[2])?.ok_or_else(|| AccessError::InvalidRecord {
                    detail: "admission value is NULL".to_string(),
                })?;
            let value = Value::from_json(&value_json).map_err(|e| AccessError::InvalidRecord {
                detail: format!("admission value invalid: {e}"),
            })?;
            match value {
                Value::Text(descriptor) => out.push((operation, descriptor)),
                _ => {
                    return Err(AccessError::InvalidRecord {
                        detail: "admission value is not text".to_string(),
                    })
                }
            }
        }
        Ok(out)
    }
}

struct CheckedCredential {
    matched: IssueRow,
    max_gen: u32,
}

impl CheckedCredential {
    fn role_kind(&self) -> Result<RoleKind, AccessError> {
        RoleKind::parse(&self.matched.role).map_err(|e| AccessError::InvalidRecord {
            detail: format!("stored role invalid: {e}"),
        })
    }

    fn matched_cap(&self) -> Result<CapabilityName, AccessError> {
        CapabilityName::parse(&self.matched.cap).map_err(|e| AccessError::InvalidRecord {
            detail: format!("stored capability invalid: {e}"),
        })
    }

    fn matched_key(&self) -> Result<KeyId, AccessError> {
        KeyId::parse(&self.matched.key_id).map_err(|e| AccessError::InvalidRecord {
            detail: format!("stored key id invalid: {e}"),
        })
    }

    fn enter_report(&self) -> EnterReport {
        EnterReport {
            capability: self.matched.cap.clone(),
            scope: self.matched.scope.clone(),
            ceiling: self.matched.ceiling,
            role: self.matched.role.clone(),
            cap_generation: self.matched.capgen,
        }
    }
}

fn assert_schema_generation() {
    debug_assert_eq!(
        ACCESS_SCHEMA_GENERATION, SCHEMA_GENERATION,
        "access is bound to the PR03 0001 baseline"
    );
    assert_eq!(
        ACCESS_SCHEMA_GENERATION, SCHEMA_GENERATION,
        "access is bound to the PR03 0001 baseline"
    );
}

fn marker_reason_entity(user: &UserId) -> CapabilityName {
    // The bootstrap marker reuses the user text as its entity anchor (both
    // share the validated alphabet); a mismatch with the descriptor fails
    // closed at read time.
    CapabilityName::parse(user.as_str()).expect("frozen user text is a valid capability anchor")
}

fn insert_admission(
    store: &SqliteStore,
    operation: &str,
    capability: &CapabilityName,
    descriptor: &str,
    seq: u64,
) -> Result<(), AccessError> {
    let op = OperationId::parse(operation).map_err(|e| AccessError::InvalidRecord {
        detail: format!("reserved admission operation invalid: {e}"),
    })?;
    let entity =
        InstalledId::parse(capability.as_str()).map_err(|e| AccessError::InvalidRecord {
            detail: format!("admission entity invalid: {e}"),
        })?;
    // The sensor column stays the shared synthetic sensor; the key identity
    // travels inside the descriptor.
    let sensor = frozen_sensor();
    let value = Value::Text(descriptor.to_string());
    let unit = access_unit();
    store
        .insert(
            &op,
            &entity,
            &sensor,
            &value,
            &unit,
            synthetic_times(),
            &synthetic_record(seq),
        )
        .map_err(AccessError::Store)?;
    Ok(())
}

fn access_row_count(store: &SqliteStore) -> Result<u64, AccessError> {
    let script = format!(
        "SELECT COUNT(*) FROM outbox WHERE operation LIKE {};",
        sql_quote("access-%")
    );
    let rows = store.exec_script(&script).map_err(AccessError::Store)?;
    let first = rows.first().ok_or_else(|| AccessError::InvalidRecord {
        detail: "admission count returned no row".to_string(),
    })?;
    let raw = first.first().ok_or_else(|| AccessError::InvalidRecord {
        detail: "admission count row is empty".to_string(),
    })?;
    raw.parse::<u64>().map_err(|_| AccessError::InvalidRecord {
        detail: format!("admission count unreadable: '{raw}'"),
    })
}

fn outbox_count(store: &SqliteStore) -> Result<u64, AccessError> {
    let rows = store
        .exec_script("SELECT COUNT(*) FROM outbox;")
        .map_err(AccessError::Store)?;
    let first = rows.first().ok_or_else(|| AccessError::InvalidRecord {
        detail: "outbox count returned no row".to_string(),
    })?;
    let raw = first.first().ok_or_else(|| AccessError::InvalidRecord {
        detail: "outbox count row is empty".to_string(),
    })?;
    raw.parse::<u64>().map_err(|_| AccessError::InvalidRecord {
        detail: format!("outbox count unreadable: '{raw}'"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validated_names_refuse_empty_long_and_bad_chars() {
        assert_eq!(
            CapabilityName::parse("").unwrap_err().code(),
            "invalid-input"
        );
        let long = "c".repeat(129);
        assert_eq!(
            CapabilityName::parse(&long).unwrap_err().code(),
            "invalid-input"
        );
        assert_eq!(
            CapabilityName::parse("reviewer 1").unwrap_err().code(),
            "invalid-input"
        );
        assert!(CapabilityName::parse("reviewer-1").is_ok());
        assert!(KeyId::parse("key-reviewer-1").is_ok());
        assert!(UserId::parse("synthetic-operator-1").is_ok());
        assert!(IssuerId::parse("bootstrap-issuer-1").is_ok());
    }

    #[test]
    fn reason_and_label_are_bounded() {
        assert!(Reason::parse("synthetic bootstrap").is_ok());
        assert_eq!(Reason::parse("").unwrap_err().code(), "invalid-input");
        let long = "r".repeat(MAX_REASON_LEN + 1);
        assert_eq!(Reason::parse(&long).unwrap_err().code(), "invalid-input");
        assert!(DisplayLabel::parse("synthetic").is_ok());
        assert_eq!(DisplayLabel::parse("").unwrap_err().code(), "invalid-input");
    }

    #[test]
    fn roles_parse_exhaustively() {
        assert_eq!(
            RoleKind::parse("reviewer").expect("reviewer"),
            RoleKind::Reviewer
        );
        assert_eq!(
            RoleKind::parse("publisher").expect("publisher"),
            RoleKind::Publisher
        );
        assert_eq!(
            RoleKind::parse("admin").unwrap_err().code(),
            "invalid-input"
        );
        assert_eq!(RoleKind::Reviewer.as_str(), "reviewer");
        assert_eq!(RoleKind::Publisher.as_str(), "publisher");
    }

    #[test]
    fn synthetic_keys_are_prefixed_redacted_and_fingerprinted() {
        let key = SyntheticKey::parse("synthetic-test-key-1").expect("synthetic");
        assert!(!key.is_empty());
        let debug = format!("{key:?}");
        assert!(debug.contains("<redacted"), "debug redacts: {debug}");
        assert!(
            debug.contains(&key.len().to_string()),
            "length-only: {debug}"
        );
        assert!(!debug.contains("synthetic-test-key-1"), "no leak: {debug}");
        assert_eq!(
            SyntheticKey::parse("real-key-1").unwrap_err().code(),
            "invalid-input"
        );
        assert_eq!(SyntheticKey::parse("").unwrap_err().code(), "invalid-input");
        // Fingerprint is deterministic and key-sensitive.
        assert_eq!(key.fingerprint(), fingerprint_str("synthetic-test-key-1"));
        assert_ne!(
            key.fingerprint(),
            SyntheticKey::parse("synthetic-test-key-2")
                .expect("other")
                .fingerprint()
        );
    }

    #[test]
    fn credential_debug_never_leaks_key_material() {
        let cred = Credential::new(
            CapabilityName::parse("reviewer-1").expect("cap"),
            KeyId::parse("key-reviewer-1").expect("key id"),
            SyntheticKey::parse("synthetic-test-key-9").expect("key"),
        );
        let debug = format!("{cred:?}");
        assert!(debug.contains("reviewer-1"));
        assert!(!debug.contains("synthetic-test-key-9"), "no leak: {debug}");
    }

    #[test]
    fn pct_round_trip_preserves_reasons() {
        for raw in [
            "synthetic bootstrap",
            "a;b=c%d",
            "line\nbreak\rhere\u{1f}end",
            " Heslo ",
            // Multi-byte UTF-8 must reassemble exactly (no mojibake).
            "caf\u{e9}",
            "synthetic caf\u{e9} \u{2615} na\u{ef}ve fa\u{e7}ade",
        ] {
            let encoded = pct_encode(raw);
            // UTF-8-safe codec: the wire form stays ASCII-only.
            assert!(
                encoded.bytes().all(|b| b < 0x80),
                "encoded must be ASCII-only: {encoded}"
            );
            assert_eq!(pct_decode(&encoded).expect("decode"), raw);
        }
        assert!(pct_decode("%ZZ").is_err());
        assert!(pct_decode("%2").is_err());
        // Lone non-UTF-8 byte fails closed (never mojibake).
        assert_eq!(pct_decode("%FF").unwrap_err().code(), "invalid-record");
        // Crafted escape that splits a UTF-8 boundary fails closed without
        // panicking (byte-oriented hex parse).
        assert!(pct_decode("%a\u{e9}").is_err());
    }

    #[test]
    fn issue_descriptor_round_trip() {
        let row = IssueRow {
            cap: "reviewer-1".to_string(),
            scope: "scope-a".to_string(),
            ceiling: 1,
            role: "reviewer".to_string(),
            key_id: "key-reviewer-1".to_string(),
            key_fp: "0123456789abcdef".to_string(),
            issuer: "bootstrap-issuer-1".to_string(),
            capgen: 1,
            user: "synthetic-operator-1".to_string(),
            reason: "synthetic bootstrap; reason=1".to_string(),
            label: "synthetic".to_string(),
        };
        let encoded = encode_issue(&row);
        let (kind, map) = decode_descriptor(&encoded).expect("decode");
        assert_eq!(kind, "issue");
        assert_eq!(decode_issue(&map).expect("issue"), row);
        let revoke = RevokeRow {
            cap: "reviewer-1".to_string(),
            key_id: "key-reviewer-1".to_string(),
            capgen: 1,
            issuer: "bootstrap-issuer-1".to_string(),
            reason: "synthetic rotation".to_string(),
        };
        let encoded = encode_revoke(&revoke);
        let (kind, map) = decode_descriptor(&encoded).expect("decode");
        assert_eq!(kind, "revoke");
        assert_eq!(decode_revoke(&map).expect("revoke"), revoke);
    }

    #[test]
    fn non_ascii_reason_and_label_round_trip_through_descriptor() {
        // Reason/DisplayLabel::parse allow non-ASCII; the UTF-8-safe codec
        // (option (a)) must preserve them exactly through the wire form.
        let row = IssueRow {
            cap: "reviewer-1".to_string(),
            scope: "scope-a".to_string(),
            ceiling: 1,
            role: "reviewer".to_string(),
            key_id: "key-reviewer-1".to_string(),
            key_fp: "0123456789abcdef".to_string(),
            issuer: "bootstrap-issuer-1".to_string(),
            capgen: 1,
            user: "synthetic-operator-1".to_string(),
            reason: "synthetic caf\u{e9} rotation".to_string(),
            label: "synth\u{e9}tique".to_string(),
        };
        let encoded = encode_issue(&row);
        assert!(
            encoded.bytes().all(|b| b < 0x80),
            "wire form must stay ASCII-only: {encoded}"
        );
        let (kind, map) = decode_descriptor(&encoded).expect("decode");
        assert_eq!(kind, "issue");
        assert_eq!(decode_issue(&map).expect("issue"), row);
    }

    #[test]
    fn access_error_codes_are_stable() {
        let cases: Vec<(AccessError, &str)> = vec![
            (
                AccessError::AlreadyBootstrapped {
                    detail: "x".to_string(),
                },
                "already-bootstrapped",
            ),
            (
                AccessError::NotBootstrapped {
                    detail: "x".to_string(),
                },
                "not-bootstrapped",
            ),
            (
                AccessError::UnknownCapability {
                    capability: "x".to_string(),
                },
                "unknown-capability",
            ),
            (
                AccessError::UnknownIssuer {
                    issuer: "x".to_string(),
                },
                "unknown-issuer",
            ),
            (
                AccessError::ForgedCredential {
                    detail: "x".to_string(),
                },
                "forged-credential",
            ),
            (
                AccessError::ScopeDenied {
                    expected: "a".to_string(),
                    presented: "b".to_string(),
                },
                "scope-denied",
            ),
            (
                AccessError::CeilingExceeded {
                    have: 1,
                    required: 2,
                },
                "ceiling-exceeded",
            ),
            (
                AccessError::RoleDenied {
                    have: "reviewer".to_string(),
                    required: "publisher".to_string(),
                },
                "role-denied",
            ),
            (
                AccessError::RevokedCredential {
                    capability: "c".to_string(),
                    key: "k".to_string(),
                },
                "revoked-credential",
            ),
            (
                AccessError::StaleGeneration {
                    capability: "c".to_string(),
                    presented: 1,
                    current: 2,
                },
                "stale-generation",
            ),
            (
                AccessError::AnonymousDenied {
                    detail: "x".to_string(),
                },
                "anonymous-denied",
            ),
            (
                AccessError::ListenerRefused {
                    detail: "x".to_string(),
                },
                "listener-refused",
            ),
            (
                AccessError::InvalidInput {
                    what: "reason",
                    detail: "x".to_string(),
                },
                "invalid-input",
            ),
            (
                AccessError::InvalidRecord {
                    detail: "x".to_string(),
                },
                "invalid-record",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code, "code drift for {error}");
            assert!(!error.to_string().is_empty());
        }
        // Storage passthrough preserves the PR03 code.
        let wrapped = AccessError::Store(StorageError::Conflict {
            detail: "x".to_string(),
        });
        assert_eq!(wrapped.code(), "conflict");
    }

    #[test]
    fn remote_listener_refusal_is_loud_and_typed() {
        assert!(refuse_remote_listener(None).is_ok());
        let err = refuse_remote_listener(Some("0.0.0.0:8080")).unwrap_err();
        assert_eq!(err.code(), "listener-refused");
    }
}
