//! M01-PR07 stable prerequisite findings for PR11 seals.
//!
//! A [`Finding`] is the referenceable record later work cites without M03:
//! a deterministic [`FindingId`] plus a `generation` (the binding revision
//! at emission) plus the content digest and the capability fingerprint that
//! scopes it. Findings are additive and content-addressed: the same binding,
//! revision and fingerprint always yield the same id, so PR11 can re-derive
//! and cite them without re-running qualification.
//!
//! PR11 entry points (stable):
//!
//! * [`Finding::for_binding`] — derive a finding for one binding.
//! * [`Finding::id`] / [`Finding::generation`] — the citable pair.
//! * [`Finding::binding_revision`] / [`Finding::digest`] / [`Finding::summary`] —
//!   the sealed content.
//! * [`capability_fingerprint`] — the capability fingerprint entry point
//!   (delegates to the synthetic key fingerprint; raw key never leaves the
//!   caller).

use super::error::BindingError;
use super::proposal::ProposedBinding;
use crate::domain::ids::BindingRevision;

/// Maximum finding-id length in bytes.
pub const MAX_FINDING_ID_LEN: usize = 128;

fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Referenceable finding identity (e.g. `finding-9f2ac301...`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FindingId(String);

impl FindingId {
    /// Validate caller text into a finding identity.
    pub fn parse(raw: &str) -> Result<FindingId, BindingError> {
        if raw.is_empty() {
            return Err(BindingError::InvalidInput {
                what: "finding-id",
                detail: "value must not be empty".to_string(),
            });
        }
        if raw.len() > MAX_FINDING_ID_LEN {
            return Err(BindingError::InvalidInput {
                what: "finding-id",
                detail: format!(
                    "value is {} chars; maximum is {MAX_FINDING_ID_LEN}",
                    raw.len()
                ),
            });
        }
        let ok = raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
        if !ok {
            return Err(BindingError::InvalidInput {
                what: "finding-id",
                detail: format!("value has unsupported characters: '{raw}'"),
            });
        }
        Ok(FindingId(raw.to_string()))
    }

    /// Borrow the canonical text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable prerequisite finding: citable id plus generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    id: FindingId,
    generation: u32,
    revision: BindingRevision,
    digest: String,
    summary: String,
    capability_fp: String,
}

impl Finding {
    /// Derive the stable finding for one binding at `revision`, scoped to
    /// the capability fingerprint `capability_fp`.
    ///
    /// Deterministic: same binding bytes plus same revision plus same
    /// fingerprint always yield the same id and digest. The `generation`
    /// equals `revision.as_u32()` so PR11 cites `(id, generation)` without
    /// M03.
    pub fn for_binding(
        binding: &ProposedBinding,
        revision: BindingRevision,
        capability_fp: &str,
    ) -> Finding {
        let canonical = format!(
            "{}\x1f{}\x1f{}",
            binding.canonical_bytes(),
            revision.as_u32(),
            capability_fp
        );
        let digest = fnv1a_hex(canonical.as_bytes());
        let id_text = format!("finding-{digest}");
        let generation = revision.as_u32();
        let summary = format!(
            "binding {}:{} {} [{}] rev {} fp {}",
            binding.point_equipment().as_str(),
            binding.point_property().as_str(),
            binding.status().as_str(),
            binding.unit().as_str(),
            revision.as_u32(),
            capability_fp,
        );
        Finding {
            id: FindingId(id_text),
            generation,
            revision,
            digest,
            summary,
            capability_fp: capability_fp.to_string(),
        }
    }

    /// Borrow the citable finding id.
    pub fn id(&self) -> &FindingId {
        &self.id
    }

    /// Borrow the citable generation (equals the binding revision).
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Borrow the binding revision at emission.
    pub fn binding_revision(&self) -> BindingRevision {
        self.revision
    }

    /// Borrow the content digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Borrow the human summary (never secret material).
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Borrow the scoping capability fingerprint.
    pub fn capability_fingerprint_text(&self) -> &str {
        &self.capability_fp
    }

    /// Rebuild a finding from stored fields (registry replay only).
    ///
    /// No digest is recomputed here: the stored id/digest/summary are the
    /// cited record. Callers must have validated the descriptor shape.
    pub fn from_stored(
        id: FindingId,
        generation: u32,
        revision: BindingRevision,
        digest: String,
        summary: String,
        capability_fp: String,
    ) -> Finding {
        Finding {
            id,
            generation,
            revision,
            digest,
            summary,
            capability_fp,
        }
    }
}

/// Capability fingerprint entry point for PR11 seals.
///
/// Delegates to the synthetic key fingerprint recorded by PR04; the raw key
/// never leaves the caller and is never logged. The fingerprint alone grants
/// nothing: it scopes a finding to the credential that proposed it.
pub fn capability_fingerprint(credential: &crate::access::Credential) -> String {
    credential.key().fingerprint()
}
