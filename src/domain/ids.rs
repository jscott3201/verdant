//! Distinct representation-level identities.
//!
//! `InstalledId` (installed/vocabulary equipment identity) is distinct from
//! [`OperationId`] (business operation), [`SourceGenerationId`]
//! (source-generation identity), [`AcquisitionStreamId`] (reserved
//! acquisition-stream placeholder) and [`RuleActivationId`] (reserved
//! rule-activation placeholder). Each is a validated newtype over a short
//! printable string; there are no cross-type conversions.
//!
//! Labels, network addresses and vocabulary display names are **not**
//! installed identity: parsing `"ahu-1"` as an [`InstalledId`] records the
//! installed equipment; a label such as `"AHU 1 (roof)"` would be refused
//! (spaces/parentheses outside the allowed set) and must travel as text.
//!
//! Stream/activation placeholders are representation only: no M02/M03 service,
//! no recovery runtime. [`BindingRevision`] is a semantic/binding revision
//! placeholder owned by the later semantics converter (M01-PR06); PR02 assigns
//! no meaning to its value.
//!
//! ```
//! use verdant_domain_ids::{InstalledId, OperationId};
//! // Distinct types: the compiler rejects mixing them.
//! let equipment = InstalledId::parse("ahu-1").unwrap();
//! let operation = OperationId::parse("op-1").unwrap();
//! assert_eq!(equipment.as_str(), "ahu-1");
//! assert_eq!(operation.as_str(), "op-1");
//! ```
//!
//! The doctest above names the crate hypothetically; the real unit tests live
//! in this module and in `tests/contracts/`.

use super::Error;

/// Maximum identifier length in bytes (all allowed chars are ASCII).
pub const MAX_ID_LEN: usize = 128;

fn validate(kind: &'static str, raw: &str) -> Result<(), Error> {
    if raw.is_empty() {
        return Err(Error::Empty { what: kind });
    }
    if raw.len() > MAX_ID_LEN {
        return Err(Error::TooLong {
            what: kind,
            len: raw.len(),
            max: MAX_ID_LEN,
        });
    }
    let ok = raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
    if !ok {
        return Err(Error::BadChars {
            what: kind,
            value: raw.to_string(),
        });
    }
    Ok(())
}

fn to_json_string(raw: &str) -> String {
    super::json::quote(raw)
}

fn from_json_string(
    kind: &'static str,
    text: &str,
    parse: fn(&str) -> Result<(), Error>,
) -> Result<String, Error> {
    let raw = super::json::parse_string_literal(text).map_err(|e| Error::Json {
        message: format!("{kind} id: {e}"),
    })?;
    parse(&raw)?;
    Ok(raw)
}

macro_rules! define_id {
    ($name:ident, $kind:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Validated construction from the canonical text form.
            ///
            /// Refuses empty, over-long (`> 128` bytes) or out-of-alphabet
            /// values with a typed [`Error`]; never panics.
            pub fn parse(raw: &str) -> Result<Self, Error> {
                validate($kind, raw)?;
                Ok(Self(raw.to_string()))
            }

            /// Borrow the canonical text.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Encode as a JSON string (`"ahu-1"`).
            pub fn to_json(&self) -> String {
                to_json_string(&self.0)
            }

            /// Decode from a JSON string; refuses malformed JSON and values
            /// that [`Self::parse`] would refuse.
            pub fn from_json(text: &str) -> Result<Self, Error> {
                let raw = from_json_string($kind, text, |s| validate($kind, s))?;
                Ok(Self(raw))
            }
        }
    };
}

define_id!(
    InstalledId,
    "installed-id",
    "Installed equipment identity (e.g. `\"ahu-1\"`, `\"vav-101\"`). Not a label, address, or vocabulary display name."
);
define_id!(
    OperationId,
    "operation-id",
    "Business operation identity (e.g. `\"op-1\"`). Not a protocol request id, writer attempt, job attempt, or database transaction."
);
define_id!(
    SourceGenerationId,
    "source-generation-id",
    "Source-generation identity (e.g. `\"gen-1\"`). The generation that scopes restored counters and replay defenses; distinct from the stream itself."
);
define_id!(
    AcquisitionStreamId,
    "acquisition-stream-id",
    "Reserved acquisition-stream placeholder (e.g. `\"stream-1\"`). Representation only; M02 services are not implemented here."
);
define_id!(
    RuleActivationId,
    "rule-activation-id",
    "Reserved rule-activation placeholder (e.g. `\"act-1\"`). Representation only; live activation/evaluation behavior arrives later."
);
define_id!(
    ScopeId,
    "scope-id",
    "Scope identity text (e.g. `\"scope-a\"`). Trusted use requires `scope::TrustedScope`; a bare `ScopeId` alone grants nothing."
);

/// Semantic/binding revision placeholder.
///
/// Owned by the later semantics converter (M01-PR06). PR02 freezes the
/// representation (`u32`, JSON string) and assigns no ordering or approval
/// meaning. `0` is the frozen placeholder example.
///
/// ```
/// # use verdant_domain_ids::BindingRevision;
/// let rev = BindingRevision::PLACEHOLDER;
/// assert_eq!(rev.as_u32(), 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BindingRevision(u32);

impl BindingRevision {
    /// Frozen placeholder example. No semantics attached.
    pub const PLACEHOLDER: BindingRevision = BindingRevision(0);

    /// Construct a revision value. No validation beyond the `u32` range;
    /// meaning is reserved for M01-PR06.
    pub fn new(value: u32) -> BindingRevision {
        BindingRevision(value)
    }

    /// Borrow the raw value.
    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// Encode as a JSON string (`"0"`) to preserve the exact value.
    pub fn to_json(self) -> String {
        super::json::quote(&self.0.to_string())
    }

    /// Decode from a JSON string; refuses malformed JSON and non-`u32` text.
    pub fn from_json(text: &str) -> Result<BindingRevision, Error> {
        let raw = super::json::parse_string_literal(text).map_err(|e| Error::Json {
            message: format!("binding-revision: {e}"),
        })?;
        raw.parse::<u32>()
            .map(BindingRevision)
            .map_err(|_| Error::InvalidValue {
                what: "binding-revision",
                value: raw,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;

    #[test]
    fn distinct_newtypes_do_not_share_identity() {
        // Representation-level distinction: five placeholder kinds plus scope
        // are different Rust types, so the compiler rejects mixing them; at
        // runtime their TypeIds differ.
        assert_ne!(TypeId::of::<InstalledId>(), TypeId::of::<OperationId>());
        assert_ne!(
            TypeId::of::<InstalledId>(),
            TypeId::of::<SourceGenerationId>()
        );
        assert_ne!(
            TypeId::of::<AcquisitionStreamId>(),
            TypeId::of::<RuleActivationId>()
        );
        assert_ne!(TypeId::of::<ScopeId>(), TypeId::of::<InstalledId>());
    }

    #[test]
    fn frozen_examples_parse() {
        assert_eq!(InstalledId::parse("ahu-1").expect("ahu").as_str(), "ahu-1");
        assert_eq!(
            InstalledId::parse("vav-101").expect("vav").as_str(),
            "vav-101"
        );
        assert_eq!(OperationId::parse("op-1").expect("op").as_str(), "op-1");
        assert_eq!(
            SourceGenerationId::parse("gen-1").expect("gen").as_str(),
            "gen-1"
        );
        assert_eq!(
            AcquisitionStreamId::parse("stream-1")
                .expect("stream")
                .as_str(),
            "stream-1"
        );
        assert_eq!(
            RuleActivationId::parse("act-1").expect("act").as_str(),
            "act-1"
        );
        assert_eq!(
            ScopeId::parse("scope-a").expect("scope").as_str(),
            "scope-a"
        );
        assert_eq!(BindingRevision::PLACEHOLDER.as_u32(), 0);
    }

    #[test]
    fn labels_are_not_installed_identity() {
        // Display labels with spaces/parentheses are refused as installed ids;
        // they must travel as text, not as identity.
        let err = InstalledId::parse("AHU 1 (roof)").unwrap_err();
        assert_eq!(err.code(), "bad-chars");
    }

    #[test]
    fn empty_long_and_bad_ids_refused() {
        assert_eq!(InstalledId::parse("").unwrap_err().code(), "empty");
        let long = "a".repeat(MAX_ID_LEN + 1);
        assert_eq!(InstalledId::parse(&long).unwrap_err().code(), "too-long");
        assert_eq!(OperationId::parse("op 1").unwrap_err().code(), "bad-chars");
        // Protocol-looking request ids are syntactically acceptable as text
        // but remain a different type: no conversion exists (compile-time).
        let req = OperationId::parse("req-9").expect("parses as operation text");
        assert_eq!(req.as_str(), "req-9");
    }

    #[test]
    fn id_json_round_trip() {
        let id = InstalledId::parse("ahu-1").expect("parse");
        assert_eq!(id.to_json(), "\"ahu-1\"");
        assert_eq!(InstalledId::from_json("\"ahu-1\"").expect("decode"), id);
        assert!(InstalledId::from_json("\"\"").is_err());
        assert!(InstalledId::from_json("not-a-string").is_err());
        assert!(InstalledId::from_json("\"bad id\"").is_err());
        // Every distinct identity kind preserves its own JSON string form.
        assert_eq!(
            OperationId::from_json(&OperationId::parse("op-1").expect("op").to_json())
                .expect("decode"),
            OperationId::parse("op-1").expect("op")
        );
        assert_eq!(
            SourceGenerationId::from_json(
                &SourceGenerationId::parse("gen-1").expect("gen").to_json()
            )
            .expect("decode"),
            SourceGenerationId::parse("gen-1").expect("gen")
        );
        assert_eq!(
            AcquisitionStreamId::from_json(
                &AcquisitionStreamId::parse("stream-1")
                    .expect("stream")
                    .to_json()
            )
            .expect("decode"),
            AcquisitionStreamId::parse("stream-1").expect("stream")
        );
        assert_eq!(
            RuleActivationId::from_json(&RuleActivationId::parse("act-1").expect("act").to_json())
                .expect("decode"),
            RuleActivationId::parse("act-1").expect("act")
        );
        assert_eq!(
            ScopeId::from_json(&ScopeId::parse("scope-a").expect("scope").to_json())
                .expect("decode"),
            ScopeId::parse("scope-a").expect("scope")
        );
    }

    #[test]
    fn binding_revision_json_round_trip() {
        let rev = BindingRevision::PLACEHOLDER;
        assert_eq!(rev.to_json(), "\"0\"");
        assert_eq!(BindingRevision::from_json("\"0\"").expect("decode"), rev);
        assert_eq!(BindingRevision::new(7).as_u32(), 7);
        assert!(BindingRevision::from_json("\"-1\"").is_err());
        assert!(BindingRevision::from_json("0").is_err());
    }
}
