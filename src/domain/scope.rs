//! Scope and credential ceiling representations (syntax validation only).
//!
//! A caller-provided tenant/role string never *is* a trusted context. It
//! does not become one through [`TrustedScope::parse`], which only validates
//! the alphabet/length rules of [`super::ids::ScopeId`]. Authentication and
//! actor-context construction belong exclusively to access. There is
//! intentionally no `From<String>`, `From<&str>` or `Default` for
//! [`TrustedScope`] or [`CredentialCeiling`]: these constructors validate
//! representation, never grant authority or prove an issued policy.
//!
//! Frozen examples: `"scope-a"`, `"scope-b"` with ceiling levels `0..=3`
//! (see [`MAX_CEILING_LEVEL`]). PR04 (access) consumes these types; PR02
//! assigns no authentication semantics.
//!
//! ```ignore
//! let scope = TrustedScope::parse("scope-a").unwrap();
//! let ceiling = CredentialCeiling::new(scope, 2).unwrap();
//! assert_eq!(ceiling.level(), 2);
//! ```

use super::ids::ScopeId;
use super::Error;

/// Syntactically validated scope handle; not evidence of authorization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustedScope {
    id: ScopeId,
}

impl TrustedScope {
    /// Validate caller scope text, without authenticating it.
    ///
    /// Accepts the frozen examples `"scope-a"`/`"scope-b"` and any other
    /// syntactically valid scope id; refuses empty, over-long and
    /// out-of-alphabet text with a typed [`Error`].
    pub fn parse(raw: &str) -> Result<TrustedScope, Error> {
        Ok(TrustedScope {
            id: ScopeId::parse(raw)?,
        })
    }

    /// Lift an already-validated [`ScopeId`] into a scope representation.
    ///
    /// This is still a validated path: the `ScopeId` could only have come
    /// from [`ScopeId::parse`]. Raw strings must go through [`Self::parse`].
    pub fn from_scope_id(id: ScopeId) -> TrustedScope {
        TrustedScope { id }
    }

    /// Borrow the canonical scope text.
    pub fn as_str(&self) -> &str {
        self.id.as_str()
    }

    /// Borrow the underlying scope identity.
    pub fn scope_id(&self) -> &ScopeId {
        &self.id
    }

    /// Encode as `{"scope":"scope-a"}` (field order frozen).
    pub fn to_json(&self) -> String {
        format!("{{\"scope\":{}}}", super::json::quote(self.as_str()))
    }

    /// Decode from `{"scope":"..."}`; refuses malformed JSON, missing fields,
    /// unexpected fields and invalid scope text.
    pub fn from_json(text: &str) -> Result<TrustedScope, Error> {
        let fields = super::json::parse_object(text)?;
        super::json::reject_unknown(&fields, &["scope"])?;
        let raw = super::json::get_string(&fields, "scope")?;
        TrustedScope::parse(&raw)
    }
}

/// Representable upper capability bound for a scope, not an issued grant.
///
/// `level` is a small integer `0..=MAX_CEILING_LEVEL`. Higher values are
/// refused rather than clamped. The scope travels with the ceiling so a
/// ceiling cannot be silently re-targeted at another scope.
pub const MAX_CEILING_LEVEL: u8 = 3;

/// Validated ceiling representation bound to one syntactically valid scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialCeiling {
    scope: TrustedScope,
    level: u8,
}

impl CredentialCeiling {
    /// Construct a ceiling for `scope` at `level`.
    ///
    /// Refuses `level > MAX_CEILING_LEVEL` with a typed [`Error`].
    pub fn new(scope: TrustedScope, level: u8) -> Result<CredentialCeiling, Error> {
        if level > MAX_CEILING_LEVEL {
            return Err(Error::InvalidValue {
                what: "credential-ceiling",
                value: level.to_string(),
            });
        }
        Ok(CredentialCeiling { scope, level })
    }

    /// Borrow the bound scope.
    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }

    /// Borrow the ceiling level.
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Encode as `{"scope":"scope-a","ceiling":"2"}`.
    ///
    /// The level is a JSON string (exact representation; no float path).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"scope\":{},\"ceiling\":{}}}",
            super::json::quote(self.scope.as_str()),
            super::json::quote(&self.level.to_string())
        )
    }

    /// Decode from `{"scope":"...","ceiling":"N"}`; refuses malformed JSON,
    /// missing/unexpected fields, non-numeric levels and levels above the max.
    pub fn from_json(text: &str) -> Result<CredentialCeiling, Error> {
        let fields = super::json::parse_object(text)?;
        super::json::reject_unknown(&fields, &["scope", "ceiling"])?;
        let scope_raw = super::json::get_string(&fields, "scope")?;
        let level_raw = super::json::get_string(&fields, "ceiling")?;
        let scope = TrustedScope::parse(&scope_raw)?;
        let level: u8 = level_raw.parse::<u8>().map_err(|_| Error::InvalidValue {
            what: "credential-ceiling",
            value: level_raw.clone(),
        })?;
        CredentialCeiling::new(scope, level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_scopes_parse() {
        for raw in ["scope-a", "scope-b"] {
            let scope = TrustedScope::parse(raw).expect("frozen scope parses");
            assert_eq!(scope.as_str(), raw);
            // Validated-id lift preserves the same trusted text.
            let lifted =
                TrustedScope::from_scope_id(super::super::ids::ScopeId::parse(raw).expect("id"));
            assert_eq!(lifted, scope);
            assert_eq!(lifted.scope_id().as_str(), raw);
        }
        let ceiling = CredentialCeiling::new(TrustedScope::parse("scope-a").expect("scope"), 2)
            .expect("ceiling");
        assert_eq!(ceiling.level(), 2);
        assert_eq!(ceiling.scope().as_str(), "scope-a");
    }

    #[test]
    fn caller_strings_without_validation_are_refused() {
        // Empty, over-long and out-of-alphabet caller strings never become
        // trusted context.
        assert_eq!(TrustedScope::parse("").unwrap_err().code(), "empty");
        let long = "s".repeat(super::super::ids::MAX_ID_LEN + 1);
        assert_eq!(TrustedScope::parse(&long).unwrap_err().code(), "too-long");
        assert_eq!(
            TrustedScope::parse("scope A").unwrap_err().code(),
            "bad-chars"
        );
        assert_eq!(
            TrustedScope::parse("scope-a;drop").unwrap_err().code(),
            "bad-chars"
        );
    }

    #[test]
    fn ceiling_level_is_bounded_not_clamped() {
        let scope = TrustedScope::parse("scope-a").expect("scope");
        assert!(CredentialCeiling::new(scope.clone(), MAX_CEILING_LEVEL).is_ok());
        let err = CredentialCeiling::new(scope, MAX_CEILING_LEVEL + 1).unwrap_err();
        assert_eq!(err.code(), "invalid-value");
    }

    #[test]
    fn scope_json_round_trip() {
        let scope = TrustedScope::parse("scope-a").expect("scope");
        assert_eq!(scope.to_json(), "{\"scope\":\"scope-a\"}");
        assert_eq!(
            TrustedScope::from_json("{\"scope\":\"scope-a\"}").expect("decode"),
            scope
        );
        // Whitespace and field order tolerance is handled by the JSON layer;
        // single-field object has no order question, but whitespace is fine.
        assert_eq!(
            TrustedScope::from_json(" { \"scope\" : \"scope-a\" } ").expect("decode"),
            scope
        );
        assert!(TrustedScope::from_json("{\"scope\":\"\"}").is_err());
        assert!(TrustedScope::from_json("{\"scope\":\"scope A\"}").is_err());
        assert!(TrustedScope::from_json("{}").is_err());
        assert!(TrustedScope::from_json("{\"scope\":\"scope-a\",\"extra\":\"1\"}").is_err());
    }

    #[test]
    fn ceiling_json_round_trip() {
        let ceiling = CredentialCeiling::new(TrustedScope::parse("scope-b").expect("scope"), 1)
            .expect("ceiling");
        assert_eq!(
            ceiling.to_json(),
            "{\"scope\":\"scope-b\",\"ceiling\":\"1\"}"
        );
        assert_eq!(
            CredentialCeiling::from_json("{\"scope\":\"scope-b\",\"ceiling\":\"1\"}")
                .expect("decode"),
            ceiling
        );
        assert!(CredentialCeiling::from_json("{\"scope\":\"scope-b\",\"ceiling\":\"9\"}").is_err());
        assert!(CredentialCeiling::from_json("{\"scope\":\"scope-b\"}").is_err());
    }
}
