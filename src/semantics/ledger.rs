//! Original versus derived/refused S01 facts. Parser evidence, never native rows.
use super::parse::Object;
use super::recipe::{Artifact, EVIDENCE, RECIPE_ID};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Original,
    Derived,
    Refusal,
}
impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Derived => "derived",
            Self::Refusal => "refusal",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub artifact: &'static str,
    pub sha256: &'static str,
    pub subject: String,
    pub predicate: String,
    pub object: Object,
    pub kind: Kind,
    pub rule: &'static str,
    pub reason: String,
    pub provenance: &'static str,
}
impl Fact {
    pub(super) fn new(
        pin: &Artifact,
        subject: &str,
        predicate: &str,
        object: Object,
        kind: Kind,
        rule: &'static str,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            artifact: pin.name,
            sha256: pin.sha256,
            subject: subject.into(),
            predicate: predicate.into(),
            object,
            kind,
            rule,
            reason: reason.into(),
            provenance: pin.provenance,
        }
    }
    /// Rule versions and artifact context survive shared unversioned term IRIs.
    /// "authored" means explicit in the artifact, not a claim about upstream
    /// authoring pipelines: Brick itself is a generated distribution.
    pub fn to_json(&self) -> String {
        let object_kind = match &self.object {
            Object::Iri(_) => "iri",
            Object::Literal(_) => "literal",
        };
        let authored = self.kind == Kind::Original;
        format!("{{\"artifact\":{},\"sha256\":{},\"subject\":{},\"predicate\":{},\"object_kind\":{},\"object\":{},\"kind\":{},\"authored\":{},\"rule\":{},\"rule_version\":1,\"recipe\":{},\"reason\":{},\"provenance\":{},\"evidence\":{}}}",
            json(self.artifact), json(self.sha256), json(&self.subject), json(&self.predicate),
            json(object_kind), json(self.object.lexical()), json(self.kind.name()), authored,
            json(self.rule), json(RECIPE_ID), json(&self.reason), json(self.provenance), json(EVIDENCE))
    }
}
pub(super) fn json(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
