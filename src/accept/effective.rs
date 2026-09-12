use super::{codec, Error, Result};
use crate::access::AccessGate;
use crate::binding::{self, BindingRegistry, ProposedBinding};
use crate::domain::{
    ids::{BindingRevision, InstalledId},
    scope::TrustedScope,
};
use crate::seal::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Bootstrap,
    Domain,
    TemporaryIntent,
    ObservedFact,
}
impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Domain => "domain",
            Self::TemporaryIntent => "temporary-intent",
            Self::ObservedFact => "observed-fact",
        }
    }
}

/// Stable configuration key, NOT the mutable target or display label. Bindings
/// use the existing domain IDs/units/roles without redefining those contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    key: InstalledId,
    label: String,
    binding: ProposedBinding,
    source: SourceKind,
}
impl Entry {
    pub fn new(key: InstalledId, label: &str, binding: ProposedBinding) -> Result<Self> {
        if label.is_empty() || label.len() > 256 || label.chars().any(char::is_control) {
            return Err(Error::Invalid("configuration label"));
        }
        Ok(Self {
            key,
            label: label.into(),
            binding,
            source: SourceKind::Domain,
        })
    }
    pub fn key(&self) -> &InstalledId {
        &self.key
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn binding(&self) -> &ProposedBinding {
        &self.binding
    }
    pub fn source(&self) -> SourceKind {
        self.source
    }
    pub fn fingerprint(&self, sha: &Sha256) -> Result<Digest> {
        Ok(sha.hash(self.binding.canonical_bytes().as_bytes())?)
    }
    fn encode(&self) -> String {
        codec::encode(&[
            self.key.as_str().into(),
            self.label.clone(),
            self.source.as_str().into(),
            self.binding.canonical_bytes(),
        ])
    }
    fn decode(raw: &str) -> Result<Self> {
        let f = codec::decode(raw, 4096, 4)?;
        if f.len() != 4 {
            return Err(Error::Invalid("entry fields"));
        }
        let canonical = f[3].split('\x1f').collect::<Vec<_>>();
        if canonical.len() != 14 || canonical[0] != "binding-canonical-v2" {
            return Err(Error::Invalid("binding version"));
        }
        let names = [
            "endpoint",
            "eclass",
            "escope",
            "equipment",
            "property",
            "pscope",
            "source",
            "unit",
            "mode",
            "requested",
            "effective",
            "feedback",
            "status",
        ];
        let fields = names
            .iter()
            .zip(&canonical[1..])
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let binding = binding::history::decode_propose(&fields)?;
        let key = InstalledId::parse(&f[0]).map_err(|_| Error::Invalid("entry key"))?;
        let mut result = Self::new(key, &f[1], binding)?;
        result.source = match f[2].as_str() {
            "domain" => SourceKind::Domain,
            "temporary-intent" => SourceKind::TemporaryIntent,
            _ => return Err(Error::Invalid("meaning source")),
        };
        if result.encode() != raw {
            return Err(Error::Invalid("noncanonical entry"));
        }
        Ok(result)
    }
}

/// Observed-fact SOURCE CATEGORY, not observed qualification. The underlying
/// fact is only that binding emitted this structural finding, with this actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedFact {
    id: String,
    generation: u32,
    actor: String,
    digest: String,
}
impl ObservedFact {
    pub fn source(&self) -> SourceKind {
        SourceKind::ObservedFact
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
    pub fn actor(&self) -> &str {
        &self.actor
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    fn encode(&self) -> String {
        codec::encode(&[
            self.id.clone(),
            self.generation.to_string(),
            self.actor.clone(),
            self.digest.clone(),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveConfig {
    scope: TrustedScope,
    binding_revision: BindingRevision,
    bootstrap_reason: String,
    entries: BTreeMap<String, Entry>,
    facts: Vec<ObservedFact>,
}
impl EffectiveConfig {
    /// Bootstrap and observed facts are read from existing truth, never caller
    /// assertions of authority. Domain < temporary-intent for named keys ONLY;
    /// neither source can supply authentication. No environment merge exists.
    pub fn resolve(
        gate: &AccessGate,
        registry: &mut BindingRegistry,
        scope: TrustedScope,
        domain: Vec<Entry>,
        intent: Vec<Entry>,
    ) -> Result<Self> {
        check_environment()?;
        if std::fs::canonicalize(gate.db_path())?
            != std::fs::canonicalize(registry.store().db_path())?
        {
            return Err(Error::Conflict("source stores differ".into()));
        }
        registry.replay_full()?;
        let bootstrap_reason = gate.bootstrap_reason()?;
        let mut entries = BTreeMap::new();
        for (items, source) in [
            (domain, SourceKind::Domain),
            (intent, SourceKind::TemporaryIntent),
        ] {
            if items.len() > 32 {
                return Err(Error::Limit("configuration entries"));
            }
            let mut seen = BTreeSet::new();
            for mut entry in items {
                if !seen.insert(entry.key.as_str().to_string()) {
                    return Err(Error::Invalid("duplicate source key"));
                }
                if source == SourceKind::TemporaryIntent
                    && !entries.contains_key(entry.key.as_str())
                {
                    return Err(Error::Invalid("intent needs a domain key"));
                }
                if entry.binding.point_scope() != &scope || entry.binding.endpoint_scope() != &scope
                {
                    return Err(Error::Invalid("configuration scope"));
                }
                entry.source = source;
                entries.insert(entry.key.as_str().to_string(), entry);
            }
        }
        if entries.is_empty() {
            return Err(Error::Invalid("empty configuration"));
        }
        let facts = registry
            .findings()
            .iter()
            .map(|f| ObservedFact {
                id: f.id().as_str().into(),
                generation: f.generation(),
                actor: f.actor_reference_text().into(),
                digest: f.digest().into(),
            })
            .collect();
        let result = Self {
            scope,
            binding_revision: registry.revision(),
            bootstrap_reason,
            entries,
            facts,
        };
        if result.canonical_bytes().len() > 16_384 {
            return Err(Error::Limit("effective configuration bytes"));
        }
        Ok(result)
    }
    pub fn scope(&self) -> &TrustedScope {
        &self.scope
    }
    pub fn binding_revision(&self) -> BindingRevision {
        self.binding_revision
    }
    pub fn bootstrap_source(&self) -> SourceKind {
        SourceKind::Bootstrap
    }
    pub fn bootstrap_reason(&self) -> &str {
        &self.bootstrap_reason
    }
    pub fn entries(&self) -> &BTreeMap<String, Entry> {
        &self.entries
    }
    pub fn facts(&self) -> &[ObservedFact] {
        &self.facts
    }
    pub fn canonical_bytes(&self) -> String {
        codec::encode(&[
            "verdant-effective-v1".into(),
            self.scope.as_str().into(),
            self.binding_revision.as_u32().to_string(),
            self.bootstrap_reason.clone(),
            codec::encode(&self.entries.values().map(Entry::encode).collect::<Vec<_>>()),
            codec::encode(
                &self
                    .facts
                    .iter()
                    .map(ObservedFact::encode)
                    .collect::<Vec<_>>(),
            ),
        ])
    }
    pub(super) fn decode(raw: &str) -> Result<Self> {
        let f = codec::decode(raw, 16_384, 6)?;
        if f.len() != 6 || f[0] != "verdant-effective-v1" {
            return Err(Error::Invalid("effective version"));
        }
        let scope = TrustedScope::parse(&f[1]).map_err(|_| Error::Invalid("effective scope"))?;
        let binding_revision = BindingRevision::new(codec::number(&f[2])?);
        let mut entries = BTreeMap::new();
        for raw in codec::decode(&f[4], 16_384, 32)? {
            let entry = Entry::decode(&raw)?;
            if entry.binding.point_scope() != &scope
                || entry.binding.endpoint_scope() != &scope
                || entries.insert(entry.key.as_str().into(), entry).is_some()
            {
                return Err(Error::Invalid("effective entry scope/key"));
            }
        }
        if entries.is_empty() {
            return Err(Error::Invalid("empty effective entries"));
        }
        let mut facts = Vec::new();
        for raw in codec::decode(&f[5], 16_384, 256)? {
            let p = codec::decode(&raw, 4096, 4)?;
            if p.len() != 4 {
                return Err(Error::Invalid("finding reference"));
            }
            binding::FindingId::parse(&p[0])?;
            facts.push(ObservedFact {
                id: p[0].clone(),
                generation: codec::number(&p[1])?,
                actor: p[2].clone(),
                digest: p[3].clone(),
            });
        }
        let result = Self {
            scope,
            binding_revision,
            bootstrap_reason: f[3].clone(),
            entries,
            facts,
        };
        if result.canonical_bytes() != raw {
            return Err(Error::Invalid("noncanonical effective config"));
        }
        Ok(result)
    }
    pub fn impact_from(&self, old: &Self) -> ImpactDiff {
        let mut diff = ImpactDiff::default();
        for (key, entry) in &self.entries {
            match old.entries.get(key) {
                None => {
                    diff.added.insert(key.clone());
                }
                Some(previous) if entry.binding != previous.binding => {
                    diff.invalidated.insert(key.clone());
                }
                Some(previous) => {
                    diff.preserved.insert(key.clone());
                    if entry.label != previous.label {
                        diff.cosmetic.insert(key.clone());
                    }
                }
            }
        }
        for key in old.entries.keys() {
            if !self.entries.contains_key(key) {
                diff.removed.insert(key.clone());
            }
        }
        diff.provenance_changed = self.bootstrap_reason != old.bootstrap_reason
            || self.facts != old.facts
            || self.binding_revision != old.binding_revision
            || self
                .entries
                .iter()
                .any(|(k, e)| old.entries.get(k).is_some_and(|p| p.source != e.source));
        diff
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImpactDiff {
    pub added: BTreeSet<String>,
    pub removed: BTreeSet<String>,
    pub invalidated: BTreeSet<String>,
    pub preserved: BTreeSet<String>,
    pub cosmetic: BTreeSet<String>,
    pub provenance_changed: bool,
}

/// The policy namespace is reserved even if a value is equal to published
/// policy, empty, unknown or non-UTF-8. Inspect names only; never retain/log env
/// values (which may be secrets). PR01 secret_env is bootstrap, not policy.
pub fn check_environment_names(names: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Result<()> {
    for name in names {
        let name = name.as_ref().to_string_lossy();
        if name.starts_with("VERDANT_POLICY_")
            || matches!(
                name.as_ref(),
                "VERDANT_TARGET" | "VERDANT_UNIT" | "VERDANT_ROLE"
            )
        {
            return Err(Error::EnvironmentOverride);
        }
    }
    Ok(())
}
pub(super) fn check_environment() -> Result<()> {
    check_environment_names(std::env::vars_os().map(|(name, _)| name))
}
