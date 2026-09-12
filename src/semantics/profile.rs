//! M01-PR06 pinned offline vocabulary profile.
//!
//! Offline curated synthetic subset for the `tiny_site` shape (one AHU, two
//! VAVs, one shared supply-air temperature sensor). Std-only, zero
//! dependencies, no network, no stores, no native lifecycle. The checked-in
//! artifact `pinned_subset.json` documents the same profile; product code
//! below freezes the identical constants so the two cannot drift (tests assert
//! agreement byte for meaningful fields).
//!
//! Provenance (honest scope): the curated `brick:*` aliases below are an
//! offline synthetic subset inspired by Brick, ASHRAE 223P and RealEstateCore
//! for the tiny shape only. Nothing is fetched. Broader Brick, 223P and REC
//! coverage is explicitly out of scope for v1: known-but-out-of-scenario
//! classes (for example `brick:Chiller`) are refused with classification
//! diagnostics, and anything else is refused as unknown. No claim is made
//! about universal canonicalization, relation inference, arbitrary vendor
//! import, or that an unmapped import is a reviewed semantic fault.
//!
//! Verdant namespace: `verdant:v1` with three kinds (`ahu`, `vav`,
//! `sensor-sat`). Labels travel as text and never grant identity (both VAVs
//! may carry `VAV`, like the domain fixture).
//!
//! ```ignore
//! # use verdant_semantics_profile::{Profile, VerdantKind};
//! # // Doctest crate name is illustrative; real tests wire via path.
//! let profile = Profile::pinned();
//! assert_eq!(profile.id(), "verdant-pinned-brick-223p-rec-v1");
//! assert_eq!(VerdantKind::Ahu.as_str(), "ahu");
//! ```

use std::fmt;

/// Pinned profile identifier (frozen; PR07 consumes this exact string).
pub const PINNED_PROFILE_ID: &str = "verdant-pinned-brick-223p-rec-v1";

/// Verdant namespace for v1 bindings (frozen).
pub const VERDANT_NAMESPACE: &str = "verdant:v1";

/// Curated supported external classes (frozen, sorted for determinism).
pub const SUPPORTED_AHU_CLASS: &str = "brick:AHU";
/// Curated supported external classes (frozen, sorted for determinism).
pub const SUPPORTED_VAV_CLASS: &str = "brick:VAV";
/// Curated supported external classes (frozen, sorted for determinism).
pub const SUPPORTED_SAT_CLASS: &str = "brick:Supply_Air_Temperature_Sensor";

/// Known-but-out-of-scenario classes with the frozen refusal reason.
pub const OUT_OF_SCENARIO_CHILLER: &str = "brick:Chiller";
/// Known-but-out-of-scenario classes with the frozen refusal reason.
pub const OUT_OF_SCENARIO_BOILER: &str = "brick:Boiler";
/// Known-but-out-of-scenario classes with the frozen refusal reason.
pub const OUT_OF_SCENARIO_METER: &str = "brick:Meter";

/// Frozen shared reason for every out-of-scenario refusal.
pub const OUT_OF_SCENARIO_REASON: &str =
    "known Brick class but outside tiny_site scenario for this profile (v1 covers only AHU, VAV and SAT sensor)";

/// Embedded copy of the checked-in curated artifact (compile-time pin).
pub const PINNED_SUBSET_JSON: &str = include_str!("pinned_subset.json");

/// Verdant kinds for v1 (exhaustive so new kinds break the build).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VerdantKind {
    Ahu,
    Vav,
    SensorSat,
}

impl VerdantKind {
    /// Canonical kind text (`ahu` | `vav` | `sensor-sat`).
    pub fn as_str(self) -> &'static str {
        match self {
            VerdantKind::Ahu => "ahu",
            VerdantKind::Vav => "vav",
            VerdantKind::SensorSat => "sensor-sat",
        }
    }

    /// Expected slot prefix for the kind (`ahu-` | `vav-` | `sensor-sat-`).
    pub fn slot_prefix(self) -> &'static str {
        match self {
            VerdantKind::Ahu => "ahu-",
            VerdantKind::Vav => "vav-",
            VerdantKind::SensorSat => "sensor-sat-",
        }
    }

    /// Parse a canonical kind string (exact, case-sensitive).
    pub fn parse(raw: &str) -> Option<VerdantKind> {
        match raw {
            "ahu" => Some(VerdantKind::Ahu),
            "vav" => Some(VerdantKind::Vav),
            "sensor-sat" => Some(VerdantKind::SensorSat),
            _ => None,
        }
    }
}

impl fmt::Display for VerdantKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerdantKind::Ahu => write!(f, "ahu"),
            VerdantKind::Vav => write!(f, "vav"),
            VerdantKind::SensorSat => write!(f, "sensor-sat"),
        }
    }
}

/// Classification of one external class under a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassDecision {
    /// Convertible in this profile with the mapped kind.
    Supported(VerdantKind),
    /// Known vocabulary but outside the tiny_site scenario for this profile.
    OutOfScenario {
        /// Frozen reason (see [`OUT_OF_SCENARIO_REASON`]).
        reason: &'static str,
    },
    /// Not recognized by this profile at all.
    Unknown,
}

/// Pinned offline profile handle (frozen; only [`Profile::pinned`] exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    id: &'static str,
    namespace: &'static str,
}

impl Profile {
    /// The one pinned profile for v1.
    pub fn pinned() -> Profile {
        Profile {
            id: PINNED_PROFILE_ID,
            namespace: VERDANT_NAMESPACE,
        }
    }

    /// Borrow the profile identifier.
    pub fn id(self) -> &'static str {
        self.id
    }

    /// Borrow the Verdant namespace.
    pub fn namespace(self) -> &'static str {
        self.namespace
    }

    /// Classify one external class string (pure; never fetches).
    pub fn classify(self, class: &str) -> ClassDecision {
        match class {
            SUPPORTED_AHU_CLASS => ClassDecision::Supported(VerdantKind::Ahu),
            SUPPORTED_VAV_CLASS => ClassDecision::Supported(VerdantKind::Vav),
            SUPPORTED_SAT_CLASS => ClassDecision::Supported(VerdantKind::SensorSat),
            OUT_OF_SCENARIO_CHILLER | OUT_OF_SCENARIO_BOILER | OUT_OF_SCENARIO_METER => {
                ClassDecision::OutOfScenario {
                    reason: OUT_OF_SCENARIO_REASON,
                }
            }
            _ => ClassDecision::Unknown,
        }
    }

    /// True only for convertible classes.
    pub fn is_supported(self, class: &str) -> bool {
        match self.classify(class) {
            ClassDecision::Supported(_) => true,
            ClassDecision::OutOfScenario { .. } => false,
            ClassDecision::Unknown => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_identity_is_frozen() {
        let profile = Profile::pinned();
        assert_eq!(profile.id(), PINNED_PROFILE_ID);
        assert_eq!(profile.id(), "verdant-pinned-brick-223p-rec-v1");
        assert_eq!(profile.namespace(), VERDANT_NAMESPACE);
        assert_eq!(profile.namespace(), "verdant:v1");
    }

    #[test]
    fn supported_classes_map_to_kinds() {
        let profile = Profile::pinned();
        match profile.classify(SUPPORTED_AHU_CLASS) {
            ClassDecision::Supported(kind) => assert_eq!(kind, VerdantKind::Ahu),
            ClassDecision::OutOfScenario { .. } => panic!("AHU must be supported"),
            ClassDecision::Unknown => panic!("AHU must be supported"),
        }
        match profile.classify(SUPPORTED_VAV_CLASS) {
            ClassDecision::Supported(kind) => assert_eq!(kind, VerdantKind::Vav),
            ClassDecision::OutOfScenario { .. } => panic!("VAV must be supported"),
            ClassDecision::Unknown => panic!("VAV must be supported"),
        }
        match profile.classify(SUPPORTED_SAT_CLASS) {
            ClassDecision::Supported(kind) => assert_eq!(kind, VerdantKind::SensorSat),
            ClassDecision::OutOfScenario { .. } => panic!("SAT must be supported"),
            ClassDecision::Unknown => panic!("SAT must be supported"),
        }
        assert!(profile.is_supported(SUPPORTED_AHU_CLASS));
        assert!(!profile.is_supported(OUT_OF_SCENARIO_CHILLER));
        assert!(!profile.is_supported("brick:Something-Else"));
    }

    #[test]
    fn out_of_scenario_and_unknown_are_distinct() {
        let profile = Profile::pinned();
        for class in [
            OUT_OF_SCENARIO_CHILLER,
            OUT_OF_SCENARIO_BOILER,
            OUT_OF_SCENARIO_METER,
        ] {
            match profile.classify(class) {
                ClassDecision::Supported(_) => panic!("{class} must not be supported"),
                ClassDecision::OutOfScenario { reason } => {
                    assert_eq!(reason, OUT_OF_SCENARIO_REASON)
                }
                ClassDecision::Unknown => panic!("{class} must be out-of-scenario"),
            }
        }
        match profile.classify("brick:Not-A-Real-Class") {
            ClassDecision::Supported(_) => panic!("must be unknown"),
            ClassDecision::OutOfScenario { .. } => panic!("must be unknown"),
            ClassDecision::Unknown => {}
        }
    }

    #[test]
    fn kinds_have_stable_text_and_prefixes() {
        assert_eq!(VerdantKind::Ahu.as_str(), "ahu");
        assert_eq!(VerdantKind::Vav.as_str(), "vav");
        assert_eq!(VerdantKind::SensorSat.as_str(), "sensor-sat");
        assert_eq!(VerdantKind::Ahu.slot_prefix(), "ahu-");
        assert_eq!(VerdantKind::Vav.slot_prefix(), "vav-");
        assert_eq!(VerdantKind::SensorSat.slot_prefix(), "sensor-sat-");
        assert_eq!(VerdantKind::parse("ahu"), Some(VerdantKind::Ahu));
        assert_eq!(VerdantKind::parse("vav"), Some(VerdantKind::Vav));
        assert_eq!(
            VerdantKind::parse("sensor-sat"),
            Some(VerdantKind::SensorSat)
        );
        assert_eq!(VerdantKind::parse("chiller"), None);
        assert_eq!(format!("{}", VerdantKind::Ahu), "ahu");
    }
}
