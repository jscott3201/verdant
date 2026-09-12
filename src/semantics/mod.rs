//! M01-PR06 offline vocabulary import and conversion.
//!
//! Pinned offline subset plus deterministic supported-subset converter with a
//! conversion record and manifest. Std-only, zero dependencies, no network,
//! no store writes, no native lifecycle, no field acquisition.
//!
//! The pinned profile lives in [`profile`]; the pure converter lives in
//! [`convert`]. The checked-in artifact `pinned_subset.json` documents the
//! same profile with honest provenance and scope (small honest subset, never
//! an invented universal import).
//!
//! PR07 handoff: [`convert::ConversionRecord`] shape (profile, input digest,
//! content digest, per-item outcomes in slot order) plus
//! [`convert::BindingSet`] revision semantics (bump on change, preserve on
//! no-op) plus [`convert::SemanticsError`] unmapped-class diagnostics
//! (`out-of-scenario` vs `unknown-class`, each naming class and profile).

pub mod convert;
pub mod profile;
