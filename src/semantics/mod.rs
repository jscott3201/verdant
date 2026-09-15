//! M01-PR06 offline vocabulary import and conversion.
//!
//! Pinned offline subset plus deterministic supported-subset converter with a
//! conversion record and manifest. The legacy converter remains std-only; the
//! separate S01 parser uses pinned oxttl. No network,
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
//!
//! R07 vocabulary admission and the conversion/binding provenance seam are
//! specified in `CONTRACT.md`. Conversion is not observed qualification.

pub mod convert;
pub mod profile;
// Integration-owner wiring only: no CLI, conversion, binding or native calls.
pub mod parse;
pub mod matrix;
pub mod ledger;
pub mod recipe;
