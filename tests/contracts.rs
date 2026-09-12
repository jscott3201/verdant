//! M01-PR02 independent JSON/native boundary fixtures.
//!
//! Test-crate root for `tests/contracts/`. The domain tree is included via
//! path for test-only access; the product binary (`src/main.rs`) wires the
//! same files via `mod domain` with no CLI change. Fixture JSON below is
//! hardcoded independently of the encoder: expected strings are literals, not
//! `to_json` output, so agreement proves conformance rather than
//! self-consistency alone.

// Include the product domain sources directly (test-only path wiring).
#[path = "../src/domain/mod.rs"]
mod domain;

#[path = "contracts/boundaries.rs"]
mod boundaries;
