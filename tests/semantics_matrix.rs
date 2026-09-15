//! FIXED S01 matrix/ledger evidence. No native materialization or field claims.
#[allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;
#[allow(dead_code)]
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "semantics_ledger_cases/fixed.rs"]
mod fixed;
#[path = "semantics_ledger_cases/refusals.rs"]
mod refusals;
#[path = "semantics_ledger_cases/artifacts.rs"]
mod artifacts;
