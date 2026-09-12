//! PR11 synthetic row/manifest/byte evidence. No program store or field data.
#![allow(dead_code)]
#[path = "../src/access/mod.rs"]
mod access;
#[path = "../src/binding/mod.rs"]
mod binding;
#[path = "seal_cases/custody.rs"]
mod custody;
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "seal_cases/identity.rs"]
mod identity;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "seal_cases/refusals.rs"]
mod refusals;
#[path = "../src/seal/mod.rs"]
mod seal;
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "../src/storage/mod.rs"]
mod storage;
