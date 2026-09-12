//! PR08A: isolated synthetic transition evidence; no executable integration.
#![allow(dead_code)]
#[path = "../src/accept/mod.rs"]
mod accept;
#[path = "../src/access/mod.rs"]
mod access;
#[path = "accept_cases/base.rs"]
mod base;
#[path = "../src/binding/mod.rs"]
mod binding;
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "accept_cases/effective.rs"]
mod effective;
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "../src/seal/mod.rs"]
mod seal;
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "../src/storage/mod.rs"]
mod storage;
#[path = "accept_cases/support.rs"]
mod support;
#[path = "accept_cases/transitions.rs"]
mod transitions;
