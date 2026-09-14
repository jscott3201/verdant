//! C01–C10: synthetic, in-memory PR03A, no live peer or durable observation claim.
#![allow(dead_code)]
#[path = "../src/accept/mod.rs"]
mod accept;
#[path = "../src/access/mod.rs"]
mod access;
#[path = "../src/api/mod.rs"]
mod api;
#[path = "bacnet_cases/support.rs"]
mod bacnet_support;
#[path = "../src/binding/mod.rs"]
mod binding;
#[path = "observation_cases/cases.rs"]
mod cases;
#[path = "observation_cases/codec.rs"]
mod codec_cases;
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "runtime_cases/helpers.rs"]
mod helpers;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "../src/observation/mod.rs"]
mod observation;
#[path = "observation_cases/boundaries.rs"]
mod observation_boundaries;
#[path = "observation_cases/support.rs"]
mod observation_support;
#[path = "../src/runtime/mod.rs"]
mod runtime;
#[path = "../src/seal/mod.rs"]
mod seal;
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "../src/storage/mod.rs"]
mod storage;
#[path = "accept_cases/support.rs"]
mod support;
