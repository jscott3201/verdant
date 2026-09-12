#![allow(dead_code)]
#[path = "../../../src/access/mod.rs"]
mod access;
#[path = "../../../src/domain/mod.rs"]
mod domain;
#[path = "../../../src/storage/mod.rs"]
mod storage;

fn main() {
    let _ = access::ActorContext::from_checked;
    let _: access::ActorContext = domain::scope::TrustedScope::parse("scope-a")
        .unwrap()
        .into();
}
