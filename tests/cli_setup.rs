//! PR09B consumer and additive-reader evidence, exclusively isolated fixtures.
#![allow(dead_code)]
#[path = "../src/accept/mod.rs"] mod accept;
#[path = "../src/access/mod.rs"] mod access;
#[path = "../src/api/mod.rs"] mod api;
#[path = "../src/binding/mod.rs"] mod binding;
#[path = "../src/domain/mod.rs"] mod domain;
#[path = "../src/native/mod.rs"] mod native;
#[path = "../src/seal/mod.rs"] mod seal;
#[path = "../src/semantics/mod.rs"] mod semantics;
#[path = "../src/storage/mod.rs"] mod storage;
#[path = "seal_cases/fixture.rs"] mod fixture;
#[path = "accept_cases/support.rs"] mod support;

use fixture::{scope, Fixture};
fn operation(raw: &str) -> domain::ids::OperationId { fixture::operation(&format!("api-{raw}")) }

fn content(f: &mut Fixture) -> api::DraftContent {
    let seq = f.registry.store().exec_script("SELECT seq FROM outbox WHERE operation='binding-finding';").unwrap()[0][0].parse().unwrap();
    api::DraftContent::new(support::config(f, "SAT"), vec![
        api::Reference::new(fixture::operation(binding::OP_FINDING_TEXT), seq).unwrap(),
    ]).unwrap()
}
fn publication(f: &Fixture) -> api::Publication {
    api::Publication { binary: "test-cli".into(), host: "synthetic".into(), native: vec![f.reference.clone()] }
}
fn with_api<T>(f: &mut Fixture, call: impl FnOnce(&mut api::Api<'_>, &access::Credential) -> T) -> T {
    call(&mut api::Api::new(&f.gate, &mut f.registry, &f.seals).unwrap(), &f.credentials.publisher)
}

#[test]
fn fixed_lookup_committed_pending_missing_and_authentication_are_read_only() {
    let mut f = Fixture::new();
    let content = content(&mut f);
    let publication = publication(&f);
    let draft = operation("lookup-draft");
    let edited = operation("lookup-edit");
    let seal_op = operation("lookup-seal");
    let commit = with_api(&mut f, |api, cred| {
        api.draft(Some(cred), &draft, &content).unwrap();
        api.edit(Some(cred), &edited, &draft, &content).unwrap();
        api.seal(Some(cred), &scope(), &seal_op, &edited, &publication).unwrap()
    });
    let before = (support::counts(&f), support::bytes(&f));
    with_api(&mut f, |api, cred| {
        for revision in [&draft, &edited] {
            let api::SealLookup::Committed { operation, commit: found } = api.sealed(Some(cred), &scope(), revision).unwrap() else { panic!("committed lookup must not be pending") };
            assert_eq!(operation, seal_op);
            assert_eq!(found.identity, commit.identity);
            assert_eq!(found.row_id, commit.row_id);
            assert_eq!(found.manifest, commit.manifest);
            assert!(found.reconciled);
        }
        assert_eq!(api.sealed(None, &scope(), &draft).unwrap_err().code(), "anonymous-denied");
        let forged = access::Credential::new(cred.capability().clone(), cred.key_id().clone(), access::SyntheticKey::parse("synthetic-forged-cli").unwrap());
        assert_eq!(api.sealed(Some(&forged), &scope(), &draft).unwrap_err().code(), "forged-credential");
        let foreign = domain::scope::TrustedScope::parse("scope-b").unwrap();
        assert_eq!(api.sealed(Some(cred), &foreign, &draft).unwrap_err().code(), "scope-denied");
        assert!(matches!(api.sealed(Some(cred), &scope(), &operation("unknown-draft")), Err(api::Error::Missing(ref m)) if m == "operation:api-unknown-draft"));
    });
    assert_eq!((support::counts(&f), support::bytes(&f)), before);

    let pending = operation("lookup-pending");
    let pending_seal = operation("lookup-pending-seal");
    with_api(&mut f, |api, cred| { api.draft(Some(cred), &pending, &content).unwrap(); });
    let path = f.scratch.db();
    seal::on_boundary(move || storage::sqlite::faults::inject(&path, storage::sqlite::faults::Fault::BeforeCommit));
    with_api(&mut f, |api, cred| {
        assert_eq!(api.seal(Some(cred), &scope(), &pending_seal, &pending, &publication).unwrap_err().code(), "sqlite-failure");
    });
    let before = (support::counts(&f), support::bytes(&f));
    with_api(&mut f, |api, cred| {
        assert!(matches!(api.sealed(Some(cred), &scope(), &pending).unwrap(), api::SealLookup::Pending { operation } if operation == pending_seal));
    });
    assert_eq!((support::counts(&f), support::bytes(&f)), before);
    with_api(&mut f, |api, cred| {
        api.cancel(Some(cred), &scope(), &pending_seal).unwrap();
        assert!(matches!(api.sealed(Some(cred), &scope(), &pending).unwrap(), api::SealLookup::Pending { operation } if operation == pending_seal));
    });
    println!("FIXED lookup trio: committed original operation+identity+row; pending-not-sealed (also canceled); unknown draft missing; auth/scope refusals and reads preserve rows/main+WAL+SHM");
}

#[test]
fn fixed_shell_verbs_retries_diagnostics_recovery_and_refusals() {
    use access::*;
    let mut f = Fixture::new();
    f.gate.issue_with_policy(
        &CapabilityName::parse("cli-owner").unwrap(), &scope(), 2, RoleKind::Publisher,
        &KeyId::parse("cli-key").unwrap(), &SyntheticKey::parse("synthetic-cli-owner").unwrap(),
        &f.credentials.publisher, &Reason::parse("CLI test only").unwrap(),
        &DisplayLabel::parse("CLI test owner").unwrap(),
        &CapabilityPolicy::administrator(vec![scope()], 2, None).unwrap(),
    ).unwrap();
    // A real pending API seal (owner seam, no raw SQL mutation) for shell refusal.
    let input = content(&mut f);
    let publication = publication(&f);
    with_api(&mut f, |api, cred| { api.draft(Some(cred), &operation("pending-draft"), &input).unwrap(); });
    let path = f.scratch.db();
    seal::on_boundary(move || storage::sqlite::faults::inject(&path, storage::sqlite::faults::Fault::BeforeCommit));
    with_api(&mut f, |api, cred| {
        assert!(api.seal(Some(cred), &scope(), &operation("pending-seal"), &operation("pending-draft"), &publication).is_err());
    });
    // Release every native owner before another process opens the fixture.
    let Fixture { gate, registry, native, seals, scratch, .. } = f;
    drop(seals); drop(native); drop(registry); drop(gate);
    {
        use std::fs::{OpenOptions, TryLockError};
        use std::time::{Duration, Instant};
        // All fixture native owners are dropped. Synchronize on the actual
        // writer LOCK, not a fixed delay or a retried product operation.
        let native_path = scratch.native();
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(native_path.join("LOCK"))
            .expect("existing writer LOCK");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) => {
                    assert!(
                        Instant::now() < deadline,
                        "writer LOCK not released: {}",
                        native_path.display()
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(TryLockError::Error(error)) => panic!("writer LOCK probe failed: {error}"),
            }
        }
        lock.unlock().expect("release synchronization lock");
    }
    let output = std::process::Command::new("bash")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/cli_cases/verbs.sh"))
        .arg(env!("CARGO_BIN_EXE_verdant")).arg(&scratch.0)
        .stdin(std::process::Stdio::null()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    println!("{stdout}");
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert!(!stdout.contains("synthetic-cli-owner"));
    assert!(stdout.contains("FIXED R1 original identity") && stdout.contains("FIXED R2 Unqualified exits 0"));
}
