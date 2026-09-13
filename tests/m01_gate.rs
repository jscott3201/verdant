//! M01-G composition on actual adapters, with test-side manifest and limits.
//!
//! G01/G02: isolated scope-a; api-m01-gate-* adapter operations, m01-gate-*
//! freely chosen identities. Retain the original namespace refusal regression.
//! Owner suites supply the negative sweep; gate_cases records the exact map.
#![allow(dead_code)]
#[path = "../src/accept/mod.rs"]
mod accept;
#[path = "../src/access/mod.rs"]
mod access;
#[path = "../src/api/mod.rs"]
mod api;
#[path = "../src/binding/mod.rs"]
mod binding;
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "../src/seal/mod.rs"]
mod seal;
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "../src/storage/mod.rs"]
mod storage;
#[path = "gate_cases/support.rs"]
mod support;
#[path = "gate_cases/journey.rs"]
mod journey;
#[path = "gate_cases/manifest.rs"]
mod manifest;
#[path = "gate_cases/enumeration.rs"]
mod enumeration;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "verdant-m01-gate-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        // Exclusive creation: never adopt or clean a pre-existing directory.
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(path.join("native")).unwrap();
        Self(path)
    }
    fn db(&self) -> PathBuf {
        self.0.join("meaning.db")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
        println!("M01_G fixture_removed={}", !self.0.exists());
    }
}

fn query(root: &Scratch, sql: &str) -> String {
    let output = Command::new("sqlite3")
        .args(["-batch", "-noheader"])
        .arg(root.db())
        .arg(sql)
        .env("HOME", &root.0)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout).unwrap()
}

fn bytes(root: &Path) -> Vec<(&'static str, Option<Vec<u8>>)> {
    ["meaning.db", "meaning.db-wal", "meaning.db-shm"]
        .into_iter()
        .map(|name| {
            let content = match std::fs::read(root.join(name)) {
                Ok(content) => Some(content),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => panic!("snapshot {name}: {error}"),
            };
            (name, content)
        })
        .collect()
}

struct Setup {
    gate: access::AccessGate,
    credential: access::Credential,
    registry: binding::BindingRegistry,
    native: native::NativeHandle,
    seals: seal::SealStore,
    content: api::DraftContent,
    sequence: u64,
    // Drop resources before their fixture even when an assertion unwinds.
    scratch: Scratch,
}

fn setup() -> Setup {
    use access::*;
    use domain::{ids::*, scope::TrustedScope, values::Unit};
    let scratch = Scratch::new();
    let reason = Reason::parse("M01-G independent synthetic setup").unwrap();
    let (gate, bootstrap) = AccessGate::bootstrap(
        &scratch.db(),
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
        &reason,
    )
    .unwrap();
    let scope = TrustedScope::parse("scope-a").unwrap();
    let credential = gate
        .issue(
            &CapabilityName::parse("m01-gate-publisher").unwrap(),
            &scope,
            2,
            RoleKind::Publisher,
            &KeyId::parse("m01-gate-key").unwrap(),
            &SyntheticKey::parse("synthetic-m01-gate-setup").unwrap(),
            &bootstrap.publisher,
            &reason,
            &DisplayLabel::parse("m01-gate-publisher").unwrap(),
        )
        .unwrap();
    let actor = gate.authenticate(Some(&credential), &scope).unwrap();
    assert_eq!(actor.capability(), "m01-gate-publisher");
    assert_eq!(actor.ceiling().scope(), &scope);
    assert_eq!(actor.role(), RoleKind::Publisher);

    let mut registry = binding::BindingRegistry::open(
        &scratch.db(),
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
    )
    .unwrap();
    registry
        .record_equipment(
            "m01-gate-ahu",
            binding::EquipmentKind::Ahu,
            scope.clone(),
            "m01-gate-ahu",
            "mstp://m01-gate-ahu",
        )
        .unwrap();
    registry
        .record_point(
            "m01-gate-ahu",
            "supply-air-temp",
            scope.clone(),
            "degC",
            binding::EndpointClass::Location,
        )
        .unwrap();
    let proposed = binding::ProposedBinding::from_import(
        binding::EndpointAddress::parse("mstp://m01-gate-ahu").unwrap(),
        binding::EndpointClass::Location,
        scope.clone(),
        InstalledId::parse("m01-gate-ahu").unwrap(),
        binding::PropertyName::parse("supply-air-temp").unwrap(),
        scope.clone(),
        InstalledId::parse("m01-gate-sensor").unwrap(),
        Unit::parse("degC").unwrap(),
        None,
        binding::BindingRole::Sense,
        binding::BindingRole::Sense,
        binding::Feedback::Absent,
        binding::BindingStatus::Valid,
    );
    registry
        .submit_proposal(
            &gate,
            Some(&credential),
            &binding::PendingProposal::new(
                OperationId::parse("api-m01-gate-proposal").unwrap(),
                registry.revision(),
                proposed.clone(),
            ),
        )
        .unwrap();
    registry
        .emit_finding_operation(
            &OperationId::parse("api-m01-gate-finding").unwrap(),
            registry.revision(),
            &gate,
            &proposed,
            &credential,
        )
        .unwrap();
    let sequence = query(
        &scratch,
        "SELECT seq FROM outbox WHERE operation='binding-finding';",
    )
    .trim()
    .parse()
    .unwrap();
    let (native, _) = native::NativeHandle::create(
        &scratch.0.join("native"),
        native::NativeSettings::local(),
    )
    .unwrap();
    assert_eq!(
        native
            .execute("INSERT (:Reading {id: 'm01-gate-reading', seq: 1})")
            .unwrap()
            .changes,
        Some(1)
    );
    let seals =
        seal::SealStore::open(registry.store().try_clone().unwrap(), native.clone()).unwrap();
    let entry = accept::Entry::new(
        InstalledId::parse("m01-gate-binding").unwrap(),
        "m01-gate-SAT",
        proposed,
    )
    .unwrap();
    let content = api::Api::new(&gate, &mut registry, &seals)
        .unwrap()
        .resolve(
            Some(&credential),
            &scope,
            vec![entry],
            vec![],
            vec![api::Reference::new(
                OperationId::parse(binding::OP_FINDING_TEXT).unwrap(),
                sequence,
            )
            .unwrap()],
        )
        .unwrap();

    Setup { scratch, gate, credential, registry, native, seals, content, sequence }
}

#[test]
fn literal_gate_operation_namespace_is_refused_by_cli_and_api_without_writes() {
    use domain::ids::OperationId;
    let Setup { scratch, gate, credential, mut registry, native, seals, content, sequence } = setup();

    // Independent SQL assertions; never print rows containing key fingerprints.
    let tables = "SELECT * FROM outbox ORDER BY id; \
                  SELECT * FROM storage_receipts ORDER BY operation; \
                  SELECT * FROM derived_marks ORDER BY entity;";
    let before_rows = query(&scratch, tables);
    let before_counts = query(
        &scratch,
        "SELECT (SELECT count(*) FROM outbox), \
         (SELECT count(*) FROM storage_receipts), \
         (SELECT count(*) FROM derived_marks);",
    );
    let before_bytes = bytes(&scratch.0);
    let operation = OperationId::parse("m01-gate-draft").unwrap();
    let error = api::Api::new(&gate, &mut registry, &seals)
        .unwrap()
        .draft(Some(&credential), &operation, &content)
        .unwrap_err();
    assert!(matches!(error, api::Error::Invalid("API operation namespace/length")));
    assert_eq!(error.code(), "api-invalid");
    assert_eq!(query(&scratch, tables), before_rows);
    assert_eq!(bytes(&scratch.0), before_bytes);
    println!("M01_G_NAMESPACE API refusal={} detail={error}", error.code());

    // Release all owners before the executable is invoked. The CLI has valid
    // syntax, configuration, credentials and binding input apart from the ID.
    drop(seals);
    drop(registry);
    drop(gate);
    drop(native.close());
    let config = scratch.0.join("site.conf");
    std::fs::write(
        &config,
        format!(
            "role = \"standalone\"\ndurable_path = \"{}\"\nsecret_env = \"M01_GATE_SECRET\"\n",
            scratch.0.display()
        ),
    )
    .unwrap();
    let closed_bytes = bytes(&scratch.0);
    let output = Command::new(env!("CARGO_BIN_EXE_verdant"))
        .args(["draft", "--config"])
        .arg(&config)
        .args([
            "--scope", "scope-a", "--capability", "m01-gate-publisher",
            "--key-id", "m01-gate-key", "--operation-id", "m01-gate-draft",
            "--entry", "m01-gate-binding|0|m01-gate-SAT", "--finding",
            &format!("binding-finding:{sequence}"),
        ])
        .env("HOME", &scratch.0)
        .env("M01_GATE_SECRET", "synthetic-m01-gate-setup")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr,
        "verdant draft refused: [api-invalid] api-invalid: Invalid(\"API operation namespace/length\")\n"
    );
    assert!(!stderr.contains("synthetic-m01-gate-setup"));
    assert_eq!(query(&scratch, tables), before_rows);
    assert_eq!(bytes(&scratch.0), closed_bytes);
    assert_eq!(
        query(&scratch, "SELECT count(*) FROM outbox WHERE operation IN ('api-intent-v1','seal-revision-v1','accept-revision-v1','accept-active-v1');"),
        "0\n"
    );
    println!("M01_G_NAMESPACE CLI exit=2 stderr={}", stderr.trim());
    println!("M01_G_NAMESPACE scope=scope-a authenticated=true resolved=true outbox|receipts|marks={} rows_unchanged=true events=0", before_counts.trim());
    for (name, content) in &closed_bytes {
        println!("M01_G_NAMESPACE {name} bytes={:?} unchanged=true", content.as_ref().map(Vec::len));
    }
}
