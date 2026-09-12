//! R05 adversarial schedules use isolated synthetic stores and observed rows/bytes.
#[allow(dead_code)]
#[path = "../src/access/mod.rs"]
mod access;
#[allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;
#[allow(dead_code)]
#[path = "../src/storage/mod.rs"]
mod storage;

use access::*;
use domain::scope::TrustedScope;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use storage::{ConnectionSettings, StoreBounds};

#[path = "access_cases/policy.rs"]
mod policy_cases;

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "verdant-r05-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }
    fn db(&self) -> PathBuf {
        self.0.join("access.db")
    }
    fn bootstrap(&self) -> (AccessGate, BootstrapCredentials) {
        AccessGate::bootstrap(
            &self.db(),
            ConnectionSettings::local_wal_full(),
            StoreBounds::tiny(),
            &reason(),
        )
        .unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn reason() -> Reason {
    Reason::parse("synthetic R05").unwrap()
}
fn scope(raw: &str) -> TrustedScope {
    TrustedScope::parse(raw).unwrap()
}
fn key(raw: &str) -> SyntheticKey {
    SyntheticKey::parse(&format!("synthetic-{raw}")).unwrap()
}
fn open(db: &Path) -> AccessGate {
    AccessGate::open(
        db,
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .unwrap()
}
fn raw(db: &Path, sql: &str) -> String {
    let out = std::process::Command::new("sqlite3")
        .arg(db)
        .arg(sql)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    rows: String,
    counts: String,
    bytes: Vec<u8>,
}
fn snapshot(db: &Path) -> Snapshot {
    let rows = raw(db, "SELECT * FROM outbox ORDER BY id; SELECT * FROM derived_marks ORDER BY entity; SELECT * FROM storage_receipts ORDER BY operation;");
    let counts = raw(db, "SELECT (SELECT count(*) FROM outbox), (SELECT count(*) FROM derived_marks), (SELECT count(*) FROM storage_receipts);");
    Snapshot {
        rows,
        counts,
        bytes: std::fs::read(db).unwrap(),
    }
}
fn issue(
    gate: &AccessGate,
    admin: &Credential,
    name: &str,
    target: &str,
    ceiling: u8,
) -> Result<Credential, AccessError> {
    gate.issue(
        &CapabilityName::parse(name).unwrap(),
        &scope(target),
        ceiling,
        RoleKind::Reviewer,
        &KeyId::parse(&format!("key-{name}")).unwrap(),
        &key(name),
        admin,
        &reason(),
        &DisplayLabel::parse("synthetic").unwrap(),
    )
}
fn rotate(gate: &AccessGate, cred: &Credential, name: &str) -> Result<Credential, AccessError> {
    gate.rotate(cred, &KeyId::parse(name).unwrap(), &key(name), &reason())
}

#[test]
fn r05_authority_boundaries() {
    let scratch = Scratch::new();
    let (gate, creds) = scratch.bootstrap();
    for (name, admin, target, ceiling, code) in [
        (
            "unauthorized-scope",
            &creds.publisher,
            "scope-c",
            1,
            "scope-denied",
        ),
        (
            "caller-ceiling",
            &creds.publisher,
            "scope-a",
            3,
            "ceiling-exceeded",
        ),
        (
            "known-issuer-no-admin",
            &creds.reviewer,
            "scope-a",
            1,
            "administration-denied",
        ),
    ] {
        let before = snapshot(&scratch.db());
        assert_eq!(
            issue(&gate, admin, name, target, ceiling)
                .unwrap_err()
                .code(),
            code
        );
        let after = snapshot(&scratch.db());
        assert_eq!(before, after);
        println!(
            "FIXED {name}: {code}; rows/counts/bytes unchanged; counts={} bytes={}",
            after.counts.trim(),
            after.bytes.len()
        );
    }
}

#[test]
fn r05_simultaneous_bootstraps() {
    let scratch = Scratch::new();
    drop(open(&scratch.db()));
    let barrier = Arc::new(Barrier::new(2));
    access::testing::arm(
        &scratch.db(),
        "bootstrap",
        2,
        Arc::new(move || {
            barrier.wait();
        }),
    );
    let results = std::thread::scope(|s| {
        let a = s.spawn(|| {
            AccessGate::bootstrap(
                &scratch.db(),
                ConnectionSettings::local_wal_full(),
                StoreBounds::tiny(),
                &reason(),
            )
        });
        let b = s.spawn(|| {
            AccessGate::bootstrap(
                &scratch.db(),
                ConnectionSettings::local_wal_full(),
                StoreBounds::tiny(),
                &reason(),
            )
        });
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .find_map(|r| r.as_ref().err())
            .unwrap()
            .code(),
        "already-bootstrapped"
    );
    let (gate, creds) = results.into_iter().find_map(Result::ok).unwrap();
    gate.enter_review(Some(&creds.reviewer), &scope("scope-a"))
        .unwrap();
    gate.enter_publish(Some(&creds.publisher), &scope("scope-a"))
        .unwrap();
    let before = snapshot(&scratch.db());
    assert_eq!(before.counts.trim(), "3|3|1");
    assert_eq!(
        AccessGate::bootstrap(
            &scratch.db(),
            ConnectionSettings::local_wal_full(),
            StoreBounds::tiny(),
            &reason()
        )
        .unwrap_err()
        .code(),
        "already-bootstrapped"
    );
    assert_eq!(before, snapshot(&scratch.db()));
    println!("FIXED simultaneous bootstraps: winners=1 loser=AlreadyBootstrapped counts=3|3|1; repeat rows/counts/bytes unchanged");
}

#[test]
fn r05_marker_before_credentials_interruption() {
    let scratch = Scratch::new();
    drop(open(&scratch.db()));
    let mut bounds = StoreBounds::tiny();
    bounds.max_value_bytes = 200; // Marker fits; the credential descriptor does not.
    let before = snapshot(&scratch.db());
    assert!(AccessGate::bootstrap(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        bounds,
        &reason()
    )
    .is_err());
    let after = snapshot(&scratch.db());
    assert_eq!(before, after);
    assert_eq!(after.counts.trim(), "0|0|0");
    access::testing::interrupt_after_marker(&scratch.db());
    let error = AccessGate::bootstrap(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
        &reason(),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("r05_injected_marker_interruption"),
        "{error}"
    );
    assert_eq!(before, snapshot(&scratch.db()));
    // The existing storage seam kills/reaps the process after ALL batch rows
    // have staged but before COMMIT. No committed marker survives this either.
    storage::sqlite::faults::inject(&scratch.db(), storage::sqlite::faults::Fault::BeforeCommit);
    assert!(AccessGate::bootstrap(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
        &reason()
    )
    .is_err());
    assert_eq!(before, snapshot(&scratch.db()));
    println!("FIXED marker-before-creds: bounds refusal + post-marker failure + precommit child teardown; counts=0|0|0 rows/bytes unchanged");
}

#[test]
fn r05_concurrent_rotations() {
    let scratch = Scratch::new();
    let (gate, creds) = scratch.bootstrap();
    let other = open(&scratch.db());
    let barrier = Arc::new(Barrier::new(2));
    access::testing::arm(
        &scratch.db(),
        "rotate",
        2,
        Arc::new(move || {
            barrier.wait();
        }),
    );
    let results = std::thread::scope(|s| {
        let a = s.spawn(|| rotate(&gate, &creds.reviewer, "key-next-a"));
        let b = s.spawn(|| rotate(&other, &creds.reviewer, "key-next-b"));
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(matches!(
        results.iter().find_map(|r| r.as_ref().err()).unwrap(),
        AccessError::StaleGeneration { .. }
            | AccessError::Store(storage::StorageError::Conflict { .. })
    ));
    let winner = results.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(
        gate.enter_review(Some(&winner), &scope("scope-a"))
            .unwrap()
            .cap_generation,
        2
    );
    assert!(gate
        .is_revoked(creds.reviewer.capability(), creds.reviewer.key_id())
        .unwrap());
    let before = snapshot(&scratch.db());
    assert_eq!(before.counts.trim(), "5|3|2");
    assert_eq!(
        rotate(&gate, &creds.reviewer, "key-third")
            .unwrap_err()
            .code(),
        "stale-generation"
    );
    assert_eq!(before, snapshot(&scratch.db()));
    println!("FIXED concurrent rotations: winners=1 loser=Conflict counts=5|3|2; repeat rows/counts/bytes unchanged");
}

#[test]
fn r05_revoke_issue_gap() {
    let scratch = Scratch::new();
    let (gate, creds) = scratch.bootstrap();
    let db = scratch.db();
    let admin = creds.publisher.clone();
    let after_revoke = Arc::new(Mutex::new(None));
    let observed = after_revoke.clone();
    access::testing::arm(
        &scratch.db(),
        "issue",
        1,
        Arc::new(move || {
            open(&db).revoke(&admin, &reason()).unwrap();
            *observed.lock().unwrap() = Some(snapshot(&db));
        }),
    );
    assert_eq!(
        issue(&gate, &creds.publisher, "gap", "scope-a", 1)
            .unwrap_err()
            .code(),
        "conflict"
    );
    assert_eq!(
        after_revoke.lock().unwrap().take().unwrap(),
        snapshot(&scratch.db())
    );
    assert_eq!(
        issue(&gate, &creds.publisher, "gap", "scope-a", 1)
            .unwrap_err()
            .code(),
        "revoked-credential"
    );
    println!(
        "FIXED revoke-issue gap: Conflict; counts={} rows/bytes unchanged after revoke",
        snapshot(&scratch.db()).counts.trim()
    );
}

#[test]
fn r05_generation_overflow() {
    let scratch = Scratch::new();
    let (gate, creds) = scratch.bootstrap();
    raw(&scratch.db(), "UPDATE outbox SET value_json=replace(value_json, 'capgen=1', 'capgen=4294967295') WHERE entity='reviewer-1';");
    let before = snapshot(&scratch.db());
    assert!(matches!(
        rotate(&gate, &creds.reviewer, "key-overflow"),
        Err(AccessError::GenerationOverflow { .. })
    ));
    assert_eq!(before, snapshot(&scratch.db()));
    println!("FIXED overflow u32::MAX: GenerationOverflow, no panic; rows/counts/bytes unchanged");
}

#[test]
fn r05_revoke_check_mutation_gap() {
    let scratch = Scratch::new();
    let (gate, creds) = scratch.bootstrap();
    let db = scratch.db();
    let cred = creds.reviewer.clone();
    let after_revoke = Arc::new(Mutex::new(None));
    let observed = after_revoke.clone();
    access::testing::arm(
        &scratch.db(),
        "revoke",
        1,
        Arc::new(move || {
            open(&db).revoke(&cred, &reason()).unwrap();
            *observed.lock().unwrap() = Some(snapshot(&db));
        }),
    );
    assert_eq!(
        gate.revoke(&creds.reviewer, &reason()).unwrap_err().code(),
        "conflict"
    );
    assert_eq!(
        after_revoke.lock().unwrap().take().unwrap(),
        snapshot(&scratch.db())
    );
    assert_eq!(snapshot(&scratch.db()).counts.trim(), "4|3|2");
    println!("FIXED revoke-check-mutation gap: counts=4|3|2; no duplicate; rows/bytes unchanged after revoke");
}

#[test]
fn r05_forged_role_and_reopen_no_fallback() {
    let scratch = Scratch::new();
    let (gate, creds) = scratch.bootstrap();
    raw(&scratch.db(), "UPDATE outbox SET value_json=replace(value_json, 'role=reviewer', 'role=admin') WHERE entity='reviewer-1';");
    let before = snapshot(&scratch.db());
    assert_eq!(
        gate.enter_review(Some(&creds.reviewer), &scope("scope-a"))
            .unwrap_err()
            .code(),
        "invalid-record"
    );
    assert_eq!(
        gate.enter_publish(Some(&creds.reviewer), &scope("scope-a"))
            .unwrap_err()
            .code(),
        "invalid-record"
    );
    drop(gate);
    drop(open(&scratch.db()));
    assert_eq!(before, snapshot(&scratch.db()));
    println!("FIXED forged role both paths + reopen: refused; rows/counts/bytes preserved");
}
