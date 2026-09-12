//! M01-PR04 access boundaries: synthetic bootstrap, named ceilings, rotation,
//! revocation (offline notary), listener refusal, migration safety, sealed
//! paths, static separation, synthetic secrets.
//!
//! Every test runs against an isolated synthetic database in an OS temp dir
//! (unique per process/test/sequence per D09; removed on drop; never a repo
//! path, never production/field/paid anything). One supported target only
//! (macOS arm64, rustc 1.97.1, system sqlite3 3.54.0): other targets,
//! power loss, real disk-full, Selene and PostgreSQL are untested limits.
//!
//! No new migrations: admission records live in the PR03 0001 outbox via
//! reserved `access-*` operations (see `src/access/mod.rs`); the
//! `migration_reservation` test still observes exactly one numbered migration.

// Allowed dead code: these path-wired trees expose the full domain/storage
// surface, but access tests exercise only the consumed subset (the remainder
// is covered by contracts/storage_sqlite). Mirrors the product wiring.
#[allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;

#[allow(dead_code)]
#[path = "../src/storage/mod.rs"]
mod storage;

#[allow(dead_code)]
#[path = "../src/access/mod.rs"]
mod access;

use access::{
    refuse_remote_listener, AccessGate, BootstrapCredentials, CapabilityName, Credential,
    DisplayLabel, KeyId, Reason, RoleKind, SyntheticKey,
};
use domain::scope::TrustedScope;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Isolated scratch root for one test. Removed on drop.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(test: &str) -> Scratch {
        let id = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "verdant-pr04-{}-{}-{}",
            std::process::id(),
            test,
            id
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Scratch { dir }
    }

    fn db(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn durable(&self) -> PathBuf {
        let dir = self.dir.join("durable");
        std::fs::create_dir_all(&dir).expect("create durable dir");
        dir
    }

    fn write_config(&self, name: &str, body: &str) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn reason(test: &str) -> Reason {
    Reason::parse(&format!(
        "synthetic {} {} {}",
        test,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ))
    .expect("synthetic reason")
}

fn label(text: &str) -> DisplayLabel {
    DisplayLabel::parse(text).expect("synthetic label")
}

fn scope_a() -> TrustedScope {
    TrustedScope::parse("scope-a").expect("frozen scope-a")
}

fn scope_b() -> TrustedScope {
    TrustedScope::parse("scope-b").expect("frozen scope-b")
}

fn synthetic_key(test: &str, who: &str) -> SyntheticKey {
    SyntheticKey::parse(&format!(
        "synthetic-{}-{}-{}-{}",
        test,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst),
        who
    ))
    .expect("synthetic key")
}

fn open_gate(scratch: &Scratch, name: &str, why: &Reason) -> (AccessGate, BootstrapCredentials) {
    AccessGate::bootstrap(
        &scratch.db(name),
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
        why,
    )
    .unwrap_or_else(|e| {
        panic!(
            "bootstrap {}: {e} [{}]",
            scratch.db(name).display(),
            e.code()
        )
    })
}

fn sqlite_raw(db: &Path, script: &str) -> (bool, String, String) {
    let output = Command::new("sqlite3")
        .arg(db)
        .arg(script)
        .stdin(Stdio::null())
        .output()
        .expect("spawn sqlite3");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_verdant"))
}

// ---------------------------------------------------------------------------
// Synthetic bootstrap + duplicate labels (labels are not identity).
// ---------------------------------------------------------------------------

#[test]
fn synthetic_bootstrap_mints_named_capabilities_with_reason() {
    let scratch = Scratch::new("bootstrap");
    let why = reason("bootstrap");
    let (gate, creds) = open_gate(&scratch, "access.db", &why);
    assert_eq!(gate.admission_count().expect("count"), 3);
    assert_eq!(gate.bootstrap_reason().expect("reason"), why.as_str());
    // Gate identity: single synthetic user, trusted issuer, isolated DB path.
    assert_eq!(gate.user().as_str(), "synthetic-operator-1");
    assert_eq!(gate.issuer().as_str(), "bootstrap-issuer-1");
    assert_eq!(gate.db_path(), scratch.db("access.db").as_path());
    // Named identities are distinct.
    assert_ne!(
        creds.reviewer.capability().as_str(),
        creds.publisher.capability().as_str()
    );
    assert_eq!(creds.reviewer.capability().as_str(), "reviewer-1");
    assert_eq!(creds.publisher.capability().as_str(), "publisher-1");
    // Duplicate labels: equal text, distinct identities.
    assert_eq!(
        gate.label_of(creds.reviewer.capability()).expect("label"),
        "synthetic"
    );
    assert_eq!(
        gate.label_of(creds.publisher.capability()).expect("label"),
        "synthetic"
    );
    assert_eq!(
        gate.label_of(creds.reviewer.capability()).expect("label"),
        gate.label_of(creds.publisher.capability()).expect("label")
    );
    assert_ne!(creds.reviewer.capability(), creds.publisher.capability());
    // Positive entry on the issued scope.
    let review = gate
        .enter_review(Some(&creds.reviewer), &scope_a())
        .expect("reviewer reviews");
    assert_eq!(review.capability, "reviewer-1");
    assert_eq!(review.scope, "scope-a");
    assert_eq!(review.ceiling, 1);
    let publish = gate
        .enter_publish(Some(&creds.publisher), &scope_a())
        .expect("publisher publishes");
    assert_eq!(publish.capability, "publisher-1");
    assert_eq!(publish.cap_generation, 1);
    println!(
        "bootstrap: reviewer + publisher minted, reason_len={} admissions=3",
        why.as_str().len()
    );
}

#[test]
fn duplicate_labels_cannot_enter_as_identity() {
    let scratch = Scratch::new("labels");
    let (gate, _) = open_gate(&scratch, "access.db", &reason("labels"));
    // The shared label parses as a name but was never issued: typed refusal.
    let poser = Credential::new(
        CapabilityName::parse("synthetic").expect("label text parses as a name"),
        KeyId::parse("key-reviewer-1").expect("key id"),
        synthetic_key("labels", "poser"),
    );
    assert_eq!(
        gate.enter_review(Some(&poser), &scope_a())
            .unwrap_err()
            .code(),
        "unknown-capability"
    );
}

// ---------------------------------------------------------------------------
// Re-bootstrap is a typed refusal (never silent overwrite).
// ---------------------------------------------------------------------------

#[test]
fn rebootstrap_is_a_typed_refusal_without_overwrite() {
    let scratch = Scratch::new("rebootstrap");
    let first = reason("rebootstrap-first");
    let (gate, creds) = open_gate(&scratch, "access.db", &first);
    let before = gate.admission_count().expect("count");
    let err = AccessGate::bootstrap(
        &scratch.db("access.db"),
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
        &reason("rebootstrap-second"),
    )
    .unwrap_err();
    assert_eq!(err.code(), "already-bootstrapped");
    assert_eq!(gate.admission_count().expect("count"), before);
    assert_eq!(gate.bootstrap_reason().expect("reason"), first.as_str());
    // Original credentials still work (no overwrite).
    gate.enter_review(Some(&creds.reviewer), &scope_a())
        .expect("still reviews");
}

// ---------------------------------------------------------------------------
// Issuance: scope-limited, ceiling-bound; forged/unknown-issuer refused.
// ---------------------------------------------------------------------------

#[test]
fn issuance_is_scope_limited_and_ceiling_bound() {
    let scratch = Scratch::new("issuance");
    let (gate, creds) = open_gate(&scratch, "access.db", &reason("issuance"));
    let cap = CapabilityName::parse("auditor-1").expect("cap");
    let key_id = KeyId::parse("key-auditor-1").expect("key id");
    let key = synthetic_key("issuance", "auditor");
    let issued = gate
        .issue(
            &cap,
            &scope_b(),
            1,
            RoleKind::Reviewer,
            &key_id,
            &key,
            &creds.publisher,
            &reason("issuance-auditor"),
            &label("synthetic"),
        )
        .expect("issue auditor in scope-b");
    // Issued scope works; other scope is denied (scope-limited).
    gate.enter_review(Some(&issued), &scope_b())
        .expect("scope-b reviews");
    assert_eq!(
        gate.enter_review(Some(&issued), &scope_a())
            .unwrap_err()
            .code(),
        "scope-denied"
    );
    // Ceiling above the max is refused before any write.
    let before = gate.admission_count().expect("count");
    assert_eq!(
        gate.issue(
            &CapabilityName::parse("too-high-1").expect("cap"),
            &scope_a(),
            9,
            RoleKind::Reviewer,
            &KeyId::parse("key-too-high-1").expect("key"),
            &synthetic_key("issuance", "high"),
            &creds.publisher,
            &reason("issuance-high"),
            &label("synthetic"),
        )
        .unwrap_err()
        .code(),
        "invalid-input"
    );
    assert_eq!(gate.admission_count().expect("count"), before);
    // Re-issuing an existing name is refused (rotation is the path).
    assert_eq!(
        gate.issue(
            &cap,
            &scope_b(),
            1,
            RoleKind::Reviewer,
            &KeyId::parse("key-auditor-2").expect("key"),
            &synthetic_key("issuance", "auditor2"),
            &creds.publisher,
            &reason("issuance-dup"),
            &label("synthetic"),
        )
        .unwrap_err()
        .code(),
        "already-bootstrapped"
    );
}

#[test]
fn forged_mint_and_unknown_issuer_are_refused() {
    let scratch = Scratch::new("forgery");
    let (gate, creds) = open_gate(&scratch, "access.db", &reason("forgery"));
    // Forged mint: capability never issued.
    let forged = Credential::new(
        CapabilityName::parse("forged-cap-1").expect("cap"),
        KeyId::parse("key-forged-1").expect("key"),
        synthetic_key("forgery", "forged"),
    );
    assert_eq!(
        gate.enter_review(Some(&forged), &scope_a())
            .unwrap_err()
            .code(),
        "unknown-capability"
    );
    // Forged key: known capability, invented key id.
    let wrong_key = Credential::new(
        creds.reviewer.capability().clone(),
        KeyId::parse("key-forged-9").expect("key"),
        synthetic_key("forgery", "wrong"),
    );
    assert_eq!(
        gate.enter_review(Some(&wrong_key), &scope_a())
            .unwrap_err()
            .code(),
        "forged-credential"
    );
    // Forged material: known ids, wrong secret.
    let wrong_secret = Credential::new(
        creds.reviewer.capability().clone(),
        creds.reviewer.key_id().clone(),
        synthetic_key("forgery", "mismatch"),
    );
    assert_eq!(
        gate.enter_review(Some(&wrong_secret), &scope_a())
            .unwrap_err()
            .code(),
        "forged-credential"
    );
    // Unknown issuer at mint time is refused before any write.
    let before = gate.admission_count().expect("count");
    assert!(sqlite_raw(gate.db_path(), "UPDATE outbox SET value_json=replace(value_json, 'issuer=bootstrap-issuer-1', 'issuer=unknown-issuer-9') WHERE entity='reviewer-1';").0);
    assert_eq!(
        gate.issue(
            &CapabilityName::parse("stranger-1").expect("cap"),
            &scope_a(),
            1,
            RoleKind::Reviewer,
            &KeyId::parse("key-stranger-1").expect("key"),
            &synthetic_key("forgery", "stranger"),
            &creds.reviewer,
            &reason("forgery-stranger"),
            &label("synthetic"),
        )
        .unwrap_err()
        .code(),
        "unknown-issuer"
    );
    assert_eq!(gate.admission_count().expect("count"), before);
}

// ---------------------------------------------------------------------------
// Every enter path checks (no unchecked path); scope/key overreach refused.
// ---------------------------------------------------------------------------

#[test]
fn every_enter_path_checks_named_ceiling_key() {
    let scratch = Scratch::new("enter-paths");
    let (gate, creds) = open_gate(&scratch, "access.db", &reason("enter-paths"));
    // Anonymous on both paths.
    assert_eq!(
        gate.enter_review(None, &scope_a()).unwrap_err().code(),
        "anonymous-denied"
    );
    assert_eq!(
        gate.enter_publish(None, &scope_a()).unwrap_err().code(),
        "anonymous-denied"
    );
    // Unknown capability on both paths.
    let unknown = Credential::new(
        CapabilityName::parse("ghost-1").expect("cap"),
        KeyId::parse("key-ghost-1").expect("key"),
        synthetic_key("enter-paths", "ghost"),
    );
    assert_eq!(
        gate.enter_review(Some(&unknown), &scope_a())
            .unwrap_err()
            .code(),
        "unknown-capability"
    );
    assert_eq!(
        gate.enter_publish(Some(&unknown), &scope_a())
            .unwrap_err()
            .code(),
        "unknown-capability"
    );
    // Scope overreach on the positive credential.
    assert_eq!(
        gate.enter_review(Some(&creds.reviewer), &scope_b())
            .unwrap_err()
            .code(),
        "scope-denied"
    );
    assert_eq!(
        gate.enter_publish(Some(&creds.publisher), &scope_b())
            .unwrap_err()
            .code(),
        "scope-denied"
    );
}

#[test]
fn overreaching_scope_and_key_are_typed_refusals() {
    let scratch = Scratch::new("overreach");
    let (gate, creds) = open_gate(&scratch, "access.db", &reason("overreach"));
    // Scope overreach.
    let denied = gate
        .enter_review(Some(&creds.reviewer), &scope_b())
        .unwrap_err();
    assert_eq!(denied.code(), "scope-denied");
    // Key overreach (wrong secret for a known identity).
    let forged = Credential::new(
        creds.publisher.capability().clone(),
        creds.publisher.key_id().clone(),
        synthetic_key("overreach", "wrong-secret"),
    );
    assert_eq!(
        gate.enter_publish(Some(&forged), &scope_a())
            .unwrap_err()
            .code(),
        "forged-credential"
    );
}

// ---------------------------------------------------------------------------
// Rotation with reason: new key works, old key fails closed.
// ---------------------------------------------------------------------------

#[test]
fn rotation_with_reason_issues_new_key_and_revokes_old() {
    let scratch = Scratch::new("rotation");
    let (gate, creds) = open_gate(&scratch, "access.db", &reason("rotation"));
    let new_key_id = KeyId::parse("key-reviewer-2").expect("key id");
    let new_key = synthetic_key("rotation", "reviewer2");
    let why = reason("rotation-with-reason");
    let rotated = gate
        .rotate(&creds.reviewer, &new_key_id, &new_key, &why)
        .expect("rotate reviewer");
    assert_eq!(rotated.capability().as_str(), "reviewer-1");
    assert_eq!(rotated.key_id().as_str(), "key-reviewer-2");
    // New key enters with bumped generation.
    let report = gate
        .enter_review(Some(&rotated), &scope_a())
        .expect("new key reviews");
    assert_eq!(report.cap_generation, 2);
    // Old key fails closed (revoked statement recorded).
    assert_eq!(
        gate.enter_review(Some(&creds.reviewer), &scope_a())
            .unwrap_err()
            .code(),
        "revoked-credential"
    );
    assert_eq!(
        gate.enter_publish(Some(&creds.reviewer), &scope_a())
            .unwrap_err()
            .code(),
        "revoked-credential"
    );
    assert!(gate
        .is_revoked(creds.reviewer.capability(), creds.reviewer.key_id())
        .expect("revoked"));
    assert!(!gate
        .is_revoked(rotated.capability(), rotated.key_id())
        .expect("active"));
    assert_eq!(
        gate.revocation_reason(creds.reviewer.capability(), creds.reviewer.key_id())
            .expect("reason"),
        Some(why.as_str().to_string())
    );
    assert_eq!(
        gate.issue_reason(creds.reviewer.capability())
            .expect("issue reason"),
        why.as_str()
    );
    println!("rotation: old revoked, new gen=2, reason recorded");
}

// ---------------------------------------------------------------------------
// Rotation guards: revoked or stale credentials cannot rotate (no gen
// inflation, no revocation void, no holder DoS). Refusals write nothing.
// ---------------------------------------------------------------------------

#[test]
fn revoked_credential_cannot_rotate() {
    let scratch = Scratch::new("rotate-revoked");
    let (gate, creds) = open_gate(&scratch, "access.db", &reason("rotate-revoked"));
    gate.revoke(&creds.reviewer, &reason("rotate-revoked-revoke"))
        .expect("revoke reviewer");
    let before = gate.admission_count().expect("count");
    // Revoked gen-1 credential must not rotate into a valid successor.
    let err = gate
        .rotate(
            &creds.reviewer,
            &KeyId::parse("key-reviewer-9").expect("key id"),
            &synthetic_key("rotate-revoked", "next"),
            &reason("rotate-revoked-try"),
        )
        .unwrap_err();
    assert_eq!(err.code(), "revoked-credential");
    // Refusal writes nothing: no revoke row, no successor issue row.
    assert_eq!(gate.admission_count().expect("count"), before);
    // The attempted successor was never issued.
    assert_eq!(
        gate.enter_review(
            Some(&Credential::new(
                creds.reviewer.capability().clone(),
                KeyId::parse("key-reviewer-9").expect("key id"),
                synthetic_key("rotate-revoked", "probe"),
            )),
            &scope_a(),
        )
        .unwrap_err()
        .code(),
        "forged-credential"
    );
    println!("rotation: revoked credential refused rotate, no writes");
}

#[test]
fn stale_generation_cannot_rotate_again() {
    let scratch = Scratch::new("rotate-stale");
    let (gate, creds) = open_gate(&scratch, "access.db", &reason("rotate-stale"));
    // gen1 -> gen2 (happy path still works).
    let rotated = gate
        .rotate(
            &creds.reviewer,
            &KeyId::parse("key-reviewer-2").expect("key id"),
            &synthetic_key("rotate-stale", "reviewer2"),
            &reason("rotate-stale-first"),
        )
        .expect("first rotate");
    assert_eq!(
        gate.enter_review(Some(&rotated), &scope_a())
            .expect("gen2 reviews")
            .cap_generation,
        2
    );
    let before = gate.admission_count().expect("count");
    // Rotating the old gen-1 credential again is refused (it is revoked and
    // stale; the revocation guard fires first, staleness is defense in
    // depth). No gen-3 successor may appear.
    let err = gate
        .rotate(
            &creds.reviewer,
            &KeyId::parse("key-reviewer-3").expect("key id"),
            &synthetic_key("rotate-stale", "reviewer3"),
            &reason("rotate-stale-retry"),
        )
        .unwrap_err();
    assert!(
        err.code() == "revoked-credential" || err.code() == "stale-generation",
        "unexpected code: {}",
        err.code()
    );
    assert_eq!(gate.admission_count().expect("count"), before);
    // gen2 remains current; no gen-3 exists.
    assert_eq!(
        gate.enter_review(Some(&rotated), &scope_a())
            .expect("gen2 still current")
            .cap_generation,
        2
    );
    println!("rotation: stale gen-1 refused second rotate, gen-2 still current");
}

// ---------------------------------------------------------------------------
// Revocation: offline-notary statement, fail closed on all paths + restart.
// ---------------------------------------------------------------------------

#[test]
fn revocation_is_offline_notary_and_fails_closed_on_all_paths() {
    let scratch = Scratch::new("revocation");
    let db = scratch.db("access.db");
    let why = reason("revocation");
    let (gate, creds) = open_gate(&scratch, "access.db", &why);
    let revoke_why = reason("revoke-publisher");
    gate.revoke(&creds.publisher, &revoke_why)
        .expect("revoke publisher");
    assert!(gate
        .is_revoked(creds.publisher.capability(), creds.publisher.key_id())
        .expect("revoked"));
    assert_eq!(
        gate.revocation_reason(creds.publisher.capability(), creds.publisher.key_id())
            .expect("reason"),
        Some(revoke_why.as_str().to_string())
    );
    // Fail closed on every enter path.
    assert_eq!(
        gate.enter_review(Some(&creds.publisher), &scope_a())
            .unwrap_err()
            .code(),
        "revoked-credential"
    );
    assert_eq!(
        gate.enter_publish(Some(&creds.publisher), &scope_a())
            .unwrap_err()
            .code(),
        "revoked-credential"
    );
    // The other capability is unaffected (still generation 1).
    let still = gate
        .enter_review(Some(&creds.reviewer), &scope_a())
        .expect("reviewer ok");
    assert_eq!(still.cap_generation, 1);
    drop(gate);
    // Offline verification: reopen the file with no live server and the
    // revocation still holds (recorded statement, not server memory).
    let reopened = AccessGate::open(
        &db,
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
    )
    .expect("reopen");
    assert!(reopened
        .is_revoked(creds.publisher.capability(), creds.publisher.key_id())
        .expect("still revoked offline"));
    assert_eq!(
        reopened
            .enter_publish(Some(&creds.publisher), &scope_a())
            .unwrap_err()
            .code(),
        "revoked-credential"
    );
    println!("revocation: offline statement verified after reopen, no live server");
}

// ---------------------------------------------------------------------------
// Anonymous remote listener refused loudly; omitted setting starts none.
// ---------------------------------------------------------------------------

#[test]
fn anonymous_remote_listener_is_refused_loudly_and_omitted_starts_none() {
    assert!(refuse_remote_listener(None).is_ok());
    let err = refuse_remote_listener(Some("0.0.0.0:8080")).unwrap_err();
    assert_eq!(err.code(), "listener-refused");

    // PR01 rule preserved through the binary: omitted setting starts no
    // listener; an explicit remote listener section is refused with a code.
    let scratch = Scratch::new("listener");
    let durable = scratch.durable();
    let ok = scratch.write_config(
        "verdant.conf",
        &format!(
            "role = \"standalone\"\ndurable_path = \"{}\"\n",
            durable.display()
        ),
    );
    let output = Command::new(bin())
        .arg("run")
        .arg("--config")
        .arg(&ok)
        .arg("--once")
        .stdin(Stdio::null())
        .output()
        .expect("spawn run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(stdout.contains("listener=none"), "{stdout}");
    assert!(
        !stdout.contains("listen="),
        "no listener address may appear: {stdout}"
    );

    let bad = scratch.write_config(
        "bad.conf",
        &format!(
            "role = \"hub\"\ndurable_path = \"{}\"\n[listener]\nbind = \"0.0.0.0:8080\"\n",
            durable.display()
        ),
    );
    let output = Command::new(bin())
        .arg("run")
        .arg("--config")
        .arg(&bad)
        .arg("--once")
        .stdin(Stdio::null())
        .output()
        .expect("spawn refused run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains("[listener-not-supported]"), "{stderr}");
}

// ---------------------------------------------------------------------------
// Missing-migration safety: unknown generation refused, never skipped.
// ---------------------------------------------------------------------------

#[test]
fn missing_migration_state_is_refused_never_skipped() {
    let scratch = Scratch::new("migration");
    let db = scratch.db("access.db");
    let (gate, creds) = open_gate(&scratch, "access.db", &reason("migration"));
    assert_eq!(gate.admission_count().expect("count"), 3);
    let (ok, _, _) = sqlite_raw(&db, "PRAGMA user_version = 9;");
    assert!(ok, "tamper the generation out of band");
    // Every access path refuses with the storage generation code.
    assert_eq!(
        gate.enter_review(Some(&creds.reviewer), &scope_a())
            .unwrap_err()
            .code(),
        "schema-generation-mismatch"
    );
    assert_eq!(
        gate.rotate(
            &creds.reviewer,
            &KeyId::parse("key-reviewer-9").expect("key"),
            &synthetic_key("migration", "rotate"),
            &reason("migration-rotate"),
        )
        .unwrap_err()
        .code(),
        "schema-generation-mismatch"
    );
    assert_eq!(
        gate.revoke(&creds.reviewer, &reason("migration-revoke"))
            .unwrap_err()
            .code(),
        "schema-generation-mismatch"
    );
    assert_eq!(
        AccessGate::open(
            &db,
            storage::ConnectionSettings::local_wal_full(),
            storage::StoreBounds::tiny(),
        )
        .unwrap_err()
        .code(),
        "schema-generation-mismatch"
    );
    assert_eq!(
        AccessGate::bootstrap(
            &db,
            storage::ConnectionSettings::local_wal_full(),
            storage::StoreBounds::tiny(),
            &reason("migration-rebootstrap"),
        )
        .unwrap_err()
        .code(),
        "schema-generation-mismatch"
    );
    // Tampered data is preserved, not wiped or silently migrated.
    let (ok, out, _) = sqlite_raw(&db, "SELECT COUNT(*) FROM outbox;");
    assert!(ok);
    assert_eq!(out.trim(), "3");
}

// ---------------------------------------------------------------------------
// Sealed config/artifact paths stay read-only through access paths.
// ---------------------------------------------------------------------------

#[test]
fn sealed_paths_stay_read_only_through_access_flows() {
    let scratch = Scratch::new("sealed");
    let sealed_dir = scratch.dir.join("sealed");
    std::fs::create_dir_all(&sealed_dir).expect("sealed dir");
    let sealed_file = sealed_dir.join("artifact.conf");
    let sealed_body = "role = \"standalone\"\n# sealed fixture (must not change)\n";
    std::fs::write(&sealed_file, sealed_body).expect("sealed file");
    let before_bytes = std::fs::read(&sealed_file).expect("read sealed");
    let before_list: Vec<String> = std::fs::read_dir(&sealed_dir)
        .expect("list sealed")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();

    // All access flows point at an isolated DB elsewhere; sealed paths are
    // never passed to any access writer.
    let (gate, creds) = open_gate(&scratch, "access.db", &reason("sealed"));
    gate.enter_review(Some(&creds.reviewer), &scope_a())
        .expect("review");
    gate.enter_publish(Some(&creds.publisher), &scope_a())
        .expect("publish");
    let rotated = gate
        .rotate(
            &creds.reviewer,
            &KeyId::parse("key-reviewer-7").expect("key"),
            &synthetic_key("sealed", "rotated"),
            &reason("sealed-rotate"),
        )
        .expect("rotate");
    gate.enter_review(Some(&rotated), &scope_a())
        .expect("rotated reviews");
    gate.revoke(&creds.publisher, &reason("sealed-revoke"))
        .expect("revoke");

    let after_bytes = std::fs::read(&sealed_file).expect("read sealed after");
    assert_eq!(before_bytes, after_bytes, "sealed artifact changed");
    let after_list: Vec<String> = std::fs::read_dir(&sealed_dir)
        .expect("list sealed after")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(before_list, after_list, "sealed dir gained files");
}

// ---------------------------------------------------------------------------
// Static separation: reviewer cannot publish (least privilege).
// ---------------------------------------------------------------------------

#[test]
fn reviewer_cannot_publish_static_separation() {
    let scratch = Scratch::new("separation");
    let (gate, creds) = open_gate(&scratch, "access.db", &reason("separation"));
    gate.enter_review(Some(&creds.reviewer), &scope_a())
        .expect("reviewer reviews");
    // Bootstrap reviewer (ceiling 1) fails the publish ceiling first.
    assert_eq!(
        gate.enter_publish(Some(&creds.reviewer), &scope_a())
            .unwrap_err()
            .code(),
        "ceiling-exceeded"
    );
    // A high-ceiling reviewer still fails the role check (least privilege).
    let high = gate
        .issue(
            &CapabilityName::parse("reviewer-high-1").expect("cap"),
            &scope_a(),
            2,
            RoleKind::Reviewer,
            &KeyId::parse("key-reviewer-high-1").expect("key"),
            &synthetic_key("separation", "high"),
            &creds.publisher,
            &reason("separation-high"),
            &label("synthetic"),
        )
        .expect("high-ceiling reviewer");
    gate.enter_review(Some(&high), &scope_a())
        .expect("high reviewer reviews");
    assert_eq!(
        gate.enter_publish(Some(&high), &scope_a())
            .unwrap_err()
            .code(),
        "role-denied"
    );
    // Publisher publishes.
    gate.enter_publish(Some(&creds.publisher), &scope_a())
        .expect("publisher publishes");
}

// ---------------------------------------------------------------------------
// Secrets: synthetic only, redacted, never stored, no recovery flow.
// ---------------------------------------------------------------------------

#[test]
fn secrets_are_synthetic_redacted_and_never_stored() {
    let scratch = Scratch::new("secrets");
    let (gate, creds) = open_gate(&scratch, "access.db", &reason("secrets"));
    // Synthetic-only: bootstrap keys carry the prefix (enforced at parse).
    assert!(SyntheticKey::parse("real-key-1").is_err());
    // Redaction: length-only, value never rendered.
    for key in [creds.reviewer.key(), creds.publisher.key()] {
        let debug = format!("{key:?}");
        assert!(debug.contains("<redacted"), "{debug}");
        assert!(!debug.contains("synthetic-bootstrap"), "leak: {debug}");
    }
    for cred in [&creds.reviewer, &creds.publisher] {
        let debug = format!("{cred:?}");
        assert!(!debug.contains("synthetic-bootstrap"), "leak: {debug}");
    }
    // Refusal paths never echo key material.
    let forged = Credential::new(
        creds.reviewer.capability().clone(),
        creds.reviewer.key_id().clone(),
        synthetic_key("secrets", "other"),
    );
    let err = gate.enter_review(Some(&forged), &scope_a()).unwrap_err();
    assert_eq!(err.code(), "forged-credential");
    assert!(!err.to_string().contains("synthetic-"), "leak: {err}");
    // The store holds fingerprints, never raw keys.
    let rows = gate
        .store()
        .exec_script("SELECT quote(value_json) FROM outbox;")
        .expect("scan values");
    let dump = format!("{rows:?}");
    assert!(!dump.contains("synthetic-bootstrap"), "raw key in store");
    // No recovery flow: the gate exposes no API returning raw key material;
    // the only key holders are the returned credentials (moved values).
    assert!(gate.label_of(creds.reviewer.capability()).is_ok());
}
