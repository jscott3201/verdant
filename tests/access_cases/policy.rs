use super::*;
use domain::clock::UnixMillis;
use storage::sqlite::{
    faults::{self, Fault},
    MutationOutcome,
};

fn issue_policy(
    gate: &AccessGate,
    admin: &Credential,
    name: &str,
    policy: &CapabilityPolicy,
) -> Result<Credential, AccessError> {
    gate.issue_with_policy(
        &CapabilityName::parse(name).unwrap(),
        &scope("scope-a"),
        2,
        RoleKind::Publisher,
        &KeyId::parse(&format!("key-{name}")).unwrap(),
        &key(name),
        admin,
        &reason(),
        &DisplayLabel::parse("synthetic").unwrap(),
        policy,
    )
}

#[test]
fn r05_policy_and_actor_facts_survive_reopen_and_rotation() {
    let scratch = Scratch::new();
    let (gate, creds) = scratch.bootstrap();
    let end = UnixMillis::new(4_000_000_000_000);
    let policy = CapabilityPolicy::administrator(vec![scope("scope-b")], 1, Some(end)).unwrap();
    let delegated = issue_policy(&gate, &creds.publisher, "delegated", &policy).unwrap();
    let report = gate
        .enter_publish(Some(&delegated), &scope("scope-a"))
        .unwrap();
    let actor = report.actor().clone();
    assert_eq!(actor.user(), SYNTHETIC_USER_TEXT);
    assert_eq!(actor.issuer(), BOOTSTRAP_ISSUER_TEXT);
    assert_eq!(actor.capability(), "delegated");
    assert_eq!(actor.key_id(), "key-delegated");
    assert_eq!(actor.cap_generation(), 1);
    assert_eq!(actor.ceiling().scope(), &scope("scope-a"));
    assert_eq!(actor.ceiling().level(), 2);
    assert_eq!(actor.role(), RoleKind::Publisher);
    assert_eq!(actor.policy(), &policy);
    drop(gate);
    let reopened = open(&scratch.db());
    let before = snapshot(&scratch.db());
    assert_eq!(
        reopened
            .authenticate(Some(&delegated), &scope("scope-a"))
            .unwrap(),
        actor
    );
    assert_eq!(before, snapshot(&scratch.db()));
    let rotated = rotate(&reopened, &delegated, "key-delegated-next").unwrap();
    let next = reopened
        .authenticate(Some(&rotated), &scope("scope-a"))
        .unwrap();
    assert_eq!(next.policy(), &policy);
    assert_eq!(next.user(), actor.user());
    assert_eq!(next.capability(), actor.capability());
    assert_eq!(next.cap_generation(), 2);
    let before = snapshot(&scratch.db());
    assert_eq!(
        issue(&reopened, &rotated, "escape-scope", "scope-a", 1)
            .unwrap_err()
            .code(),
        "scope-denied"
    );
    assert_eq!(
        issue(&reopened, &rotated, "escape-ceiling", "scope-b", 2)
            .unwrap_err()
            .code(),
        "ceiling-exceeded"
    );
    assert_eq!(
        issue(&reopened, &rotated, "escape-expiry", "scope-b", 1)
            .unwrap_err()
            .code(),
        "policy-denied"
    );
    assert_eq!(before, snapshot(&scratch.db()));
    // Independent wire fragment, not encoder output: expiry/scopes are persisted.
    assert!(before
        .rows
        .contains("admin=1;scopes=scope-b;expires=4000000000000"));
    let child = reopened
        .issue_with_policy(
            &CapabilityName::parse("bounded-child").unwrap(),
            &scope("scope-b"),
            1,
            RoleKind::Reviewer,
            &KeyId::parse("key-bounded-child").unwrap(),
            &key("bounded-child"),
            &rotated,
            &reason(),
            &DisplayLabel::parse("synthetic").unwrap(),
            &CapabilityPolicy::entry_only(Some(end)),
        )
        .unwrap();
    reopened
        .enter_review(Some(&child), &scope("scope-b"))
        .unwrap();
    println!("FIXED policy/actor: scope, ceiling, admin and expiry persisted; stable user/capability across rotation; bounded child enters");
}

#[test]
fn r05_expiry_and_policy_refusals_preserve_rows_counts_bytes() {
    let scratch = Scratch::new();
    let (gate, creds) = scratch.bootstrap();
    let before = snapshot(&scratch.db());
    let policy = CapabilityPolicy::entry_only(Some(UnixMillis::new(0)));
    assert_eq!(
        issue_policy(&gate, &creds.publisher, "expired", &policy)
            .unwrap_err()
            .code(),
        "expired-credential"
    );
    let overreach = CapabilityPolicy::administrator(vec![scope("scope-c")], 2, None).unwrap();
    assert_eq!(
        issue_policy(&gate, &creds.publisher, "scope-escape", &overreach)
            .unwrap_err()
            .code(),
        "policy-denied"
    );
    let overreach = CapabilityPolicy::administrator(vec![scope("scope-a")], 3, None).unwrap();
    assert_eq!(
        issue_policy(&gate, &creds.publisher, "admin-escape", &overreach)
            .unwrap_err()
            .code(),
        "policy-denied"
    );
    assert_eq!(before, snapshot(&scratch.db()));
    // Persist an expired policy using the operator corruption probe; reopen
    // must enforce the record, not substitute a default non-expiring policy.
    raw(&scratch.db(), "UPDATE outbox SET value_json=replace(value_json,'expires=none','expires=0') WHERE entity='publisher-1';");
    let before = snapshot(&scratch.db());
    let reopened = open(&scratch.db());
    for result in [
        reopened.enter_review(Some(&creds.publisher), &scope("scope-a")),
        reopened.enter_publish(Some(&creds.publisher), &scope("scope-a")),
    ] {
        assert_eq!(result.unwrap_err().code(), "expired-credential");
    }
    assert_eq!(
        issue(&reopened, &creds.publisher, "expired-admin", "scope-a", 1)
            .unwrap_err()
            .code(),
        "expired-credential"
    );
    assert_eq!(
        rotate(&reopened, &creds.publisher, "expired-rotate")
            .unwrap_err()
            .code(),
        "expired-credential"
    );
    assert_eq!(
        reopened
            .revoke(&creds.publisher, &reason())
            .unwrap_err()
            .code(),
        "expired-credential"
    );
    assert_eq!(before, snapshot(&scratch.db()));
    println!("FIXED expired policy: entry/issue/rotate/revoke refuse after reopen; rows/counts/bytes unchanged");
}

#[test]
fn r05_rotation_precommit_and_unknown_reconciliation() {
    let scratch = Scratch::new();
    let (gate, creds) = scratch.bootstrap();
    let before = snapshot(&scratch.db());
    faults::inject(&scratch.db(), Fault::BeforeCommit);
    assert!(rotate(&gate, &creds.reviewer, "key-interrupted").is_err());
    assert_eq!(before, snapshot(&scratch.db()));
    gate.enter_review(Some(&creds.reviewer), &scope("scope-a"))
        .unwrap();
    faults::inject(&scratch.db(), Fault::LostResponse);
    let error = rotate(&gate, &creds.reviewer, "key-unknown").unwrap_err();
    assert_eq!(error.code(), "mutation-unknown");
    let AccessError::MutationUnknown { operation, .. } = error else {
        panic!("typed UNKNOWN");
    };
    let committed = snapshot(&scratch.db());
    assert_eq!(committed.counts.trim(), "5|3|2");
    assert!(matches!(
        gate.store().reconcile_operation(&operation),
        MutationOutcome::Committed { .. }
    ));
    assert!(matches!(
        gate.store().reconcile_operation(&operation),
        MutationOutcome::Committed { .. }
    ));
    assert_eq!(committed, snapshot(&scratch.db()));
    let successor = Credential::new(
        creds.reviewer.capability().clone(),
        KeyId::parse("key-unknown").unwrap(),
        key("key-unknown"),
    );
    assert_eq!(
        gate.enter_review(Some(&successor), &scope("scope-a"))
            .unwrap()
            .cap_generation,
        2
    );
    let execution = gate.store().execution_report();
    assert_eq!(execution.running, 0);
    assert_eq!(execution.spawned, execution.reaped);
    println!("FIXED rotation: precommit rows/counts/bytes unchanged; UNKNOWN reconciles same identity counts=5|3|2 survivors=0");
}

#[test]
fn r05_reopen_empty_and_partial_state_never_mints() {
    let scratch = Scratch::new();
    let gate = open(&scratch.db());
    let before = snapshot(&scratch.db());
    let invented = Credential::new(
        CapabilityName::parse(PUBLISHER_CAP_TEXT).unwrap(),
        KeyId::parse(PUBLISHER_KEY_TEXT).unwrap(),
        key("invented"),
    );
    assert_eq!(
        gate.enter_publish(Some(&invented), &scope("scope-a"))
            .unwrap_err()
            .code(),
        "not-bootstrapped"
    );
    assert_eq!(
        issue(&gate, &invented, "invented", "scope-a", 1)
            .unwrap_err()
            .code(),
        "not-bootstrapped"
    );
    drop(gate);
    drop(open(&scratch.db()));
    assert_eq!(before, snapshot(&scratch.db()));
    let (gate, creds) = scratch.bootstrap();
    raw(
        &scratch.db(),
        "DELETE FROM outbox WHERE operation='access-bootstrap';",
    );
    let before = snapshot(&scratch.db());
    drop(gate);
    let gate = open(&scratch.db());
    assert_eq!(
        gate.enter_publish(Some(&creds.publisher), &scope("scope-a"))
            .unwrap_err()
            .code(),
        "invalid-record"
    );
    assert_eq!(
        issue(&gate, &creds.publisher, "fallback", "scope-a", 1)
            .unwrap_err()
            .code(),
        "invalid-record"
    );
    assert_eq!(before, snapshot(&scratch.db()));
    println!("FIXED reopen-no-fallback: empty/partial rows/counts/bytes preserved; no credentials issued");
}

#[test]
fn r05_malformed_record_probes_preserve_the_probe() {
    for sql in [
        "UPDATE outbox SET value_json=replace(value_json,'v=2','v=1') WHERE entity='reviewer-1';",
        "UPDATE outbox SET value_json=replace(value_json,'expires=none','expires=tomorrow') WHERE entity='reviewer-1';",
        "UPDATE outbox SET value_json=replace(value_json,'admin=none;scopes=','admin=9;scopes=scope-a') WHERE entity='reviewer-1';",
        "UPDATE outbox SET value_json=replace(value_json,';expires=none','') WHERE entity='reviewer-1';",
        "UPDATE outbox SET value_json=replace(value_json,';expires=none',';expires=none;expires=none') WHERE entity='reviewer-1';",
        "UPDATE outbox SET value_json=replace(value_json,';expires=none',';expires=none;extra=1') WHERE entity='reviewer-1';",
        "UPDATE outbox SET entity='other' WHERE entity='reviewer-1';",
        "UPDATE outbox SET operation='access-revoke' WHERE entity='reviewer-1';",
        "UPDATE outbox SET value_json=replace(value_json,'synthetic-operator-1','other-user') WHERE entity='reviewer-1';",
    ] {
        let scratch = Scratch::new();
        let (gate, creds) = scratch.bootstrap();
        raw(&scratch.db(), sql);
        let before = snapshot(&scratch.db());
        assert_eq!(gate.enter_review(Some(&creds.reviewer), &scope("scope-a")).unwrap_err().code(), "invalid-record", "{sql}");
        assert_eq!(gate.enter_publish(Some(&creds.reviewer), &scope("scope-a")).unwrap_err().code(), "invalid-record", "{sql}");
        assert_eq!(rotate(&gate, &creds.reviewer, "key-probe").unwrap_err().code(), "invalid-record", "{sql}");
        assert_eq!(gate.revoke(&creds.reviewer, &reason()).unwrap_err().code(), "invalid-record", "{sql}");
        assert_eq!(before, snapshot(&scratch.db()), "probe was not preserved: {sql}");
    }
    println!("FIXED nine malformed probes: both entries/rotate/revoke fail closed; exact probe rows/counts/bytes preserved");
}

#[test]
fn r05_actor_context_construction_is_access_private() {
    let scratch = Scratch::new();
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/access_cases/fixtures/forged_actor.rs");
    let out = std::process::Command::new("rustc")
        .args(["--edition=2021", "--emit=metadata"])
        .arg(&source)
        .arg("-o")
        .arg(scratch.0.join("forged.rmeta"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    let errors = String::from_utf8(out.stderr).unwrap();
    assert!(
        errors.contains("E0624") && errors.contains("E0277"),
        "wrong compile failure: {errors}"
    );
    println!("FIXED actor construction: rustc refuses private constructor and parsed-scope conversion (E0624/E0277)");
}

#[test]
fn r05_clock_expiry_is_checked_at_the_writer_boundary() {
    let scratch = Scratch::new();
    let (gate, creds) = scratch.bootstrap();
    // The application snapshot's clock is before the deadline, while SQLite's
    // real wall clock at mutation is after it. No sleeps or scheduling guesses.
    let before = snapshot(&scratch.db());
    let result = access::testing::with_clock(-1, || {
        issue_policy(
            &gate,
            &creds.publisher,
            "boundary-expiry",
            &CapabilityPolicy::entry_only(Some(UnixMillis::new(0))),
        )
    });
    assert_eq!(result.unwrap_err().code(), "policy-denied");
    assert_eq!(before, snapshot(&scratch.db()));
    raw(&scratch.db(), "UPDATE outbox SET value_json=replace(value_json,'expires=none','expires=100') WHERE entity='reviewer-1';");
    let before = snapshot(&scratch.db());
    access::testing::with_clock(99, || {
        gate.enter_review(Some(&creds.reviewer), &scope("scope-a"))
            .unwrap();
    });
    for now in [100, 101] {
        access::testing::with_clock(now, || {
            assert_eq!(
                gate.enter_review(Some(&creds.reviewer), &scope("scope-a"))
                    .unwrap_err()
                    .code(),
                "expired-credential"
            );
        });
    }
    assert_eq!(before, snapshot(&scratch.db()));
    println!("FIXED expiry: before/at/after deadline and SQL writer-boundary check; rows/counts/bytes preserved");
}

#[test]
fn r05_fresh_store_simultaneous_bootstraps() {
    let scratch = Scratch::new();
    let barrier = Barrier::new(2);
    let results = std::thread::scope(|s| {
        let boot = || {
            barrier.wait();
            AccessGate::bootstrap(
                &scratch.db(),
                ConnectionSettings::local_wal_full(),
                StoreBounds::tiny(),
                &reason(),
            )
        };
        let a = s.spawn(boot);
        let b = s.spawn(boot);
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
    assert_eq!(snapshot(&scratch.db()).counts.trim(), "3|3|1");
    println!(
        "FIXED simultaneous fresh-file bootstrap: winners=1 loser=AlreadyBootstrapped counts=3|3|1"
    );
}
