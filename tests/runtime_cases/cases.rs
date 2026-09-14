use crate::{
    access,
    domain::scope::TrustedScope,
    fixture,
    helpers::*,
    runtime::{self, admission::WorkClass::*, Drain, Error, Runtime, State},
};
use std::time::{Duration, Instant};

#[test]
fn a01_default_is_inert_and_network_silent() {
    let mut runtime = Runtime::default();
    assert_eq!(runtime.status().state, State::Disabled);
    assert_eq!(runtime.status().network_calls, 0);
    assert_eq!(runtime.status().inert_handoffs, 0);
    assert_eq!(runtime.enqueue(CurrentSensing, KEY, lifetime()).unwrap_err().code(), "runtime-not-running");
    runtime.poll();
    assert_eq!(runtime.status().usage.retained, [0; 3]);
    assert_eq!(runtime.status().usage.running, [0; 3]);
}

#[test]
fn a02_absent_acceptance_refuses_startup() {
    let site = site(false, false);
    let mut runtime = Runtime::inert(&site.scratch.0, fixture::scope()).unwrap();
    runtime.begin_start(site.credential.clone()).unwrap();
    wait(&mut runtime, |r| r.status().state != State::Starting);
    assert_eq!(runtime.status().state, State::Held);
    assert_eq!(runtime.status().last_error, Some("runtime-no-acceptance"));
    assert_eq!(runtime.status().inert_handoffs, 0);
    stopped(&mut runtime);
}

#[test]
fn a02_unavailable_exact_content_refuses_restart() {
    let site = site(true, false);
    let mut runtime = start(&site);
    let generation = {
        let (accepted, seals, _) = runtime.test_stores();
        let active = accepted.active(&fixture::scope()).unwrap().unwrap();
        seals.capture_simulation(active.request().acceptance().seal()).unwrap().native_refs()[0].generation()
    };
    stopped(&mut runtime);
    std::fs::remove_file(site.scratch.native().join(format!("SNAPSHOT-{generation:020}.logical"))).unwrap();
    runtime.begin_start(site.credential.clone()).unwrap();
    wait(&mut runtime, |r| r.status().state != State::Starting);
    assert_eq!(runtime.status().state, State::Held);
    assert_eq!(runtime.status().last_error, Some("accept-blocked"));
    assert_eq!(runtime.status().inert_handoffs, 0);
    stopped(&mut runtime);
}

#[test]
fn a03_forged_and_cross_scope_callers_refuse() {
    let site = site(true, false);
    let mut runtime = Runtime::inert(&site.scratch.0, fixture::scope()).unwrap();
    let forged = access::Credential::new(
        site.credential.capability().clone(),
        site.credential.key_id().clone(),
        access::SyntheticKey::parse("synthetic-wrong-runtime-key").unwrap(),
    );
    runtime.begin_start(forged).unwrap();
    wait(&mut runtime, |r| r.status().state != State::Starting);
    assert_eq!(runtime.status().state, State::Held);
    assert_eq!(runtime.status().last_error, Some("forged-credential"));
    assert_eq!(runtime.status().inert_handoffs, 0);
    stopped(&mut runtime);
    drop(runtime);
    // Independent site avoids treating asynchronous native LOCK release as a
    // credential result. Publisher's entry scope remains scope-a, not scope-b.
    let other = crate::helpers::site(true, false);
    let mut runtime = Runtime::inert(&other.scratch.0, TrustedScope::parse("scope-b").unwrap()).unwrap();
    runtime.begin_start(other.credential.clone()).unwrap();
    wait(&mut runtime, |r| r.status().state != State::Starting);
    assert_eq!(runtime.status().state, State::Held);
    assert_eq!(runtime.status().last_error, Some("scope-denied"));
    assert_eq!(runtime.status().inert_handoffs, 0);
    stopped(&mut runtime);
}

#[test]
fn a04_stale_activation_at_handoff_emits_nothing() {
    let site = site(true, true);
    let mut runtime = start(&site);
    let latch = Latch::default();
    runtime.before_handoff = Some(latch.hook());
    let id = runtime.enqueue(CurrentSensing, KEY, lifetime()).unwrap();
    runtime.dispatch_next().unwrap();
    latch.entered();
    advance(&runtime, &site);
    latch.release();
    assert_eq!(result(&mut runtime, id).unwrap_err().code(), "runtime-stale-generation");
    assert_eq!(runtime.status().inert_handoffs, 0);
    assert_eq!(runtime.status().state, State::Held);
    stopped(&mut runtime);
}

#[test]
fn a04_superseded_callback_is_not_delivered() {
    let site = site(true, true);
    let mut runtime = start(&site);
    let latch = Latch::default();
    runtime.before_callback = Some(latch.hook());
    let id = runtime.enqueue(CurrentSensing, KEY, lifetime()).unwrap();
    runtime.dispatch_next().unwrap();
    latch.entered();
    advance(&runtime, &site);
    latch.release();
    assert_eq!(result(&mut runtime, id).unwrap_err().code(), "runtime-stale-generation");
    assert_eq!(runtime.status().inert_handoffs, 1); // cannot recall a past handoff
    assert_eq!(runtime.status().network_calls, 0);
    stopped(&mut runtime);
}

#[test]
fn a05_queue_deadline_expires_before_dispatch() {
    let site = site(true, false);
    let mut runtime = start(&site);
    assert_eq!(runtime.enqueue(CurrentSensing, KEY, Instant::now()).unwrap_err().code(), "runtime-deadline");
    let deadline = Instant::now() + Duration::from_millis(20);
    let id = runtime.enqueue(CurrentSensing, KEY, deadline).unwrap();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(runtime.dispatch_next().unwrap(), Some(id));
    assert_eq!(result(&mut runtime, id).unwrap_err().code(), "runtime-deadline");
    assert_eq!(runtime.status().inert_handoffs, 0);
    assert_eq!(runtime.status().usage.running, [0; 3]);
    stopped(&mut runtime);
}

#[test]
fn a06_optional_saturation_preserves_mandatory_reservations() {
    let site = site(true, false);
    let mut runtime = start(&site);
    for _ in 0..60 {
        runtime.enqueue(OptionalDiscovery, KEY, lifetime()).unwrap();
    }
    assert!(matches!(
        runtime.enqueue(OptionalDiscovery, KEY, lifetime()),
        Err(Error::Saturated { class: OptionalDiscovery, running: false })
    ));
    let sense = runtime.enqueue(CurrentSensing, KEY, lifetime()).unwrap();
    let reconcile = runtime.enqueue(Reconciliation, KEY, lifetime()).unwrap();
    runtime.enqueue(CurrentSensing, KEY, lifetime()).unwrap();
    runtime.enqueue(Reconciliation, KEY, lifetime()).unwrap();
    assert_eq!(runtime.status().usage.retained, [2, 2, 60]);
    assert_eq!(runtime.dispatch_next().unwrap(), Some(sense));
    result(&mut runtime, sense).unwrap();
    assert_eq!(runtime.dispatch_next().unwrap(), Some(reconcile));
    result(&mut runtime, reconcile).unwrap();
    assert_eq!(runtime.status().usage.retained, [1, 1, 60]);
    stopped(&mut runtime);
}

#[test]
fn a07_stop_reports_surviving_work_then_joins_actual_owner() {
    let site = site(true, false);
    let mut runtime = start(&site);
    let latch = Latch::default();
    runtime.before_callback = Some(latch.hook());
    let id = runtime.enqueue(CurrentSensing, KEY, lifetime()).unwrap();
    runtime.dispatch_next().unwrap();
    latch.entered();
    runtime.cancel(id).unwrap();
    assert_eq!(runtime.stop(Duration::ZERO).unwrap(), Drain::Unresolved { jobs: 1 });
    assert_eq!(runtime.status().usage.retained, [1, 0, 0]);
    assert_eq!(runtime.status().usage.running, [1, 0, 0]);
    assert_eq!(runtime.begin_start(site.credential.clone()).unwrap_err().code(), "runtime-not-stopped");
    assert!(matches!(Runtime::inert(&site.scratch.0, fixture::scope()), Err(Error::OwnerBusy)));
    assert!(runtime.take_result(id).is_none());
    latch.release();
    stopped(&mut runtime);
    assert!(runtime.take_result(id).is_none());
    assert_eq!(runtime.status().inert_handoffs, 1);
}

#[test]
fn a08_slow_unrelated_native_job_cannot_hold_handoff_hostage() {
    let site = site(true, false);
    let mut runtime = start(&site);
    let latch = Latch::default();
    let hook = latch.hook();
    runtime
        .test_native_job(move |native| {
            assert_eq!(native.execute("MATCH (r:Reading) RETURN r").unwrap().row_count, Some(1));
            hook(); // real native job remains owned; deterministic completion delay
        })
        .unwrap();
    latch.entered();
    let id = runtime.enqueue(CurrentSensing, KEY, lifetime()).unwrap();
    runtime.dispatch_next().unwrap();
    let raw = result(&mut runtime, id).unwrap();
    assert_eq!(raw.outcome, runtime::RawOutcome::NotAttemptedInert);
    assert_eq!(runtime.status().usage.running, [0, 0, 1]);
    assert_eq!(runtime.stop(Duration::ZERO).unwrap(), Drain::Unresolved { jobs: 1 });
    latch.release();
    stopped(&mut runtime);
}

#[test]
fn a09_repeated_start_stop_retains_one_owner_and_new_incarnations() {
    let site = site(true, false);
    let mut runtime = start(&site);
    let before = runtime.status();
    assert_eq!(runtime.begin_start(site.credential.clone()).unwrap_err().code(), "runtime-not-stopped");
    assert!(matches!(Runtime::inert(&site.scratch.0, fixture::scope()), Err(Error::OwnerBusy)));
    stopped(&mut runtime);
    runtime.begin_start(site.credential.clone()).unwrap();
    wait(&mut runtime, |r| r.status().state != State::Starting);
    let after = runtime.status();
    assert_eq!(after.state, State::RunningInert);
    assert_eq!(before.accepted_revision, after.accepted_revision);
    assert_eq!(before.active_generation, after.active_generation);
    assert_ne!(before.incarnation, after.incarnation);
    assert_ne!(before.source_generation, after.source_generation);
    assert!(matches!(Runtime::inert(&site.scratch.0, TrustedScope::parse("scope-b").unwrap()), Err(Error::OwnerBusy)));
    stopped(&mut runtime);
}

#[test]
fn a10_status_and_raw_receipt_do_not_upgrade_structural_meaning() {
    let site = site(true, false);
    let mut runtime = start(&site);
    let (_, _, gate) = runtime.test_stores();
    let before = gate
        .store()
        .exec_script("SELECT (SELECT count(*) FROM outbox),(SELECT count(*) FROM storage_receipts);")
        .unwrap();
    let id = runtime.enqueue(CurrentSensing, KEY, lifetime()).unwrap();
    runtime.dispatch_next().unwrap();
    let raw = result(&mut runtime, id).unwrap();
    assert_eq!(raw.binding_key.as_str(), "sat-binding");
    assert_eq!(raw.source.as_str(), "sensor-sat-1");
    assert_eq!(raw.endpoint, "mstp://ahu-1");
    assert_eq!(raw.property, "supply-air-temp");
    assert_eq!(raw.accepted_revision.get(), 1);
    assert_eq!(raw.active_generation.get(), 1);
    assert!(raw.source_time.is_none());
    assert_eq!(raw.receipt_origin, runtime::ReceiptOrigin::InertAdapterReturn);
    assert_eq!(raw.outcome, runtime::RawOutcome::NotAttemptedInert);
    assert!(!runtime.status().observed_qualification);
    assert_eq!(runtime.status().network_calls, 0);
    let (_, _, gate) = runtime.test_stores();
    assert_eq!(
        before,
        gate.store()
            .exec_script("SELECT (SELECT count(*) FROM outbox),(SELECT count(*) FROM storage_receipts);")
            .unwrap()
    );
    stopped(&mut runtime);
    assert!(!runtime.status().observed_qualification);
}

#[test]
fn current_inventory_has_independent_cli_expectation() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_verdant")).arg("capabilities").output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "verdant capabilities v1\nsetup: draft edit validate seal accept status read recovery (local synthetic access)\ncompiled: storage access native semantics binding seal acceptance api inert-runtime\nrun: no-field shell; runtime owner not configured or started\nruntime-api: explicit start; exact accepted/active content required; inert only\navailability: checked per operation; active pointer is not a lease\nqualification: unsupported; structural meaning is not observed qualification\nfield-authority: none\nlistener: none\nprotocols: no BACnet Modbus COV discovery or writes\n");
}

#[test]
fn a03_revocation_after_queue_refuses_handoff() {
    let site = site(true, false);
    let mut runtime = start(&site);
    let id = runtime.enqueue(CurrentSensing, KEY, lifetime()).unwrap();
    let (_, _, gate) = runtime.test_stores();
    gate.revoke(&site.credential, &access::Reason::parse("synthetic runtime revocation").unwrap()).unwrap();
    runtime.dispatch_next().unwrap();
    assert_eq!(result(&mut runtime, id).unwrap_err().code(), "revoked-credential");
    assert_eq!(runtime.status().inert_handoffs, 0);
    assert_eq!(runtime.status().state, State::Held);
    stopped(&mut runtime);
}

#[test]
fn a06_running_optional_work_cannot_consume_mandatory_capacity() {
    let site = site(true, false);
    let mut runtime = start(&site);
    let latches = [Latch::default(), Latch::default()];
    for latch in &latches {
        let hook = latch.hook();
        runtime.test_native_job(move |_| hook()).unwrap();
        latch.entered();
    }
    assert!(matches!(
        runtime.test_native_job(|_| {}),
        Err(Error::Saturated { class: OptionalDiscovery, running: true })
    ));
    assert_eq!(runtime.status().usage.running, [0, 0, 2]);
    let id = runtime.enqueue(Reconciliation, KEY, lifetime()).unwrap();
    runtime.dispatch_next().unwrap();
    result(&mut runtime, id).unwrap();
    assert_eq!(runtime.status().usage.running, [0, 0, 2]);
    for latch in latches {
        latch.release();
    }
    stopped(&mut runtime);
}

#[test]
fn a07_worker_panic_is_joined_and_reported_not_success() {
    let site = site(true, false);
    let mut runtime = start(&site);
    runtime.before_callback = Some(std::sync::Arc::new(|| panic!("synthetic inert callback failure")));
    let id = runtime.enqueue(CurrentSensing, KEY, lifetime()).unwrap();
    runtime.dispatch_next().unwrap();
    assert_eq!(result(&mut runtime, id).unwrap_err().code(), "runtime-worker-panic");
    assert_eq!(runtime.status().usage.running, [0; 3]);
    stopped(&mut runtime);
}
