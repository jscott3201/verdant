use crate::{accept, api, enumeration, manifest, query, setup, support::*, Scratch};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[test]
fn setup_validate_seal_accept_activate_clean_restart_recover() {
    journey(false);
}

#[test]
fn setup_validate_seal_accept_activate_killed_owner_restart_recover() {
    journey(true);
}

fn journey(crash: bool) {
    let mut f = setup();
    let inventory = manifest::Inventory::capture(&f.scratch);
    let before = Snapshot::take(&f.scratch);
    assert_eq!(before.counts, [8, 6, 5]);
    assert_eq!(before.events, [0; 4]);
    let setup_native = native_bytes(&f.scratch);
    assert_eq!(query(&f.scratch, "SELECT count(*) FROM outbox WHERE operation='binding-finding';"), "1\n");
    assert_eq!(f.native.execute(GRAPH).unwrap().row_count, Some(1));
    let status = f.api().status(Some(&credential()), &scope()).unwrap();
    assert_eq!(status.accepted_content, api::Availability::NoAcceptance);
    assert_eq!(status.operational, api::Readiness::Pending);
    assert!(status.active.is_none());
    before.unchanged(&f.scratch, "setup-api-readback");
    let (root, sequence) = f.close();
    before.unchanged(&root, "setup-owner-close");
    let finding = format!("binding-finding:{sequence}");
    let draft = ["--operation-id", DRAFT, "--entry", "m01-gate-binding|0|m01-gate-SAT", "--finding", &finding];
    let draft_output = "draft ok operation=api-m01-gate-draft draft=api-m01-gate-draft entries=1\n";
    assert_eq!(clean(cli(&root, "draft", &draft)), draft_output);
    let drafted = before.appended(&root, "CLI-draft", 2, [1, 0, 0, 0]);
    assert_eq!(clean(cli(&root, "draft", &draft)), draft_output);
    let validation = clean(cli(&root, "validate", &["--revision", DRAFT]));
    assert_eq!(validation, concat!("validate ok count=1 next_offset=none\n",
        "validate item Unqualified { key: \"m01-gate-binding\", status: \"valid\" }\n"));
    drafted.unchanged(&root, "CLI-retry-and-validate-unqualified-not-ready");
    assert!(setup_native == native_bytes(&root), "draft/validate must not mutate native content");
    let seal_args = ["--operation-id", SEAL, "--revision", DRAFT, "--binary", &inventory.binary, "--host", &inventory.host];
    let sealed_output = clean(cli(&root, "seal", &seal_args));
    assert!(sealed_output.contains("seal ok operation=api-m01-gate-seal"));
    let sealed = drafted.appended(&root, "CLI-seal-not-accepted", 2, [2, 1, 0, 0]);
    let native_snapshot = native_bytes(&root);
    assert!(setup_native != native_snapshot, "seal must capture an actual native checkpoint");
    assert!(clean(cli(&root, "seal", &seal_args)).contains("reconciled=true"));
    sealed.unchanged(&root, "CLI-seal-retry");
    let args = ["--operation-id", ACCEPT, "--seal-operation", SEAL, "--expected", "0"];
    let accept_output = clean(cli(&root, "accept", &args));
    let accepted_bytes = sealed.appended(&root, "CLI-accept-not-active", 2, [3, 1, 1, 0]);
    assert_eq!(clean(cli(&root, "accept", &args)), accept_output);
    accepted_bytes.unchanged(&root, "CLI-accept-retry");

    let mut owners = Owners::open(&root.0);
    let api::SealLookup::Committed { operation, commit } = owners.api()
        .sealed(Some(&credential()), &scope(), &op(DRAFT)).unwrap() else { panic!("not sealed") };
    assert_eq!(operation.as_str(), SEAL);
    inventory.verify_seal(&commit);
    inventory.record_seal(&root, &commit);
    assert_eq!(sealed_output, format!("seal ok operation={SEAL} identity={} row={} reconciled=false\n", commit.identity.as_str(), commit.row_id));
    let staged = owners.api().read(Some(&credential()), &scope(), &op(DRAFT)).unwrap();
    assert_eq!(staged.author, AUTHOR);
    assert_eq!(staged.staged_operation().as_str(), "accept-stage-api-m01-gate-draft");
    let entries = owners.api().entries(Some(&credential()), &scope(), &op(DRAFT), all()).unwrap().items;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key().as_str(), "m01-gate-binding");
    let owner = owners.accepted();
    let accepted = owner.current(&scope()).unwrap().unwrap();
    assert_eq!(accepted.revision.get(), 1);
    assert_eq!(accept_output, format!("accept ok operation={ACCEPT} revision=1 row={}\n", accepted.row_id));
    assert_eq!(accepted.request.operation().as_str(), "api-effect-api-m01-gate-accept");
    assert_eq!(accepted.request.staged_operation(), staged.staged_operation());
    assert_eq!(accepted.request.seal(), &commit.identity);
    assert_eq!(accepted.actor_reference, AUTHOR);
    assert_event(&root, "accept-revision-v1", &[
        "verdant-accepted-v1", "api-effect-api-m01-gate-accept", "0", "1", "scope-a",
        "accept-stage-api-m01-gate-draft", commit.identity.as_str(), AUTHOR, "accepted",
    ]);
    assert!(owner.active(&scope()).unwrap().is_none());
    accepted_bytes.unchanged(&root, "API-reopen-exact-accepted-publication");
    assert!(native_snapshot == native_bytes(&root), "seal retries/acceptance must not mutate native artifacts");
    let request = accept::ActivationRequest::new(op(ACTIVATE), accept::ActiveGeneration::INITIAL, accepted.request.clone());
    drop(owner);
    if crash {
        owners.close();
        kill_activated_owner(&root);
    } else {
        let active = owners.accepted().activate(&request, &owners.seals).unwrap();
        assert_eq!(active.generation().get(), 1);
        assert_eq!(active.revision(), accepted.revision);
        owners.close();
    }
    let activated_bytes = accepted_bytes.appended(&root, "API-activate-owner-stopped", 1, [3, 1, 1, 1]);
    assert_event(&root, "accept-active-v1", &[
        "verdant-active-v1", ACTIVATE, "0", "1", "scope-a", "api-effect-api-m01-gate-accept",
        "0", "1", "accept-stage-api-m01-gate-draft", commit.identity.as_str(), "activated",
    ]);
    let mut owners = Owners::open(&root.0);
    let owner = owners.accepted();
    let active = owner.reconcile_activation(&request).unwrap().unwrap();
    assert_eq!(active.generation().get(), 1);
    assert_eq!(active.revision().get(), 1);
    assert_eq!(active.request(), &request);
    assert!(active.reconciled());
    assert_eq!(owner.activate(&request, &owners.seals).unwrap().row_id(), active.row_id());
    assert_eq!(owner.current(&scope()).unwrap().unwrap().request, accepted.request);
    assert_eq!(owner.read_staged(staged.staged_operation()).unwrap().config().entries().values().cloned().collect::<Vec<_>>(), entries);
    assert_eq!(owners.api().submit_accept(Some(&credential()), &scope(), &op(ACCEPT)).unwrap().row_id, accepted.row_id);
    for actual in [
        owners.api().read_accepted(Some(&credential()), &scope(), all()).unwrap().unwrap().items,
        owners.api().read_active(Some(&credential()), &scope(), all()).unwrap().unwrap().items,
    ] { assert_eq!(actual, entries); }
    assert_eq!(owners.native.execute(GRAPH).unwrap().row_count, Some(1));
    let api::SealLookup::Committed { commit: recovered_seal, .. } = owners.api()
        .sealed(Some(&credential()), &scope(), &op(DRAFT)).unwrap() else { panic!("seal lost on restart") };
    assert_eq!(recovered_seal.identity, commit.identity);
    assert_eq!(recovered_seal.manifest, commit.manifest);
    assert_eq!(std::fs::read_to_string(root.0.join("m01-gate-seal-manifest.txt")).unwrap(),
        recovered_seal.manifest.canonical_bytes());
    let status = owners.api().status(Some(&credential()), &scope()).unwrap();
    assert_eq!(status.accepted_content, api::Availability::Available);
    assert_eq!(status.active_content, Some(api::Availability::Available));
    assert_eq!(status.operational, api::Readiness::Unknown);
    assert_eq!(status.field_authority, api::Readiness::Unsupported);
    assert_eq!(status.qualification, api::Readiness::Unsupported);
    let error = owner.transition(&accepted, accept::Stage::Qualified).unwrap_err();
    assert_eq!(error.code(), "accept-not-yet");
    drop(owner);
    activated_bytes.unchanged(&root, "recover-retry-qualified-refusal");
    owners.close();
    for view in ["accepted", "active"] {
        let read = clean(cli(&root, "read", &["--view", view]));
        assert!(read.starts_with("read ok count=1 next_offset=none\n"));
        assert!(read.contains("m01-gate-binding") && read.contains("m01-gate-SAT"));
    }
    activated_bytes.unchanged(&root, "CLI-recovered-accepted-and-active-readback");
    enumeration::no_field_dispatch(&root);
    activated_bytes.unchanged(&root, "shell-no-field-dispatch");
    assert!(native_snapshot == native_bytes(&root), "activation/restart/recovery/shell must preserve native bytes");
    assert_eq!(std::fs::read_to_string(root.0.join("m01-gate-manifest.txt")).unwrap(), inventory.text);
    assert_eq!(query(&root, "SELECT count(*) FROM outbox WHERE value_json LIKE '%synthetic-m01-gate-%';"), "0\n");
    println!("M01_G journey={} accepted_row={} active_row={} seal={} recovered_exactly=true field_dispatch=unsupported qualification=not-yet",
        if crash { "SIGKILL-process-crash" } else { "clean-close" }, accepted.row_id, active.row_id(), commit.identity.as_str());
}

// SQLite's JSON reader and a test-local framing decoder avoid using Verdant's
// encoder/decoder pair as the sole oracle for the committed event payloads.
fn assert_event(root: &Scratch, event: &str, expected: &[&str]) {
    let raw = query(root, &format!("SELECT json_extract(value_json,'$.value') FROM outbox WHERE operation='{event}';"));
    assert_eq!(manifest::fields(raw.strip_suffix('\n').unwrap()), expected);
    assert_eq!(query(root, &format!("SELECT unit,source_ms,receipt_ms,ingestion_ms,generation,seq,status,claimed_by,created_nanos FROM outbox WHERE operation='{event}';")),
        "count|0|0|0|gen-1|1|queued||0\n");
}

const CHILD: &str = "journey::activated_owner_child";
const CHILD_ENV: &str = "VERDANT_M01_GATE_CHILD_ROOT";
pub const CHILD_SKIP: &str = "M01_G skipped=activated-owner-child reason=parent-owned-kill-fixture-not-requested";

#[test]
fn activated_owner_child() {
    let Some(root) = std::env::var_os(CHILD_ENV) else {
        println!("{CHILD_SKIP}");
        return;
    };
    let owners = Owners::open(std::path::Path::new(&root));
    let owner = owners.accepted();
    let accepted = owner.current(&scope()).unwrap().unwrap();
    let request = accept::ActivationRequest::new(op(ACTIVATE), accept::ActiveGeneration::INITIAL, accepted.request);
    let active = owner.activate(&request, &owners.seals).unwrap();
    assert_eq!(active.generation().get(), 1);
    assert_eq!(owners.registry.store().execution_report().running, 0);
    println!("M01_G_ACTIVATED_COMMIT_READY");
    std::io::stdout().flush().unwrap();
    let mut one = [0u8];
    let _ = std::io::stdin().read_exact(&mut one);
    panic!("parent must kill this owner after COMMIT, not close stdin");
}

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn kill_activated_owner(root: &Scratch) {
    use std::os::unix::process::ExitStatusExt;
    // Declare before Reap so unwinding also reaps before closing the write end.
    let owner_stdin;
    let mut child = Reap(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD, "--nocapture"])
        .env(CHILD_ENV, &root.0).env("HOME", &root.0)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap());
    // Child::wait closes attached stdin before waiting. SIGKILL delivery can
    // race that EOF, so retain the pipe separately through the observed reap.
    owner_stdin = child.0.stdin.take().expect("piped owner stdin");
    let stdout = child.0.stdout.take().unwrap();
    let stderr = child.0.stderr.take().unwrap();
    let (ready, waiting) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            if line == "M01_G_ACTIVATED_COMMIT_READY" { ready.send(()).unwrap(); }
            output.push_str(&line);
            output.push('\n');
        }
        output
    });
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        BufReader::new(stderr).read_to_string(&mut text).unwrap();
        text
    });
    let ready = waiting.recv_timeout(Duration::from_secs(60));
    // Timeout means failure, never a recovered commit or a successful stop.
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    let output = reader.join().unwrap();
    let errors = errors.join().unwrap();
    assert!(ready.is_ok(), "child did not reach COMMIT: {output}\n{errors}");
    assert_eq!(status.signal(), Some(9));
    drop(owner_stdin);
    assert!(errors.is_empty(), "{errors}");
    assert!(output.contains("M01_G_ACTIVATED_COMMIT_READY"));
    println!("M01_G observed_owner_signal=9 reaped=true after_commit=true (not power-loss)");
}

pub fn assert_child_skip() {
    let output = clean(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD, "--nocapture"]).env_remove(CHILD_ENV)
        .stdin(Stdio::null()).output().unwrap());
    assert!(output.contains(CHILD_SKIP));
    assert!(output.contains("1 passed; 0 failed"));
    assert!(!output.contains("M01_G_ACTIVATED_COMMIT_READY"));
    println!("{CHILD_SKIP} (harness pass, not a crash execution)");
}
