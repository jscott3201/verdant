//! The negative sweep composes owning suites; a map is NOT execution evidence.
//! Full cargo test must execute those suites. Only the missing gate composition,
//! kill-pattern, reason enumeration and manifest are new scenarios here.
use crate::{api, journey, manifest, native, setup, support::*, Scratch};
use std::process::{Command, Stdio};

pub const SWEEP: &[(&str, &str, &str)] = &[
    ("counterfeit-scope", "tests/api_cases/operations.rs", "fixed_authentication_and_scope_refusals_preserve_rows_events_and_bytes"),
    ("ambiguous-binding", "tests/binding_proposals.rs", "ambiguous_feedback_is_refused"),
    ("competing-acceptance", "tests/accept_cases/transitions.rs", "fixed_conflicting_expected_revisions_have_one_winner_and_zero_row_conflict"),
    ("lost-response", "tests/accept_cases/transitions.rs", "fixed_lost_response_reconciles_same_event_and_reused_identity_refuses"),
    ("missing-nested-content", "tests/seal_cases/refusals.rs", "missing_nested_ref_and_cycle_refuse_without_rows"),
    ("missing-accepted-content", "tests/api_cases/lifecycle.rs", "fixed_pagination_refuses_bounds_and_unavailable_content_does_not_erase_acceptance"),
    ("stale-activation-callback", "tests/activation_cases/ordering.rs", "stale_callbacks_and_historical_recovery_never_restore_superseded_pointer"),
    ("native-debt", "tests/native_maintenance.rs", "r09_post_checkpoint_dirty_recovery_repair_and_shutdown"),
    ("long-reader-pressure", "src/storage/sqlite/execution_tests.rs", "r04_wal_behind_reader_is_accounted_and_degraded_until_checkpoint"),
    ("queue-pressure", "tests/storage_sqlite.rs", "handoff_full_is_a_refusal_not_a_drop"),
    ("owner-shutdown", "tests/native_maintenance.rs", "r09_bootstrap_refusals_and_stale_close_authority_preserve_files"),
    ("sqlite-owner-shutdown", "src/storage/sqlite/execution_tests.rs", "r04_drop_cancels_staged_transaction_before_releasing_permit"),
    ("dispatched-caller-shutdown", "tests/api_cases/lifecycle.rs", "fixed_cancel_before_dispatch_is_inspectable_and_lost_caller_reconciles_after_join"),
    ("no-field-dispatch", "tests/role_boundaries.rs", "refuses_field_listener_request"),
];

#[test]
fn milestone_negative_bullets_have_explicit_owner_suites() {
    let mut bullets = std::collections::BTreeSet::new();
    for &(bullet, file, case) in SWEEP {
        assert!(bullets.insert(bullet));
        let source = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file)).unwrap();
        assert!(source.contains(&format!("#[test]\nfn {case}(")), "mapped test missing: {file}::{case}");
        println!("M01_G_SWEEP composed={bullet} owner={file}::{case} execution=required-full-suite");
    }
    assert_eq!(bullets, std::collections::BTreeSet::from([
        "counterfeit-scope", "ambiguous-binding", "competing-acceptance", "lost-response",
        "missing-nested-content", "missing-accepted-content", "stale-activation-callback",
        "native-debt", "long-reader-pressure", "queue-pressure", "owner-shutdown",
        "sqlite-owner-shutdown", "dispatched-caller-shutdown", "no-field-dispatch",
    ])); // combined bullets split to distinguish native/SQLite/dispatcher ownership
    println!("M01_G_SWEEP added=adapter-composition,post-activation-SIGKILL,reason-enumeration,source-artifact-manifest");
}

/// Extract just one existing workflow run block, failing if its shape changes.
/// This tests actual selection/empty-execution shell, not a parallel policy model.
fn workflow(step: &str) -> String {
    let source = include_str!("../../.github/workflows/pr01.yml");
    let block = source.split_once(&format!("      - name: {step}\n")).unwrap().1;
    let body = block.split_once("        run: |\n").unwrap().1;
    let mut out = String::new();
    for line in body.lines() {
        if line.is_empty() { out.push('\n'); }
        else if let Some(line) = line.strip_prefix("          ") {
            out.push_str(line); out.push('\n');
        } else { break; }
    }
    assert!(!out.trim().is_empty());
    out
}

#[test]
fn mandatory_skipped_empty_and_blocked_cases_have_reasons_not_silent_passes() {
    let root = Scratch::new();
    let selection = workflow("Classify selection (product vs docs-only)")
        .replace("${{ github.event_name }}", "pull_request")
        .replace("${{ github.event.pull_request.base.sha }}", "m01-gate-base")
        .replace("${{ github.event.before }}", "m01-gate-base");
    assert!(!selection.contains("${{"));
    // Git diff is the selection input seam. All classification logic is unchanged.
    for (files, expected, reason) in [
        ("", "no-changes", "Empty change set: skipping product execution (NOT a product pass)."),
        ("README.md\nAGENTS.md", "docs-only", "Docs-only selection: product tests are SKIPPED and must not be claimed as run."),
        ("tests/m01_gate.rs", "product", "Product selection: executing build + tests."),
    ] {
        let output_path = root.0.join(format!("m01-gate-{expected}"));
        let code = format!("git() {{ printf '%s' \"$M01_GATE_DIFF\"; }}\n{selection}");
        let output = clean(Command::new("bash").args(["-c", &code])
            .env("M01_GATE_DIFF", files).env("GITHUB_OUTPUT", &output_path)
            .current_dir(&root.0).output().unwrap());
        assert!(output.contains(reason));
        assert_eq!(std::fs::read_to_string(output_path).unwrap(), format!("selection={expected}\n"));
        println!("M01_G_ENUM selection={expected} reason={reason}");
    }
    let empty_gate = workflow("Test — full run, empty execution fails (product execution)");
    let gate = &empty_gate[empty_gate.find("passed=\"").unwrap()..];
    for log in ["", "     Summary [   0.010s] 0 tests run: 0 passed, 0 skipped\n",
        "test result: ok. 99 passed; 0 failed; 0 ignored\n"] {
        std::fs::write(root.0.join("pr01-test.log"), log).unwrap();
        let output = Command::new("bash").args(["-c", gate]).current_dir(&root.0).output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(String::from_utf8(output.stdout).unwrap().contains("empty tests: 0 tests executed — an empty run does NOT pass."));
    }
    println!("M01_G_ENUM empty-log,zero-tests,nested-libtest-only=refused exit=3 reason=empty-execution-not-pass");
    std::fs::write(root.0.join("pr01-test.log"), "test result: ok. 99 passed; 0 failed\n     Summary [   0.010s] 5 tests run: 5 passed, 0 skipped\n").unwrap();
    let positive = clean(Command::new("bash").args(["-c", gate]).current_dir(&root.0).output().unwrap());
    assert!(positive.contains("Executed passing test instances (across binaries): 5"));
    // Fail the external tool-install seam; use CI's implicit bash -e. No build,
    // test, or downstream inventory may be mistaken for completed setup.
    let install = workflow("Install pinned toolchain (setup layer)");
    let code = format!("rustup() {{ printf 'm01-gate synthetic installer failure\\n' >&2; return 42; }}\nrustc() {{ printf 'UNEXPECTED compiler'; }}\ncargo() {{ printf 'UNEXPECTED cargo'; }}\n{install}");
    let blocked = Command::new("bash").args(["-e", "-c", &code]).current_dir(&root.0).output().unwrap();
    assert_eq!(blocked.status.code(), Some(42));
    assert!(blocked.stdout.is_empty());
    assert_eq!(blocked.stderr, b"m01-gate synthetic installer failure\n");
    println!("M01_G_ENUM setup=blocked exit=42 reason=installer-failure downstream-not-run (fault-injected setup seam)");
    journey::assert_child_skip();
    let evidence = manifest::run(env!("CARGO_BIN_EXE_verdant"), &["evidence"]);
    let nonexecuted: Vec<_> = evidence.lines().filter(|l| l.starts_with("case ") && !l.split_whitespace().nth(2).is_some_and(|s| s == "executed")).collect();
    assert_eq!(nonexecuted.len(), 4);
    for (id, state, reason) in [
        ("selene-library-oce-inventory", "report-only", "actual compatibility inventoried; native engine deferred to M01-PR05 per D05"),
        ("durable-stores", "blocked", "PR01 links no sqlite; missing schema must not become an empty usable store"),
        ("native-lifecycle", "blocked", "no native engine, salvage, or graph server here"),
        ("other-targets", "untested", "only the reported target_tested is claimed; all others remain untested"),
    ] {
        let line = nonexecuted.iter().find(|l| l.starts_with(&format!("case {id} {state} "))).unwrap();
        assert!(line.ends_with(&format!(" :: {reason}")));
        println!("M01_G_ENUM historical-PR01 {id}={state} reason={reason}");
    }
    // Historical report wording is NOT current module capability. Actually open
    // an empty native directory: neither a usable store nor silent bootstrap.
    let error = native::NativeHandle::open(&root.0.join("native"), native::NativeSettings::local()).unwrap_err();
    assert_eq!(error.code(), "not-initialized");
    assert!(matches!(&error, native::NativeError::NotInitialized { detail, .. } if !detail.is_empty()));
    assert_eq!(std::fs::read_dir(root.0.join("native")).unwrap().count(), 0);
    println!("M01_G_ENUM empty-native=refused reason={error}");
}

#[test]
fn reviewed_sqlite_flag_surface_is_unchanged_and_supported() {
    let code = workflow("SQLite CLI flag compatibility (product execution)");
    let output = clean(Command::new("bash").args(["-c", &code])
        .current_dir(env!("CARGO_MANIFEST_DIR")).stdin(Stdio::null()).output().unwrap());
    assert!(output.contains("Source-derived sqlite3 flags:"));
    println!("M01_G_FLAGS digest=377203c4df62680336b5b0aa426bcc97d9854ebce820d51940d44a357e1e9968 unchanged=true exact-argv-memory-probe=true\n{output}");
}

#[test]
fn empty_publication_and_absent_acceptance_are_explicit_non_success_states() {
    let mut f = setup();
    let content = f.content.clone();
    f.api().draft(Some(&credential()), &op(DRAFT), &content).unwrap();
    let before = Snapshot::take(&f.scratch);
    let api = f.api();
    let status = api.status(Some(&credential()), &scope()).unwrap();
    assert_eq!(status.accepted_content, api::Availability::NoAcceptance);
    assert_eq!(status.operational, api::Readiness::Pending);
    assert!(api.read_accepted(Some(&credential()), &scope(), all()).unwrap().is_none());
    let missing = api.sealed(Some(&credential()), &scope(), &op(DRAFT)).unwrap_err();
    assert!(matches!(missing, api::Error::Missing(ref reason) if reason == "seal:api-m01-gate-draft"));
    let error = f.api().seal(Some(&credential()), &scope(), &op(SEAL), &op(DRAFT), &api::Publication {
        binary: "m01-gate-empty".into(), host: "m01-gate-local".into(), native: vec![],
    }).unwrap_err();
    assert!(matches!(error, api::Error::Invalid("explicit native content required")));
    assert_eq!(error.code(), "api-invalid");
    before.unchanged(&f.scratch, "empty-native-publication-no-acceptance");
    println!("M01_G_ENUM no-acceptance=pending missing-seal={missing} empty-publication=refused reason={error}");
    f.close();
}

pub fn no_field_dispatch(root: &Scratch) {
    let config = config(root);
    let health = clean(Command::new(env!("CARGO_BIN_EXE_verdant"))
        .args(["health", "--config"]).arg(&config).env("M01_GATE_SECRET", SECRET)
        .env("HOME", &root.0).stdin(Stdio::null()).output().unwrap());
    let expected = format!(concat!(
        "verdant health checked\nversion: 0.1.0\nrustc: rustc 1.97.1 (8bab26f4f 2026-07-14)\n",
        "target: {}\nprofile: debug\n",
        "field_capability: absent (no field listener in PR01; native engine deferred to M01-PR05)\n",
        "listener: none (local-only; PR01 binds no socket)\n",
        "stores: not-implemented (durable stores owned by M01-PR03)\n",
        "selene_native: bundled (selene-db 2.0.0-alpha.1 git rev b65c2344; lifecycle owned by M01-PR05)\n",
        "sqlite_linked: no (system sqlite3 present, not linked in PR01)\n",
        "config: ok ({})\nrole: standalone\ndurable_path: {} (present, directory)\n",
        "secret: env:M01_GATE_SECRET=present ({} chars, value redacted)\n"),
        env!("VERDANT_BUILD_TARGET"), config.display(), root.0.display(), SECRET.len());
    assert_eq!(health.as_bytes(), expected.as_bytes());
    let child = Command::new(env!("CARGO_BIN_EXE_verdant"))
        .args(["run", "--config"]).arg(&config).arg("--once")
        .env("M01_GATE_SECRET", SECRET).env("HOME", &root.0)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = child.id();
    let run = clean(child.wait_with_output().unwrap());
    assert_eq!(run, format!("verdant starting role=standalone durable_path={} listener=none field_capability=absent pid={pid}\nverdant stopped reason=once role=standalone exit=0\n", root.0.display()));
    for (extra, marker) in [("field_listener = true\n", "field-capability-absent"), ("role = \"nope\"\n", "unknown-role")] {
        let text = if marker == "unknown-role" {
            format!("{extra}durable_path = \"{}\"\n", root.0.display())
        } else { format!("role = \"standalone\"\ndurable_path = \"{}\"\n{extra}", root.0.display()) };
        std::fs::write(&config, text).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_verdant"))
            .args(["run", "--config"]).arg(&config).arg("--once")
            .env("HOME", &root.0).stdin(Stdio::null()).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr).unwrap().contains(&format!("[{marker}]")));
    }
    for (limit, reason) in [
        ("power-loss", "process-kill leaves OS caches intact"),
        ("disk-full", "synthetic budgets are not physical ENOSPC qualification"),
        ("host-global", "handle-family bounds are not host-global quotas"),
        ("real-auth", "only synthetic access credentials; no IdP/crypto qualification"),
        ("field-dispatch", "Unsupported and field-capability-absent; no physical acquisition/control"),
    ] { println!("M01_G_LIMIT {limit}=unqualified reason={reason}"); }
    println!("M01_G_SMOKE exact-health+run-bytes=true observed_exit=0 refused-role+field-exit=1");
}
