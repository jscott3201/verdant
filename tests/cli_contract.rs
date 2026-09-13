//! Independent executable parsing and extended frozen-shell contract.
use std::{path::PathBuf, process::{Command, Output, Stdio}};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_verdant")).args(args).stdin(Stdio::null()).output().unwrap()
}
fn text(output: &Output) -> &str { std::str::from_utf8(&output.stdout).unwrap() }
fn success(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty());
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("verdant-cli-contract-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
}

#[test]
fn fixed_parser_refuses_before_config_io_and_help_needs_no_authentication() {
    let common = ["--config", "/absent/cli-config", "--scope", "scope-a", "--capability", "cli-owner", "--key-id", "cli-key"];
    for (verb, invalid) in [
        ("draft", vec![]),
        ("draft", vec!["--operation-id", "bad-namespace"]),
        ("draft", vec!["--operation-id", "api-ok", "--operation-id", "api-duplicate"]),
        ("edit", vec!["--operation-id", "api-edit"]),
        ("validate", vec!["--revision", "api-draft", "--size", "0"]),
        ("validate", vec!["--revision", "api-draft", "--size", "65"]),
        ("validate", vec!["--revision", "api-draft", "--size", "-1"]),
        ("seal", vec!["--revision", "api-draft", "--binary", "b"]),
        ("seal", vec!["--revision", "api-draft", "--binary", "b", "--host", "h", "--size", "1"]),
        ("accept", vec!["--operation-id", "api-accept", "--seal-operation", "api-seal", "--expected", "257"]),
        ("accept", vec!["--operation-id", "api-accept", "--seal-operation", "api-seal", "--expected", "abc"]),
        ("status", vec!["--offset", "257"]),
        ("status", vec!["--offset", "184467440737095516160"]),
        ("status", vec!["--size"]),
        ("status", vec!["--size", ""]),
        ("read", vec!["--view", "latest"]),
        ("read", vec!["--view", "accepted", "--revision", "api-draft"]),
        ("read", vec!["--view", "sealed", "--revision", "api-draft", "--offset", "0"]),
        ("recovery", vec!["--action", "bootstrap", "--operation-id", "api-recover", "--new-key-id", "new", "--new-secret-env", "UNSET"]),
        ("recovery", vec!["--action", "re-bootstrap", "--operation-id", "api-recover", "--new-key-id", "new", "--new-secret-env", "UNSET"]),
        ("recovery", vec!["--action", "rotate", "--operation-id", "api-recover", "--new-key-id", "new", "--new-secret-env", "UNSET", "--new-capability", "other"]),
    ] {
        let mut args = vec![verb]; args.extend(common); args.extend(invalid);
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("[api-"));
    }
    let help = run(&["--help"]); success(&help);
    for verb in ["draft", "edit", "validate", "seal", "accept", "status", "read", "recovery"] {
        let out = run(&[verb, "--help"]); success(&out); assert_eq!(out.stdout, help.stdout);
    }
    for contract in ["size 1..64", "offset 0..256", "0 success/diagnostics", "1 config/store/owner failure", "2 usage/invalid/page bounds", "3 access refusal", "4 conflict/frozen/canceled", "5 missing/pending content", "6 outcome unknown", "api- and be at most 80 bytes"] {
        assert!(text(&help).contains(contract), "{contract}");
    }
    println!("FIXED parser: 21 malformed/duplicate/overflow/unsupported combinations exit 2 before config IO; eight credential-free help paths; exit table and bounds visible");
}

#[test]
fn fixed_extended_shell_guard_full_bytes_and_no_store_activation() {
    let scratch = Scratch::new();
    let durable = scratch.0.join("durable with spaces");
    std::fs::create_dir(&durable).unwrap();
    let config = scratch.0.join("site.conf");
    std::fs::write(&config, format!("role = \"standalone\"\ndurable_path = \"{}\"\n", durable.display())).unwrap();
    let config_text = config.to_str().unwrap();
    let version = "verdant 0.1.0\n";
    for args in [vec!["version"], vec!["--version"], vec!["-V"]] {
        let out = run(&args); success(&out); assert_eq!(text(&out), version);
    }
    let compiler = env!("VERDANT_RUSTC_VERSION");
    let target = env!("VERDANT_BUILD_TARGET");
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    // Independent BASE literals, not calls into production renderers.
    let verbose = format!("verdant 0.1.0\nrustc: {compiler}\ntarget: {target}\nprofile: {profile}\nedition: 2021\ndependencies: selene-db 2.0.0-alpha.1 (git rev b65c2344; default features; system sqlite3 3.54.0 via std::process, not linked)\nfeatures: none\nnative libraries linked: none (system sqlite3 is present but NOT linked in PR01)\n");
    let out = run(&["version", "--verbose"]); success(&out); assert_eq!(text(&out), verbose);
    for configured in [false, true] {
        for verbose in [false, true] {
            let mut args = vec!["health"];
            if configured { args.extend(["--config", config_text]); }
            if verbose { args.push("--verbose"); }
            let out = run(&args); success(&out);
            let status = if configured { "checked" } else { "ok" };
            let mut expected = format!("verdant health {status}\nversion: 0.1.0\nrustc: {compiler}\ntarget: {target}\nprofile: {profile}\nfield_capability: absent (no field listener in PR01; native engine deferred to M01-PR05)\nlistener: none (local-only; PR01 binds no socket)\nstores: not-implemented (durable stores owned by M01-PR03)\nselene_native: bundled (selene-db 2.0.0-alpha.1 git rev b65c2344; lifecycle owned by M01-PR05)\nsqlite_linked: no (system sqlite3 present, not linked in PR01)\n");
            if verbose { expected.push_str("dependencies: selene-db 2.0.0-alpha.1 (git rev b65c2344; default features)\nfeatures: none\nnative libraries linked: none\n"); }
            if configured { expected.push_str(&format!("config: ok ({config_text})\nrole: standalone\ndurable_path: {} (present, directory)\nsecret: unconfigured (synthetic local actors only)\n", durable.display())); }
            else { expected.push_str("config: none supplied (role unconfigured)\n"); }
            assert_eq!(text(&out), expected);
        }
    }
    for once in [true, false] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_verdant"));
        command.args(["run", "--config", config_text]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if once { command.arg("--once"); }
        let child = command.spawn().unwrap(); let pid = child.id(); let out = child.wait_with_output().unwrap(); success(&out);
        let reason = if once { "once" } else { "stdin-eof" };
        assert_eq!(text(&out), format!("verdant starting role=standalone durable_path={} listener=none field_capability=absent pid={pid}\nverdant stopped reason={reason} role=standalone exit=0\n", durable.display()));
    }
    let evidence = run(&["evidence"]); success(&evidence);
    let expected = format!("# verdant evidence — M01-PR01 integration contract §6 (report; execution owned by cargo test + CI)\nprofile_selected: standalone (edge/hub validated through the same constrained path)\ntarget_tested: {target}\nprofile_built: {profile}\nrustc: {compiler}\nsource_note: tested source/tree and artifact are named by the validation handoff and CI manifest, not by this report (no self-referential report SHA)\n{}", include_str!("cli_cases/evidence_cases.txt"));
    assert_eq!(text(&evidence), expected);
    assert_eq!(std::fs::read_dir(&durable).unwrap().count(), 0);
    // Config auth refusal remains exit 1; no secret and no store creation.
    std::fs::write(&config, format!("role = \"standalone\"\ndurable_path = \"{}\"\nsecret_env = \"VERDANT_CLI_CONTRACT_MISSING\"\n", durable.display())).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_verdant")).args(["status", "--config", config_text, "--scope", "scope-a", "--capability", "owner", "--key-id", "key"]).env_remove("VERDANT_CLI_CONTRACT_MISSING").output().unwrap();
    assert_eq!(out.status.code(), Some(1)); assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("[unresolved-secret]"));
    assert_eq!(std::fs::read_dir(&durable).unwrap().count(), 0);
    println!("FIXED frozen bytes: version/verbose + four health modes + run once/EOF + full evidence; no stores activated; unresolved secret exit 1");
}
