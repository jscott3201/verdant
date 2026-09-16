//! verdant — M01-PR01 minimal entry point.
//!
//! One constrained local role at a time (`standalone` | `edge` | `hub`).
//! Local-only: PR01 binds no socket, creates no directories, runs no broker,
//! historian, workers or field acquisition. Diagnostics and the §6
//! evidence-completeness report are subcommands, not a new platform.

mod config;
// M01-PR02 shared domain (representation only; no CLI behavior change here).
// Allowed dead code until PR03/PR04/PR05/PR06 consume these types.
#[allow(dead_code)]
mod domain;
// M01-PR03 durable stores (SQLite envelope over the system sqlite3 CLI).
// Wiring only: the CLI surface is unchanged in this slice.
#[allow(dead_code)]
mod storage;
// M01-PR04 named capability ceilings and direct-entry access.
// Wiring only: the CLI surface is unchanged in this slice.
#[allow(dead_code)]
mod access;
// M01-PR05 Selene native lifecycle (single public/native facade).
// Wiring only: the CLI surface is unchanged in this slice.
#[allow(dead_code)]
mod native;
// M01-PR06 offline vocabulary import and conversion (pure/offline; no CLI
// surface change in this slice).
#[allow(dead_code)]
mod semantics;
// M01-PR07 equipment and proposed bindings (scoped records + proposals).
// Wiring only: the CLI surface is unchanged in this slice.
#[allow(dead_code)]
mod binding;
mod seal;
mod accept;
mod api;
mod runtime;
mod observation;
// M02-PR05 human action preview (synthetic-only templates; no CLI change here).
#[allow(dead_code)]
mod action_preview;
// M02-PR06 durable admission and per-target state (inert sink; no CLI change here).
#[allow(dead_code)]
mod action_journal;
// M02-PR07 controlled dispatch and observed outcomes (harness-only; no CLI change here).
#[allow(dead_code)]
mod action_dispatch;
// M02-PR08 normal expiry and exact release (harness-only policy; no CLI change here).
#[allow(dead_code)]
mod action_expiry;
// M02-PR11 uncertain effects and restart recovery (harness-only; no CLI change here).
#[allow(dead_code)]
mod action_recovery;
// M02-PR09 publication, replacement and exclusion (harness-only; no CLI change here).
#[allow(dead_code)]
mod action_publication;
// M02-PR12 maintenance, offboarding and current custody (harness-only; no CLI change here).
#[allow(dead_code)]
mod action_custody;
// M02 Slice C joined seal/admission/dispatch/wall path (harness-only; no CLI change here).
#[allow(dead_code)]
mod action_joined;
// M02-PR10 frozen action/capability manifest for UI + later MCP readers
// (read-only data; harness-only; no CLI change here).
#[allow(dead_code)]
mod action_manifest;
#[cfg(test)]
#[path = "../tests/cli_cases/errors.rs"]
mod cli_setup_errors;

use config::{load_from_path, Role};
use std::env;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const RUSTC_VERSION: &str = env!("VERDANT_RUSTC_VERSION");
const BUILD_TARGET: &str = env!("VERDANT_BUILD_TARGET");

fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

fn usage() -> String {
    format!(
        "verdant {VERSION} — M01-PR01 runnable workspace and profile boundaries (local-only)\n\
         \n\
         usage:\n\
         \x20 verdant version [--verbose]\n\
         \x20 verdant health [--config PATH] [--verbose]\n\
         \x20 verdant run --config PATH [--once] [--max-seconds N]\n\
         \x20 verdant evidence\n\
         \x20 verdant capabilities\n\
         \x20 verdant (draft|edit|validate|seal|accept|status|read|recovery) OPTIONS\n\
         \x20 verdant (-h|--help) | (-V|--version)\n\
         \n\
         setup OPTIONS (local synthetic access; existing stores only):\n\
         \x20 all: --config PATH --scope SCOPE --capability NAME --key-id ID\n\
         \x20 config secret_env supplies the synthetic key; durable_path contains meaning.db + native/\n\
         \x20 draft: --operation-id ID [--entry 'KEY|PROPOSAL_INDEX|LABEL']...\n\
         \x20 edit: --operation-id ID --revision PARENT [--entry 'KEY|PROPOSAL_INDEX|LABEL']...\n\
         \x20 draft/edit: full replacement inputs; [--intent 'KEY|PROPOSAL_INDEX|LABEL']...\n\
         \x20 [--finding 'OPERATION:SEQUENCE']...; proposal indexes are zero-based, no implicit selection\n\
         \x20 validate: --revision ID [--size N --offset N]; diagnostics (including Unqualified) exit 0\n\
         \x20 seal: --revision ID --binary REF --host REF [--operation-id ID]\n\
         \x20 accept: --operation-id ID --seal-operation ID --expected REVISION (0 initially)\n\
         \x20 status: [--size N --offset N] (scope status + operation page)\n\
         \x20 read: [--view revision|accepted|active|sealed] [--revision ID] [--size N --offset N]\n\
         \x20 revision/sealed views require --revision; sealed has no pagination\n\
         \x20 recovery: --action provision|re-bootstrap|rotate --operation-id ID\n\
         \x20 --new-key-id ID --new-secret-env ENV [--new-capability NAME (re-bootstrap only)]\n\
         \x20 recovery retains the API's scoped, synthetic, non-escalating policy; no initial bootstrap\n\
         \x20 pages: size 1..64 (default 64), offset 0..256 (default 0); beyond bounds refused\n\
         \x20 output: line-oriented verb ok + identity/page markers, Debug records (not a wire codec)\n\
         \x20 seal first captures native content; retries read original receipts, never claim pending success\n\
         \x20 retain operation IDs and exact inputs; pending seal needs owner reconciliation, not recapture\n\
         \x20 API operation IDs must start api- and be at most 80 bytes (existing API namespace)\n\
         \x20 exits: 0 success/diagnostics; 1 config/store/owner failure; 2 usage/invalid/page bounds;\n\
         \x20 3 access refusal; 4 conflict/frozen/canceled; 5 missing/pending content; 6 outcome unknown\n\
         \x20 refusals use stderr with [machine-code]; unknown outcomes retain the operation ID\n\
         \x20 example: verdant status --config site.conf --scope scope-a --capability publisher --key-id key-1\n\
         \n\
         run blocks until stdin EOF, --max-seconds elapses, or a signal ends it;\n\
         it consumes no commands on stdin and binds no socket."
    )
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            if args.len() > 2 {
                eprintln!("too many arguments for help");
                return ExitCode::from(2);
            }
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        "-V" | "--version" => {
            if args.len() > 1 {
                eprintln!("--version takes no arguments");
                return ExitCode::from(2);
            }
            println!("verdant {VERSION}");
            ExitCode::SUCCESS
        }
        "version" => cmd_version(&args[1..]),
        "health" => cmd_health(&args[1..]),
        "run" => cmd_run(&args[1..]),
        "evidence" => cmd_evidence(&args[1..]),
        "capabilities" => runtime::inventory::command(&args[1..]),
        "draft" | "edit" | "validate" | "seal" | "accept" | "status" | "read" | "recovery" =>
            cmd_setup(&args[0], &args[1..]),
        other => {
            eprintln!("unknown command '{other}'\n{}", usage());
            ExitCode::from(2)
        }
    }
}

fn cmd_version(args: &[String]) -> ExitCode {
    let mut verbose = false;
    for arg in args {
        if arg == "--verbose" {
            verbose = true;
        } else {
            eprintln!("unknown version flag '{arg}' (only --verbose)");
            return ExitCode::from(2);
        }
    }
    println!("verdant {VERSION}");
    if verbose {
        println!("rustc: {RUSTC_VERSION}");
        println!("target: {BUILD_TARGET}");
        println!("profile: {}", profile());
        println!("edition: 2021");
        // Compiled-in inventory fact (Cargo.toml direct dep + Cargo.lock pin via
        // the recorded native constants); never shelled out at runtime.
        let dep = crate::native::presence();
        let dep_rev_short = dep.rev.get(..8).unwrap_or(dep.rev);
        println!("dependencies: {} {} (git rev {dep_rev_short}; default features; system sqlite3 3.54.0 via std::process, not linked)", dep.facade, dep.crate_version);
        println!("features: none");
        println!("native libraries linked: none (system sqlite3 is present but NOT linked in PR01)");
    }
    ExitCode::SUCCESS
}

struct HealthOptions {
    config: Option<PathBuf>,
    verbose: bool,
}

fn parse_health_args(args: &[String]) -> Result<HealthOptions, String> {
    let mut config = None;
    let mut verbose = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--verbose" => verbose = true,
            "--config" => {
                i += 1;
                let value = args.get(i).ok_or("--config requires a PATH value")?;
                config = Some(PathBuf::from(value));
            }
            other => return Err(format!("unknown health flag '{other}' (only --config, --verbose)")),
        }
        i += 1;
    }
    Ok(HealthOptions { config, verbose })
}

fn cmd_health(args: &[String]) -> ExitCode {
    let opts = match parse_health_args(args) {
        Ok(opts) => opts,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    // Static build inventory first: true even when no config is supplied.
    // Native identity is the compiled-in pin (same constants as version); no runtime shell-out.
    let native = crate::native::presence();
    let native_rev_short = native.rev.get(..8).unwrap_or(native.rev);
    println!("verdant health {}", if opts.config.is_some() { "checked" } else { "ok" });
    println!("version: {VERSION}");
    println!("rustc: {RUSTC_VERSION}");
    println!("target: {BUILD_TARGET}");
    println!("profile: {}", profile());
    println!("field_capability: absent (no field listener in PR01; native engine deferred to M01-PR05)");
    println!("listener: none (local-only; PR01 binds no socket)");
    println!("stores: not-implemented (durable stores owned by M01-PR03)");
    println!("selene_native: bundled ({} {} git rev {native_rev_short}; lifecycle owned by M01-PR05)", native.facade, native.crate_version);
    println!("sqlite_linked: no (system sqlite3 present, not linked in PR01)");
    if opts.verbose {
        println!("dependencies: {} {} (git rev {native_rev_short}; default features)", native.facade, native.crate_version);
        println!("features: none");
        println!("native libraries linked: none");
    }
    match opts.config {
        None => {
            println!("config: none supplied (role unconfigured)");
            ExitCode::SUCCESS
        }
        Some(path) => match load_from_path(&path) {
            Ok(cfg) => {
                println!("config: ok ({})", path.display());
                println!("role: {}", cfg.role.as_str());
                println!("durable_path: {} (present, directory)", cfg.durable_path.display());
                match (&cfg.secret_env, &cfg.secret) {
                    (Some(var), Some(secret)) => println!(
                        "secret: env:{var}=present ({} chars, value redacted)",
                        secret.len()
                    ),
                    _ => println!("secret: unconfigured (synthetic local actors only)"),
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("verdant health error: {} [{}]", err, err.code());
                ExitCode::from(1)
            }
        },
    }
}

struct RunOptions {
    config: PathBuf,
    once: bool,
    max_seconds: Option<u64>,
}

fn parse_run_args(args: &[String]) -> Result<RunOptions, String> {
    let mut config: Option<PathBuf> = None;
    let mut once = false;
    let mut max_seconds: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                let value = args.get(i).ok_or("--config requires a PATH value")?;
                config = Some(PathBuf::from(value));
            }
            "--once" => once = true,
            "--max-seconds" => {
                i += 1;
                let value = args.get(i).ok_or("--max-seconds requires a value")?;
                max_seconds = Some(value.parse::<u64>().map_err(|_| {
                    format!("--max-seconds expects a non-negative integer, got '{value}'")
                })?);
            }
            other => {
                return Err(format!(
                    "unknown run flag '{other}' (only --config, --once, --max-seconds)"
                ))
            }
        }
        i += 1;
    }
    let config = config.ok_or("run requires --config PATH")?;
    Ok(RunOptions {
        config,
        once,
        max_seconds,
    })
}

/// A validated constrained role starts, reports readiness, then stops on an
/// explicit condition only: `--once`, `--max-seconds`, stdin EOF, or a fatal
/// signal. A stop is always an observed exit with a `stopped` line, never a
/// caller-side timeout inference.
fn cmd_run(args: &[String]) -> ExitCode {
    let opts = match parse_run_args(args) {
        Ok(opts) => opts,
        Err(message) => {
            eprintln!("{message}\n{}", usage());
            return ExitCode::from(2);
        }
    };
    let cfg = match load_from_path(&opts.config) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("verdant refuses to start: {} [{}]", err, err.code());
            return ExitCode::from(1);
        }
    };
    println!(
        "verdant starting role={} durable_path={} listener=none field_capability=absent pid={}",
        cfg.role.as_str(),
        cfg.durable_path.display(),
        std::process::id(),
    );
    // Flush readiness before blocking so a supervising caller observes start.
    use std::io::Write as _;
    let _ = io::stdout().flush();

    if opts.once {
        println!(
            "verdant stopped reason=once role={} exit=0",
            cfg.role.as_str()
        );
        return ExitCode::SUCCESS;
    }

    let reason = wait_for_stop(opts.max_seconds);
    println!(
        "verdant stopped reason={} role={} exit=0",
        reason,
        cfg.role.as_str()
    );
    ExitCode::SUCCESS
}

fn wait_for_stop(max_seconds: Option<u64>) -> String {
    let (tx, rx) = mpsc::channel::<&'static str>();
    std::thread::spawn(move || {
        let mut byte = [0u8; 1];
        loop {
            match io::stdin().read(&mut byte) {
                // EOF (supervisor closed stdin): explicit stop request.
                Ok(0) => {
                    let _ = tx.send("stdin-eof");
                    break;
                }
                // Any input byte is ignored; run consumes no stdin commands.
                Ok(_) => continue,
                Err(_) => {
                    let _ = tx.send("stdin-error");
                    break;
                }
            }
        }
    });
    match max_seconds {
        Some(budget) => match rx.recv_timeout(Duration::from_secs(budget)) {
            Ok(reason) => reason.to_string(),
            Err(mpsc::RecvTimeoutError::Timeout) => "max-seconds-elapsed".to_string(),
            Err(mpsc::RecvTimeoutError::Disconnected) => "stdin-closed".to_string(),
        },
        None => rx.recv().unwrap_or("stdin-closed").to_string(),
    }
}

fn json_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Integration contract §6 evidence-completeness report (introduction of the
/// required check for M01-PR01).
///
/// Informational only: pass/fail is owned by `cargo test` (which executes the
/// `executed` cases, including the `evidence_completeness` test that asserts
/// this report lists every required case) and by CI selection accounting.
/// `blocked` / `untested` / `report-only` rows never count as execution.
fn cmd_evidence(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        eprintln!("evidence takes no arguments");
        return ExitCode::from(2);
    }
    println!("# verdant evidence — M01-PR01 integration contract §6 (report; execution owned by cargo test + CI)");
    println!("profile_selected: standalone (edge/hub validated through the same constrained path)");
    println!("target_tested: {BUILD_TARGET}");
    println!("profile_built: {}", profile());
    println!("rustc: {RUSTC_VERSION}");
    println!("source_note: tested source/tree and artifact are named by the validation handoff and CI manifest, not by this report (no self-referential report SHA)");
    // case <id> <status> <verified_by> :: <note>
    let cases: &[(&str, &str, &str, &str)] = &[
        ("valid-standalone-start-stop", "executed", "tests/role_boundaries.rs valid_standalone_starts_and_stops", "starts, prints starting+stopped, observed exit 0"),
        ("valid-edge-start-stop", "executed", "tests/role_boundaries.rs valid_edge_starts_and_stops", "same constrained path as standalone"),
        ("valid-hub-start-stop", "executed", "tests/role_boundaries.rs valid_hub_starts_and_stops", "same constrained path as standalone"),
        ("refuse-unknown-role", "executed", "tests/role_boundaries.rs refuses_unknown_role", "names the bad value and lists standalone/edge/hub"),
        ("refuse-unknown-key", "executed", "tests/role_boundaries.rs refuses_unknown_key", "strict keys; allowed set named"),
        ("refuse-missing-durable-path", "executed", "tests/role_boundaries.rs refuses_missing_durable_path", "fails without creating the directory"),
        ("refuse-unresolved-secret", "executed", "tests/role_boundaries.rs refuses_unresolved_secret", "unset/empty secret_env is a refusal; value never logged"),
        ("field-capability-absent", "executed", "tests/role_boundaries.rs refuses_field_listener_request", "field_listener=true and [field] both refused"),
        ("no-field-listener-by-default", "executed", "tests/role_boundaries.rs omitted_field_setting_starts_no_listener", "omitted/false setting starts no listener; run reports listener=none"),
        ("version-health-diagnostics", "executed", "tests/role_boundaries.rs version_and_health_report_build_inventory", "version/health print compiler/target/profile/deps/features/native libs"),
        ("selene-library-oce-inventory", "report-only", "validation handoff (no implementation)", "actual compatibility inventoried; native engine deferred to M01-PR05 per D05"),
        ("durable-stores", "blocked", "M01-PR03 owns SQLite transactions/stores", "PR01 links no sqlite; missing schema must not become an empty usable store"),
        ("native-lifecycle", "blocked", "M01-PR05 owns public Selene lifecycle", "no native engine, salvage, or graph server here"),
        ("other-targets", "untested", "none (one supported target built first)", "only the reported target_tested is claimed; all others remain untested"),
    ];
    for (id, status, verified_by, note) in cases {
        println!("case {} {} {} :: {}", json_escape(id), status, json_escape(verified_by), json_escape(note));
    }
    // Keep Role referenced so role validation stays linked to this report.
    let _ = [Role::Standalone, Role::Edge, Role::Hub];
    ExitCode::SUCCESS
}

// PR09B: transport only. Existing owners authenticate, resolve, commit and reconcile.
type SetupResult<T> = Result<T, (u8, String)>;
fn setup_error(error: api::Error) -> (u8, String) {
    let exit = match &error {
        api::Error::Unauthenticated | api::Error::RecoveryRestricted => 3,
        api::Error::Invalid(_) | api::Error::Limit(_) => 2,
        api::Error::Conflict(_) | api::Error::SealedMutation | api::Error::Cancelled => 4,
        api::Error::Missing(_) => 5,
        api::Error::Unknown { .. } => 6,
        api::Error::Access(_) | api::Error::Binding(_) | api::Error::Accept(_) | api::Error::Seal(_)
        | api::Error::Storage(_) | api::Error::Io(_) => 1,
    };
    // Owner errors retain their stable code even when nested through API errors.
    let exit = match error.code() {
        "accept-invalid" | "accept-limit" | "seal-invalid" | "seal-limit" | "invalid-input" => 2,
        "accept-conflict" | "seal-conflict" | "conflict" | "sealed-mutation" => 4,
        "seal-missing-reference" => 5,
        "accept-unknown" | "seal-unknown" | "mutation-unknown" => 6,
        "anonymous-denied" | "forged-credential" | "scope-denied" | "role-denied"
        | "unknown-capability" | "unknown-issuer" | "stale-generation" | "not-bootstrapped"
        | "ceiling-exceeded" | "revoked-credential" | "expired-credential"
        | "administration-denied" | "policy-denied" | "api-recovery-restricted" => 3,
        _ => exit,
    };
    (exit, format!("[{}] {error}", error.code()))
}
fn setup_invalid(message: &'static str) -> (u8, String) {
    setup_error(api::Error::Invalid(message))
}
struct SetupOptions<'a>(std::collections::BTreeMap<&'a str, Vec<&'a str>>);
impl<'a> SetupOptions<'a> {
    fn parse(verb: &str, args: &'a [String]) -> SetupResult<Self> {
        let mut options = Self(std::collections::BTreeMap::new());
        if args.len() % 2 != 0 { return Err(setup_invalid("flags require values")); }
        for pair in args.chunks_exact(2) {
            let flag = pair[0].as_str();
            let allowed = matches!(flag, "--config" | "--scope" | "--capability" | "--key-id")
                || match verb {
                    "draft" => matches!(flag, "--operation-id" | "--entry" | "--intent" | "--finding"),
                    "edit" => matches!(flag, "--operation-id" | "--revision" | "--entry" | "--intent" | "--finding"),
                    "validate" => matches!(flag, "--revision" | "--size" | "--offset"),
                    "seal" => matches!(flag, "--revision" | "--binary" | "--host" | "--operation-id"),
                    "accept" => matches!(flag, "--operation-id" | "--seal-operation" | "--expected"),
                    "status" => matches!(flag, "--size" | "--offset"),
                    "read" => matches!(flag, "--revision" | "--view" | "--size" | "--offset"),
                    "recovery" => matches!(flag, "--action" | "--operation-id" | "--new-key-id" | "--new-secret-env" | "--new-capability"),
                    _ => false,
                };
            if !allowed || pair[1].is_empty() { return Err(setup_invalid("unknown flag or empty value")); }
            let values = options.0.entry(flag).or_default();
            if !values.is_empty() && !matches!(flag, "--entry" | "--intent" | "--finding") {
                return Err(setup_invalid("duplicate singleton flag"));
            }
            values.push(&pair[1]);
            if values.len() > 32 { return Err(setup_invalid("too many repeated inputs (maximum 32)")); }
        }
        for flag in ["--config", "--scope", "--capability", "--key-id"] { options.required(flag)?; }
        let required: &[&str] = match verb {
            "draft" => &["--operation-id"], "edit" => &["--operation-id", "--revision"],
            "validate" => &["--revision"], "seal" => &["--revision", "--binary", "--host"],
            "accept" => &["--operation-id", "--seal-operation", "--expected"],
            "recovery" => &["--action", "--operation-id", "--new-key-id", "--new-secret-env"],
            _ => &[],
        };
        for flag in required { options.required(flag)?; }
        for flag in ["--operation-id", "--revision", "--seal-operation"] {
            if options.value(flag).is_some() { options.operation(flag)?; }
        }
        if verb == "accept" && options.number("--expected", "0")? > 256 { return Err(setup_invalid("accepted revision 0..=256")); }
        if verb == "read" {
            match options.value("--view").unwrap_or("revision") {
                "revision" | "sealed" => { options.required("--revision")?; }
                "accepted" | "active" if options.value("--revision").is_none() => {}
                _ => return Err(setup_invalid("read view/revision combination")),
            }
            if options.value("--view") == Some("sealed") && (options.value("--size").is_some() || options.value("--offset").is_some()) {
                return Err(setup_invalid("sealed lookup is not paginated"));
            }
        }
        if verb == "recovery" {
            match options.required("--action")? {
                "re-bootstrap" => { options.required("--new-capability")?; }
                "provision" | "rotate" if options.value("--new-capability").is_none() => {}
                _ => return Err(setup_invalid("recovery action/new-capability combination")),
            }
        }
        options.page()?;
        Ok(options)
    }
    fn value(&self, flag: &str) -> Option<&str> { self.0.get(flag).map(|v| v[0]) }
    fn required(&self, flag: &str) -> SetupResult<&str> {
        self.value(flag).ok_or_else(|| (2, format!("[api-invalid] requires {flag}")))
    }
    fn number(&self, flag: &str, default: &str) -> SetupResult<usize> {
        self.value(flag).unwrap_or(default).parse().map_err(|_| setup_invalid("expected non-negative integer"))
    }
    fn page(&self) -> SetupResult<api::PageRequest> {
        api::PageRequest::new(self.number("--offset", "0")?, self.number("--size", "64")?).map_err(setup_error)
    }
    fn operation(&self, flag: &str) -> SetupResult<domain::ids::OperationId> {
        let raw = self.required(flag)?;
        if !raw.starts_with("api-") || raw.len() > 80 { return Err(setup_invalid("API operation namespace/length")); }
        domain::ids::OperationId::parse(raw).map_err(|_| setup_invalid("operation ID"))
    }
    fn entries(&self, flag: &str, registry: &binding::BindingRegistry) -> SetupResult<Vec<accept::Entry>> {
        self.0.get(flag).into_iter().flatten().map(|raw| {
            let mut fields = raw.splitn(3, '|');
            let key = domain::ids::InstalledId::parse(fields.next().unwrap_or("")).map_err(|_| setup_invalid("entry key"))?;
            let index: usize = fields.next().unwrap_or("").parse().map_err(|_| setup_invalid("proposal index"))?;
            let proposal = registry.bindings().get(index).ok_or_else(|| setup_invalid("proposal index absent"))?;
            accept::Entry::new(key, fields.next().unwrap_or(""), proposal.clone()).map_err(|e| setup_error(e.into()))
        }).collect()
    }
}
fn setup_key(variable: &str) -> SetupResult<access::SyntheticKey> {
    let mut bytes = env::var(variable).map_err(|_| (3, "[api-unauthenticated] secret env unresolved".into()))?.into_bytes();
    let key = std::str::from_utf8(&bytes).map_err(|_| setup_invalid("secret UTF-8"))
        .and_then(|text| access::SyntheticKey::parse(text).map_err(|e| setup_error(e.into())));
    bytes.fill(0); // Best effort, in addition to SyntheticKey/Config's zeroizing drop.
    key
}
fn cmd_setup(verb: &str, args: &[String]) -> ExitCode {
    if args == ["--help"] { println!("{}", usage()); return ExitCode::SUCCESS; }
    match SetupOptions::parse(verb, args).and_then(|options| run_setup(verb, &options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err((exit, message)) => { eprintln!("verdant {verb} refused: {message}"); ExitCode::from(exit) }
    }
}
fn setup_page<T: std::fmt::Debug>(verb: &str, page: api::Page<T>, options: &SetupOptions<'_>) -> SetupResult<()> {
    let next = if page.next.is_some() { (options.number("--offset", "0")? + options.number("--size", "64")?).to_string() } else { "none".into() };
    println!("{verb} ok count={} next_offset={next}", page.items.len());
    for item in page.items { println!("{verb} item {item:?}"); }
    Ok(())
}
fn run_setup(verb: &str, options: &SetupOptions<'_>) -> SetupResult<()> {
    use domain::{ids::OperationId, scope::TrustedScope};
    let cfg = load_from_path(&PathBuf::from(options.required("--config")?))
        .map_err(|e| (1, format!("[{}] {e}", e.code())))?;
    let scope = TrustedScope::parse(options.required("--scope")?).map_err(|_| setup_invalid("scope"))?;
    let credential = access::Credential::new(
        access::CapabilityName::parse(options.required("--capability")?).map_err(|e| setup_error(e.into()))?,
        access::KeyId::parse(options.required("--key-id")?).map_err(|e| setup_error(e.into()))?,
        setup_key(cfg.secret_env.as_deref().ok_or_else(|| setup_error(api::Error::Unauthenticated))?)?);
    let db = cfg.durable_path.join("meaning.db");
    let native_dir = cfg.durable_path.join("native");
    drop(cfg);
    if !db.is_file() { return Err(setup_error(api::Error::Missing("existing meaning.db required".into()))); }
    let gate = access::AccessGate::open(&db, storage::ConnectionSettings::local_wal_full(), storage::StoreBounds::tiny()).map_err(|e| setup_error(e.into()))?;
    // Rotation must reach API reconciliation even when its old key is revoked.
    if verb != "recovery" { gate.enter_review(Some(&credential), &scope).map_err(|e| setup_error(e.into()))?; }
    let mut registry = binding::BindingRegistry::open(&db, storage::ConnectionSettings::local_wal_full(), storage::StoreBounds::tiny()).map_err(|e| setup_error(e.into()))?;
    let (native, _) = native::NativeHandle::open(&native_dir, native::NativeSettings::local()).map_err(|e| (1, format!("[{}] {e}", e.code())))?;
    let seals = seal::SealStore::open(registry.store().try_clone().map_err(|e| setup_error(e.into()))?, native.clone()).map_err(|e| setup_error(e.into()))?;
    let (domain, intent) = (options.entries("--entry", &registry)?, options.entries("--intent", &registry)?);
    let mut api = api::Api::new(&gate, &mut registry, &seals).map_err(setup_error)?;
    let auth = Some(&credential);
    match verb {
        "draft" | "edit" => {
            let findings = options.0.get("--finding").into_iter().flatten().map(|raw| {
                let (op, seq) = raw.rsplit_once(':').ok_or_else(|| setup_invalid("finding OPERATION:SEQUENCE"))?;
                api::Reference::new(OperationId::parse(op).map_err(|_| setup_invalid("finding operation"))?, seq.parse().map_err(|_| setup_invalid("finding sequence"))?).map_err(setup_error)
            }).collect::<SetupResult<Vec<_>>>()?;
            let content = api.resolve(auth, &scope, domain, intent, findings).map_err(setup_error)?;
            let op = options.operation("--operation-id")?;
            let revision = if verb == "draft" { api.draft(auth, &op, &content).map_err(setup_error)? } else {
                let (revision, impact) = api.edit(auth, &op, &options.operation("--revision")?, &content).map_err(setup_error)?;
                println!("edit impact {impact:?}"); revision
            };
            println!("{verb} ok operation={} draft={} entries={}", revision.operation.as_str(), revision.draft.as_str(), revision.entry_count());
        }
        "validate" => setup_page(verb, api.validate(auth, &scope, &options.operation("--revision")?, options.page()?).map_err(setup_error)?, options)?,
        "read" => match options.value("--view").unwrap_or("revision") {
            "revision" => setup_page(verb, api.entries(auth, &scope, &options.operation("--revision")?, options.page()?).map_err(setup_error)?, options)?,
            "sealed" => match api.sealed(auth, &scope, &options.operation("--revision")?).map_err(setup_error)? {
                api::SealLookup::Committed { operation, commit } => println!("read ok operation={} identity={} row={}", operation.as_str(), commit.identity.as_str(), commit.row_id),
                api::SealLookup::Pending { operation } => return Err(setup_error(api::Error::Missing(format!("pending-not-sealed:{}", operation.as_str())))),
            },
            view => {
                let page = if view == "accepted" { api.read_accepted(auth, &scope, options.page()?) } else { api.read_active(auth, &scope, options.page()?) }.map_err(setup_error)?;
                match page { Some(page) => setup_page(verb, page, options)?, None => println!("read ok {view}=none") }
            }
        },
        "status" => {
            let status = api.status(auth, &scope).map_err(setup_error)?;
            let page = api.operations(auth, &scope, options.page()?).map_err(setup_error)?;
            println!("status scope {status:?}"); setup_page(verb, page, options)?;
        }
        "seal" => {
            gate.enter_publish(auth, &scope).map_err(|e| setup_error(e.into()))?;
            let revision = options.operation("--revision")?;
            api.read(auth, &scope, &revision).map_err(setup_error)?;
            let prior = match api.sealed(auth, &scope, &revision) {
                Ok(api::SealLookup::Committed { commit, .. }) => Some(commit),
                Ok(api::SealLookup::Pending { operation }) => return Err(setup_error(api::Error::Missing(format!("pending-not-sealed:{}", operation.as_str())))),
                Err(api::Error::Missing(_)) => None,
                Err(error) => return Err(setup_error(error)),
            };
            let op = match options.value("--operation-id") {
                Some(_) => options.operation("--operation-id")?,
                None => OperationId::parse(&format!("api-cli-seal-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| setup_invalid("clock before epoch"))?.as_nanos())).map_err(|_| setup_invalid("seal operation"))?,
            };
            let publication = api::Publication { binary: options.required("--binary")?.into(), host: options.required("--host")?.into(),
                native: match prior { Some(commit) => commit.manifest.native_refs().to_vec(), None => vec![seal::NativeRef::capture(&native, seals.hash_tool()).map_err(|e| setup_error(e.into()))?] } };
            let result = api.seal(auth, &scope, &op, &revision, &publication);
            let (operation, commit) = match result {
                Ok(commit) => (op.clone(), commit),
                Err(api::Error::SealedMutation) => match api.sealed(auth, &scope, &revision).map_err(setup_error)? {
                    api::SealLookup::Committed { operation, .. } => {
                        // Re-check original immutable inputs, not just the freeze error.
                        let commit = api.seal(auth, &scope, &operation, &revision, &publication).map_err(setup_error)?;
                        (operation, commit)
                    }
                    api::SealLookup::Pending { operation } => return Err(setup_error(api::Error::Missing(format!("pending-not-sealed:{}", operation.as_str())))),
                },
                Err(error) => { let (exit, message) = setup_error(error); return Err((exit, format!("operation={} {message}", op.as_str()))); }
            };
            println!("seal ok operation={} identity={} row={} reconciled={}", operation.as_str(), commit.identity.as_str(), commit.row_id, commit.reconciled);
        }
        "accept" => {
            let op = options.operation("--operation-id")?;
            let expected = options.required("--expected")?.parse().map_err(|_| setup_invalid("accepted revision"))?;
            let accepted = api.accept(auth, &scope, &op, &options.operation("--seal-operation")?, accept::AcceptedRevision::new(expected).map_err(|e| setup_error(e.into()))?).map_err(setup_error)?;
            println!("accept ok operation={} revision={} row={}", op.as_str(), accepted.revision.get(), accepted.row_id);
        }
        "recovery" => {
            let op = options.operation("--operation-id")?;
            let id = access::KeyId::parse(options.required("--new-key-id")?).map_err(|e| setup_error(e.into()))?;
            let key = setup_key(options.required("--new-secret-env")?)?;
            let action = options.required("--action")?;
            let issued = match action {
                "provision" => api.provision_recovery(auth, &scope, &op, &id, &key),
                "rotate" => api.recover(auth, &scope, &op, api::RecoveryAction::Rotate { key_id: &id, key: &key }),
                _ => {
                    let replacement = access::Credential::new(access::CapabilityName::parse(options.required("--new-capability")?).map_err(|e| setup_error(e.into()))?, id, key);
                    api.recover(auth, &scope, &op, api::RecoveryAction::Rebootstrap { replacement: &replacement })
                }
            }.map_err(setup_error)?;
            println!("recovery ok action={action} operation={} capability={} key_id={}", op.as_str(), issued.capability().as_str(), issued.key_id().as_str());
        }
        _ => return Err(setup_invalid("unknown setup verb")),
    }
    Ok(())
}
