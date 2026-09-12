//! verdant — M01-PR01 minimal entry point.
//!
//! One constrained local role at a time (`standalone` | `edge` | `hub`).
//! Local-only: PR01 binds no socket, creates no directories, runs no broker,
//! historian, workers or field acquisition. Diagnostics and the §6
//! evidence-completeness report are subcommands, not a new platform.

mod config;

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
         \x20 verdant (-h|--help) | (-V|--version)\n\
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
        println!("dependencies: none (std-only; no source downloads beyond the pinned toolchain)");
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
    println!("verdant health {}", if opts.config.is_some() { "checked" } else { "ok" });
    println!("version: {VERSION}");
    println!("rustc: {RUSTC_VERSION}");
    println!("target: {BUILD_TARGET}");
    println!("profile: {}", profile());
    println!("field_capability: absent (no field listener in PR01; native engine deferred to M01-PR05)");
    println!("listener: none (local-only; PR01 binds no socket)");
    println!("stores: not-implemented (durable stores owned by M01-PR03)");
    println!("selene_native: not-bundled (report only; lifecycle owned by M01-PR05)");
    println!("sqlite_linked: no (system sqlite3 present, not linked in PR01)");
    if opts.verbose {
        println!("dependencies: none (std-only)");
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
