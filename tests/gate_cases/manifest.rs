//! Test-side source/artifact inventory, not a new product attestation surface.
use crate::{native, query, seal, semantics, storage, support::clean, Scratch};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BASE: &str = "928c75dc6c5e5a3ea7ba3942cc07b0532629ad26";
const SELENE: &str = "b65c2344c916d2c3ceeb72cefcd72e7960e95e25";
const PROFILE: &str = "verdant-pinned-brick-223p-rec-v1";
const CONVERTER: &str = "verdant-converter-r07-v1";
const OWNED: &[&str] = &[
    "tests/m01_gate.rs", "tests/gate_cases/support.rs", "tests/gate_cases/journey.rs",
    "tests/gate_cases/manifest.rs", "tests/gate_cases/enumeration.rs",
];

pub fn run(exe: &str, args: &[&str]) -> String {
    clean(Command::new(exe).args(args).current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::null()).output().unwrap())
}
pub fn digest(path: &Path) -> String {
    let hash = || {
        let output = clean(Command::new("/usr/bin/shasum").args(["-a", "256"])
            .arg(path).stdin(Stdio::null()).output().unwrap());
        let (hex, name) = output.trim_end().split_once("  ").unwrap();
        assert_eq!(name, path.to_str().unwrap());
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        hex.to_owned()
    };
    let hex = hash();
    assert_eq!(hash(), hex, "digest changed for {}", path.display());
    hex
}
fn executable(name: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|dir| dir.join(name)).find(|p| p.is_file()).unwrap().canonicalize().unwrap()
}

fn version<const N: usize>(raw: &str) -> Option<[u64; N]> {
    raw.split('.').map(|part| {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) { return None; }
        part.parse().ok()
    }).collect::<Option<Vec<_>>>()?.try_into().ok()
}
fn supported_sqlite(raw: &str) -> bool {
    raw.split_whitespace().next().and_then(version::<3>)
        .is_some_and(|v| v[0] == 3 && v >= [3, 50, 0])
}
fn supported_shasum(raw: &str) -> bool {
    version::<2>(raw.trim()).is_some_and(|v| v >= [6, 0])
}

#[test]
fn tool_versions_are_environment_relative_with_explicit_floors() {
    for raw in ["3.50.0", "3.50.6 2025-07-30 ci-source (64-bit)\n", "3.54.0", "3.100.0"] {
        assert!(supported_sqlite(raw), "{raw}");
    }
    for raw in ["", "3.49.99", "2.99.0", "4.0.0", "3.50", "3.50.0.1", "3.+50.0", "3.50.x", "3.50.0-dev", "3.50.18446744073709551616"] {
        assert!(!supported_sqlite(raw), "{raw}");
    }
    for raw in ["6.00\n", "6.01\n", "6.02\n", "6.10\n", "7.00\n"] {
        assert!(supported_shasum(raw), "{raw}");
    }
    for raw in ["", "5.99", "6", "6.", "+6.02", "6.02.1", "6.02-dev", "6.02 extra", "6.18446744073709551616"] {
        assert!(!supported_shasum(raw), "{raw}");
    }
}

pub struct Inventory {
    pub binary: String,
    pub host: String,
    pub text: String,
    hash_tool: String,
}
impl Inventory {
    pub fn capture(root: &Scratch) -> Self {
        let head = run("git", &["rev-parse", "HEAD"]).trim().to_owned();
        assert_eq!(head.len(), 40);
        assert!(head.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(run("git", &["show", "-s", "--format=%H", "HEAD"]).trim(), head);
        assert!(Command::new("git").args(["merge-base", "--is-ancestor", BASE, &head])
            .current_dir(env!("CARGO_MANIFEST_DIR")).status().unwrap().success());
        // HEAD advances on delivery; never pin the eventual test commit to its parent.
        let rust = run("rustc", &["-V"]);
        let cargo = run("cargo", &["-V"]);
        assert_eq!(rust, "rustc 1.97.1 (8bab26f4f 2026-07-14)\n");
        assert_eq!(cargo, "cargo 1.97.1 (c980f4866 2026-06-30)\n");
        assert_eq!(env!("VERDANT_RUSTC_VERSION"), rust.trim());
        assert_eq!(env!("VERDANT_BUILD_TARGET"), "aarch64-apple-darwin");
        assert!(cfg!(debug_assertions), "M01-G evidence is debug only");
        assert!(include_str!("../../rust-toolchain.toml").contains("channel = \"1.97.1\""));
        assert!(include_str!("../../Cargo.toml").contains("rust-version = \"1.97.1\""));
        assert!(include_str!("../../Cargo.toml").contains(SELENE));
        assert!(include_str!("../../Cargo.lock").contains(&format!(
            "name = \"selene-db\"\nversion = \"2.0.0-alpha.1\"\nsource = \"git+https://github.com/jscott3201/selene-db.git?rev={SELENE}#{SELENE}\"")));
        assert_eq!(native::SELENE_REV, SELENE);
        assert_eq!(semantics::profile::PINNED_PROFILE_ID, PROFILE);
        assert_eq!(storage::SCHEMA_GENERATION, 1);
        assert_eq!(query(root, "SELECT generation,applied_note FROM schema_migrations ORDER BY generation;"),
            "1|M01-PR03 0001_init: initial tiny outbox\n2|R03 0002_receipts: admission and reconciliation\n");
        assert_eq!(query(root, "PRAGMA user_version;"), "1\n");
        // Source identities/toolchain/target stay exact. Host tool versions have
        // floors (SQLite 3.50.0 within major 3; shasum 6.0), not local equality.
        // The reviewed flag gate and SHA-256 known-answer probe enforce behavior.
        // Tool/binary bytes are host-relative: hash twice, check format, record;
        // never compare them to hardcoded bytes from a different build or host.
        let sqlite = run("sqlite3", &["--version"]);
        assert!(supported_sqlite(&sqlite), "unsupported sqlite3 version: {sqlite:?}");
        let shasum = run("/usr/bin/shasum", &["--version"]);
        assert!(supported_shasum(&shasum), "unsupported shasum version: {shasum:?}");
        let hash_tool = format!("/usr/bin/shasum -a 256; version={}", shasum.trim());
        assert_eq!(executable("sqlite3"), Path::new("/usr/bin/sqlite3"));
        assert_eq!(executable("shasum"), Path::new("/usr/bin/shasum"));
        let binary_digest = digest(Path::new(env!("CARGO_BIN_EXE_verdant")));
        let binary = format!("m01-gate-verdant-sha256-{binary_digest}");
        let host = "m01-gate-macos-arm64-debug".into();
        let mut text = format!(
            "head={head}\nbase={BASE}\nsource_state={}rust={rust}cargo={cargo}target=aarch64-apple-darwin\nprofile=debug\nsqlite3={sqlite}shasum={shasum}selene={SELENE}\nmigrations=0001_init,0002_receipts\nprofile_id={PROFILE}\nconverter={CONVERTER}\nbinary_sha256={binary_digest}\n",
            run("git", &["status", "--porcelain", "--untracked-files=all"]),
        );
        // Source bytes disambiguate an uncommitted test tree from HEAD. Digests of
        // system executables are measurements, not portable OS image pins.
        for file in OWNED.iter().copied().chain([
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
            "migrations/sqlite/0001_init.sql", "migrations/sqlite/0002_receipts.sql",
        ]) {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
            if OWNED.contains(&file) {
                let source = std::fs::read(&path).unwrap();
                let lines = source.iter().filter(|b| **b == b'\n').count();
                assert!(source.ends_with(b"\n"));
                assert!(lines <= 700, "{file}: {lines} lines exceeds staged cap");
                text.push_str(&format!("owned_lines {file}={lines}\n"));
            }
            text.push_str(&format!("sha256 {file}={}\n", digest(&path)));
        }
        for file in ["/usr/bin/sqlite3", "/usr/bin/shasum"] {
            text.push_str(&format!("sha256 {file}={}\n", digest(Path::new(file))));
        }
        println!("M01_G_MANIFEST\n{text}");
        std::fs::write(root.0.join("m01-gate-manifest.txt"), &text).unwrap();
        Self { binary, host, text, hash_tool }
    }
    pub fn verify_seal(&self, commit: &seal::SealCommit) {
        let parts = fields(&commit.manifest.canonical_bytes());
        assert_eq!(parts.len(), 14);
        assert_eq!(&parts[..3], ["verdant-seal-v1", "valid-structural-not-qualified", "scope-a"]);
        assert_eq!(&parts[4..7], ["1", PROFILE, CONVERTER]);
        let runtime = fields(&parts[7]);
        assert_eq!(runtime, [self.binary.as_str(), self.host.as_str(), "0.1.0",
            "rustc 1.97.1 (8bab26f4f 2026-07-14)", "aarch64-apple-darwin", SELENE]);
        assert_eq!(parts[8], crate::support::AUTHOR);
        assert_eq!(parts[9], self.hash_tool);
        assert_eq!(commit.manifest.row_count(), 2); // stage -> actor-joined finding
        assert_eq!(commit.manifest.native_refs().len(), 1);
        assert_eq!(commit.manifest.finding_fingerprints().len(), 1);
    }
    pub fn record_seal(&self, root: &Scratch, commit: &seal::SealCommit) {
        let path = root.0.join("m01-gate-seal-manifest.txt");
        std::fs::write(&path, commit.manifest.canonical_bytes()).unwrap();
        // Hash actual canonical bytes through the fixed-path external tool, not the
        // product's Manifest::identity implementation or a digest-shaped string.
        assert_eq!(digest(&path), commit.identity.as_str());
        println!("M01_G_MANIFEST seal_sha256={} canonical_bytes={} native_refs=1 finding_refs=1",
            commit.identity.as_str(), std::fs::metadata(path).unwrap().len());
    }
}

// Independent test decoder: exact UTF-8 byte lengths; no encoder-derived oracle.
pub fn fields(raw: &str) -> Vec<String> {
    let mut remaining = raw;
    let mut fields = Vec::new();
    while !remaining.is_empty() {
        let (length, body) = remaining.split_once(':').unwrap();
        let length: usize = length.parse().unwrap();
        let (value, rest) = body.split_at_checked(length).unwrap();
        fields.push(value.into());
        remaining = rest;
    }
    fields
}
