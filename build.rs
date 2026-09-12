//! Build-time inventory for M01-PR01 diagnostics.
//!
//! Records the exact compiler and build target into the binary so
//! `verdant version --verbose` / `verdant health` report evidence, not guesses.
//! Local-only: invokes the pinned `rustc` from PATH, no network.

use std::process::Command;

fn main() {
    let rustc_version = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown (rustc not on build PATH)".to_string());

    // TARGET is set by Cargo for every build script invocation.
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=VERDANT_RUSTC_VERSION={rustc_version}");
    println!("cargo:rustc-env=VERDANT_BUILD_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
