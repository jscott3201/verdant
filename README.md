# Verdant

A building operations application in development: native equipment semantics,
fault detection, qualified human controls, corrective work and evidence of
resolution. One application is planned for standalone, edge and hub profiles.

## Current status — 12 September 2026

B01 foundation PRs and B02's M01-PR07 binding PR are merged. The code includes
shared domain representations, a SQLite CLI-backed operational store,
synthetic scoped access, the actual public Selene lifecycle adapter, a small
synthetic semantic converter, and binding records/replay.

The entry point is still the local-only foundation shell. It does not activate
field acquisition, equipment writes, a PostgreSQL hub, MCP, candidate workers,
or a complete native-site acceptance workflow. Compiled modules and passing
isolated tests are not the same as those active services. M01-G has not passed.

The [current program handoff](https://github.com/jscott3201/verdant-program/blob/main/CODEX_HANDOFF.md)
and [implementation audit](https://github.com/jscott3201/verdant-program/blob/main/implementation/reviews/2026-09-12-entry-audit.md)
insert targeted storage, authority, binding and native-model repairs before
M01-PR11 seals and PR08 acceptance. Preserve the accepted B02 direction; this
is not a new project or another broad architecture pass.

Two narrow code drafts are open: [#10, finding status identity](https://github.com/jscott3201/verdant/pull/10)
and [#11, non-destructive native probes](https://github.com/jscott3201/verdant/pull/11).
Both passed their recorded GitHub build/full-test/smoke jobs and remain
unmerged for independent review. They do not close all audit findings.

## Build and local evidence

```sh
cargo build --locked
cargo test --locked
./target/debug/verdant health
./target/debug/verdant evidence
```

The toolchain is pinned to Rust/Cargo 1.97.1. The current direct dependency is
`selene-db 2.0.0-alpha.1` at
`b65c2344c916d2c3ceeb72cefcd72e7960e95e25` with default features.
SQLite is currently an external `sqlite3` executable, not a Rust-linked driver.
The local acceptance record states 3.54.0; the inspected macOS arm64 CI run
used 3.50.6. Record the actual executable and build for each validation.

The main CI run at `e4dc077936781dc7b956f3b0690797fd907282b4` reported 522
successful test executions. Some module tests repeat across integration
binaries; that number is not 522 distinct acceptance requirements. The CLI
`evidence` output is informational, not proof that a new test has run.

## Scope and safeguards

Use authorized synthetic fixtures and disposable local stores only. The
current keys are deliberately synthetic, and the semantic profile is a curated
three-class fixture, not validated full Brick/223P/REC support. The repairs
retain those useful fixtures while establishing the actual model and authority
boundaries required for later stages.

Human controls remain early planned scope, but no current native type, imported
status, credential label, model edit or green test grants field authority.
Preserve existing local-only exposure, exact pins, migration history and the
700-line/no-grandfather-growth rule. Follow [AGENTS.md](AGENTS.md) before changes.

The research, 73-slice core roadmap, four optional SC slices, accepted decisions
and execution records live in [verdant-program](https://github.com/jscott3201/verdant-program).
UI implementation is tracked separately. `Cargo.toml` remains `publish = false`;
distribution and licensing are owner decisions, not established by a build.
