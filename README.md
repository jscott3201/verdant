# Verdant

Verdant is an open-source building-operations application: fault detection,
qualified human equipment control, corrective work, and evidence of resolution.

> Early-foundation state: the workspace runs and the shared domain contracts
> exist, but the operational pieces (durable stores, native engine, field
> acquisition, hub coordination, MCP surface, background workers) are not
> built yet.

## Current status

M01 foundations are in progress:

- Delivered: runnable workspace with constrained local roles (`standalone` |
  `edge` | `hub`) and shared domain contracts (identities, values, times,
  operation outcomes).
- Not yet: durable stores, native lifecycle, field acquisition, hub
  coordination, MCP surface, background workers.

`src/main.rs` (the `evidence` subcommand) and `src/domain/mod.rs` state the
exact boundaries.

## Quick start

Prerequisite: Rust 1.97.1, pinned by `rust-toolchain.toml` (picked up
automatically by rustup).

```sh
cargo build --locked
cargo test --locked
./target/debug/verdant version
./target/debug/verdant health
./target/debug/verdant evidence
```

`version` and `health` report the build inventory (compiler, target, profile);
`evidence` prints the integration-contract evidence report. The report is
informational — pass/fail is owned by `cargo test` and CI.

## Project layout

- `src/config` — role and configuration boundaries (validated local roles,
  strict keys, refusal on bad input).
- `src/domain` — shared representation contracts: identities, values, times,
  operation outcomes. Representation only; no runtime, stores, or field
  acquisition here.
- `tests` — boundary and contract tests (`role_boundaries.rs`, `contracts/`).

## Contributing

PRs target `main` with review and green checks (see
`.github/workflows/pr01.yml`). Keep changes scoped; docs-only changes must
not claim product tests ran.

## License

No license terms have been chosen yet — distribution terms are TBD.
