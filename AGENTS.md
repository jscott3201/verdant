# AGENTS.md

Agent instructions for Verdant. Complements `README.md` (human overview);
this file is the normative working contract for automated changes. It follows
the agents.md open format: one file of practical commands and boundaries, no
tutorial bloat.

## Project overview

- One Rust binary crate (`verdant`, `src/main.rs`), zero dependencies
  (std-only). `Cargo.toml` sets `publish = false`.
- All builds and tests run with `--locked`; the toolchain is pinned to 1.97.1
  by `rust-toolchain.toml` (changing the pin is an owner decision, not a
  build convenience).
- Local-only foundation: binds no socket, creates no directories at startup,
  runs no broker, historian, workers, or field acquisition.

## Build / test commands

```sh
cargo build --locked
cargo test --locked
./target/debug/verdant evidence   # informational report; execution owned by cargo test + CI
```

- CI lives at `.github/workflows/pr01.yml`: selection policy, build, full
  test run (empty execution fails), evidence report, and smoke
  start/stop/refusal assertions. Read it before changing checks.
- Full product validation also re-runs the evidence-completeness test and the
  `health` / `run` smoke markers; see the workflow for the exact steps.

## Conventions

- Validated newtypes for domain identity (`src/domain`); caller strings
  cannot manufacture trusted context (no `From<String>` / `Default` on trust
  boundaries).
- Typed errors with stable machine codes (`Error::code()`); malformed input
  is refused, never panics — no `unwrap` / `expect` on input paths.
- Keep matches exhaustive so new variants break the build, not behavior.
- Contract fixtures are independent: expected JSON strings are hardcoded
  literals, never encoder output (`tests/contracts.rs`).
- PR01 CLI output lines (`starting` / `stopped` markers, `health` inventory,
  `evidence` cases) are test-asserted; do not reword them without updating
  `tests/role_boundaries.rs`, `tests/contracts/`, and the CI smoke greps.
- Single-crate workspace: no empty per-feature crates; new modules go under
  `src/` via the integration owner.
- Storage and schema changes are reserved through the integration owner;
  applied migrations are never rewritten.
- Rust file line cap (local pre-commit hook, grandfather + enforce-forward):
  `.rs` files are capped at 700 total lines
  (staged `git show :path | wc -l`). New or previously compliant files over
  700 fail; grandfathered files fail only on growth (staged > HEAD).
  Grandfathered as of this change (record, do not split here):
  `src/access/mod.rs` (2053), `src/storage/sqlite/mod.rs` (1548),
  `tests/storage_sqlite.rs` (1199), `tests/access_boundaries.rs` (904),
  `src/semantics/convert.rs` (949), `tests/semantics_profile.rs` (778).
  Fresh clones: `git config core.hooksPath .githooks`. Product CI does not
  run git hooks (server-side unaffected — hooks are local).

## Scope boundaries

B01 slice ownership — do not implement outside the owning slice:

- PR03 owns durable stores / SQLite transactions.
- PR04 owns access control.
- PR05 owns the native engine lifecycle.
- PR06 owns the semantics converter.
- `src/domain` is representation only: no stream/recovery runtime, no auth,
  no stores/SQL, no native lifecycle, no field acquisition.

If a change seems to need product files outside your owned scope, stop and
report it as a finding instead.

## Evidence rules

- Docs-only changes (only `*.md`, per the CI selection policy) skip product
  execution and must NOT claim product tests ran.
- Product changes require `cargo build --locked`, the full `cargo test
  --locked` run (empty execution fails), the `evidence` report, and the smoke
  assertions — and must report the exact pins, target, and profile tested.
- Never infer a stop or a pass from a timeout; stops are observed exits with
  explicit codes and `stopped` markers.

## Security notes

- Secrets are env-referenced and redacted (length-only display, value never
  logged); unresolved secrets are a startup refusal. `src/domain` holds no
  secrets — keep it that way.
- Minimize secret lifetime in memory; zeroize / overwrite secret bytes on use
  wherever they are held.
- No sockets, no stores, and no real credentials in scope; tests use
  synthetic fixtures only (`fixture::tiny_site`: `ahu-1`, `vav-101`,
  `sensor-sat-1`).
