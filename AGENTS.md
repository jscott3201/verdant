# AGENTS.md

Agent instructions for Verdant. Complements `README.md` (human overview);
this file is the normative working contract for automated changes. It follows
the agents.md open format: one file of practical commands and boundaries, no
tutorial bloat.

## Project overview

- One Rust binary crate (`verdant`, `src/main.rs`) with exactly one direct
  dependency (`selene-db 2.0.0-alpha.1` at git rev
  `b65c2344c916d2c3ceeb72cefcd72e7960e95e25`, default features); system
  `sqlite3` is driven via `std::process`, not linked: observed 3.54.0 locally
  versus 3.50.6 in PR14–PR19 CI. `Cargo.toml` sets `publish = false`.
  Pins/source/run references are in [README.md](README.md#quick-start); do not
  infer the runtime SQLite version from the compiled PR01 inventory string.
- All builds and tests run with `--locked`; the toolchain is pinned to 1.97.1
  by `rust-toolchain.toml` (changing the pin is an owner decision, not a
  build convenience).
- Local-only CLI shell: binds no socket, creates no directories at startup,
  and activates no stores/native lifecycle, broker, historian, operational
  workers or field acquisition (`src/main.rs:255–325`). Storage, synthetic
  access, native lifecycle, conversion and binding modules ARE compiled and
  tested, not absent (`src/main.rs:8–32`). Preserve the distinction between
  compiled support, isolated execution evidence, configured shell and active
  readiness; `health`/`evidence` retain historical PR01 wording, not a current
  module-capability manifest (`src/main.rs:155–207,350–383`).
- [README repair map](README.md#merged-repair-evidence-r01r07-and-pr19) records
  merged R01–R07: owned probes, status-bearing v2 identity, checked admission
  and receipts/0002, bounded/reaped execution, atomic synthetic credentials
  and access-private actors/v2 policy, actor-joined findings/shared evolution/
  windowed replay, and closed vocabularies/provenance. Use its cited sources
  and runs, not old slice-introduction comments, as the starting evidence.

## Build / test commands

```sh
cargo build --locked
cargo nextest run --locked --no-tests=fail   # primary runner, cargo-nextest 0.9.143
cargo test --locked                        # supported local fallback/sanity path
./target/debug/verdant evidence   # informational report; not test execution
```

- CI lives at `.github/workflows/pr01.yml`: Linux-only (`ubuntu-latest`),
  selection policy, build, full nextest run (empty execution fails), evidence report, and smoke
  start/stop/refusal assertions. Read it before changing checks.
- Install nextest locally if absent with `cargo install cargo-nextest --locked
  --version 0.9.143`; CI uses `taiki-e/install-action` with the same version.
  `.config/nextest.toml` keeps default CPU parallelism, zero retries, 60s slow
  warnings without termination, and no first-failure cancellation. No new
  clippy/fmt gates. macOS/arm64/debug validation remains local/manual only.
- Full product validation also re-runs the evidence-completeness test and the
  `health` / `run` smoke markers; see the workflow for the exact steps.
- SQLite CLI flags are extracted from the reviewed storage argument surface
  and checked against the runner's CLI, then exercised on `:memory:`. A changed
  surface fails closed: review extraction/callers before updating its digest;
  never blindly refresh it. Preserve the 3.50.x compatibility boundary
  (`src/storage/sqlite/connection.rs:21–30`, `execution.rs:322–332`).
- CI provisions `libdigest-sha-perl` via apt for `/usr/bin/shasum`, and SQLite
  3.53.4 from the pinned sqlite.org Linux x64 tools archive, verifying its
  published SHA3-256 before extraction. URL/hash and measured versions are in
  the workflow pins inventory; stock Ubuntu SQLite is below the 3.50.0 floor.
- CI records Linux `ldd` (no SQLite dynamic linkage) and the Selene source from
  `Cargo.lock`; macOS `otool -L` is local-only. Neither is a static-link audit.
  Checkout stays pinned to PR19's observed v4 SHA. Fresh checkout/product sources
  are always used, but dependency artifacts are no longer clean-room:
  `Swatinem/rust-cache@v2` restores Cargo registry data, git dependency clones/
  checkouts, and `target` dependency builds. `cache-bin: false` excludes installed
  tools/rustup shims; workspace builds and incremental artifacts are not cached.
  Exact cache paths/exclusions are in `docs/evidence-levels.md`; the runner/tool
  image is not hermetic and cached artifacts never replace executing tests.

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
  Historical hook-introduction counts (not current sizes; do not split here):
  `src/access/mod.rs` (2053), `src/storage/sqlite/mod.rs` (1548),
  `tests/storage_sqlite.rs` (1199), `tests/access_boundaries.rs` (904),
  `src/semantics/convert.rs` (949), `tests/semantics_profile.rs` (778).
  Fresh clones: `git config core.hooksPath .githooks`. Product CI does not
  run git hooks (server-side unaffected — hooks are local).

## Scope boundaries

Module ownership origins (M01 PR numbers, not R01–R08 repair IDs) — do not
implement outside the current owner-supplied slice:

- PR03 owns durable stores / SQLite transactions.
- PR04 owns access control.
- PR05 owns the native engine lifecycle.
- PR06 owns the semantics converter.
- PR07 owns binding records/proposals/findings; R01–R07 repairs did not make
  these modules operational CLI services (see the README source map).
- `src/domain` is representation only: no stream/recovery runtime, no auth,
  no stores/SQL, no native lifecycle, no field acquisition.

If a change seems to need product files outside your owned scope, stop and
report it as a finding instead.

## Evidence rules

- Docs-only changes (only `*.md`, per the CI selection policy) skip product
  execution and must NOT claim product tests ran.
- Product changes require `cargo build --locked`, the full `cargo nextest run
  --locked --no-tests=fail` run, the `evidence` report, and the smoke
  assertions — and must report the exact pins, target, and profile tested.
  `cargo test --locked` remains a local fallback/sanity check, not evidence of a
  nextest run. This binary-only crate has no separate library doctest target.
- `.yml` is not docs-only. Preserve selection, empty-fails, evidence,
  completeness, smoke and pins when changing CI. Sum passing test instances
  over binaries; do not call repeated included-module tests unique scenarios.
- PR19's green CI `34714433781` (1007 instances, `a67c8e4`, merged `06cb89e`)
  supersedes failed main run `34713888722`, not its historical record. In the
  failed run one busy-retry test passed twice and failed in a third binary
  (`operation-deadline` vs `busy`). The adjudicated scheduler race was fixed
  test-only by a 1000 → 30000 ms wall margin around a nominal 155 ms retry
  horizon; strict `busy` remains (`src/storage/sqlite/execution_tests.rs:267–289`,
  `mod.rs:59–60`). Do not describe this as zero flakiness or real-time proof.
- The CI test-log SHA-256 is supplemental, not independent archival proof.
  Anchor delivery to green product CI at the delivered head, run ID and tested
  checkout SHA; a prior run or report alone does not validate later edits.
- Linux CI proves only the target/profile/tree in its green product run; moving
  the workflow to Ubuntu is not itself Linux execution evidence. Historical
  macOS CI and manual macOS/arm64/debug runs do not validate Linux, or vice versa.
  There is no release-tier qualification. Process-crash and synthetic
  space-budget tests are not power-loss/disk-full qualification; handle-family
  limits are not host-global quotas. Native-row fixtures are contract-only,
  not application row persistence. See [README limits](README.md#explicit-limits)
  for sources and further exclusions.
- Never infer a stop or a pass from a timeout; stops are observed exits with
  explicit codes and `stopped` markers.

## Security notes

- Secrets are env-referenced and redacted (length-only display, value never
  logged); unresolved secrets are a startup refusal. `src/domain` holds no
  secrets — keep it that way.
- Minimize secret lifetime in memory; zeroize / overwrite secret bytes on use
  wherever they are held.
- No real credentials, crypto/auth/IdP integration, field observation or actual
  control is delivered. Synthetic access checks exist; FNV is not a security
  primitive (`src/access/mod.rs:71–96`). `ActorContext` is access-constructed,
  not a parsed caller assertion (`src/access/context.rs:114–123`).
- Tests may open isolated temporary stores, never program-repository stores;
  use synthetic fixtures (`fixture::tiny_site`: `ahu-1`, `vav-101`,
  `sensor-sat-1`). Storage requires a trusted owner-writable parent, trusted
  `sqlite3` and controlled `HOME`/`.sqliterc`; it is not a hostile-filesystem
  sandbox (`src/storage/sqlite/admission.rs:1–3,57–79`, `connection.rs:21–30`).
- No compatibility debt: v1 access/binding descriptors are refused and need
  an explicit operator reset/recreation, not automatic conversion. Do not
  confuse that policy with the supported additive storage `0002_receipts`
  upgrade keeping `user_version=1` (`src/access/mod.rs:34`,
  `src/binding/mod.rs:99–102`, `migrations/sqlite/0002_receipts.sql:1–15`).
- Conversion and structural proposals never establish observed qualification;
  stored provenance is replayed, not upgraded. Raw-DB tampering is outside
  the guarded-writer trust model (`src/semantics/CONTRACT.md:55–89`).
