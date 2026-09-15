# Evidence levels

[Back to README](../README.md) · [Capabilities](capabilities.md) ·
[Runtime budgets](runtime-budgets.md) · [Roadmap](../roadmap/overview.md)

Verdant's M01 gate records a synthetic local journey, not real-site qualification.
M02 work currently provides an inert runtime API, not field acquisition. Read
source, tests and reports at the following distinct levels.

| Level | Current meaning / source |
| --- | --- |
| Compiled support | The single binary wires configuration, representation-only domain types, SQLite storage, synthetic access, Selene native lifecycle, offline semantics, binding, seals, acceptance, setup APIs and the inert runtime ([src/main.rs](../src/main.rs)). |
| Isolated execution evidence | Tests exercise modules using synthetic fixtures and temporary stores. The [M01 gate](../tests/m01_gate.rs) covers the local setup journey; [runtime tests](../tests/runtime_owner.rs) exercise the inert composition separately. Historical CI counts below are passing instances summed over binaries, not unique scenarios. |
| Configured runtime | `standalone`, `edge` and `hub` select the same constrained shell. Configuration requires an existing directory and resolves an optional environment secret; this does not open a store ([configuration](../src/config/mod.rs), [CLI](../src/main.rs)). Setup verbs separately open existing stores with synthetic credentials; ordinary `run` does not start the inert API. |
| Active readiness | `starting` means the shell started. `health` is inventory/configuration validation, not active storage, native, field or application readiness; `listener: none` remains literal. Native presence likewise performs no I/O ([CLI](../src/main.rs), [native presence](../src/native/mod.rs)). The inert API checks content availability per operation, not observed qualification. |

## Historical CLI output

The unchanged PR01 `health`/`evidence` output contains `stores: not-implemented`
and native-deferred/blocked rows. Verbose version output also contains a
compiled-in SQLite `3.54.0` inventory string ([source](../src/main.rs)). These
are historical output contracts, **not current module-absence claims or a
runtime SQLite version probe**. `verdant capabilities` is the separate current
inventory ([source](../src/runtime/inventory.rs)).

The informational `evidence` command never proves tests ran. Its `executed`
labels identify the cases covered by the test contract, not execution during
that command. Consult actual test results and CI selection instead.

## Build and host inventory

- Rust **1.97.1** is pinned by [rust-toolchain.toml](../rust-toolchain.toml);
  all Cargo builds and tests use `--locked`.
- **cargo-nextest 0.9.143** is the primary test runner, installed in CI via
  `taiki-e/install-action@v2` with checksums enabled and no install fallback.
  Locally, if absent: `cargo install cargo-nextest --locked --version 0.9.143`.
  `cargo nextest run --locked --no-tests=fail` runs the full suite;
  `cargo test --locked` remains a supported local fallback/sanity path. These
  are separate runner results. The binary-only crate has no library doctest target.
- [Cargo.toml](../Cargo.toml) defines one unpublished binary crate and exactly
  one direct dependency: **selene-db 2.0.0-alpha.1**, git revision
  **b65c2344c916d2c3ceeb72cefcd72e7960e95e25**, default features. The source is
  recorded in [Cargo.lock](../Cargo.lock); transitive dependencies are not zero.
- SQLite is driven through `std::process`, **not linked**. Historical observed
  versions were **3.54.0 locally** and **3.50.6 in PR14–PR19 CI**; these are
  observations, not interchangeable pins. The [gate inventory](../tests/gate_cases/manifest.rs)
  checks SQLite 3.x at least 3.50.0 and `shasum` at least 6.0, records the actual
  `PATH` selections, and separately records `/usr/bin/shasum` used by seals.
- The [seal digest boundary](../src/seal/digest.rs) probes the fixed hash tool
  with a known answer. That does not turn synthetic access fingerprints into
  cryptographic authentication.
- Historical local `otool -L target/debug/verdant` output listed
  `libiconv.2.dylib` and `libSystem.B.dylib`, with no SQLite dynamic library;
  `otool` is now local macOS validation only. Linux CI uses `ldd`, refuses
  unresolved libraries, and asserts no SQLite dynamic dependency. Neither
  command is a static-link audit.
  The process boundary is established by [connection.rs](../src/storage/sqlite/connection.rs)
  and [execution.rs](../src/storage/sqlite/execution.rs).

Historical runs below evidence **macOS / arm64 / debug** (`aarch64-apple-darwin`).
CI now targets **Linux x86_64 / debug** on `ubuntu-latest`; a green product CI log
at the delivered head is the Linux proof, not this workflow change or a macOS
run. macOS remains local/manual validation only. The gate inventory gets the
exact target from `build.rs`'s Cargo `TARGET` export (`VERDANT_BUILD_TARGET`) and
uses `m01-gate-{target}-debug` consistently in its inventory and seal assertion.
Source, executable and seal digests remain measured, not copied from another
host; all tool floors and the owned-file 700-line check remain in force.
There is no release tier yet: release, other targets, and physical-device
behavior remain unqualified. Neither OS lane establishes the other's behavior.

### Linux tool provisioning

Before checkout/toolchain/cache/product steps, CI installs
`libdigest-sha-perl` with apt for the required `/usr/bin/shasum`. Its actual
package and tool versions are reported, not OS-image pins; the **6.0** floor
remains asserted by the gate. Stock Ubuntu SQLite 3.45 is below the unchanged
**SQLite 3.x ≥3.50.0** floor, so the workflow instead downloads:

- Version: **3.53.4**, Linux x86_64 CLI (upstream archive spelling: `linux-x64`).
- URL: <https://sqlite.org/2026/sqlite-tools-linux-x64-3530400.zip>
- Published SHA3SUM / **SHA3-256**:
  `6eeb57e8f2aef7687f9f016a980992cf2799c8c07a87c5e21495530f91915047`.
- Checksum source: [SQLite download page](https://sqlite.org/download.html),
  the Linux tools row (also published as its `PRODUCT` CSV `SHA3-HASH` column).
  The reviewed value is frozen in the workflow, not scraped from a moving page
  during CI. This is an archive checksum, not a hash of `sqlite3.c` or a signature.

`openssl dgst -sha3-256` must match before extraction. Only `sqlite3` is extracted
under `RUNNER_TEMP`, its exact version is asserted, and that directory is
prepended to `PATH`. The pins step records URL, expected and verified archive
hash, selected CLI path/version, and measured executable SHA-256. Tools are
provisioned afresh, not restored from the dependency cache. The archive was
downloaded and its published hash matched locally; executing that Linux binary
and apt provisioning on Ubuntu remain CI evidence, not macOS-local evidence.

## CI evidence policy

[pr01.yml](../.github/workflows/pr01.yml) is the executable check definition:

1. Provision tools and the pinned rustup toolchain, then classify changes:
   only paths ending in `.md` qualify as docs-only. License,
   SVG and workflow files select product execution. Empty changes, docs-only
   skip, setup failure, empty tests and product success are distinct outcomes.
2. Check source-derived SQLite flags against the runner CLI and exercise the
   exact argument spellings on `:memory:`. The reviewed argument-surface digest
   fails closed on change; it must not be blindly refreshed.
3. Build with the pinned toolchain and `--locked`; record linkage and the Selene
   source from the lockfile.
4. Run the full suite with `cargo nextest run --locked --no-tests=fail`.
   Zero executed tests fails; preserve the runner's exit via `pipefail`.
   Parse passing instances only from the uncolored nextest `Summary` line;
   included-module tests repeat across binaries and are not unique scenarios.
   The [profile](../.config/nextest.toml) retains default CPU parallelism,
   `retries = 0`, `slow-timeout = "60s"` (warnings only, no termination), and
   `fail-fast = false` (no new cancellation on first failing test). There is
   no auto-retry, per-test termination policy, or new clippy/fmt gate.
5. Print the informational evidence report, rerun `evidence_completeness`, and
   assert `health`/`run` start, stop and refusal markers with observed exits.
6. Record compiler, host, SQLite version, selection, tested checkout SHA and
   source-tree state. A timeout is never evidence of a successful stop.

Checkout is pinned to the unchanged exact v4 action commit. **Clean-room policy
amendment:** every run still uses a fresh checkout and current product sources,
but no longer a clean-room dependency build. `Swatinem/rust-cache@v2` restores
and saves the following paths (under `CARGO_HOME`, normally `~/.cargo`):

- `registry`: dependency index/cache and crate archives; ordinary unpacked
  sources are recreated, with retained `-sys` sources for timestamp-sensitive builds.
- `git`: dependency clone databases and pinned checkouts (an explicit addition
  beyond registry data; this is not Verdant's source checkout).
- `target`: dependency build artifacts, fingerprints and build-script output;
  workspace-crate builds, incremental artifacts and test reports are cleaned
  before saving. `cache-workspace-crates` and `cache-all-crates` stay false.

`cache-bin: false` excludes Cargo's `bin`, `.crates.toml` and `.crates2.json`
from restore/save and avoids cleaning/clobbering installed tools and rustup
shims. No additional cache directories are configured. SQLite archives,
nextest executables, product sources, stores and test results are not reused
as evidence. Cache keys include OS/architecture, toolchain, manifests/lockfile
and Rust build environment; the action disables incremental builds. The cache
action's path/key log is the record of what a particular run restored. This
is **not a hermetic tool/OS environment**. The test-log SHA-256 is supplemental,
not an independently archived log attestation.

PR and push-main triggers and merge-tree deduplication are unchanged: an
identical-tree merge records the PR-head provenance instead of executing again;
tree equality alone does not verify the earlier run's conclusion. Other pushes
retain the selection policy. Workflow/ref concurrency cancels superseded runs;
cancellation and the existing 20-minute outer job timeout are never passes or
successful-stop evidence.

**Observed nextest semantics (0.9.143, macOS/arm64/debug):** before editing the
gate, `cargo nextest run --locked -E 'none()'` returned **4**, with
`0 tests run: 0 passed, 0 skipped`; explicit `--no-tests=fail` also returned **4**.
A one-test selection returned **0** with `1 test run: 1 passed, 98 skipped`.
The gate therefore uses the explicit native empty-run failure plus a positive
summary-count check, not libtest's nested `test result` lines. The exact empty
probe can be repeated with `cargo nextest run --locked --no-tests=fail -E 'none()'`;
its expected nonzero exit is a successful policy probe, not a passing test run.

The delivery anchor is a **green product CI run at the delivered head**, its run
ID and tested checkout SHA; PR jobs can test a merge checkout. Historical runs
below do not validate later edits. Current runs are available in
[GitHub Actions](https://github.com/jscott3201/verdant/actions/workflows/pr01.yml).

## Merged repair evidence (R01–R07 and PR19)

This historical source/evidence map was relocated from the README. It is not a
replacement behavioral specification or a claim that those runs tested today's
tree. PR19's run recorded **1007 passing test instances**, plus completeness and
smoke checks; it is not the current checkout's test count.

| Repair | Established boundary and decisive source | Observed green PR CI (head, summed instances) |
| --- | --- | --- |
| R01 / PR13 | Native writability probes own only a freshly created file; collisions refuse without truncating/removing existing artifacts ([handle.rs](../src/native/handle.rs)). | [34702306657](https://github.com/jscott3201/verdant/actions/runs/34702306657), `f798e24`, 540 |
| R02 / PR13 | Versioned canonical binding input includes lifecycle status, so new synthetic finding identity distinguishes status; stored findings are not recomputed ([proposal.rs](../src/binding/proposal.rs), [findings.rs](../src/binding/findings.rs)). | Same PR13 run |
| R03 / PR14 | Checked file/schema/ledger admission, private no-clobber bootstrap, held-connection mutations and receipts; additive `0002_receipts` leaves `user_version=1` and `0001` unchanged ([admission.rs](../src/storage/sqlite/admission.rs), [mutation.rs](../src/storage/sqlite/mutation.rs), [migration](../migrations/sqlite/0002_receipts.sql)). | [34704871246](https://github.com/jscott3201/verdant/actions/runs/34704871246), `fc6dd66`, 618, after CLI-flag repair |
| R04 / PR15 | Per-family permits/deadlines, bounded input/output/rows, joined pipe pumps and owned-child kill/reap; retry pauses share the operation budget ([execution.rs](../src/storage/sqlite/execution.rs)). | [34706810965](https://github.com/jscott3201/verdant/actions/runs/34706810965), `0bb58c9`, 772 |
| R05 / PR16 | Atomic synthetic bootstrap/rotation and guarded mutations; access-private `ActorContext`, persisted scope/ceiling/expiry policy and v2-only records ([gate.rs](../src/access/gate.rs), [context.rs](../src/access/context.rs), [access](../src/access/mod.rs)). | [34710442835](https://github.com/jscott3201/verdant/actions/runs/34710442835), `0c1729d`, 863 |
| R06 / PR17 | Durable proposals/findings join live actor authority, not a key fingerprint; shared revision/sequence evolution and receipts guard new effects. Full reconstruction is separate from stale-marked observation windows ([writer.rs](../src/binding/writer.rs), [history.rs](../src/binding/history.rs)). | [34712261674](https://github.com/jscott3201/verdant/actions/runs/34712261674), `fbdeb9f`, 961 |
| R07 / PR18 | Closed conversion vocabularies and faithful status/provenance through guarded writers and replay; conversion/proposal paths do not mint observed qualification ([convert.rs](../src/semantics/convert.rs), [writer.rs](../src/binding/writer.rs), [contract](../src/semantics/CONTRACT.md)). | [34713652484](https://github.com/jscott3201/verdant/actions/runs/34713652484), `e9e23f7`, 1007 |
| PR19 | Test-only busy-retry deadline margin: 1000 → 30000 ms, retaining strict `busy` and the separate deadline assertion ([execution_tests.rs](../src/storage/sqlite/execution_tests.rs)); product retry constants unchanged ([sqlite/mod.rs](../src/storage/sqlite/mod.rs)). | [34714433781](https://github.com/jscott3201/verdant/actions/runs/34714433781), `a67c8e4`, 1007; merged as `06cb89e` |

**Failure history is evidence too.** Main-push
[34713888722](https://github.com/jscott3201/verdant/actions/runs/34713888722) at
`8ee99c8` failed `r04_lock_wait_retries_share_deadline_and_permit`: the same test
passed in two binaries and failed in a third with `operation-deadline` instead
of `busy`. The [PR19 adjudication](https://github.com/jscott3201/verdant/pull/19)
identified scheduler-dependent wall-time contention, not a product regression:
a 1000 ms deadline competed with a nominal 155 ms retry horizon (six 5 ms waits
plus five 25 ms pauses, excluding CLI overhead). The fix enlarged only the test
margin, not the accepted outcome. Green PR19 supersedes that failed baseline
evidence; it does not erase the failure or establish real-time guarantees.

## Compatibility and trust limits

- Credentials/actors are **synthetic only**. FNV fingerprints/digests are not
  cryptographic authentication, signatures, tamper evidence or a real IdP.
  Parsed identities cannot mint trusted context ([access](../src/access/mod.rs),
  [ActorContext](../src/access/context.rs)).
- `mapped`, `imported` and structurally `valid` are not `observed-qualified`.
  Conversion and structural proposals do not establish observation; stored
  provenance is replayed, not upgraded ([semantics contract](../src/semantics/CONTRACT.md)).
- Process-crash/reopen and synthetic capacity tests are **not power-loss or
  real disk-full proof** ([storage](../src/storage/mod.rs),
  [native lifecycle](../src/native/handle.rs)). Handle/shared-family limits are
  not host-global quotas. SQLite execution is not a process-tree sandbox or a
  child heap/CPU quota ([execution](../src/storage/sqlite/execution.rs)).
- The native-row representation is contract-only, not application row persistence
  ([boundary fixtures](../tests/contracts/boundaries.rs)). Selene lifecycle tests
  are separate; the native alpha store is disposable across dependency-pin
  changes ([native](../src/native/mod.rs)).
- Existing **v1 access/binding descriptor databases require explicit operator
  reset/recreation**, not silent conversion ([access](../src/access/mod.rs),
  [binding](../src/binding/mod.rs), [history](../src/binding/history.rs)). This is
  distinct from the supported storage-schema `0001` → additive `0002_receipts`
  upgrade, which keeps `user_version=1`.
- SQLite requires a trusted owner-writable parent, trusted executable and
  controlled `HOME` (including `.sqliterc`). Same-UID hostile replacement and
  raw-database tampering are outside the trust model. SQLite 3.50.x has no
  `-noinit` protection here ([admission](../src/storage/sqlite/admission.rs),
  [connection](../src/storage/sqlite/connection.rs)). Replay fidelity is not
  tamper detection.
