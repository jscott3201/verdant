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
  CI records the same kind of check. `otool` alone is not a static-link audit.
  The process boundary is established by [connection.rs](../src/storage/sqlite/connection.rs)
  and [execution.rs](../src/storage/sqlite/execution.rs).

Only **macOS / arm64 / debug** (`aarch64-apple-darwin`) is evidenced here.
Release, other targets, and physical-device behavior remain unqualified.

## CI evidence policy

[pr01.yml](../.github/workflows/pr01.yml) is the executable check definition:

1. Classify changes: only paths ending in `.md` qualify as docs-only. License,
   SVG and workflow files select product execution. Empty changes, docs-only
   skip, setup failure, empty tests and product success are distinct outcomes.
2. Check source-derived SQLite flags against the runner CLI and exercise the
   exact argument spellings on `:memory:`. The reviewed argument-surface digest
   fails closed on change; it must not be blindly refreshed.
3. Build with the pinned toolchain and `--locked`; record linkage and the Selene
   source from the lockfile.
4. Run the full test suite. Zero executed tests fails. Sum passing test instances
   over binaries; included-module tests repeat and are not unique scenarios.
5. Print the informational evidence report, rerun `evidence_completeness`, and
   assert `health`/`run` start, stop and refusal markers with observed exits.
6. Record compiler, host, SQLite version, selection, tested checkout SHA and
   source-tree state. A timeout is never evidence of a successful stop.

Checkout is pinned to an exact v4 action commit. No project-artifact cache is
restored or saved: hosted product runs are clean-room for project artifacts,
**not a hermetic tool/OS environment**. The test-log SHA-256 is supplemental,
not an independently archived log attestation.

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
