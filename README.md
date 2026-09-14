# Verdant

Verdant is being built for building operations: fault detection, qualified
human equipment control, corrective work, and evidence of resolution. Those
are goals, not delivered operational capabilities.

> **Foundation, not a full application.** Storage, synthetic access, native
> lifecycle, conversion and binding modules are compiled and exercised in
> isolated tests. Headless setup verbs open existing stores with synthetic local
> credentials. The ordinary `run` command remains the no-field/no-listener shell;
> it does not start the separately compiled inert runtime API.

## Current status

M01 deliveries are merged; their gate is bounded synthetic evidence, not real-site
native-semantic qualification. M02-PR01A adds an inert composition seam, not a
BACnet adapter or completion of parent PR01. Keep these evidence levels distinct:

| Level | Current meaning / source |
| --- | --- |
| Compiled support | Single binary wires `config`, representation-only `domain`, SQLite `storage`, synthetic `access`, Selene `native`, offline `semantics`, and `binding` ([src/main.rs:8–32](src/main.rs#L8)). |
| Isolated execution evidence | Tests exercise those modules with synthetic fixtures and temporary stores. PR19's [CI 34714433781](https://github.com/jscott3201/verdant/actions/runs/34714433781) ran **1007 passing test instances**, summed over binaries, not 1007 unique scenarios; it also ran completeness and smoke checks. |
| Configured runtime | `standalone`, `edge`, and `hub` select the same constrained shell. Config validation requires an existing directory and resolves an optional env secret; it does not open a store ([src/config/mod.rs:239–247](src/config/mod.rs#L239), [src/main.rs:255–295](src/main.rs#L255)). |
| Active readiness | `starting` means the shell has started. `health` is inventory/config validation, not active storage, native, field or application readiness; `listener: none` remains literal ([src/main.rs:155–207](src/main.rs#L155)). Native presence likewise does no I/O ([src/native/mod.rs:114–151](src/native/mod.rs#L114)). |

The unchanged PR01 CLI/report contains historical `stores: not-implemented`,
native-deferred/blocked rows, and a compiled-in SQLite `3.54.0` inventory string
([src/main.rs:120–126](src/main.rs#L120), [350–383](src/main.rs#L350)).
These are **not** current module-absence claims or a runtime SQLite version
probe. Read them with the levels above and actual CI inventory below; the
informational `evidence` report never proves that tests ran.

### Current setup and inert runtime inventory

`verdant capabilities` is the **separate current inventory**. Historical PR01
`health` and `evidence` output remains unchanged. Setup verbs are `draft`, `edit`,
`validate`, `seal`, `accept`, `status`, `read` and `recovery`; see `verdant --help`
for their existing synthetic credential/configuration and operation-ID contracts.
Acceptance and activation are different, and neither starts field work.

The API-first [`runtime`](src/runtime/mod.rs) composition opens supported access,
binding, native and seal owners once, retains them across stop/start, and reads
exact accepted/active content through existing authenticated APIs. Startup checks
seal availability as well as pointer identity. It accepts only explicit selected
structurally valid sensing keys. A closed inert adapter returns
`NotAttemptedInert`: no packet, sensor timestamp, observed value or qualification.
There is no generic protocol client, listener, automatic polling, writable
runtime API, observation spool or new migration. Ordinary `run` does not call it.

One budget family counts queued work, actual jobs and retained results across
the separate supported store handle families. These **fixture assumptions**, not
measured capacity or facility settings, are enforced in
[`admission.rs`](src/runtime/admission.rs):

| Resource | Runtime fixture bound |
| --- | --- |
| Queued + running + retained-result slots | 64 total: 2 current-sensing, 2 reconciliation, 60 optional-discovery; mandatory slots cannot be borrowed |
| Concurrent jobs (including SQLite/hash/native verification) | 4 total: 1 current-sensing, 1 reconciliation, 2 optional; startup consumes reconciliation capacity |
| Raw-envelope reservation | 65,536 bytes each; 4,194,304 bytes aggregate; errors retain typed origin/stable code rather than subprocess output |
| Request lifetime / stop budget | At most 35,000 ms including queueing; stop can return explicitly unresolved jobs |
| Result retention | Finite slot count until explicit take or stop; not a current-value cache, history window or freshness promise |
| Observation spool / runtime pins | 0 bytes / 0 pins admitted; later PR03 owns those contracts |

The derivation stays below `StoreBounds::tiny`'s 64 tasks/16 operations and
`NativeBounds::local`'s 8 admissions. Existing owner limits remain unchanged:
SQLite WAL/FULL, 5,000 ms busy wait, 35,000 ms operation budget and 8,388,608-byte
retained-journal setting; native maintenance's 1,048,576-byte working and
1,048,576-byte future-journal reserves; seal's 32 live seals, 256 history rows,
64 closure nodes, depth 16, 262,144 closure bytes, 8 native refs and 2,097,152 bytes
per artifact. API pages/work stay 64/256 and review/publish ceilings stay 1/2.
These are not host-global memory/disk quotas or hard live-WAL limits. Other
independent owners are not silently covered by this runtime's accounting.

Accepted revision, active generation, runtime incarnation and source generation
remain distinct. Content, authority and generation are rechecked at handoff;
superseded callbacks are refused. Checks are last-read evidence, not a lease or
cross-process fence. No SQL transaction or native/registry guard spans the inert
adapter call. Stop closes intake and joins actual jobs, or returns `Unresolved`
while retaining their reservations. Keep that owner and poll/stop again; dropping
it reports abandoned work as unresolved and does **not** assert a successful join.
`Stopped` refers to runtime jobs, not closing the retained stores or proving all
Selene-internal shutdown work finished. No real-time scheduling guarantee is made.

[`tests/runtime_owner.rs`](tests/runtime_owner.rs) selects B03 A01–A10 against
isolated synthetic stores. Real-source semantics (F02/E05), non-fixture access
(E06), approved peer traffic (E03), and facility action choices D06/D07 remain
unresolved at their consumers. The observed `bacnet-client`/Tokio and
`apdu_retries(0)` preparation is recorded as **pending PR01B input only** in
[`inert.rs`](src/runtime/inert.rs); no dependency was adopted or wire behavior
qualified here.

## Merged repair evidence (R01–R07 and PR19)

This is a source/evidence map, not a replacement behavioral specification.
R08 reconciles documentation and CI before M01-G; it does not seal M01-G.

| Repair | Established boundary and decisive source | Observed green PR CI (head, summed instances) |
| --- | --- | --- |
| R01 / PR13 | Native writability probe owns only a freshly created file; collisions are refused without truncating/removing existing artifacts ([handle.rs:472–498](src/native/handle.rs#L472)). | [34702306657](https://github.com/jscott3201/verdant/actions/runs/34702306657), `f798e24`, 540 |
| R02 / PR13 | Versioned canonical binding input includes lifecycle status, so new synthetic finding identity distinguishes status; stored findings are not recomputed ([proposal.rs:244–269](src/binding/proposal.rs#L244), [findings.rs:157–177](src/binding/findings.rs#L157)). | Same PR13 run |
| R03 / PR14 | Checked file/schema/ledger admission, private no-clobber bootstrap, held-connection mutations and operation receipts; additive `0002_receipts` leaves `user_version=1` and `0001` unchanged ([admission.rs:103–195](src/storage/sqlite/admission.rs#L103), [251–281](src/storage/sqlite/admission.rs#L251), [mutation.rs:50–138](src/storage/sqlite/mutation.rs#L50), [0002:1–30](migrations/sqlite/0002_receipts.sql#L1)). | [34704871246](https://github.com/jscott3201/verdant/actions/runs/34704871246), `fc6dd66`, 618, after CLI-flag repair |
| R04 / PR15 | Per-family operation permits/deadlines, bounded input/output/rows, joined pipe pumps and owned-child kill/reap; retry pauses share the operation budget ([execution.rs:1–6](src/storage/sqlite/execution.rs#L1), [65–120](src/storage/sqlite/execution.rs#L65), [287–306](src/storage/sqlite/execution.rs#L287)). | [34706810965](https://github.com/jscott3201/verdant/actions/runs/34706810965), `0bb58c9`, 772 |
| R05 / PR16 | Atomic synthetic bootstrap/rotation and guarded mutations; access-private `ActorContext`, persisted scope/ceiling/expiry policy and v2-only records ([gate.rs:15–95](src/access/gate.rs#L15), [160–302](src/access/gate.rs#L160), [context.rs:4–123](src/access/context.rs#L4), [access/mod.rs:30–34](src/access/mod.rs#L30)). | [34710442835](https://github.com/jscott3201/verdant/actions/runs/34710442835), `0c1729d`, 863 |
| R06 / PR17 | Durable proposals/findings join live actor authority, not a key fingerprint; shared revision/sequence evolution and receipts guard new effects. Full reconstruction is separate from stale-marked observation windows ([writer.rs:45–122](src/binding/writer.rs#L45), [148–168](src/binding/writer.rs#L148), [history.rs:26–79](src/binding/history.rs#L26), [231–280](src/binding/history.rs#L231)). | [34712261674](https://github.com/jscott3201/verdant/actions/runs/34712261674), `fbdeb9f`, 961 |
| R07 / PR18 | Closed conversion vocabularies, faithful status/provenance through guarded writers and replay; no conversion/proposal path mints observed qualification ([convert.rs:792–879](src/semantics/convert.rs#L792), [writer.rs:124–135](src/binding/writer.rs#L124), [semantics/CONTRACT.md:3–89](src/semantics/CONTRACT.md#L3)). | [34713652484](https://github.com/jscott3201/verdant/actions/runs/34713652484), `e9e23f7`, 1007 |
| PR19 | Test-only busy-retry deadline margin: 1000 → 30000 ms, retaining strict `busy` and the separate deadline assertion ([execution_tests.rs:267–289](src/storage/sqlite/execution_tests.rs#L267)); product retry constants unchanged ([mod.rs:59–60](src/storage/sqlite/mod.rs#L59)). | [34714433781](https://github.com/jscott3201/verdant/actions/runs/34714433781), `a67c8e4`, 1007; merged as `06cb89e` |

**Failure history is evidence too.** Main-push [34713888722](https://github.com/jscott3201/verdant/actions/runs/34713888722)
at `8ee99c8` failed `r04_lock_wait_retries_share_deadline_and_permit`:
the same test passed in two binaries and failed in a third with
`operation-deadline` instead of `busy`. The [PR19 adjudication](https://github.com/jscott3201/verdant/pull/19)
identified scheduler-dependent wall-time contention, not a product regression:
a 1000 ms deadline competed with a nominal 155 ms retry horizon (six 5 ms
waits plus five 25 ms pauses, excluding CLI overhead). The fix enlarged only
the test margin, not the accepted outcome. Green PR19 replaces that failed
baseline evidence; it does not erase the failure or establish real-time guarantees.

## Explicit limits

- Credentials/actors are **synthetic only**. FNV fingerprints/digests are not
  cryptographic authentication, signatures, tamper evidence, or a real IdP;
  parsed identities cannot mint trusted context ([access/mod.rs:71–96](src/access/mod.rs#L71),
  [context.rs:114–123](src/access/context.rs#L114)).
- `mapped`, `imported`, and structurally `valid` are not `observed-qualified`.
  No field acquisition, actual equipment control, discovery, hub coordination,
  MCP surface, UI, or operational background workers are delivered
  ([binding/mod.rs:77–86](src/binding/mod.rs#L77), [semantics/CONTRACT.md:55–89](src/semantics/CONTRACT.md#L55)).
- Process-crash/reopen and synthetic capacity tests are **not power-loss or
  real disk-full proof** ([storage/mod.rs:23–28](src/storage/mod.rs#L23),
  [native/handle.rs:30–35](src/native/handle.rs#L30)). Limits are per-handle/shared
  family, not host-global quotas; SQLite execution is not a process-tree sandbox
  or a child heap/CPU quota ([sqlite/mod.rs:210–245](src/storage/sqlite/mod.rs#L210),
  [execution.rs:1–6,24](src/storage/sqlite/execution.rs#L1), [native/handle.rs:1–28](src/native/handle.rs#L1)).
- Only **macOS / arm64 / debug** is evidenced here (`aarch64-apple-darwin`);
  release, other targets and physical-device behavior are unqualified. Timing
  tests have wall-clock margins, not real-time guarantees (PR19 run above).
- The native-row representation seam is contract-only, not application row
  persistence. Selene lifecycle tests are a separate capability; the native
  alpha store is disposable across pin changes ([tests/contracts/boundaries.rs:435–489](tests/contracts/boundaries.rs#L435),
  [native/mod.rs:4–10,77–80](src/native/mod.rs#L4)).
- Existing **v1 access/binding descriptor databases need an explicit operator
  reset/recreation**, not silent compatibility or an invented migration
  ([access/mod.rs:34](src/access/mod.rs#L34), [binding/mod.rs:99–102](src/binding/mod.rs#L99),
  [history.rs:51–56](src/binding/history.rs#L51)). This is distinct from R03's
  supported storage-schema `0001` → additive `0002_receipts` upgrade.
- SQLite requires a trusted owner-writable parent, trusted executable and
  controlled `HOME` (including `.sqliterc`); same-UID hostile replacement and
  raw-DB tampering are outside the trust model. SQLite 3.50.x has no `-noinit`
  protection here ([admission.rs:1–3,57–79](src/storage/sqlite/admission.rs#L1),
  [connection.rs:21–30](src/storage/sqlite/connection.rs#L21), [semantics/CONTRACT.md:81–89](src/semantics/CONTRACT.md#L81)).

## Quick start

Prerequisites: Rust **1.97.1**, pinned by [rust-toolchain.toml](rust-toolchain.toml),
and a compatible system `sqlite3` CLI on `PATH`. All Cargo builds/tests use
`--locked`. [Cargo.toml:1–28](Cargo.toml#L1) defines one unpublished binary crate
and exactly one direct dependency: **selene-db 2.0.0-alpha.1**, git revision
**b65c2344c916d2c3ceeb72cefcd72e7960e95e25**, default features
([Cargo.lock:946–948](Cargo.lock#L946)); transitive dependencies are not zero.

SQLite is driven through `std::process`, **not linked**. Observed versions:
**3.54.0 locally**, **3.50.6 in PR14–PR19 CI**, not interchangeable pins.
Local `otool -L target/debug/verdant` lists `libiconv.2.dylib` and
`libSystem.B.dylib`, no SQLite dynamic library; CI records the same check.
`otool` alone is not a static-link audit: the process boundary is established
by [connection.rs:27–30](src/storage/sqlite/connection.rs#L27) and
[execution.rs:322–332](src/storage/sqlite/execution.rs#L322).

```sh
cargo build --locked
cargo test --locked
./target/debug/verdant version
./target/debug/verdant health
./target/debug/verdant evidence
cargo test --locked evidence_completeness -- --nocapture
```

For `run`, supply a validated config naming an already-existing directory;
the workflow contains the isolated start/stop/refusal smoke example. Nothing
in this quick start starts operational stores or a field listener.

## Project layout

- `src/config` — role and configuration boundaries (validated local roles,
  strict keys, refusal on bad input).
- `src/domain` — shared representation contracts: identities, values, times,
  operation outcomes. Representation only; no runtime, stores, or field
  acquisition here.
- `src/storage`, `src/access`, `src/native`, `src/semantics`, `src/binding` —
  the compiled/tested foundations mapped above, not CLI activation.
- `migrations/sqlite` — immutable `0001_init` plus additive `0002_receipts`.
- `tests` — synthetic module, boundary and independent contract fixtures.

## CI evidence policy

[pr01.yml](.github/workflows/pr01.yml) retains selection, pinned toolchain,
locked build, full tests with a nonempty summed count, informational evidence,
explicit completeness rerun, start/stop/refusal smoke, and environment inventory.
Only `*.md` changes skip product execution; workflow changes select product.
Setup failure, docs-only skip, empty selection, empty tests and product success
are distinct. A timeout never establishes a successful stop.

R08 adds source-derived SQLite flag compatibility (with a fail-closed reviewed
argument-surface guard), `otool -L` evidence/refusal of SQLite dynamic linkage,
and the Selene revision read from `Cargo.lock`. Checkout is SHA-pinned to the
exact v4 commit logged in PR19. No cache is restored or saved: every hosted
product CI run is clean-room for project artifacts, **not a hermetic tool/OS
environment**. Inventory records the actual runner and system SQLite version.

CI emits a supplemental SHA-256 of the full test log; it is not an independently
archived log attestation. The anchor is a **green product CI run at the delivered
head**, its run ID and tested checkout SHA (PR jobs can test a merge checkout).
The historical runs above do not validate this R08 workflow revision: final
proof requires its PR CI after delivery.

## Contributing

PRs target `main` with review and green checks (see
`.github/workflows/pr01.yml`). Keep changes scoped; docs-only changes must
not claim product tests ran.

## License

No license terms have been chosen yet — distribution terms are TBD.
