# AGENTS.md

Agent instructions for Verdant. Complements `README.md`; this file supplies
working commands and boundaries, with detailed acceptance in the program repo.

## Current session — 12 September 2026

B01 and M01-PR07 are merged, and B02 was accepted. Source is this repository;
do not restart application-repository selection or an unstarted B01.

Read the current [program handoff](https://github.com/jscott3201/verdant-program/blob/main/CODEX_HANDOFF.md),
[implementation audit](https://github.com/jscott3201/verdant-program/blob/main/implementation/reviews/2026-09-12-entry-audit.md),
and [R01–R09 repair cards](https://github.com/jscott3201/verdant-program/blob/main/planning/remediation/2026-09-12-b02-entry.md).
The unchanged [B01/B02 acceptance record](https://github.com/jscott3201/verdant-program/blob/main/planning/dispatch/b01-completion-and-b02-acceptance.md)
retains owner decisions and standing branch/review permission.

Validate the narrow code-fix drafts #10/#11, then close the relevant storage,
trusted-context, binding and actual native-model gaps before treating PR07
findings as authoritative input to M01-PR11 seals or PR08 acceptance. Both
code drafts passed their recorded GitHub build/full-test/smoke jobs, but remain
unmerged pending independent review. Those passes do not close all repairs.

The roadmap is not replaced. After relevant repair evidence is integrated,
resume PR11 → PR08 → PR09 → PR10. M01-G is not passed by a merged title or a
synthetic fixture. M02–M06 and UI remain separate future work.

## Project overview and accepted pins

- One Rust binary crate (`verdant`, `src/main.rs`) with one current direct
  dependency (`selene-db 2.0.0-alpha.1`, git
  `b65c2344c916d2c3ceeb72cefcd72e7960e95e25`, default features).
  `Cargo.toml` sets `publish = false`.
- SQLite currently uses the system `sqlite3` executable through `std::process`,
  not a linked Rust driver. The local record states 3.54.0; inspected main CI
  used 3.50.6. Always record the actual executable/build; do not conflate them.
- All builds/tests use `--locked`; `rust-toolchain.toml` pins 1.97.1.
  Changes to compiler, dependency or native-library choices require a narrow
  owner-recorded amendment, not a convenience upgrade or hidden addition.
- Preserve D05 disposable alpha-state limitations across incompatible Selene
  builds. Still prove the native model within the selected build.
- The entry point is still a local-only shell with no field listener or active
  acquisition. Storage, native, access and binding modules have isolated tests;
  their existence is distinct from an active configured service.

## Build and test commands

```sh
cargo build --locked
cargo test --locked
./target/debug/verdant evidence   # informational; not proof a new test ran
```

Read `.github/workflows/pr01.yml` before changing checks. Product validation
includes the targeted evidence-completeness rerun and health/run smoke cases.
Record actual selected suites, tests, target and pins. Path-imported modules
currently rerun some unit tests in several binaries, so the aggregate count is
not a distinct acceptance-case count.

The review session did not run local product tests. Existing main CI and new
PR CI are separately observed evidence. Before merging fixes, inspect their
actual heads/results and run the permitted local checks; preserve any failures.

## Conventions and ownership

- Distinguish parseable identity/scope references from authenticated context.
  Valid characters alone do not confer scope or an issuance-controlled ceiling.
  The actual trust constructor belongs to validated access/policy code.
- Typed errors have stable codes. Malformed input is refused, not panicked;
  no `unwrap` / `expect` on input paths.
- Keep matches exhaustive. Independent fixture expectations do not call the
  production encoder/arbiter to generate their own supposed oracle.
- Changes to CLI markers require corresponding contract tests and CI greps.
  Correct stale capability statements without claiming inactive services run.
- Keep one crate unless a reviewed concrete boundary justifies another.
  Coherent small modules belong under `src/`; no empty framework scaffolding.
- Applied migrations remain unchanged. Reserve successor IDs through the
  integration owner; an old one-migration test is not a lifetime schema limit.
- At most two implementation lanes and one heavyweight run initially. Give
  each lane separate database paths, native directories, ports and temporary
  identities. Do not race shared schema/root manifests or the same coordinator.
- Every slice owns its code, meaningful tests, migrations and concise handoff.
  Read the specific R-card and predecessor interface before editing outside
  its named responsibility. Report a missing contract rather than broadening
  the product or changing an upstream checkout silently.

## File size policy

`.rs` files are capped at 700 total staged lines (`git show :path | wc -l`).
New or previously compliant files over 700 fail. Grandfathered files fail on
growth; preserve the existing hook's enforcement semantics.

Recorded grandfathered files: `src/access/mod.rs` (2053),
`src/storage/sqlite/mod.rs` (1548), `tests/storage_sqlite.rs` (1199),
`tests/access_boundaries.rs` (904), `src/semantics/convert.rs` (949),
`tests/semantics_profile.rs` (778). Split coherent responsibilities when
repairing them; do not inflate or broadly reformat these files.

Fresh clones: `git config core.hooksPath .githooks`. The inspected workflow does
not run local hooks automatically; R08 owns deliberate CI enforcement.

## Correctness boundaries for current repairs

SQLite checks must guard the body before effects. A printed version header
parsed after commit is not an admission guard. Reconcile unknown outcomes,
refuse unknown/damaged store identity before DDL, and make bootstrap/rotation
checked transactions. Count actual executions and child lifetime, not only
handles. Busy timeout and journal_size_limit do not establish total CPU/time
or live-WAL bounds.

Only a newly created probe belongs to the caller. Never truncate or delete an
existing probe file/symlink. Native maintenance needs bounded pressure/recovery
admission; measurement failure after checkpoint must preserve the commit fact.

Binding entry and replay validate current same-scope active equipment, point
and source records, concurrent revisions and operation identity. Finding
emission requires current authenticated context and actual registered input.
Raw rehydration or an imported status cannot manufacture observed qualification.

The current semantic subset and access keys are explicitly synthetic. Keep
them as fixtures, not proof of actual Brick/223P/REC integration or production
authentication. Real native qualification requires pinned source artifacts
and actual queried relationship/value evidence at the selected Selene pin.
Real seals need complete versioned content and a reviewed cryptographic digest,
not FNV or credential-verifier fingerprints as authority.

## Security and evidence

No field routes, production credentials, remote listeners, real notifications,
customer data, partner accounts or paid infrastructure enter this repair batch.
Tests may create only authorized disposable local SQLite/native fixtures.
Candidate/assistance environments do not receive reviewer, field, signing or
recovery secrets. Minimize secret lifetime and never log credentials.

Docs-only changes may skip product execution under the declared CI policy and
must not claim it ran. Product changes need actual build/test/smoke evidence.
A timeout is not observed termination or rollback. Record source/configuration,
actual commands/results, independent review, changed formats, task cleanup and
untested limits. Source analysis, ordinary reopen, process-crash evidence and
field qualification remain distinct.

Update the current program execution snapshot when repairs land; preserve old
local reports and accepted decisions. No corrective PR or green test result
by itself passes M01-G or authorizes physical operation.
