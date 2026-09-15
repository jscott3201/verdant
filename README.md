# Verdant

Verdant is an early-stage, local-first foundation for building operations, written
in Rust. It brings together site-model representation, local storage, synthetic
access checks, and a headless setup CLI. The longer-term direction is acquisition,
fault detection, corrective work, and evidence of resolution—not capabilities
you can deploy from this checkout today.

> **Foundation, not a full application.** This README describes the current source
> checkout, whose crate version is **0.1.0**, not a production-readiness promise.
> The **M01 synthetic gate is recorded**; **M02 acquisition work is in progress**.
> The compiled runtime API is **inert only**, and ordinary `run` does not start it.

**No field authority, no equipment control.** Use synthetic local fixtures and
disposable stores only. Verdant does not observe or qualify real equipment,
authenticate real users, or provide a physical-safety guarantee. All CLI examples
below stay local and open no network listener.

## Build from source

The supported starting point is a source checkout. The binary crate is marked
`publish = false`; these instructions do not assume an installable registry
package or a prebuilt release.

CI runs on **Linux x86_64 / debug** (`ubuntu-latest`); **macOS / Apple Silicon /
debug** remains a local/manual validation lane. A configured lane is not proof:
use its actual run log, target and tested checkout SHA. Prerequisites:

- Rust **1.97.1**, selected by [rust-toolchain.toml](rust-toolchain.toml). With
  `rustup` installed, use the pinned toolchain rather than changing the pin.
- A trusted system **`sqlite3`** CLI on `PATH`. The test inventory requires
  SQLite 3.x, at least 3.50.0; CI also checks the actual command-line flags.
- **`shasum` 6.0 or newer** on `PATH`, plus `/usr/bin/shasum` for application
  seals. Both the tool and its runtime must be trusted.
- Git and the native build tools needed by the Rust toolchain.
- **cargo-nextest 0.9.143** for the primary test path; `cargo test` remains usable.
  Linux CI provisions the pinned SQLite tools and `/usr/bin/shasum` before other
  setup; see [tool provisioning](docs/evidence-levels.md#linux-tool-provisioning).

```sh
git clone https://github.com/jscott3201/verdant.git
cd verdant
cargo build --locked
cargo install cargo-nextest --locked --version 0.9.143 # if not already installed
cargo nextest run --locked --no-tests=fail
cargo test --locked # supported fallback / runner-compatibility sanity check
./target/debug/verdant evidence
```

Run the remaining examples from the repository root. Builds and tests always use
`--locked`. SQLite runs as a subprocess, not a linked database library. The exact
Selene dependency pin, host-tool distinctions, and CI inventory are documented in
[evidence levels](docs/evidence-levels.md#build-and-host-inventory).

## Quick start

Inspect the binary without opening stores or starting services:

```sh
./target/debug/verdant --help
./target/debug/verdant version --verbose
./target/debug/verdant health
./target/debug/verdant capabilities
```

Try the constrained shell with a temporary, already-existing directory. This
self-contained subshell removes only its own temporary directory on exit:

```sh
(
  set -eu
  work="$(mktemp -d "${TMPDIR:-/tmp}/verdant-demo-XXXXXX")"
  trap 'rm -rf "$work"' EXIT
  printf 'role = "standalone"\ndurable_path = "%s"\nfield_listener = false\n' \
    "$work" > "$work/site.conf"

  ./target/debug/verdant health --config "$work/site.conf"
  ./target/debug/verdant run --config "$work/site.conf" --once
)
```

Expect `listener: none` from `health`, followed by `verdant starting` and
`verdant stopped reason=once` from `run`, with exit code 0. This validates the
configuration and shell lifecycle; it does **not** create a database, start the
inert runtime API, or prove application readiness. `edge` and `hub` select the
same constrained shell, not network services.

### CLI tour

| Command | What it does today |
| --- | --- |
| `version [--verbose]` | Reports the crate version and compiled build inventory. |
| `health [--config PATH]` | Reports inventory and optionally validates a local configuration; not a live readiness probe. |
| `run --config PATH --once` | Starts and explicitly stops the no-listener shell. Without `--once`, it waits for stdin EOF or an optional `--max-seconds N` limit. |
| `evidence` | Prints an informational report; it does not execute tests. |
| `capabilities` | Reports the separate current capability inventory and its no-field limits. |
| `draft`, `edit`, `validate`, `seal`, `accept`, `status`, `read`, `recovery` | Headless setup operations over existing stores with synthetic local credentials. These are not an initial bootstrap wizard or field-control commands. |

The detailed [setup and inert-runtime guide](docs/capabilities.md) explains the
setup prerequisites, operation IDs, diagnostic exits, and `NotAttemptedInert`.
For the exact options, run `./target/debug/verdant --help`. Some `health` and
`evidence` wording is historical; see the
[output interpretation note](docs/evidence-levels.md#historical-cli-output)
before treating it as a current module inventory.

## Capabilities

Implemented modules and passing synthetic tests are different from operational
services. See [evidence levels](docs/evidence-levels.md) for that distinction.

| Area | Available foundation | Not established |
| --- | --- | --- |
| Local storage | SQLite transactions, receipts and replay; pinned Selene native lifecycle tested in isolation. | Production durability, application-native row persistence, or a running historian. |
| Site meaning | Offline synthetic vocabulary conversion, structural bindings and findings. | Full ontology support, real-site meaning, or observed qualification. |
| Setup | Draft/edit/validate/seal/accept and read/recovery paths with synthetic access checks. | Real authentication, automatic activation, or permission to operate equipment. |
| Runtime | Explicitly started, bounded inert API over accepted/active content. | Network acquisition, automatic polling, observation persistence, or a writable runtime API. |

## Explicit limits

| Boundary | Current limit |
| --- | --- |
| Credentials and authority | Synthetic credentials and actors only; FNV fingerprints are not cryptographic authentication, signatures, or an identity provider. |
| Meaning and qualification | `mapped`, `imported`, and structurally `valid` do not mean `observed-qualified`. A seal or accepted/active pointer does not grant field authority. |
| Transports | No BACnet or Modbus traffic, COV subscriptions, discovery, writes, or listener. There is no operational hub, MCP surface, UI, or fault/work service. |
| Platforms | Linux-only CI records **x86_64 / debug** evidence at the tested head; **macOS / arm64 / debug** (`aarch64-apple-darwin`) is local/manual validation. Neither lane proves the other; a workflow edit alone proves neither. Release builds, other targets, and physical devices remain unqualified. |
| Durability | Process-crash/reopen and synthetic capacity tests are **not power-loss or real disk-full proof**. The native alpha store is disposable across dependency-pin changes. |
| Resource limits | Limits are per handle/shared family, not host-global quotas. Fixture budgets are not measured capacity, performance, or real-time guarantees. |
| Local trust | Stores require a trusted owner-writable parent, trusted tools, and controlled `HOME`/`.sqliterc`; this is not a hostile-filesystem sandbox. |

Before reusing an existing store, read the
[compatibility and trust limits](docs/evidence-levels.md#compatibility-and-trust-limits).
For numeric fixture bounds and shutdown caveats, see
[runtime budgets](docs/runtime-budgets.md).

## Development and contributing

Bug reports, documentation improvements, synthetic test cases, and scoped PRs
are welcome. Work on a branch, target `main`, and require review and green CI
before merging. Include focused tests for changed behavior and keep support
claims within the evidence. Do not use real credentials or facility data in tests.

Use the build/test commands above, and rerun the report-completeness check with:

```sh
cargo nextest run --locked --no-tests=fail --test role_boundaries -E 'test(=evidence_completeness)' --nocapture
# Fallback:
cargo test --locked evidence_completeness -- --nocapture
```

[AGENTS.md](AGENTS.md) records repository boundaries and commands. New or
previously compliant Rust files have a **700-line cap**; grandfathered larger
files may not grow. The [CI workflow](.github/workflows/pr01.yml) includes full
tests and explicit start/stop/refusal smoke assertions. Only changes consisting
entirely of `*.md` skip product execution; license files and SVGs do not qualify.
A docs-only skip must never be reported as a product-test pass.

The nextest profile uses default CPU parallelism, **zero retries**, and warn-only
60s slow notices, without cancelling tests on the first failure. CI cancels
superseded workflow runs on the same ref; cancellation is not a pass. No clippy
or fmt gate is added. Fresh checkout/product sources remain mandatory, but
registry/git dependency data and compiled dependencies in `target` are reused
by `rust-cache` with `cache-bin: false` (no rustup-shim/tool cache). This explicitly
replaces the former artifact-clean-room policy; see the
[exact cache scope and evidence policy](docs/evidence-levels.md#ci-evidence-policy).

### Repository map

| Path | Purpose |
| --- | --- |
| [`src/main.rs`](src/main.rs), [`src/config/`](src/config/) | CLI and validated local roles/configuration. |
| [`src/domain/`](src/domain/) | Shared representation only: identities, values, times and outcomes. |
| [`src/storage/`](src/storage/), [`src/native/`](src/native/) | SQLite storage and the pinned Selene lifecycle. |
| [`src/access/`](src/access/), [`src/semantics/`](src/semantics/), [`src/binding/`](src/binding/) | Synthetic access, offline meaning and structural proposals/findings. |
| [`src/seal/`](src/seal/), [`src/accept/`](src/accept/), [`src/api/`](src/api/) | Immutable application content, acceptance/activation state and headless setup APIs. |
| [`src/runtime/`](src/runtime/) | Separately compiled, explicitly started inert runtime API. |
| [`migrations/sqlite/`](migrations/sqlite/) | Immutable initial schema and additive receipts migration. |
| [`tests/`](tests/) | Synthetic module, boundary and independent contract fixtures. |
| [`docs/`](docs/), [`roadmap/`](roadmap/) | Technical guides and milestone direction. |

## Documentation and help

- [Setup and current capabilities](docs/capabilities.md)
- [Evidence levels and CI inventory](docs/evidence-levels.md)
- [Runtime fixture budgets and lifecycle limits](docs/runtime-budgets.md)
- [Roadmap: M01 through M06](roadmap/overview.md)
- [Issues](https://github.com/jscott3201/verdant/issues) — include the source
  revision, OS/architecture, exact command, and a sanitized synthetic reproduction.
  Issues are public: do not post credentials or sensitive site details.

<a id="merged-repair-evidence-r01r07-and-pr19"></a>
The historical [repair source/evidence map](docs/evidence-levels.md#merged-repair-evidence-r01r07-and-pr19)
is retained in the technical guide, separate from current user-facing capabilities.

## License

Verdant is dual-licensed under the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option
(`MIT OR Apache-2.0`). Dependencies retain their own license terms.
