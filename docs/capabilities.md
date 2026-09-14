# Setup and current capabilities

[Back to README](../README.md) · [Evidence levels](evidence-levels.md) ·
[Runtime budgets](runtime-budgets.md) · [Roadmap](../roadmap/overview.md)

**Local and synthetic only.** Setup can change application content in existing
stores; it does not observe equipment, establish qualification or grant field
authority. None of these CLI verbs starts a listener.

## The capabilities command

From a built checkout:

```sh
./target/debug/verdant capabilities
./target/debug/verdant --help
```

`capabilities` takes no arguments and reports the separate current inventory
([source](../src/runtime/inventory.rs)): compiled foundations and setup verbs,
ordinary `run` as a no-field shell, and an explicitly started inert runtime API.
It reports no BACnet, Modbus, COV, discovery or writes. It is an inventory, not a
readiness probe. The historical `health` and `evidence` output remains unchanged;
see [how to interpret it](evidence-levels.md#historical-cli-output).

## Headless setup prerequisites

The [CLI implementation and help](../src/main.rs) define the exact flags and
failure codes. Use `./target/debug/verdant draft --help` (or another setup verb)
to inspect them without opening a store.

- Every setup operation needs `--config PATH --scope SCOPE --capability NAME
  --key-id ID`. Configuration must name an existing local `durable_path` with
  `meaning.db` and `native/`. The `secret_env` setting names the environment
  variable holding the synthetic key; do not put real credentials in examples.
- The stores and synthetic authority must already have been created through
  the supported owners. This CLI has **no initial bootstrap verb**. The empty
  temporary directory in the README's shell example is deliberately insufficient
  for setup; do not try to manufacture a usable store with ad hoc SQL.
- Test only in disposable local stores under trusted, owner-writable parents,
  with trusted `sqlite3`, `/usr/bin/shasum`, and controlled `HOME`/`.sqliterc`.
- The [CLI tests](../tests/cli_setup.rs) provide isolated synthetic journeys;
  they are test fixtures, not instructions for a live site deployment.

## Setup verbs

| Verb | Scope and important limits |
| --- | --- |
| `draft` | Creates a revision from explicit entries, intents and finding references; requires an operation ID. |
| `edit` | Creates a replacement from an explicit parent revision and full replacement inputs, not a partial patch. |
| `validate` | Returns structural diagnostics for a revision. Diagnostics, including `Unqualified`, exit 0; this is not qualification. |
| `seal` | Captures native content and seals a revision with binary/host references. Retries read original receipts; pending content is not reported as sealed. |
| `accept` | Accepts an identified seal with an expected accepted revision (`0` initially). Acceptance and activation are distinct; neither starts field work. |
| `status` | Reads scope status and a bounded operation page. |
| `read` | Reads revision, accepted, active or sealed views. Revision/sealed views require a revision ID; sealed lookup is not paginated. |
| `recovery` | Scoped synthetic `provision`, `re-bootstrap` or `rotate` operations under the existing non-escalating policy; not initial bootstrap. |

For `draft`/`edit`, entry and intent inputs use `KEY|PROPOSAL_INDEX|LABEL`;
proposal indexes are zero-based and nothing is implicitly selected. Finding
references use `OPERATION:SEQUENCE`. Required flags vary by verb; consult help
rather than treating this table as a complete invocation.

API operation IDs must start with `api-` and be at most 80 bytes. Retain IDs and
exact inputs for reconciliation. A pending seal requires owner reconciliation,
not recapture under a new identity. Page size is 1–64 (default 64); offsets are
0–256 (default 0), with out-of-bounds requests refused.

Output is line-oriented success/identity/page markers and debug records, **not a
stable wire codec**. Refusals use stderr with `[machine-code]`; unknown outcomes
retain their operation ID.

| Exit | Meaning for setup verbs |
| --- | --- |
| 0 | Success or validation diagnostics; inspect the records. |
| 1 | Configuration, store or owner failure. |
| 2 | Usage, invalid input or page bounds. |
| 3 | Access refusal. |
| 4 | Conflict, frozen content or cancellation. |
| 5 | Missing or pending content. |
| 6 | Outcome unknown; retain identity for reconciliation. |

## Inert runtime API

The separately compiled [runtime](../src/runtime/mod.rs) is API-first, not a CLI
service. Default construction starts no owners or workers. Explicit startup
opens supported access, binding, native and seal owners once, retains them across
stop/start, and reads exact accepted/active content through the existing
synthetic access-checked APIs. Startup checks seal availability as well as
pointer identity. It accepts only explicitly selected, structurally valid
sensing keys ([owner selection](../src/runtime/owners.rs)).

The closed [inert adapter](../src/runtime/inert.rs) returns
**`NotAttemptedInert`**. That means:

- No network packet or property read was attempted.
- There is no sensor/source timestamp or observed value—not even an invented
  zero. `source_time` remains absent.
- Receipt time records the inert adapter's local return, not a sensor reading.
- No normalization, durable observation or observed qualification is implied.

Accepted revision, active generation, runtime incarnation and source generation
remain distinct. Content, authority and generations are rechecked at handoff;
superseded callbacks are refused. These are last-read checks, not a lease or
cross-process fence. No SQL transaction or native/registry guard spans the
adapter call. See [runtime budgets](runtime-budgets.md) for retention and
unresolved-stop behavior.

There is no generic protocol client, automatic polling, writable runtime API,
observation spool or runtime migration. Ordinary `run` never calls this API.
Comments recording preparation for a later protocol adapter in `inert.rs` are
not an adopted dependency or verified wire behavior. Real-source semantics,
non-fixture access, approved peer traffic and facility-specific action policy
remain outside this inert implementation. The
[runtime tests](../tests/runtime_owner.rs) use synthetic stores, not real peers.
