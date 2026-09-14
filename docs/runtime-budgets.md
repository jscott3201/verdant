# Runtime fixture budgets

[Back to README](../README.md) · [Capabilities](capabilities.md) ·
[Evidence levels](evidence-levels.md)

These are **synthetic fixture assumptions**, not measured capacity, performance
targets or facility settings. They apply to the explicitly started inert
[runtime API](../src/runtime/mod.rs), which ordinary CLI `run` does not start.
Class names such as current sensing and optional discovery partition accounting;
they do not mean that sensors are read or discovery packets are sent.

## Fixture bounds

One budget family counts queued work, actual jobs and retained results across
the separate supported store handle families. Enforcement lives in
[admission.rs](../src/runtime/admission.rs).

| Resource | Runtime fixture bound |
| --- | --- |
| Queued + running + retained-result slots | 64 total: 2 current-sensing, 2 reconciliation, 60 optional-discovery; mandatory slots cannot be borrowed. |
| Concurrent jobs, including SQLite/hash/native verification | 4 total: 1 current-sensing, 1 reconciliation, 2 optional; startup consumes reconciliation capacity. |
| Raw-envelope reservation | 65,536 bytes each; 4,194,304 bytes aggregate. Errors retain typed origin/stable code rather than subprocess output. |
| Request lifetime / stop budget | 35,000 ms request budget including queueing; stop is capped at a 35,000 ms wait budget and can return explicitly unresolved jobs. Neither is a hard real-time completion guarantee. |
| Result retention | Finite slot count until explicit take or stop; not a current-value cache, history window or freshness promise. |
| Observation spool / runtime pins | 0 bytes / 0 pins admitted. Durable observation storage is future work. |

## Derivation and retained owner limits

The 64 slots fit [StoreBounds::tiny](../src/storage/mod.rs)'s 64 tasks and the
API's 64-entry page ceiling. Four concurrent jobs stay below the store family's
16 running operations and [NativeBounds::local](../src/native/settings.rs)'s
8 admissions. Each running verification is sequential within one slot, even
though supported access and binding openers create separate SQLite families.
At most 64 envelopes × 65,536 bytes gives a 4 MiB reservation, not a bound on
total process memory.

Existing owner settings and reserves remain separate:

| Owner | Local fixture setting / reserve |
| --- | --- |
| [SQLite](../src/storage/mod.rs) | WAL/FULL, 5,000 ms busy wait, 35,000 ms operation budget, 8,388,608-byte retained-journal setting. |
| [Native maintenance](../src/native/settings.rs) | 1,048,576-byte working reserve and 1,048,576-byte future-journal reserve. |
| [Seal custody](../src/seal/mod.rs) | 32 live seals, 256 history rows, 64 closure nodes, depth 16, 262,144 closure bytes, 8 native references, 2,097,152 bytes per artifact. |
| [Setup API](../src/api/mod.rs) | Page/work bounds of 64/256. |
| [Synthetic access](../src/access/mod.rs) | Review/publish ceilings of 1/2. |

The native reserves are planning allowances, not allocated disk. SQLite's
retained-journal setting trims a reset/checkpointed journal; it is **not a hard
live-WAL cap**. Independent owners are not silently included in this runtime's
accounting.

## Stop and unresolved work

The runtime closes intake and joins actual jobs, or returns `Unresolved` while
retaining their reservations. Keep that owner and poll/stop again. Dropping it
reports abandoned work as unresolved and does **not** assert a successful join.
`Stopped` refers to runtime jobs, not closing retained stores or proving all
Selene-internal shutdown work finished ([runtime lifecycle](../src/runtime/mod.rs)).

No SQL transaction or native/registry guard spans the inert adapter call.
Content, authority and generation checks are last-read evidence, not a lease or
cross-process fence; see the [capability guide](capabilities.md#inert-runtime-api).

## What these budgets do not prove

- No host-global memory/disk quota, child-process heap/CPU limit, or process-tree
  sandbox follows from handle-family admission limits.
- No power-loss, real disk-full, sustained-throughput, latency or real-time
  scheduling qualification follows from synthetic tests.
- No observation freshness, historical retention window, durable observation
  spool, field acquisition, subscription or writer admission is delivered here.
- Cancellation or a deadline does not prove a worker exited; only an observed
  join establishes that part of a stop.

The [runtime test suite](../tests/runtime_owner.rs) exercises these boundaries
with isolated synthetic stores. See [evidence levels](evidence-levels.md) for
platform and historical test-count limitations.
