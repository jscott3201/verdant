# M02-PR04 synthetic Modbus/TCP read boundary

## Profile and source

D02/E01 (2026-09-14) selects exactly rusty-modbus **client, types, codec,
frame, tcp**, all 0.1.1/default features at
`70c8e50ab08ad039513a437f0fa328bf5974b57c`. Tokio 1 gains `io-util` for
the test peer; the existing net/rt/sync/macros/time features remain. Rust/Cargo
1.97.1, Selene and BACnet pins are unchanged. No facade/full, TLS, server,
gateway, pool, RTU/serial, CLI, simulator, conformance or Python package is selected.

Reviewed pinned source: client `methods/coils.rs`, `methods/registers.rs`,
`methods/mod.rs`, `client.rs`, `config.rs`, `lifecycle.rs`, `transaction.rs`;
TCP `connect.rs`, `transport.rs`; frame `frame.rs`; types `header.rs`.
These are source evidence, not a protocol-conformance certification.

## Admission and meaning

- Only `127.0.0.1`, ports ≥1024 excluding 502/802/8080/47808, unit 255 (direct TCP) or 1–247
  (addressed loopback fixture) can be admitted. Unit 0 is refused before a
  public client call. There is no DNS, routed destination, broadcast, generic
  request, unrestricted client accessor, write or listener API in the wrapper.
  Ephemeral allocation is established by `test_peer::Pair::at` binding the peer
  to `127.0.0.1:0` (reconnect reuses that peer) and `TcpTransport::connect` leaving
  the client port to the OS, not by the numeric admission/audit guard. OS port
  ranges, including Linux's sysctl-tunable range, are not baked into this boundary.
- The private runtime admission method verifies current accepted/active sensing
  binding identity before yielding one immutable map. Ordinary CLI dispatch
  remains unchanged and never starts this client. This is synthetic preparation,
  not non-fixture authority, a selected operational service or observed qualification.
- A `Read` is a zero-based wire address, not vendor 1-based/4xxxx notation.
  Quantities are 1–2000 bits or 1–125 words; the inclusive last address must fit
  u16. The client checks exact response function/unit and data length, including
  unused bit padding. FC03 raw is the **only** raw read variant exposed by this
  pinned public library; it has the same length checks as the word variant.
- A map retains revision, source role, target/unit, function/address/quantity,
  encoding, word/byte order, scale and explicitly supplied unit. Byte order applies
  within a word; word order names significance. Signed integers use two's
  complement. Integer scaling is exactly
  `(integer * numerator + offset) / 10^places`, with at most nine decimal places;
  no binary floating-point rounding or inferred units. Bool maps require one bit
  and identity scale. U16/I16 require one word; U32/I32 require two.
- Unsupported encodings (including floating-point/vendor layouts) preserve
  Unknown quality and refuse dependent use. Unknown units remain unknown.
  Wrong quantity/shape is invalid, never a silent map. The existing
  TransportResult/ValueQuality/Suitability/Refusal types are reused, not copied.
  Map equality, not just revision text, is checked when decoding a sample.
- A sample retains raw words/bits/FC03 register bytes, full map, runtime
  incarnation, source generation, per-client sequence and read-return wall and
  monotonic receipt times. These are **not durable observation IDs**, a sensor
  timestamp or kernel-arrival timestamp. No second latest-value owner or SQL
  receive path is introduced. M03 byte-fit/durable Modbus-row integration is not
  qualified by this profile.

## Lifecycle and resources

`connect -> sequential bounded reads -> shutdown` is explicit. The default
request timeout is five seconds, max retries is zero, and the retryable-exception
set/delay is untouched. Tests observe one logical attempt then exhaustion for
timeout/busy; **wire-single-packet semantics remain unverified**.

One connection retains one CurrentSensing slot from the original runtime budget;
each read temporarily holds the second retained slot and one active slot.
Reconciliation/optional partitions remain unchanged. No new semaphore exists.
The existing 35-second fixture lifetime bounds read admission; runtime stop seals
it. Client ownership must still be explicitly shut down: an idle connection is
not a background operational worker. Returned evidence is caller-owned, not an
unbounded internal result queue or spool.

Shutdown seals immediately, awaits the public client's drain/join (10-second
configuration), then drops its retained sink. A second outer ten-second wait
can report Unresolved; retain the owner and retry shutdown. `TransportSink` has
no close/flush method, so upstream logical shutdown alone cannot prove socket
closure. Tests additionally observe peer EOF and both endpoints rebinding.
Abort/caller cancellation retires the client and declares a coverage change;
abort or Drop alone is never reported as joined. Dropping an unjoined owner leaves
the runtime reservation unresolved, rather than manufacturing cleanup evidence.

Reconnect requires a fresh runtime permit after shutdown and exact same map/peer.
It establishes new process-local source identity while retaining sticky coverage
loss. Health/reconnect/fresh poll never refreshes an old sample or repairs an
unobserved interval. Existing PR03B `Coverage::read_retained` composition is reused
without changing COV, replay, gaps, custody, migrations or storage admission.

The Modbus scripted/capture/in-flight payload assumption is **12480 bytes**:
8 scripted replies + 32 capture records + 4 active slots × 2 frames, each ≤260
bytes. Tests enforce script/frame/capture counts. This sits beside the unchanged
BACnet 57344-byte precedent; it is not an allocator/RSS, OS buffer, host-global
quota or facility-capacity measurement.

## Live acceptance and capture manifest

`cargo test --locked --test modbus_live modbus_ -- --nocapture` emits a
`MODBUS-CAPTURE` line for **every** live connection. Each line names its actual
ephemeral `client` and `peer` addresses, byte totals and observed cleanup.
`test_peer.rs` uses the real pinned TcpTransport and client, with a test-only
transport decorator and independently hardcoded complete peer frames. It extends
the existing `bacnet/test_loopback.rs` PacketLog; TCP stream bytes are compared,
not syscall or IP packet counts. Responses deliberately split across header/PDU.

| Capture case | Acceptance |
| --- | --- |
| FC01-direct-9-bits | exact FC01 bit order/quantity, wrong read route refused |
| FC02-addressed-1-bits / FC02-addressed-2000-bits | false, addressed slave, max quantity |
| FC03-signed-multi-and-raw | signed multi-word and raw reads, transaction progression, distinct receipts |
| FC04-1-registers / FC04-125-registers | zero and maximum register quantity |
| unit-mismatch / function-mismatch | correlated but wrong unit/function refused |
| short-quantity / long-quantity / malformed-byte-count | exact quantity/PDU validation |
| FC01-padding | nonzero unused bits refused |
| timeout-no-reply / wrong-transaction / busy-zero-retries | one attempt exhausted, no fresh second read |
| caller-cancel-abort-join | caller disappearance is loss, runtime stop remains unresolved until join |
| reconnect-before / reconnect-after-same-peer | same named peer, fresh source, sticky lost interval |
| coverage-loss-PR03B | actual timeout composed with unchanged bounded custody/replay |

All captured traffic is directed between the named loopback endpoints; privileged
ports and 502/802/8080/47808 are forbidden (Modbus, the refused listener fixture,
and BACnet). These are **instrumented fixture-boundary captures, not host-wide
pcap or evidence about uninstrumented/off-interface traffic**. Malformed-PDU
cases retain well-framed MBAP envelopes; hostile/truncated MBAP byte streams are
not newly qualified here. No facility values, PLC, physical link, broadcast,
real-network behavior, real-time deadlines or zero-flakiness claim is made.

Socket-free tests cover the full function/unit allowlist, invalid destinations,
zero/over-limit quantities, address overflow, exact mapping/order/scaling,
unknown units/encodings, map revision/content changes and shared-budget refusal.
