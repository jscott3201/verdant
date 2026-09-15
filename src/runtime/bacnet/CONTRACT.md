# M02-PR01B read contract and evidence manifest

Integration owner: Muse Spark contributor orchestrator. Implementation: Astra.
Independent peer/decoder review belongs to the orchestrator's review lane.
This is compiled socket-free support plus test-only live loopback evidence behind
the PR01A handoff, not a configured CLI service, commissioned binding, observed
qualification, or parent PR01 closure.

## E01, E03 and residuals

Exactly five added direct dependencies: bacnet-client, bacnet-types,
bacnet-services and bacnet-transport at rusty-bacnet
`02dd371201cb5d203058e9d0c8076c9ec9127338`, default features (ipv6/sc-tls OFF),
plus crates.io tokio 1 with net/rt/sync/macros/time (and PR04's inherited io-util).
This live slice changes no dependencies, features or pins. The lockfile selects
Tokio 1.53.1 and the BACnet crates 0.11.0. Existing Selene and compiler pins stay
unchanged: Selene `b65c2344c916d2c3ceeb72cefcd72e7960e95e25`, Rust/Cargo 1.97.1.
Validation target/profile: macOS / aarch64-apple-darwin / debug only.
The new transitive packages are lockfile dependencies, not additional direct APIs.
The development revision may drift upstream: every pin change needs revalidation.

Live reads/directed discovery: proven-with-captures in the E03 2026-09-14 amended
test-only profile. `src/runtime/bacnet/live_fixture.rs` binds exactly two named
127.0.0.1:0 UDP endpoints per run; their actual macOS ephemeral ports are printed
by READ-CAPTURE. No wildcard bind is needed. Only directed ReadProperty,
ReadPropertyMultiple and one-instance WhoIs are emitted. All fixture socket sends
and receives are captured and paired byte-for-byte, including capture-empty
refusals. BVLC Original-Unicast-NPDU, length, direct NPDU and service/property/range
literals are audited (MBAP is Modbus-specific and is not a BACnet header).
These are instrumented boundary captures, NOT host-wide pcap or proof about
uninstrumented traffic. No fixture packet is addressed off-loopback. Both tasks
join, the receive channel reaches observed EOF (UDP itself has no EOF), all socket
owners release, and both exact ports successfully rebind before the run passes.
No upstream source, IP-specific transport builder, COV implementation or ordinary
CLI activation is changed. Non-test builds still use only the in-memory transport.

APDU timeout = 6000 ms; APDU retries = 0, immutable during active work.
Verdant performs no retries or fallback service requests.
Read single-packet emission: proven-with-captures for the selected loopback RP/RPM
success, per-property/remote error, reject, abort, invalid reply, oversize, silent
peer TSM expiry and RP cancellation paths. Exactly one client UDP request send and
one identical peer receive occur per attempted read; denied/queued-expired work
emits zero. The transport does not suppress duplicate sends to manufacture this
result. The real 6000 ms TSM expiry is awaited for both RP and RPM, not cut short
by an accelerated timeout. This is NOT real-network duplication/loss qualification,
real-device interoperability, or a retry guarantee for other services/transports.
COV-wire and Modbus-wire retry items remain inherited and unchanged.
The pinned client's silent-peer TSM expiry returns `Abort(10)` (TSM_TIMEOUT),
not `Error::Timeout`; this raw reason is retained and does not claim a received
Abort packet. Its exact source is client/requests.rs:452–463 at the above pin.

## Frozen boundary and ownership

`src/runtime/mod.rs` keeps dispatch_next -> verify_content -> check_generation ->
adapter.read -> check_generation/cancellation. Admission copies the exact explicit
plan joined to the selected scope/key/source/endpoint/property. No discovered
device lookup can change its destination. Numeric direct endpoints only; routed
targets, DNS and broadcasts are refused. The fake profile's direct mapping from
the synthetic `mstp://ahu-1` binding is explicit fixture configuration, NOT a
commissioned route or evidence of real MS/TP or semantic onboarding.
The private fake-send boundary rechecks deadline/cancellation after startup and
encoding, immediately before capture; refused work does not consume its script.

`src/runtime/bacnet/client.rs` alone owns the private upstream read-client tuple. Its
only request operations are ReadProperty, ReadPropertyMultiple and directed WhoIs
for one instance. There is no public generic callback, transport injection, raw client,
Deref, writer, management, COV, file, BBMD or global WhoIs surface. The private
fake port also gates outgoing request type/destination and never forwards incoming
requests, routes or segmented frames that could provoke unsolicited responses.
The fixture performs no new product protocol-stack implementation: public service
codecs and client transaction processing are exercised with constrained direct
NPDUs. The private static ReadPort seam has only FakePort in non-test builds.
The test port retains the same destination/service/deadline gate and bounds before
upstream decode. Directed discovery waits for the bounded scripted reply count;
this fixture handshake is not a production discovery window or scan algorithm.

One timer-only Tokio executor per configured adapter is driven by the PR01A-owned
threads. It opens no I/O driver or additional worker thread. Each admitted job
owns its client and stops it before returning; public client stop joins its
dispatch and network dispatch, then stops the fake transport. Cancellation drops
the request future, not the stop future. A held stop retains the actual PR01A
job, lease and reservations; a bounded controller stop reports Unresolved. Drop
is not stop evidence. No SQL/native guard spans the client call.
The live test driver additionally owns an I/O-enabled current-thread reactor for
its isolated peer sockets; it drives the unchanged PR01A queue/dispatch/result and
private read client. No I/O driver or socket is added to ordinary adapter startup.

Candidate identity is (realm, device instance); conflicting advertisements stay
inspectable and cannot produce an accepted binding or plan. Expiry marks the
candidate, not acceptance or disappearance. Explicit discard releases candidate
reservations. Discovery outputs are retained only after generation recheck.
Per-property successes/errors remain separate; a batch is not simultaneous.
Source time is always absent. ReceiptOrigin::BacnetClientReturn means the earliest
response-correlated context exposed by the selected public client, recorded before
client stop. It is neither socket ingress nor a fabricated sensor timestamp.

## E02 extension of the PR01A fixture family

These are synthetic fixture assumptions and enforced payload/count boundaries,
not measured capacity, hard RSS/allocator limits, host-global quotas or facility
settings. `src/runtime/admission.rs` still owns shared admission.

* Retained slots: [2 current sensing, 2 reconciliation, 60 optional]. Active:
  [1, 1, 2]. No mandatory capacity is borrowed by discovery.
* Maximum request lifetime/drain = 35000 ms. B-case timeout = 30000 ms, including
  setup and checked at completion; waits use that same absolute test deadline.
  Existing bounded owner openers keep their own limits. Timeout means failure,
  never an inferred stop. APDU timeout = 6000 ms fits within the remaining lifetime.
* Maximum 16 plans/destinations; 8 explicit properties per RPM; 512 value bytes;
  1024 NPDU bytes checked before client decode, plus the 65536-byte PR01A raw
  envelope check. No segmented response admission or open-ended property expansion.
* One fake peer: 8 scripts x 4 replies x 1024 = 32768 bytes; captures:
  8 x 1024 = 8192 bytes; active transit: 4 x 4 x 1024 = 16384 bytes.
  Total bounded fake payload = 57344 bytes, separate from the existing 4 MiB
  retained-envelope reservation. Upstream fixed queues/executor metadata excluded.
* Maximum 16 candidates, 4 distinct advertisements per candidate, TTL 30000 ms.
  Each candidate reserves a slot from the SAME 60 optional slots, including when
  queued work/results already exhaust that partition. Full/conflicting tables
  refuse rather than silently retarget or evict inspectable conflicts.
* Poll first phase = one period after start; fixture period 100..30000 ms.
  A stalled scheduler reports missed periods and moves next to now + period;
  no catch-up burst, no automatic runtime ticker, no invented missed samples.
* Spool/pins remain zero; storage/native/journal reserves are unchanged.
* Live capture: at most 128 entries of 1029 bytes; receive margin is 1024+1 NPDU
  bytes solely to prove oversize refusal. Raw/filter queues each hold at most four
  messages, peer scripts at most eight exchanges/four replies. These test-fixture
  limits are separate from admission's shared [2,2,60]/[1,1,2] reservations.
  The 65536/65537 retained-envelope check uses a live-derived envelope with a
  synthetic enlarged capacity, NOT an impossible 65536-byte UDP payload. Poll
  phase/stall cases use explicit clock events driving actual reads, not suspend
  qualification or an operational ticker. Socket rebind has a 5s failure budget.

## Parent source/case/evidence manifest

PR01A A01–A10 remain in `tests/runtime_cases/cases.rs`, using real supported
owners and synthetic isolated stores. Their source includes `src/runtime/mod.rs`,
owners.rs, task.rs, admission.rs and inert.rs. Historic PR01 CLI byte strings and
10/10 evidence completeness remain separate, unchanged evidence contracts.

PR01B's integration binary is `tests/bacnet_reads.rs`; sources are model.rs,
client.rs, fake.rs, quarantine.rs, poll.rs and `src/runtime/plug.rs`.
Independent request/reply literals live in `tests/bacnet_cases/support.rs`:
manually specified APDU service choices, direct destinations, context/application
tags and value/error bytes (BACnet Clauses 15.5, 15.7, 16.10 and 20), not encoder
round trips. Full-case execution is evidenced by test output, not this name map.

| Case | Executable evidence (socket-free only) |
| --- | --- |
| B01 | reads::b01_allowed_direct_read_and_independent_bytes |
| B02 | reads::b02_allowlist_denials_emit_nothing; lifecycle::b02_generation_is_checked_before_fake_handoff |
| B03 | reads::b03_advertisements_are_quarantined_distinct_and_conflicts_inspectable; bounds_tests::b03_candidate_and_conflict_bounds_refuse_without_erasing_history |
| B04 | reads::b04_multi_read_retains_each_property_error |
| B05 | lifecycle::b05_expired_and_canceled_queued_reads_emit_nothing; fake::tests::b05_final_fake_handoff_rechecks_deadline_and_cancellation |
| B06 | reads::b06_oversized_input_refuses_before_upstream_and_value_copy_is_bounded; reads::b06_oversized_discovery_is_not_an_empty_success |
| B07 | lifecycle::b07_shared_saturation_preserves_mandatory_slots; lifecycle::b07_quarantine_uses_same_optional_reservation_family; bounds_tests::b07_fake_script_count_and_payload_bounds_refuse |
| B08 | lifecycle::b08_stalled_poll_records_misses_without_burst |
| B09 | manifest::b09_only_read_and_directed_discovery_bytes_reach_fake_port |
| B10 | lifecycle::b10_cancel_during_read_retains_owner_until_actual_stop_join; lifecycle::b10_superseded_callback_is_not_delivered; lifecycle::b10_public_client_timeout_is_an_outcome_not_a_retry_policy_claim |
| B11 | reads::b11_receipt_origin_explicit_source_time_absent |
| B12 | manifest::b12_parent_source_case_evidence_manifest_has_live_captures_and_remaining_deferrals |

The same integration binary additionally runs the following live rows. Every
Case::finish emits its endpoint pair, exact request count, sent/received counts,
start/stop/channel-EOF/rebind audit; refusal rows explicitly assert capture-empty.
`tests/bacnet_cases/live_support.rs` drives the real runtime owner. Independent
literals are in unchanged support.rs plus live_reads.rs/live_limits.rs, not client
encoder output. Source/case maps alone are not execution evidence.

| Live coverage | Executable case | READ-CAPTURE subcases |
| --- | --- | --- |
| B01/B11-live | live_reads::live_b01_b11_read_variants_and_receipt | rp-scalar; rp-array-count; rp-array-element; rp-false |
| B02/B09-live | live_reads::live_b02_b09_destination_service_and_attempted_calls_emit_nothing | denied-destination; denied-service; forbidden-attempts |
| B03-live | live_reads::live_b03_discovery_realms_conflicts_and_commissioned_freeze | directed-discovery-realm-a; directed-discovery-realm-b; frozen-before-after-live-and-synthetic-adverts; advertised-binding-promotion-refused |
| B04-live | live_reads::live_b04_rpm_per_property_and_unsupported_outcomes | rpm-per-property-error; rpm-unrecognized-service; rp-unknown-property; rp-unrecognized-service; rp-remote-abort; rp-mismatched-property |
| B05-live | live_limits::live_b05_queued_deadline_and_cancellation_are_capture_empty | queued-expired-canceled |
| B06-live | live_limits::live_b06_value_npdu_and_retained_envelope_bounds | value-512; value-513; npdu-1024; npdu-1025 |
| B07-live | live_limits::live_b07_shared_exhaustion_preserves_mandatory_reserve | shared-exhaustion-mandatory-reads; live-quarantine-shares-budget |
| B08-live | live_limits::live_b08_startup_missed_poll_no_burst_or_false_samples | poll-startup-stall-no-burst |
| B10-live | live_limits::live_b10_zero_retry_rp_and_rpm_timeout_and_cancel | rp-timeout; rpm-timeout; rp-canceled-after-emission |

Parent live-peer acceptance remains open: this manifest does not adjudicate full
original parent closure or independent review. Facility/real-device behavior,
physical packet behavior outside these instrumented endpoints, and production
live transport activation remain unproven. COV, Modbus, writer chain, F02,
UI/hub/MCP, migrations, real credentials, facility values and field qualification
remain excluded. M03 consumer byte-fit is not established by this read fixture.
