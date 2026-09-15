//! PR03 re-validation on live envelopes: PR36 loopback -> normalization -> 0003.
//! Retires that closure-matrix item only. The frozen historical D10 checklist is
//! unchanged; parent closure, F02/E05, facility proof and M03 byte-fit remain open
//! or residual. No production socket, new Window API, migration or field authority.
#![allow(dead_code)]
#[path = "../src/accept/mod.rs"]
mod accept;
#[path = "accept_cases/support.rs"]
mod accept_support;
#[path = "../src/access/mod.rs"]
mod access;
#[path = "../src/api/mod.rs"]
mod api;
#[path = "bacnet_cases/support.rs"]
mod bacnet_support;
#[path = "../src/binding/mod.rs"]
mod binding;
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "observation_live_cases/envelopes.rs"]
mod envelopes;
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "runtime_cases/helpers.rs"]
mod helpers;
#[path = "bacnet_cases/live_support.rs"]
#[allow(unused_imports)] // The shared PR36 driver also re-exports unused discovery fixtures.
mod live_support;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "../src/observation/mod.rs"]
mod observation;
#[path = "observation_cases/support.rs"]
mod observation_support;
#[path = "../src/runtime/mod.rs"]
mod runtime;
#[path = "../src/seal/mod.rs"]
mod seal;
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "../src/storage/mod.rs"]
mod storage;

mod support {
    // Existing runtime fixture wiring, not another acceptance implementation.
    pub use crate::accept_support::*;
    pub use crate::observation_support::{clock, key, mark, unit};
    use crate::{accept, access, binding, fixture, live_support::*, observation::*, storage};
    use identity::{ProducerId, ProducerIncarnation};
    use normalize::{Codec, UnitProvenance};
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use storage::{sqlite::MutationOutcome, ConnectionSettings, StoreBounds};
    use time::{Freshness, FreshnessPolicy, ObservationTimes};
    use window::{Access, Checkpoint, Retention, Window};

    pub fn live_policy() -> FreshnessPolicy {
        // Owner-approved LIVE fixture values only. Harness::pending and its
        // synthetic 100ms/2ms policy are intentionally untouched.
        FreshnessPolicy::new(Duration::from_secs(12), Duration::from_millis(250)).unwrap()
    }
    pub fn receipt_ms(raw: &RawEnvelope) -> u64 {
        raw.receipt_time
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap()
    }
    pub fn pending(
        raw: &RawEnvelope,
        context: &BindingContext,
        codec: Codec,
        units: UnitProvenance,
    ) -> PendingObservation {
        let ms = receipt_ms(raw);
        // Explicit fixture clock coordinates aligned with the live receipt. They
        // are not a serialization of Instant or host boot/suspend qualification.
        // Keep the envelope's actual wall time, absent source and origin unchanged.
        PendingObservation::from_bacnet(
            raw,
            context.clone(),
            Normalization {
                units,
                codec,
                receipt_mark: mark(ms),
                ingestion: clock(ms),
            },
            live_policy(),
        )
        .unwrap()
    }
    pub fn incarnation() -> ProducerIncarnation {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        ProducerIncarnation::parse(&format!(
            "live-{}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
        .unwrap()
    }
    pub fn committed(result: MutationOutcome) {
        assert!(matches!(result, MutationOutcome::Committed { .. }), "{result:?}");
    }
    pub fn ack(tags: &[u8]) -> Vec<u8> {
        // Independent fixed RP ACK framing, same AI:1/presentValue as READ.
        // Only the literal application value varies; no production encoder.
        let mut bytes = vec![1, 0, 48, 0, 12, 12, 0, 0, 0, 1, 25, 85, 62];
        bytes.extend_from_slice(tags);
        bytes.push(63);
        bytes
    }
    pub fn acquire(request: Request, exchanges: Vec<Exchange>, name: &str) -> Vec<RawEnvelope> {
        let count = exchanges.len();
        let mut c = Case::new(request, exchanges);
        let rows = (0..count)
            .map(|_| {
                let raw = c.run(CurrentSensing).unwrap();
                assert_eq!(batch(&raw).target, c.target);
                assert_eq!(raw.runtime_incarnation, c.runtime.status().incarnation.unwrap());
                assert_eq!(
                    raw.source_generation,
                    c.runtime.status().source_generation.unwrap()
                );
                raw
            })
            .collect();
        // Observed stop/join/EOF/rebind and exact wire requests, never a timeout
        // inferred as a stop. Release the peer before storage-only operations.
        c.finish(name);
        rows
    }
    pub fn samples(count: usize) -> Vec<RawEnvelope> {
        let mut rows = Vec::new();
        while rows.len() < count {
            let n = (count - rows.len()).min(8); // PR36 Case's fixed exchange bound.
            rows.extend(acquire(
                Request::read_property(pv()),
                vec![exchange(READ, ACK); n],
                "pr03-samples",
            ));
        }
        rows
    }

    pub struct Driver {
        pub gate: access::AccessGate,
        pub credentials: access::BootstrapCredentials,
        pub registry: binding::BindingRegistry,
        pub config: accept::EffectiveConfig,
        pub scratch: fixture::Scratch,
    }
    impl Driver {
        pub fn new() -> Self {
            let scratch = fixture::Scratch::new();
            let (gate, credentials) = access::AccessGate::bootstrap(
                &scratch.db(),
                ConnectionSettings::local_wal_full(),
                StoreBounds::tiny(),
                &access::Reason::parse("PR03 loopback-live revalidation; no field authority").unwrap(),
            )
            .unwrap();
            let mut registry = binding::BindingRegistry::open(
                &scratch.db(),
                ConnectionSettings::local_wal_full(),
                StoreBounds::tiny(),
            )
            .unwrap();
            let config = crate::observation_support::config(&gate, &mut registry, fixture::scope());
            assert_eq!(
                registry
                    .store()
                    .exec_script(
                        "PRAGMA user_version; SELECT group_concat(generation) FROM schema_migrations;"
                    )
                    .unwrap(),
                vec![vec!["1"], vec!["1,2,3"]]
            );
            Self {
                gate,
                credentials,
                registry,
                config,
                scratch,
            }
        }
        pub fn access(&self) -> Access<'_> {
            Access {
                gate: &self.gate,
                credential: Some(&self.credentials.reviewer),
            }
        }
        pub fn open(&self, checkpoint: Option<&Checkpoint>) -> Window {
            // open_synthetic covers custody of loopback-live rows, under synthetic
            // review authority. It does NOT activate an acquisition service or
            // upgrade meaning, freshness, provenance or field qualification.
            Window::open_synthetic(
                self.registry.store().try_clone().unwrap(),
                self.access(),
                fixture::scope(),
                ProducerId::parse("sensor-sat-producer").unwrap(),
                incarnation(),
                checkpoint,
            )
            .unwrap()
        }
        pub fn context(&self, raw: &RawEnvelope, property: Property) -> BindingContext {
            BindingContext::loopback(&self.config, raw, property).unwrap()
        }
        pub fn row(&self, w: &Window, raw: &RawEnvelope) -> NormalizedObservation {
            w.identify(
                self.access(),
                pending(raw, &self.context(raw, pv()), Codec::Scalar, unit()),
            )
            .unwrap()
        }
        pub fn capture(
            &self,
            w: &Window,
            row: &NormalizedObservation,
            class: Retention,
            ms: u64,
        ) -> spool::Capture {
            let before = w.checkpoint(self.access()).unwrap();
            let ticket = w.prepare_capture(self.access(), row, class, &clock(ms)).unwrap();
            assert_eq!(
                w.checkpoint(self.access()).unwrap(),
                before,
                "preparation is not capture"
            );
            committed(w.submit_capture(self.access(), &ticket, &clock(ms)).unwrap());
            assert_eq!(w.checkpoint(self.access()).unwrap().next, before.next + 1);
            self.assert_stored(w, row);
            ticket
        }
        pub fn append(&self, w: &Window, raw: &RawEnvelope, class: Retention) -> NormalizedObservation {
            let row = self.row(w, raw);
            self.capture(w, &row, class, receipt_ms(raw));
            row
        }
        pub fn assert_stored(&self, w: &Window, row: &NormalizedObservation) {
            // Law 1 across actual client return, normalization, durable readback.
            assert_eq!(row.raw().source_time, None);
            assert_eq!(
                row.raw().receipt_origin,
                runtime::ReceiptOrigin::BacnetClientReturn
            );
            assert_eq!(
                row.time().receipt_origin,
                runtime::ReceiptOrigin::BacnetClientReturn
            );
            assert!(matches!(row.time().times, ObservationTimes::SourceAbsent { .. }));
            let stored = w.read(self.access(), row.id()).unwrap().unwrap();
            assert_eq!(stored.id, *row.id());
            assert_eq!(stored.value, row.decoded().value);
            assert_eq!(stored.unit, row.decoded().unit);
            assert_eq!(stored.source_ms, None);
            assert_eq!(stored.receipt_ms, row.time().times.receipt().as_millis());
            assert_eq!(stored.receipt_mark, row.time().receipt_mark);
            assert_eq!(stored.raw_evidence, format!("{row:?}")); // Same-build witness, not a portable codec.
            assert_eq!(stored.freshness, Freshness::Unknown);
            assert_eq!(
                stored.dependent_value().unwrap_err().code(),
                "replayed-evidence-not-fresh"
            );
        }
    }
}

mod window_cases {
    use crate::{access, domain::scope::TrustedScope, live_support::*, observation::*, support::*};
    use identity::ObservationId;
    use window::{Access, Retention};

    #[test]
    fn c10_live_rows_require_scope_and_current_review_for_read_pin_and_capture() {
        let h = Driver::new();
        let raws = samples(2);
        let w = h.open(None);
        w.select_binding(h.access(), &h.context(&raws[0], pv())).unwrap();
        let row = h.append(&w, &raws[0], Retention::OptionalHistory);
        let ms = receipt_ms(&raws[0]);
        let pin = w.pin(h.access(), row.id(), &clock(ms)).unwrap();
        let scope = TrustedScope::parse("scope-b").unwrap();
        let other = ObservationId::new(
            scope.clone(),
            row.id().producer().clone(),
            row.id().position().clone(),
        );
        assert_eq!(
            w.read(h.access(), &other).unwrap_err().code(),
            "scope-or-producer-mismatch"
        );
        assert_eq!(
            w.pin(h.access(), &other, &clock(ms)).unwrap_err().code(),
            "scope-or-producer-mismatch"
        );
        let b = h
            .gate
            .issue(
                &access::CapabilityName::parse("b-reviewer").unwrap(),
                &scope,
                1,
                access::RoleKind::Reviewer,
                &access::KeyId::parse("b-key").unwrap(),
                &access::SyntheticKey::parse("synthetic-b-key").unwrap(),
                &h.credentials.publisher,
                &access::Reason::parse("synthetic scope B").unwrap(),
                &access::DisplayLabel::parse("B").unwrap(),
            )
            .unwrap();
        for (credential, code) in [(None, "anonymous-denied"), (Some(&b), "scope-denied")] {
            let denied = Access {
                gate: &h.gate,
                credential,
            };
            assert_eq!(w.read(denied, row.id()).unwrap_err().code(), code);
            assert_eq!(w.current(denied, &key()).unwrap_err().code(), code);
            assert_eq!(w.replay(denied, 0, 64).unwrap_err().code(), code);
            assert_eq!(w.pin(denied, row.id(), &clock(ms)).unwrap_err().code(), code);
            assert_eq!(w.materialize(denied, &pin, &clock(ms)).unwrap_err().code(), code);
        }
        let next = h.row(&w, &raws[1]);
        let ticket = w
            .prepare_capture(h.access(), &next, Retention::OptionalHistory, &clock(ms))
            .unwrap();
        h.gate
            .revoke(
                &h.credentials.reviewer,
                &access::Reason::parse("synthetic revoke").unwrap(),
            )
            .unwrap();
        assert_eq!(
            w.read(h.access(), row.id()).unwrap_err().code(),
            "revoked-credential"
        );
        assert_eq!(
            w.current(h.access(), &key()).unwrap_err().code(),
            "revoked-credential"
        );
        assert_eq!(
            w.materialize(h.access(), &pin, &clock(ms)).unwrap_err().code(),
            "revoked-credential"
        );
        assert_eq!(
            w.submit_capture(h.access(), &ticket, &clock(ms))
                .unwrap_err()
                .code(),
            "revoked-credential"
        );
        assert_eq!(
            h.registry
                .store()
                .exec_script("SELECT count(*) FROM observations;")
                .unwrap(),
            vec![vec!["1"]]
        );
    }

    #[test]
    fn d01_live_slow_subscriber_replays_or_reads_durable_tombstones() {
        let h = Driver::new();
        let w = h.open(None);
        let raws = samples(12);
        let rows: Vec<_> = raws
            .iter()
            .map(|raw| h.append(&w, raw, Retention::OptionalHistory))
            .collect();
        let page = w.replay(h.access(), 0, 64).unwrap();
        assert_eq!(page.records.len(), 12);
        assert!(page.gaps.is_empty() && !page.more);
        assert_eq!(w.evict(h.access(), &clock(receipt_ms(&raws[11]))).unwrap(), 8);
        let checkpoint = w.checkpoint(h.access()).unwrap();
        drop(w);
        let w = h.open(Some(&checkpoint));
        let page = w.replay(h.access(), 0, 64).unwrap();
        assert_eq!(
            page.records
                .iter()
                .map(|r| r.id.position().seq())
                .collect::<Vec<_>>(),
            vec![8, 9, 10, 11]
        );
        assert_eq!(
            page.gaps,
            vec![crate::storage::observation_writer::Gap {
                from: 0,
                to: 7,
                reason: "window-evicted".into()
            }]
        );
        assert_eq!((page.next, page.more), (12, false));
        let page = w.replay(h.access(), 4, 2).unwrap();
        assert_eq!(
            (page.gaps[0].from, page.gaps[0].to, page.next, page.more),
            (4, 5, 6, true)
        );
        assert_eq!(w.replay(h.access(), 0, 0).unwrap_err().code(), "replay-limit");
        for row in &rows[8..] {
            h.assert_stored(&w, row);
        }
    }

    #[test]
    fn d02_live_optional_slots_preserve_mandatory_reserve_and_refusal_does_not_capture() {
        let h = Driver::new();
        let w = h.open(None);
        let raws = samples(33);
        for raw in &raws[..28] {
            h.append(&w, raw, Retention::OptionalHistory);
        }
        let before = w.checkpoint(h.access()).unwrap();
        let row = h.row(&w, &raws[28]);
        assert_eq!(
            w.prepare_capture(
                h.access(),
                &row,
                Retention::OptionalHistory,
                &clock(receipt_ms(&raws[28]))
            )
            .unwrap_err()
            .code(),
            "mandatory-reserve"
        );
        assert_eq!(w.checkpoint(h.access()).unwrap(), before);
        for raw in &raws[28..32] {
            h.append(&w, raw, Retention::Mandatory);
        }
        let row = h.row(&w, &raws[32]);
        assert_eq!(
            w.prepare_capture(
                h.access(),
                &row,
                Retention::Mandatory,
                &clock(receipt_ms(&raws[32]))
            )
            .unwrap_err()
            .code(),
            "spool-full-escalate"
        );
        assert_eq!(w.checkpoint(h.access()).unwrap().next, 32);
        assert_eq!(w.replay(h.access(), 0, 64).unwrap().records.len(), 32);
        assert!(w.read(h.access(), row.id()).unwrap().is_none());
    }

    #[test]
    fn d03_d04_live_pins_ttl_owned_readback_and_eviction_protect_current_and_mandatory() {
        let h = Driver::new();
        let w = h.open(None);
        // One runtime context; deliver the newest receipt before older live rows
        // so current is OUTSIDE the newest-two retention tail during eviction.
        let raws = acquire(
            Request::read_property(pv()),
            vec![exchange(READ, ACK); 8],
            "pr03-pins",
        );
        w.select_binding(h.access(), &h.context(&raws[0], pv())).unwrap();
        let mandatory = h.append(&w, &raws[0], Retention::Mandatory);
        let held = h.append(&w, &raws[1], Retention::OptionalHistory);
        let ms = receipt_ms(&raws[7]);
        let expected = w.read(h.access(), held.id()).unwrap().unwrap();
        assert_eq!(expected.value.to_json(), r#"{"type":"integer","value":"7"}"#);
        let pins: Vec<_> = (0..8)
            .map(|_| w.pin(h.access(), held.id(), &clock(ms)).unwrap())
            .collect();
        assert_eq!(
            w.pin(h.access(), held.id(), &clock(ms)).unwrap_err().code(),
            "pin-full"
        );
        let latest = h.append(&w, &raws[7], Retention::OptionalHistory);
        for raw in &raws[2..7] {
            h.append(&w, raw, Retention::OptionalHistory);
        }
        let checkpoint = w.checkpoint(h.access()).unwrap();
        drop(w);
        let w = h.open(Some(&checkpoint));
        let owned = w.materialize(h.access(), &pins[0], &clock(ms + 34_999)).unwrap();
        assert_eq!(owned, expected);
        assert_eq!(
            w.materialize(h.access(), &pins[0], &clock(ms + 35_000))
                .unwrap_err()
                .code(),
            "pin-expired"
        );
        // Independent eviction oracle: 0 mandatory, 1 pinned, 2 current, 6–7 tail.
        assert_eq!(w.evict(h.access(), &clock(ms + 1)).unwrap(), 3);
        assert_eq!(
            w.replay(h.access(), 0, 64)
                .unwrap()
                .records
                .iter()
                .map(|r| r.id.position().seq())
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 6, 7]
        );
        assert!(w.read(h.access(), mandatory.id()).unwrap().is_some());
        assert_eq!(
            w.materialize(h.access(), &pins[1], &clock(ms + 1)).unwrap(),
            expected
        );
        assert_eq!(w.current(h.access(), &key()).unwrap().unwrap().id, *latest.id());
        w.settle(h.access(), mandatory.id()).unwrap();
        for pin in &pins {
            w.release_pin(h.access(), pin).unwrap();
        }
        assert_eq!(owned, expected, "materialization is owned after pin release");
        assert_eq!(
            w.materialize(h.access(), &pins[0], &clock(ms + 1))
                .unwrap_err()
                .code(),
            "pin-not-held"
        );
        assert_eq!(w.evict(h.access(), &clock(ms + 1)).unwrap(), 2);
        assert!(w.read(h.access(), held.id()).unwrap().is_none());
        assert!(w.read(h.access(), mandatory.id()).unwrap().is_none());
        h.assert_stored(&w, &latest);
    }
}
