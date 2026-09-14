//! Explicit E03 loopback fixtures only; each connection MUST finish its capture.
#![allow(dead_code)]
#[path = "../src/accept/mod.rs"]
mod accept;
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
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "runtime_cases/helpers.rs"]
mod helpers;
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
#[path = "accept_cases/support.rs"]
mod support;
use domain::values::{Unit, Value};
use observation::normalize::{Refusal, Suitability, TransportResult, ValueQuality};
use runtime::{
    modbus::{
        mapping::*,
        test_peer::{Pair, Step},
        *,
    },
    Drain, Runtime,
};
use std::time::Duration;

fn map(target: Target, function: Function, quantity: u16, encoding: Encoding) -> Map {
    Map::new(
        "fixture-map-r1",
        "synthetic-sense",
        target,
        Read::new(function, 16, quantity).unwrap(),
        encoding,
        ByteOrder::Big,
        WordOrder::HighFirst,
        Scale::IDENTITY,
        Unit::parse("degC").unwrap(),
    )
    .unwrap()
}
fn step(request: &[u8], response: &[u8]) -> Step {
    Step {
        request: request.to_vec(),
        response: Some(response.to_vec()),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn modbus_fc01_direct_coils_exact_bits_and_no_wrong_read_route() {
    let mut runtime = Runtime::default();
    let (pair, mut client) = Pair::new(
        &mut runtime,
        |t| map(t, Function::Coils, 9, Encoding::Unsupported("bit-vector".into())),
        255,
        vec![step(
            &[0, 1, 0, 0, 0, 6, 255, 1, 0, 16, 0, 9],
            &[0, 1, 0, 0, 0, 5, 255, 1, 2, 1, 1],
        )],
        TIMEOUT,
    )
    .await;
    assert!(matches!(
        client.read_input_registers().await,
        Err(Error::DeniedService)
    ));
    let sample = client.read_coils().await.unwrap();
    assert_eq!(
        sample.payload,
        Payload::Bits(vec![true, false, false, false, false, false, false, false, true])
    );
    assert_eq!(
        sample.decode(&sample.map).unwrap().suitability,
        Suitability::Refused(Refusal::Unsupported)
    );
    assert!(client.is_connected());
    pair.finish("FC01-direct-9-bits", &mut client).await;
    assert!(matches!(client.read_coils().await, Err(Error::Closed)));
    drop(client);
    assert_eq!(runtime.stop(Duration::ZERO).unwrap(), Drain::Stopped);
}

#[tokio::test(flavor = "current_thread")]
async fn modbus_fc02_addressed_false_and_max_quantity() {
    for quantity in [1, 2000] {
        let mut runtime = Runtime::default();
        let (request, response) = if quantity == 1 {
            (
                vec![0, 1, 0, 0, 0, 6, 1, 2, 0, 16, 0, 1],
                vec![0, 1, 0, 0, 0, 4, 1, 2, 1, 0],
            )
        } else {
            let mut response = vec![0, 1, 0, 0, 0, 253, 1, 2, 250];
            response.extend([0; 250]);
            (vec![0, 1, 0, 0, 0, 6, 1, 2, 0, 16, 7, 208], response)
        };
        let (pair, mut client) = Pair::new(
            &mut runtime,
            |t| {
                map(
                    t,
                    Function::DiscreteInputs,
                    quantity,
                    if quantity == 1 {
                        Encoding::Bool
                    } else {
                        Encoding::Unsupported("bit-vector".into())
                    },
                )
            },
            1,
            vec![Step {
                request,
                response: Some(response),
            }],
            TIMEOUT,
        )
        .await;
        let sample = client.read_discrete_inputs().await.unwrap();
        assert_eq!(sample.payload, Payload::Bits(vec![false; usize::from(quantity)]));
        if quantity == 1 {
            assert_eq!(sample.decode(&sample.map).unwrap().value, Value::Bool(false));
        }
        pair.finish(&format!("FC02-addressed-{quantity}-bits"), &mut client)
            .await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn modbus_fc03_signed_multi_register_and_raw_have_distinct_receipts() {
    let mut runtime = Runtime::default();
    let (pair, mut client) = Pair::new(
        &mut runtime,
        |t| map(t, Function::HoldingRegisters, 2, Encoding::I32),
        247,
        vec![
            step(
                &[0, 1, 0, 0, 0, 6, 247, 3, 0, 16, 0, 2],
                &[0, 1, 0, 0, 0, 7, 247, 3, 4, 255, 255, 255, 254],
            ),
            step(
                &[0, 2, 0, 0, 0, 6, 247, 3, 0, 16, 0, 2],
                &[0, 2, 0, 0, 0, 7, 247, 3, 4, 255, 255, 255, 254],
            ),
        ],
        TIMEOUT,
    )
    .await;
    let first = client.read_holding_registers().await.unwrap();
    let second = client.read_holding_registers_raw().await.unwrap();
    assert_eq!(first.payload, Payload::Words(vec![65535, 65534]));
    assert_eq!(second.payload, Payload::RegisterBytes(vec![255, 255, 255, 254]));
    assert_eq!(first.decode(&first.map).unwrap().value, Value::Integer(-2));
    assert_eq!(second.decode(&first.map).unwrap().value, Value::Integer(-2));
    assert_eq!(first.incarnation, second.incarnation);
    assert_eq!(first.source, second.source);
    assert_ne!(first.sequence, second.sequence);
    assert!(second.receipt_monotonic >= first.receipt_monotonic);
    let changed = Map::new(
        "fixture-map-r2",
        "synthetic-sense",
        first.map.target(),
        first.map.read(),
        Encoding::I32,
        ByteOrder::Big,
        WordOrder::LowFirst,
        Scale::IDENTITY,
        Unit::parse("degC").unwrap(),
    )
    .unwrap();
    assert!(matches!(first.decode(&changed), Err(Error::MapChanged)));
    let receipt = first.receipt_time;
    assert!(client.is_connected());
    assert_eq!(
        first.receipt_time, receipt,
        "health never refreshes an observation"
    );
    pair.finish("FC03-signed-multi-and-raw", &mut client).await;
}

#[tokio::test(flavor = "current_thread")]
async fn modbus_fc04_zero_and_max_register_quantity() {
    for quantity in [1, 125] {
        let mut runtime = Runtime::default();
        let request = vec![0, 1, 0, 0, 0, 6, 255, 4, 0, 16, 0, quantity as u8];
        let response = if quantity == 1 {
            vec![0, 1, 0, 0, 0, 5, 255, 4, 2, 0, 0]
        } else {
            let mut bytes = vec![0, 1, 0, 0, 0, 253, 255, 4, 250];
            bytes.extend([0; 250]);
            bytes
        };
        let (pair, mut client) = Pair::new(
            &mut runtime,
            |t| {
                map(
                    t,
                    Function::InputRegisters,
                    quantity,
                    if quantity == 1 {
                        Encoding::U16
                    } else {
                        Encoding::Unsupported("register-vector".into())
                    },
                )
            },
            255,
            vec![Step {
                request,
                response: Some(response),
            }],
            TIMEOUT,
        )
        .await;
        let sample = client.read_input_registers().await.unwrap();
        assert_eq!(sample.payload, Payload::Words(vec![0; usize::from(quantity)]));
        if quantity == 1 {
            assert_eq!(sample.decode(&sample.map).unwrap().value, Value::Integer(0));
        }
        pair.finish(&format!("FC04-{quantity}-registers"), &mut client)
            .await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn modbus_wrong_unit_function_lengths_and_malformed_pdu_are_not_values() {
    // Independent complete MBAP frames with semantically invalid response PDUs.
    for (case, reply) in [
        ("unit-mismatch", vec![0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 7]),
        ("function-mismatch", vec![0, 1, 0, 0, 0, 5, 255, 4, 2, 0, 7]),
        ("short-quantity", vec![0, 1, 0, 0, 0, 3, 255, 3, 0]),
        ("long-quantity", vec![0, 1, 0, 0, 0, 7, 255, 3, 4, 0, 7, 0, 8]),
        ("malformed-byte-count", vec![0, 1, 0, 0, 0, 5, 255, 3, 4, 0, 7]),
    ] {
        let mut runtime = Runtime::default();
        let (pair, mut client) = Pair::new(
            &mut runtime,
            |t| map(t, Function::HoldingRegisters, 1, Encoding::U16),
            255,
            vec![Step {
                request: vec![0, 1, 0, 0, 0, 6, 255, 3, 0, 16, 0, 1],
                response: Some(reply),
            }],
            TIMEOUT,
        )
        .await;
        let error = client.read_holding_registers().await.unwrap_err();
        assert_eq!(
            error.transport(),
            TransportResult::InvalidReply,
            "{case}: {error:?}"
        );
        assert!(client.coverage().unobserved_interval);
        assert_eq!(client.coverage().changes, 1);
        assert!(!client.is_connected());
        pair.finish(case, &mut client).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn modbus_bad_bit_padding_is_refused() {
    let mut runtime = Runtime::default();
    let (pair, mut client) = Pair::new(
        &mut runtime,
        |t| map(t, Function::Coils, 1, Encoding::Bool),
        255,
        vec![step(
            &[0, 1, 0, 0, 0, 6, 255, 1, 0, 16, 0, 1],
            &[0, 1, 0, 0, 0, 4, 255, 1, 1, 128],
        )],
        TIMEOUT,
    )
    .await;
    assert_eq!(
        client.read_coils().await.unwrap_err().transport(),
        TransportResult::InvalidReply
    );
    pair.finish("FC01-padding", &mut client).await;
}

#[tokio::test(flavor = "current_thread")]
async fn modbus_timeout_wrong_transaction_and_busy_exhaust_one_attempt() {
    for (case, response) in [
        ("timeout-no-reply", None),
        ("wrong-transaction", Some(vec![0, 2, 0, 0, 0, 5, 255, 3, 2, 0, 7])),
        ("busy-zero-retries", Some(vec![0, 1, 0, 0, 0, 3, 255, 131, 6])),
    ] {
        let mut runtime = Runtime::default();
        let (pair, mut client) = Pair::new(
            &mut runtime,
            |t| map(t, Function::HoldingRegisters, 1, Encoding::U16),
            255,
            vec![Step {
                request: vec![0, 1, 0, 0, 0, 6, 255, 3, 0, 16, 0, 1],
                response,
            }],
            Duration::from_millis(200),
        )
        .await;
        let error = client.read_holding_registers().await.unwrap_err();
        match &error {
            Error::Client(rusty_modbus_client::ClientError::RetriesExhausted { attempts, last_error }) => {
                assert_eq!(*attempts, 1);
                if case == "busy-zero-retries" {
                    assert!(matches!(
                        last_error.as_ref(),
                        rusty_modbus_client::ClientError::Exception(_)
                    ));
                } else {
                    assert!(matches!(
                        last_error.as_ref(),
                        rusty_modbus_client::ClientError::Timeout
                    ));
                }
            }
            _ => panic!("unexpected {case} result: {error:?}"),
        }
        assert!(client.coverage().unobserved_interval);
        assert!(!client.is_connected());
        // No late reply can become a fresh second sample in this retired client.
        assert!(client.read_holding_registers().await.is_err());
        assert_eq!(
            runtime.stop(Duration::ZERO).unwrap(),
            Drain::Unresolved { jobs: 1 }
        );
        pair.finish(case, &mut client).await;
        drop(client);
        assert_eq!(runtime.stop(Duration::ZERO).unwrap(), Drain::Stopped);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn modbus_caller_cancellation_then_abort_still_requires_join() {
    let mut runtime = Runtime::default();
    let (pair, mut client) = Pair::new(
        &mut runtime,
        |t| map(t, Function::InputRegisters, 1, Encoding::U16),
        255,
        vec![Step {
            request: vec![0, 1, 0, 0, 0, 6, 255, 4, 0, 16, 0, 1],
            response: None,
        }],
        TIMEOUT,
    )
    .await;
    {
        let call = client.read_input_registers();
        tokio::pin!(call);
        tokio::select! {
            result = &mut call => panic!("read completed before cancellation: {result:?}"),
            _ = async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while !pair.log.packets().iter().any(|p| !p.sent) { tokio::task::yield_now().await; }
                }).await.unwrap();
            } => {}
        }
    }
    assert_eq!(client.coverage().changes, 1);
    assert!(!client.is_connected());
    client.abort();
    assert!(matches!(client.read_input_registers().await, Err(Error::Closed)));
    assert_eq!(
        runtime.stop(Duration::ZERO).unwrap(),
        Drain::Unresolved { jobs: 1 }
    );
    pair.finish("caller-cancel-abort-join", &mut client).await;
    drop(client);
    assert_eq!(runtime.stop(Duration::ZERO).unwrap(), Drain::Stopped);
}

#[test]
fn modbus_word_mapping_order_scale_unknowns_and_revision_are_explicit() {
    let target = Target::loopback("127.0.0.1:55001".parse().unwrap(), 255).unwrap();
    for (encoding, bytes, word_order, payload, expected) in [
        (
            Encoding::I16,
            ByteOrder::Big,
            WordOrder::HighFirst,
            vec![65534],
            "-2",
        ),
        (
            Encoding::U16,
            ByteOrder::Little,
            WordOrder::HighFirst,
            vec![0x3412],
            "4660",
        ),
        (
            Encoding::U32,
            ByteOrder::Big,
            WordOrder::HighFirst,
            vec![1, 2],
            "65538",
        ),
        (
            Encoding::U32,
            ByteOrder::Big,
            WordOrder::LowFirst,
            vec![2, 1],
            "65538",
        ),
        (
            Encoding::I32,
            ByteOrder::Little,
            WordOrder::LowFirst,
            vec![0xfeff, 0xffff],
            "-2",
        ),
    ] {
        let read = Read::new(Function::HoldingRegisters, 0, payload.len() as u16).unwrap();
        let map = Map::new(
            "r1",
            "synthetic-sense",
            target,
            read,
            encoding,
            bytes,
            word_order,
            Scale::IDENTITY,
            Unit::parse("Pa").unwrap(),
        )
        .unwrap();
        let out = map.decode(Some(&Payload::Words(payload)), TransportResult::ValueReturned);
        assert_eq!(out.value, Value::Integer(expected.parse().unwrap()));
        assert_eq!(out.map, map);
        assert_eq!(out.suitability, Suitability::SyntheticValueOnly);
    }
    let read = Read::new(Function::InputRegisters, 0, 1).unwrap();
    let scaled = Map::new(
        "r3",
        "synthetic-sense",
        target,
        read,
        Encoding::I16,
        ByteOrder::Big,
        WordOrder::HighFirst,
        Scale {
            numerator: 5,
            offset: 1,
            places: 2,
        },
        Unit::parse("degC").unwrap(),
    )
    .unwrap();
    assert_eq!(
        scaled
            .decode(Some(&Payload::Words(vec![65534])), TransportResult::ValueReturned)
            .value,
        Value::Decimal(domain::values::Decimal::parse("-0.09").unwrap())
    );
    assert!(matches!(
        Map::new(
            "r1",
            "synthetic-sense",
            target,
            read,
            Encoding::I32,
            ByteOrder::Big,
            WordOrder::HighFirst,
            Scale::IDENTITY,
            Unit::parse("Pa").unwrap()
        ),
        Err(Error::Quantity)
    ));
    let unknown_unit = Map::new(
        "r1",
        "synthetic-sense",
        target,
        read,
        Encoding::U16,
        ByteOrder::Big,
        WordOrder::HighFirst,
        Scale::IDENTITY,
        Unit::parse("vendor-furlongs").unwrap(),
    )
    .unwrap();
    let out = unknown_unit.decode(Some(&Payload::Words(vec![0])), TransportResult::ValueReturned);
    assert_eq!(out.unit.as_str(), "vendor-furlongs");
    assert_eq!(out.value, Value::Integer(0));
    assert_eq!(out.suitability, Suitability::Refused(Refusal::UnknownUnit));
    let out = scaled.decode(Some(&Payload::Words(vec![])), TransportResult::ValueReturned);
    assert_eq!(out.quality, ValueQuality::Invalid);
    let out = scaled.decode(None, TransportResult::Timeout);
    assert_eq!(out.value, Value::Missing);
    assert_eq!(out.suitability, Suitability::Refused(Refusal::Transport));
}

#[tokio::test(flavor = "current_thread")]
async fn modbus_reconnect_keeps_loss_and_old_receipts_historical() {
    let mut runtime = Runtime::default();
    let script = || {
        vec![step(
            &[0, 1, 0, 0, 0, 6, 255, 4, 0, 16, 0, 1],
            &[0, 1, 0, 0, 0, 5, 255, 4, 2, 0, 7],
        )]
    };
    let (pair, mut first) = Pair::new(
        &mut runtime,
        |t| map(t, Function::InputRegisters, 1, Encoding::U16),
        255,
        script(),
        TIMEOUT,
    )
    .await;
    let old = first.read_input_registers().await.unwrap();
    pair.finish("reconnect-before", &mut first).await;
    assert_eq!(runtime.status().usage.retained, [0, 0, 0]);
    let before = first.coverage();
    let (pair, mut second) = Pair::reconnect(&mut runtime, &first, script()).await;
    assert!(second.is_connected());
    assert!(second.coverage().unobserved_interval);
    assert_eq!(second.coverage().changes, before.changes + 1);
    let new = second.read_input_registers().await.unwrap();
    assert_eq!(old.payload, new.payload);
    assert_ne!(old.source, new.source);
    assert_ne!(old.incarnation, new.incarnation);
    assert!(new.receipt_monotonic >= old.receipt_monotonic);
    assert!(
        second.coverage().unobserved_interval,
        "a poll cannot fill lost history"
    );
    assert!(!second.coverage().revalidation_due);
    pair.finish("reconnect-after-same-peer", &mut second).await;
}

#[test]
fn modbus_loss_reads_pr03b_without_allocating_positions_or_repairing_gaps() {
    use observation::{identity::ProducerId, normalize::Codec, window::*};
    use observation_support::{bytes, clock, incarnation, unit, Harness};
    // Stores and records are prepared OUTSIDE the receive path, in isolated temp storage.
    let h = Harness::new();
    let access = Access {
        gate: &h.gate,
        credential: Some(&h.credentials.reviewer),
    };
    let w = Window::open_synthetic(
        h.registry.store().try_clone().unwrap(),
        access,
        fixture::scope(),
        ProducerId::parse("sensor-sat-producer").unwrap(),
        incarnation("modbus-custody"),
        None,
    )
    .unwrap();
    let raw = bytes(&[0x21, 7], 1000);
    let row = w
        .identify(access, h.pending(&raw, &h.context, Codec::Scalar, unit(), 1000))
        .unwrap();
    let ticket = w
        .prepare_capture(access, &row, Retention::OptionalHistory, &clock(1000))
        .unwrap();
    assert!(matches!(
        w.submit_capture(access, &ticket, &clock(1000)).unwrap(),
        storage::sqlite::MutationOutcome::Committed { .. }
    ));
    let checkpoint = w.checkpoint(access).unwrap();
    let before = w.replay(access, 0, 64).unwrap();
    let coverage = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut runtime = Runtime::default();
            let (pair, mut client) = Pair::new(
                &mut runtime,
                |t| map(t, Function::InputRegisters, 1, Encoding::U16),
                255,
                vec![Step {
                    request: vec![0, 1, 0, 0, 0, 6, 255, 4, 0, 16, 0, 1],
                    response: None,
                }],
                Duration::from_millis(200),
            )
            .await;
            assert_eq!(
                client.read_input_registers().await.unwrap_err().transport(),
                TransportResult::Timeout
            );
            let coverage = client.coverage();
            pair.finish("coverage-loss-PR03B", &mut client).await;
            coverage
        });
    let retained = coverage.read_retained(|| w.replay(access, 0, 64)).unwrap();
    assert_eq!(retained.coverage, coverage);
    assert_eq!(retained.evidence, before);
    assert!(retained.coverage.unobserved_interval);
    assert!(retained.evidence.gaps.is_empty());
    assert_eq!(w.checkpoint(access).unwrap(), checkpoint);
    assert_eq!(
        retained.evidence.records[0].dependent_value().unwrap_err().code(),
        "replayed-evidence-not-fresh"
    );
    // Deliberate isolated-store fault, NOT what a transport timeout does.
    h.registry
        .store()
        .exec_script("DELETE FROM observations WHERE seq=0;")
        .unwrap();
    assert_eq!(
        coverage
            .read_retained(|| w.replay(access, 0, 1))
            .unwrap_err()
            .code(),
        "unaccounted-history-gap"
    );
    assert_eq!(w.checkpoint(access).unwrap(), checkpoint);
}
