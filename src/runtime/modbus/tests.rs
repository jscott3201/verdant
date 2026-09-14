//! Socket-free admission/configuration checks. Live cases live only in the
//! modbus_live integration binary, not every included runtime test binary.
use super::*;

#[test]
fn modbus_admission_denies_every_service_except_four_reads() {
    for fc in 0..=255 {
        assert_eq!(Function::parse(fc).is_ok(), matches!(fc, 1..=4));
    }
    let peer = "127.0.0.1:55001".parse().unwrap();
    assert!(matches!(
        Target::loopback(peer, 0),
        Err(Error::BroadcastReadNotAllowed)
    ));
    for unit in 1..=255 {
        assert_eq!(
            Target::loopback(peer, unit).is_ok(),
            matches!(unit, 1..=247 | 255)
        );
    }
    for peer in [
        "127.0.0.1:502",
        "127.0.0.1:802",
        "127.0.0.1:0",
        "0.0.0.0:55001",
        "192.0.2.1:55001",
        "255.255.255.255:55001",
        "[::1]:55001",
    ] {
        assert!(matches!(
            Target::loopback(peer.parse().unwrap(), 255),
            Err(Error::DeniedDestination)
        ));
    }
    for f in [
        Function::Coils,
        Function::DiscreteInputs,
        Function::HoldingRegisters,
        Function::InputRegisters,
    ] {
        let limit = if f.bits() { 2000 } else { 125 };
        assert!(matches!(Read::new(f, 0, 0), Err(Error::Quantity)));
        assert!(matches!(Read::new(f, 0, limit + 1), Err(Error::Quantity)));
        assert!(matches!(Read::new(f, u16::MAX, 2), Err(Error::Address)));
        assert!(Read::new(f, u16::MAX, 1).is_ok());
        assert_eq!(Read::new(f, 0, limit).unwrap().bytes(), 250);
    }
}
#[test]
fn modbus_configuration_and_wrapper_have_no_write_escape_hatch() {
    let cfg = config(255, TIMEOUT);
    assert_eq!(cfg.timeout, Duration::from_secs(5));
    assert_eq!(cfg.shutdown_timeout, Duration::from_secs(10));
    assert_eq!(cfg.retry.max_retries, 0);
    assert_eq!(cfg.max_in_flight, 1);
    assert_eq!(cfg.retry.retry_delay, ClientConfig::default().retry.retry_delay);
    assert_eq!(
        cfg.retry.retryable_exceptions,
        ClientConfig::default().retry.retryable_exceptions
    );
    let source = include_str!("mod.rs");
    for forbidden in [
        ".write_",
        ".send_broadcast(",
        "_to_device(",
        "from_rtu_transport(",
        "impl Deref",
        "pub client:",
        "pub fn from_transport",
        "TcpListener",
        "TcpSocket",
        "exec_script",
        "Sqlite",
        "rusqlite",
        "BEGIN TRANSACTION",
    ] {
        assert!(
            !source.contains(forbidden),
            "wrapper escape/receive path: {forbidden}"
        );
    }
    assert_eq!(admission::MODBUS_FAKE_PAYLOAD_BYTES, 12_480);
    assert_eq!(crate::runtime::admission::BACNET_FAKE_PAYLOAD_BYTES, 57_344);
}

#[test]
fn modbus_shares_family_and_releases_unused_permits_without_new_capacity() {
    use crate::domain::values::Unit;
    use crate::runtime::{admission::WorkClass, Runtime};
    use mapping::{ByteOrder, Encoding, Map, Scale, WordOrder};
    let mut runtime = Runtime::default();
    let target = Target::loopback("127.0.0.1:55001".parse().unwrap(), 255).unwrap();
    let map = Map::new(
        "r1",
        "synthetic-sense",
        target,
        Read::new(Function::InputRegisters, 0, 1).unwrap(),
        Encoding::U16,
        ByteOrder::Big,
        WordOrder::HighFirst,
        Scale::IDENTITY,
        Unit::parse("Pa").unwrap(),
    )
    .unwrap();
    let optional: Vec<_> = (0..60)
        .map(|_| {
            runtime
                .budget
                .reserve(WorkClass::OptionalDiscovery, false)
                .unwrap()
        })
        .collect();
    let permit = runtime.fixture_modbus(map.clone()).unwrap();
    assert!(runtime.fixture_modbus(map.clone()).is_err());
    let active = runtime.budget.reserve(WorkClass::CurrentSensing, true).unwrap();
    assert!(matches!(
        permit.slot.as_ref().unwrap().receive(),
        Err(Error::Budget)
    ));
    assert_eq!(
        runtime.status().usage.retained,
        [1, 0, 60],
        "failed receive released its partial reservation"
    );
    let mandatory = runtime.budget.reserve(WorkClass::Reconciliation, true).unwrap();
    drop((active, mandatory, permit));
    runtime.poll();
    assert_eq!(runtime.status().usage.retained, [0, 0, 60]);
    drop(optional);
    assert_eq!(runtime.status().usage.running, [0, 0, 0]);
}
