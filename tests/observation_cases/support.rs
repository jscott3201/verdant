use crate::{accept, access, bacnet_support, binding, domain, fixture, observation::*, runtime, storage};
use domain::{
    clock::{BootId, MonotonicMark},
    ids::{InstalledId, SourceGenerationId},
    scope::TrustedScope,
    values::Unit,
};
use identity::{Producer, ProducerId, ProducerIncarnation};
use index::SyntheticReceiver;
use normalize::{Codec, UnitProvenance};
use std::{
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use time::{ClockReading, Continuity, FreshnessPolicy};

pub fn wall(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}
pub fn mark(ms: u64) -> MonotonicMark {
    MonotonicMark::new(BootId::parse("synthetic-boot-a").unwrap(), ms * 1_000_000)
}
pub fn clock(ms: u64) -> ClockReading {
    ClockReading {
        wall: wall(ms),
        monotonic: mark(ms),
        continuity: Continuity::Confirmed,
    }
}
pub fn policy() -> FreshnessPolicy {
    FreshnessPolicy::new(Duration::from_millis(100), Duration::from_millis(2)).unwrap()
}
pub fn incarnation(text: &str) -> ProducerIncarnation {
    ProducerIncarnation::parse(text).unwrap()
}
pub fn unit() -> UnitProvenance {
    UnitProvenance::SyntheticBinding(Unit::parse("degC").unwrap())
}
pub fn key() -> InstalledId {
    InstalledId::parse("sat-binding").unwrap()
}

pub fn seed() -> runtime::RawEnvelope {
    static RAW: OnceLock<runtime::RawEnvelope> = OnceLock::new();
    RAW.get_or_init(|| {
        let mut case = bacnet_support::Case::new(bacnet_support::single(), false);
        case.reply(bacnet_support::ACK);
        let raw = case.run(runtime::admission::WorkClass::CurrentSensing).unwrap();
        let runtime::RawOutcome::Bacnet(batch) = &raw.outcome else {
            panic!("read batch");
        };
        // PR01B really returns application tags, not domain Value JSON.
        assert_eq!(
            batch.properties[0].outcome,
            runtime::bacnet::PropertyOutcome::Value(vec![0x21, 7])
        );
        assert_eq!(raw.source_time, None);
        assert_eq!(raw.receipt_origin, runtime::ReceiptOrigin::BacnetClientReturn);
        case.stop();
        raw
    })
    .clone()
}
pub fn raw(outcome: runtime::bacnet::PropertyOutcome, ms: u64) -> runtime::RawEnvelope {
    let mut raw = seed();
    raw.receipt_time = wall(ms);
    let runtime::RawOutcome::Bacnet(batch) = &mut raw.outcome else {
        panic!("batch");
    };
    batch.properties[0].outcome = outcome;
    raw
}
pub fn bytes(bytes: &[u8], ms: u64) -> runtime::RawEnvelope {
    raw(runtime::bacnet::PropertyOutcome::Value(bytes.to_vec()), ms)
}

pub struct Harness {
    pub gate: access::AccessGate,
    pub credentials: access::BootstrapCredentials,
    pub registry: binding::BindingRegistry,
    pub receiver: SyntheticReceiver,
    pub producer: Producer,
    pub config: accept::EffectiveConfig,
    pub context: BindingContext,
    pub raw: runtime::RawEnvelope,
    pub scratch: fixture::Scratch,
}
impl Harness {
    pub fn new() -> Self {
        let scratch = fixture::Scratch::new();
        let (gate, credentials) = access::AccessGate::bootstrap(
            &scratch.db(),
            storage::ConnectionSettings::local_wal_full(),
            storage::StoreBounds::tiny(),
            &access::Reason::parse("synthetic PR03A").unwrap(),
        )
        .unwrap();
        let mut registry = binding::BindingRegistry::open(
            &scratch.db(),
            storage::ConnectionSettings::local_wal_full(),
            storage::StoreBounds::tiny(),
        )
        .unwrap();
        let raw = bytes(&[0x21, 0], 1000);
        let config = config(&gate, &mut registry, fixture::scope());
        let context = BindingContext::synthetic(&config, &raw, bacnet_support::pv()).unwrap();
        let mut receiver =
            SyntheticReceiver::new(SourceGenerationId::parse("synthetic-receiver").unwrap(), 64).unwrap();
        receiver
            .select_binding(&gate, Some(&credentials.reviewer), None, context.clone())
            .unwrap();
        let producer = receiver
            .start(
                &gate,
                Some(&credentials.reviewer),
                fixture::scope(),
                ProducerId::parse("sensor-sat-producer").unwrap(),
                incarnation("process-a"),
            )
            .unwrap();
        Self {
            gate,
            credentials,
            registry,
            receiver,
            producer,
            config,
            context,
            raw,
            scratch,
        }
    }
    pub fn pending(
        &self,
        raw: &runtime::RawEnvelope,
        context: &BindingContext,
        codec: Codec,
        units: UnitProvenance,
        ms: u64,
    ) -> PendingObservation {
        PendingObservation::from_bacnet(
            raw,
            context.clone(),
            Normalization {
                units,
                codec,
                receipt_mark: mark(ms),
                ingestion: clock(ms),
            },
            policy(),
        )
        .unwrap()
    }
    pub fn emit(&mut self, bytes: &[u8], ms: u64) -> NormalizedObservation {
        let raw = bytes_as_raw(bytes, ms);
        let pending = self.pending(&raw, &self.context, Codec::Scalar, unit(), ms);
        self.receiver
            .emit(
                &self.gate,
                Some(&self.credentials.reviewer),
                &mut self.producer,
                pending,
            )
            .unwrap()
    }
}
fn bytes_as_raw(value: &[u8], ms: u64) -> runtime::RawEnvelope {
    bytes(value, ms)
}
pub fn config(
    gate: &access::AccessGate,
    registry: &mut binding::BindingRegistry,
    scope: TrustedScope,
) -> accept::EffectiveConfig {
    let binding = binding::ProposedBinding::from_import(
        binding::EndpointAddress::parse("mstp://ahu-1").unwrap(),
        binding::EndpointClass::Location,
        scope.clone(),
        InstalledId::parse("ahu-1").unwrap(),
        binding::PropertyName::parse("supply-air-temp").unwrap(),
        scope.clone(),
        InstalledId::parse("sensor-sat-1").unwrap(),
        Unit::parse("degC").unwrap(),
        None,
        binding::BindingRole::Sense,
        binding::BindingRole::Sense,
        binding::Feedback::Absent,
        binding::BindingStatus::Valid,
    );
    accept::EffectiveConfig::resolve(
        gate,
        registry,
        scope,
        vec![accept::Entry::new(key(), "synthetic SAT", binding).unwrap()],
        vec![],
    )
    .unwrap()
}
