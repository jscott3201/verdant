//! Synthetic live loopback acceptance. Peer bytes below are independent literal
//! expectations, not the client's encoders. Shared harness knows no COV service.
use super::{cov::*, test_loopback::*, *};
use crate::runtime::{admission::WorkClass, Drain, Runtime};
use bacnet_client::client::ManagedCOVSubscriptionOptions;
use bacnet_services::cov::{SubscribeCOVPropertyRequest, SubscribeCOVRequest};
use std::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};

#[derive(Default)]
struct PeerState {
    subscriptions: AtomicUsize,
    reads: AtomicUsize,
    acks: AtomicUsize,
    fail_renewal: AtomicBool,
    fail_unsubscribe: AtomicBool,
    fail_read: AtomicBool,
}
fn process_id(id: u32) -> Vec<u8> {
    // Independent context unsigned [0], canonical minimum width.
    let bytes = id.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
    let mut out = vec![0x08 | (4 - first) as u8];
    out.extend_from_slice(&bytes[first..]);
    out
}
fn notification(id: u32, invoke: u8, value: u8) -> Vec<u8> {
    // NPDU direct, ConfirmedCOVNotification(1), AI:1 / device:123;
    // timeRemaining=2 seconds, presentValue=unsigned scalar. All fixture values.
    let mut p = vec![1, 4, 0, 3, invoke, 1];
    p.extend(process_id(id));
    p.extend([0x1c, 2, 0, 0, 123, 0x2c, 0, 0, 0, 1, 0x39, 2, 0x4e, 0x09, 85, 0x2e, 0x21, value, 0x2f, 0x4f]);
    p
}
fn respond(p: &[u8], state: &PeerState, property: bool) -> Vec<Vec<u8>> {
    if p.starts_with(&[1, 0, 0x20]) {
        assert_eq!(p.len(), 5);
        assert_eq!(p[4], 1);
        state.acks.fetch_add(1, Ordering::SeqCst);
        return vec![];
    }
    assert!(p.starts_with(&[1, 4, 0, 3]), "unexpected APDU {p:?}");
    let invoke = p[4];
    let service = p[5];
    if service == 12 {
        assert_eq!(&p[6..], &[0x0c, 0, 0, 0, 1, 0x19, 85]);
        state.reads.fetch_add(1, Ordering::SeqCst);
        if state.fail_read.load(Ordering::SeqCst) {
            return vec![vec![1, 0, 0x60, invoke, 9]];
        }
        return vec![vec![1, 0, 0x30, invoke, 12, 0x0c, 0, 0, 0, 1, 0x19, 85, 0x3e, 0x21, 7, 0x3f]];
    }
    assert_eq!(service, if property { 28 } else { 5 }, "forbidden service {service}");
    let (id, cancel) = if property {
        let r = SubscribeCOVPropertyRequest::decode(&p[6..]).unwrap();
        assert_eq!(r.monitored_property_identifier.to_raw(), 85);
        assert_eq!(r.monitored_property_array_index, None);
        (r.subscriber_process_identifier, r.is_cancellation())
    } else {
        let r = SubscribeCOVRequest::decode(&p[6..]).unwrap();
        (r.subscriber_process_identifier, r.is_cancellation())
    };
    let mut expected = process_id(id);
    expected.extend([0x1c, 0, 0, 0, 1]);
    if !cancel {
        expected.extend([0x29, 1, 0x39, 2]);
    } // fixture lifetime 2 seconds
    if property {
        expected.extend([0x4e, 0x09, 85, 0x4f]);
        if !cancel {
            expected.extend([0x5c, 0x3f, 0, 0, 0]);
        } // fixture deadband 0.5
    }
    assert_eq!(&p[6..], expected);
    let failure = if cancel {
        state.fail_unsubscribe.load(Ordering::SeqCst)
    } else {
        let n = state.subscriptions.fetch_add(1, Ordering::SeqCst);
        n > 0 && state.fail_renewal.load(Ordering::SeqCst)
    };
    vec![if failure { vec![1, 0, 0x60, invoke, 9] } else { vec![1, 0, 0x20, invoke, service] }]
}
fn options(property: bool) -> FixtureOptions {
    let defaults = ManagedCOVSubscriptionOptions::default();
    assert_eq!(defaults.renewal_margin, Duration::from_secs(30));
    assert_eq!(defaults.event_channel_capacity, 16);
    // Accelerated test fixture: 2 s lifetime, 1 s margin, 4 notifications.
    // Inherited client APDU settings remain 6000 ms / zero retries / 480 bytes.
    FixtureOptions::new(
        2,
        defaults.with_renewal_margin(Duration::from_secs(1)).with_event_channel_capacity(4),
        if property { Kind::Property { increment: Some(0.5) } } else { Kind::Object },
    )
    .unwrap()
}
struct Case {
    owner: Subscription<LoopbackPort>,
    runtime: Runtime,
    pair: Pair,
    state: Arc<PeerState>,
}
impl Case {
    async fn new(property: bool) -> Self {
        let state = Arc::new(PeerState::default());
        let peer_state = state.clone();
        let (pair, port) = Pair::new(move |p| respond(p, &peer_state, property)).await;
        let mut runtime = Runtime::default();
        let target =
            DirectTarget::parse("synthetic-loopback", &format!("bacnet-ip://{}", pair.peer)).unwrap();
        let plan = BindingPlan::new(
            "sat-binding",
            "sensor-sat-1",
            &format!("bacnet-ip://{}", pair.peer),
            "present-value",
            target,
            Request::read_property(Property::new(0, 1, 85, None).unwrap()),
        )
        .unwrap();
        let permit = runtime.fixture_cov(plan).unwrap();
        let owner = Subscription::open(permit, port, options(property)).await.unwrap();
        Self { owner, runtime, pair, state }
    }
    async fn start(&mut self) {
        self.owner.maintain(Instant::now()).await.unwrap();
        assert!(self.owner.coverage().subscribed);
        assert_eq!(self.owner.current().unwrap().value, [0x21, 7]);
        assert_eq!(self.owner.current().unwrap().origin, Receipt::PollReturn);
    }
    async fn notified(&self, generation: SubscriptionGeneration, count: usize) {
        let before = self.state.acks.load(Ordering::SeqCst);
        for n in 0..count {
            self.pair.inject(notification(generation.wire(), 100 + n as u8, 9)).await;
        }
        // Fixture wall margin only: wait for peer-observed ACKs, never infer delivery from sleep.
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.state.acks.load(Ordering::SeqCst) < before + count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    async fn finish(mut self, name: &str, expected: RemoteOutcome) {
        assert_eq!(self.owner.unsubscribe().await, expected);
        self.owner.stop().await.unwrap();
        drop(self.owner);
        assert_eq!(self.runtime.stop(Duration::ZERO).unwrap(), Drain::Stopped);
        assert_eq!(self.runtime.status().usage.retained, [0; 3]);
        assert_eq!(self.runtime.status().usage.running, [0; 3]);
        self.pair.finish(name).await;
    }
}
#[tokio::test(flavor = "current_thread")]
async fn cov_startup_stable_silence_equal_payloads_are_events() {
    let mut c = Case::new(false).await;
    c.start().await;
    let original = c.owner.current().cloned();
    let packets = c.pair.log.packets().len();
    for _ in 0..8 {
        c.owner.maintain(Instant::now()).await.unwrap();
    }
    assert_eq!(c.owner.current().cloned(), original);
    assert_eq!(c.pair.log.packets().len(), packets, "stable silence does not trigger reads");
    c.notified(c.owner.generation(), 2).await;
    let values = c.owner.drain().unwrap();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0].value, values[1].value);
    assert!(values.iter().all(|v| v.origin == Receipt::NotificationDequeue));
    c.finish("startup-silence-equal", RemoteOutcome::Confirmed).await;
}
#[tokio::test(flavor = "current_thread")]
async fn cov_managed_renewal_never_retimestamps() {
    let mut c = Case::new(false).await;
    c.start().await;
    let sample = c.owner.current().cloned();
    let generation = c.owner.generation();
    tokio::time::sleep_until(c.owner.renewal_at().into()).await;
    c.owner.maintain(Instant::now()).await.unwrap();
    assert_eq!(c.state.subscriptions.load(Ordering::SeqCst), 2);
    assert_eq!(c.state.reads.load(Ordering::SeqCst), 1);
    assert_eq!(c.owner.current().cloned(), sample);
    assert_eq!(c.owner.generation(), generation);
    c.finish("renewal-no-retimestamp", RemoteOutcome::Confirmed).await;
}
#[tokio::test(flavor = "current_thread")]
async fn cov_property_subscribe_renew_unsubscribe() {
    let mut c = Case::new(true).await;
    c.start().await;
    let sample = c.owner.current().cloned();
    tokio::time::sleep_until(c.owner.renewal_at().into()).await;
    c.owner.maintain(Instant::now()).await.unwrap();
    assert_eq!(c.state.subscriptions.load(Ordering::SeqCst), 2);
    assert_eq!(c.owner.current().cloned(), sample);
    c.finish("property-variant", RemoteOutcome::Confirmed).await;
}
#[tokio::test(flavor = "current_thread")]
async fn cov_renewal_failure_declares_loss_and_polls_current_only() {
    let mut c = Case::new(false).await;
    c.start().await;
    c.state.fail_renewal.store(true, Ordering::SeqCst);
    tokio::time::sleep_until(c.owner.renewal_at().into()).await;
    assert_eq!(c.owner.maintain(Instant::now()).await.unwrap_err(), Error::InvalidReply);
    let status = c.owner.coverage();
    assert_eq!(status.last, Loss::RenewalFailed);
    assert!(!status.subscribed && status.unobserved_interval && !status.revalidation_due);
    assert_eq!(c.state.reads.load(Ordering::SeqCst), 2);
    c.finish("renewal-failure", RemoteOutcome::Confirmed).await;
}
#[tokio::test(flavor = "current_thread")]
async fn cov_expiry_and_failed_revalidation_do_not_burst_or_refresh() {
    let mut c = Case::new(false).await;
    c.start().await;
    let sample = c.owner.current().cloned();
    c.state.fail_read.store(true, Ordering::SeqCst);
    // Fixture scheduler stall: beyond the 2 second subscription lifetime.
    tokio::time::sleep_until((c.owner.renewal_at() + Duration::from_secs(1)).into()).await;
    assert_eq!(c.owner.coverage().last, Loss::Expired);
    assert!(!c.owner.coverage().subscribed);
    assert_eq!(c.owner.maintain(Instant::now()).await.unwrap_err(), Error::InvalidReply);
    assert_eq!(c.owner.current().cloned(), sample);
    for _ in 0..8 {
        c.owner.maintain(Instant::now()).await.unwrap();
    }
    assert_eq!(c.state.reads.load(Ordering::SeqCst), 2);
    assert_eq!(c.state.subscriptions.load(Ordering::SeqCst), 2);
    assert!(c.owner.coverage().revalidation_due && c.owner.coverage().unobserved_interval);
    c.finish("expiry-bounded-failed-poll", RemoteOutcome::Confirmed).await;
}
#[tokio::test(flavor = "current_thread")]
async fn cov_overflow_lag_is_coverage_not_durable_positions() {
    let mut c = Case::new(false).await;
    c.start().await;
    c.notified(c.owner.generation(), 12).await;
    let samples = c.owner.drain().unwrap();
    assert_eq!(samples.len(), 4);
    assert_eq!(c.owner.coverage().last, Loss::Lagged(8));
    assert!(c.owner.coverage().revalidation_due);
    c.owner.revalidate().await.unwrap();
    assert!(c.owner.coverage().unobserved_interval);
    assert!(!c.owner.coverage().revalidation_due);
    assert_eq!(c.owner.current().unwrap().origin, Receipt::PollReturn);
    assert_eq!(c.state.reads.load(Ordering::SeqCst), 2);
    c.owner.revalidate().await.unwrap();
    assert_eq!(c.state.reads.load(Ordering::SeqCst), 2, "no duplicate poll");
    c.finish("overflow-lag-current-only", RemoteOutcome::Confirmed).await;
}
#[tokio::test(flavor = "current_thread")]
async fn cov_reconnect_fences_old_generation() {
    let mut c = Case::new(false).await;
    c.start().await;
    let old = c.owner.generation();
    c.owner.reconnect(false).await.unwrap();
    assert_eq!(c.owner.prior_unsubscribe_outcome(), RemoteOutcome::Confirmed);
    assert_ne!(old, c.owner.generation());
    assert_eq!(c.owner.coverage().last, Loss::Reconnect);
    let current = c.owner.current().cloned();
    c.notified(old, 1).await;
    assert!(c.owner.drain().unwrap().is_empty());
    assert_eq!(c.owner.current().cloned(), current);
    c.notified(c.owner.generation(), 1).await;
    assert_eq!(c.owner.drain().unwrap().len(), 1);
    c.finish("reconnect-old-generation", RemoteOutcome::Confirmed).await;
}
#[tokio::test(flavor = "current_thread")]
async fn cov_host_resume_declares_loss_without_reconstructing_interval() {
    let mut c = Case::new(false).await;
    c.start().await;
    let old = c.owner.generation();
    c.owner.reconnect(true).await.unwrap();
    assert_eq!(c.owner.coverage().last, Loss::HostResume);
    assert!(c.owner.coverage().unobserved_interval);
    assert_ne!(c.owner.generation(), old);
    assert_eq!(c.owner.current().unwrap().origin, Receipt::PollReturn);
    c.finish("host-resume", RemoteOutcome::Confirmed).await;
}
#[tokio::test(flavor = "current_thread")]
async fn cov_unsubscribe_failure_is_not_confirmed_cleanup() {
    let mut c = Case::new(false).await;
    c.start().await;
    c.state.fail_unsubscribe.store(true, Ordering::SeqCst);
    assert_eq!(c.owner.unsubscribe().await, RemoteOutcome::Failed);
    assert_eq!(c.owner.unsubscribe_outcome(), RemoteOutcome::Failed);
    assert_eq!(c.owner.subscribe().await.unwrap_err(), Error::NotCurrent);
    c.finish("unsubscribe-failure", RemoteOutcome::Failed).await;
}
#[tokio::test(flavor = "current_thread")]
async fn cov_capacity_loss_and_stop_account_for_actual_owner() {
    let mut c = Case::new(false).await;
    c.start().await;
    // Same admission family, not a private semaphore; preserve reconciliation.
    let held = c.runtime.budget.reserve(WorkClass::CurrentSensing, false).unwrap();
    assert_eq!(c.owner.drain().unwrap_err(), Error::Budget);
    assert_eq!(c.owner.coverage().last, Loss::Capacity);
    assert_eq!(c.owner.revalidate().await.unwrap_err(), Error::Budget);
    assert_eq!(c.state.reads.load(Ordering::SeqCst), 1);
    let mandatory = c.runtime.budget.reserve(WorkClass::Reconciliation, true).unwrap();
    drop((held, mandatory));
    c.owner.revalidate().await.unwrap();
    assert!(c.owner.coverage().unobserved_interval);
    assert_eq!(c.runtime.stop(Duration::ZERO).unwrap(), Drain::Unresolved { jobs: 1 });
    assert_eq!(c.owner.drain().unwrap_err(), Error::NotCurrent);
    c.finish("capacity-and-stop", RemoteOutcome::Confirmed).await;
}
#[test]
fn cov_closed_api_and_fixture_bounds() {
    // Source guard complements per-run wire allowlists. Nothing forwards an
    // arbitrary service or exposes an upstream client/transport/route getter.
    let source = include_str!("cov.rs");
    for forbidden in [
        "_to_device(",
        ".send_broadcast(",
        ".who_is(",
        ".write_property(",
        ".device_communication_control(",
        ".reinitialize_device(",
        "Deref",
        "pub fn client(",
        "pub fn transport(",
        ".register_foreign_device(",
        ".write_bdt(",
        ".read_bdt(",
        ".delete_foreign_device(",
        concat!("Sqlite", "Store"),
        concat!("observation_", "writer"),
        concat!("block", "_on"),
        concat!("thread::", "sleep"),
    ] {
        assert!(!source.contains(forbidden), "{forbidden}");
    }
    for endpoint in [
        "bacnet-ip://0.0.0.0:1234",
        "bacnet-ip://255.255.255.255:1234",
        "bacnet-ip://224.0.0.1:1234",
        "bacnet-ip://localhost:1234",
        "bacnet-ip://127.0.0.1:0",
        "bacnet-ip://127.0.0.1:1234/route/2",
        "bacnet-ip://[::1]:1234",
    ] {
        assert!(DirectTarget::parse("fixture", endpoint).is_err());
    }
    assert!(FixtureOptions::new(0, ManagedCOVSubscriptionOptions::default(), Kind::Object).is_err());
    assert!(FixtureOptions::new(
        35,
        ManagedCOVSubscriptionOptions::default(),
        Kind::Property { increment: Some(f32::NAN) }
    )
    .is_err());
}
