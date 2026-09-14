//! Finite, direct-only subscription owner. Drive `maintain` from one owner;
//! it performs at most one renewal and one revalidation, never catch-up bursts.
//! No detached renewal task: the same scheduler works for object AND property
//! subscriptions using the pinned public direct APIs. A stopped scheduler loses
//! coverage at expiry; transport liveness is not coverage or point freshness.
use super::{
    cov_admission::{Permit, Slot},
    *,
};
use bacnet_client::client::{
    BACnetClient, ClientConfig, ClientOptions, ConfirmedCOVNotificationResponse as Response,
    ManagedCOVSubscriptionOptions, ReceivedCOVNotification,
};
use bacnet_transport::port::TransportPort;
use bacnet_types::{enums::PropertyIdentifier, error::Error as WireError};
use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime},
};
use tokio::sync::broadcast::{self, error::TryRecvError};

static GENERATION: AtomicU32 = AtomicU32::new(1);
/// Process-local subscription identity, also a unique wire subscriber ID. Never
/// an observation ID, durable sequence, source generation, or restart continuity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SubscriptionGeneration(u32);
impl SubscriptionGeneration {
    fn next() -> Result<Self> {
        GENERATION
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .map(Self)
            .map_err(|_| Error::Invalid("subscription identity exhausted"))
    }
    pub fn wire(self) -> u32 {
        self.0
    }
}
#[derive(Debug, Clone, Copy)]
pub(crate) enum Kind {
    Object,
    Property { increment: Option<f32> },
}
#[derive(Debug, Clone)]
pub(crate) struct FixtureOptions {
    lifetime: u32,
    margin: Duration,
    capacity: usize,
    kind: Kind,
}
impl FixtureOptions {
    /// All numbers are synthetic assumptions, NOT facility recommendations.
    /// Start at upstream options defaults (30 seconds margin / 16 events).
    pub fn new(lifetime: u32, managed: ManagedCOVSubscriptionOptions, kind: Kind) -> Result<Self> {
        if lifetime == 0
            || u64::from(lifetime) > crate::runtime::admission::MAX_LIFETIME.as_secs()
            || managed.renewal_margin >= Duration::from_secs(lifetime.into())
            || managed.renewal_margin.is_zero()
            || !(1..=16).contains(&managed.event_channel_capacity)
        {
            return Err(Error::Invalid("finite COV fixture bounds"));
        }
        if let Kind::Property { increment: Some(n) } = kind {
            if !n.is_finite() || n < 0.0 {
                return Err(Error::Invalid("fixture deadband"));
            }
        }
        Ok(Self { lifetime, margin: managed.renewal_margin, capacity: managed.event_channel_capacity, kind })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Loss {
    Startup,
    Lagged(u64),
    Capacity,
    RenewalFailed,
    Expired,
    Reconnect,
    HostResume,
    Closed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Coverage {
    pub changes: u64,
    pub last: Loss,
    pub revalidation_due: bool,
    /// Sticky: a fresh poll/renewal never fills the unobserved interval.
    pub unobserved_interval: bool,
    pub subscribed: bool,
}
/// Retained durable evidence and subscription coverage are independent facts.
/// The integration caller supplies the existing PR03B bounded custody/replay
/// read OUTSIDE receive processing. Errors (including unaccounted-history-gap)
/// pass through unchanged; successful replay cannot clear subscription loss.
#[derive(Debug)]
pub(crate) struct Retained<T> {
    pub coverage: Coverage,
    pub evidence: T,
}
impl Coverage {
    pub fn read_retained<T, E>(
        self,
        read: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<Retained<T>, E> {
        read().map(|evidence| Retained { coverage: self, evidence })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Receipt {
    NotificationDequeue,
    PollReturn,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sample {
    pub generation: SubscriptionGeneration,
    pub value: Vec<u8>,
    pub receipt_time: SystemTime,
    pub receipt_monotonic: Instant,
    pub origin: Receipt,
    // No source timestamp or fabricated durable position.
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteOutcome {
    NotAttempted,
    Uncertain,
    Confirmed,
    Failed,
}

fn matches(received: &ReceivedCOVNotification, target: &DirectTarget, property: Property) -> bool {
    received.source_network.is_none()
        && received.source_address.is_none()
        && received.source_mac.as_ref() == target.mac()
        && received.notification.monitored_object_identifier == property.object
}
/// Pure bounded predicate. Ack means protocol receipt ONLY, not durability.
fn ack(received: &ReceivedCOVNotification, target: &DirectTarget, property: Property) -> Response {
    if matches(received, target, property)
        && received.notification.list_of_values.len() <= MAX_PROPERTIES
        && received.notification.list_of_values.iter().all(|p| p.value.len() <= MAX_VALUE_BYTES)
    {
        Response::Ack
    } else {
        Response::NoResponse
    }
}

#[must_use = "unsubscribe and stop().await, then stop the runtime; Drop is not a join"]
pub(crate) struct Subscription<T: TransportPort + 'static> {
    client: BACnetClient<T>,
    receiver: broadcast::Receiver<ReceivedCOVNotification>,
    slot: Arc<Slot>,
    target: DirectTarget,
    property: Property,
    options: FixtureOptions,
    generation: SubscriptionGeneration,
    renew_at: Instant,
    poll_at: Instant,
    expires: Instant,
    coverage: Coverage,
    current: Option<Sample>,
    unsubscribe: RemoteOutcome,
    prior_unsubscribe: RemoteOutcome,
    stopped: bool,
}
impl<T: TransportPort + 'static> Subscription<T> {
    /// Internal integration only; no generic client/transport getter or public
    /// device lookup, management, routing, broadcast or arbitrary-service method.
    pub(crate) async fn open(permit: Permit, port: T, options: FixtureOptions) -> Result<Self> {
        let generation = SubscriptionGeneration::next()?;
        permit.slot.check().map_err(|_| Error::NotCurrent)?;
        let target = permit.plan.target;
        let property = permit.property;
        let ack_target = target.clone();
        let config = ClientConfig {
            apdu_timeout_ms: APDU_TIMEOUT_MS,
            apdu_retries: APDU_RETRIES,
            max_apdu_length: 480,
            segmented_response_accepted: false,
            ..ClientConfig::default()
        };
        let client_options = ClientOptions::default()
            .with_cov_channel_capacity(options.capacity)
            .with_confirmed_cov_notification_ack_policy(move |r| ack(r, &ack_target, property));
        let client = match BACnetClient::start_with_options(config, port, client_options).await {
            Ok(client) => client,
            Err(_) => {
                permit.slot.finish();
                return Err(Error::ClientStart);
            }
        };
        let receiver = client.cov_notifications();
        let now = Instant::now();
        Ok(Self {
            client,
            receiver,
            slot: permit.slot,
            target,
            property,
            options,
            generation,
            renew_at: now,
            poll_at: now,
            expires: now,
            current: None,
            unsubscribe: RemoteOutcome::NotAttempted,
            prior_unsubscribe: RemoteOutcome::NotAttempted,
            stopped: false,
            coverage: Coverage {
                changes: 0,
                last: Loss::Startup,
                revalidation_due: true,
                unobserved_interval: false,
                subscribed: false,
            },
        })
    }
    pub fn generation(&self) -> SubscriptionGeneration {
        self.generation
    }
    pub fn coverage(&mut self) -> Coverage {
        self.expire(Instant::now());
        self.coverage
    }
    pub fn current(&self) -> Option<&Sample> {
        self.current.as_ref()
    }
    pub fn unsubscribe_outcome(&self) -> RemoteOutcome {
        self.unsubscribe
    }
    pub fn prior_unsubscribe_outcome(&self) -> RemoteOutcome {
        self.prior_unsubscribe
    }
    pub fn renewal_at(&self) -> Instant {
        self.renew_at
    }
    fn loss(&mut self, reason: Loss) {
        self.coverage.changes = self.coverage.changes.saturating_add(1);
        self.coverage.last = reason;
        self.coverage.unobserved_interval = true;
        self.coverage.revalidation_due = true;
    }
    fn expire(&mut self, now: Instant) {
        if self.coverage.subscribed && now >= self.expires {
            self.coverage.subscribed = false;
            self.loss(Loss::Expired);
        }
    }
    fn check(&self) -> Result<()> {
        if self.stopped || self.unsubscribe != RemoteOutcome::NotAttempted {
            return Err(Error::NotCurrent);
        }
        self.slot.check().map_err(|_| Error::NotCurrent)
    }
    async fn subscribe_direct(&self) -> std::result::Result<(), WireError> {
        match self.options.kind {
            Kind::Object => {
                self.client
                    .subscribe_cov(
                        self.target.mac(),
                        self.generation.wire(),
                        self.property.object,
                        true,
                        Some(self.options.lifetime),
                    )
                    .await
            }
            Kind::Property { increment } => {
                self.client
                    .subscribe_cov_property(
                        self.target.mac(),
                        self.generation.wire(),
                        self.property.object,
                        PropertyIdentifier::from_raw(self.property.identifier),
                        self.property.array_index,
                        true,
                        Some(self.options.lifetime),
                        increment,
                    )
                    .await
            }
        }
    }
    pub async fn subscribe(&mut self) -> Result<()> {
        self.check()?;
        let _active = match self.slot.receive() {
            Ok(slot) => slot,
            Err(_) => {
                self.loss(Loss::Capacity);
                return Err(Error::Budget);
            }
        };
        // Set conservative failure state BEFORE await; canceled work cannot
        // retain a successful coverage claim. Renewal never touches `current`.
        self.coverage.subscribed = false;
        let started = Instant::now();
        // Conservative request-start lifetime, not a peer-grant/receipt timestamp.
        self.renew_at = started + self.options.margin;
        match self.subscribe_direct().await {
            Ok(()) => {
                self.check()?;
                self.expires = started + Duration::from_secs(self.options.lifetime.into());
                self.renew_at = self.expires - self.options.margin;
                if Instant::now() >= self.expires {
                    self.loss(Loss::Expired);
                    return Err(Error::NotCurrent);
                }
                self.coverage.subscribed = true;
                Ok(())
            }
            Err(_) => {
                self.loss(Loss::RenewalFailed);
                Err(Error::InvalidReply)
            }
        }
    }
    /// Bounded dequeue; returns every equal-valued event separately. No blocking
    /// callback work, ingestion, persistence or value-hash deduplication here.
    pub fn drain(&mut self) -> Result<Vec<Sample>> {
        self.check()?;
        self.expire(Instant::now());
        let _receive = match self.slot.receive() {
            Ok(slot) => slot,
            Err(_) => {
                self.loss(Loss::Capacity);
                return Err(Error::Budget);
            }
        };
        let mut samples = Vec::new();
        for _ in 0..=self.options.capacity {
            match self.receiver.try_recv() {
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Closed) => {
                    self.coverage.subscribed = false;
                    self.loss(Loss::Closed);
                    break;
                }
                Err(TryRecvError::Lagged(n)) => {
                    self.loss(Loss::Lagged(n));
                }
                Ok(received) => {
                    if received.notification.subscriber_process_identifier != self.generation.wire()
                        || !matches(&received, &self.target, self.property)
                    {
                        continue;
                    }
                    if received.notification.list_of_values.len() > MAX_PROPERTIES {
                        self.loss(Loss::Capacity);
                        continue;
                    }
                    // A dequeued lifetime may shorten, never extend, our
                    // conservative deadline. It is not a value timestamp.
                    let remaining = Duration::from_secs(received.notification.time_remaining.into());
                    self.renew_at =
                        self.renew_at.min(Instant::now() + remaining.saturating_sub(self.options.margin));
                    if remaining.is_zero() {
                        self.coverage.subscribed = false;
                        self.loss(Loss::Expired);
                    }
                    let mut values = received.notification.list_of_values.iter().filter(|p| {
                        p.property_identifier.to_raw() == self.property.identifier
                            && p.property_array_index == self.property.array_index
                    });
                    let (Some(value), None) = (values.next(), values.next()) else {
                        continue;
                    };
                    if value.value.len() > MAX_VALUE_BYTES {
                        self.loss(Loss::Capacity);
                        continue;
                    }
                    let sample = Sample {
                        generation: self.generation,
                        value: value.value.clone(),
                        receipt_time: SystemTime::now(),
                        receipt_monotonic: Instant::now(),
                        origin: Receipt::NotificationDequeue,
                    };
                    self.current = Some(sample.clone());
                    samples.push(sample);
                }
            }
        }
        Ok(samples)
    }
    /// A single fresh read establishes current value only. The sticky loss fact
    /// survives it. Failed/canceled reads leave revalidation pending.
    pub async fn revalidate(&mut self) -> Result<()> {
        self.check()?;
        if !self.coverage.revalidation_due {
            return Ok(());
        }
        let _active = match self.slot.receive() {
            Ok(slot) => slot,
            Err(_) => {
                self.loss(Loss::Capacity);
                return Err(Error::Budget);
            }
        };
        // Backoff applies even if the future is canceled after handoff. One
        // fixture margin between failed attempts; no tight failure retry loop.
        if Instant::now() < self.poll_at {
            return Ok(());
        }
        self.poll_at = Instant::now() + self.options.margin;
        let ack = self
            .client
            .read_property(
                self.target.mac(),
                self.property.object,
                PropertyIdentifier::from_raw(self.property.identifier),
                self.property.array_index,
            )
            .await;
        let ack = match ack {
            Ok(ack) => ack,
            Err(_) => {
                self.poll_at = Instant::now() + self.options.margin;
                return Err(Error::InvalidReply);
            }
        };
        self.check()?;
        if ack.object_identifier != self.property.object
            || ack.property_identifier.to_raw() != self.property.identifier
            || ack.property_array_index != self.property.array_index
            || ack.property_value.len() > MAX_VALUE_BYTES
        {
            return Err(Error::InvalidReply);
        }
        self.current = Some(Sample {
            generation: self.generation,
            value: ack.property_value,
            receipt_time: SystemTime::now(),
            receipt_monotonic: Instant::now(),
            origin: Receipt::PollReturn,
        });
        self.coverage.revalidation_due = false;
        self.poll_at = Instant::now();
        Ok(())
    }
    /// Call with the scheduler's monotonic reading, at most once per turn. No
    /// request on stable silence before renewal. No replay of missed timer ticks.
    pub async fn maintain(&mut self, now: Instant) -> Result<()> {
        self.check()?;
        self.expire(now);
        let renewal = if now >= self.renew_at { self.subscribe().await } else { Ok(()) };
        // Bound failure retry cadence too; caller polling cannot burst renewals.
        if renewal.is_err() {
            self.renew_at = Instant::now() + self.options.margin;
        }
        let poll = self.revalidate().await;
        renewal.and(poll)
    }
    /// Reconnect/resume invalidate the old wire subscriber identity BEFORE any
    /// fresh subscribe. Old notifications can be acked but cannot become current.
    pub async fn reconnect(&mut self, resume: bool) -> Result<()> {
        self.prior_unsubscribe = self.unsubscribe().await;
        self.generation = SubscriptionGeneration::next()?;
        self.unsubscribe = RemoteOutcome::NotAttempted;
        self.coverage.subscribed = false;
        self.loss(if resume { Loss::HostResume } else { Loss::Reconnect });
        self.current = None;
        self.receiver = self.client.cov_notifications();
        self.renew_at = Instant::now();
        self.maintain(Instant::now()).await
    }
    /// Original target cleanup bypasses canceled admission. Mark uncertainty
    /// before await; neither cancellation nor Drop is confirmed remote cleanup.
    pub async fn unsubscribe(&mut self) -> RemoteOutcome {
        if self.stopped || self.unsubscribe != RemoteOutcome::NotAttempted {
            return self.unsubscribe;
        }
        self.coverage.subscribed = false;
        self.unsubscribe = RemoteOutcome::Uncertain;
        let result = match self.options.kind {
            Kind::Object => {
                self.client
                    .unsubscribe_cov(self.target.mac(), self.generation.wire(), self.property.object)
                    .await
            }
            Kind::Property { .. } => {
                self.client
                    .unsubscribe_cov_property(
                        self.target.mac(),
                        self.generation.wire(),
                        self.property.object,
                        PropertyIdentifier::from_raw(self.property.identifier),
                        self.property.array_index,
                    )
                    .await
            }
        };
        self.unsubscribe = if result.is_ok() { RemoteOutcome::Confirmed } else { RemoteOutcome::Failed };
        self.unsubscribe
    }
    pub async fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        self.unsubscribe().await;
        self.client.stop().await.map_err(|_| Error::ClientStop)?;
        self.stopped = true;
        self.slot.finish();
        Ok(())
    }
}
impl<T: TransportPort + 'static> Drop for Subscription<T> {
    fn drop(&mut self) {
        if !self.stopped {
            self.slot.cancel();
            eprintln!("COV owner abandoned: runtime stop unresolved, not joined");
        }
    }
}
