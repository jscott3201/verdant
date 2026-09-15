//! The only owner of an upstream client. No client/transport getter, Deref,
//! arbitrary service, callback or device-instance convenience API is exposed.
use super::{
    fake::{Delivery, FakePort, Receipt},
    model::*,
    Error, Result,
};
use crate::runtime::{task::Cancellation, RawOutcome};
use bacnet_client::client::{BACnetClient, ClientConfig};
use bacnet_services::{common::PropertyReference, rpm::ReadAccessSpecification};
use bacnet_transport::port::TransportPort;
use bacnet_types::{enums::PropertyIdentifier, error::Error as WireError};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

// Private static-dispatch seam: FakePort is the sole non-test implementation.
// No public transport injection, client getter or mutable retry configuration.
pub(super) trait ReadPort: TransportPort {
    fn delivery(&self) -> Arc<Mutex<Delivery>>;
}
impl ReadPort for FakePort {
    fn delivery(&self) -> Arc<Mutex<Delivery>> {
        self.delivery.clone()
    }
}
struct ReadClient<P: ReadPort>(BACnetClient<P>);
impl<P: ReadPort + 'static> ReadClient<P> {
    async fn start(port: P) -> Result<Self> {
        let config = ClientConfig {
            apdu_timeout_ms: APDU_TIMEOUT_MS,
            apdu_retries: APDU_RETRIES,
            max_apdu_length: 480,
            segmented_response_accepted: false,
            ..ClientConfig::default()
        };
        // Never invokes the upstream IP-specific builder. Live ports are cfg(test)
        // only; ordinary builds still consume only the private socket-free port.
        BACnetClient::start(config, port).await.map(Self).map_err(|_| Error::ClientStart)
    }
    async fn read(&self, plan: &BindingPlan) -> RawOutcome {
        let results = match plan.request.operation() {
            Operation::Single(property) => {
                let response = self
                    .0
                    .read_property(
                        plan.target.mac(),
                        property.object,
                        PropertyIdentifier::from_raw(property.identifier),
                        property.array_index,
                    )
                    .await;
                let outcome = match response {
                    Ok(ack)
                        if ack.object_identifier == property.object
                            && ack.property_identifier.to_raw() == property.identifier
                            && ack.property_array_index == property.array_index =>
                    {
                        value(ack.property_value)
                    }
                    Ok(_) => PropertyOutcome::InvalidReply,
                    Err(error) => wire_error(error),
                };
                vec![PropertyResult { property: *property, outcome }]
            }
            Operation::Multiple(properties) => {
                let specs = properties
                    .iter()
                    .map(|property| ReadAccessSpecification {
                        object_identifier: property.object,
                        list_of_property_references: vec![PropertyReference {
                            property_identifier: PropertyIdentifier::from_raw(property.identifier),
                            property_array_index: property.array_index,
                        }],
                    })
                    .collect();
                match self.0.read_property_multiple(plan.target.mac(), specs).await {
                    Err(error) => repeated(properties, wire_error(error)),
                    Ok(ack) => {
                        let count: usize =
                            ack.list_of_read_access_results.iter().map(|row| row.list_of_results.len()).sum();
                        if count > MAX_PROPERTIES {
                            repeated(properties, PropertyOutcome::Oversized)
                        } else {
                            properties
                                .iter()
                                .map(|property| {
                                    let mut matches = ack
                                        .list_of_read_access_results
                                        .iter()
                                        .filter(|row| row.object_identifier == property.object)
                                        .flat_map(|row| &row.list_of_results)
                                        .filter(|item| {
                                            item.property_identifier.to_raw() == property.identifier
                                                && item.property_array_index == property.array_index
                                        });
                                    let outcome = match (matches.next(), matches.next()) {
                                        (Some(item), None) => match (&item.property_value, item.error) {
                                            (Some(bytes), None) => value(bytes.clone()),
                                            (None, Some((class, code))) => PropertyOutcome::RemoteError {
                                                class: class.to_raw() as u32,
                                                code: code.to_raw() as u32,
                                            },
                                            (None, None) | (Some(_), Some(_)) => {
                                                PropertyOutcome::InvalidReply
                                            }
                                        },
                                        _ => PropertyOutcome::InvalidReply,
                                    };
                                    PropertyResult { property: *property, outcome }
                                })
                                .collect()
                        }
                    }
                }
            }
            Operation::Discover { instance } => {
                // Range is the one admitted instance. No global/local broadcast.
                return match self.0.who_is_directed(plan.target.mac(), Some(*instance), Some(*instance)).await
                {
                    Ok(()) => RawOutcome::Quarantined(Vec::new()),
                    Err(_) => RawOutcome::DiscoveryRefused,
                };
            }
        };
        RawOutcome::Bacnet(ReadBatch { target: plan.target.clone(), properties: results })
    }
}
fn value(bytes: Vec<u8>) -> PropertyOutcome {
    if bytes.len() > MAX_VALUE_BYTES {
        PropertyOutcome::Oversized
    } else {
        PropertyOutcome::Value(bytes)
    }
}
fn repeated(properties: &[Property], outcome: PropertyOutcome) -> Vec<PropertyResult> {
    properties
        .iter()
        .map(|property| PropertyResult { property: *property, outcome: outcome.clone() })
        .collect()
}
fn wire_error(error: WireError) -> PropertyOutcome {
    match error {
        WireError::Protocol { class, code } => PropertyOutcome::RemoteError { class, code },
        WireError::Reject { reason } => PropertyOutcome::Reject(reason),
        WireError::Abort { reason } => PropertyOutcome::Abort(reason),
        WireError::Timeout(_) => PropertyOutcome::Timeout,
        WireError::Transport(_) => PropertyOutcome::TransportFailure,
        WireError::Encoding(_)
        | WireError::Decoding { .. }
        | WireError::Segmentation(_)
        | WireError::BufferTooShort { .. }
        | WireError::InvalidTag(_)
        | WireError::OutOfRange(_)
        | WireError::RoutedPathTooLong { .. }
        | WireError::RoutedPathCapacityExceeded { .. } => PropertyOutcome::InvalidReply,
    }
}

pub(super) async fn execute<P: ReadPort + 'static>(
    port: P,
    plan: &BindingPlan,
    cancel: &Cancellation,
    deadline: Instant,
) -> crate::runtime::Result<(RawOutcome, Receipt)> {
    cancel.check(deadline)?;
    let delivery = port.delivery();
    let mut client = ReadClient::start(port).await?;
    // The absolute PR01A lifetime includes queue/content verification. Canceling
    // the read future is followed by the real client's stop/dispatch joins.
    // Stop is NOT wrapped in a timeout that could detach its owned work.
    let result = {
        let read = client.read(plan);
        tokio::pin!(read);
        loop {
            tokio::select! {
                result = &mut read => break Ok(result),
                _ = tokio::time::sleep(Duration::from_millis(2)) => {
                    if let Err(error) = cancel.check(deadline) { break Err(error); }
                }
            }
        }
    };
    // This is the earliest response-correlated context exposed by the public
    // client. It is NOT socket ingress, a sensor time, or a simultaneous sample.
    let receipt = Receipt { wall: SystemTime::now(), monotonic: Instant::now() };
    client.0.stop().await.map_err(|_| Error::ClientStop)?;
    cancel.check(deadline)?;
    let mut outcome = result?;
    let mut delivery = delivery.lock().map_err(|_| Error::Poisoned)?;
    if let Some(error) = delivery.error.take() {
        if error == Error::Oversized && plan.request.service() != Service::DirectedWhoIs {
            outcome = RawOutcome::Bacnet(ReadBatch {
                target: plan.target.clone(),
                properties: repeated(&plan.request.properties(), PropertyOutcome::Oversized),
            });
        } else {
            return Err(error.into());
        }
    }
    if let Operation::Discover { instance } = plan.request.operation() {
        if delivery.advertisements.iter().any(|advertisement| advertisement.instance != *instance) {
            return Err(Error::InvalidReply.into());
        }
        if matches!(outcome, RawOutcome::Quarantined(_)) {
            outcome = RawOutcome::Quarantined(std::mem::take(&mut delivery.advertisements));
        }
    }
    Ok((outcome, receipt))
}
