//! M02-PR04: API-first, explicit loopback-only synthetic Modbus/TCP reads.
//! No CLI activation, listener, discovery, generic raw PDU or write escape hatch.
//! The pinned public client owns transactions and replay classification. We
//! restrict its surface and configure zero retries, not a wire-packet guarantee.
pub(crate) mod admission;
pub(crate) mod mapping;
mod model;
use crate::runtime::bacnet::cov::{Coverage, Loss};
use crate::{
    observation::normalize::TransportResult,
    runtime::{RuntimeIncarnation, SourceGeneration},
};
use admission::{Permit, Slot};
use mapping::{Map, Mapped};
pub(crate) use model::{Function, Payload, Read, Target};
use rusty_modbus_client::{ClientConfig, ClientError, ModbusClient};
use rusty_modbus_tcp::{
    transport::{TransportConnect, TransportSink, TransportStream},
    TcpConfig, TcpSink, TcpTransport,
};
use rusty_modbus_types::UnitId;
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

pub(crate) const TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
#[derive(Debug)]
pub(crate) enum Error {
    DeniedDestination,
    DeniedService,
    BroadcastReadNotAllowed,
    InvalidUnit,
    Quantity,
    Address,
    Map,
    MapChanged,
    Budget,
    Cancelled,
    Closed,
    Unresolved,
    Client(ClientError),
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::DeniedDestination => "modbus-destination-denied",
            Self::DeniedService => "modbus-service-denied",
            Self::BroadcastReadNotAllowed => "modbus-broadcast-read-not-allowed",
            Self::InvalidUnit => "modbus-invalid-unit",
            Self::Quantity => "modbus-quantity",
            Self::Address => "modbus-address",
            Self::Map => "modbus-map",
            Self::MapChanged => "modbus-map-changed",
            Self::Budget => "modbus-shared-budget",
            Self::Cancelled => "modbus-cancelled",
            Self::Closed => "modbus-closed",
            Self::Unresolved => "modbus-unresolved",
            Self::Client(_) => "modbus-client",
        }
    }
    pub fn transport(&self) -> TransportResult {
        fn upstream(error: &ClientError) -> TransportResult {
            match error {
                ClientError::Timeout => TransportResult::Timeout,
                ClientError::RetriesExhausted { last_error, .. } => upstream(last_error),
                ClientError::Exception(exc) => TransportResult::RemoteError {
                    class: 0,
                    code: u32::from(exc.exception_code.code()),
                },
                ClientError::UnexpectedResponseUnitId { .. }
                | ClientError::UnexpectedResponse { .. }
                | ClientError::UnexpectedResponseLength { .. }
                | ClientError::ShortResponse { .. }
                | ClientError::UnexpectedResponsePadding { .. }
                | ClientError::Codec(_)
                | ClientError::UnexpectedResponseEcho { .. }
                | ClientError::UnexpectedFileRecordSubResponseCount { .. }
                | ClientError::InvalidDeviceIdentificationContinuation { .. }
                | ClientError::DeviceIdentificationPaginationLimit { .. } => TransportResult::InvalidReply,
                ClientError::Transport(_)
                | ClientError::Encode(_)
                | ClientError::TransactionConflict(_)
                | ClientError::NotConnected
                | ClientError::BroadcastReadNotAllowed
                | ClientError::ShuttingDown => TransportResult::Failure,
            }
        }
        match self {
            Self::Client(e) => upstream(e),
            _ => TransportResult::Failure,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}
impl std::error::Error for Error {}
impl From<ClientError> for Error {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}
pub(crate) type Result<T> = std::result::Result<T, Error>;

fn config(unit: u8, timeout: Duration) -> ClientConfig {
    let mut config = ClientConfig {
        unit_id: UnitId(unit),
        timeout,
        max_in_flight: 1,
        shutdown_timeout: SHUTDOWN_TIMEOUT,
        ..ClientConfig::default()
    };
    config.retry.max_retries = 0; // Retryable exception set and delay untouched.
    config
}

/// Raw evidence, not a latest-value owner or durable observation ID. Receipt is
/// read-return time (not a sensor timestamp or kernel-arrival timestamp).
#[derive(Debug, Clone)]
pub(crate) struct Sample {
    pub payload: Payload,
    pub map: Map,
    pub incarnation: RuntimeIncarnation,
    pub source: SourceGeneration,
    pub sequence: u64,
    pub receipt_time: SystemTime,
    pub receipt_monotonic: Instant,
}
impl Sample {
    pub fn decode(&self, expected: &Map) -> Result<Mapped> {
        if &self.map != expected {
            return Err(Error::MapChanged);
        }
        Ok(self
            .map
            .decode(Some(&self.payload), TransportResult::ValueReturned))
    }
}

#[must_use = "shutdown joins; abort and Drop alone do not prove cleanup"]
pub(crate) struct Client<S: TransportSink + Send + 'static = TcpSink> {
    // Never returned or dereferenced to the unrestricted upstream client.
    client: Option<ModbusClient<S>>,
    slot: Arc<Slot>,
    map: Map,
    sequence: u64,
    coverage: Coverage,
    sealed: bool,
}
impl Client {
    pub async fn connect(permit: Permit) -> Result<Self> {
        Self::connect_with(permit, TIMEOUT).await
    }
    /// Explicit fresh admission after a proven shutdown. No target/map changes,
    /// automatic retries, old observation refresh or history repair on reconnect.
    pub async fn reconnect(previous: &Self, permit: Permit) -> Result<Self> {
        let coverage = previous.reconnect_coverage(&permit.map)?;
        let mut client = Self::connect(permit).await?;
        client.coverage = coverage;
        Ok(client)
    }
    async fn connect_with(permit: Permit, timeout: Duration) -> Result<Self> {
        let slot = permit.slot.as_ref().ok_or(Error::Closed)?;
        let _active = slot.receive()?;
        let tcp = TcpConfig {
            connect_timeout: timeout,
            read_timeout: Some(timeout),
            write_timeout: Some(timeout),
            ..TcpConfig::default()
        };
        let (sink, stream) = tokio::select! {
            _ = slot.cancelled() => return Err(Error::Cancelled),
            result = TcpTransport::connect(tcp, permit.map.target().address()) =>
                result.map_err(ClientError::Transport)?,
        };
        Self::from_transport(permit, sink, stream, timeout)
    }
}
impl<S: TransportSink + Send + 'static> Client<S> {
    fn reconnect_coverage(&self, map: &Map) -> Result<Coverage> {
        if self.client.is_some() || !self.slot.joined() {
            return Err(Error::Unresolved);
        }
        if &self.map != map {
            return Err(Error::MapChanged);
        }
        let mut coverage = self.coverage;
        loss(&mut coverage);
        coverage.last = Loss::Reconnect;
        Ok(coverage)
    }
    // Private: a transport injection seam is NOT part of the wrapper's surface.
    fn from_transport<R: TransportStream + Send + 'static>(
        mut permit: Permit,
        sink: S,
        stream: R,
        timeout: Duration,
    ) -> Result<Self> {
        let slot = permit.slot.as_ref().ok_or(Error::Closed)?;
        slot.check()?;
        let client = ModbusClient::from_transport(sink, stream, config(permit.map.target().unit(), timeout));
        let slot = permit.slot.take().ok_or(Error::Closed)?;
        Ok(Self {
            client: Some(client),
            slot,
            map: permit.map.clone(),
            sequence: 0,
            sealed: false,
            coverage: Coverage {
                changes: 0,
                last: Loss::Startup,
                revalidation_due: true,
                unobserved_interval: false,
                subscribed: false,
            },
        })
    }
    pub fn coverage(&self) -> Coverage {
        self.coverage
    }
    pub fn is_connected(&self) -> bool {
        // Passive only; neither this nor reconnect changes old sample timestamps.
        !self.sealed && self.client.as_ref().is_some_and(ModbusClient::is_connected)
    }
    pub async fn read_coils(&mut self) -> Result<Sample> {
        self.read(Function::Coils, false).await
    }
    pub async fn read_discrete_inputs(&mut self) -> Result<Sample> {
        self.read(Function::DiscreteInputs, false).await
    }
    pub async fn read_holding_registers(&mut self) -> Result<Sample> {
        self.read(Function::HoldingRegisters, false).await
    }
    pub async fn read_holding_registers_raw(&mut self) -> Result<Sample> {
        self.read(Function::HoldingRegisters, true).await
    }
    pub async fn read_input_registers(&mut self) -> Result<Sample> {
        self.read(Function::InputRegisters, false).await
    }

    async fn read(&mut self, function: Function, raw: bool) -> Result<Sample> {
        if self.sealed {
            return Err(Error::Closed);
        }
        if function != self.map.read().function() {
            return Err(Error::DeniedService);
        }
        let _reserved = self.slot.receive()?;
        let client = self.client.as_ref().ok_or(Error::Closed)?;
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Closed)?;
        let read = self.map.read();
        let unit = UnitId(self.map.target().unit());
        // Cancellation before completion retires this client and declares loss.
        // It cannot leave a late response eligible for a subsequent fresh read.
        let mut guard = ReadGuard {
            client,
            coverage: &mut self.coverage,
            completed: false,
        };
        let call = async {
            let (address, quantity) = (read.address(), read.quantity());
            match function {
                Function::Coils => client
                    .read_coils(unit, address, quantity)
                    .await
                    .map(Payload::Bits),
                Function::DiscreteInputs => client
                    .read_discrete_inputs(unit, address, quantity)
                    .await
                    .map(Payload::Bits),
                Function::HoldingRegisters if raw => client
                    .read_holding_registers_raw(unit, address, quantity)
                    .await
                    .map(|b| Payload::RegisterBytes(b.to_vec())),
                Function::HoldingRegisters => client
                    .read_holding_registers(unit, address, quantity)
                    .await
                    .map(Payload::Words),
                Function::InputRegisters => client
                    .read_input_registers(unit, address, quantity)
                    .await
                    .map(Payload::Words),
            }
        };
        let payload = tokio::select! {
            _ = self.slot.cancelled() => return Err(Error::Cancelled),
            result = call => result?,
        };
        guard.completed = true;
        guard.coverage.revalidation_due = false;
        Ok(Sample {
            payload,
            map: self.map.clone(),
            incarnation: self.slot.incarnation,
            source: self.slot.source,
            sequence: self.sequence,
            receipt_time: SystemTime::now(),
            receipt_monotonic: Instant::now(),
        })
    }
    pub fn abort(&mut self) {
        self.sealed = true;
        if let Some(client) = &self.client {
            client.abort();
        }
        loss(&mut self.coverage);
    }
    /// Seals first, joins client tasks, then DROPS the sink. On an outer deadline
    /// retain this owner and retry shutdown: a timeout is never a successful join.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.sealed = true;
        if let Some(client) = &self.client {
            if tokio::time::timeout(SHUTDOWN_TIMEOUT, client.shutdown())
                .await
                .is_err()
            {
                client.abort();
                return Err(Error::Unresolved);
            }
            self.client = None;
            loss(&mut self.coverage);
        }
        self.slot.finish();
        Ok(())
    }
}
impl<S: TransportSink + Send + 'static> Drop for Client<S> {
    fn drop(&mut self) {
        if let Some(client) = &self.client {
            client.abort();
            // The Runtime keeps the unresolved reservation; no invented join.
            eprintln!("verdant modbus unresolved: owner dropped before shutdown/join");
        }
    }
}
fn loss(coverage: &mut Coverage) {
    coverage.changes = coverage.changes.saturating_add(1);
    coverage.last = Loss::Closed;
    coverage.unobserved_interval = true;
    coverage.revalidation_due = true;
}
struct ReadGuard<'a, S: TransportSink + Send + 'static> {
    client: &'a ModbusClient<S>,
    coverage: &'a mut Coverage,
    completed: bool,
}
impl<S: TransportSink + Send + 'static> Drop for ReadGuard<'_, S> {
    fn drop(&mut self) {
        if !self.completed {
            self.client.abort();
            loss(self.coverage);
        }
    }
}

#[cfg(test)]
pub(crate) mod test_peer;
#[cfg(test)]
mod tests;
