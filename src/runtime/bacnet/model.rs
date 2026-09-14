//! Closed, immutable acquisition plans. No discovered-device lookup or raw client.
use super::{Error, Result};
use crate::domain::{ids::InstalledId, scope::TrustedScope};
use bacnet_types::{enums::ObjectType, primitives::ObjectIdentifier};
use std::net::SocketAddrV4;

pub const MAX_PROPERTIES: usize = 8;
pub const MAX_PLANS: usize = 16;
pub const MAX_NPDU_BYTES: usize = 1_024;
pub const MAX_VALUE_BYTES: usize = 512;
pub const APDU_TIMEOUT_MS: u64 = 6_000;
pub const APDU_RETRIES: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectTarget {
    realm: InstalledId,
    mac: [u8; 6],
}
impl DirectTarget {
    /// Numeric direct destination only. No DNS, broadcast, discovery resolution,
    /// routed destination, or facility authority is supplied by this constructor.
    pub fn parse(realm: &str, endpoint: &str) -> Result<Self> {
        let address: SocketAddrV4 = endpoint
            .strip_prefix("bacnet-ip://")
            .ok_or(Error::Invalid("direct BACnet/IP destination required"))?
            .parse()
            .map_err(|_| Error::Invalid("numeric direct destination required"))?;
        let ip = *address.ip();
        if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || address.port() == 0 {
            return Err(Error::Invalid("non-unicast destination"));
        }
        let realm = InstalledId::parse(realm).map_err(|_| Error::Invalid("realm"))?;
        let [a, b, c, d] = ip.octets();
        let [hi, lo] = address.port().to_be_bytes();
        Ok(Self { realm, mac: [a, b, c, d, hi, lo] })
    }
    pub fn realm(&self) -> &InstalledId {
        &self.realm
    }
    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Property {
    pub(super) object: ObjectIdentifier,
    pub(super) identifier: u32,
    pub(super) array_index: Option<u32>,
}
impl Property {
    pub fn new(object_type: u16, instance: u32, identifier: u32, array_index: Option<u32>) -> Result<Self> {
        let object = ObjectIdentifier::new(ObjectType::from_raw(u32::from(object_type)), instance)
            .map_err(|_| Error::Invalid("object identifier"))?;
        // ALL/REQUIRED/OPTIONAL are open-ended RPM expansion, not bounded properties.
        if matches!(identifier, 8 | 80 | 105) {
            return Err(Error::Invalid("property expansion refused"));
        }
        Ok(Self { object, identifier, array_index })
    }
    pub fn object(&self) -> ObjectIdentifier {
        self.object
    }
    pub fn identifier(&self) -> u32 {
        self.identifier
    }
    pub fn array_index(&self) -> Option<u32> {
        self.array_index
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    ReadProperty,
    ReadPropertyMultiple,
    DirectedWhoIs,
}
#[derive(Debug, Clone)]
pub struct Request(Operation);
#[derive(Debug, Clone)]
pub(super) enum Operation {
    Single(Property),
    Multiple(Vec<Property>),
    Discover { instance: u32 },
}
impl Request {
    pub fn read_property(property: Property) -> Self {
        Self(Operation::Single(property))
    }
    pub fn read_property_multiple(properties: Vec<Property>) -> Result<Self> {
        if properties.is_empty() || properties.len() > MAX_PROPERTIES {
            return Err(Error::Invalid("property count"));
        }
        for (index, property) in properties.iter().enumerate() {
            if properties[..index].contains(property) {
                return Err(Error::Invalid("duplicate property"));
            }
        }
        Ok(Self(Operation::Multiple(properties.into_boxed_slice().into_vec())))
    }
    /// One explicit instance at one admitted direct destination, never a scan.
    pub fn directed_discovery(instance: u32) -> Result<Self> {
        ObjectIdentifier::new(ObjectType::DEVICE, instance).map_err(|_| Error::Invalid("device instance"))?;
        Ok(Self(Operation::Discover { instance }))
    }
    pub fn service(&self) -> Service {
        match self.0 {
            Operation::Single(_) => Service::ReadProperty,
            Operation::Multiple(_) => Service::ReadPropertyMultiple,
            Operation::Discover { .. } => Service::DirectedWhoIs,
        }
    }
    pub(super) fn operation(&self) -> &Operation {
        &self.0
    }
    pub(super) fn properties(&self) -> Vec<Property> {
        match &self.0 {
            Operation::Single(property) => vec![*property],
            Operation::Multiple(properties) => properties.clone(),
            Operation::Discover { .. } => Vec::new(),
        }
    }
}

/// Explicit synthetic mapping, joined to the exact accepted binding on admission.
/// It is not a commissioned route inferred from a semantic label or advertisement.
#[derive(Debug, Clone)]
pub struct BindingPlan {
    pub(super) key: InstalledId,
    pub(super) source: InstalledId,
    pub(super) endpoint: String,
    pub(super) property: String,
    pub(super) target: DirectTarget,
    pub(super) request: Request,
}
impl BindingPlan {
    pub fn new(
        key: &str,
        source: &str,
        endpoint: &str,
        property: &str,
        target: DirectTarget,
        request: Request,
    ) -> Result<Self> {
        if endpoint.len() > 256 || property.len() > 128 || endpoint.is_empty() || property.is_empty() {
            return Err(Error::Invalid("binding plan strings"));
        }
        Ok(Self {
            key: InstalledId::parse(key).map_err(|_| Error::Invalid("binding key"))?,
            source: InstalledId::parse(source).map_err(|_| Error::Invalid("source identity"))?,
            endpoint: endpoint.into(),
            property: property.into(),
            target,
            request,
        })
    }
}
#[derive(Debug, Clone)]
pub struct Profile {
    pub(super) scope: TrustedScope,
    pub(super) plans: Vec<BindingPlan>,
    pub(super) destinations: Vec<DirectTarget>,
    pub(super) services: Vec<Service>,
}
impl Profile {
    pub fn new(
        scope: TrustedScope,
        plans: Vec<BindingPlan>,
        destinations: Vec<DirectTarget>,
        services: Vec<Service>,
    ) -> Result<Self> {
        if plans.len() > MAX_PLANS || destinations.len() > MAX_PLANS || services.len() > 3 {
            return Err(Error::Invalid("profile bound"));
        }
        for (index, plan) in plans.iter().enumerate() {
            if plans[..index].iter().any(|prior| prior.key == plan.key) {
                return Err(Error::Invalid("duplicate binding plan"));
            }
        }
        Ok(Self {
            scope,
            plans: plans.into_boxed_slice().into_vec(),
            destinations: destinations.into_boxed_slice().into_vec(),
            services: services.into_boxed_slice().into_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyOutcome {
    Value(Vec<u8>),
    RemoteError {
        class: u32,
        code: u32,
    },
    Reject(u8),
    /// Public-client reason; may be locally generated (e.g. TSM_TIMEOUT=10),
    /// so this alone does not prove that an Abort PDU was received.
    Abort(u8),
    Timeout,
    InvalidReply,
    Oversized,
    TransportFailure,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyResult {
    pub property: Property,
    pub outcome: PropertyOutcome,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadBatch {
    pub target: DirectTarget,
    pub properties: Vec<PropertyResult>,
}
