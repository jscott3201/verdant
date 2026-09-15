//! Explicit zero-based wire addresses, never 4xxxx/1-based vendor notation.
use super::{Error, Result};
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Function {
    Coils,
    DiscreteInputs,
    HoldingRegisters,
    InputRegisters,
}
impl Function {
    pub fn parse(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Coils),
            2 => Ok(Self::DiscreteInputs),
            3 => Ok(Self::HoldingRegisters),
            4 => Ok(Self::InputRegisters),
            _ => Err(Error::DeniedService),
        }
    }
    pub fn code(self) -> u8 {
        match self {
            Self::Coils => 1,
            Self::DiscreteInputs => 2,
            Self::HoldingRegisters => 3,
            Self::InputRegisters => 4,
        }
    }
    pub fn bits(self) -> bool {
        matches!(self, Self::Coils | Self::DiscreteInputs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Target {
    address: SocketAddr,
    unit: u8,
}
impl Target {
    /// E03 fixture scope only. No DNS, retargeting, route, wildcard destination,
    /// default service port, facility peer or broadcast can be represented.
    pub fn loopback(address: SocketAddr, unit: u8) -> Result<Self> {
        if unit == 0 {
            return Err(Error::BroadcastReadNotAllowed);
        }
        if !matches!(unit, 1..=247 | 255) {
            return Err(Error::InvalidUnit);
        }
        // test_peer::Pair::at proves ephemeral allocation by binding :0 (reconnect
        // reuses that peer). A number alone cannot prove it: OS ranges are tunable.
        // Match the capture audit: unprivileged, excluding Modbus, BACnet and the
        // refused 8080 listener fixture; never admit a facility address.
        if address.ip() != Ipv4Addr::LOCALHOST
            || address.port() < 1024
            || [502, 802, 8080, 47808].contains(&address.port())
        {
            return Err(Error::DeniedDestination);
        }
        Ok(Self { address, unit })
    }
    pub fn address(self) -> SocketAddr {
        self.address
    }
    pub fn unit(self) -> u8 {
        self.unit
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Read {
    function: Function,
    address: u16,
    quantity: u16,
}
impl Read {
    pub fn new(function: Function, address: u16, quantity: u16) -> Result<Self> {
        let limit = if function.bits() { 2000 } else { 125 };
        if quantity == 0 || quantity > limit {
            return Err(Error::Quantity);
        }
        if u32::from(address) + u32::from(quantity) > 65536 {
            return Err(Error::Address);
        }
        Ok(Self {
            function,
            address,
            quantity,
        })
    }
    pub fn function(self) -> Function {
        self.function
    }
    pub fn address(self) -> u16 {
        self.address
    }
    pub fn quantity(self) -> u16 {
        self.quantity
    }
    pub fn bytes(self) -> usize {
        if self.function.bits() {
            usize::from(self.quantity).div_ceil(8)
        } else {
            usize::from(self.quantity) * 2
        }
    }
}

/// Returned words are unsigned *wire* words. Signedness/order/scaling belongs
/// exclusively to an explicit revisioned Map, not to the transport or unit ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Payload {
    Bits(Vec<bool>),
    Words(Vec<u16>),
    /// Upstream FC03 raw register bytes (big-endian words, no MBAP/PDU prefix).
    RegisterBytes(Vec<u8>),
}
