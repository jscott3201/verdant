//! Law-2 equivalent, synthetic map evidence only. No vendor catalog or implicit
//! units. Word order is significance order; byte order applies within each u16.
//! Integer scaling is EXACT: (integer * numerator + offset) / 10^places.
//! Floats and unsupported encodings remain Unknown, never guessed from bits.
use super::{Error, Function, Payload, Read, Result, Target};
use crate::{
    domain::values::{Decimal, Diagnostic, Unit, Value},
    observation::normalize::{Refusal, Suitability, TransportResult, ValueQuality},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ByteOrder {
    Big,
    Little,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WordOrder {
    HighFirst,
    LowFirst,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Encoding {
    Bool,
    U16,
    I16,
    U32,
    I32,
    Unsupported(String),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scale {
    pub numerator: i32,
    pub offset: i32,
    pub places: u8,
}
impl Scale {
    pub const IDENTITY: Self = Self {
        numerator: 1,
        offset: 0,
        places: 0,
    };
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Map {
    revision: String,
    source_role: String,
    target: Target,
    read: Read,
    encoding: Encoding,
    byte_order: ByteOrder,
    word_order: WordOrder,
    scale: Scale,
    unit: Unit,
}
impl Map {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        revision: &str,
        source_role: &str,
        target: Target,
        read: Read,
        encoding: Encoding,
        byte_order: ByteOrder,
        word_order: WordOrder,
        scale: Scale,
        unit: Unit,
    ) -> Result<Self> {
        for token in [revision, source_role, unit.as_str()] {
            if token.is_empty() || token.len() > 128 || token.chars().any(char::is_control) {
                return Err(Error::Map);
            }
        }
        if scale.places > 9 {
            return Err(Error::Map);
        }
        let words = match &encoding {
            Encoding::Bool if read.function().bits() && scale == Scale::IDENTITY => 1,
            Encoding::U16 | Encoding::I16 if !read.function().bits() => 1,
            Encoding::U32 | Encoding::I32 if !read.function().bits() => 2,
            Encoding::Unsupported(token) if !token.is_empty() && token.len() <= 128 => read.quantity(),
            Encoding::Bool
            | Encoding::U16
            | Encoding::I16
            | Encoding::U32
            | Encoding::I32
            | Encoding::Unsupported(_) => return Err(Error::Map),
        };
        if read.quantity() != words {
            return Err(Error::Quantity);
        }
        Ok(Self {
            revision: revision.into(),
            source_role: source_role.into(),
            target,
            read,
            encoding,
            byte_order,
            word_order,
            scale,
            unit,
        })
    }
    pub fn revision(&self) -> &str {
        &self.revision
    }
    pub fn target(&self) -> Target {
        self.target
    }
    pub fn read(&self) -> Read {
        self.read
    }
    pub fn unit(&self) -> &Unit {
        &self.unit
    }

    /// Exact map equality prevents same-revision-but-different-content retargets.
    /// Callers supply failures as transport evidence, not a zero word substitute.
    pub fn decode(&self, payload: Option<&Payload>, transport: TransportResult) -> Mapped {
        let (value, quality) = if transport != TransportResult::ValueReturned {
            (Value::Missing, ValueQuality::Missing)
        } else {
            self.value(payload)
        };
        let refusal = if transport != TransportResult::ValueReturned {
            Some(Refusal::Transport)
        } else {
            match &quality {
                ValueQuality::Valid if self.unit.is_unknown() => Some(Refusal::UnknownUnit),
                ValueQuality::Valid => None,
                ValueQuality::Missing => Some(Refusal::Missing),
                ValueQuality::Invalid => Some(Refusal::Invalid),
                ValueQuality::NonFinite => Some(Refusal::NonFinite),
                ValueQuality::Unknown { .. } => Some(Refusal::Unsupported),
            }
        };
        Mapped {
            value,
            unit: self.unit.clone(),
            map: self.clone(),
            transport,
            quality,
            suitability: refusal.map_or(Suitability::SyntheticValueOnly, Suitability::Refused),
        }
    }
    fn value(&self, payload: Option<&Payload>) -> (Value, ValueQuality) {
        let invalid = || {
            (
                Value::Diagnostic(Diagnostic::Invalid("map payload shape".into())),
                ValueQuality::Invalid,
            )
        };
        let shape = match payload {
            Some(Payload::Bits(bits)) => {
                self.read.function().bits() && bits.len() == usize::from(self.read.quantity())
            }
            Some(Payload::Words(words)) => {
                !self.read.function().bits() && words.len() == usize::from(self.read.quantity())
            }
            Some(Payload::RegisterBytes(bytes)) => {
                !self.read.function().bits() && bytes.len() == self.read.bytes()
            }
            None => false,
        };
        if !shape {
            return invalid();
        }
        if let Encoding::Unsupported(token) = &self.encoding {
            return (
                Value::Diagnostic(Diagnostic::Invalid(token.clone())),
                ValueQuality::Unknown {
                    detail: token.clone(),
                },
            );
        }
        if self.encoding == Encoding::Bool {
            return match payload {
                Some(Payload::Bits(bits)) if bits.len() == 1 => (Value::Bool(bits[0]), ValueQuality::Valid),
                _ => invalid(),
            };
        }
        let words = match payload {
            Some(Payload::Words(words)) => words.clone(),
            Some(Payload::RegisterBytes(bytes)) if bytes.len() == self.read.bytes() => bytes
                .chunks_exact(2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .collect(),
            Some(Payload::RegisterBytes(_)) | Some(Payload::Bits(_)) | None => return invalid(),
        };
        if words.len() != usize::from(self.read.quantity()) {
            return invalid();
        }
        let mut words: Vec<_> = words
            .into_iter()
            .map(|w| match self.byte_order {
                ByteOrder::Big => w,
                ByteOrder::Little => w.swap_bytes(),
            })
            .collect();
        if self.word_order == WordOrder::LowFirst {
            words.reverse();
        }
        let n = match self.encoding {
            Encoding::U16 => i128::from(words[0]),
            Encoding::I16 => i128::from(words[0] as i16),
            Encoding::U32 => i128::from((u32::from(words[0]) << 16) | u32::from(words[1])),
            Encoding::I32 => i128::from(((u32::from(words[0]) << 16) | u32::from(words[1])) as i32),
            Encoding::Bool | Encoding::Unsupported(_) => return invalid(),
        };
        let n = n * i128::from(self.scale.numerator) + i128::from(self.scale.offset);
        if self.scale.places == 0 {
            return (Value::Integer(n), ValueQuality::Valid);
        }
        let divisor = 10i128.pow(u32::from(self.scale.places));
        let abs = n.abs();
        let text = format!(
            "{}{}.{:0width$}",
            if n < 0 { "-" } else { "" },
            abs / divisor,
            abs % divisor,
            width = usize::from(self.scale.places)
        );
        match Decimal::parse(&text) {
            Ok(decimal) => (Value::Decimal(decimal), ValueQuality::Valid),
            Err(_) => invalid(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mapped {
    pub value: Value,
    pub unit: Unit,
    /// Complete explicit per-map provenance, including revision/role/target/read.
    pub map: Map,
    pub transport: TransportResult,
    pub quality: ValueQuality,
    pub suitability: Suitability,
}
