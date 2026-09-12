//! Source/receipt/ingestion time and identified monotonic/boot context.
//!
//! A source time is optional/uncertain; receipt observes transport; ingestion
//! records when the application stored the record. [`TimeTriple`] keeps the
//! three distinct and refuses impossible orders (`source <= receipt <=
//! ingestion`).
//!
//! Monotonic values have a process/boot domain and must not be compared
//! blindly after restart or across machines. [`MonotonicMark`] is the only
//! portable monotonic representation (`boot` + `nanos_since_boot`);
//! `std::time::Instant` is process-local and is **never** serialized here
//! (there is no `from_instant`-to-JSON path and no `Instant` field in any
//! portable struct). Checked [`MonotonicMark::elapsed_since`] refuses
//! cross-boot comparisons and impossible (`end < start`) elapsed times.
//!
//! Wall times are `i64` millis since the Unix epoch; monotonic nanos are `u64`
//! since boot. All arithmetic is checked.

use super::Error;

/// Wall-clock millis since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnixMillis(i64);

impl UnixMillis {
    /// Construct a wall time. Any `i64` is representable; ordering is checked
    /// by [`TimeTriple::new`], not here.
    pub fn new(millis: i64) -> UnixMillis {
        UnixMillis(millis)
    }

    /// Borrow the raw millis.
    pub fn as_millis(self) -> i64 {
        self.0
    }
}

/// Identified boot context for monotonic marks.
///
/// Distinct from other identities so a boot is never confused with a scope,
/// device or operation. Validated like other ids (non-empty, `<= 128` bytes,
/// `[A-Za-z0-9-_.:/]`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BootId(String);

impl BootId {
    /// Validate boot text (e.g. `"boot-7"`).
    pub fn parse(raw: &str) -> Result<BootId, Error> {
        if raw.is_empty() {
            return Err(Error::Empty { what: "boot-id" });
        }
        if raw.len() > super::ids::MAX_ID_LEN {
            return Err(Error::TooLong {
                what: "boot-id",
                len: raw.len(),
                max: super::ids::MAX_ID_LEN,
            });
        }
        let ok = raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
        if !ok {
            return Err(Error::BadChars {
                what: "boot-id",
                value: raw.to_string(),
            });
        }
        Ok(BootId(raw.to_string()))
    }

    /// Borrow the canonical text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Portable monotonic mark: identified boot plus nanos since that boot.
///
/// This is the portable history form. It is constructed from explicit
/// `(boot, nanos)` values supplied by the caller (e.g. from a host monotonic
/// source paired with its boot identity); it is never derived by serializing
/// a process-local `std::time::Instant`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MonotonicMark {
    boot: BootId,
    nanos_since_boot: u64,
}

impl MonotonicMark {
    /// Construct a mark from its identified boot and nanos since that boot.
    pub fn new(boot: BootId, nanos_since_boot: u64) -> MonotonicMark {
        MonotonicMark {
            boot,
            nanos_since_boot,
        }
    }

    /// Borrow the boot identity.
    pub fn boot(&self) -> &BootId {
        &self.boot
    }

    /// Borrow the nanos since boot.
    pub fn nanos_since_boot(&self) -> u64 {
        self.nanos_since_boot
    }

    /// Checked elapsed time from `earlier` to `self`.
    ///
    /// Refuses cross-boot comparisons ([`Error::BootMismatch`]) and
    /// impossible elapsed times where `self < earlier`
    /// ([`Error::ImpossibleElapsed`]). Uses checked subtraction; overflow is
    /// impossible for `u64` differences but the refusal path is explicit.
    pub fn elapsed_since(&self, earlier: &MonotonicMark) -> Result<std::time::Duration, Error> {
        if self.boot != earlier.boot {
            return Err(Error::BootMismatch {
                expected: earlier.boot.as_str().to_string(),
                got: self.boot.as_str().to_string(),
            });
        }
        let nanos = self
            .nanos_since_boot
            .checked_sub(earlier.nanos_since_boot)
            .ok_or_else(|| Error::ImpossibleElapsed {
                detail: format!(
                    "end {} is before start {} on boot '{}'",
                    self.nanos_since_boot,
                    earlier.nanos_since_boot,
                    self.boot.as_str()
                ),
            })?;
        Ok(std::time::Duration::from_nanos(nanos))
    }

    /// Encode as `{"boot":"boot-7","nanos_since_boot":"123"}` (nanos as a
    /// JSON string for exactness).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"boot\":{},\"nanos_since_boot\":{}}}",
            super::json::quote(self.boot.as_str()),
            super::json::quote(&self.nanos_since_boot.to_string())
        )
    }

    /// Decode from `{"boot":"...","nanos_since_boot":"..."}`; refuses
    /// malformed JSON, missing/unexpected fields and invalid boot/nanos text.
    pub fn from_json(text: &str) -> Result<MonotonicMark, Error> {
        let fields = super::json::parse_object(text)?;
        super::json::reject_unknown(&fields, &["boot", "nanos_since_boot"])?;
        let boot_raw = super::json::get_string(&fields, "boot")?;
        let nanos_raw = super::json::get_string(&fields, "nanos_since_boot")?;
        let boot = BootId::parse(&boot_raw)?;
        let nanos: u64 = nanos_raw.parse::<u64>().map_err(|_| Error::InvalidValue {
            what: "nanos-since-boot",
            value: nanos_raw.clone(),
        })?;
        Ok(MonotonicMark::new(boot, nanos))
    }
}

/// Source/receipt/ingestion triple.
///
/// `source <= receipt <= ingestion` (millis). Construction refuses impossible
/// orders; a renewed subscription must not rewrite the source time, and
/// backfill does not establish live prerequisites (those policies live with
/// the later consumer; here only the ordering invariant is frozen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimeTriple {
    source: UnixMillis,
    receipt: UnixMillis,
    ingestion: UnixMillis,
}

impl TimeTriple {
    /// Construct a triple, refusing impossible orders with a typed [`Error`].
    pub fn new(
        source: UnixMillis,
        receipt: UnixMillis,
        ingestion: UnixMillis,
    ) -> Result<TimeTriple, Error> {
        if source.as_millis() > receipt.as_millis() {
            return Err(Error::ImpossibleOrder {
                detail: format!(
                    "receipt {} is before source {}",
                    receipt.as_millis(),
                    source.as_millis()
                ),
            });
        }
        if receipt.as_millis() > ingestion.as_millis() {
            return Err(Error::ImpossibleOrder {
                detail: format!(
                    "ingestion {} is before receipt {}",
                    ingestion.as_millis(),
                    receipt.as_millis()
                ),
            });
        }
        Ok(TimeTriple {
            source,
            receipt,
            ingestion,
        })
    }

    /// Borrow the source time.
    pub fn source(self) -> UnixMillis {
        self.source
    }

    /// Borrow the receipt time.
    pub fn receipt(self) -> UnixMillis {
        self.receipt
    }

    /// Borrow the ingestion time.
    pub fn ingestion(self) -> UnixMillis {
        self.ingestion
    }

    /// Encode as `{"source_ms":"...","receipt_ms":"...","ingestion_ms":"..."}`
    /// (millis as JSON strings for exactness; field order frozen).
    pub fn to_json(self) -> String {
        format!(
            "{{\"source_ms\":{},\"receipt_ms\":{},\"ingestion_ms\":{}}}",
            super::json::quote(&self.source.as_millis().to_string()),
            super::json::quote(&self.receipt.as_millis().to_string()),
            super::json::quote(&self.ingestion.as_millis().to_string())
        )
    }

    /// Decode from the frozen encoding; refuses malformed JSON,
    /// missing/unexpected fields, non-integer millis and impossible orders.
    pub fn from_json(text: &str) -> Result<TimeTriple, Error> {
        let fields = super::json::parse_object(text)?;
        super::json::reject_unknown(&fields, &["source_ms", "receipt_ms", "ingestion_ms"])?;
        let parse_millis = |name: &'static str| -> Result<UnixMillis, Error> {
            let raw = super::json::get_string(&fields, name)?;
            raw.parse::<i64>()
                .map(UnixMillis)
                .map_err(|_| Error::InvalidValue {
                    what: "unix-millis",
                    value: raw,
                })
        };
        let source = parse_millis("source_ms")?;
        let receipt = parse_millis("receipt_ms")?;
        let ingestion = parse_millis("ingestion_ms")?;
        TimeTriple::new(source, receipt, ingestion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_preserves_distinct_times_and_refuses_impossible_order() {
        let triple = TimeTriple::new(
            UnixMillis::new(1_700_000_000_123),
            UnixMillis::new(1_700_000_000_456),
            UnixMillis::new(1_700_000_000_789),
        )
        .expect("valid triple");
        assert_eq!(triple.source().as_millis(), 1_700_000_000_123);
        assert_eq!(triple.receipt().as_millis(), 1_700_000_000_456);
        assert_eq!(triple.ingestion().as_millis(), 1_700_000_000_789);

        // Receipt before source is impossible.
        let err = TimeTriple::new(
            UnixMillis::new(200),
            UnixMillis::new(100),
            UnixMillis::new(300),
        )
        .unwrap_err();
        assert_eq!(err.code(), "impossible-order");

        // Ingestion before receipt is impossible.
        let err = TimeTriple::new(
            UnixMillis::new(100),
            UnixMillis::new(300),
            UnixMillis::new(200),
        )
        .unwrap_err();
        assert_eq!(err.code(), "impossible-order");

        // Equal times are allowed (same-millis delivery).
        assert!(
            TimeTriple::new(UnixMillis::new(5), UnixMillis::new(5), UnixMillis::new(5)).is_ok()
        );
    }

    #[test]
    fn monotonic_elapsed_is_checked_and_boot_scoped() {
        let boot_a = BootId::parse("boot-7").expect("boot");
        let boot_b = BootId::parse("boot-8").expect("boot");
        let start = MonotonicMark::new(boot_a.clone(), 1_000);
        let end = MonotonicMark::new(boot_a.clone(), 2_500);
        assert_eq!(start.boot().as_str(), "boot-7");
        assert_eq!(start.nanos_since_boot(), 1_000);
        assert_eq!(end.boot().as_str(), "boot-7");
        assert_eq!(end.nanos_since_boot(), 2_500);
        assert_eq!(
            end.elapsed_since(&start).expect("elapsed"),
            std::time::Duration::from_nanos(1_500)
        );
        // Zero elapsed is allowed.
        assert_eq!(
            start.elapsed_since(&start).expect("zero"),
            std::time::Duration::from_nanos(0)
        );
        // End before start is impossible.
        let err = start.elapsed_since(&end).unwrap_err();
        assert_eq!(err.code(), "impossible-elapsed");
        // Cross-boot comparison is refused, never silently subtracted.
        let other_boot = MonotonicMark::new(boot_b, 2_500);
        let err = other_boot.elapsed_since(&start).unwrap_err();
        assert_eq!(err.code(), "boot-mismatch");
    }

    #[test]
    fn boot_ids_are_validated() {
        assert!(BootId::parse("boot-7").is_ok());
        assert_eq!(BootId::parse("").unwrap_err().code(), "empty");
        assert_eq!(BootId::parse("boot 7").unwrap_err().code(), "bad-chars");
    }

    #[test]
    fn clock_json_round_trips() {
        let triple = TimeTriple::new(
            UnixMillis::new(1_700_000_000_123),
            UnixMillis::new(1_700_000_000_456),
            UnixMillis::new(1_700_000_000_789),
        )
        .expect("triple");
        let json = triple.to_json();
        assert_eq!(
            json,
            "{\"source_ms\":\"1700000000123\",\"receipt_ms\":\"1700000000456\",\"ingestion_ms\":\"1700000000789\"}"
        );
        assert_eq!(TimeTriple::from_json(&json).expect("decode"), triple);
        assert!(TimeTriple::from_json(
            "{\"source_ms\":\"200\",\"receipt_ms\":\"100\",\"ingestion_ms\":\"300\"}"
        )
        .is_err());

        let mark = MonotonicMark::new(BootId::parse("boot-7").expect("boot"), 1_234_567);
        let json = mark.to_json();
        assert_eq!(
            json,
            "{\"boot\":\"boot-7\",\"nanos_since_boot\":\"1234567\"}"
        );
        assert_eq!(MonotonicMark::from_json(&json).expect("decode"), mark);
        // Portable form carries boot + nanos only; there is no Instant field
        // to assert on: the struct has exactly these two fields by
        // construction, and `to_json` emits exactly them.
        assert!(json.contains("\"boot\""));
        assert!(json.contains("\"nanos_since_boot\""));
    }
}
