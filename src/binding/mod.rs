//! M01-PR07 equipment and proposed bindings (B02 first slice).
//!
//! Scoped equipment / space / property / source records plus proposed
//! endpoint-to-point bindings with explicit units, enums and
//! requested / effective / feedback roles. Joins PR04 access (capability
//! ceilings), PR05 native lifecycle (persistence decision) and PR06
//! conversion (imported bindings). Std-only plus the PR02/PR03/PR04/PR06
//! surfaces consumed below; no new dependencies (D02 freeze holds).
//!
//! ## Consumed, never redefined
//!
//! * PR02 [`InstalledId`](crate::domain::ids::InstalledId),
//!   [`Unit`](crate::domain::values::Unit),
//!   [`Value`](crate::domain::values::Value),
//!   [`OpMode`](crate::domain::values::OpMode) and the `tiny_site` shape
//!   (`ahu-1`, `vav-101`, `vav-102`, `sensor-sat-1`, two scopes, duplicate
//!   VAV labels).
//! * PR04 [`AccessGate`](crate::access::AccessGate) `enter_review` /
//!   `enter_publish` plus ceiling semantics plus
//!   [`is_revoked`](crate::access::AccessGate::is_revoked): bindings are
//!   checked against capabilities; cross-scope traversal and links grant
//!   nothing.
//! * PR05 [`NativeHandle`](crate::native::NativeHandle) /
//!   [`OpenReport`](crate::native::report::OpenReport) /
//!   [`Readiness`](crate::native::report::Readiness) plus refusal codes:
//!   considered for persistence (see below); the durable record lives in
//!   the PR03 store, not in a disposable native store.
//! * PR06 [`ConversionRecord`](crate::semantics::convert::ConversionRecord) /
//!   [`BindingSet`](crate::semantics::convert::BindingSet) shapes plus
//!   revision plus diagnostic codes: imported bindings enter through
//!   conversion outcomes only (see [`import`]).
//!
//! ## Persistence decision: 0001 outbox, no 0002 migration
//!
//! Binding records reuse the PR03 0001 `outbox` as additive rows with
//! reserved `binding-*` operations (PR04 pattern). `0002_binding.sql` is
//! NOT created: the outbox already carries `(operation, entity, sensor,
//! value_json, unit, times, generation, seq, status)` with exactly the
//! shape binding history needs (ordered, durable, per-connection verified).
//! `SCHEMA_GENERATION` stays `1`; R03's existing `0002_receipts` supplies
//! operation identity and reconciliation. R06 adds no migration. Full registry
//! reconstruction and explicit bounded observation windows are separate APIs;
//! a truncated window can never become mutation truth.
//!
//! Native (Selene) persistence was considered and declined: per D05 the
//! Selene pin carries no persisted-data compat across builds (treat native
//! stores as disposable, recreate from source), while binding prerequisite
//! findings must stay durable alongside access admission rows in the SQLite
//! baseline at tiny_site scale. No native lifecycle, checkpoint or prune
//! runs in this slice.
//!
//! Change record (integration §2 style):
//!
//! ```text
//! backend + owner .....: sqlite / M01-PR07 (binding record log)
//! predecessors ........: 0001_init (consumed, not forked; no new migration)
//! fresh-install .......: PR03 0001 apply + user_version = 1, then binding
//!                         records accumulate (refused duplicates never write)
//! supported upgrade ...: none in this slice (generation stays 0001)
//! queued-msg compat ...: binding rows are additive outbox rows; duplicates
//!                         tolerated + counted at the store layer, binding
//!                         duplicates refused at the registry layer with
//!                         duplicate-identity (never silently merged)
//! lock / space needs ..: same envelope as PR03/PR04 (WAL + FULL-sync + 5 s
//!                         busy timeout, bounded retries); temp DBs in OS temp
//!                         dirs only, unique names, removed on drop
//! interruption outcome : uncommitted inserts never survive; partial writes
//!                         leave visible rows and replay deterministically
//! read / write policy .: every binding read/write runs inside the verified
//!                         PR03 envelope (generation + durability re-read
//!                         in-band); unknown generation refused, never skipped
//! rollback boundary ...: no schema change; data rollback is explicit per-row
//!                         (retirement is a new recorded statement, not a
//!                         delete); applied migrations never rewritten
//! ```
//!
//! ## Statuses and exclusions
//!
//! `imported` (from conversion) vs `valid` (structural shape/units/roles
//! check) vs `observed-qualified` (evidence-backed) are kept separate. No
//! static validation in this slice may claim sensing/actuation
//! qualification; qualification is a later concern and tests assert its
//! absence. Bindings never authorize actuation: a native actuatable class
//! or a protocol address alone is not permission (there is no `authorize`
//! method by design). Network discovery/scanning, UI, field/hub/MCP and
//! workers are excluded (stop, do not implement here).
//!
//! ## PR11 handoff (stable entry points)
//!
//! * [`findings::Finding::for_binding`] — derive a finding for one binding.
//! * [`findings::Finding::id`] / [`findings::Finding::generation`] — the
//!   citable `(id, generation)` pair (generation equals the binding
//!   revision at emission).
//! * [`registry::BindingRegistry::revision`] — the binding revision
//!   (PR02 [`BindingRevision`](crate::domain::ids::BindingRevision)).
//! * [`findings::Finding::actor_reference_text`] — stable capability, scope,
//!   capability generation and issuer, joined from a live R05 entry report.
//!
//! R06 descriptor decision: v2 only (including record rows); v1 databases are
//! refused, not silently upgraded. Binding revision/sequence and the row commit
//! together behind the R03 guarded receipt boundary. No cached actor grants a
//! mutation, and pure `propose`/`import_binding` remain independent of storage.

pub mod error;
pub mod findings;
pub mod history;
pub mod import;
pub mod proposal;
pub mod records;
pub mod registry;
pub mod writer;
mod authority;

pub use error::BindingError;
#[allow(unused_imports)]
pub use findings::{Finding, FindingId};
#[allow(unused_imports)]
pub use writer::{PendingProposal, ProposalCommit};
#[allow(unused_imports)]
pub use import::{import_binding, import_diagnostic, import_site};
#[allow(unused_imports)]
pub use proposal::{propose, BindingRole, BindingStatus, Feedback, ProposedBinding};
#[allow(unused_imports)]
pub use records::{
    EndpointAddress, EndpointClass, EquipmentKind, EquipmentRecord, PointRecord, PropertyName,
    RecordLabel, SourceRecord, SpaceRecord,
};
#[allow(unused_imports)]
pub use registry::{
    BindingRegistry, BINDING_SCHEMA_GENERATION, BINDING_SENSOR_TEXT, BINDING_UNIT_TEXT,
    OP_EQUIPMENT_TEXT, OP_FINDING_TEXT, OP_POINT_TEXT, OP_PROPOSE_TEXT, OP_RETIRE_TEXT,
    OP_SOURCE_TEXT, OP_SPACE_TEXT,
};

use std::collections::BTreeMap;

pub(crate) fn assert_schema_generation() {
    debug_assert_eq!(
        BINDING_SCHEMA_GENERATION,
        crate::storage::SCHEMA_GENERATION,
        "binding is bound to the PR03 0001 baseline"
    );
    assert_eq!(
        BINDING_SCHEMA_GENERATION,
        crate::storage::SCHEMA_GENERATION,
        "binding is bound to the PR03 0001 baseline"
    );
}

pub(crate) fn pct_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for &b in raw.as_bytes() {
        match b {
            b'%' => out.push_str("%25"),
            b';' => out.push_str("%3B"),
            b'=' => out.push_str("%3D"),
            b'\n' => out.push_str("%0A"),
            b'\r' => out.push_str("%0D"),
            0x1F => out.push_str("%1F"),
            0x20..=0x7E => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub(crate) fn pct_decode(raw: &str) -> Result<String, BindingError> {
    let bad = |detail: String| BindingError::InvalidRecord { detail };
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(bad(format!("truncated percent escape in '{raw}'")));
            }
            let hex_bytes = &bytes[i + 1..i + 3];
            let hex = std::str::from_utf8(hex_bytes)
                .map_err(|_| bad(format!("invalid escape in '{raw}'")))?;
            let byte = u8::from_str_radix(hex, 16)
                .map_err(|_| bad(format!("invalid percent escape '%{hex}' in '{raw}'")))?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| bad(format!("field is not valid UTF-8 in '{raw}'")))
}

pub(crate) fn sql_quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('\'');
    for ch in raw.chars() {
        if ch == '\'' {
            out.push_str("''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

pub(crate) fn unquote_column(raw: &str) -> Result<Option<String>, BindingError> {
    if raw == "NULL" {
        return Ok(None);
    }
    let inner = raw
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .ok_or_else(|| BindingError::InvalidRecord {
            detail: format!("quoted binding column malformed: '{raw}'"),
        })?;
    Ok(Some(inner.replace("''", "'")))
}

pub(crate) fn synthetic_times() -> crate::domain::clock::TimeTriple {
    use crate::domain::clock::{TimeTriple, UnixMillis};
    TimeTriple::new(
        UnixMillis::new(1_700_000_000_123),
        UnixMillis::new(1_700_000_000_456),
        UnixMillis::new(1_700_000_000_789),
    )
    .expect("frozen binding times are ordered")
}

pub(crate) fn synthetic_record(seq: u64) -> crate::domain::outcomes::RecordIdentity {
    crate::domain::outcomes::RecordIdentity::new(
        crate::domain::ids::SourceGenerationId::parse("gen-1")
            .expect("frozen binding generation is valid"),
        seq,
    )
}

pub(crate) fn frozen_sensor() -> crate::domain::ids::InstalledId {
    crate::domain::ids::InstalledId::parse(BINDING_SENSOR_TEXT)
        .expect("frozen binding sensor is valid")
}

pub(crate) fn binding_unit() -> crate::domain::values::Unit {
    crate::domain::values::Unit::parse(BINDING_UNIT_TEXT).expect("frozen binding unit is valid")
}

pub(crate) fn split_descriptor(raw: &str) -> Result<BTreeMap<String, String>, BindingError> {
    let mut map = BTreeMap::new();
    for part in raw.split(';') {
        let eq = part.find('=').ok_or_else(|| BindingError::InvalidRecord {
            detail: format!("binding descriptor part without '=': '{part}'"),
        })?;
        let key = part[..eq].to_string();
        let encoded = &part[eq + 1..];
        if key.is_empty() {
            return Err(BindingError::InvalidRecord {
                detail: "binding descriptor has an empty key".to_string(),
            });
        }
        if map.insert(key.clone(), pct_decode(encoded)?).is_some() {
            return Err(BindingError::InvalidRecord {
                detail: format!("binding descriptor duplicates key '{key}'"),
            });
        }
    }
    Ok(map)
}

pub(crate) fn require_field(
    map: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<String, BindingError> {
    map.get(key)
        .cloned()
        .ok_or_else(|| BindingError::InvalidRecord {
            detail: format!("binding descriptor missing field '{key}'"),
        })
}
