//! Domain/primitive-only projection for the synthetic observation owner.
//! One journal per store. All changes use the existing admitted WAL/FULL writer,
//! exact snapshot CAS and attempt receipts; no second SQLite process owner.
#![allow(dead_code)]
use super::{
    sqlite::{MutationOutcome, PreparedMutation, SqliteStore},
    StorageError,
};
use crate::domain::{ids::OperationId, values::Value};
use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, StorageError>;
pub type Object = BTreeMap<String, JsonVal>;
/// Closed projection grammar: string, null, object only. String escaping uses
/// the public domain Value codec; the private domain parser is not re-included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonVal {
    Null,
    Str(String),
    Object(Object),
}
pub const REPLAY_ROWS: u64 = 64; // E02 fixture assumption, not measured capacity.
const STATE: &str = "operation='obw:state' AND request='obw-state-v1'";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub id: String,
    pub generation: String,
    pub seq: u64,
    pub expiry_ms: i64,
    pub admit_seq: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub from: u64,
    pub to: u64,
    pub reason: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Image {
    pub state: Option<String>,
    /// Exact JSON capsules, never hashes or re-encoded floating point values.
    pub rows: Vec<String>,
    pub pins: Vec<Pin>,
    pub gaps: Vec<Gap>,
}
#[derive(Debug, Clone)]
pub struct Ticket {
    mutation: PreparedMutation,
    pub revision: u64,
    saved: String,
}
impl Ticket {
    /// Caller persists before dispatch. Recovery accepts these bytes for a
    /// read-only receipt comparison, never as executable caller-supplied SQL.
    pub fn reconciliation_bytes(&self) -> &str {
        &self.saved
    }
}
pub struct Writer(pub SqliteStore);

pub fn invalid(detail: &str) -> StorageError {
    StorageError::InvalidRecord {
        detail: detail.into(),
    }
}
pub fn object(raw: &str) -> Result<Object> {
    fn parse(raw: &str, depth: usize) -> Result<(JsonVal, &str)> {
        if depth > 4 {
            return Err(invalid("projection nesting"));
        }
        if raw.starts_with('"') {
            let mut escaped = false;
            for (i, c) in raw.char_indices().skip(1) {
                if escaped {
                    escaped = false;
                    continue;
                }
                if c == '\\' {
                    escaped = true;
                    continue;
                }
                if c == '"' {
                    let value = Value::from_json(&format!(
                        "{{\"type\":\"text\",\"value\":{}}}",
                        &raw[..i + 1]
                    ))
                    .map_err(|e| invalid(&e.to_string()))?;
                    return match value {
                        Value::Text(s) => Ok((JsonVal::Str(s), &raw[i + 1..])),
                        _ => Err(invalid("text")),
                    };
                }
            }
            return Err(invalid("unterminated projection string"));
        }
        if let Some(rest) = raw.strip_prefix("null") {
            return Ok((JsonVal::Null, rest));
        }
        let mut rest = raw
            .strip_prefix('{')
            .ok_or_else(|| invalid("projection object"))?;
        let mut fields = Object::new();
        if let Some(rest) = rest.strip_prefix('}') {
            return Ok((JsonVal::Object(fields), rest));
        }
        loop {
            let (key, tail) = parse(rest, depth + 1)?;
            let JsonVal::Str(key) = key else {
                return Err(invalid("projection key"));
            };
            let tail = tail
                .strip_prefix(':')
                .ok_or_else(|| invalid("projection colon"))?;
            let (value, tail) = parse(tail, depth + 1)?;
            if fields.insert(key, value).is_some() || fields.len() > 64 {
                return Err(invalid("duplicate/excess projection fields"));
            }
            if let Some(tail) = tail.strip_prefix('}') {
                return Ok((JsonVal::Object(fields), tail));
            }
            rest = tail
                .strip_prefix(',')
                .ok_or_else(|| invalid("projection comma"))?;
        }
    }
    if raw.len() > 8 * 1024 * 1024 {
        return Err(invalid("projection bytes"));
    }
    match parse(raw, 0)? {
        (JsonVal::Object(fields), "") => Ok(fields),
        _ => Err(invalid("projection framing")),
    }
}
pub fn text(fields: &Object, key: &'static str) -> Result<String> {
    match fields.get(key) {
        Some(JsonVal::Str(s)) => Ok(s.clone()),
        _ => Err(invalid(key)),
    }
}
pub fn number(fields: &Object, key: &'static str) -> Result<u64> {
    text(fields, key)?.parse().map_err(|_| invalid(key))
}
pub fn signed(fields: &Object, key: &'static str) -> Result<i64> {
    text(fields, key)?.parse().map_err(|_| invalid(key))
}
pub fn encode(fields: Object) -> String {
    fn string(s: String) -> String {
        let encoded = Value::Text(s).to_json();
        // The public domain encoding is frozen by independent contract fixtures.
        encoded
            .trim_start_matches("{\"type\":\"text\",\"value\":")
            .trim_end_matches('}')
            .to_string()
    }
    format!(
        "{{{}}}",
        fields
            .into_iter()
            .map(|(key, value)| {
                let value = match value {
                    JsonVal::Null => "null".into(),
                    JsonVal::Str(s) => string(s),
                    JsonVal::Object(f) => encode(f),
                };
                format!("{}:{value}", string(key))
            })
            .collect::<Vec<_>>()
            .join(",")
    )
}
pub fn put(fields: &mut Object, key: &str, value: impl ToString) {
    fields.insert(key.into(), JsonVal::Str(value.to_string()));
}
fn quote(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "''"))
}
fn integer(n: u64) -> Result<u64> {
    if n > i64::MAX as u64 {
        Err(invalid("SQLite integer range"))
    } else {
        Ok(n)
    }
}
fn unhex(raw: &str) -> Result<String> {
    if !raw.is_ascii() || raw.len() % 2 != 0 {
        return Err(invalid("hex framing"));
    }
    let bytes = raw
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| (b as char).to_digit(16).ok_or_else(|| invalid("hex digit"));
            Ok((digit(pair[0])? * 16 + digit(pair[1])?) as u8)
        })
        .collect::<Result<Vec<_>>>()?;
    String::from_utf8(bytes).map_err(|_| invalid("UTF-8"))
}

impl Writer {
    pub fn identity(&self) -> Result<String> {
        let rows = self
            .0
            .exec_script("SELECT identity FROM storage_identity WHERE singleton=1;")?;
        match rows.as_slice() {
            [row] if row.len() == 1 => Ok(row[0].clone()),
            _ => Err(invalid("store identity")),
        }
    }
    /// A single SELECT gives one snapshot even against independently opened writers.
    /// Hex framing preserves pipes/newlines in raw evidence. Output is bounded by
    /// the existing execution family; overflow refuses the entire read.
    pub fn load(&self) -> Result<Image> {
        let rows = self.0.exec_script(&format!(
            "SELECT 'state',hex(response) FROM storage_receipts WHERE {STATE}
             UNION ALL SELECT 'row',hex(value_json) FROM observations
             UNION ALL SELECT 'pin',hex(json_object('id',pin_id,'generation',generation,'seq',CAST(seq AS TEXT),'expiry',CAST(expiry_ms AS TEXT),'admit',CAST(admit_seq AS TEXT))) FROM pins
             UNION ALL SELECT 'gap',hex(json_object('from',CAST(from_seq AS TEXT),'to',CAST(to_seq AS TEXT),'reason',reason)) FROM gaps;"))?;
        let mut image = Image::default();
        for row in rows {
            if row.len() != 2 {
                return Err(invalid("projection row shape"));
            }
            let raw = unhex(&row[1])?;
            match row[0].as_str() {
                "state" if image.state.is_none() => image.state = Some(raw),
                "row" => image.rows.push(raw),
                "pin" => {
                    let f = object(&raw)?;
                    image.pins.push(Pin {
                        id: text(&f, "id")?,
                        generation: text(&f, "generation")?,
                        seq: number(&f, "seq")?,
                        expiry_ms: signed(&f, "expiry")?,
                        admit_seq: number(&f, "admit")?,
                    });
                }
                "gap" => {
                    let f = object(&raw)?;
                    image.gaps.push(Gap {
                        from: number(&f, "from")?,
                        to: number(&f, "to")?,
                        reason: text(&f, "reason")?,
                    });
                }
                _ => return Err(invalid("projection discriminant")),
            }
        }
        if image.rows.len() > 32 || image.pins.len() > 8 || image.gaps.len() > 64 {
            return Err(invalid("projection exceeds fixture bounds"));
        }
        Ok(image)
    }
    /// Internal generated SQL only. Snapshot equality is checked inside the
    /// admitted writer lock, so independent handles cannot overspend budgets.
    pub fn prepare(&self, old: &Image, new: &Image) -> Result<Ticket> {
        let state = new.state.as_ref().ok_or_else(|| invalid("state missing"))?;
        let f = object(state)?;
        let revision = integer(number(&f, "revision")?)?;
        let previous = old.state.as_deref().map(object).transpose()?;
        let expected = previous
            .as_ref()
            .map(|f| number(f, "revision"))
            .transpose()?
            .unwrap_or(0);
        if expected.checked_add(1) != Some(revision) {
            return Err(invalid("revision must advance once"));
        }
        let scope = quote(&text(&f, "scope")?);
        let producer = quote(&text(&f, "producer")?);
        let condition = match &old.state {
            Some(raw) => format!("(SELECT response FROM storage_receipts WHERE {STATE})={}",quote(raw)),
            None => "NOT EXISTS(SELECT 1 FROM storage_receipts WHERE operation='obw:state') AND NOT EXISTS(SELECT 1 FROM observations) AND NOT EXISTS(SELECT 1 FROM pins) AND NOT EXISTS(SELECT 1 FROM gaps)".into(),
        };
        // One payload literal, not one full copy per projected column. Attempt
        // receipts include this body and share the existing finite stdin budget.
        let mut body = String::from("CREATE TEMP TABLE obw_payload(data TEXT);");
        // Pins first; retained pins remain in place. Referenced rows cannot be deleted.
        for pin in &old.pins {
            if !new.pins.contains(pin) {
                body.push_str(&format!(
                    "DELETE FROM pins WHERE pin_id={};",
                    quote(&pin.id)
                ));
            }
        }
        for raw in &old.rows {
            let seq = integer(number(&object(raw)?, "seq")?)?;
            if !new
                .rows
                .iter()
                .any(|r| object(r).and_then(|f| number(&f, "seq")).ok() == Some(seq))
            {
                body.push_str(&format!("DELETE FROM observations WHERE scope={scope} AND producer={producer} AND seq={seq};"));
            }
        }
        let mut payload_bytes = state.len();
        for raw in &new.rows {
            if old.rows.contains(raw) {
                continue;
            }
            let f = object(raw)?;
            integer(number(&f, "seq")?)?;
            payload_bytes = payload_bytes
                .checked_add(raw.len())
                .ok_or_else(|| invalid("payload overflow"))?;
            let p = quote(raw);
            body.push_str(&format!("DELETE FROM obw_payload; INSERT INTO obw_payload VALUES({p});
                INSERT INTO observations(scope,producer,generation,seq,binding_key,value_json,unit,source_ms,receipt_ms,ingestion_ms,receipt_mark,incarnation,suitability,created)
                SELECT {scope},{producer},json_extract(data,'$.generation'),CAST(json_extract(data,'$.seq') AS INTEGER),json_extract(data,'$.key'),data,json_extract(data,'$.unit'),CAST(json_extract(data,'$.source') AS INTEGER),CAST(json_extract(data,'$.receipt') AS INTEGER),CAST(json_extract(data,'$.ingestion') AS INTEGER),json_extract(data,'$.mark'),json_extract(data,'$.incarnation'),json_extract(data,'$.suitability'),{revision} FROM obw_payload WHERE 1
                ON CONFLICT(scope,producer,generation,seq) DO UPDATE SET value_json=excluded.value_json;"));
        }
        for pin in &new.pins {
            if old.pins.contains(pin) {
                continue;
            }
            body.push_str(&format!(
                "INSERT INTO pins VALUES({},{scope},{producer},{},{},{},{});",
                quote(&pin.id),
                quote(&pin.generation),
                integer(pin.seq)?,
                pin.expiry_ms,
                integer(pin.admit_seq)?
            ));
        }
        if new.gaps != old.gaps {
            body.push_str(&format!(
                "DELETE FROM gaps WHERE scope={scope} AND producer={producer};"
            ));
            for gap in &new.gaps {
                body.push_str(&format!(
                    "INSERT INTO gaps VALUES({scope},{producer},{},{},{});",
                    integer(gap.from)?,
                    integer(gap.to)?,
                    quote(&gap.reason)
                ));
            }
        }
        // Only this owner's finite attempt receipts are pruned, never outbox or
        // other owners' receipts. The durable revision guard survives their expiry.
        if revision > REPLAY_ROWS {
            body.push_str(&format!("DELETE FROM storage_receipts WHERE operation GLOB 'obw:ticket:[0-9]*' AND CAST(substr(operation,12) AS INTEGER)<={};",revision-REPLAY_ROWS));
        }
        body.push_str(&format!("INSERT INTO storage_receipts(operation,request,response) VALUES('obw:state','obw-state-v1',{}) ON CONFLICT(operation) DO UPDATE SET response=excluded.response;
            CREATE TEMP TABLE obw_result(id INTEGER PRIMARY KEY); INSERT INTO obw_result VALUES(1);",quote(state)));
        let op = OperationId::parse(&format!("obw:ticket:{revision}"))
            .map_err(|e| invalid(&e.to_string()))?;
        let mutation = self
            .0
            .prepare_guarded_batch(&condition, &body, payload_bytes)?
            .with_operation(op);
        let mut saved = Object::new();
        put(&mut saved, "store", self.identity()?);
        put(&mut saved, "revision", revision);
        put(&mut saved, "condition", condition);
        put(&mut saved, "body", body);
        put(&mut saved, "payload", payload_bytes);
        Ok(Ticket {
            mutation,
            revision,
            saved: encode(saved),
        })
    }
    pub fn submit(&self, ticket: &Ticket) -> MutationOutcome {
        self.retained_outcome(self.0.submit(&ticket.mutation), ticket.revision)
    }
    /// Absence after the replay horizon is NOT permission to submit fresh work.
    pub fn reconcile(&self, ticket: &Ticket) -> MutationOutcome {
        self.retained_outcome(self.0.reconcile(&ticket.mutation), ticket.revision)
    }
    fn retained_outcome(&self, outcome: MutationOutcome, revision: u64) -> MutationOutcome {
        let MutationOutcome::NotCommitted { operation, error } = outcome else {
            return outcome;
        };
        let horizon: Result<bool> = (|| {
            let image = self.load()?;
            let Some(state) = image.state else {
                return Ok(false);
            };
            let current = number(&object(&state)?, "revision")?;
            Ok(current < revision || current - revision < REPLAY_ROWS)
        })();
        match horizon {
            Ok(true) => MutationOutcome::NotCommitted { operation, error },
            Ok(false) => MutationOutcome::Unknown {
                operation,
                detail: "outside receipt replay horizon; absence cannot prove original noncommit"
                    .into(),
            },
            Err(error) => MutationOutcome::Unknown {
                operation,
                detail: format!("receipt retention unproved: {error}"),
            },
        }
    }
    /// Restored bytes only reconstruct the exact request for comparison. This
    /// method deliberately does NOT return a submit-capable PreparedMutation.
    pub fn reconcile_saved(&self, saved: &str) -> Result<MutationOutcome> {
        let f = object(saved)?;
        if text(&f, "store")? != self.identity()? {
            return Err(invalid("receipt store mismatch"));
        }
        let revision = integer(number(&f, "revision")?)?;
        let op = OperationId::parse(&format!("obw:ticket:{revision}"))
            .map_err(|e| invalid(&e.to_string()))?;
        let payload =
            usize::try_from(number(&f, "payload")?).map_err(|_| invalid("receipt payload"))?;
        let ticket = self
            .0
            .prepare_guarded_batch(&text(&f, "condition")?, &text(&f, "body")?, payload)?
            .with_operation(op);
        Ok(self.retained_outcome(self.0.reconcile(&ticket), revision))
    }
}
