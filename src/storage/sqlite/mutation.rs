//! Receipts bind an attempt identity to its exact request and result, in the
//! same transaction as the mutation. Business operation duplicates remain
//! additive. Keep a PreparedMutation across retries; never turn UNKNOWN into
//! fresh work. Receipts are retained indefinitely (no pruning contract yet).
use super::*;
use super::admission::scalar;
use super::connection::{failure, Connection};
use std::sync::atomic::AtomicBool;

pub(super) fn next_sequence() -> u64 {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    SEQUENCE.fetch_add(1, Ordering::SeqCst)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Shape { Insert, Rows, Change }

/// Immutable request ticket. Clone/persist the operation identity before
/// dispatch; resubmitting this ticket replays its receipt, not its effects.
#[derive(Debug, Clone)]
pub struct PreparedMutation {
    operation: OperationId,
    store: String,
    body: String,
    shape: Shape,
    pub(super) payload_bytes: usize,
    attempted: Arc<AtomicBool>,
}

impl PreparedMutation {
    pub fn operation(&self) -> &OperationId { &self.operation }

    /// Reconstruct a safe typed request after restart using the SAME persisted
    /// attempt ID. Different arguments under that ID conflict, never overwrite.
    pub fn with_operation(mut self, operation: OperationId) -> Self {
        self.operation = operation;
        self.attempted = Arc::new(AtomicBool::new(true));
        self
    }

    pub(super) fn new(store: &SqliteStore, body: &str, shape: Shape) -> Result<Self, StorageError> {
        let id = format!("storage-{}-{}-{}", std::process::id(), epoch_nanos_now(), next_sequence());
        let operation = OperationId::parse(&id).map_err(|e| failure(&e.to_string()))?;
        Ok(Self { operation, store: store.inner.identity.clone(), body: body.into(), shape, payload_bytes: 0, attempted: Arc::new(AtomicBool::new(false)) })
    }

    fn request(&self) -> String { hex(format!("{:?}:{}:{}", self.shape, self.store, self.body).as_bytes()) }
}

/// Noncommit is known only before COMMIT dispatch, with the owning process
/// reaped, or after a successful writer-barrier receipt lookup. A failed
/// reconciliation is UNKNOWN, never evidence that the operation did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationOutcome {
    Committed { operation: OperationId, rows: Vec<Vec<String>> },
    NotCommitted { operation: OperationId, error: StorageError },
    Conflict { operation: OperationId, detail: String },
    Unknown { operation: OperationId, detail: String },
}

impl MutationOutcome {
    pub(super) fn into_result(self) -> Result<Vec<Vec<String>>, StorageError> {
        match self {
            Self::Committed { rows, .. } => Ok(rows),
            Self::NotCommitted { error, .. } => Err(error),
            Self::Conflict { detail, .. } => Err(StorageError::Conflict { detail }),
            Self::Unknown { operation, detail } => Err(failure(&format!(
                "UNKNOWN outcome for {}; reconcile that identity, do not retry as new work: {detail}", operation.as_str()))),
        }
    }
}

impl SqliteStore {
    /// Dispatch or idempotently reconcile the exact ticket. A reused identity
    /// with different request bytes conflicts before any mutation.
    pub fn submit(&self, pending: &PreparedMutation) -> MutationOutcome {
        let operation = pending.operation.clone();
        let retried = pending.attempted.swap(true, Ordering::SeqCst);
        if pending.store != self.inner.identity {
            return MutationOutcome::Conflict { operation, detail: "request belongs to a different store".into() };
        }
        let mut conn = match self.admitted(true) {
            Ok(conn) => conn,
            Err(error) if retried => return MutationOutcome::Unknown { operation, detail: error.to_string() },
            Err(error) => return MutationOutcome::NotCommitted { operation, error },
        };
        let mut absent = false;
        let staged = (|| {
            if let Some((request, response)) = receipt(&mut conn, &operation)? {
                if request != pending.request() { return Err(StorageError::Conflict { detail: "operation identity reused with different request".into() }); }
                let rows = decode_response(&response)?;
                validate_rows(pending.shape, &rows)?;
                return Ok((false, rows));
            }
            absent = true; // Writer barrier proves no prior receipt.
            if pending.shape == Shape::Insert {
                if pending.payload_bytes > self.inner.bounds.max_value_bytes {
                    return Err(StorageError::ValueTooLarge { len: pending.payload_bytes, max: self.inner.bounds.max_value_bytes });
                }
                if let Some(detail) = self.maintenance_reason() { return Err(StorageError::MaintenanceRequired { detail }); }
                // Admission/space preconditions are rechecked while owning the
                // writer lock. This remains a synthetic budget, not disk-full proof.
                if self.db_size_bytes().saturating_add(pending.payload_bytes as u64) > self.inner.bounds.max_db_bytes {
                    return Err(StorageError::SpaceExhausted { detail: "synthetic writer-admission space budget".into() });
                }
            }
            let rows = conn.exchange(&pending.body)?;
            validate_rows(pending.shape, &rows)?;
            let response = encode_response(&rows);
            conn.exchange(&format!("INSERT INTO storage_receipts(operation, request, response) VALUES ({}, {}, {});",
                sql_quote(operation.as_str()), sql_quote(&pending.request()), sql_quote(&response)))?;
            Ok((true, rows))
        })();
        match staged {
            Ok((false, rows)) => outcome(pending.shape, operation, rows),
            Ok((true, rows)) => {
                #[cfg(test)] if super::faults::before_commit(self.db_path()) {
                    drop(conn); // observed process teardown, entire staged batch rolled back
                    return MutationOutcome::NotCommitted { operation, error: failure("injected precommit interruption") };
                }
                let committed = conn.commit();
                #[cfg(test)] let committed = super::faults::commit_response(self.db_path(), committed);
                drop(conn);
                match committed {
                    Ok(()) => outcome(pending.shape, operation, rows),
                    Err(error) => MutationOutcome::Unknown { operation, detail: error.to_string() },
                }
            }
            Err(error) => {
                drop(conn); // Kill/reap before asserting known noncommit.
                match error {
                    StorageError::Conflict { detail } => MutationOutcome::Conflict { operation, detail },
                    error if !absent => MutationOutcome::Unknown { operation, detail: error.to_string() },
                    error => MutationOutcome::NotCommitted { operation, error },
                }
            }
        }
    }

    /// Read-only reconciliation under a writer barrier. Absence is a known
    /// noncommit at this barrier, not permission for a still-running caller
    /// to dispatch different work. Stop/join dispatchers before deciding.
    pub fn reconcile(&self, pending: &PreparedMutation) -> MutationOutcome {
        let operation = pending.operation.clone();
        let result = (|| {
            let mut conn = self.admitted(true)?;
            receipt(&mut conn, &operation)
        })();
        match result {
            Ok(Some((request, response))) if request == pending.request() && pending.store == self.inner.identity => {
                match decode_response(&response).and_then(|rows| { validate_rows(pending.shape, &rows)?; Ok(rows) }) {
                    Ok(rows) => outcome(pending.shape, operation, rows),
                    Err(error) => MutationOutcome::Unknown { operation, detail: error.to_string() },
                }
            }
            Ok(Some(_)) => MutationOutcome::Conflict { operation, detail: "operation identity/request mismatch".into() },
            Ok(None) if pending.store == self.inner.identity => MutationOutcome::NotCommitted { operation, error: failure("no receipt at writer barrier") },
            Ok(None) => MutationOutcome::Conflict { operation, detail: "request belongs to a different store".into() },
            Err(error) => MutationOutcome::Unknown { operation, detail: error.to_string() },
        }
    }

    /// Legacy callers can recover the operation ID reported by an UNKNOWN
    /// error. This looks up evidence only; it never dispatches another attempt.
    pub fn reconcile_operation(&self, operation: &OperationId) -> MutationOutcome {
        let result = (|| {
            let mut conn = self.admitted(true)?;
            receipt(&mut conn, operation)
        })();
        let operation = operation.clone();
        match result {
            Ok(Some((request, response))) => {
                let decoded = (|| {
                    let request = unhex(&request)?;
                    let (shape, rest) = request.split_once(':').ok_or_else(|| failure("receipt request framing"))?;
                    let (store, _) = rest.split_once(':').ok_or_else(|| failure("receipt store framing"))?;
                    if store != self.inner.identity { return Err(failure("receipt store identity mismatch")); }
                    let shape = match shape { "Insert" => Shape::Insert, "Rows" => Shape::Rows, "Change" => Shape::Change, _ => return Err(failure("receipt kind unknown")) };
                    let rows = decode_response(&response)?;
                    validate_rows(shape, &rows)?;
                    Ok((shape, rows))
                })();
                match decoded {
                    Ok((shape, rows)) => outcome(shape, operation, rows),
                    Err(error) => MutationOutcome::Unknown { operation, detail: error.to_string() },
                }
            }
            Ok(None) => MutationOutcome::NotCommitted { operation, error: failure("no receipt at writer barrier") },
            Err(error) => MutationOutcome::Unknown { operation, detail: error.to_string() },
        }
    }

    pub(super) fn exec_mutation(&self, body: &str, shape: Shape) -> Result<VerifiedOutput, StorageError> {
        let pending = PreparedMutation::new(self, body, shape)?;
        let rows = self.submit(&pending).into_result()?;
        Ok(VerifiedOutput { verified: VerifiedSettings {
            generation: SCHEMA_GENERATION,
            journal_size_limit_bytes: self.inner.settings.journal_size_limit_bytes,
        }, body_rows: rows })
    }
}

fn receipt(conn: &mut Connection, operation: &OperationId) -> Result<Option<(String, String)>, StorageError> {
    let rows = conn.exchange(&format!("SELECT request, response FROM storage_receipts WHERE operation={};", sql_quote(operation.as_str())))?;
    match rows.as_slice() {
        [] => Ok(None),
        [row] if row.len() == 2 => Ok(Some((row[0].clone(), row[1].clone()))),
        _ => Err(failure("malformed receipt")),
    }
}

fn outcome(shape: Shape, operation: OperationId, rows: Vec<Vec<String>>) -> MutationOutcome {
    if shape == Shape::Change && rows == vec![vec!["0".to_string()]] {
        MutationOutcome::Conflict { operation, detail: "zero affected rows (claim owner/state or entity mismatch)".into() }
    } else { MutationOutcome::Committed { operation, rows } }
}

fn validate_rows(shape: Shape, rows: &[Vec<String>]) -> Result<(), StorageError> {
    match shape {
        Shape::Insert => {
            if rows.len() != 2 || scalar(vec![rows[0].clone()])?.parse::<i64>().ok().filter(|n| *n > 0).is_none()
                || rows[1] != vec!["1".to_string()] { return Err(failure("malformed insert response")); }
        }
        Shape::Rows => { for row in rows { decode_row(row)?; } }
        Shape::Change => {
            let value = scalar(rows.to_vec())?;
            if value != "0" && value != "1" { return Err(failure("malformed changes response")); }
        }
    }
    Ok(())
}

pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes { let _ = write!(out, "{byte:02X}"); }
    out
}

fn unhex(raw: &str) -> Result<String, StorageError> {
    if raw.len() % 2 != 0 || !raw.is_ascii() { return Err(failure("malformed receipt hex")); }
    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().chunks_exact(2) {
        let digit = |b: u8| (b as char).to_digit(16).ok_or_else(|| failure("malformed receipt hex"));
        bytes.push((digit(pair[0])? * 16 + digit(pair[1])?) as u8);
    }
    String::from_utf8(bytes).map_err(|_| failure("malformed receipt UTF-8"))
}

fn encode_response(rows: &[Vec<String>]) -> String {
    // Each column hex-encoded independently; separators cannot occur in hex.
    rows.iter().map(|row| row.iter().map(|cell| hex(cell.as_bytes())).collect::<Vec<_>>().join(",")).collect::<Vec<_>>().join(";")
}

fn decode_response(response: &str) -> Result<Vec<Vec<String>>, StorageError> {
    if response.is_empty() { return Ok(Vec::new()); }
    response.split(';').map(|row| row.split(',').map(unhex).collect()).collect()
}
