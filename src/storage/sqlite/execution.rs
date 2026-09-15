//! One RAII operation spans admission retries and one held CLI at a time.
//! Three joined pipe pumps prevent stdin/stdout/stderr deadlock. Each reader
//! uses 4096 bytes and the shared event queue holds two chunks: at most 16 KiB
//! of read-ahead beyond accepted output. There is no unbounded line reader.
//! Drop is cancellation, not graceful commit. Only the trusted sqlite3 child
//! is owned; this is not a process-tree sandbox or a child-heap/CPU quota.
use super::*;
use std::io::{self, Read, Write};
use std::process::{Child, ExitStatus};
use std::sync::{mpsc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub(super) struct ExecutionState {
    running: AtomicU32,
    refused: AtomicU64,
    spawned: AtomicU64,
    reaped: AtomicU64,
    input_bytes: AtomicU64,
    output_bytes: AtomicU64,
}

/// Live family counters, not a globally atomic snapshot or cross-open quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionReport {
    /// Admitted operations, including lock-retry pauses and child teardown.
    pub running: u32,
    /// Capacity refusals only (all occurred before spawn).
    pub refused: u64,
    pub spawned: u64,
    /// Children for which wait returned a status, once per owned child.
    pub reaped: u64,
    /// Fully written and flushed scripts; partial failed writes are excluded.
    pub input_bytes: u64,
    /// Controller-observed stdout + stderr, including the first over-cap chunk.
    /// Bounded pump read-ahead discarded on cancellation is excluded.
    pub output_bytes: u64,
}

impl ExecutionState {
    pub(super) fn report(&self) -> ExecutionReport {
        ExecutionReport {
            running: self.running.load(Ordering::SeqCst),
            refused: self.refused.load(Ordering::SeqCst),
            spawned: self.spawned.load(Ordering::SeqCst),
            reaped: self.reaped.load(Ordering::SeqCst),
            input_bytes: self.input_bytes.load(Ordering::SeqCst),
            output_bytes: self.output_bytes.load(Ordering::SeqCst),
        }
    }
}

#[derive(Default)]
struct Usage { input: usize, output: usize, rows: usize }

pub(super) struct Operation {
    state: Arc<ExecutionState>,
    bounds: StoreBounds,
    deadline: Instant,
    timeout_ms: u64,
    usage: Mutex<Usage>,
}

impl Operation {
    pub(super) fn start(state: Arc<ExecutionState>, settings: &ConnectionSettings, bounds: &StoreBounds) -> Result<Arc<Self>, StorageError> {
        if bounds.max_input_bytes == 0 || bounds.max_output_bytes == 0 || bounds.max_output_rows == 0
            || bounds.max_replay_rows == 0 || settings.operation_timeout_ms == 0 {
            return Err(StorageError::InvalidInput { what: "execution bounds", detail: "byte, row, replay and wall budgets must be positive".into() });
        }
        let deadline = Instant::now().checked_add(Duration::from_millis(settings.operation_timeout_ms))
            .ok_or_else(|| StorageError::InvalidInput { what: "operation deadline", detail: "duration is not representable".into() })?;
        if state.running.fetch_update(Ordering::SeqCst, Ordering::SeqCst,
            |n| (n < bounds.max_running_operations).then(|| n + 1)).is_err() {
            state.refused.fetch_add(1, Ordering::SeqCst);
            return Err(StorageError::TooManyRunningOperations { max: bounds.max_running_operations });
        }
        Ok(Arc::new(Self { state, bounds: bounds.clone(), deadline, timeout_ms: settings.operation_timeout_ms, usage: Mutex::new(Usage::default()) }))
    }

    pub(super) fn standalone(settings: &ConnectionSettings, bounds: &StoreBounds) -> Result<Arc<Self>, StorageError> {
        Self::start(Arc::new(ExecutionState::default()), settings, bounds)
    }

    pub(super) fn remaining(&self) -> Result<Duration, StorageError> {
        self.deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
            .ok_or(StorageError::DeadlineExceeded { timeout_ms: self.timeout_ms })
    }

    pub(super) fn pause(&self, duration: Duration) -> Result<(), StorageError> {
        std::thread::sleep(duration.min(self.remaining()?));
        self.remaining().map(|_| ())
    }

    pub(super) fn check_input(&self, len: usize) -> Result<(), StorageError> {
        self.remaining()?;
        if len > self.bounds.max_input_bytes {
            return Err(StorageError::ExecutionLimit { resource: "input bytes", max: self.bounds.max_input_bytes });
        }
        Ok(())
    }

    fn charge(&self, resource: &'static str, bytes: usize) -> Result<(), StorageError> {
        self.remaining()?;
        let mut usage = self.usage.lock().map_err(|_| connection::failure("execution usage poisoned"))?;
        let (used, max) = match resource {
            "input bytes" => (&mut usage.input, self.bounds.max_input_bytes),
            "output bytes" => (&mut usage.output, self.bounds.max_output_bytes),
            "output rows" => (&mut usage.rows, self.bounds.max_output_rows),
            _ => return Err(connection::failure("unknown execution resource")),
        };
        if bytes > max.saturating_sub(*used) { return Err(StorageError::ExecutionLimit { resource, max }); }
        *used += bytes;
        Ok(())
    }
}

impl Drop for Operation {
    fn drop(&mut self) { self.state.running.fetch_sub(1, Ordering::SeqCst); }
}

enum Event { Stdout(Vec<u8>), Stderr(Vec<u8>), End(bool), Written(usize), Io(io::Error) }

pub(super) struct Process {
    child: Child,
    input: Option<mpsc::SyncSender<Vec<u8>>>,
    events: Option<mpsc::Receiver<Event>>,
    workers: Vec<JoinHandle<()>>,
    operation: Arc<Operation>,
    path: PathBuf,
    stderr: Vec<u8>,
    pending: Vec<u8>,
    stdout_end: bool,
    stderr_end: bool,
    writing: bool,
    finished: bool,
}

impl Process {
    #[cfg(test)]
    pub(super) fn id(&self) -> u32 { self.child.id() }

    pub(super) fn spawn(mut command: Command, path: &Path, operation: Arc<Operation>) -> Result<Self, StorageError> {
        operation.remaining()?;
        #[cfg(test)] super::faults::record_spawn_attempt();
        let child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
            .map_err(|e| if e.kind() == io::ErrorKind::NotFound { StorageError::MissingSqlite { detail: e.to_string() } }
                else { admission::io_error(path, e) })?;
        operation.state.spawned.fetch_add(1, Ordering::SeqCst);
        let mut process = Self { child, input: None, events: None, workers: Vec::new(), operation, path: path.into(),
            stderr: Vec::new(), pending: Vec::new(), stdout_end: false, stderr_end: false, writing: false, finished: false };
        let (send, recv) = mpsc::sync_channel(2);
        process.events = Some(recv);
        let mut stdin = process.child.stdin.take().ok_or_else(|| connection::failure("missing child stdin"))?;
        let stdout = process.child.stdout.take().ok_or_else(|| connection::failure("missing child stdout"))?;
        let stderr = process.child.stderr.take().ok_or_else(|| connection::failure("missing child stderr"))?;
        let (input, scripts) = mpsc::sync_channel::<Vec<u8>>(1);
        process.input = Some(input);
        let written = send.clone();
        process.workers.push(std::thread::Builder::new().name("sqlite-stdin".into()).spawn(move || {
            while let Ok(bytes) = scripts.recv() {
                let result = stdin.write_all(&bytes).and_then(|()| stdin.flush());
                let failed = result.is_err();
                let event = match result { Ok(()) => Event::Written(bytes.len()), Err(e) => Event::Io(e) };
                if written.send(event).is_err() || failed { break; }
            }
        }).map_err(|e| admission::io_error(path, e))?);
        for (pipe, is_stdout) in [(Box::new(stdout) as Box<dyn Read + Send>, true), (Box::new(stderr), false)] {
            let send = send.clone();
            process.workers.push(std::thread::Builder::new().name("sqlite-output".into()).spawn(move || pump(pipe, send, is_stdout))
                .map_err(|e| admission::io_error(path, e))?);
        }
        Ok(process)
    }

    fn enqueue(&mut self, parts: &[&str]) -> Result<(), StorageError> {
        let len = parts.iter().try_fold(0usize, |n, s| n.checked_add(s.len()))
            .ok_or(StorageError::ExecutionLimit { resource: "input bytes", max: self.operation.bounds.max_input_bytes })?;
        self.operation.charge("input bytes", len)?;
        let mut bytes = Vec::with_capacity(len);
        for part in parts { bytes.extend_from_slice(part.as_bytes()); }
        self.input.as_ref().ok_or_else(|| admission::io_error(&self.path, io::Error::new(io::ErrorKind::BrokenPipe, "closed sqlite stdin")))?
            .try_send(bytes).map_err(|e| admission::io_error(&self.path, io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())))?;
        self.writing = true;
        Ok(())
    }

    fn event(&mut self) -> Result<(), StorageError> {
        let remaining = self.operation.remaining()?;
        let event = self.events.as_ref().ok_or_else(|| connection::failure("cancelled CLI"))?
            .recv_timeout(remaining).map_err(|e| match e {
                mpsc::RecvTimeoutError::Timeout => StorageError::DeadlineExceeded { timeout_ms: self.operation.timeout_ms },
                mpsc::RecvTimeoutError::Disconnected => connection::failure("CLI pumps disconnected"),
            })?;
        match event {
            Event::Stdout(bytes) => {
                self.operation.state.output_bytes.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                self.operation.charge("output bytes", bytes.len())?;
                self.operation.charge("output rows", bytes.iter().filter(|b| **b == b'\n').count())?;
                self.pending.extend_from_slice(&bytes);
            }
            Event::Stderr(bytes) => {
                self.operation.state.output_bytes.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                self.operation.charge("output bytes", bytes.len())?;
                self.stderr.extend_from_slice(&bytes);
            }
            Event::End(stdout) => if stdout {
                if self.pending.last().is_some_and(|b| *b != b'\n') {
                    self.operation.charge("output rows", 1)?;
                }
                self.stdout_end = true;
            } else { self.stderr_end = true; },
            Event::Written(bytes) => {
                self.operation.state.input_bytes.fetch_add(bytes as u64, Ordering::SeqCst);
                self.writing = false;
            }
            Event::Io(error) => return Err(admission::io_error(&self.path, error)),
        }
        Ok(())
    }

    pub(super) fn exchange(&mut self, sql: &str) -> Result<Vec<Vec<String>>, StorageError> {
        let result = self.exchange_inner(sql);
        if result.is_err() { self.cancel(); }
        result
    }

    fn exchange_inner(&mut self, sql: &str) -> Result<Vec<Vec<String>>, StorageError> {
        self.enqueue(&[sql, "\n.print ", SENT_END, "\n"])?;
        let mut rows = Vec::new();
        let mut ended = false;
        let mut scanned = 0; // A long partial line is scanned once, not per chunk.
        loop {
            self.operation.remaining()?;
            let mut consumed = 0;
            for (index, byte) in self.pending.iter().enumerate().skip(scanned) {
                if *byte != b'\n' { continue; }
                let line = std::str::from_utf8(&self.pending[consumed..index])
                    .map_err(|_| connection::failure("CLI stdout is not UTF-8"))?.trim_end_matches('\r');
                if line == SENT_END { ended = true; }
                else if ended { return Err(connection::failure("unexpected output after response marker")); }
                else { rows.push(line.split(COL_SEP).map(str::to_owned).collect()); }
                consumed = index + 1;
            }
            scanned = self.pending.len() - consumed;
            self.pending.drain(..consumed);
            if ended && !self.writing { return Ok(rows); }
            if self.stdout_end && self.stderr_end && !self.writing {
                let status = self.exit()?;
                return Err(connection::failure(&format!("CLI exited {status}: {}", String::from_utf8_lossy(&self.stderr))));
            }
            self.event()?;
        }
    }

    pub(super) fn collect(&mut self, parts: &[&str]) -> Result<Output, StorageError> {
        let result = (|| {
            self.enqueue(parts)?;
            self.input.take(); // Writer owns any submitted buffer until EOF.
            while !(self.stdout_end && self.stderr_end && !self.writing) { self.event()?; }
            let status = self.exit()?;
            Ok(Output { status, stdout: std::mem::take(&mut self.pending), stderr: std::mem::take(&mut self.stderr) })
        })();
        if result.is_err() { self.cancel(); }
        result
    }

    pub(super) fn finish(&mut self) -> Result<ExitStatus, StorageError> {
        self.input.take();
        let result = (|| {
            while !(self.stdout_end && self.stderr_end && !self.writing) { self.event()?; }
            self.exit()
        })();
        if result.is_err() { self.cancel(); }
        result
    }

    fn exit(&mut self) -> Result<ExitStatus, StorageError> {
        loop {
            self.operation.remaining()?;
            if let Some(status) = self.child.try_wait().map_err(|e| admission::io_error(&self.path, e))? {
                return Ok(status);
            }
            self.operation.pause(Duration::from_millis(1))?;
        }
    }

    fn cancel(&mut self) {
        if self.finished { return; }
        let _ = self.child.kill();
        // Reap even after stdin errors or successful try_wait. Interrupted wait
        // is retried; cleanup is observed, never inferred from a timer.
        loop {
            match self.child.wait() {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(_) => { self.operation.state.reaped.fetch_add(1, Ordering::SeqCst); break; }
                Err(_) => break,
            }
        }
        self.input.take();
        self.events.take(); // Unblocks reader/writer sends before joining.
        for worker in self.workers.drain(..) { let _ = worker.join(); }
        self.finished = true;
    }
}

impl Drop for Process { fn drop(&mut self) { self.cancel(); } }

fn pump(mut pipe: Box<dyn Read + Send>, send: mpsc::SyncSender<Event>, stdout: bool) {
    let mut buffer = [0u8; 4096];
    loop {
        let event = match pipe.read(&mut buffer) {
            Ok(0) => { let _ = send.send(Event::End(stdout)); break; }
            Ok(n) if stdout => Event::Stdout(buffer[..n].to_vec()),
            Ok(n) => Event::Stderr(buffer[..n].to_vec()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => { let _ = send.send(Event::Io(e)); break; }
        };
        if send.send(event).is_err() { break; }
    }
}

pub(super) fn run_script(db_path: &Path, extra_args: &[&str], script: &str, operation: Arc<Operation>) -> Result<Output, StorageError> {
    // R03 executable/flags unchanged: no -noinit/-ifexists on SQLite 3.50.x.
    let io_path = if db_path == Path::new(":memory:") { db_path.to_path_buf() }
        else { connection::canonical_parent_path(db_path)? };
    let mut command = Command::new("sqlite3");
    command.args(["-batch", "-nofollow"]).args(extra_args).arg(&io_path);
    let mut process = Process::spawn(command, db_path, operation)?;
    let mut output = process.collect(&[".bail on\n", script, "\n"])?;
    output.stderr = String::from_utf8_lossy(&output.stderr)
        .replace(io_path.to_string_lossy().as_ref(), db_path.to_string_lossy().as_ref()).into_bytes();
    Ok(output)
}
