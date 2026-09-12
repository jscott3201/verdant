//! A held CLI connection. Admission and mutations never cross connections.
//! Before COMMIT is sent, dropping this owner kills/reaps the child and rolls
//! back. After sending COMMIT, transport failure is an UNKNOWN outcome.
use super::*;
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdin, ChildStdout};

pub(super) fn canonical_parent_path(path: &Path) -> Result<PathBuf, StorageError> {
    // SQLite's -nofollow rejects symlinked ancestors too (e.g. macOS
    // /var -> /private/var). Resolve only the parent, NEVER the leaf:
    // -nofollow must still refuse a leaf replaced after file admission.
    let parent = path.parent().ok_or_else(|| failure("database parent missing"))?;
    let leaf = path.file_name().ok_or_else(|| failure("database filename missing"))?;
    Ok(parent.canonicalize().map_err(|e| super::admission::io_error(path, e))?.join(leaf))
}

pub(super) struct Connection {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    public_path: PathBuf,
    io_path: PathBuf,
}

impl Connection {
    pub(super) fn open(path: &Path) -> Result<Self, StorageError> {
        let io_path = canonical_parent_path(path)?;
        let mut child = Command::new("sqlite3")
            .args(["-batch", "-bail", "-noinit", "-nofollow", "-ifexists", "-list", "-noheader", "-separator"])
            .arg(COL_SEP.to_string())
            .arg(&io_path)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().map_err(|e| StorageError::MissingSqlite { detail: e.to_string() })?;
        let input = child.stdin.take();
        let output = match child.stdout.take() {
            Some(output) => BufReader::new(output),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(failure("missing child stdout"));
            }
        };
        Ok(Self { child, input, output, public_path: path.to_path_buf(), io_path })
    }

    pub(super) fn exchange(&mut self, sql: &str) -> Result<Vec<Vec<String>>, StorageError> {
        self.send(&format!("{sql}\n.print {SENT_END}\n"))?;
        let mut rows = Vec::new();
        loop {
            let mut line = String::new();
            let count = self.output.read_line(&mut line)
                .map_err(|e| failure(&format!("response read: {e}")))?;
            if count == 0 {
                let status = self.child.wait().map_err(|e| failure(&e.to_string()))?;
                let mut stderr = String::new();
                if let Some(mut pipe) = self.child.stderr.take() {
                    use std::io::Read as _;
                    let _ = pipe.read_to_string(&mut stderr);
                }
                let stderr = stderr.replace(self.io_path.to_string_lossy().as_ref(), self.public_path.to_string_lossy().as_ref());
                return Err(failure(&format!("CLI exited {status}: {stderr}")));
            }
            let line = line.trim_end_matches(['\n', '\r']);
            if line == SENT_END { return Ok(rows); }
            rows.push(line.split(COL_SEP).map(str::to_owned).collect());
        }
    }

    fn send(&mut self, script: &str) -> Result<(), StorageError> {
        let input = self.input.as_mut().ok_or_else(|| failure("closed child stdin"))?;
        input.write_all(script.as_bytes()).and_then(|()| input.flush())
            .map_err(|e| failure(&format!("request write: {e}")))
    }

    /// Success requires both a COMMIT reply and an observed zero exit.
    pub(super) fn commit(&mut self) -> Result<(), StorageError> {
        let rows = self.exchange("COMMIT;")?;
        if !rows.is_empty() { return Err(failure("malformed commit response")); }
        self.input.take();
        let status = self.child.wait().map_err(|e| failure(&e.to_string()))?;
        if status.success() { Ok(()) } else { Err(failure(&format!("commit exit {status}"))) }
    }

    pub(super) fn configure(&mut self, settings: &ConnectionSettings) -> Result<(), StorageError> {
        // Connection-local setup occurs before BEGIN. The persistent journal
        // mode is never changed on an unvalidated existing file.
        self.exchange(&format!("PRAGMA busy_timeout={}; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA journal_size_limit={};",
            settings.busy_timeout_ms, settings.journal_size_limit_bytes))?;
        Ok(())
    }

    pub(super) fn verify_settings(&mut self, settings: &ConnectionSettings) -> Result<(), StorageError> {
        let rows = self.exchange(&format!("SELECT '{SENT_BEGIN}'; PRAGMA user_version; PRAGMA journal_mode; PRAGMA synchronous; PRAGMA foreign_keys; PRAGMA busy_timeout; PRAGMA journal_size_limit; SELECT '{SENT_DATA}';"))?;
        let mut text = rows.iter().map(|r| r.join(&COL_SEP.to_string())).collect::<Vec<_>>().join("\n");
        text.push_str(&format!("\n{SENT_END}\n"));
        parse_envelope(&text, settings)?;
        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(super) fn failure(detail: &str) -> StorageError {
    StorageError::SqliteFailure { detail: detail.to_string() }
}
