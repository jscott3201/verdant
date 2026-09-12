//! A held CLI connection. Admission and mutations never cross connections.
//! Before COMMIT is sent, dropping this owner kills/reaps the child and rolls
//! back. After sending COMMIT, transport failure is an UNKNOWN outcome.
use super::*;
use super::execution::{Operation, Process};

pub(super) fn canonical_parent_path(path: &Path) -> Result<PathBuf, StorageError> {
    // Resolve only the parent (macOS /var is an alias), never the leaf.
    let parent = path.parent().ok_or_else(|| failure("database parent missing"))?;
    let leaf = path.file_name().ok_or_else(|| failure("database filename missing"))?;
    Ok(parent.canonicalize().map_err(|e| super::admission::io_error(path, e))?.join(leaf))
}

pub(super) struct Connection {
    process: Process,
    public_path: PathBuf,
    io_path: PathBuf,
}

impl Connection {
    pub(super) fn open(path: &Path, operation: Arc<Operation>) -> Result<Self, StorageError> {
        operation.remaining()?;
        let io_path = canonical_parent_path(path)?;
        // R03 policy frozen: Rust checks existence; -nofollow guards the leaf.
        // No -ifexists/-noinit in 3.50.x; controlled HOME is a prerequisite.
        std::fs::symlink_metadata(path).map_err(|e| super::admission::io_error(path, e))?;
        let mut command = Command::new("sqlite3");
        command.args(["-batch", "-bail", "-nofollow", "-list", "-noheader", "-separator"])
            .arg(COL_SEP.to_string()).arg(&io_path);
        let process = Process::spawn(command, path, operation)?;
        Ok(Self { process, public_path: path.to_path_buf(), io_path })
    }

    pub(super) fn exchange(&mut self, sql: &str) -> Result<Vec<Vec<String>>, StorageError> {
        self.process.exchange(sql).map_err(|error| match error {
            StorageError::SqliteFailure { detail } => failure(&detail.replace(self.io_path.to_string_lossy().as_ref(), self.public_path.to_string_lossy().as_ref())),
            other => other,
        })
    }

    /// Success requires both a COMMIT reply and an observed zero exit. R03
    /// labels any failure here UNKNOWN and reconciles the same receipt ID.
    pub(super) fn commit(&mut self) -> Result<(), StorageError> {
        let rows = self.exchange("COMMIT;")?;
        if !rows.is_empty() { return Err(failure("malformed commit response")); }
        #[cfg(test)] super::execution_tests::after_commit_reply(&mut self.process)?;
        let status = self.process.finish()?;
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

pub(super) fn failure(detail: &str) -> StorageError {
    StorageError::SqliteFailure { detail: detail.to_string() }
}
