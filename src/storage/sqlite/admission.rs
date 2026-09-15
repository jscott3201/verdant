//! Fresh creation is private + no-clobber publication; open never repairs.
//! The trusted, owner-writable parent is a filesystem boundary: privileged
//! same-UID replacement of files while SQLite owns locks is not supported.
use super::*;
use super::connection::{failure, Connection};
use super::execution::{ExecutionState, Operation};
use std::fs::{self, OpenOptions};
use std::sync::OnceLock;

const NOTE_1: &str = "M01-PR03 0001_init: initial tiny outbox";
const NOTE_2: &str = "R03 0002_receipts: admission and reconciliation";
const NOTE_3: &str = "M02-PR03B 0003_observations: finite window and custody";
const NOTE_4: &str = "M02-PR06 0004_action_journal: durable admission and per-target state";
// Complete ordered schema, one framed result: additive tables must not spend
// the existing consumers' per-operation row budget before their bounded read.
// No objects/DDL bytes are omitted; execution byte limits still apply in full.
const OBJECTS: &str = "SELECT hex(json_group_array(json_array(type,name,tbl_name,coalesce(sql,'')))) FROM (SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name);";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FileStamp {
    device: u64,
    inode: u64,
    owner: u32,
}

#[cfg(unix)]
pub(super) fn file_stamp(path: &Path) -> Result<FileStamp, StorageError> {
    use std::os::unix::fs::MetadataExt as _;
    let mut meta = fs::symlink_metadata(path).map_err(|e| io_error(path, e))?;
    // No-clobber hard-link publication has a brief two-link interval before
    // the private name is removed. Wait boundedly; never admit a durable alias.
    for _ in 0..BUSY_RETRIES {
        if meta.nlink() != 2 { break; }
        std::thread::sleep(std::time::Duration::from_millis(BUSY_RETRY_PAUSE_MS));
        meta = fs::symlink_metadata(path).map_err(|e| io_error(path, e))?;
    }
    if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o022 != 0 {
        return Err(failure("database must be a regular, single-link, owner-writable-only file"));
    }
    Ok(FileStamp { device: meta.dev(), inode: meta.ino(), owner: meta.uid() })
}

#[cfg(not(unix))]
pub(super) fn file_stamp(_path: &Path) -> Result<FileStamp, StorageError> {
    Err(failure("file-identity admission is not qualified on this platform"))
}

pub(super) fn io_error(path: &Path, error: std::io::Error) -> StorageError {
    StorageError::Io { path: path.display().to_string(), message: error.to_string() }
}

fn validate_settings(settings: &ConnectionSettings) -> Result<(), StorageError> {
    if settings.journal_mode != "wal" || settings.synchronous_level != "2"
        || settings.foreign_keys != "1" || settings.busy_timeout_ms > i32::MAX as u32
        || settings.journal_size_limit_bytes > i64::MAX as u64
    {
        return Err(StorageError::DurabilityUnavailable { detail: "only WAL/FULL/FK with representable limits is supported".into() });
    }
    Ok(())
}

fn parent_path(path: &Path) -> Result<PathBuf, StorageError> {
    let parent = path.parent().filter(|p| p.is_dir()).ok_or_else(|| StorageError::UnwritablePath {
        path: path.display().to_string(), reason: "parent directory is missing (never created implicitly)".into(),
    })?;
    if parent_permissions_readonly(parent) {
        return Err(StorageError::ReadOnlyPath { path: path.display().to_string() });
    }
    if path.is_dir() {
        return Err(StorageError::UnwritablePath { path: path.display().to_string(), reason: "database path is a directory".into() });
    }
    // Refuse before even the owner probe, version probe or reference CLI runs.
    super::connection::refuse_leaf_symlink(path)?;
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt as _;
        let meta = fs::metadata(parent).map_err(|e| io_error(path, e))?;
        #[cfg(test)] super::faults::record_spawn_attempt();
        let uid = Command::new("id").arg("-u").output().map_err(|e| io_error(path, e))?;
        let uid = String::from_utf8_lossy(&uid.stdout).trim().parse::<u32>()
            .map_err(|_| failure("cannot establish process owner"))?;
        if meta.uid() != uid || meta.mode() & 0o022 != 0 {
            return Err(failure("database parent must be owned by this process user and not group/world writable"));
        }
        if fs::symlink_metadata(path).is_ok() && file_stamp(path)?.owner != uid {
            return Err(failure("database owner differs from process owner"));
        }
    }
    path.file_name().ok_or_else(|| failure("database filename missing"))?;
    Ok(path.to_path_buf())
}

type Objects = Vec<Vec<String>>;
fn reference_objects() -> Result<&'static (Objects, Objects, Objects, Objects), StorageError> {
    static OBJECT_CACHE: OnceLock<Result<(Objects, Objects, Objects, Objects), StorageError>> = OnceLock::new();
    OBJECT_CACHE.get_or_init(|| {
        let script = format!("{}\n{OBJECTS}\nSELECT 'NEXT';\n{}\n{OBJECTS}\nSELECT 'NEXT';\n{}\n{OBJECTS}\nSELECT 'NEXT';\n{}\n{OBJECTS}", super::super::MIGRATION_0001_SQL, super::super::MIGRATION_0002_SQL, super::super::MIGRATION_0003_SQL, super::super::MIGRATION_0004_SQL);
        let output = run_script_stdin(Path::new(":memory:"), &["-separator", "|"], &script)?;
        if !output.status.success() { return Err(failure("reference schema construction failed")); }
        let text = String::from_utf8(output.stdout).map_err(|_| failure("reference schema encoding"))?;
        let (old, rest) = text.split_once("NEXT\n").ok_or_else(|| failure("reference schema framing"))?;
        let (middle, rest) = rest.split_once("NEXT\n").ok_or_else(|| failure("reference schema 0003 framing"))?;
        let (new3, new4) = rest.split_once("NEXT\n").ok_or_else(|| failure("reference schema 0004 framing"))?;
        let rows = |text: &str| text.lines().map(|l| l.split('|').map(str::to_owned).collect()).collect();
        Ok((rows(old), rows(middle), rows(new3), rows(new4)))
    }).as_ref().map_err(Clone::clone)
}

pub(super) fn scalar(rows: Vec<Vec<String>>) -> Result<String, StorageError> {
    if rows.len() != 1 || rows[0].len() != 1 { return Err(failure("expected exactly one scalar")); }
    Ok(rows[0][0].clone())
}

/// Returns None only for exactly supported 0001/0002 predecessors. Both 0003
/// and writer-gated 0004 are valid currents (fresh open stays at 0003 until
/// the M02-PR06 writer ensure applies 0004). No DDL here.
pub(super) fn validate(conn: &mut Connection) -> Result<Option<String>, StorageError> {
    let generation = scalar(conn.exchange("PRAGMA user_version;")?)?;
    if generation != SCHEMA_GENERATION.to_string() {
        return Err(StorageError::SchemaMismatch { expected: SCHEMA_GENERATION, found: generation });
    }
    let objects = conn.exchange(OBJECTS)?;
    let (old, middle, new3, new4) = reference_objects()?;
    if objects != *old && objects != *middle && objects != *new3 && objects != *new4 { return Err(failure("schema objects differ; refusing without repair")); }
    let ledger = conn.exchange("SELECT generation, hex(applied_note) FROM schema_migrations ORDER BY generation;")?;
    let note = |n: u32, s: &str| vec![n.to_string(), super::mutation::hex(s.as_bytes())];
    let app = scalar(conn.exchange("PRAGMA application_id;")?)?;
    if objects == *old && ledger == vec![note(1, NOTE_1)] && app == "0" { return Ok(None); }
    let predecessor = objects == *middle && ledger == vec![note(1, NOTE_1), note(2, NOTE_2)];
    let current3 = objects == *new3 && ledger == vec![note(1, NOTE_1), note(2, NOTE_2), note(3, NOTE_3)];
    let current4 = objects == *new4 && ledger == vec![note(1, NOTE_1), note(2, NOTE_2), note(3, NOTE_3), note(4, NOTE_4)];
    if (!predecessor && !current3 && !current4) || app != "1447383636" {
        return Err(StorageError::SchemaMismatch { expected: SCHEMA_GENERATION, found: "unsupported migration ledger/application identity".into() });
    }
    let identity = scalar(conn.exchange("SELECT identity FROM storage_identity WHERE singleton=1;")?)?;
    if identity.len() != 64 || !identity.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(failure("invalid store identity"));
    }
    Ok(if predecessor { None } else { Some(identity) })
}

pub(super) fn open(path: &Path, settings: ConnectionSettings, bounds: StoreBounds) -> Result<(SqliteStore, OpenReport), StorageError> {
    validate_settings(&settings)?;
    let path = parent_path(path)?;
    let version = sqlite_version(&settings, &bounds)?;
    // Populate the immutable reference before holding a database child. The
    // bounded fixture never adds a second child to an admitted store operation.
    // Reference construction uses fixed internal bounds, not caller budgets:
    // a small open budget must not poison the process-wide reference cache.
    reference_objects()?;
    if fs::symlink_metadata(&path).is_ok() {
        return existing(&path, settings, bounds, version);
    }
    let private = PrivateFile::new(&path)?;
    let (identity, report) = initialize(&private.0, &settings, &bounds, &version)
        .map_err(|e| private.public_error(&path, e))?;
    #[cfg(test)] super::faults::before_publish(&path)?;
    match fs::hard_link(&private.0, &path) {
        Ok(()) => {
            fs::remove_file(&private.0).map_err(|e| io_error(&path, e))?;
            let store = make_store(&path, settings, bounds, version, identity)?;
            let (file_mode, file_uid) = db_file_identity(&path);
            Ok((store, OpenReport { fresh: true, store: report, file_mode, file_uid }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => existing(&path, settings, bounds, version),
        Err(e) => Err(io_error(&path, e)),
    }
}

fn initialize(path: &Path, settings: &ConnectionSettings, bounds: &StoreBounds, version: &str) -> Result<(String, StoreReport), StorageError> {
    let mut conn = Connection::open(path, Operation::standalone(settings, bounds)?)?;
    conn.configure(settings)?;
    conn.exchange("PRAGMA journal_mode=WAL; BEGIN IMMEDIATE;")?;
    conn.exchange(&format!("{}\nPRAGMA user_version=1; INSERT INTO schema_migrations VALUES (1, {});\n{}\n{}",
        super::super::MIGRATION_0001_SQL, sql_quote(NOTE_1), super::super::MIGRATION_0002_SQL, super::super::MIGRATION_0003_SQL))?;
    let identity = validate(&mut conn)?.ok_or_else(|| failure("bootstrap revision missing"))?;
    conn.verify_settings(settings)?;
    conn.commit().map_err(|e| failure(&format!("private bootstrap failed, not published: {e}")))?;
    drop(conn);
    let store = make_store(path, settings.clone(), bounds.clone(), version.to_owned(), identity.clone())?;
    let report = store.report()?; // Validate everything before the publication point.
    drop(store);
    Ok((identity, report))
}

fn existing(path: &Path, settings: ConnectionSettings, bounds: StoreBounds, version: String) -> Result<(SqliteStore, OpenReport), StorageError> {
    let stamp = file_stamp(path)?;
    let mut conn = Connection::open(path, Operation::standalone(&settings, &bounds)?)?;
    conn.configure(&settings)?;
    // A read snapshot first: invalid stores are refused before writer admission
    // (including before enabling WAL). BEGIN IMMEDIATE revalidates below.
    conn.exchange("BEGIN;")?;
    validate(&mut conn)?;
    conn.verify_settings(&settings)?;
    conn.exchange("ROLLBACK; BEGIN IMMEDIATE;")?;
    let identity = match validate(&mut conn)? {
        Some(identity) => identity,
        None => {
            if file_stamp(path)? != stamp { return Err(failure("file replaced during upgrade admission")); }
            if scalar(conn.exchange("SELECT count(*) FROM schema_migrations;")?)? == "1" {
                conn.exchange(super::super::MIGRATION_0002_SQL)?;
            }
            conn.exchange(super::super::MIGRATION_0003_SQL)?;
            validate(&mut conn)?.ok_or_else(|| failure("upgrade identity missing"))?
        }
    };
    conn.verify_settings(&settings)?;
    if file_stamp(path)? != stamp { return Err(failure("file replaced during open")); }
    conn.commit().map_err(|e| failure(&format!("upgrade/open outcome unknown; reopen to validate ledger: {e}")))?;
    drop(conn);
    let store = make_store(path, settings, bounds, version, identity)?;
    let report = store.report()?;
    let (file_mode, file_uid) = db_file_identity(path);
    Ok((store, OpenReport { fresh: false, store: report, file_mode, file_uid }))
}

fn make_store(path: &Path, settings: ConnectionSettings, bounds: StoreBounds, sqlite_version: String, identity: String) -> Result<SqliteStore, StorageError> {
    Ok(SqliteStore { inner: Arc::new(Inner {
        db_path: path.to_path_buf(), settings, bounds, sqlite_version, identity,
        file_stamp: file_stamp(path)?, handles: AtomicU32::new(1),
        execution: Arc::new(ExecutionState::default()),
        last_checkpoint_epoch_secs: AtomicU64::new(0),
    }) })
}

struct PrivateFile(PathBuf);
impl PrivateFile {
    fn new(path: &Path) -> Result<Self, StorageError> {
        let private = path.with_file_name(format!(".verdant-bootstrap-{}-{}-{}", std::process::id(), epoch_nanos_now(), super::mutation::next_sequence()));
        Self::reserve(path, private)
    }

    fn reserve(path: &Path, private: PathBuf) -> Result<Self, StorageError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options.open(&private).map_err(|e| io_error(path, e))?;
        Ok(Self(private))
    }

    fn public_error(&self, path: &Path, error: StorageError) -> StorageError {
        // Connection already maps its canonical OS path back to the private
        // name. Bootstrap errors must then identify the requested database,
        // not the unpublished implementation detail (including nested errors).
        match error {
            StorageError::SqliteFailure { detail } => failure(&detail.replace(self.0.to_string_lossy().as_ref(), path.to_string_lossy().as_ref())),
            StorageError::Io { message, .. } => StorageError::Io { path: path.display().to_string(), message },
            other => other,
        }
    }
}
impl Drop for PrivateFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(wal_path(&self.0));
        let mut shm = self.0.as_os_str().to_owned();
        shm.push("-shm");
        let _ = fs::remove_file(PathBuf::from(shm));
    }
}

#[cfg(all(test, unix))]
#[path = "probe_tests.rs"]
mod probe_tests;

impl SqliteStore {
    pub(super) fn admitted(&self, writer: bool) -> Result<Connection, StorageError> {
        let operation = self.operation()?;
        for attempt in 0..=BUSY_RETRIES {
            match self.admit_once(writer, Arc::clone(&operation)) {
                Err(StorageError::SqliteFailure { detail }) if is_busy_text(&detail) => {
                    if attempt == BUSY_RETRIES { return Err(StorageError::Busy { detail }); }
                    operation.pause(std::time::Duration::from_millis(BUSY_RETRY_PAUSE_MS))?;
                }
                result => return result,
            }
        }
        Err(failure("admission retries exhausted"))
    }

    fn admit_once(&self, writer: bool, operation: Arc<Operation>) -> Result<Connection, StorageError> {
        operation.remaining()?;
        if file_stamp(self.db_path())? != self.inner.file_stamp { return Err(failure("database file identity changed")); }
        #[cfg(test)] super::faults::before_admission(self.db_path());
        let mut conn = Connection::open(self.db_path(), operation)?;
        conn.configure(&self.inner.settings)?;
        conn.exchange(if writer { "BEGIN IMMEDIATE;" } else { "BEGIN;" })?;
        if validate(&mut conn)?.as_deref() != Some(self.inner.identity.as_str()) {
            return Err(failure("store identity/revision changed; reopen required"));
        }
        conn.verify_settings(&self.inner.settings)?;
        // Already WAL, so setting it in this owning transaction cannot convert
        // an unrelated file or race a check on a different connection.
        conn.exchange("PRAGMA journal_mode=WAL;")?;
        if file_stamp(self.db_path())? != self.inner.file_stamp { return Err(failure("database replaced during admission")); }
        Ok(conn)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, DirBuilderExt as _, PermissionsExt as _};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("verdant-io-path-{}-{}-{}", std::process::id(), epoch_nanos_now(), super::super::mutation::next_sequence()));
            fs::DirBuilder::new().mode(0o700).create(&path).expect("scratch");
            let path = path.canonicalize().expect("physical scratch");
            fs::create_dir(path.join("real")).expect("real parent");
            symlink(path.join("real"), path.join("public")).expect("parent alias");
            Self(path)
        }
        fn db(&self) -> PathBuf { self.0.join("public/store.db") }
        fn open(&self) -> Result<(SqliteStore, OpenReport), StorageError> {
            open(&self.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny())
        }
        fn entries(&self) -> Vec<std::ffi::OsString> {
            let mut names = fs::read_dir(self.0.join("real")).expect("entries")
                .map(|entry| entry.expect("entry").file_name()).collect::<Vec<_>>();
            names.sort();
            names
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) { fs::remove_dir_all(&self.0).expect("cleanup scratch"); }
    }

    #[test]
    fn io_path_parent_alias_bootstraps_and_reopens_with_public_identity() {
        let scratch = Scratch::new();
        let (store, report) = scratch.open().expect("bootstrap through parent alias");
        assert!(report.fresh);
        assert_eq!(store.db_path(), scratch.db());
        assert_ne!(store.db_path(), scratch.db().canonicalize().expect("physical file"));
        assert_eq!(store.exec_script("BEGIN; SELECT 1; ROLLBACK;").expect("stdin driver through parent alias"), vec![vec!["1".to_string()]]);
        let request = store.prepare_claim(1, "path-test").expect("prepare");
        assert!(matches!(store.submit(&request), MutationOutcome::Committed { rows, .. } if rows.is_empty()));
        drop(store);
        let (store, report) = scratch.open().expect("reopen through parent alias");
        assert!(!report.fresh);
        assert_eq!(store.db_path(), scratch.db());
        assert_eq!(report.store, store.report().expect("public store report"));
        drop(store);
        let names = scratch.entries();
        assert!(names.contains(&std::ffi::OsString::from("store.db")), "{names:?}");
        // WAL sidecars can outlive the CLI connection; no other artifacts may.
        assert!(names.iter().all(|name| matches!(name.to_str(), Some("store.db" | "store.db-shm" | "store.db-wal"))), "unexpected artifacts: {names:?}");
    }

    #[test]
    fn io_path_leaf_symlinks_still_refuse_without_touching_targets() {
        let scratch = Scratch::new();
        let initial_spawns = super::super::faults::spawn_attempts();
        drop(scratch.open().expect("target"));
        assert!(super::super::faults::spawn_attempts() > initial_spawns, "spawn observer must see valid opens");
        let target = scratch.0.join("real/store.db");
        let before = fs::read(&target).expect("target bytes");
        for name in ["store.db", "absent.db"] {
            let leaf = scratch.0.join("public/leaf.db");
            symlink(scratch.0.join("real").join(name), &leaf).expect("leaf alias");
            let entries = scratch.entries();
            let spawns = super::super::faults::spawn_attempts();
            let error = open(&leaf, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).unwrap_err();
            assert_eq!(error.code(), "sqlite-failure");
            assert_eq!(super::super::faults::spawn_attempts(), spawns, "admission must refuse before any child");
            let detail = error.to_string();
            assert!(detail.contains(leaf.to_str().expect("public path")), "{detail}");
            assert!(!detail.contains(scratch.0.join("real/leaf.db").to_str().expect("OS path")), "{detail}");
            // Lower-level callers must also refuse before spawn, not at exchange.
            let error = Connection::open(&leaf, Operation::standalone(&ConnectionSettings::local_wal_full(), &StoreBounds::tiny()).expect("budget")).err().expect("leaf refusal before connection");
            assert_eq!(error.code(), "sqlite-failure");
            assert_eq!(super::super::faults::spawn_attempts(), spawns, "connection must refuse before spawn");
            let detail = error.to_string();
            assert!(detail.contains(leaf.to_str().expect("public path")), "{detail}");
            assert!(!detail.contains(scratch.0.join("real/leaf.db").to_str().expect("OS path")), "{detail}");
            let error = run_script_stdin(&leaf, &[], "SELECT 1;").unwrap_err();
            assert_eq!(error.code(), "sqlite-failure");
            assert_eq!(super::super::faults::spawn_attempts(), spawns, "stdin driver must refuse before spawn");
            let detail = error.to_string();
            assert!(detail.contains(leaf.to_str().expect("public path")), "{detail}");
            assert!(!detail.contains(scratch.0.join("real/leaf.db").to_str().expect("OS path")), "{detail}");
            assert_eq!(fs::read(&target).expect("unchanged target"), before);
            assert_eq!(scratch.entries(), entries);
            assert!(!scratch.0.join("real/absent.db").exists());
            assert!(fs::symlink_metadata(&leaf).expect("leaf remains").is_symlink());
            fs::remove_file(leaf).expect("remove fixture link");
        }
    }

    #[test]
    fn io_path_bootstrap_and_resolution_errors_use_only_public_path() {
        let scratch = Scratch::new();
        let path = scratch.db();
        let private = PrivateFile::new(&path).expect("reserve bootstrap file");
        assert!(private.0.is_file());
        fs::remove_file(&private.0).expect("simulate lost private file");
        let error = initialize(&private.0, &ConnectionSettings::local_wal_full(), &StoreBounds::tiny(), "fixture")
            .map_err(|e| private.public_error(&path, e)).unwrap_err();
        assert!(matches!(&error, StorageError::Io { path: reported, .. } if reported == &path.display().to_string()));
        let detail = error.to_string();
        assert!(detail.contains(path.to_str().expect("public path")), "{detail}");
        assert!(!detail.contains(".verdant-bootstrap-"), "{detail}");
        assert!(!detail.contains(scratch.0.join("real").to_str().expect("physical parent")), "{detail}");
        assert!(scratch.entries().is_empty());
        assert!(!path.exists(), "Rust admission must not recreate a lost file");
        let missing = scratch.0.join("public/missing/store.db");
        let error = Connection::open(&missing, Operation::standalone(&ConnectionSettings::local_wal_full(), &StoreBounds::tiny()).expect("budget")).err().expect("missing parent refusal");
        assert!(matches!(error, StorageError::Io { path, .. } if path == missing.display().to_string()));
        let error = run_script_stdin(&missing, &[], "SELECT 1;").unwrap_err();
        assert!(matches!(error, StorageError::Io { path, .. } if path == missing.display().to_string()));
    }

    #[test]
    fn io_path_permission_refusals_preserve_files_and_public_path() {
        let scratch = Scratch::new();
        let parent = scratch.0.join("real");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o555)).expect("read-only parent");
        let refused = scratch.open();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).expect("restore parent");
        assert!(matches!(refused.unwrap_err(), StorageError::ReadOnlyPath { path } if path == scratch.db().display().to_string()));
        assert!(scratch.entries().is_empty());
        fs::write(scratch.db(), b"foreign bytes").expect("foreign file");
        fs::set_permissions(scratch.db(), fs::Permissions::from_mode(0o666)).expect("unsafe file permissions");
        let entries = scratch.entries();
        assert_eq!(scratch.open().unwrap_err().code(), "sqlite-failure");
        assert_eq!(fs::read(scratch.db()).expect("unchanged foreign file"), b"foreign bytes");
        assert_eq!(fs::metadata(scratch.db()).expect("mode").permissions().mode() & 0o777, 0o666);
        assert_eq!(scratch.entries(), entries);
    }
}
