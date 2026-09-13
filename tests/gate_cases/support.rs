use crate::{accept, access, api, binding, bytes, domain, native, query, seal, storage, Scratch, Setup};
use std::path::Path;
use std::process::{Command, Output, Stdio};

pub const DRAFT: &str = "api-m01-gate-draft";
pub const SEAL: &str = "api-m01-gate-seal";
pub const ACCEPT: &str = "api-m01-gate-accept";
pub const ACTIVATE: &str = "api-m01-gate-activate";
pub const AUTHOR: &str = "capability=m01-gate-publisher;scope=scope-a;capgen=1;issuer=bootstrap-issuer-1";
pub const SECRET: &str = "synthetic-m01-gate-setup";
pub const GRAPH: &str = "MATCH (r:Reading) WHERE r.id = 'm01-gate-reading' AND r.seq = 1 RETURN r";
pub const TABLES: &str = "SELECT * FROM outbox ORDER BY id; \
    SELECT * FROM storage_receipts ORDER BY operation; \
    SELECT * FROM derived_marks ORDER BY entity;";

pub fn scope() -> domain::scope::TrustedScope {
    domain::scope::TrustedScope::parse("scope-a").unwrap()
}
pub fn op(raw: &str) -> domain::ids::OperationId {
    domain::ids::OperationId::parse(raw).unwrap()
}
pub fn credential() -> access::Credential {
    access::Credential::new(
        access::CapabilityName::parse("m01-gate-publisher").unwrap(),
        access::KeyId::parse("m01-gate-key").unwrap(),
        access::SyntheticKey::parse(SECRET).unwrap(),
    )
}
pub fn all() -> api::PageRequest {
    api::PageRequest::new(0, 64).unwrap()
}

impl Setup {
    pub fn api(&mut self) -> api::Api<'_> {
        api::Api::new(&self.gate, &mut self.registry, &self.seals).unwrap()
    }
    pub fn close(self) -> (Scratch, u64) {
        let Self { scratch, gate, credential, registry, native, seals, content, sequence } = self;
        drop(content);
        drop(credential);
        drop(seals);
        drop(registry);
        drop(gate);
        drop(native.close());
        {
            use std::fs::{OpenOptions, TryLockError};
            use std::time::{Duration, Instant};
            // All fixture native owners are dropped. Synchronize on the actual
            // writer LOCK, not a fixed delay or a retried product operation.
            let native_path = scratch.0.join("native");
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .open(native_path.join("LOCK"))
                .expect("existing writer LOCK");
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match lock.try_lock() {
                    Ok(()) => break,
                    Err(TryLockError::WouldBlock) => {
                        assert!(
                            Instant::now() < deadline,
                            "writer LOCK not released: {}",
                            native_path.display()
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(TryLockError::Error(error)) => panic!("writer LOCK probe failed: {error}"),
                }
            }
            lock.unlock().expect("release synchronization lock");
        }
        (scratch, sequence)
    }
}

pub struct Owners {
    pub gate: access::AccessGate,
    pub registry: binding::BindingRegistry,
    pub native: native::NativeHandle,
    pub seals: seal::SealStore,
}
impl Owners {
    pub fn open(root: &Path) -> Self {
        let gate = access::AccessGate::open(
            &root.join("meaning.db"), storage::ConnectionSettings::local_wal_full(),
            storage::StoreBounds::tiny(),
        ).unwrap();
        let registry = binding::BindingRegistry::open(
            &root.join("meaning.db"), storage::ConnectionSettings::local_wal_full(),
            storage::StoreBounds::tiny(),
        ).unwrap();
        let (native, _) = native::NativeHandle::open(
            &root.join("native"), native::NativeSettings::local(),
        ).unwrap();
        let seals = seal::SealStore::open(registry.store().try_clone().unwrap(), native.clone()).unwrap();
        Self { gate, registry, native, seals }
    }
    pub fn api(&mut self) -> api::Api<'_> {
        api::Api::new(&self.gate, &mut self.registry, &self.seals).unwrap()
    }
    pub fn accepted(&self) -> accept::AcceptanceStore {
        accept::AcceptanceStore::new(self.registry.store().try_clone().unwrap())
    }
    pub fn close(self) {
        let Self { gate, registry, native, seals } = self;
        let native_path = native.dir().to_path_buf();
        drop(seals);
        drop(registry);
        drop(gate);
        drop(native.close());
        {
            use std::fs::{OpenOptions, TryLockError};
            use std::time::{Duration, Instant};
            // All fixture native owners are dropped. Synchronize on the actual
            // writer LOCK, not a fixed delay or a retried product operation.
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .open(native_path.join("LOCK"))
                .expect("existing writer LOCK");
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match lock.try_lock() {
                    Ok(()) => break,
                    Err(TryLockError::WouldBlock) => {
                        assert!(
                            Instant::now() < deadline,
                            "writer LOCK not released: {}",
                            native_path.display()
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(TryLockError::Error(error)) => panic!("writer LOCK probe failed: {error}"),
                }
            }
            lock.unlock().expect("release synchronization lock");
        }
    }
}

pub fn config(root: &Scratch) -> std::path::PathBuf {
    let config = root.0.join("site.conf");
    std::fs::write(&config, format!(
        "role = \"standalone\"\ndurable_path = \"{}\"\nsecret_env = \"M01_GATE_SECRET\"\n",
        root.0.display(),
    )).unwrap();
    config
}
pub fn cli(root: &Scratch, verb: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_verdant"))
        .args([verb, "--config"]).arg(config(root))
        .args(["--scope", "scope-a", "--capability", "m01-gate-publisher", "--key-id", "m01-gate-key"])
        .args(args).env("HOME", &root.0).env("M01_GATE_SECRET", SECRET)
        .stdin(Stdio::null()).output().unwrap()
}
pub fn clean(output: Output) -> String {
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

/// Complete small fixture artifacts, including names; never omit missing files
/// or silently turn I/O failures into None. No generated/native internals parsed.
pub fn native_bytes(root: &Scratch) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn visit(root: &Path, dir: &Path, result: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() { visit(root, &path, result); }
            else {
                assert!(kind.is_file(), "unexpected fixture artifact: {}", path.display());
                result.insert(path.strip_prefix(root).unwrap().to_owned(), std::fs::read(path).unwrap());
            }
        }
    }
    let mut result = std::collections::BTreeMap::new();
    visit(&root.0, &root.0.join("native"), &mut result);
    assert!(!result.is_empty());
    result
}

#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub rows: String,
    pub bytes: Vec<(&'static str, Option<Vec<u8>>)>,
    pub counts: [u64; 3],
    pub events: [u64; 4],
}
fn numbers<const N: usize>(text: String) -> [u64; N] {
    text.trim().split('|').map(|v| v.parse().unwrap()).collect::<Vec<_>>().try_into().unwrap()
}
impl Snapshot {
    pub fn take(root: &Scratch) -> Self {
        let rows = query(root, TABLES);
        let counts = numbers(query(root, "SELECT (SELECT count(*) FROM outbox), \
            (SELECT count(*) FROM storage_receipts),(SELECT count(*) FROM derived_marks);"));
        let events = numbers(query(root, "SELECT \
            (SELECT count(*) FROM outbox WHERE operation='api-intent-v1'), \
            (SELECT count(*) FROM outbox WHERE operation='seal-revision-v1'), \
            (SELECT count(*) FROM outbox WHERE operation='accept-revision-v1'), \
            (SELECT count(*) FROM outbox WHERE operation='accept-active-v1');"));
        Self { rows, bytes: bytes(&root.0), counts, events }
    }
    pub fn unchanged(&self, root: &Scratch, leg: &str) {
        let after = Self::take(root);
        // Do not log access rows (synthetic key fingerprints).
        assert!(self.rows == after.rows, "{leg}: rows changed");
        assert!(self.bytes == after.bytes, "{leg}: main/WAL/SHM changed");
        assert_eq!(self.counts, after.counts, "{leg}");
        assert_eq!(self.events, after.events, "{leg}");
        after.report(leg);
    }
    pub fn appended(&self, root: &Scratch, leg: &str, rows: u64, events: [u64; 4]) -> Self {
        let after = Self::take(root);
        assert_eq!(after.counts, [self.counts[0] + rows, self.counts[1] + rows, self.counts[2]], "{leg}");
        assert_eq!(after.events, events, "{leg}");
        assert!(self.bytes != after.bytes, "{leg}: committed bytes must differ");
        // Existing rows/receipts/marks are immutable, regardless of append order.
        for old in self.rows.lines() {
            assert!(after.rows.lines().any(|row| row == old), "{leg}: prior row lost/changed");
        }
        after.report(leg);
        after
    }
    pub fn report(&self, leg: &str) {
        println!("M01_G leg={leg} rows|receipts|marks={:?} intent|seal|accept|active={:?} sqlite_bytes={:?}",
            self.counts, self.events, self.bytes.iter().map(|(n, b)| (*n, b.as_ref().map(Vec::len))).collect::<Vec<_>>());
    }
}
