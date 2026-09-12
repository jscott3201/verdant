use crate::{access, binding, domain, native, seal, storage};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "verdant-pr11-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::create_dir(dir.join("native")).unwrap();
        Self(dir)
    }
    pub fn db(&self) -> PathBuf {
        self.0.join("meaning.db")
    }
    pub fn native(&self) -> PathBuf {
        self.0.join("native")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

pub struct Fixture {
    pub gate: access::AccessGate,
    pub credentials: access::BootstrapCredentials,
    pub registry: binding::BindingRegistry,
    pub native: native::NativeHandle,
    pub seals: seal::SealStore,
    pub reference: seal::NativeRef,
    pub finding: seal::RowKey,
    pub scratch: Scratch,
}
pub fn scope() -> domain::scope::TrustedScope {
    domain::scope::TrustedScope::parse("scope-a").unwrap()
}
pub fn operation(raw: &str) -> domain::ids::OperationId {
    domain::ids::OperationId::parse(raw).unwrap()
}
pub fn row(raw: &str, seq: u64) -> seal::RowKey {
    seal::RowKey::new(operation(raw), seq).unwrap()
}
impl Fixture {
    pub fn new() -> Self {
        Self::with_status(binding::BindingStatus::Valid)
    }
    pub fn with_status(status: binding::BindingStatus) -> Self {
        let scratch = Scratch::new();
        let (gate, credentials) = access::AccessGate::bootstrap(
            &scratch.db(),
            storage::ConnectionSettings::local_wal_full(),
            storage::StoreBounds::tiny(),
            &access::Reason::parse("PR11 synthetic fixture").unwrap(),
        )
        .unwrap();
        let mut registry = binding::BindingRegistry::open(
            &scratch.db(),
            storage::ConnectionSettings::local_wal_full(),
            storage::StoreBounds::tiny(),
        )
        .unwrap();
        registry
            .record_equipment(
                "ahu-1",
                binding::EquipmentKind::Ahu,
                scope(),
                "AHU",
                "mstp://ahu-1",
            )
            .unwrap();
        registry
            .record_point(
                "ahu-1",
                "supply-air-temp",
                scope(),
                "degC",
                binding::EndpointClass::Location,
            )
            .unwrap();
        let binding = binding::ProposedBinding::from_import(
            binding::EndpointAddress::parse("mstp://ahu-1").unwrap(),
            binding::EndpointClass::Location,
            scope(),
            domain::ids::InstalledId::parse("ahu-1").unwrap(),
            binding::PropertyName::parse("supply-air-temp").unwrap(),
            scope(),
            domain::ids::InstalledId::parse("sensor-sat-1").unwrap(),
            domain::values::Unit::parse("degC").unwrap(),
            None,
            binding::BindingRole::Sense,
            binding::BindingRole::Sense,
            binding::Feedback::Absent,
            status,
        );
        let pending = binding::PendingProposal::new(
            operation("fixture-proposal"),
            registry.revision(),
            binding.clone(),
        );
        registry
            .submit_proposal(&gate, Some(&credentials.publisher), &pending)
            .unwrap();
        registry
            .emit_finding_operation(
                &operation("fixture-finding"),
                registry.revision(),
                &gate,
                &binding,
                &credentials.publisher,
            )
            .unwrap();
        let seq = registry
            .store()
            .exec_script("SELECT seq FROM outbox WHERE operation='binding-finding';")
            .unwrap()[0][0]
            .parse()
            .unwrap();
        let finding = row(binding::OP_FINDING_TEXT, seq);
        let (native, _) =
            native::NativeHandle::create(&scratch.native(), native::NativeSettings::local())
                .unwrap();
        native.execute("INSERT (:Reading {seq: 1})").unwrap();
        let seals =
            seal::SealStore::open(registry.store().try_clone().unwrap(), native.clone()).unwrap();
        let reference = seal::NativeRef::capture(&native, seals.hash_tool()).unwrap();
        Self {
            gate,
            credentials,
            registry,
            native,
            seals,
            reference,
            finding,
            scratch,
        }
    }
    pub fn draft(&self) -> seal::Draft {
        self.draft_with(vec![self.finding.clone()], "verdant-test-binary@5382387")
    }
    pub fn draft_with(&self, roots: Vec<seal::RowKey>, binary: &str) -> seal::Draft {
        seal::Draft::new(
            self.registry.revision(),
            scope(),
            seal::RuntimeRef::new(binary, "synthetic-macos-arm64-debug").unwrap(),
            roots,
            vec![self.reference.clone()],
        )
        .unwrap()
    }
    pub fn seal(&mut self, op: &str, draft: &seal::Draft) -> seal::Result<seal::SealCommit> {
        self.seals.seal(
            &operation(op),
            draft,
            &mut self.registry,
            &self.gate,
            &self.credentials.publisher,
        )
    }
    pub fn content(&self, op: &str, payload: &str, children: Vec<seal::RowKey>) -> seal::RowKey {
        self.registry
            .store()
            .insert(
                &operation(op),
                &domain::ids::InstalledId::parse("ahu-1").unwrap(),
                &domain::ids::InstalledId::parse("sensor-sat-1").unwrap(),
                &seal::ContentNode::new(payload.into(), children)
                    .unwrap()
                    .value(),
                &domain::values::Unit::parse("count").unwrap(),
                binding::synthetic_times(),
                &binding::synthetic_record(1),
            )
            .unwrap();
        row(op, 1)
    }
    pub fn seal_rows(&self) -> Vec<Vec<String>> {
        self.registry.store().exec_script("SELECT id,seq,value_json FROM outbox WHERE operation='seal-revision-v1' ORDER BY id;").unwrap()
    }
    pub fn release(&mut self, op: &str, id: &seal::Digest) -> seal::Result<()> {
        self.seals.release(
            &operation(op),
            id,
            &mut self.registry,
            &self.gate,
            &self.credentials.publisher,
        )
    }
}
