//! M02-PR06 durable admission and per-target state, SYNTHETIC-ONLY.
#![allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "../src/storage/mod.rs"]
mod storage;
#[path = "../src/access/mod.rs"]
mod access;
#[path = "../src/native/mod.rs"]
mod native;
#[path = "../src/seal/mod.rs"]
mod seal;
#[path = "../src/accept/mod.rs"]
mod accept;
#[path = "../src/api/mod.rs"]
mod api;
#[path = "../src/binding/mod.rs"]
mod binding;
#[path = "../src/runtime/mod.rs"]
mod runtime;
#[path = "../src/observation/mod.rs"]
mod observation;
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[path = "../src/action_preview/mod.rs"]
mod action_preview;
#[path = "../src/action_journal/mod.rs"]
mod action_journal;

use access::RoleKind;
use action_journal::{Journal, JournalReceivers};
use action_preview::{Precondition, Preview, SealOrder};
use domain::ids::{BindingRevision, InstalledId, OperationId};
use domain::scope::TrustedScope;
use domain::values::Unit;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use storage::{ConnectionSettings, StoreBounds};

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "verdant-m02-pr06-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&dir).expect("isolated scratch");
        Self(dir)
    }
    fn db(&self) -> PathBuf {
        self.0.join("store.db")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("cleanup scratch");
    }
}
fn open_journal(scratch: &Scratch) -> (Journal, JournalReceivers) {
    Journal::open(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .expect("writer open")
}
fn scope_a() -> TrustedScope {
    TrustedScope::parse("scope-a").expect("frozen scope-a")
}
fn scope_b() -> TrustedScope {
    TrustedScope::parse("scope-b").expect("frozen scope-b")
}
fn equipment(raw: &str) -> InstalledId {
    InstalledId::parse(raw).expect("frozen equipment")
}
fn operation(raw: &str) -> OperationId {
    OperationId::parse(raw).expect("operation parses")
}
fn precondition_fresh() -> Precondition {
    Precondition::new(
        action_preview::synthetic_time(1_700_000_000_000),
        action_preview::synthetic_time(1_700_000_060_000),
    )
    .expect("fresh precondition")
}
fn seal_ready() -> SealOrder {
    let mut order = SealOrder::new();
    order.check_custody().expect("custody");
    order.decode().expect("decode");
    order.reconstruct().expect("reconstruct");
    order
}
fn preview_at(setpoint: f64) -> Preview {
    Preview::preview(
        scope_a(),
        equipment("ahu-1"),
        BindingRevision::new(7),
        accept::AcceptedRevision::new(1).expect("accepted revision"),
        binding::BindingStatus::Valid,
        2,
        RoleKind::Publisher,
        Some(8),
        2,
        85,
        None,
        Unit::parse("degC").expect("degC"),
        setpoint,
        None,
        &["ahu-1-sp"],
        precondition_fresh(),
        &seal_ready(),
        equipment("ahu-1"),
        false,
    )
    .expect("permitted preview")
}
fn preview_vav(setpoint: f64) -> Preview {
    Preview::preview(
        scope_a(),
        equipment("vav-101"),
        BindingRevision::new(7),
        accept::AcceptedRevision::new(1).expect("accepted revision"),
        binding::BindingStatus::Valid,
        2,
        RoleKind::Publisher,
        Some(8),
        2,
        85,
        None,
        Unit::parse("degC").expect("degC"),
        setpoint,
        None,
        &["vav-101-sp"],
        precondition_fresh(),
        &seal_ready(),
        equipment("vav-101"),
        false,
    )
    .expect("permitted vav preview")
}
fn raw(path: &Path, sql: &str) -> String {
    let mut child = Command::new("sqlite3")
        .args(["-batch", "-bail"])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sqlite3");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(sql.as_bytes())
        .expect("SQL");
    let out = child.wait_with_output().expect("exit");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("UTF8")
}
fn journal_count(journal: &Journal) -> String {
    journal
        .store()
        .exec_script("SELECT count(*) FROM action_journal;")
        .expect("count")
        .into_iter()
        .next()
        .expect("row")[0]
        .clone()
}

#[test]
fn same_key_same_payload_retry_reconciles() {
    let scratch = Scratch::new();
    let (mut journal, _rx) = open_journal(&scratch);
    let preview = preview_at(22.0);
    assert_eq!(
        preview.canonical_bytes(),
        "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish"
    );
    assert_eq!(preview.format(), "verdant-preview-v1");
    assert!(!preview.is_reservation());
    assert!(!preview.is_dispatch());
    assert!(!preview.is_qualified());
    assert_eq!(preview.timing().apdu_retries(), 0);
    assert_eq!(preview.timing().apdu_retries(), runtime::bacnet::APDU_RETRIES);
    let first = journal
        .admit(operation("adm-retry-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("first admit");
    assert!(!first.reconciled());
    assert_eq!(first.operation().as_str(), "adm-retry-1");
    assert_eq!(first.target_generation(), 1);
    assert_eq!(first.expected_generation(), 0);
    assert_eq!(first.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
    assert_eq!(first.deadline_secs(), 5);
    assert_eq!(first.ceiling(), 2);
    assert_eq!(first.actor(), "publisher-1/scope-a");
    assert_eq!(first.journal_format(), "verdant-action-journal-v1");
    assert!(!first.is_dispatch());
    let second = journal
        .admit(operation("adm-retry-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("retry reconciles");
    assert!(second.reconciled());
    assert_eq!(second.operation().as_str(), "adm-retry-1");
    assert_eq!(second.payload(), first.payload());
    assert_eq!(second.target_generation(), 1);
    assert_eq!(second.attempt().as_str(), first.attempt().as_str());
    assert_eq!(journal_count(&journal), "1");
    assert_eq!(journal.essential_announced(), 1);
    assert_eq!(
        raw(&scratch.db(), "SELECT generation FROM schema_migrations ORDER BY generation;"),
        "1\n2\n3\n4\n5\n"
    );
    assert_eq!(raw(&scratch.db(), "PRAGMA user_version;"), "1\n");
}

#[test]
fn conflicting_payload_on_same_key_refuses_without_overwrite() {
    let scratch = Scratch::new();
    let (mut journal, _rx) = open_journal(&scratch);
    let first_preview = preview_at(22.0);
    let second_preview = preview_at(23.0);
    assert_eq!(
        second_preview.canonical_bytes(),
        "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|23.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish"
    );
    journal
        .admit(operation("adm-conflict-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &first_preview, 0)
        .expect("first admit");
    let error = journal
        .admit(operation("adm-conflict-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &second_preview, 0)
        .unwrap_err();
    assert_eq!(error.code(), "admission-conflict");
    let recovered = journal.reconcile(&operation("adm-conflict-1"), &scope_a()).expect("original retained");
    assert_eq!(recovered.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
    assert_eq!(journal_count(&journal), "1");
    assert_eq!(journal.essential_announced(), 1);
}

#[test]
fn concurrent_replacement_uses_expected_generation() {
    let scratch = Scratch::new();
    let (mut journal, _rx) = open_journal(&scratch);
    journal
        .admit(operation("adm-gen-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.0), 0)
        .expect("gen 0 wins");
    let stale = journal
        .admit(operation("adm-gen-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.5), 0)
        .unwrap_err();
    assert_eq!(stale.code(), "admission-stale-generation");
    match stale {
        action_journal::WriterError::StaleGeneration { expected, current } => {
            assert_eq!(expected, 0);
            assert_eq!(current, 1);
        }
        other => panic!("wrong variant: {other:?}"),
    }
    let current = journal
        .admit(operation("adm-gen-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.5), 1)
        .expect("current generation wins");
    assert_eq!(current.target_generation(), 2);
    assert_eq!(
        current.payload(),
        "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.5000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish"
    );
    assert_eq!(journal_count(&journal), "2");
}

#[test]
fn cross_scope_keys_do_not_disclose_outcomes() {
    let scratch = Scratch::new();
    let (mut journal, _rx) = open_journal(&scratch);
    journal
        .admit(operation("adm-scope-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.0), 0)
        .expect("scope-a admit");
    let error = journal.reconcile(&operation("adm-scope-1"), &scope_b()).unwrap_err();
    assert_eq!(error.code(), "admission-not-found");
    let message = error.to_string();
    assert!(!message.contains("22.0000"));
    assert!(!message.contains("unavailable-feedback"));
    assert!(!message.contains("null-relinquish"));
}

#[test]
fn failed_journal_prevents_new_handoff() {
    let scratch = Scratch::new();
    let (mut journal, _rx) = open_journal(&scratch);
    journal
        .admit(operation("adm-handoff-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.0), 0)
        .expect("valid admit");
    assert_eq!(journal.essential_announced(), 1);
    let _ = journal
        .admit(operation("adm-handoff-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(23.0), 0)
        .unwrap_err();
    assert_eq!(journal.essential_announced(), 1);
    let _ = journal
        .admit(operation("adm-handoff-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.5), 0)
        .unwrap_err();
    assert_eq!(journal.essential_announced(), 1);
    assert_eq!(journal_count(&journal), "1");
}

#[test]
fn cancel_before_handoff_emits_nothing() {
    let scratch = Scratch::new();
    let (journal, _rx) = open_journal(&scratch);
    let preview = preview_at(22.0);
    let pending = journal
        .prepare(operation("adm-cancel-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0)
        .expect("prepare");
    Journal::cancel(pending);
    assert_eq!(journal_count(&journal), "0");
    assert_eq!(journal.essential_announced(), 0);
    assert_eq!(journal.history_announced(), 0);
    assert_eq!(
        journal.reconcile(&operation("adm-cancel-1"), &scope_a()).unwrap_err().code(),
        "admission-not-found"
    );
}

#[test]
fn deleted_row_does_not_make_stale_admissible() {
    let scratch = Scratch::new();
    let (mut journal, _rx) = open_journal(&scratch);
    journal
        .admit(operation("adm-del-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.0), 0)
        .expect("first admit");
    raw(&scratch.db(), "DELETE FROM action_journal WHERE operation='adm-del-1';");
    assert_eq!(raw(&scratch.db(), "SELECT count(*) FROM action_journal;"), "0\n");
    assert_eq!(
        raw(&scratch.db(), "SELECT current_generation FROM action_targets WHERE scope='scope-a' AND equipment='ahu-1';"),
        "1\n"
    );
    let stale = journal
        .admit(operation("adm-del-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.5), 0)
        .unwrap_err();
    assert_eq!(stale.code(), "admission-stale-generation");
    assert_eq!(raw(&scratch.db(), "SELECT count(*) FROM action_journal;"), "0\n");
    assert_eq!(
        journal.reconcile(&operation("adm-del-1"), &scope_a()).unwrap_err().code(),
        "admission-not-found"
    );
}

#[test]
fn crash_at_handoff_boundary_is_unknown_with_reconciliation() {
    let scratch = Scratch::new();
    let (mut journal, _rx) = open_journal(&scratch);
    action_journal::inject_handoff_crash();
    let error = journal
        .admit(operation("adm-crash-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.0), 0)
        .unwrap_err();
    assert_eq!(error.code(), "admission-unknown");
    match &error {
        action_journal::WriterError::Unknown { operation, .. } => {
            assert_eq!(operation.as_str(), "adm-crash-1");
        }
        other => panic!("wrong variant: {other:?}"),
    }
    assert_eq!(journal.essential_announced(), 0);
    let recovered = journal.reconcile(&operation("adm-crash-1"), &scope_a()).expect("reconcile recovers");
    assert_eq!(recovered.operation().as_str(), "adm-crash-1");
    assert!(recovered.reconciled());
    assert_eq!(recovered.payload(), "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish");
}

#[test]
fn lost_wakeup_still_reconciles_from_durable_rows() {
    let scratch = Scratch::new();
    let (mut journal, receivers) = open_journal(&scratch);
    journal
        .admit(operation("adm-wakeup-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.0), 0)
        .expect("admit");
    drop(receivers);
    let recovered = journal.reconcile(&operation("adm-wakeup-1"), &scope_a()).expect("reconcile after lost wake-up");
    assert_eq!(recovered.operation().as_str(), "adm-wakeup-1");
    assert!(recovered.reconciled());
    assert_eq!(recovered.target_generation(), 1);
}

#[test]
fn lock_ordering_and_separate_bounded_queues() {
    let scratch = Scratch::new();
    let (mut journal, receivers) = open_journal(&scratch);
    assert_eq!(journal.essential_capacity(), 64);
    assert_eq!(journal.history_capacity(), 1);
    assert_ne!(journal.essential_capacity(), journal.history_capacity());
    journal
        .admit(operation("adm-lock-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.0), 0)
        .expect("ahu-1 target");
    journal
        .admit(operation("adm-lock-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_vav(21.5), 0)
        .expect("vav-101 target without building-wide lock");
    assert_eq!(journal.essential_announced(), 2);
    assert_eq!(journal.history_announced(), 1);
    assert_eq!(journal.history_refused(), 1);
    assert_eq!(journal_count(&journal), "2");
    drop(receivers);
    let first = journal.reconcile(&operation("adm-lock-1"), &scope_a()).expect("essential reconciles");
    assert!(!first.is_dispatch());
    assert_eq!(first.journal_format(), "verdant-action-journal-v1");
}
