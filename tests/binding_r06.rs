//! R06 synthetic row/descriptor regressions. Each fixture owns and removes its DB.
#[allow(dead_code)]
#[path = "../src/domain/mod.rs"]
mod domain;
#[allow(dead_code)]
#[path = "../src/storage/mod.rs"]
mod storage;
#[allow(dead_code)]
#[path = "../src/access/mod.rs"]
mod access;
#[allow(dead_code)]
#[path = "../src/semantics/mod.rs"]
mod semantics;
#[allow(dead_code)]
#[path = "../src/binding/mod.rs"]
mod binding;

use access::{AccessGate, BootstrapCredentials, Reason};
use binding::{BindingRegistry, BindingRole, EndpointClass, EquipmentKind, Feedback};
use domain::{scope::TrustedScope, values::Unit};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use storage::{ConnectionSettings, StoreBounds};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("verdant-r06-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }
    fn db(&self) -> PathBuf { self.0.join("binding.db") }
    fn registry(&self) -> BindingRegistry {
        BindingRegistry::open(&self.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).unwrap()
    }
    fn gate(&self) -> (AccessGate, BootstrapCredentials) {
        AccessGate::bootstrap(&self.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny(), &Reason::parse("synthetic R06").unwrap()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
}
fn scope() -> TrustedScope { TrustedScope::parse("scope-a").unwrap() }
fn seed(registry: &mut BindingRegistry) {
    registry.record_equipment("ahu-1", EquipmentKind::Ahu, scope(), "AHU", "mstp://ahu-1").unwrap();
    registry.record_point("ahu-1", "supply-air-temp", scope(), "degC", EndpointClass::Location).unwrap();
}
fn propose(registry: &mut BindingRegistry, gate: &AccessGate, creds: &BootstrapCredentials) -> binding::ProposedBinding {
    registry.propose_with_credential(gate, Some(&creds.publisher), "mstp://ahu-1", EndpointClass::Location, scope(), "ahu-1", "supply-air-temp", "sensor-sat-1", Unit::parse("degC").unwrap(), None, BindingRole::Sense, BindingRole::Sense, Feedback::Absent).unwrap()
}
fn rows(registry: &BindingRegistry) -> Vec<Vec<String>> {
    registry.store().exec_script("SELECT id, seq, value_json FROM outbox WHERE operation LIKE 'binding-%' ORDER BY id;").unwrap()
}
fn pending(registry: &BindingRegistry, operation: &str) -> binding::PendingProposal {
    let proposed = binding::propose(binding::EndpointAddress::parse("mstp://ahu-1").unwrap(), EndpointClass::Location, scope(), domain::ids::InstalledId::parse("ahu-1").unwrap(), binding::PropertyName::parse("supply-air-temp").unwrap(), scope(), domain::ids::InstalledId::parse("sensor-sat-1").unwrap(), &Unit::parse("degC").unwrap(), EndpointClass::Location, Unit::parse("degC").unwrap(), None, BindingRole::Sense, BindingRole::Sense, Feedback::Absent).unwrap();
    binding::PendingProposal::new(domain::ids::OperationId::parse(operation).unwrap(), registry.revision(), proposed)
}

#[test]
fn r06_revoked_between_enter_and_emit() {
    let fixture = Fixture::new();
    let (gate, creds) = fixture.gate();
    let mut registry = fixture.registry();
    seed(&mut registry);
    let proposed = propose(&mut registry, &gate, &creds);
    let entered = gate.enter_review(Some(&creds.publisher), &scope()).unwrap();
    gate.revoke(&creds.publisher, &Reason::parse("synthetic revoke after entry").unwrap()).unwrap();
    let before = rows(&registry);
    let error = registry.emit_finding(&gate, &proposed, &creds.publisher).unwrap_err();
    let after = rows(&registry);
    assert_eq!(after, before);
    assert!(matches!(error, binding::BindingError::CapabilityDenied { ref access_code, .. } if access_code == "revoked-credential"));
    assert_eq!(entered.actor().cap_generation(), 1);
    println!("FIXED revoked emission: rows {} -> {}; denial={error}", before.len(), after.len());
}

#[test]
fn r06_two_handles_share_one_evolution() {
    let fixture = Fixture::new();
    let mut first = fixture.registry();
    let mut second = fixture.registry();
    first.record_equipment("ahu-1", EquipmentKind::Ahu, scope(), "AHU", "mstp://ahu-1").unwrap();
    second.record_equipment("vav-101", EquipmentKind::Vav, scope(), "VAV", "mstp://vav-101").unwrap();
    let durable = rows(&first);
    assert_eq!(durable.iter().map(|row| row[1].as_str()).collect::<Vec<_>>(), vec!["1", "2"]);
    assert_eq!(second.revision().as_u32(), 2);
    assert_eq!(fixture.registry().revision().as_u32(), 2);
    println!("FIXED two handles: seqs=[1,2], writer re-resolved revision=2; rows={}", durable.len());
}

#[test]
fn r06_duplicate_proposal_retry() {
    let fixture = Fixture::new();
    let (gate, creds) = fixture.gate();
    let mut registry = fixture.registry();
    seed(&mut registry);
    let request = pending(&registry, "synthetic-same-op");
    let first = registry.submit_proposal(&gate, Some(&creds.publisher), &request).unwrap();
    let before = rows(&registry);
    let bytes = std::fs::read(fixture.db()).unwrap();
    let second = registry.submit_proposal(&gate, Some(&creds.publisher), &request).unwrap();
    assert_eq!(first, second);
    assert_eq!(registry.bindings().len(), 1);
    assert_eq!(rows(&registry), before);
    assert_eq!(std::fs::read(fixture.db()).unwrap(), bytes);
    let distinct = pending(&registry, "synthetic-distinct-op");
    let third = registry.submit_proposal(&gate, Some(&creds.publisher), &distinct).unwrap();
    assert_ne!(first.row_id, third.row_id);
    assert_eq!(registry.bindings().len(), 2);
    println!("FIXED identical operation: same row_id={}, preserved bytes={}; distinct operation row_id={}", first.row_id, bytes.len(), third.row_id);
}

#[test]
fn r06_interrupted_evolution() {
    let fixture = Fixture::new();
    let mut registry = fixture.registry();
    let before = std::fs::read(fixture.db()).unwrap();
    storage::sqlite::faults::inject(&fixture.db(), storage::sqlite::faults::Fault::BeforeCommit);
    let error = registry.record_equipment("ahu-1", EquipmentKind::Ahu, scope(), "AHU", "mstp://ahu-1").unwrap_err();
    assert_eq!(error.code(), "sqlite-failure");
    assert!(rows(&registry).is_empty());
    assert_eq!(std::fs::read(fixture.db()).unwrap(), before);
    registry.record_equipment("ahu-1", EquipmentKind::Ahu, scope(), "AHU", "mstp://ahu-1").unwrap();
    assert_eq!(rows(&registry)[0][1], "1");
    assert_eq!(registry.revision().as_u32(), 1);
    println!("FIXED precommit teardown: zero rows, preserved bytes={}, retry seq=1 (no lost evolution)", before.len());
}

#[test]
fn r06_history_has_explicit_window() {
    let fixture = Fixture::new();
    let mut registry = fixture.registry();
    for index in 0..70 {
        registry.record_point("ahu-1", &format!("synthetic-{index}"), scope(), "degC", EndpointClass::Location).unwrap();
    }
    let mut bounds = StoreBounds::tiny();
    bounds.max_replay_rows = 2;
    let reopened = BindingRegistry::open(&fixture.db(), ConnectionSettings::local_wal_full(), bounds).unwrap();
    assert_eq!(reopened.revision().as_u32(), 70);
    assert_eq!(rows(&reopened).len(), 70);
    let window = reopened.replay_window(domain::clock::UnixMillis::new(0), 100).unwrap();
    assert_eq!(window.rows.iter().map(|row| row.sequence).collect::<Vec<_>>(), vec![69, 70]);
    assert!(window.stale);
    assert_eq!(reopened.replay_window(domain::clock::UnixMillis::new(i64::MAX), 2).unwrap_err(), binding::BindingError::EmptyWindow);
    assert_eq!(reopened.replay_window(domain::clock::UnixMillis::new(0), 0).unwrap_err().code(), "invalid-input");
    let mut bounded = StoreBounds::tiny();
    bounded.max_output_rows = 63; // Exact fixed open/upgrade protocol floor.
    bounded.max_replay_rows = 2;
    let before_io = binding::history::window_io_counts();
    let direct = BindingRegistry::open_window(&fixture.db(), ConnectionSettings::local_wal_full(), bounded.clone(), domain::clock::UnixMillis::new(0), 2).unwrap();
    assert_eq!(direct, window);
    assert_eq!(binding::history::window_io_counts(), (before_io.0 + 1, before_io.1 + 1));
    assert_eq!(BindingRegistry::open(&fixture.db(), ConnectionSettings::local_wal_full(), bounded).err().unwrap().code(), "execution-limit");
    let mut complete_bounds = StoreBounds::tiny();
    complete_bounds.max_output_rows = 103; // 70 history lines + 33 protocol lines.
    complete_bounds.max_replay_rows = 70;
    let complete = BindingRegistry::open_window(&fixture.db(), ConnectionSettings::local_wal_full(), complete_bounds.clone(), domain::clock::UnixMillis::new(0), 70).unwrap();
    assert_eq!(complete.rows.iter().map(|row| row.sequence).collect::<Vec<_>>(), (1..=70).collect::<Vec<_>>());
    assert!(!complete.stale);
    // Exclusion by time, not just horizon, must also be explicit staleness.
    registry.store().exec_script("UPDATE outbox SET created_nanos='0' WHERE operation LIKE 'binding-%' AND seq='1';").unwrap();
    let recent = BindingRegistry::open_window(&fixture.db(), ConnectionSettings::local_wal_full(), complete_bounds, domain::clock::UnixMillis::new(1), 70).unwrap();
    assert_eq!(recent.rows.len(), 69);
    assert_eq!(recent.rows[0].sequence, 2);
    assert!(recent.stale);
    println!("FIXED full replay=70; horizon=2/cap=63 -> seqs=[69,70], stale=true (full replay still refuses); horizon=70/cap=103 -> 70 rows, stale=false; since excludes one -> 69 rows, stale=true; expired window refused");
}

#[test]
fn r06_created_nanos_is_integer_text_and_round_trips() {
    let fixture = Fixture::new();
    let mut registry = fixture.registry();
    seed(&mut registry);
    let stored = registry.store().exec_script("SELECT typeof(created_nanos),created_nanos,CAST(created_nanos AS INTEGER) FROM outbox WHERE operation LIKE 'binding-%' ORDER BY id;").unwrap();
    assert_eq!(stored.len(), 2);
    for row in &stored {
        assert_eq!(row[0], "text");
        assert!(!row[1].contains("e+"));
        assert!(!row[1].contains('.'));
        assert!(row[1].bytes().all(|byte| byte.is_ascii_digit()));
        assert_eq!(row[1], row[2]);
        assert!(row[1].parse::<i64>().unwrap() > 0);
    }
    let since = stored[1][1].parse::<i64>().unwrap() / 1_000_000;
    let round_trip = registry.replay_window(domain::clock::UnixMillis::new(since), 2).unwrap();
    assert_eq!(round_trip.rows.last().unwrap().sequence, 2);
    // Independent integer vectors prove inclusive millisecond filtering; no
    // sleep or dependence on two writes landing in different wall-clock ticks.
    registry.store().exec_script("UPDATE outbox SET created_nanos=CASE seq WHEN '1' THEN '1789238414500000000' ELSE '1789238414501000000' END WHERE operation LIKE 'binding-%';").unwrap();
    let complete = registry.replay_window(domain::clock::UnixMillis::new(1_789_238_414_500), 2).unwrap();
    assert_eq!(complete.rows.iter().map(|row| row.sequence).collect::<Vec<_>>(), vec![1, 2]);
    assert!(!complete.stale);
    let recent = registry.replay_window(domain::clock::UnixMillis::new(1_789_238_414_501), 2).unwrap();
    assert_eq!(recent.rows.iter().map(|row| row.sequence).collect::<Vec<_>>(), vec![2]);
    assert!(recent.stale);
    assert_eq!(registry.replay_window(domain::clock::UnixMillis::new(1_789_238_414_502), 2).unwrap_err(), binding::BindingError::EmptyWindow);
    println!("FIXED integer timestamp text={stored:?}; live write/filter round-trip; exact since=.500 -> [1,2]/fresh, .501 -> [2]/stale, .502 -> EmptyWindow");
}

#[test]
fn r06_storage_insert_created_nanos_is_integer_text() {
    let fixture = Fixture::new();
    let registry = fixture.registry();
    let time = domain::clock::UnixMillis::new(0);
    registry.store().insert(
        &domain::ids::OperationId::parse("synthetic-storage-timestamp").unwrap(),
        &domain::ids::InstalledId::parse("ahu-1").unwrap(),
        &domain::ids::InstalledId::parse("sensor-sat-1").unwrap(),
        &domain::values::Value::Missing, &Unit::parse("degC").unwrap(),
        domain::clock::TimeTriple::new(time, time, time).unwrap(),
        &domain::outcomes::RecordIdentity::new(domain::ids::SourceGenerationId::parse("gen-1").unwrap(), 1),
    ).unwrap();
    let stored = registry.store().exec_script("SELECT typeof(created_nanos),created_nanos,CAST(created_nanos AS INTEGER) FROM outbox WHERE operation='synthetic-storage-timestamp';").unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0][0], "text");
    assert!(!stored[0][1].contains("e+"));
    assert!(!stored[0][1].contains('.'));
    assert_eq!(stored[0][1], stored[0][2]);
    assert!(stored[0][1].parse::<i64>().unwrap() > 0);
    println!("FIXED sibling storage insert integer timestamp text={stored:?}");
}

#[test]
fn r06_window_refuses_non_integer_created_nanos_before_filtering() {
    let fixture = Fixture::new();
    let mut registry = fixture.registry();
    seed(&mut registry);
    let mut bounds = StoreBounds::tiny();
    bounds.max_output_rows = 63;
    for invalid in ["1.7892384145e+18", "1789238414500000000.0", "123junk", "", " 123", "1e3", "9223372036854775808", "-9223372036854775809"] {
        // Corrupt the older row: a horizon of one would otherwise hide it.
        registry.store().exec_script(&format!("UPDATE outbox SET created_nanos={} WHERE operation LIKE 'binding-%' AND seq='1';", binding::sql_quote(invalid))).unwrap();
        let before = std::fs::read(fixture.db()).unwrap();
        for since in [0, 1, i64::MAX] {
            let since = domain::clock::UnixMillis::new(since);
            let error = registry.replay_window(since, 1).unwrap_err();
            assert!(matches!(error, binding::BindingError::InvalidRecord { ref detail } if detail.contains("created_nanos")));
            assert_eq!(BindingRegistry::open_window(&fixture.db(), ConnectionSettings::local_wal_full(), bounds.clone(), since, 1).unwrap_err(), error);
        }
        assert_eq!(std::fs::read(fixture.db()).unwrap(), before);
        println!("FIXED malformed created_nanos={invalid:?}: InvalidRecord before time/horizon exclusion; unchanged bytes={}", before.len());
    }
}

#[test]
fn r06_incoherent_window_refuses_before_storage_io() {
    let fixture = Fixture::new();
    let registry = fixture.registry();
    let before_rows = rows(&registry);
    assert!(before_rows.is_empty());
    let before_bytes = std::fs::read(fixture.db()).unwrap();
    for (horizon, cap) in [(2, 40), (30, 62), (31, 63), (70, 102), (u32::MAX, 103), (0, 103)] {
        let mut bounds = StoreBounds::tiny();
        bounds.max_output_rows = cap;
        bounds.max_replay_rows = 2; // Clamping cannot conceal an incoherent request.
        for path in [fixture.db(), fixture.0.join("never-opened.db")] {
            let before_io = binding::history::window_io_counts();
            let error = BindingRegistry::open_window(&path, ConnectionSettings::local_wal_full(), bounds.clone(), domain::clock::UnixMillis::new(0), horizon).unwrap_err();
            assert!(matches!(error, binding::BindingError::InvalidInput { what: "replay output budget" | "replay horizon", .. }));
            assert_eq!(binding::history::window_io_counts(), before_io, "must not open storage or read rows");
        }
        assert!(!fixture.0.join("never-opened.db").exists());
        assert_eq!(rows(&registry), before_rows);
        assert_eq!(std::fs::read(fixture.db()).unwrap(), before_bytes);
        println!("FIXED window admission: horizon={horizon}, cap={cap}, invalid-input; opens=0 reads=0 rows=0; preserved bytes={}", before_bytes.len());
    }
    let before_execution = registry.store().execution_report();
    let before_io = binding::history::window_io_counts();
    assert!(matches!(registry.replay_window(domain::clock::UnixMillis::new(0), 8_160).unwrap_err(), binding::BindingError::InvalidInput { what: "replay output budget", .. }));
    assert_eq!(registry.store().execution_report(), before_execution);
    assert_eq!(binding::history::window_io_counts(), before_io);
}

#[test]
fn r06_retry_resolves_current_truth() {
    let fixture = Fixture::new();
    let (gate, creds) = fixture.gate();
    let mut first = fixture.registry();
    seed(&mut first);
    let mut cached = fixture.registry();
    let request = pending(&cached, "synthetic-pending-before-retire");
    first.retire("ahu-1", "synthetic retirement").unwrap();
    let before = rows(&first);
    assert!(matches!(cached.submit_proposal(&gate, Some(&creds.publisher), &request).unwrap_err(), binding::BindingError::Conflict { .. }));
    assert!(cached.is_retired("ahu-1"));
    let refreshed = pending(&cached, "synthetic-pending-before-retire");
    assert!(matches!(cached.submit_proposal(&gate, Some(&creds.publisher), &refreshed).unwrap_err(), binding::BindingError::Conflict { .. }));
    assert_eq!(rows(&cached), before);
    assert!(fixture.registry().is_retired("ahu-1"));
    println!("FIXED stale retry: retired equipment refused, unchanged rows={}; resolved revision={}", before.len(), cached.revision().as_u32());
}

#[test]
fn r06_cross_revision_import() {
    let fixture = Fixture::new();
    let (gate, creds) = fixture.gate();
    let mut registry = fixture.registry();
    seed(&mut registry);
    let item = semantics::convert::ExternalItem::parse("synthetic-ahu", semantics::profile::SUPPORTED_AHU_CLASS, "ahu-1", "AHU", "degC", domain::values::Value::Missing).unwrap();
    let conversion = binding::import_site(&semantics::convert::ExternalSite::new(vec![item]).unwrap(), &semantics::profile::Profile::pinned()).unwrap();
    let set = semantics::convert::BindingSet::from_conversion(&conversion, registry.revision());
    registry.record_source("sensor-sat-1", scope(), "SAT").unwrap();
    assert_ne!(set.revision(), registry.revision());
    let before = rows(&registry);
    let error = registry.import_with_credential(&gate, Some(&creds.publisher), &set.bindings()[0], set.revision(), "mstp://ahu-1", EndpointClass::Location, scope(), "supply-air-temp", "sensor-sat-1", BindingRole::Sense, BindingRole::Sense, Feedback::Absent).unwrap_err();
    assert!(matches!(error, binding::BindingError::Conflict { .. }));
    assert_eq!(rows(&registry), before);
    let imported = registry.import_with_credential(&gate, Some(&creds.publisher), &set.bindings()[0], registry.revision(), "mstp://ahu-1", EndpointClass::Location, scope(), "supply-air-temp", "sensor-sat-1", BindingRole::Sense, BindingRole::Sense, Feedback::Absent).unwrap();
    assert_eq!(imported.status(), binding::BindingStatus::Imported);
    assert!(rows(&registry).last().unwrap()[2].contains(";revision=3;"));
    println!("FIXED cross-revision import: input rev=2 refused at rev=3; matching rev=3 accepted; descriptor={}", rows(&registry).last().unwrap()[2]);
}

#[test]
fn r06_concurrent_writers_have_one_winner() {
    let fixture = Fixture::new();
    let first = fixture.registry();
    let second = fixture.registry();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut threads = Vec::new();
    for (mut registry, id, kind) in [(first, "ahu-1", EquipmentKind::Ahu), (second, "vav-101", EquipmentKind::Vav)] {
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            binding::writer::on_boundary(move || { barrier.wait(); });
            (id, registry.record_equipment(id, kind, scope(), "synthetic", "mstp://ahu-1"))
        }));
    }
    let results = threads.into_iter().map(|t| t.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|(_, result)| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|(_, result)| matches!(result, Err(binding::BindingError::Conflict { .. }))).count(), 1);
    let registry = fixture.registry();
    assert_eq!(rows(&registry).len(), 1);
    assert_eq!(rows(&registry)[0][1], "1");
    assert_eq!(registry.revision().as_u32(), 1);
    println!("FIXED concurrent writers: {results:?}; durable rows=1, seq=1, revision=1");
}

#[test]
fn r06_unknown_reconciles_without_second_write() {
    let fixture = Fixture::new();
    let (gate, creds) = fixture.gate();
    let mut registry = fixture.registry();
    seed(&mut registry);
    let request = pending(&registry, "synthetic-lost-response");
    storage::sqlite::faults::inject(&fixture.db(), storage::sqlite::faults::Fault::LostResponse);
    let error = registry.submit_proposal(&gate, Some(&creds.publisher), &request).unwrap_err();
    assert!(matches!(error, binding::BindingError::MutationUnknown { ref operation, .. } if operation == request.operation()));
    let committed_rows = rows(&registry);
    let bytes = std::fs::read(fixture.db()).unwrap();
    drop(registry);
    let mut registry = fixture.registry();
    let recovered = registry.reconcile_proposal(&request).unwrap().unwrap();
    assert_eq!(registry.submit_proposal(&gate, Some(&creds.publisher), &request).unwrap(), recovered);
    assert_eq!(rows(&registry), committed_rows);
    assert_eq!(std::fs::read(fixture.db()).unwrap(), bytes);
    assert_eq!(registry.bindings().len(), 1);
    println!("FIXED lost commit response: UNKNOWN -> same-ID row {}, proposal rows=1; unchanged bytes={}", recovered.row_id, bytes.len());
}

#[test]
fn r06_authority_change_after_entry_loses_before_write() {
    let fixture = Fixture::new();
    let (gate, creds) = fixture.gate();
    let mut registry = fixture.registry();
    seed(&mut registry);
    let proposed = propose(&mut registry, &gate, &creds);
    let before = rows(&registry);
    let revoker = AccessGate::open(&fixture.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).unwrap();
    let credential = creds.publisher.clone();
    binding::writer::on_boundary(move || revoker.revoke(&credential, &Reason::parse("synthetic revoke at write").unwrap()).unwrap());
    let error = registry.emit_finding(&gate, &proposed, &creds.publisher).unwrap_err();
    assert!(matches!(error, binding::BindingError::Conflict { .. }));
    assert_eq!(rows(&registry), before);
    assert!(registry.findings().is_empty());
    println!("FIXED authority changed after authentication: Conflict; unchanged binding rows={}", before.len());
}

#[test]
fn r06_rotation_reauthenticates_pending_proposal_and_v2_actor() {
    let fixture = Fixture::new();
    let (gate, creds) = fixture.gate();
    let mut registry = fixture.registry();
    seed(&mut registry);
    let request = pending(&registry, "synthetic-rotation-pending");
    let next = gate.rotate(&creds.publisher, &access::KeyId::parse("synthetic-new-key").unwrap(), &access::SyntheticKey::parse("synthetic-rotation-material").unwrap(), &Reason::parse("synthetic rotation").unwrap()).unwrap();
    assert_eq!(registry.submit_proposal(&gate, Some(&creds.publisher), &request).unwrap_err().code(), "capability-denied");
    let committed = registry.submit_proposal(&gate, Some(&next), &request).unwrap();
    let finding = registry.emit_finding(&gate, &committed.binding, &next).unwrap();
    assert_eq!(finding.actor_reference_text(), "capability=publisher-1;scope=scope-a;capgen=2;issuer=bootstrap-issuer-1");
    let durable = rows(&registry);
    for row in &durable[2..] {
        assert!(row[2].contains("v=2;kind="));
        assert!(row[2].contains("capability=publisher-1;scope=scope-a;capgen=2;issuer=bootstrap-issuer-1"));
        assert!(!row[2].contains(&next.key().fingerprint()));
        assert!(!row[2].contains("synthetic-rotation-material"));
        assert!(!row[2].contains("synthetic-new-key"));
        assert!(!row[2].contains(";fp="));
    }
    assert_eq!(fixture.registry().findings()[0], finding);
    println!("FIXED pending rotation: old credential refused, capgen=2 persisted; finding pair=({},{}); descriptor={}", finding.id().as_str(), finding.generation(), durable.last().unwrap()[2]);
}

#[test]
fn r06_expiry_is_checked_at_sql_mutation_boundary() {
    let fixture = Fixture::new();
    let (gate, creds) = fixture.gate();
    let mut registry = fixture.registry();
    seed(&mut registry);
    let request = pending(&registry, "synthetic-expired-op");
    // Explicit test corruption seam: app clock says live, SQLite wall clock is
    // after expiry. No sleep or scheduling assumption determines the outcome.
    registry.store().exec_script("UPDATE outbox SET value_json=replace(value_json,'expires=none','expires=100') WHERE entity='publisher-1';").unwrap();
    let before = rows(&registry);
    let bytes = std::fs::read(fixture.db()).unwrap();
    let counts = registry.store().exec_script("SELECT (SELECT COUNT(*) FROM outbox),(SELECT COUNT(*) FROM storage_receipts),(SELECT COUNT(*) FROM derived_marks);").unwrap();
    let error = access::testing::with_clock(99, || registry.submit_proposal(&gate, Some(&creds.publisher), &request)).unwrap_err();
    assert!(matches!(error, binding::BindingError::CapabilityDenied { ref access_code, .. } if access_code == "expired-credential"));
    assert_eq!(rows(&registry), before);
    assert_eq!(registry.store().exec_script("SELECT (SELECT COUNT(*) FROM outbox),(SELECT COUNT(*) FROM storage_receipts),(SELECT COUNT(*) FROM derived_marks);").unwrap(), counts);
    assert_eq!(std::fs::read(fixture.db()).unwrap(), bytes);
    println!("FIXED expiry at write: no rows/marks/receipts; counts={counts:?}; preserved bytes={}", bytes.len());
}

#[test]
fn r06_operation_reuse_with_changed_inputs_conflicts() {
    let fixture = Fixture::new();
    let (gate, creds) = fixture.gate();
    let mut registry = fixture.registry();
    seed(&mut registry);
    let request = pending(&registry, "synthetic-reused-operation");
    registry.submit_proposal(&gate, Some(&creds.publisher), &request).unwrap();
    let changed = pending(&registry, "synthetic-reused-operation");
    let before = rows(&registry);
    assert!(matches!(registry.submit_proposal(&gate, Some(&creds.publisher), &changed).unwrap_err(), binding::BindingError::Conflict { .. }));
    assert_eq!(rows(&registry), before);
    let operation = domain::ids::OperationId::parse("synthetic-finding-operation").unwrap();
    let revision = registry.revision();
    let finding = registry.emit_finding_operation(&operation, revision, &gate, request.binding(), &creds.publisher).unwrap();
    let before = rows(&registry);
    assert_eq!(registry.emit_finding_operation(&operation, revision, &gate, request.binding(), &creds.publisher).unwrap(), finding);
    assert_eq!(rows(&registry), before);
    assert_eq!(registry.findings().len(), 1);
}
