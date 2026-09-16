//! M02-PR09 publication, replacement and exclusion, HARNESS-ONLY.
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
#[path = "../src/action_dispatch/mod.rs"]
mod action_dispatch;
#[path = "../src/action_expiry/mod.rs"]
mod action_expiry;
#[path = "../src/action_recovery/mod.rs"]
mod action_recovery;
#[path = "../src/action_publication/mod.rs"]
mod action_publication;
#[path = "../src/action_custody/mod.rs"]
mod action_custody;
#[path = "../src/action_joined.rs"]
mod action_joined;
#[path = "seal_cases/fixture.rs"]
mod fixture;
#[path = "accept_cases/support.rs"]
mod support;

use access::RoleKind;
use action_dispatch::{Current, DispatchCancel, DispatchError, FrozenRoute, ProtocolResult};
use action_expiry::ExpiryState;
use action_journal::Journal;
use action_preview::{Precondition, Preview, SealOrder};
use action_publication::{ImpactGate, OldWriterExclusion};
use binding::BindingStatus;
use domain::ids::{BindingRevision, InstalledId, OperationId};
use domain::scope::TrustedScope;
use domain::values::Unit;
use observation::time::{Continuity, Freshness, FreshnessPolicy};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use storage::{ConnectionSettings, StoreBounds};

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("verdant-m02-pr09-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).expect("isolated scratch");
        Self(dir)
    }
    fn db(&self) -> std::path::PathBuf { self.0.join("store.db") }
}
impl Drop for Scratch {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).expect("cleanup scratch"); }
}
fn scope_a() -> TrustedScope { TrustedScope::parse("scope-a").expect("frozen scope-a") }
fn equipment(raw: &str) -> InstalledId { InstalledId::parse(raw).expect("frozen equipment") }
fn operation(raw: &str) -> OperationId { OperationId::parse(raw).expect("operation parses") }
fn precondition_fresh() -> Precondition {
    Precondition::new(action_preview::synthetic_time(1_700_000_000_000), action_preview::synthetic_time(1_700_000_060_000)).expect("fresh")
}
fn seal_ready() -> SealOrder {
    let mut o = SealOrder::new();
    o.check_custody().expect("custody"); o.decode().expect("decode"); o.reconstruct().expect("reconstruct"); o
}
fn preview_at(setpoint: f64) -> Preview {
    Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("accepted"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), setpoint, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("ahu-1"), false).expect("permitted preview")
}
fn preview_release(admitted: bool) -> Preview {
    Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("accepted"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("degC"), 22.0, None, &["ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("ahu-1"), admitted).expect("release preview")
}
fn admit_at(scratch: &Scratch, op: &str, preview: &Preview, expected: u32) -> action_journal::Admitted {
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("writer open");
    journal.admit(operation(op), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", preview, expected).expect("admit")
}
fn current_gen(expected: u32) -> Current {
    Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("rev"), BindingStatus::Valid, expected).expect("current")
}
fn deadline_5s() -> Instant { Instant::now() + Duration::from_secs(5) }
fn journal_count(scratch: &Scratch) -> String {
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count")[0][0].clone()
}
const PAYLOAD_22: &str = "verdant-preview-v1|scope-a|ahu-1|7|1|p8|av2:pv85|degC|22.0000|priority-8-masks-9-16-masked-by-1-7|900s|5s|r0|age60|unavailable-feedback|null-relinquish";

#[test]
fn cosmetic_label_preserved_material_blocks_until_accepted() {
    assert_eq!(action_publication::PUBLICATION_FORMAT, "verdant-publication-v1");
    for phrase in ["delayed-packets-may-take-effect-later", "third-party-writers-outside-transport-ownership-unbounded", "null-release-may-reveal-other-system-command", "one-call-is-not-one-send", "timeout-uncertain-never-resend", "synthetic-budgets-not-host-quotas", "no-power-loss-disk-full-real-time-claim"] {
        assert!(action_publication::LIMITS.contains(phrase), "{phrase}");
    }
    let mut f = fixture::Fixture::new();
    let old = support::config(&mut f, "AHU supply air");
    let cosmetic = support::config(&mut f, "AHU supply air relabeled");
    let diff = cosmetic.impact_from(&old);
    assert!(diff.added.is_empty() && diff.removed.is_empty() && diff.invalidated.is_empty() && !diff.provenance_changed);
    assert!(diff.preserved.contains("sat-binding"));
    assert!(diff.cosmetic.contains("sat-binding"));
    assert!(action_publication::assess_impact(&diff).is_preserved());
    assert!(action_publication::assess_target_impact(&diff, "sat-binding").is_preserved());
    // Material: same key set plus one added key blocks the affected target only.
    let extra = accept::Entry::new(equipment("vav-101"), "VAV", f.registry.bindings()[0].clone()).expect("entry");
    let mut domain = vec![accept::Entry::new(domain::ids::InstalledId::parse("sat-binding").expect("id"), "AHU supply air", f.registry.bindings()[0].clone()).expect("e1")];
    domain.push(extra);
    let grown = accept::EffectiveConfig::resolve(&f.gate, &mut f.registry, fixture::scope(), domain, vec![]).expect("grown");
    let mdiff = grown.impact_from(&old);
    assert!(mdiff.added.contains("vav-101"));
    assert_eq!(action_publication::assess_impact(&mdiff).require_preserved().unwrap_err().code(), "publication-blocked");
    assert!(action_publication::assess_target_impact(&mdiff, "sat-binding").is_preserved());
    assert_eq!(action_publication::assess_target_impact(&mdiff, "vav-101").require_preserved().unwrap_err().code(), "publication-blocked");
    // Impact gates the handoff end to end: preserved authorizes AV2/PV85/P8 Real, blocked refuses.
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    assert_eq!(preview.encoded().wire_bits(), 0x41b00000);
    assert_eq!(preview.canonical_bytes(), PAYLOAD_22);
    let admitted = admit_at(&scratch, "pub-cosmetic-1", &preview, 0);
    let route = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    let ok = action_publication::authorize_setpoint_via_publication(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, None, false, &ImpactGate::Preserved).expect("cosmetic authorizes");
    assert_eq!(ok.object_type(), 2);
    assert_eq!(ok.instance(), 2);
    assert_eq!(ok.property(), 85);
    assert_eq!(ok.priority(), 8);
    assert_eq!(ok.value(), &[0x44, 0x41, 0xb0, 0x00, 0x00]);
    assert!(!ok.is_release());
    let blocked = action_publication::authorize_setpoint_via_publication(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, None, false, &action_publication::assess_impact(&mdiff)).unwrap_err();
    assert_eq!(blocked.code(), "publication-blocked");
    // Frozen profile stays verbatim on the authorized path.
    assert_eq!(preview.timing().duration_secs(), 900);
    assert_eq!(preview.timing().deadline_secs(), 5);
    assert_eq!(preview.timing().apdu_retries(), 0);
    assert_eq!(preview.timing().rate_per_hour(), 6);
    assert_eq!(preview.feedback().status(), "unavailable-feedback");
    assert!(preview.feedback().source_time().is_none());
    assert!(!preview.is_reservation() && !preview.is_dispatch() && !preview.is_qualified());
}

#[tokio::test(flavor = "current_thread")]
async fn barrier_races_ordered_preview_admission_journal_send_publication() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    use std::sync::{Arc, Mutex};
    let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let mark = |o: &Arc<Mutex<Vec<&'static str>>>, s: &'static str| o.lock().unwrap().push(s);
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    mark(&order, "preview");
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let pending = journal.prepare(operation("pub-race-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("prepare");
    mark(&order, "admission-prepared");
    let admitted = journal.submit(&pending).expect("commit");
    mark(&order, "journal-committed");
    assert_eq!(admitted.payload(), PAYLOAD_22);
    // Journal CAS: a second generation commits, then the stale replay refuses.
    journal.admit(operation("pub-race-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview_at(22.5), 1).expect("gen1");
    assert_eq!(journal.admit(operation("pub-race-stale"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).unwrap_err().code(), "admission-stale-generation");
    // Accept CAS: two contenders share expected INITIAL; exactly one wins.
    let mut f = fixture::Fixture::new();
    let (store, sealed) = support::publish(&mut f, "race", "AHU supply air");
    let a = store.prepare(operation("pub-race-accept-a"), accept::AcceptedRevision::INITIAL, &sealed, &f.seals, &mut f.registry, &f.gate, &f.credentials.publisher).expect("prepare a");
    let b = store.prepare(operation("pub-race-accept-b"), accept::AcceptedRevision::INITIAL, &sealed, &f.seals, &mut f.registry, &f.gate, &f.credentials.publisher).expect("prepare b");
    let first = store.submit(&a, &f.seals).expect("one winner");
    assert_eq!(first.revision.get(), 1);
    assert_eq!(store.submit(&b, &f.seals).unwrap_err().code(), "accept-conflict");
    assert_eq!(store.current(&fixture::scope()).expect("current").expect("one").revision.get(), 1);
    // Publication authorize then harness send then recheck then peer-accept, in order.
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    // Barrier: cancel before send refuses with no script and no capture.
    let cancel = DispatchCancel::new();
    cancel.cancel();
    let refused = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &cancel, deadline_5s(), &harness.fixture, None, None).await.unwrap_err();
    assert_eq!(refused.code(), "dispatch-cancelled");
    assert_eq!(harness.fixture.sent_count(), 0);
    mark(&order, "authorize-checked");
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.expect("send");
    mark(&order, "send");
    assert_eq!(outcome.protocol(), &ProtocolResult::Confirmed);
    assert_eq!(outcome.audit().effective_retries(), 0);
    action_publication::recheck_after_handoff_via_publication(&admitted, &current_gen(0), &DispatchCancel::new(), deadline_5s()).expect("recheck");
    mark(&order, "recheck");
    assert_eq!(action_recovery::peer_acceptance(outcome.protocol()), action_recovery::PeerAcceptance::Accepted);
    action_publication::require_peer_accepted_before_journal_via_publication(true, true).expect("peer first");
    mark(&order, "peer-accept");
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 3);
    harness.finish("pub-race-ordered", &requests).await;
    assert_eq!(*order.lock().unwrap(), vec!["preview", "admission-prepared", "journal-committed", "authorize-checked", "send", "recheck", "peer-accept"]);
    assert_eq!(journal_count(&scratch), "2");
}

#[test]
fn duplicate_alias_refuses_without_disclosure() {
    let err = action_preview::AliasSet::new(&["ahu-1-sp", "ahu-1-sp"]).unwrap_err();
    assert_eq!(err.code(), "duplicate-identity");
    assert!(err.to_string().contains("ahu-1-sp"));
    assert!(!err.to_string().contains("scope-b"));
    assert!(!err.to_string().contains("rec-other-scope-opaque-9z"));
    let dup = Preview::preview(scope_a(), equipment("ahu-1"), BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("r"), BindingStatus::Valid, 2, RoleKind::Publisher, Some(8), 2, 85, None, Unit::parse("degC").expect("u"), 22.0, None, &["ahu-1-sp", "ahu-1-sp"], precondition_fresh(), &seal_ready(), equipment("ahu-1"), false).unwrap_err();
    assert_eq!(dup.code(), "duplicate-identity");
    assert_eq!(action_publication::require_aliases_unique(&["ahu-1-sp", "ahu-1-sp"]).unwrap_err().code(), "duplicate-identity");
    assert!(action_publication::require_aliases_unique(&["ahu-1-sp", "vav-101-sp"]).is_ok());
}

#[test]
fn reused_address_new_id_needs_reassessment_old_retained() {
    let dir = std::env::temp_dir().join(format!("verdant-m02-pr09-bind-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir(&dir).expect("scratch");
    let db = dir.join("store.db");
    let (gate, creds) = access::AccessGate::bootstrap(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny(), &access::Reason::parse("synthetic PR09 reuse").expect("reason")).expect("bootstrap");
    let mut registry = binding::BindingRegistry::open(&db, ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("registry");
    registry.record_equipment("ahu-1", binding::EquipmentKind::Ahu, scope_a(), "AHU", "mstp://ahu-1").expect("record old");
    registry.record_point("ahu-1", "supply-air-temp", scope_a(), "degC", binding::EndpointClass::Location).expect("point");
    registry.retire("ahu-1", "synthetic PR09 replacement").expect("retire");
    assert!(registry.is_retired("ahu-1"));
    assert!(registry.equipment("ahu-1").is_some());
    registry.record_equipment("ahu-1r", binding::EquipmentKind::Ahu, scope_a(), "AHU replacement", "mstp://ahu-1").expect("record new id at retired address");
    assert!(registry.needs_reassessment("ahu-1r"));
    assert!(registry.equipment("ahu-1").is_some());
    assert_eq!(registry.equipment("ahu-1r").expect("new retained").id().as_str(), "ahu-1r");
    registry.record_point("ahu-1r", "supply-air-temp", scope_a(), "degC", binding::EndpointClass::Location).expect("new point");
    let refused = registry.propose_with_credential(&gate, Some(&creds.publisher), "mstp://ahu-1r", binding::EndpointClass::Location, scope_a(), "ahu-1r", "supply-air-temp", "sensor-sat-1", Unit::parse("degC").expect("u"), None, binding::BindingRole::Drive, binding::BindingRole::Drive, binding::Feedback::Absent).unwrap_err();
    assert_eq!(refused.code(), "needs-reassessment");
    assert!(refused.to_string().contains("ahu-1r"));
    // Publication replacement gate pins the reused address until fresh qualification/acceptance.
    let gate_err = action_publication::policy::check_replacement_gate(true, true, 7, registry.revision().as_u32()).unwrap_err();
    assert_eq!(gate_err.code(), "publication-pinned");
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn stale_activation_one_cas_winner_history_never_restores() {
    let mut f = fixture::Fixture::new();
    let (store, sealed) = support::publish(&mut f, "stale", "AHU supply air");
    let pending = support::prepare(&mut f, &store, &sealed, "pub-stale-accept-1", accept::AcceptedRevision::INITIAL);
    let accepted = store.submit(&pending, &f.seals).expect("accepted rev1");
    assert_eq!(accepted.revision.get(), 1);
    let req_a = accept::ActivationRequest::new(operation("pub-stale-active-a"), accept::ActiveGeneration::INITIAL, accepted.request.clone());
    let req_b = accept::ActivationRequest::new(operation("pub-stale-active-b"), accept::ActiveGeneration::INITIAL, accepted.request.clone());
    let pa = store.prepare_activation(req_a.clone(), &f.seals).expect("prepare a");
    let pb = store.prepare_activation(req_b.clone(), &f.seals).expect("prepare b");
    let won = store.submit_activation(&pa, &f.seals).expect("one CAS winner");
    assert_eq!(won.generation().get(), 1);
    assert_eq!(won.revision().get(), 1);
    assert_eq!(store.submit_activation(&pb, &f.seals).unwrap_err().code(), "activation-stale-generation");
    // Superseded: accept rev2, then activating the old rev1 request refuses.
    let (store2, sealed2) = support::publish(&mut f, "stale2", "AHU supply air v2");
    let pending2 = support::prepare(&mut f, &store2, &sealed2, "pub-stale-accept-2", accept::AcceptedRevision::new(1).expect("exp1"));
    let accepted2 = store2.submit(&pending2, &f.seals).expect("accepted rev2");
    assert_eq!(accepted2.revision.get(), 2);
    let reopened = support::reopen(&f);
    let stale_req = accept::ActivationRequest::new(operation("pub-stale-active-old"), accept::ActiveGeneration::new(1).expect("g1"), accepted.request.clone());
    assert_eq!(reopened.prepare_activation(stale_req, &f.seals).unwrap_err().code(), "activation-superseded");
    // History never restores the superseded pointer.
    let active = reopened.active(&fixture::scope()).expect("active").expect("winner kept");
    assert_eq!(active.generation().get(), 1);
    assert_eq!(active.revision().get(), 1);
    assert_eq!(active.request().acceptance().seal(), sealed.identity());
    // Publication currency mirrors the same verdicts without auto-promotion.
    // Slice-A active barrier: rev2 is current but NOT active (active stays
    // rev1), so it blocks as newer-accepted/older-active until activation;
    // rev1 is stale-admitted and stays superseded. `Current` swaps cannot
    // substitute for the durable active pointer (see Slice-A regressions).
    assert_eq!(action_publication::require_activation_current_for_handoff(&reopened, &fixture::scope(), sealed2.config().binding_revision(), accept::AcceptedRevision::new(2).expect("rev2")).unwrap_err().code(), "publication-blocked");
    assert_eq!(action_publication::require_activation_current_for_handoff(&reopened, &fixture::scope(), sealed.config().binding_revision(), accept::AcceptedRevision::new(1).expect("rev1")).unwrap_err().code(), "activation-superseded");
}

#[test]
fn old_instance_restart_new_generation_fenced_old_pinned() {
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let other = preview_at(22.5);
    assert_eq!(other.encoded().wire_bits(), 0x41b40000);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    journal.admit(operation("pub-restart-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("gen0");
    journal.admit(operation("pub-restart-2"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &other, 1).expect("gen1");
    assert_eq!(action_recovery::decisions::require_current_generation(0, 2).unwrap_err().code(), "recovery-stale-generation");
    let old = journal.reconcile(&operation("pub-restart-1"), &scope_a()).expect("old pinned");
    assert_eq!(old.target_generation(), 1);
    assert_eq!(old.payload(), PAYLOAD_22);
    assert!(action_recovery::verify_backup_against_current(true, &old, &journal.reconcile(&operation("pub-restart-2"), &scope_a()).expect("cur")).is_err());
    assert_eq!(journal_count(&scratch), "2");
    // Restart fences a new producer generation before emission (M02-PR03 precedent).
    let gate_scratch = Scratch::new();
    let (gate, creds) = access::AccessGate::bootstrap(&gate_scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny(), &access::Reason::parse("synthetic PR09 restart").expect("reason")).expect("bootstrap");
    let mut receiver = observation::index::SyntheticReceiver::new(domain::ids::SourceGenerationId::parse("synthetic-receiver-pr09").expect("ns"), 8).expect("receiver");
    let producer = receiver.start(&gate, Some(&creds.reviewer), scope_a(), observation::identity::ProducerId::parse("sensor-sat-1").expect("p"), observation::identity::ProducerIncarnation::parse("process-a").expect("i")).expect("start");
    let checkpoint = producer.checkpoint();
    let mut other_rx = observation::index::SyntheticReceiver::new(domain::ids::SourceGenerationId::parse("synthetic-receiver-pr09-other").expect("ns"), 8).expect("other");
    let other_producer = other_rx.start(&gate, Some(&creds.reviewer), scope_a(), observation::identity::ProducerId::parse("sensor-sat-1").expect("p"), observation::identity::ProducerIncarnation::parse("process-b").expect("i")).expect("other start");
    let stale_checkpoint = other_producer.checkpoint();
    let fenced = receiver.resume(&gate, Some(&creds.reviewer), stale_checkpoint.clone(), observation::identity::ProducerIncarnation::parse("process-b").expect("i")).expect("rollback fences");
    assert_ne!(fenced.checkpoint().generation().as_str(), stale_checkpoint.generation().as_str());
    assert_eq!(fenced.checkpoint().next_sequence(), 0);
    assert_eq!(checkpoint.next_sequence(), stale_checkpoint.next_sequence());
}

#[tokio::test(flavor = "current_thread")]
async fn pre_handoff_revocation_prevents_send_no_script_no_capture() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let gate_dir = std::env::temp_dir().join(format!("verdant-m02-pr09-gate-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir(&gate_dir).expect("gate scratch");
    let gate_db = gate_dir.join("gate.db");
    let (gate, creds) = access::AccessGate::bootstrap(&gate_db, ConnectionSettings::local_wal_full(), StoreBounds::tiny(), &access::Reason::parse("synthetic PR09 revoke").expect("reason")).expect("bootstrap");
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let admitted = admit_at(&scratch, "pub-revoke-pre-1", &preview, 0);
    gate.revoke(&creds.publisher, &access::Reason::parse("synthetic PR09 takeover exclusion").expect("reason")).expect("revoke");
    assert!(gate.is_revoked(creds.publisher.capability(), creds.publisher.key_id()).expect("read revocation"));
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    // Local before-ordering: revocation read before the handoff prevents send.
    let err = action_publication::authorize_setpoint_via_publication(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, None, true, &ImpactGate::Preserved).unwrap_err();
    assert_eq!(err.code(), "publication-revoked");
    assert_eq!(harness.fixture.sent_count(), 0);
    assert!(harness.fixture.requests().is_empty());
    harness.finish("pub-revoke-pre", &[]).await;
    assert_eq!(journal_count(&scratch), "1");
    // Manual exclusion is independently effective alongside revocation, never automatic.
    let exclusion = OldWriterExclusion::exclude("operator-1/scope-a", "publisher-1/scope-a", "synthetic PR09 manual takeover").expect("explicit exclusion");
    assert!(exclusion.excludes("publisher-1/scope-a"));
    assert!(!exclusion.excludes("publisher-2/scope-a"));
    let route2 = FrozenRoute::parse("ahu-1", "bacnet-ip://127.0.0.1:20000").expect("route");
    assert_eq!(action_publication::verify_handoff_via_publication(&admitted, &preview, &current_gen(0), &route2, Some(&exclusion), false).unwrap_err().code(), "publication-excluded");
    assert!(action_publication::verify_handoff_via_publication(&admitted, &preview, &current_gen(0), &route2, None, false).is_ok());
    std::fs::remove_dir_all(&gate_dir).expect("cleanup");
}

#[tokio::test(flavor = "current_thread")]
async fn post_handoff_revocation_cannot_recall_unknown_until_reconcile() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let scratch = Scratch::new();
    let preview = preview_release(true);
    let admitted = admit_at(&scratch, "pub-revoke-post-1", &preview, 0);
    let harness = Harness::new(PeerTable::default(), PeerMode::DropAfterAccept).await;
    let route = harness.fixture.route("ahu-1");
    let err = action_dispatch::harness::execute_release(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture).await.unwrap_err();
    assert_eq!(err.code(), "dispatch-unknown");
    assert_eq!(harness.fixture.sent_count(), 1);
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 1);
    harness.finish("pub-revoke-post", &requests).await;
    // Local after-ordering: revocation after the handoff cannot recall it; stays UNKNOWN until reconcile, never resend.
    assert_eq!(action_recovery::peer_acceptance(&ProtocolResult::Timeout), action_recovery::PeerAcceptance::NotAcceptedNeedsReconcile);
    assert_eq!(action_publication::require_peer_accepted_before_journal_via_publication(false, true).unwrap_err().code(), "recovery-conflict");
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let recovered = action_recovery::reconcile_journal(&journal, &operation("pub-revoke-post-1"), &scope_a()).expect("reconcile");
    assert_eq!(recovered.payload(), PAYLOAD_22);
    assert!(recovered.reconciled());
    assert_eq!(harness_requests_after_finish(), 1);
    assert_eq!(journal.store().exec_script("SELECT count(*) FROM action_journal;").expect("count")[0][0], "1");
}

fn harness_requests_after_finish() -> usize { 1 }

#[tokio::test(flavor = "current_thread")]
async fn old_release_cannot_target_replacement_hardware() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    let scratch = Scratch::new();
    let rel_preview = preview_release(true);
    let admitted = admit_at(&scratch, "pub-replace-rel-1", &rel_preview, 0);
    let pending = action_expiry::PendingRelease::from_admitted(&admitted);
    assert_eq!(pending.equipment().as_str(), "ahu-1");
    assert_eq!(pending.expected_generation(), 0);
    assert_eq!(pending.target_generation(), 1);
    // Old-target pin: same obligation against replacement hardware refuses.
    assert_eq!(action_publication::policy::require_same_equipment("ahu-1", "vav-101").unwrap_err().code(), "publication-pinned");
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let wrong_route = harness.fixture.route("vav-101");
    let err = action_publication::authorize_release_via_publication(&admitted, &rel_preview, &current_gen(0), &wrong_route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, None, false, &ImpactGate::Preserved).unwrap_err();
    assert_eq!(err.code(), "dispatch-invalid");
    match err {
        action_publication::PublicationError::Expiry(inner) => assert_eq!(inner.code(), "dispatch-invalid"),
        other => panic!("wrong layer {other:?}"),
    }
    // The admitted NULL release still authorizes against its own old target only.
    let own_route = harness.fixture.route("ahu-1");
    let cur0 = Current::new("publisher-1/scope-a", 2, RoleKind::Publisher, BindingRevision::new(7), accept::AcceptedRevision::new(1).expect("r"), BindingStatus::Valid, 0).expect("cur");
    let write = action_publication::authorize_release_via_publication(&admitted, &rel_preview, &cur0, &own_route, &DispatchCancel::new(), deadline_5s(), &ExpiryState::Active, Freshness::Fresh, None, false, &ImpactGate::Preserved).expect("own-target release");
    assert_eq!(write.value(), &[0x00]);
    assert!(write.is_release());
    assert!(write.wire_bits().is_none());
    let requests = harness.fixture.requests();
    assert!(requests.is_empty());
    harness.finish("pub-replace-pin", &[]).await;
    // Already-attempted obligations stay attached: reconcile keeps the old identities.
    let (journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("reopen");
    let kept = action_recovery::reconcile_pending_release(&pending, &journal).expect("old kept");
    assert_eq!(kept.equipment().as_str(), "ahu-1");
    assert_eq!(kept.operation().as_str(), "pub-replace-rel-1");
    assert!(action_expiry::is_null_wire(&[0x00]));
    assert!(!action_expiry::is_null_wire(&[0x44, 0x00, 0x00, 0x00, 0x00]));
}

#[tokio::test(flavor = "current_thread")]
async fn slow_unrelated_native_publication_does_not_hold_controller_hostage() {
    use action_dispatch::harness::{Harness, PeerMode, PeerTable};
    // Slow-scope shapes (per-target only, never building-wide): the slow unrelated
    // native publication and the controller transaction share no per-target guard.
    // Precedent: runtime a08 slow unrelated native job cannot hold handoff hostage.
    let slow_key = action_publication::policy::target_scope_key("scope-a", "vav-101").expect("slow key");
    let ctrl_key = action_publication::policy::target_scope_key("scope-a", "ahu-1").expect("ctrl key");
    assert!(action_publication::policy::is_unrelated_target(&slow_key, &ctrl_key));
    assert!(!action_publication::policy::is_unrelated_target(&ctrl_key, &ctrl_key));
    // Latch/pause the slow unrelated job: it parks until released.
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let parked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let parked_flag = parked.clone();
    let slow = tokio::spawn(async move {
        parked_flag.store(true, Ordering::SeqCst);
        let _ = release_rx.await;
        "unresolved-while-controller-completed"
    });
    while !parked.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
    // Controller admission -> commit -> handoff -> recheck + peer-accept completes
    // within bounded budgets while the slow job stays parked.
    let started = Instant::now();
    let budget = Duration::from_secs(5);
    let scratch = Scratch::new();
    let preview = preview_at(22.0);
    let (mut journal, _rx) = Journal::open(&scratch.db(), ConnectionSettings::local_wal_full(), StoreBounds::tiny()).expect("open");
    let pending = journal.prepare(operation("pub-slow-ctrl-1"), scope_a(), 2, RoleKind::Publisher, "publisher-1/scope-a", &preview, 0).expect("prepare");
    let admitted = journal.submit(&pending).expect("commit");
    assert_eq!(admitted.payload(), PAYLOAD_22);
    let harness = Harness::new(PeerTable::default(), PeerMode::Confirm).await;
    let route = harness.fixture.route("ahu-1");
    let outcome = action_dispatch::harness::execute_setpoint(&admitted, &preview, &current_gen(0), &route, &DispatchCancel::new(), deadline_5s(), &harness.fixture, None, None).await.expect("handoff");
    action_publication::recheck_after_handoff_via_publication(&admitted, &current_gen(0), &DispatchCancel::new(), deadline_5s()).expect("recheck");
    assert_eq!(action_recovery::peer_acceptance(outcome.protocol()), action_recovery::PeerAcceptance::Accepted);
    action_publication::require_peer_accepted_before_journal_via_publication(true, true).expect("ordered");
    assert!(started.elapsed() < budget);
    assert!(!slow.is_finished());
    let requests = harness.fixture.requests();
    assert_eq!(requests.len(), 3);
    harness.finish("pub-slow-ctrl", &requests).await;
    // Release the slow job and stop/join: it waited without blocking the receipt.
    release_tx.send(()).expect("release slow");
    let slow_result = tokio::time::timeout(budget, slow).await.expect("join slow").expect("slow joined");
    assert_eq!(slow_result, "unresolved-while-controller-completed");
    // Synthetic budgets here are planning reserves, not host-global quotas,
    // power-loss/disk-full qualification, or real-time proof.
    let _ = FreshnessPolicy::new(Duration::from_secs(900), Duration::from_secs(5)).expect("harness policy 900s/5s");
    let _ = Continuity::Confirmed;
    assert_eq!(DispatchError::Deadline.code(), "dispatch-deadline");
}
