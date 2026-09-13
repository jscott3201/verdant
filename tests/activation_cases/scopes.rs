use crate::helpers::*;
use crate::{access, binding, domain, seal};

#[test]
fn two_scopes_have_independent_pointers_and_availability_blocks() {
    let mut f = Fixture::new();
    let (store, a) = accepted(&mut f, "scope-a", Revision::INITIAL);
    let b_scope = domain::scope::TrustedScope::parse("scope-b").unwrap();
    let b_credential = f.gate.issue(
        &access::CapabilityName::parse("publisher-scope-b").unwrap(), &b_scope, 2,
        access::RoleKind::Publisher, &access::KeyId::parse("key-scope-b").unwrap(),
        &access::SyntheticKey::parse("synthetic-pr08b-scope-b").unwrap(),
        &f.credentials.publisher, &access::Reason::parse("synthetic scope-b activation fixture").unwrap(),
        &access::DisplayLabel::parse("synthetic scope-b publisher").unwrap(),
    ).unwrap();
    f.registry.record_equipment("vav-101", binding::EquipmentKind::Vav,
        b_scope.clone(), "VAV", "mstp://vav-101").unwrap();
    f.registry.record_point("vav-101", "supply-air-temp", b_scope.clone(),
        "degC", binding::EndpointClass::Location).unwrap();
    let binding = binding::ProposedBinding::from_import(
        binding::EndpointAddress::parse("mstp://vav-101").unwrap(),
        binding::EndpointClass::Location, b_scope.clone(),
        domain::ids::InstalledId::parse("vav-101").unwrap(),
        binding::PropertyName::parse("supply-air-temp").unwrap(), b_scope.clone(),
        domain::ids::InstalledId::parse("sensor-sat-1").unwrap(),
        domain::values::Unit::parse("degC").unwrap(), None,
        binding::BindingRole::Sense, binding::BindingRole::Sense,
        binding::Feedback::Absent, binding::BindingStatus::Valid,
    );
    f.registry.submit_proposal(&f.gate, Some(&b_credential),
        &binding::PendingProposal::new(operation("proposal-scope-b"), f.registry.revision(), binding.clone())).unwrap();
    f.registry.emit_finding_operation(&operation("finding-scope-b"), f.registry.revision(),
        &f.gate, &binding, &b_credential).unwrap();
    let seq = f.registry.store().exec_script(
        "SELECT seq FROM outbox WHERE operation='binding-finding' ORDER BY id DESC LIMIT 1;",
    ).unwrap()[0][0].parse().unwrap();
    let config = accept::EffectiveConfig::resolve(&f.gate, &mut f.registry, b_scope.clone(),
        vec![accept::Entry::new(domain::ids::InstalledId::parse("sat-binding").unwrap(),
            "VAV supply air", binding).unwrap()], vec![]).unwrap();
    let staged = store.stage(&operation("accept-stage-scope-b"), config,
        vec![row(binding::OP_FINDING_TEXT, seq)]).unwrap();
    let draft = seal::Draft::new(f.registry.revision(), b_scope.clone(),
        seal::RuntimeRef::new("synthetic-pr08b", "synthetic-macos-arm64-debug").unwrap(),
        vec![staged.root().unwrap()], vec![f.reference.clone()]).unwrap();
    let seal = f.seals.seal(&operation("seal-scope-b"), &draft,
        &mut f.registry, &f.gate, &b_credential).unwrap();
    let sealed = store.sealed(&staged, &seal.identity, &f.seals).unwrap();
    let pending = store.prepare(operation("accept-scope-b"), Revision::INITIAL, &sealed,
        &f.seals, &mut f.registry, &f.gate, &b_credential).unwrap();
    let b = store.submit(&pending, &f.seals).unwrap();
    let a_request = request("activate-scope-a", Generation::INITIAL, &a);
    let b_request = request("activate-scope-b", Generation::INITIAL, &b);
    let a_pending = store.prepare_activation(a_request.clone(), &f.seals).unwrap();
    let b_pending = store.prepare_activation(b_request.clone(), &f.seals).unwrap();
    let a_active = store.submit_activation(&a_pending, &f.seals).unwrap();
    let b_active = store.submit_activation(&b_pending, &f.seals).unwrap();
    assert_eq!(a_active.generation().get(), 1);
    assert_eq!(b_active.generation().get(), 1);
    assert_eq!(a_active.revision().get(), 1);
    assert_eq!(b_active.revision().get(), 1);
    assert_ne!(a_active.row_id(), b_active.row_id());
    f.release("release-scope-a", a.request.seal()).unwrap();
    let before = snapshot(&f);
    assert!(matches!(store.activate(&a_request, &f.seals),
        Err(Error::ActivationBlocked { scope: affected, .. }) if affected == scope()));
    assert_eq!(store.activate(&b_request, &f.seals).unwrap().row_id(), b_active.row_id());
    assert_eq!(store.active(&scope()).unwrap().unwrap().row_id(), a_active.row_id());
    assert_eq!(store.active(&b_scope).unwrap().unwrap().row_id(), b_active.row_id());
    assert_eq!(before, snapshot(&f));
    println!("FIXED same DB two scopes: active generations=1,1 revisions=1,1 events=2; released scope-a blocked, scope-b replay succeeds; no rollback or byte changes");
}
