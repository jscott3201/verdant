//! R07 seam evidence. Writer rows and synthetic decode vectors are separate:
//! no raw DB mutation is used to manufacture an observed-qualified row.
use super::*;
use binding::{Finding, PendingProposal, ProposedBinding};
use domain::clock::UnixMillis;
use domain::ids::{BindingRevision, OperationId};

fn conversion(slot: &str, mode: Option<OpMode>) -> semantics::convert::Binding {
    let value = mode.map(Value::Mode).unwrap_or(Value::Missing);
    let item = ExternalItem::parse("ext-ahu-1", SUPPORTED_AHU_CLASS, slot, "VAV", "degC", value)
        .expect("external fixture");
    import_site(&ExternalSite::new(vec![item]).unwrap(), &Profile::pinned())
        .unwrap()
        .bindings()[0]
        .clone()
}

fn canonical(mode: &str, role: &str, feedback: &str, status: &str) -> String {
    // Independent literal layout (not ProposedBinding::canonical_bytes).
    format!("binding-canonical-v2\x1fmstp://ahu-1\x1flocation\x1fscope-a\x1fahu-1\x1fsupply-air-temp\x1fscope-a\x1fsensor-sat-1\x1fdegC\x1f{mode}\x1f{role}\x1f{role}\x1f{feedback}\x1f{status}")
}

fn proposal_fields(mode: &str, role: &str, feedback: &str, status: &str) -> String {
    format!("v=2;kind=propose;endpoint=mstp://ahu-1;eclass=location;escope=scope-a;equipment=ahu-1;property=supply-air-temp;pscope=scope-a;source=sensor-sat-1;unit=degC;mode={mode};requested={role};effective={role};feedback={feedback};status={status}")
}

fn with_status(binding: &ProposedBinding, status: BindingStatus) -> ProposedBinding {
    ProposedBinding::from_import(
        binding.endpoint().clone(),
        binding.endpoint_class(),
        binding.endpoint_scope().clone(),
        binding.point_equipment().clone(),
        binding.point_property().clone(),
        binding.point_scope().clone(),
        binding.source().clone(),
        binding.unit().clone(),
        binding.mode().cloned(),
        binding.requested(),
        binding.effective(),
        binding.feedback(),
        status,
    )
}

pub(super) fn assert_writer_separation_and_fidelity() {
    let scratch = Scratch::new("r07-separation");
    let (gate, creds) = open_gate(&scratch, "seam.db");
    let mut registry = open_registry(&scratch, "seam.db");
    seed_tiny(&mut registry);
    let report = gate
        .enter_publish(Some(&creds.publisher), &scope_a())
        .unwrap();
    let actor = report.actor();
    let actor_text = format!(
        "capability={};scope=scope-a;capgen={};issuer={}",
        actor.capability(),
        actor.cap_generation(),
        actor.issuer()
    );
    let mut expected_bindings = Vec::new();
    let mut expected_findings = Vec::new();
    // Exhaust the two credentialed proposal/import entry paths, both role
    // branches, and both mode-decode branches. All use conversion-sourced data.
    for (role, role_text, feedback, feedback_text) in [
        (BindingRole::Sense, "sense", Feedback::Absent, "absent"),
        (
            BindingRole::Drive,
            "drive",
            Feedback::Single(BindingRole::Drive),
            "drive",
        ),
    ] {
        for (mode, mode_text) in [(None, "-"), (Some(OpMode::Standby), "standby")] {
            let converted = conversion("ahu-1", mode.clone());
            for status in [BindingStatus::Valid, BindingStatus::Imported] {
                let revision = registry.revision();
                let proposed = match status {
                    BindingStatus::Valid => registry.propose_with_credential(
                        &gate,
                        Some(&creds.publisher),
                        "mstp://ahu-1",
                        EndpointClass::Location,
                        scope_a(),
                        converted.verdant_id().as_str(),
                        "supply-air-temp",
                        "sensor-sat-1",
                        converted.unit().clone(),
                        semantics::convert::mode_of(converted.value()).cloned(),
                        role,
                        role,
                        feedback,
                    ),
                    BindingStatus::Imported => registry.import_with_credential(
                        &gate,
                        Some(&creds.publisher),
                        &converted,
                        revision,
                        "mstp://ahu-1",
                        EndpointClass::Location,
                        scope_a(),
                        "supply-air-temp",
                        "sensor-sat-1",
                        role,
                        role,
                        feedback,
                    ),
                    BindingStatus::ObservedQualified => panic!("not a writer-produced status"),
                }
                .expect("guarded writer");
                assert_eq!(proposed.status(), status);
                assert!(!proposed.status().is_observed_qualified());
                let expected_bytes =
                    canonical(mode_text, role_text, feedback_text, status.as_str());
                assert_eq!(proposed.canonical_bytes(), expected_bytes);
                let rows = registry.read_descriptors().unwrap();
                let row = rows.last().unwrap();
                assert_eq!(row.operation, "binding-propose");
                assert_eq!(row.entity, "ahu-1");
                let map = binding::split_descriptor(&row.descriptor).unwrap();
                let operation = OperationId::parse(&map["operation"]).unwrap();
                let expected_descriptor = format!(
                    "{};operation={};revision={};{actor_text}",
                    proposal_fields(mode_text, role_text, feedback_text, status.as_str()),
                    operation.as_str(),
                    revision.as_u32()
                );
                assert_eq!(row.descriptor, expected_descriptor);
                assert_eq!(
                    row.value_json,
                    format!("{{\"type\":\"text\",\"value\":\"{expected_descriptor}\"}}")
                );
                assert_eq!(binding::history::decode_propose(&map).unwrap(), proposed);
                // Receipt reconciliation uses decode_propose too. Both receipt
                // APIs return identical fields and cannot append a second row.
                let pending = PendingProposal::new(operation, revision, proposed.clone());
                let commit = registry.reconcile_proposal(&pending).unwrap().unwrap();
                assert_eq!(commit.binding, proposed);
                assert_eq!(commit.row_id, row.id);
                assert_eq!(commit.revision.as_u32(), revision.as_u32() + 1);
                assert_eq!(
                    registry
                        .submit_proposal(&gate, Some(&creds.publisher), &pending)
                        .unwrap(),
                    commit
                );
                assert_eq!(registry.read_descriptors().unwrap(), rows);

                let finding_revision = registry.revision();
                let finding = registry
                    .emit_finding(&gate, &proposed, &creds.publisher)
                    .unwrap();
                let expected_summary = format!(
                    "binding ahu-1:supply-air-temp {} [degC] rev {} actor {actor_text}",
                    status.as_str(),
                    finding_revision.as_u32()
                );
                assert_eq!(finding.summary(), expected_summary);
                assert!(!finding.summary().contains("observed-qualified"));
                assert_eq!(
                    finding,
                    Finding::for_binding(&proposed, finding_revision, &actor_text)
                );
                let finding_rows = registry.read_descriptors().unwrap();
                let finding_row = finding_rows.last().unwrap();
                let fields = binding::split_descriptor(&finding_row.descriptor).unwrap();
                assert_eq!(fields["summary"], expected_summary);
                assert_eq!(fields["binding"], expected_bytes);
                assert_eq!(fields["fid"], finding.id().as_str());
                assert_eq!(fields["digest"], finding.digest());
                assert_eq!(fields["generation"], finding_revision.as_u32().to_string());
                assert_eq!(fields["revision"], fields["generation"]);
                let operation = OperationId::parse(&fields["operation"]).unwrap();
                // Independent descriptor layout and escaping for these ASCII
                // fixtures, not the writer's percent/JSON encoder.
                let escaped_summary = expected_summary.replace('=', "%3D").replace(';', "%3B");
                let escaped_binding = expected_bytes.replace('\x1f', "%1F");
                let rev = finding_revision.as_u32();
                let expected_finding_descriptor = format!(
                    "v=2;kind=finding;operation={};fid={};generation={rev};revision={rev};digest={};summary={escaped_summary};{actor_text};equipment=ahu-1;property=supply-air-temp;binding={escaped_binding}",
                    operation.as_str(), finding.id().as_str(), finding.digest());
                assert_eq!(finding_row.operation, "binding-finding");
                assert_eq!(finding_row.entity, "ahu-1");
                assert_eq!(finding_row.descriptor, expected_finding_descriptor);
                assert_eq!(
                    finding_row.value_json,
                    format!("{{\"type\":\"text\",\"value\":\"{expected_finding_descriptor}\"}}")
                );
                assert_eq!(
                    registry
                        .emit_finding_operation(
                            &operation,
                            finding_revision,
                            &gate,
                            &proposed,
                            &creds.publisher
                        )
                        .unwrap(),
                    finding
                );
                assert_eq!(registry.read_descriptors().unwrap(), finding_rows);
                println!("R07 writer {:?}: {}", status, row.descriptor);
                println!("R07 finding: {}", finding_row.descriptor);
                expected_bindings.push(proposed);
                expected_findings.push(finding);
            }
        }
    }
    let rows = registry.read_descriptors().unwrap();
    assert_eq!(rows.len(), 24, "8 seed records + 8 proposals + 8 findings");
    assert_eq!(expected_bindings.len(), 8);
    assert_eq!(expected_findings.len(), 8);
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row.sequence, index as u64 + 1);
    }
    let revision = registry.revision();
    registry.replay_full().unwrap();
    assert_eq!(registry.bindings(), expected_bindings);
    assert_eq!(registry.findings(), expected_findings);
    assert_eq!(registry.revision(), revision);
    let window = registry.replay_window(UnixMillis::new(0), 64).unwrap();
    assert!(!window.stale);
    assert_eq!(
        window.rows, rows,
        "bounded decoder preserves every row byte"
    );
    let opened_window = BindingRegistry::open_window(
        &scratch.db("seam.db"),
        storage::ConnectionSettings::local_wal_full(),
        storage::StoreBounds::tiny(),
        UnixMillis::new(0),
        64,
    )
    .unwrap();
    assert_eq!(opened_window, window);
    drop(registry);
    let mut reopened = open_registry(&scratch, "seam.db");
    assert_eq!(reopened.bindings(), expected_bindings);
    assert_eq!(reopened.findings(), expected_findings);
    assert_eq!(reopened.revision(), revision);
    assert_eq!(reopened.read_descriptors().unwrap(), rows);
    // Even an in-memory, caller-manufactured status cannot pass a new writer
    // operation. This exercises the real guard, NOT raw-DB tampering.
    let forged = with_status(&expected_bindings[0], BindingStatus::ObservedQualified);
    let pending = PendingProposal::new(
        OperationId::parse("r07-static-qualified").unwrap(),
        revision,
        forged.clone(),
    );
    for error in [
        reopened
            .submit_proposal(&gate, Some(&creds.publisher), &pending)
            .unwrap_err(),
        reopened
            .emit_finding(&gate, &forged, &creds.publisher)
            .unwrap_err(),
    ] {
        assert!(
            matches!(error, binding::BindingError::Conflict { ref detail }
            if detail == "static proposal cannot claim observed qualification")
        );
    }
    assert_eq!(reopened.read_descriptors().unwrap(), rows);
    println!("R07 fidelity: 8 proposals + 8 findings; full/reopen/window/open-window/receipt exact; observed-qualified writer refusals=2; rows unchanged=24");
}

#[test]
fn every_status_decode_and_summary_is_faithful_in_both_directions() {
    let scratch = Scratch::new("r07-decode-vectors");
    let mut registry = open_registry(&scratch, "vectors.db");
    let base = binding::propose(
        binding::EndpointAddress::parse("mstp://ahu-1").unwrap(),
        EndpointClass::Location,
        scope_a(),
        domain::ids::InstalledId::parse("ahu-1").unwrap(),
        binding::PropertyName::parse("supply-air-temp").unwrap(),
        scope_a(),
        domain::ids::InstalledId::parse("sensor-sat-1").unwrap(),
        &unit("degC"),
        EndpointClass::Location,
        unit("degC"),
        Some(OpMode::Standby),
        BindingRole::Sense,
        BindingRole::Sense,
        Feedback::Absent,
    )
    .unwrap();
    // OQ is a synthetic representation vector only; no current writer mints it.
    // These vectors cover the decoder shared by replay and receipt recovery.
    for (status, text) in [
        (BindingStatus::Imported, "imported"),
        (BindingStatus::Valid, "valid"),
        (BindingStatus::ObservedQualified, "observed-qualified"),
    ] {
        let expected = with_status(&base, status);
        let descriptor = format!("{};operation=r07-vector;revision=7;capability=publisher;scope=scope-a;capgen=1;issuer=local",
            proposal_fields("standby", "sense", "absent", text));
        let map = binding::split_descriptor(&descriptor).unwrap();
        let decoded = binding::history::decode_propose(&map).unwrap();
        assert_eq!(decoded, expected, "no upgrade, downgrade or field drift");
        assert_eq!(
            decoded.canonical_bytes(),
            canonical("standby", "sense", "absent", text)
        );
        assert_eq!(decoded.status().as_str(), text);
        registry.replay_propose(&map).unwrap();
        assert_eq!(registry.bindings().last(), Some(&expected));
        let actor = "capability=publisher;scope=scope-a;capgen=1;issuer=local";
        let finding = Finding::for_binding(&decoded, BindingRevision::new(7), actor);
        let summary = format!("binding ahu-1:supply-air-temp {text} [degC] rev 7 actor {actor}");
        assert_eq!(finding.summary(), summary);
        let mut fields = binding::split_descriptor(actor).unwrap();
        for (key, value) in [
            ("fid", finding.id().as_str()),
            ("generation", "7"),
            ("revision", "7"),
            ("digest", finding.digest()),
            ("summary", summary.as_str()),
            ("equipment", "ahu-1"),
            ("property", "supply-air-temp"),
        ] {
            fields.insert(key.into(), value.into());
        }
        registry.replay_finding(&fields).unwrap();
        assert_eq!(registry.findings().last(), Some(&finding));
        println!(
            "R07 decode vector {text}: {}; summary={summary}",
            decoded.canonical_bytes()
        );
    }
    // Only in-memory vectors were decoded; no synthetic qualification persisted.
    assert!(registry.read_descriptors().unwrap().is_empty());
}

#[test]
fn ahu_9_conversion_does_not_create_recorded_point_truth() {
    let scratch = Scratch::new("r07-ahu9");
    let (gate, creds) = open_gate(&scratch, "ahu9.db");
    let mut registry = open_registry(&scratch, "ahu9.db");
    seed_tiny(&mut registry);
    let converted = conversion("ahu-9", None);
    assert_eq!(converted.verdant_id().as_str(), "ahu-9");
    let before = registry.read_descriptors().unwrap();
    let revision = registry.revision();
    let error = registry
        .import_with_credential(
            &gate,
            Some(&creds.publisher),
            &converted,
            revision,
            "mstp://ahu-9",
            EndpointClass::Location,
            scope_a(),
            "supply-air-temp",
            "sensor-sat-1",
            BindingRole::Sense,
            BindingRole::Sense,
            Feedback::Absent,
        )
        .unwrap_err();
    assert!(
        matches!(error, binding::BindingError::InvalidRecord { ref detail }
        if detail == "unknown point 'ahu-9:supply-air-temp'; record the point before importing")
    );
    assert_eq!(registry.revision(), revision);
    assert!(registry.equipment("ahu-9").is_none());
    assert_eq!(registry.read_descriptors().unwrap(), before);
}
