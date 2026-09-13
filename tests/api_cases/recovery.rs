use crate::{access::*, api, domain, fixture::*, operations::*, support};
use api::RecoveryAction;

fn credential(capability: &str, key_id: &str, key: &str) -> Credential {
    Credential::new(
        CapabilityName::parse(capability).unwrap(),
        KeyId::parse(key_id).unwrap(),
        SyntheticKey::parse(key).unwrap(),
    )
}

#[test]
fn fixed_recovery_scope_proof_rebootstrap_rotation_and_non_escalation() {
    let mut f = Fixture::new();
    let key_id = KeyId::parse("recovery-key-1").unwrap();
    let key = SyntheticKey::parse("synthetic-recovery-secret").unwrap();
    let provision = operation("api-provision-recovery");
    let recovery = with_api(&mut f, |api, owner| {
        api.provision_recovery(Some(owner), &scope(), &provision, &key_id, &key)
            .unwrap()
    });
    let counts = support::counts(&f);
    let bytes = support::bytes(&f);
    with_api(&mut f, |api, owner| {
        assert_eq!(
            api.provision_recovery(Some(owner), &scope(), &provision, &key_id, &key)
                .unwrap(),
            recovery
        );
    });
    assert_eq!(support::counts(&f), counts);
    assert_eq!(support::bytes(&f), bytes);
    let actor = f.gate.authenticate(Some(&recovery), &scope()).unwrap();
    assert_eq!(actor.policy().administrative_scopes(), &[scope()]);
    assert_eq!(actor.policy().administrative_ceiling(), Some(2));
    assert_eq!(actor.role(), RoleKind::Reviewer);
    let replacement = credential(
        "recovered-publisher",
        "recovered-key",
        "synthetic-replacement-secret",
    );
    let recover_op = operation("api-rebootstrap-scope");
    let recovered = with_api(&mut f, |api, _| {
        api.recover(
            Some(&recovery),
            &scope(),
            &recover_op,
            RecoveryAction::Rebootstrap {
                replacement: &replacement,
            },
        )
        .unwrap()
    });
    let counts = support::counts(&f);
    let bytes = support::bytes(&f);
    with_api(&mut f, |api, _| {
        assert_eq!(
            api.recover(
                Some(&recovery),
                &scope(),
                &recover_op,
                RecoveryAction::Rebootstrap {
                    replacement: &replacement
                }
            )
            .unwrap(),
            recovered
        )
    });
    assert_eq!(support::counts(&f), counts);
    assert_eq!(support::bytes(&f), bytes);
    let actor = f.gate.authenticate(Some(&recovered), &scope()).unwrap();
    assert_eq!(actor.policy(), &CapabilityPolicy::entry_only(None));
    assert_eq!(actor.role(), RoleKind::Publisher);
    assert_eq!(f.gate.bootstrap_reason().unwrap(), "PR11 synthetic fixture");

    let input = content(&mut f, "recovery cannot publish");
    let publication = publication(&f);
    let before = (support::counts(&f), support::bytes(&f));
    let foreign = domain::scope::TrustedScope::parse("scope-b").unwrap();
    with_api(&mut f, |api, _| {
        let op = operation("api-denied-recovery");
        assert_eq!(
            api.draft(Some(&recovery), &op, &input).unwrap_err().code(),
            "api-recovery-restricted"
        );
        assert_eq!(
            api.read(Some(&recovery), &scope(), &op).unwrap_err().code(),
            "api-recovery-restricted"
        );
        assert_eq!(
            api.seal(Some(&recovery), &scope(), &op, &op, &publication)
                .unwrap_err()
                .code(),
            "api-recovery-restricted"
        );
        assert_eq!(
            api.submit_accept(Some(&recovery), &scope(), &op)
                .unwrap_err()
                .code(),
            "api-recovery-restricted"
        );
        assert_eq!(
            api.recover(
                Some(&recovery),
                &foreign,
                &op,
                RecoveryAction::Rebootstrap {
                    replacement: &replacement
                }
            )
            .unwrap_err()
            .code(),
            "scope-denied"
        );
        assert_eq!(
            api.recover(
                Some(&recovered),
                &scope(),
                &op,
                RecoveryAction::Rebootstrap {
                    replacement: &replacement
                }
            )
            .unwrap_err()
            .code(),
            "api-recovery-restricted"
        );
        assert_eq!(
            api.provision_recovery(Some(&recovered), &scope(), &op, &key_id, &key)
                .unwrap_err()
                .code(),
            "administration-denied"
        );
        assert_eq!(
            api.recover(
                None,
                &scope(),
                &op,
                RecoveryAction::Rebootstrap {
                    replacement: &replacement
                }
            )
            .unwrap_err()
            .code(),
            "api-unauthenticated"
        );
        // Recovery's closed action enum has only rebootstrap/rotate; it accepts
        // no SQL, executable, field action, policy, ceiling, or requested role.
        let status = api.status(Some(&recovered), &scope()).unwrap();
        assert_eq!(status.field_authority, api::Readiness::Unsupported);
        assert_eq!(status.qualification, api::Readiness::Unsupported);
    });
    // Existing access policy is defense in depth even below the API: it cannot
    // mint cross-scope authority, increase the ceiling, or delegate broader policy.
    let name = CapabilityName::parse("denied-child").unwrap();
    let reason = Reason::parse("synthetic denied recovery escalation").unwrap();
    let label = DisplayLabel::parse("synthetic denied").unwrap();
    assert_eq!(
        f.gate
            .issue(
                &name,
                &foreign,
                2,
                RoleKind::Publisher,
                &key_id,
                &key,
                &recovery,
                &reason,
                &label
            )
            .unwrap_err()
            .code(),
        "scope-denied"
    );
    assert_eq!(
        f.gate
            .issue(
                &name,
                &scope(),
                3,
                RoleKind::Publisher,
                &key_id,
                &key,
                &recovery,
                &reason,
                &label
            )
            .unwrap_err()
            .code(),
        "ceiling-exceeded"
    );
    assert_eq!(
        f.gate
            .issue_with_policy(
                &name,
                &scope(),
                2,
                RoleKind::Publisher,
                &key_id,
                &key,
                &recovery,
                &reason,
                &label,
                &CapabilityPolicy::administrator(vec![scope(), foreign], 2, None).unwrap()
            )
            .unwrap_err()
            .code(),
        "policy-denied"
    );
    assert_eq!((support::counts(&f), support::bytes(&f)), before);
    assert!(support::events(&f).is_empty());

    let rotate_op = operation("api-rotate-recovery");
    let next_id = KeyId::parse("recovery-key-2").unwrap();
    let next_key = SyntheticKey::parse("synthetic-next-recovery-secret").unwrap();
    let next = with_api(&mut f, |api, _| {
        api.recover(
            Some(&recovery),
            &scope(),
            &rotate_op,
            RecoveryAction::Rotate {
                key_id: &next_id,
                key: &next_key,
            },
        )
        .unwrap()
    });
    assert!(f
        .gate
        .is_revoked(recovery.capability(), recovery.key_id())
        .unwrap());
    let counts = support::counts(&f);
    let bytes = support::bytes(&f);
    with_api(&mut f, |api, _| {
        assert_eq!(
            api.recover(
                Some(&recovery),
                &scope(),
                &rotate_op,
                RecoveryAction::Rotate {
                    key_id: &next_id,
                    key: &next_key
                }
            )
            .unwrap(),
            next
        )
    });
    assert_eq!(support::counts(&f), counts);
    assert_eq!(support::bytes(&f), bytes);
    assert_eq!(
        f.gate.authenticate(Some(&next), &scope()).unwrap().policy(),
        &CapabilityPolicy::administrator(vec![scope()], 2, None).unwrap()
    );
    let rows = f
        .registry
        .store()
        .exec_script("SELECT value_json FROM outbox WHERE operation='api-intent-v1';")
        .unwrap();
    assert!(!format!("{rows:?}").contains("synthetic-recovery-secret"));
    assert!(!format!("{rows:?}").contains("synthetic-replacement-secret"));
    assert!(!format!("{rows:?}").contains("synthetic-next-recovery-secret"));
    println!("FIXED: restricted recovery provisioning, rebootstrap and rotation reconcile; 11 cannot-cases preserve rows/events/bytes, bootstrap untouched, no raw secrets in journal");
}
