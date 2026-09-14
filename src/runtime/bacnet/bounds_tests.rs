//! Additional finite fixture boundaries, not live transport qualification.
use super::*;
fn advertisement(instance: u32, host: u8) -> Advertisement {
    Advertisement {
        target: DirectTarget::parse("realm-a", &format!("bacnet-ip://127.0.0.{host}:47808")).unwrap(),
        instance,
        max_apdu: 480,
        segmentation: 3,
        vendor: 7,
    }
}
#[test]
fn b03_candidate_and_conflict_bounds_refuse_without_erasing_history() {
    let budget = Arc::new(Budget::default());
    let mut quarantine = quarantine::Quarantine::new(budget.clone());
    let now = Instant::now();
    for instance in 0..MAX_CANDIDATES as u32 {
        quarantine.observe(advertisement(instance, 2), now).unwrap();
    }
    assert_eq!(budget.usage().retained, [0, 0, 16]);
    assert_eq!(quarantine.observe(advertisement(99, 2), now), Err(Error::QuarantineFull));
    for host in 3..=5 {
        quarantine.observe(advertisement(0, host), now).unwrap();
    }
    assert_eq!(quarantine.observe(advertisement(0, 6), now), Err(Error::QuarantineFull));
    let expired = quarantine.snapshot(now + CANDIDATE_TTL);
    assert_eq!(expired[0].advertisements.len(), 4);
    assert!(expired.iter().all(|candidate| candidate.expired));
    quarantine.observe(advertisement(0, 2), now + CANDIDATE_TTL).unwrap();
    assert!(!quarantine.snapshot(now + CANDIDATE_TTL)[0].expired);
    quarantine.clear();
    assert_eq!(budget.usage().retained, [0; 3]);
}
#[test]
fn b07_fake_script_count_and_payload_bounds_refuse() {
    let peer = fake::ScriptedPeer::default();
    for _ in 0..fake::MAX_SCRIPTS {
        peer.push(fake::Script::Silence).unwrap();
    }
    assert_eq!(peer.push(fake::Script::Silence), Err(Error::Budget));
    let oversized = fake::Reply { source: advertisement(0, 2).target, npdu: vec![0; MAX_NPDU_BYTES + 1] };
    assert_eq!(
        fake::ScriptedPeer::default().push(fake::Script::Replies(vec![oversized])),
        Err(Error::Oversized)
    );
}
