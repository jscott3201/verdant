pub(crate) use crate::accept::{
    self, Accepted, AcceptedRevision as Revision, ActivationRequest, ActiveGeneration as Generation,
    Error, Stage,
};
pub use crate::fixture::*;
pub use crate::support::*;

pub fn accepted(f: &mut Fixture, tag: &str, expected: Revision) -> (accept::AcceptanceStore, Accepted) {
    let (store, sealed) = publish(f, tag, tag);
    let pending = prepare(f, &store, &sealed, &format!("accept-{tag}"), expected);
    let accepted = store.submit(&pending, &f.seals).unwrap();
    (store, accepted)
}
pub fn request(tag: &str, expected: Generation, accepted: &Accepted) -> ActivationRequest {
    ActivationRequest::new(operation(tag), expected, accepted.request.clone())
}
pub fn active_events(f: &Fixture) -> Vec<Vec<String>> {
    f.registry.store().exec_script("SELECT id,seq,value_json FROM outbox WHERE operation='accept-active-v1' ORDER BY id;").unwrap()
}
pub fn snapshot(f: &Fixture) -> (Vec<Vec<String>>, Vec<Vec<String>>, Vec<(String, Option<Vec<u8>>)>) {
    (active_events(f), counts(f), bytes(f))
}
pub fn one_effect(before: &[Vec<String>], after: &[Vec<String>]) {
    for col in [0, 1] {
        assert_eq!(after[0][col].parse::<u64>().unwrap(), before[0][col].parse::<u64>().unwrap() + 1);
    }
    assert_eq!(after[0][2], before[0][2]);
}

pub const WAIT: std::time::Duration = std::time::Duration::from_secs(30);
