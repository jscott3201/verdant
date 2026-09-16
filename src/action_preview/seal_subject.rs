//! Seal subject rebind: clear-on-subject-change (Slice E G4), factored out of
//! `preview.rs` so that file does not grow.
//!
//! `SealOrder::check_custody_with` replaces the held profile/ledger. The
//! decode/reconstruct/verified flags are proofs about the PREVIOUS subject;
//! keeping them across a subject change would let `is_verified` report the
//! new profile with the old proof (mixed digest). The owner decision is
//! clear-on-subject-change, not reject-rebind: rebinding the SAME profile
//! keeps prior progress, rebinding a DIFFERENT profile clears the proof
//! flags (custody stays true, the new profile/ledger are stored). Failure
//! ordering is unchanged: a refused `ledger_status` returns before any
//! mutation, preserving the real `s03-*` codes via `From` in `preview.rs`.

use crate::semantics::sealed_profile::Profile;

/// Rebind seal custody to `incoming` with `ledger_bytes`, clearing stale
/// proof on subject change. All slots are the `SealOrder` private fields
/// passed by `preview.rs` (this sibling cannot name them, so it borrows
/// them); the ledger-availability check stays in `preview.rs` and runs
/// before this call, so refusal never mutates.
pub fn rebind_custody(
    profile_slot: &mut Option<Profile>,
    ledger_slot: &mut Option<Vec<u8>>,
    decoded: &mut bool,
    reconstructed: &mut bool,
    verified: &mut bool,
    custody: &mut bool,
    incoming: &Profile,
    ledger_bytes: &[u8],
) {
    if subject_changed(profile_slot.as_ref(), incoming) {
        // Prior decode/reconstruct/verified proofs belong to the old subject
        // and must not survive the rebind (no mixed digest).
        *decoded = false;
        *reconstructed = false;
        *verified = false;
    }
    *custody = true;
    *profile_slot = Some(incoming.clone());
    *ledger_slot = Some(ledger_bytes.to_vec());
}

/// Subject comparison: the held profile versus the incoming one. `None` held
/// (first custody) counts as a change from nothing, which only clears
/// already-false flags — a no-op for single-custody flows.
pub fn subject_changed(held: Option<&Profile>, incoming: &Profile) -> bool {
    held != Some(incoming)
}
