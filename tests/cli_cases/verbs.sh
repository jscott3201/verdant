#!/usr/bin/env bash
# Invoked by cli_setup.rs with already-created, isolated synthetic owners.
# No initial-bootstrap CLI, program store, real credential, or field service.
set -euo pipefail
bin="$1"
root="$2"
work="$(mktemp -d "${TMPDIR:-/tmp}/verdant-cli-shell-XXXXXX")"
trap 'rm -rf "$work"' EXIT
export CLI_SECRET=synthetic-cli-owner
export CLI_NEW=synthetic-cli-recovery
printf 'role = "standalone"\ndurable_path = "%s"\nsecret_env = "CLI_SECRET"\n' "$root" > "$work/site.conf"
cap=cli-owner
key=cli-key
scope=scope-a
finding="binding-finding:$(sqlite3 "$root/meaning.db" "SELECT seq FROM outbox WHERE operation='binding-finding';")"
call() {
    local verb="$1"; shift
    "$bin" "$verb" --config "$work/site.conf" --scope "$scope" --capability "$cap" --key-id "$key" "$@"
}
ok() {
    local marker="$1"; shift
    local code=0
    call "$@" > "$work/out" 2> "$work/err" || code=$?
    if [ "$code" -ne 0 ] || [ -s "$work/err" ]; then cat "$work/out" "$work/err" >&2; exit 1; fi
    if ! grep -Fq -- "$marker" "$work/out"; then cat "$work/out" >&2; printf 'missing marker: %s\n' "$marker" >&2; exit 1; fi
    printf 'FIXED shell: %s exit=0 marker=%s\n' "$1" "$marker"
}
refuse() {
    local expected="$1" marker="$2"; shift 2
    local code=0
    call "$@" > "$work/out" 2> "$work/err" || code=$?
    if [ "$code" -ne "$expected" ] || [ -s "$work/out" ]; then cat "$work/out" "$work/err" >&2; printf 'expected %s got %s\n' "$expected" "$code" >&2; exit 1; fi
    grep -Fq -- "$marker" "$work/err"
    printf 'FIXED shell: %s exit=%s stderr=%s\n' "$1" "$code" "$marker"
}
draft=(--operation-id api-cli-draft --entry 'sat-binding|0|SAT' --finding "$finding")
ok 'draft ok operation=api-cli-draft' draft "${draft[@]}"
ok 'draft ok operation=api-cli-draft' draft "${draft[@]}"
refuse 4 '[api-conflict]' draft --operation-id api-cli-draft --entry 'sat-binding|0|changed'
ok 'edit ok operation=api-cli-edit draft=api-cli-draft' edit --operation-id api-cli-edit --revision api-cli-draft --entry "sat-binding|0|Supply air | l'état °C" --finding "$finding"
ok 'Unqualified' validate --revision api-cli-edit --size 1 --offset 0
grep -Fq 'count=1 next_offset=none' "$work/out"
printf 'FIXED R2 Unqualified exits 0 (not a refusal)\n'
ok 'read ok count=1' read --revision api-cli-edit
grep -Fq "Supply air | l'état °C" "$work/out"
ok 'read ok count=0' read --revision api-cli-edit --size 64 --offset 256
for verb in validate read; do
    refuse 2 '[api-limit]' "$verb" --revision api-cli-edit --size 0
    refuse 2 '[api-limit]' "$verb" --revision api-cli-edit --size 65
    refuse 2 '[api-limit]' "$verb" --revision api-cli-edit --offset 257
    refuse 5 '[api-missing-content]' "$verb" --revision api-absent
done
ok 'status ok' status --size 1 --offset 0
grep -Fq 'next_offset=1' "$work/out"
ok 'status ok count=0' status --size 64 --offset 256
refuse 2 '[api-limit]' status --size 65
refuse 2 '[api-limit]' status --offset 257
seal_args=(--revision api-cli-edit --binary test-cli --host synthetic)
ok 'seal ok operation=api-cli-seal-' seal "${seal_args[@]}"
read -r _ _ op_field identity row _ < "$work/out"
original="${op_field#operation=}"
ok "operation=$original $identity $row reconciled=true" seal "${seal_args[@]}"
ok "operation=$original $identity $row reconciled=true" seal "${seal_args[@]}" --operation-id "$original"
ok "operation=$original $identity $row" read --view sealed --revision api-cli-draft
# Both default readback and explicit-ID retries must still validate exact input.
refuse 4 '[api-conflict]' seal --revision api-cli-edit --binary changed --host synthetic
refuse 4 '[api-conflict]' seal --revision api-cli-edit --binary changed --host synthetic --operation-id "$original"
refuse 4 '[api-conflict]' seal --revision api-cli-draft --binary test-cli --host synthetic
refuse 4 '[api-sealed-mutation]' edit --operation-id api-frozen-edit --revision api-cli-edit --entry 'sat-binding|0|edit frozen'
ok 'draft ok' draft --operation-id api-another-draft --entry 'sat-binding|0|SAT' --finding "$finding"
refuse 4 '[api-conflict]' seal --revision api-another-draft --binary test-cli --host synthetic --operation-id "$original"
refuse 5 'pending-not-sealed:api-pending-seal' seal --revision api-pending-draft --binary test-cli --host synthetic
refuse 5 'pending-not-sealed:api-pending-seal' read --view sealed --revision api-pending-draft
refuse 5 '[api-missing-content]' read --view sealed --revision api-absent
printf 'FIXED R1 original identity: operation=%s %s %s; default+explicit retries reconcile; changed inputs/stale revision/reused ID conflict; pending is refused\n' "$original" "$identity" "$row"
ok 'accept ok operation=api-cli-accept revision=1' accept --operation-id api-cli-accept --seal-operation "$original" --expected 0
ok 'accept ok operation=api-cli-accept revision=1' accept --operation-id api-cli-accept --seal-operation "$original" --expected 0
refuse 4 '[accept-conflict]' accept --operation-id api-stale-accept --seal-operation "$original" --expected 0
ok 'read ok count=1' read --view accepted --size 1
ok 'read ok active=none' read --view active
ok 'operational: Unknown' status
grep -Fq 'field_authority: Unsupported, qualification: Unsupported' "$work/out"
# Genuine access refusals across the verbs, with valid syntax and no secret leak.
CLI_SECRET=synthetic-forged-cli
refuse 3 '[forged-credential]' draft "${draft[@]}"
refuse 3 '[forged-credential]' edit --operation-id api-denied --revision api-cli-edit
refuse 3 '[forged-credential]' validate --revision api-cli-edit
refuse 3 '[forged-credential]' seal "${seal_args[@]}"
refuse 3 '[forged-credential]' accept --operation-id api-denied --seal-operation "$original" --expected 1
refuse 3 '[forged-credential]' status
refuse 3 '[forged-credential]' read --revision api-cli-edit
refuse 3 '[forged-credential]' recovery --action provision --operation-id api-denied --new-key-id recovery-1 --new-secret-env CLI_NEW
CLI_SECRET=synthetic-cli-owner
scope=scope-b
refuse 3 '[scope-denied]' status
scope=scope-a
ok 'recovery ok action=provision' recovery --action provision --operation-id api-provision --new-key-id recovery-1 --new-secret-env CLI_NEW
ok 'recovery ok action=provision' recovery --action provision --operation-id api-provision --new-key-id recovery-1 --new-secret-env CLI_NEW
cap=api-recovery-scope-a
key=recovery-1
CLI_SECRET=synthetic-cli-recovery
CLI_NEW=synthetic-cli-replacement
ok 'recovery ok action=re-bootstrap' recovery --action re-bootstrap --operation-id api-rebootstrap --new-key-id replacement-1 --new-secret-env CLI_NEW --new-capability replacement
ok 'recovery ok action=re-bootstrap' recovery --action re-bootstrap --operation-id api-rebootstrap --new-key-id replacement-1 --new-secret-env CLI_NEW --new-capability replacement
refuse 3 '[api-recovery-restricted]' status
refuse 3 '[api-recovery-restricted]' recovery --action re-bootstrap --operation-id api-denied-rebootstrap --new-key-id other --new-secret-env CLI_NEW --new-capability api-recovery-other
CLI_NEW=synthetic-cli-next-recovery
ok 'recovery ok action=rotate' recovery --action rotate --operation-id api-rotate --new-key-id recovery-2 --new-secret-env CLI_NEW
ok 'recovery ok action=rotate' recovery --action rotate --operation-id api-rotate --new-key-id recovery-2 --new-secret-env CLI_NEW
refuse 3 '[revoked-credential]' status
cap=replacement
key=replacement-1
CLI_SECRET=synthetic-cli-replacement
ok 'status ok' status
refuse 3 '[administration-denied]' recovery --action provision --operation-id api-no-admin --new-key-id no-admin --new-secret-env CLI_NEW
refuse 3 '[api-recovery-restricted]' recovery --action rotate --operation-id api-no-recovery --new-key-id no-recovery --new-secret-env CLI_NEW
printf 'FIXED recovery = API: provision/re-bootstrap/rotate retries; revoked old key; recovery cannot read/publish, replacement cannot administer/rotate recovery\n'
# SQLite truth is verification only, never fixture repair or business mutation.
test "$(sqlite3 "$root/meaning.db" "SELECT count(*) FROM outbox WHERE operation='accept-revision-v1';")" = 1
test "$(sqlite3 "$root/meaning.db" "SELECT count(*) FROM outbox WHERE operation='seal-revision-v1';")" = 1
test "$(sqlite3 "$root/meaning.db" "SELECT count(*) FROM outbox WHERE value_json LIKE '%synthetic-cli-%';")" = 0
