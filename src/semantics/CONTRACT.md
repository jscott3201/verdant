# Pinned vocabulary and conversion/binding seam (R07)

## Closed vocabulary, open representation

Profile `verdant-pinned-brick-223p-rec-v1`, namespace `verdant:v1`, is an
offline curated **synthetic subset**, not an upstream ontology import.
Nothing is fetched; broader Brick, ASHRAE 223P and RealEstateCore support,
relation inference and universal canonicalization remain excluded.

Conversion admits these exact, case-sensitive tokens:

| Field | Admitted tokens |
| --- | --- |
| Class | `brick:AHU`, `brick:VAV`, `brick:Supply_Air_Temperature_Sensor` |
| Unit | `degC`, `percent`, `Pa`, `L/s` |
| `Value::Mode` | `occupied`, `unoccupied`, `standby` |

There is no trimming, case folding, synonym recognition, unit conversion,
or inference from labels or `Value::Text`. `VAV` is inert display text.
`brick:Boiler`, `brick:Chiller`, and `brick:Meter` retain `out-of-scenario`;
other syntactically valid unmapped classes retain `unknown-class`, naming
the original class and profile. Malformed candidate syntax is `invalid-input`.

PR02 `Unit`/`OpMode` still preserve unknown tokens. `ExternalItem::parse`
retains that representation behavior; **conversion admission** refuses
unknown units or modes with `SemanticsError::InvalidInput` (`invalid-input`),
`what=unit|mode`, and detail naming the exact token and pinned profile.
`furlongs-per-fortnight`, `DEGc`, `pa`, `l/S`, and mode `turbo` therefore
parse as unknown but do not convert. A manually constructed `Unknown` is
not promoted, even if its text spells a known mode. No domain behavior changes.

Checks run in sorted source-key order: class, slot prefix, unit, mode;
then collisions are checked across admitted candidates. Existing class,
slot and collision diagnostic bytes and successful binding/record formats
remain unchanged. Supported units/values are copied verbatim; no physical
compatibility or observed measurement claim follows from token membership.

## Slot boundary and purity

The profile is a vocabulary for the `tiny_site` shape, **not** an installed
identity allowlist or an enforced equipment count. Classes map to prefixes
`ahu-`, `vav-`, `sensor-sat-`. Thus `brick:AHU` plus `ahu-9` converts.
That does not create equipment or point truth: credentialed import resolves
`(ahu-9, property)` against the binding registry and refuses an unrecorded
point before writing. Labels neither select a kind nor establish identity.

The converter uses borrowed inputs and returns owned values; it does not
open files, stores, sockets, native engines or field acquisition, and does
not read time or random state. `apply` never mutates its borrowed current
state: same profile/digests is a no-op; changed inputs return a bumped state;
refusal returns no replacement state. Existing revision/overflow behavior
and deterministic content/input digests remain intact. FNV digests are
synthetic change identifiers, **not cryptographic provenance**.

## Provenance and guarded writer boundary

Conversion output says `mapped`, not `observed-qualified`. Binding proposal
DTOs retain identity, unit, optional mode, endpoint/scopes and roles; they do
not carry the converter's label or non-mode scalar value. Those fields stay
in the conversion output; no new persisted field is implied by this seam.

The current writer paths are:

| Path | Status / effect |
| --- | --- |
| Pure `propose`, then `propose_with_credential` | `valid`: structural checks only |
| `import_site` / `import_binding`, then `import_with_credential` | `imported`: conversion-sourced |
| `submit_proposal` (including pending imports) | Re-resolves truth and rejects `observed-qualified` for new work |
| `emit_finding` / `emit_finding_operation` | Requires a durable proposal and live authority; summary faithfully cites its status |
| Receipt reconciliation / retry | Returns the committed binding/finding, not a fresh authorization or status upgrade |
| Full replay / reopen | Reconstructs stored fields exactly, without re-qualification |
| Replay window / open window | Historical row bytes only, not mutation truth or authority |

Both Sense/review and Drive/publish branches obey this separation. No
credentialed conversion/proposal/finding path mints observed qualification.
`Finding::for_binding` renders the supplied status faithfully: an imported
binding yields an `imported` summary. The pure function does not authenticate
or certify its input; synthetic `observed-qualified` DTOs can be represented
and decoded, but the guarded writer rejects them for new effects.

**Trust model:** stored bytes are trusted iff written by the guarded writer
within its trusted filesystem boundary. Raw-DB writes (including editing
`status=imported` into `status=observed-qualified`, actor or capgen fields)
are outside this model. This follows R03's [trusted-parent boundary in
`src/storage/sqlite/admission.rs`](../storage/sqlite/admission.rs): privileged
same-UID filesystem replacement while SQLite owns locks is explicitly
unsupported. Replay fidelity is not tamper detection. No tamper-evidence
machinery or qualification-evidence model is added; field observation,
sensing/actuation qualification and actual control remain future work.

## Evidence and limits

`tests/semantics_vocabulary.rs` asserts the FIXED token matrix with independent
literal templates, unknown preservation, inert labels, `ahu-9` and purity.
Existing `tests/semantics_profile.rs` freezes successful binding/outcome and
failure bytes and checks the embedded artifact against its on-disk bytes.

The separation test in `tests/binding_proposals.rs`, backed by
`tests/semantics_cases/provenance.rs`, exercises both credentialed writers,
both roles, optional-mode branches, finding emission and receipt retries.
It compares complete bindings, canonical bytes, proposal descriptors/JSON,
finding fields, full replay, reopen and both window decoders. Separate
synthetic vectors assert exact decode and summary fidelity for **all three**
statuses in both directions (no upgrade or downgrade). They do not claim
that a current writer can produce `observed-qualified` rows and do not
tamper with a database. These are local synthetic checks, not field or
cross-platform qualification.
