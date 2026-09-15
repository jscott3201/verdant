# F02-S01: offline source matrix and ledger, recipe v1

**Parser evidence only — mapped, not observed-qualified.** This is a separate
read-only extraction path, not an extension of the R07 converter. It neither
materializes Selene nodes nor changes the publication/sealing interface. S02
owns native materialization and independent readback/reopen. No field evidence,
facility values, SHACL validation result, or complete OWL equivalence is claimed.

Authority: `verdant-program/planning/semantics/s01-lock-manifest.md` §§1–8 and
its phase-2 ratification, `brick-open223-alignment.md` S01, and the owner dispatch.
The application baseline was `d13a74d779f0eeea8b8897156c35cea7a3f536df`.
`source-candidates.json` remains a planning inventory, not an executable lock.

## Pinned procedure

The executable catalog is `src/semantics/recipe.rs::ARTIFACTS`: eleven exact
names, sizes, SHA-256 values, recorded acquisition URLs, ontology IRIs and
provenance. The Brick release tag is source provenance, **not** its asset digest.
REC is embedded in Brick; the Brick-side recpatches are selected, not the
REC-side 1.3 variant. No files are fetched by Rust. URLs in the catalog are data.

1. In a disposable directory **outside every repository**, reacquire the eleven
   artifacts using `curl -fL` and the catalog URLs (the manifest §6/§8.2 recipe).
   Use `--proto '=https' --proto-redir '=https' --connect-timeout 20
   --max-time 120 --max-filesize 7000000`. Do not substitute another URL/version
   or an old local copy on failure. Only the recorded acquisition URLs are
   authorized; an ontology IRI is not a download instruction.
2. Use `wc -c` and `shasum -a 256` on every complete download and compare with
   `ARTIFACTS`/the manifest. Any acquisition mismatch is a stop, not a refresh
   opportunity. Never commit full TTL downloads. Read-only source notices are
   catalogued, not treated as an omnibus license grant.
3. Run the explicit source gate below with that directory. `Catalog::load`
   rechecks the set, sizes and **computed** SHA-256 values before parsing anything.
   It accepts bytes, not caller-asserted checksums, executable paths or resolvers.
   It probes the existing system SHA-256 mechanism with the independent `abc`
   vector. The fixed `/usr/bin/shasum` child has bounded pipes, a five-second
   deadline, and joined workers/reaping. This assumes the same trusted system
   executable/environment model as the sealing owner, not a hostile-host sandbox.
4. Parse each entire artifact with `oxttl=0.2.4`, default-features **off**,
   `TurtleParser::new().for_slice`: synchronous, strict (`lenient=false`), no
   supplied base/prefixes, no RDF 1.2, no parallel parser. A Turtle-authored base
   or prefix is syntax only; resolved full IRIs remain exact/case-sensitive.
5. Check the local import catalog, ontology/version duplication, and bounded
   expansion graph. Extract the closed matrix and sorted per-fact ledger.
   `MATRIX`, `LEDGER`, and `RECIPE` output explicitly say parser-only. Original
   literals retain their parsed RDF value/datatype/language in N-Triples form,
   not the source's exact Turtle spelling (for example, the parser lowercases
   language tags). Raw-byte identity remains the artifact SHA. Derived reporting
   text is not asserted into RDF. No source preprocessing is performed.

```sh
cargo test --locked --test semantics_matrix
VERDANT_S01_ARTIFACT_DIR=/absolute/task/scratch \
  cargo test --locked --test semantics_matrix \
  pinned_artifacts_matrix_ledger_and_import_closure -- --ignored --nocapture
```

The full-artifact test is explicitly ignored in the ordinary offline suite;
it is **required separately** for S01 source validation. Its explicit invocation
fails if the directory/files are absent, in-repository, oversized or mismatched.
It does not silently replace full artifacts with synthetic snippets. The final
same-length mutation is an intentional negative test, not an acquisition change.

### Bounds and refusal rules (v1)

| Boundary | Limit / refusal |
| --- | --- |
| Artifacts | Exactly 11 named pins; unexpected names/URLs, duplicates, missing entries refuse |
| Input bytes | 7,000,000 per artifact, 16,000,000 aggregate; checked before parsing |
| QUDT bundle | 6,725,499 exact bytes fits the explicit 7 MB budget; no truncated/split substitutes |
| Syntax work | 300,000 emitted triples per artifact; 150,000 retained facts; 65,536 serialized bytes per term |
| Imports | 32 per document; graph ≤32 nodes, ≤32 edges/node, ≤32 depth |
| Ancestry | ≤32 nodes per path, ≤256 distinct ancestors; cycles refuse |
| Integrity | Empty/comment-only input, malformed Turtle, unsubstituted `$$QUDT_VERSION$$`, singleton placeholder/TODO refuse |
| Editorial data | Real `vaem:todo` annotations and QUDT `"TBD"` symbol are not integrity placeholders |
| Versions | Conflicting versionInfo on one subject or incompatible duplicate ontology versions refuse |
| Execution | `remote_import_fetch=false`; `arbitrary_imported_rule_execution=false` |

Only named-subject facts for the predicates listed in `parse.rs::retained` enter
the read-only document. Blank-node structures count against parsing bounds but
are not retained as identity, traversed, or executed. This is a deliberately
bounded projection, **not** a complete RDF round trip or general site importer.
Parser allocation can precede the per-term check, but the full input byte bound
is enforced first. Resource limits are per invocation, not host-global quotas.

### Explicit transitive decisions

| Import | Disposition and reason |
| --- | --- |
| QUDT 3.1.0 facade/qudt | Refuse expansion: no facade definitions are needed for exact predicate-name extraction; no schema entailment |
| QUDT 3.1.0 dimensionvector | Refuse: the matrix cites no dimension vectors and does no dimensional reasoning |
| QUDT 3.1.0 prefix | Refuse: the matrix cites no prefix definitions and does no scaling |
| QUDT 3.1.0 sou | Refuse: no systems-of-units interpretation |
| vaem | Refuse: no metadata-vocabulary interpretation |
| skos/core | Inline prefLabel/altLabel literals as text only; no import fetching, identity, equivalence or inference |
| dash / shacl | Pinned bytes parsed as data; **manual bounded checks only**, never a SHACL engine |
| Brick / embedded REC backreferences | Only the exact ratified backreferences are catalog references, not expansion edges; arbitrary expansion cycles refuse |

Required included imports must all be present. These documented refusals are
not assertions of full import closure semantics. A later matrix that needs
facade/dimension/prefix definitions must explicitly include and pin them first;
it cannot reinterpret this refusal as satisfied support. A SHACL engine requires
a new D02 decision.

### Matrix and provenance

The closed matrix contains **39 edition-qualified rows**:

- Brick AHU, VAV, supply/air/temperature sensor ancestry, Sensor, Equipment,
  HVAC_Equipment; 223 Equipment, Sensor, ObservableProperty and
  QuantifiableObservableProperty; embedded REC Room and Space.
- Brick hasPoint/isPointOf, feeds and hasLocation; REC hasPoint and locatedIn;
  223 observes, hasProperty and connectsTo. Direction is manual source-description
  mapping, not inverse/symmetric/transitive entailment. `connectsTo` is
  **Connection → Connectable**, with flow subject to object, not two generic
  equipment endpoints. Location is not service; a sensor is not its property.
- Four units and four quantity kinds in **each** of the two source contexts:
  `degC → DEG_C → Temperature`, `percent → PERCENT → DimensionlessRatio`,
  `Pa → PA → ForcePerArea`, `L/s → L-PER-SEC → VolumeFlowRate`.

The PA detail is deliberate: neither locked unit artifact asserts
`PA hasQuantityKind Pressure`; Pressure's `applicableUnit PA` does not authorize
inverting or folding those assertions. Original additional quantity-kind links
are preserved in the ledger, not silently discarded as synonyms. No numeric
values are accepted, scaled or converted here.

Brick's QUDT context stays **3.1.0**; 223's stays **3.2.1**. The shared unversioned
unit/quantitykind IRIs have separate artifact+SHA provenance. Mapping the same
four tokens in both contexts is an explicit v1 mapping decision backed by each
artifact's own assertions, **not** cross-version definition equivalence or
permission to substitute artifacts. An unknown class or different namespace
with the same local name stays unsupported; labels never mint identity.

Each reported fact carries artifact, SHA, full subject/predicate, object kind,
original/derived/refusal, authored boolean, rule ID/version, reason, recipe and
source provenance. `authored=true` means explicit in the locked artifact, not
proof that a human authored it rather than an upstream generator. An ancestry
entry records its complete explicit path and originals, never adds an entailed
type. Import-disposition entries preserve both the original assertion and the
derived inclusion/backreference/text-only decision or refusal. The original
artifact remains the authority for facts outside the bounded projection.

Independent expected JSON is hardcoded in `fixed.rs`, not generated from the
encoders. The external gate matches the AHU ledger literal against actual parsed
bytes. Synthetic cases use only tiny_site identities. Separate negative cases
cover malformed/empty/placeholder data, bytes/term/triple bounds, namespace
collisions, ancestry depth/cycles, duplicate versions, missing/remote/duplicate
catalog inputs, skew refusal and import cycles. An invalid SPARQL string in a
shape is deliberately inert. None of these tests is native application evidence.

## D02 adoption audit (2026-09-15 UTC)

Only new direct dependency: `oxttl = "=0.2.4", default-features = false`.
Intentional `cargo update -p verdant` resolved the new lock entries; **all builds
and tests use `--locked`**. Cargo cannot update a changed lock with `--locked`.
The diff adds only oxttl, oxrdf, oxiri and oxilangtag plus Verdant's oxttl edge;
no existing package version/source/checksum changed.

All packages below have exact entries in Cargo.lock with source
`registry+https://github.com/rust-lang/crates.io-index` and registry checksums.
`yanked=false` was checked for **each exact version** via
`https://crates.io/api/v1/crates/NAME/VERSION`, including oxttl. The table is the
normal/build closure from `cargo tree --locked -p oxttl --target all`, not every
package in the application lockfile.

| Package | Exact version | Declared rust-version | Role |
| --- | --- | --- | --- |
| oxttl | 0.2.4 | 1.87 | New direct parser |
| oxrdf | 0.3.4 | 1.87 | New RDF data structures |
| oxiri | 0.2.11 | 1.60 | New IRI syntax |
| oxilangtag | 0.1.6 | 1.63 | New language-tag syntax |
| memchr | 2.8.3 | 1.61 | Existing runtime |
| thiserror | 2.0.20 | 1.71 | Existing runtime/error derive |
| thiserror-impl | 2.0.20 | 1.71 | Existing proc macro |
| proc-macro2 | 1.0.107 | 1.71 | Existing macro support |
| quote | 1.0.47 | 1.71 | Existing macro support |
| syn | 3.0.5 | 1.71 | Existing thiserror macro parser |
| syn | 2.0.119 | 1.71 | Existing zerocopy macro parser |
| unicode-ident | 1.0.24 | 1.71 | Existing macro support |
| rand | 0.9.5 | 1.63 | Existing, oxrdf blank-node generation |
| rand_chacha | 0.9.0 | 1.63 | Existing RNG |
| rand_core | 0.9.5 | 1.63 | Existing RNG |
| ppv-lite86 | 0.2.21 | 1.61 | Existing RNG/SIMD |
| zerocopy | 0.8.57 | 1.56.0 | Existing RNG support |
| zerocopy-derive | 0.8.57 | Not declared | Existing proc macro; actual pinned build is evidence, not an invented MSRV |
| getrandom | 0.3.4 | 1.63 | Existing system randomness |
| cfg-if | 1.0.4 | 1.32 | Existing target selection |
| libc | 0.2.189 | 1.65 | Existing host platform support |
| r-efi | 5.3.0 | 1.68 | Non-host UEFI closure only |
| wasip2 | 1.0.4+wasi-0.2.12 | 1.87.0 | Non-host WASI closure only |
| wit-bindgen | 0.57.1 | 1.85.0 | Non-host WASI closure only |

Observed oxttl inverse feature tree has only Verdant's direct edge: neither
`async-tokio` nor `rdf-12` is enabled. oxrdf has its empty default feature set;
neither rdf-12, rdfc-10 nor serde is selected. oxilangtag defaults to std; its
optional serde lockfile reference is not an enabled parser serialization feature.
memchr uses std/alloc; thiserror uses std; rand uses its existing default RNG
closure. The normal/build parser tree contains **no rayon or tempfile and no
Tokio edge**. Existing application Tokio for adapters is unchanged. This is not
a claim that unrelated application dependencies have no such packages.

oxttl/oxrdf and most closure packages are MIT OR Apache-2.0; exceptions include
oxilangtag (MIT), memchr (Unlicense OR MIT), unicode-ident (MIT/Apache choice
AND Unicode-3.0), zerocopy (BSD-2-Clause/Apache/MIT choice), r-efi
(MIT/Apache/LGPL choice) and WASI bindings (Apache with LLVM-exception/Apache/MIT
choice). These are registry declarations, not legal certification or a full
security-advisory audit. No dependency security mechanism was replaced.

MSRV metadata is below the unchanged Rust/Cargo **1.97.1** pin where declared.
Actual execution is **aarch64-apple-darwin, debug**, not a Rust 1.87, UEFI, WASI,
release, cross-platform, or field qualification. Blank-node randomness is a
transitive implementation detail; generated IDs never enter the stable ledger.
