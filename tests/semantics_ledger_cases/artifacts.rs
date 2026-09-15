use crate::semantics::{ledger::Kind, matrix::*, parse::*, recipe::*};
use std::io::Read;

/// Explicit external-data gate: absence must fail this invocation, never pass.
/// Ordinary cargo test is offline and does not acquire/cache upstream artifacts.
#[test]
#[ignore = "requires externally reacquired manifest bytes; see README.md in this directory"]
fn pinned_artifacts_matrix_ledger_and_import_closure() {
    let dir =
        std::env::var_os("VERDANT_S01_ARTIFACT_DIR").expect("explicit task scratch directory");
    let dir = std::path::Path::new(&dir);
    assert!(
        !dir.canonicalize().unwrap().starts_with(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .canonicalize()
                .unwrap()
        ),
        "artifact bytes never in product repository"
    );
    let bytes: Vec<_> = ARTIFACTS
        .iter()
        .map(|pin| {
            let mut bytes = Vec::new();
            std::fs::File::open(dir.join(pin.name))
                .unwrap()
                .take((MAX_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .unwrap();
            bytes
        })
        .collect();
    let inputs: Vec<_> = ARTIFACTS
        .iter()
        .zip(&bytes)
        .map(|(pin, bytes)| Input {
            name: pin.name,
            bytes,
        })
        .collect();
    let catalog = Catalog::load(&inputs).unwrap();
    let report = Report::extract(&catalog).unwrap();
    assert_eq!(
        Catalog::load(&inputs[..inputs.len() - 1]).unwrap_err(),
        Error::Missing("shacl.ttl".into())
    );
    let reversed: Vec<_> = inputs
        .iter()
        .rev()
        .map(|i| Input {
            name: i.name,
            bytes: i.bytes,
        })
        .collect();
    let again = Report::extract(&Catalog::load(&reversed).unwrap()).unwrap();
    assert_eq!(report.rows, again.rows);
    assert_eq!(
        report.ledger, again.ledger,
        "no blank-ID or file-order dependence"
    );
    assert_eq!(report.rows.len(), 39);
    assert!(report
        .ledger
        .iter()
        .any(|f| f.to_json() == super::fixed::AHU_FACT));
    for pin in ARTIFACTS {
        let doc = catalog.document(pin.name).unwrap();
        assert!(doc.triples() > 0);
        println!(
            "VERIFIED {} bytes={} sha256={} parsed-triples={} evidence=parser-only",
            pin.name,
            pin.bytes,
            pin.sha256,
            doc.triples()
        );
    }
    let doc = catalog.document(BRICK).unwrap();
    let ancestry = doc
        .ancestry("https://brickschema.org/schema/Brick#Supply_Air_Temperature_Sensor")
        .unwrap();
    assert_eq!(
        ancestry["https://brickschema.org/schema/Brick#Sensor"],
        [
            "https://brickschema.org/schema/Brick#Supply_Air_Temperature_Sensor",
            "https://brickschema.org/schema/Brick#Air_Temperature_Sensor",
            "https://brickschema.org/schema/Brick#Temperature_Sensor",
            "https://brickschema.org/schema/Brick#Sensor",
        ]
    );
    assert_eq!(
        doc.ancestry("https://w3id.org/rec#Room").unwrap()["https://w3id.org/rec#Architecture"],
        [
            "https://w3id.org/rec#Room",
            "https://w3id.org/rec#Architecture"
        ]
    );
    for source in [UNIT31, QUDT32] {
        assert!(catalog.document(source).unwrap().has(
            "http://qudt.org/vocab/unit/PA",
            HAS_QK,
            "http://qudt.org/vocab/quantitykind/ForcePerArea"
        ));
        assert!(!catalog.document(source).unwrap().has(
            "http://qudt.org/vocab/unit/PA",
            HAS_QK,
            "http://qudt.org/vocab/quantitykind/Pressure"
        ));
    }
    assert!(report
        .ledger
        .iter()
        .any(|f| f.kind == Kind::Refusal
            && f.object.iri() == Some("http://qudt.org/3.1.0/vocab/sou")));
    assert!(report
        .ledger
        .iter()
        .any(|f| f.kind == Kind::Derived && f.rule == "explicit-ancestry-path"));
    for row in &report.rows {
        println!("MATRIX {}", row.to_json());
    }
    for fact in &report.ledger {
        println!("LEDGER {}", fact.to_json());
    }
    println!(
        "RECIPE {RECIPE_ID} {PARSER}; {EVIDENCE}; ledger-facts={}",
        report.ledger.len()
    );
    // Same byte length, one changed byte. Deliberate negative fixture, not an
    // acquisition mismatch: proves the product checks hashes, not just sizes.
    let mut changed = bytes.clone();
    changed[0][0] = b'#';
    let corrupt: Vec<_> = ARTIFACTS
        .iter()
        .zip(&changed)
        .map(|(pin, bytes)| Input {
            name: pin.name,
            bytes,
        })
        .collect();
    assert_eq!(
        Catalog::load(&corrupt).unwrap_err(),
        Error::Digest(BRICK.into())
    );
}
