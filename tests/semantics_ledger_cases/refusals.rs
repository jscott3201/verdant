use crate::semantics::{parse::*, recipe::*};
use std::collections::BTreeMap;

#[test]
fn fixed_empty_placeholder_syntax_and_size_refusals() {
    for bytes in [b"".as_slice(), b" \n", b"# only comment"] {
        assert_eq!(Document::parse(bytes).unwrap_err(), Error::Empty);
    }
    for bytes in [b"TODO".as_slice(), b"placeholder", b"# $$QUDT_VERSION$$"] {
        assert_eq!(Document::parse(bytes).unwrap_err(), Error::Placeholder);
    }
    assert_eq!(
        Document::parse(b"<urn:s> <urn:p> .").unwrap_err(),
        Error::Syntax
    );
    assert_eq!(
        Document::parse(&vec![b' '; MAX_BYTES + 1]).unwrap_err(),
        Error::Limit("artifact bytes")
    );
    let mut exact = vec![b' '; MAX_BYTES];
    let triple = b"<urn:s> <urn:p> <urn:o> .";
    exact[..triple.len()].copy_from_slice(triple);
    assert_eq!(Document::parse(&exact).unwrap().triples(), 1);
    assert_eq!(
        Document::parse(format!("<urn:s> <urn:p> \"{}\" .", "a".repeat(MAX_TERM_BYTES)).as_bytes())
            .unwrap_err(),
        Error::Limit("term bytes")
    );
    let input = format!(
        "@prefix : <http://example.com/> .\n{}",
        ":s :p :o .\n".repeat(MAX_TRIPLES + 1)
    );
    assert_eq!(
        Document::parse(input.as_bytes()).unwrap_err(),
        Error::Limit("triples")
    );
}

#[test]
fn fixed_duplicate_versions_and_ancestry_cycles_refuse() {
    assert_eq!(
        Document::parse(
            br#"<urn:ontology> <http://www.w3.org/2002/07/owl#versionIRI> <urn:v1>, <urn:v2> ."#
        )
        .unwrap_err(),
        Error::Duplicate("urn:ontology".into())
    );
    assert_eq!(
        Document::parse(
            br#"<urn:ontology> <http://www.w3.org/2002/07/owl#versionInfo> "1", "2" ."#
        )
        .unwrap_err(),
        Error::Duplicate("urn:ontology".into())
    );
    let doc = Document::parse(
        br#"
        @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
        <urn:a> rdfs:subClassOf <urn:b> . <urn:b> rdfs:subClassOf <urn:a> .
    "#,
    )
    .unwrap();
    assert_eq!(
        doc.ancestry("urn:a").unwrap_err(),
        Error::Cycle("urn:a".into())
    );
    let chain: String = (0..MAX_DEPTH)
        .map(|n| format!("<urn:{n}> <{SUBCLASS}> <urn:{}> .\n", n + 1))
        .collect();
    assert_eq!(
        Document::parse(chain.as_bytes())
            .unwrap()
            .ancestry("urn:0")
            .unwrap_err(),
        Error::Limit("ancestry depth")
    );
}

#[test]
fn fixed_import_allowlist_and_expansion_cycles() {
    for bytes in [
        br#"<urn:ontology> <http://www.w3.org/2002/07/owl#imports> [] ."#.as_slice(),
        br#"<urn:ontology> <http://www.w3.org/2002/07/owl#imports> "https://example.com" ."#,
    ] {
        assert_eq!(
            Document::parse(bytes).unwrap_err(),
            Error::Unsupported("import requires named IRIs".into())
        );
    }
    for (source, iri) in [
        (QK31, "http://qudt.org/3.1.0/schema/facade/qudt"),
        (UNIT31, "http://qudt.org/3.1.0/schema/facade/qudt"),
        (QK31, "http://qudt.org/3.1.0/vocab/dimensionvector"),
        (UNIT31, "http://qudt.org/3.1.0/vocab/prefix"),
        (UNIT31, "http://qudt.org/3.1.0/vocab/sou"),
        (QUDT32, "http://www.linkedmodel.org/schema/vaem"),
    ] {
        let (action, reason) = import_action(source, iri).unwrap();
        assert_eq!(action, ImportAction::Refuse);
        assert!(!reason.is_empty());
    }
    assert_eq!(
        import_action(QUDT32, "http://www.w3.org/2004/02/skos/core")
            .unwrap()
            .0,
        ImportAction::LabelsOnly
    );
    assert_eq!(
        import_action("recpatches.ttl", "https://brickschema.org/schema/1.4/Brick")
            .unwrap()
            .0,
        ImportAction::Backreference
    );
    assert_eq!(
        import_action("recpatches.ttl", "https://brickschema.org/schema/1.3/Brick")
            .unwrap_err()
            .code(),
        "s01-unexpected-remote"
    );
    assert_eq!(
        import_action(BRICK, "https://example.com/remote.ttl")
            .unwrap_err()
            .code(),
        "s01-unexpected-remote"
    );
    let mut edges = BTreeMap::from([("a".into(), vec!["b".into()])]);
    assert_eq!(
        check_cycles(&edges).unwrap_err(),
        Error::Missing("b".into())
    );
    edges.insert("b".into(), vec!["a".into()]);
    assert_eq!(check_cycles(&edges).unwrap_err(), Error::Cycle("a".into()));
    edges.insert("b".into(), vec![]);
    check_cycles(&edges).unwrap();
    assert!(!REMOTE_IMPORT_FETCH);
    assert!(!ARBITRARY_IMPORTED_RULE_EXECUTION);
}

#[test]
fn fixed_catalog_missing_unknown_duplicate_and_mismatch_before_expansion() {
    assert_eq!(
        Catalog::load(&[]).unwrap_err(),
        Error::Missing(BRICK.into())
    );
    assert_eq!(
        Catalog::load(&[Input {
            name: "https://example.com/Brick.ttl",
            bytes: b"bad"
        }])
        .unwrap_err()
        .code(),
        "s01-unexpected-remote"
    );
    assert_eq!(
        Catalog::load(&[Input {
            name: BRICK,
            bytes: b""
        }])
        .unwrap_err(),
        Error::Empty
    );
    assert_eq!(
        Catalog::load(&[Input {
            name: BRICK,
            bytes: b"<urn:s> <urn:p> <urn:o>."
        }])
        .unwrap_err(),
        Error::Digest(BRICK.into())
    );
    let padding = vec![b' '; artifact(BRICK).unwrap().bytes];
    let mut bytes = padding;
    bytes[0] = b'#';
    let inputs = [
        Input {
            name: BRICK,
            bytes: &bytes,
        },
        Input {
            name: BRICK,
            bytes: &bytes,
        },
    ];
    assert_eq!(
        Catalog::load(&inputs).unwrap_err(),
        Error::Duplicate(BRICK.into())
    );
}

#[test]
fn fixed_sha256_known_answers() {
    assert_eq!(
        sha256(b"").unwrap(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256(b"abc").unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256(&vec![0; MAX_BYTES + 1]).unwrap_err(),
        Error::Limit("hash bytes")
    );
}
