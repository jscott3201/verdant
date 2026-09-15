use crate::semantics::{
    ledger::{Fact, Kind},
    matrix::*,
    parse::*,
    recipe::*,
};

// Independent literals, not output captured from the production encoder.
pub const AHU_FACT: &str = r#"{"artifact":"Brick.ttl","sha256":"b65720b7b9b64c646745c689777e6138c0d59ce0088df0aeb78fbd444d04d8e7","subject":"https://brickschema.org/schema/Brick#AHU","predicate":"http://www.w3.org/2000/01/rdf-schema#subClassOf","object_kind":"iri","object":"https://brickschema.org/schema/Brick#HVAC_Equipment","kind":"original","authored":true,"rule":"source-assertion","rule_version":1,"recipe":"verdant-f02-s01-v1","reason":"explicit in artifact; not upstream authoring-history evidence","provenance":"Brick v1.4.4; tag 4b5be60d27f9b4d96fe477f45513fa71afebe684; release 216036536; asset 251163888; generated distribution; embedded REC 4.0","evidence":"parser-only; mapped; not observed-qualified; no native materialization"}"#;

#[test]
fn fixed_original_fact_json_preserves_artifact_and_authorship() {
    let pin = artifact(BRICK).unwrap();
    let fact = Fact {
        artifact: pin.name,
        sha256: pin.sha256,
        subject: "https://brickschema.org/schema/Brick#AHU".into(),
        predicate: SUBCLASS.into(),
        object: Object::Iri("https://brickschema.org/schema/Brick#HVAC_Equipment".into()),
        kind: Kind::Original,
        rule: "source-assertion",
        reason: "explicit in artifact; not upstream authoring-history evidence".into(),
        provenance: pin.provenance,
    };
    assert_eq!(fact.to_json(), AHU_FACT);
}

#[test]
fn fixed_literal_json_retains_kind_and_escapes_without_qualification() {
    let fact = Fact {
        artifact: "tiny_site synthetic",
        sha256: "not-a-locked-artifact",
        subject: "urn:tiny_site:ahu-1".into(),
        predicate: "urn:label".into(),
        object: Object::Literal("\"VAV\"\n\\\t\u{0001}".into()),
        kind: Kind::Refusal,
        rule: "labels-not-identity",
        reason: "not identity".into(),
        provenance: "synthetic encoder vector",
    };
    assert_eq!(
        fact.to_json(),
        r#"{"artifact":"tiny_site synthetic","sha256":"not-a-locked-artifact","subject":"urn:tiny_site:ahu-1","predicate":"urn:label","object_kind":"literal","object":"\"VAV\"\n\\\t\u0001","kind":"refusal","authored":false,"rule":"labels-not-identity","rule_version":1,"recipe":"verdant-f02-s01-v1","reason":"not identity","provenance":"synthetic encoder vector","evidence":"parser-only; mapped; not observed-qualified; no native materialization"}"#
    );
}

#[test]
fn fixed_relation_direction_is_not_inverse_or_equivalent_execution() {
    for (source, iri, expected) in [
        (
            BRICK,
            "https://brickschema.org/schema/Brick#feeds",
            r#"{"artifact":"Brick.ttl","iri":"https://brickschema.org/schema/Brick#feeds","kind":"relation","direction":"subject upstream -> object downstream","status":"mapped","evidence":"parser-only"}"#,
        ),
        (
            S223,
            "http://data.ashrae.org/standard223#observes",
            r#"{"artifact":"223p.ttl","iri":"http://data.ashrae.org/standard223#observes","kind":"relation","direction":"subject Sensor -> object ObservableProperty","status":"mapped","evidence":"parser-only"}"#,
        ),
        (
            S223,
            "http://data.ashrae.org/standard223#connectsTo",
            r#"{"artifact":"223p.ttl","iri":"http://data.ashrae.org/standard223#connectsTo","kind":"relation","direction":"subject Connection -> object Connectable; flow subject to object","status":"mapped","evidence":"parser-only"}"#,
        ),
    ] {
        assert_eq!(supported(source, iri).unwrap().to_json(), expected);
    }
    let doc = Document::parse(
        br#"
        @prefix b: <https://brickschema.org/schema/Brick#> .
        @prefix owl: <http://www.w3.org/2002/07/owl#> .
        @prefix sh: <http://www.w3.org/ns/shacl#> .
        b:feeds owl:inverseOf b:isFedBy .
        <urn:tiny_site:ahu-1> b:feeds <urn:tiny_site:vav-101> .
        b:feeds sh:rule [ sh:select "THIS IS NOT SPARQL" ] .
    "#,
    )
    .unwrap();
    assert_eq!(doc.triples(), 4, "shapes parsed as data, not evaluated");
    assert!(!doc.has(
        "urn:tiny_site:vav-101",
        &format!("{B}isFedBy"),
        "urn:tiny_site:ahu-1"
    ));
}

#[test]
fn fixed_namespace_collision_and_ancestry_are_read_only() {
    // Manual excerpts from Brick.ttl 43663/47116 and explicit synthetic graph.
    // These are NOT substitutes for the separately hash-verified full artifacts.
    let bytes = br#"
        @prefix b: <https://brickschema.org/schema/Brick#> .
        @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
        @prefix owl: <http://www.w3.org/2002/07/owl#> .
        @prefix wrong: <http://example.com/not-brick#> .
        b:Supply_Air_Temperature_Sensor rdfs:subClassOf b:Air_Temperature_Sensor .
        b:Air_Temperature_Sensor rdfs:subClassOf b:Temperature_Sensor .
        b:Temperature_Sensor rdfs:subClassOf b:Sensor .
        b:AHU owl:equivalentClass b:Air_Handling_Unit .
        wrong:AHU rdfs:label "AHU" .
        <urn:tiny_site:sensor-sat-1> a b:Supply_Air_Temperature_Sensor .
    "#;
    let doc = Document::parse(bytes).unwrap();
    let before = doc.clone();
    let path = doc
        .ancestry("https://brickschema.org/schema/Brick#Supply_Air_Temperature_Sensor")
        .unwrap();
    assert_eq!(
        path["https://brickschema.org/schema/Brick#Sensor"],
        [
            "https://brickschema.org/schema/Brick#Supply_Air_Temperature_Sensor",
            "https://brickschema.org/schema/Brick#Air_Temperature_Sensor",
            "https://brickschema.org/schema/Brick#Temperature_Sensor",
            "https://brickschema.org/schema/Brick#Sensor",
        ]
    );
    assert_eq!(path.len(), 3);
    assert!(doc
        .ancestry("https://brickschema.org/schema/Brick#AHU")
        .unwrap()
        .is_empty());
    assert!(!doc.has(
        "urn:tiny_site:sensor-sat-1",
        TYPE,
        "https://brickschema.org/schema/Brick#Sensor"
    ));
    for iri in [
        "http://example.com/not-brick#AHU",
        "brick:AHU",
        "AHU",
        "https://brickschema.org/schema/Brick#ahu",
        "https://brickschema.org/schema/Brick#Air_Handling_Unit",
    ] {
        assert_eq!(supported(BRICK, iri).unwrap_err().code(), "s01-unsupported");
    }
    assert!(supported(S223, "https://brickschema.org/schema/Brick#Sensor").is_err());
    assert!(supported(BRICK, "https://brickschema.org/schema/Brick#Sensor").is_ok());
    assert!(supported(S223, "http://data.ashrae.org/standard223#Sensor").is_ok());
    assert_eq!(doc, before);
}

#[test]
fn fixed_unit_skew_mapping_never_folds_or_converts() {
    for source in [UNIT31, QUDT32] {
        for (token, unit, quantity) in [
            (
                "degC",
                "http://qudt.org/vocab/unit/DEG_C",
                "http://qudt.org/vocab/quantitykind/Temperature",
            ),
            (
                "percent",
                "http://qudt.org/vocab/unit/PERCENT",
                "http://qudt.org/vocab/quantitykind/DimensionlessRatio",
            ),
            (
                "Pa",
                "http://qudt.org/vocab/unit/PA",
                "http://qudt.org/vocab/quantitykind/ForcePerArea",
            ),
            (
                "L/s",
                "http://qudt.org/vocab/unit/L-PER-SEC",
                "http://qudt.org/vocab/quantitykind/VolumeFlowRate",
            ),
        ] {
            assert_eq!(
                unit_mapping(source, token).unwrap(),
                (unit.into(), quantity.into())
            );
        }
        for token in ["pa", "DEGc", "degF", "percent ", "l/S", "Cel", "°C"] {
            assert_eq!(
                unit_mapping(source, token).unwrap_err().code(),
                "s01-unsupported"
            );
        }
    }
    assert!(unit_mapping(BRICK, "degC").is_err());
    assert!(unit_mapping("unit-3.2.1.ttl", "degC").is_err());
    assert_eq!(
        import_action(BRICK, "http://qudt.org/3.2.1/shacl/qudt-all")
            .unwrap_err()
            .code(),
        "s01-unexpected-remote"
    );
}
