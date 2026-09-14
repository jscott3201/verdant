use super::*;

#[test]
fn d10_original_pr03_acceptance_checklist_keeps_parent_closure_open() {
    // Executed PR03A cases remain in tests/observation.rs (C01–C10). This checklist
    // is not a replacement for their execution or original live PR01 input.
    let checklist = [
        ("identity/equal/conflicting", "C03-C05 + D06-D07"),
        ("raw/value/unit/time", "C01-C02/C09 + D03"),
        ("late/old binding", "C06 + persisted_current"),
        ("finite window/spool/custody", "D01-D04/D08"),
        ("restart/replay", "C07-C08 + D05-D07"),
        ("accepted/sealed survival", "D09"),
        ("scoped read/pin/materialize", "C10 + scoped_reads"),
        (
            "original live PR01 input",
            "OPEN: no isolated-peer execution",
        ),
        ("non-synthetic semantic input", "OPEN: F02/E05"),
        (
            "M03 byte-fit",
            "RESIDUAL: consumer qualification, not a blocker here",
        ),
    ];
    assert_eq!(checklist.len(), 10);
    assert_eq!(
        checklist
            .iter()
            .filter(|(_, s)| s.starts_with("OPEN"))
            .count(),
        2
    );
}

#[test]
fn persisted_current_keeps_late_and_old_binding_data_historical() {
    let h = Harness::new();
    let w = open(&h, None);
    w.select_binding(access(&h), &h.context).unwrap();
    let old = append(&h, &w, 0, Retention::OptionalHistory);
    let late = row(&h, &w, &[0x21, 0], 900);
    capture(&h, &w, &late, Retention::OptionalHistory, 1001);
    assert_eq!(
        w.current(access(&h), &key()).unwrap().unwrap().id,
        *old.id()
    );
    let mut raw = bytes(&[0x21, 2], 1010);
    raw.active_generation =
        accept::ActiveGeneration::new(h.raw.active_generation.get() + 1).unwrap();
    let context = BindingContext::synthetic(&h.config, &raw, bacnet_support::pv()).unwrap();
    w.select_binding(access(&h), &context).unwrap();
    assert!(w.current(access(&h), &key()).unwrap().is_none());
    let newest = w
        .identify(
            access(&h),
            h.pending(&raw, &context, Codec::Scalar, unit(), 1010),
        )
        .unwrap();
    capture(&h, &w, &newest, Retention::OptionalHistory, 1010);
    let historical = append(&h, &w, 20, Retention::OptionalHistory);
    let checkpoint = w.checkpoint(access(&h)).unwrap();
    drop(w);
    let w = open(&h, Some(&checkpoint));
    assert_eq!(
        w.current(access(&h), &key()).unwrap().unwrap().id,
        *newest.id()
    );
    assert!(w.read(access(&h), historical.id()).unwrap().is_some());
    assert_eq!(
        w.select_binding(access(&h), &h.context).unwrap_err().code(),
        "old-binding-selection"
    );
    assert_eq!(sql(&h, "SELECT seq FROM current;"), vec![vec!["2"]]);
}

#[test]
fn scoped_reads_and_single_module_type_identity() {
    let h = Harness::new();
    let w = open(&h, None);
    let observation: observation::NormalizedObservation =
        append(&h, &w, 0, Retention::OptionalHistory);
    // Compilation proves PR03A enters the canonical observation service without
    // conversion; storage-only harnesses compile with no observation module.
    w.reconcile_observation(access(&h), &observation).unwrap();
    let other = observation::identity::ObservationId::new(
        domain::scope::TrustedScope::parse("scope-b").unwrap(),
        observation.id().producer().clone(),
        observation.id().position().clone(),
    );
    assert_eq!(
        w.read(access(&h), &other).unwrap_err().code(),
        "scope-or-producer-mismatch"
    );
    assert_eq!(
        w.pin(access(&h), &other, &clock(1000)).unwrap_err().code(),
        "scope-or-producer-mismatch"
    );
    assert!(w
        .read(
            Access {
                gate: &h.gate,
                credential: None
            },
            observation.id()
        )
        .is_err());
}

#[test]
fn migration_fresh_and_exact_0002_upgrade_preserve_identity_and_rows() {
    use std::io::Write;
    let scratch = fixture::Scratch::new();
    let mut child = std::process::Command::new("sqlite3")
        .arg(&scratch.db())
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let script = format!("PRAGMA journal_mode=WAL; BEGIN IMMEDIATE; {} PRAGMA user_version=1; INSERT INTO schema_migrations VALUES(1,'M01-PR03 0001_init: initial tiny outbox'); {} INSERT INTO storage_receipts VALUES('other-owner','request','response'); COMMIT;",storage::MIGRATION_0001_SQL,storage::MIGRATION_0002_SQL);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
    let raw = |query: &str| {
        let out = std::process::Command::new("sqlite3")
            .arg(&scratch.db())
            .arg(query)
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let identity = raw("SELECT identity FROM storage_identity;");
    let store = SqliteStore::open(
        &scratch.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .unwrap()
    .0;
    assert_eq!(raw("SELECT identity FROM storage_identity;"), identity);
    assert_eq!(
        raw("PRAGMA user_version; SELECT group_concat(generation) FROM schema_migrations;"),
        "1\n1,2,3\n"
    );
    assert_eq!(
        raw("SELECT request,response FROM storage_receipts WHERE operation='other-owner';"),
        "request|response\n"
    );
    assert_eq!(raw("SELECT count(*) FROM observations; SELECT count(*) FROM pins; SELECT count(*) FROM gaps;"),"0\n0\n0\n");
    drop(store);
    let fresh = fixture::Scratch::new();
    let store = SqliteStore::open(
        &fresh.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny(),
    )
    .unwrap()
    .0;
    assert_eq!(
        store
            .exec_script("SELECT group_concat(generation) FROM schema_migrations;")
            .unwrap(),
        vec![vec!["1,2,3"]]
    );
    store.exec_script("DROP VIEW current;").unwrap();
    drop(store);
    assert!(SqliteStore::open(
        &fresh.db(),
        ConnectionSettings::local_wal_full(),
        StoreBounds::tiny()
    )
    .is_err());
}

#[test]
fn projection_codec_has_independent_escape_null_and_refusal_fixtures() {
    use storage::observation_writer::{encode, object, JsonVal, Object};
    let expected = "{\"a\":\"é|\\n}\\\"\",\"b\":null,\"c\":{\"seq\":\"0\"}}";
    let fields = Object::from([
        ("a".into(), JsonVal::Str("é|\n}\"".into())),
        ("b".into(), JsonVal::Null),
        (
            "c".into(),
            JsonVal::Object(Object::from([("seq".into(), JsonVal::Str("0".into()))])),
        ),
    ]);
    assert_eq!(encode(fields.clone()), expected);
    assert_eq!(object(expected).unwrap(), fields);
    for bad in [
        "{",
        "{\"a\":1}",
        "{\"a\":[]}",
        "{\"a\":true}",
        "{\"a\":\"x\",\"a\":\"y\"}",
        "{\"a\":\"\\q\"}",
        "{}extra",
    ] {
        assert!(object(bad).is_err(), "{bad}");
    }
}
