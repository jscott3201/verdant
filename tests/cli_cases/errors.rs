//! Mapping checks complement subprocess refusals; no synthetic Unknown is a
//! claim that a real CLI process was fault-injected into an uncertain commit.
use super::*;

#[test]
fn fixed_exit_mapping_retains_nested_owner_codes_and_unknown_operation() {
    let op = domain::ids::OperationId::parse("api-uncertain").unwrap();
    for error in [
        api::Error::Unknown { operation: op.clone(), detail: "unknown fixture".into() },
        api::Error::Accept(accept::Error::Unknown { operation: op.clone(), detail: "unknown fixture".into() }),
        api::Error::Seal(seal::SealError::Unknown { operation: op, detail: "unknown fixture".into() }),
    ] {
        let code = error.code();
        let (exit, message) = setup_error(error);
        assert_eq!(exit, 6);
        assert!(message.contains(code) && message.contains("api-uncertain"));
    }
    for error in [
        api::Error::Storage(storage::StorageError::SqliteFailure { detail: "fixture".into() }),
        api::Error::Access(access::AccessError::Store(storage::StorageError::SqliteFailure { detail: "fixture".into() })),
        api::Error::Accept(accept::Error::Storage(storage::StorageError::SqliteFailure { detail: "fixture".into() })),
    ] {
        let (exit, message) = setup_error(error);
        assert_eq!(exit, 1);
        assert!(message.starts_with("[sqlite-failure]"));
    }
    for (error, expected) in [
        (api::Error::Unauthenticated, 3),
        (api::Error::Invalid("fixture"), 2),
        (api::Error::Limit("fixture"), 2),
        (api::Error::Conflict("fixture"), 4),
        (api::Error::SealedMutation, 4),
        (api::Error::Cancelled, 4),
        (api::Error::Missing("pending-not-sealed:api-fixture".into()), 5),
    ] { assert_eq!(setup_error(error).0, expected); }
}

#[test]
fn fixed_parse_pages_and_operation_identity_passthrough() {
    let args = ["--config", "unused", "--scope", "scope-a", "--capability", "owner", "--key-id", "key",
        "--revision", "api-draft", "--binary", "binary", "--host", "host", "--operation-id", "api-exact/retry:1"]
        .map(str::to_string);
    let parsed = SetupOptions::parse("seal", &args).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(parsed.operation("--operation-id").unwrap().as_str(), "api-exact/retry:1");
    for (size, offset) in [("1", "0"), ("64", "256")] {
        let args = ["--config", "unused", "--scope", "scope-a", "--capability", "owner", "--key-id", "key",
            "--size", size, "--offset", offset].map(str::to_string);
        assert!(SetupOptions::parse("status", &args).is_ok());
    }
}
