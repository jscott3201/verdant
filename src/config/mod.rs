//! M01-PR01 profile-boundary configuration.
//!
//! Local-only bootstrap for one constrained role (`standalone` | `edge` | `hub`).
//! Strict flat keys, explicit refusals, opaque credentials that are never logged.
//!
//! Out of scope here by assignment: durable stores (M01-PR03 owns them; PR01
//! never creates the durable path implicitly) and any native/field engine
//! (M01-PR05 owns the lifecycle; PR01 starts no field listener).
//!
//! Config syntax is an intentionally small `key = value` format (one entry per
//! line, `#` comments, double-quoted strings, bare `true`/`false` for the one
//! boolean). Zero dependencies: parsing is std-only so PR01 needs no source
//! downloads beyond the pinned toolchain.

use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// Roles PR01 validates. Anything else is refused with the valid set named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Standalone,
    Edge,
    Hub,
}

impl Role {
    /// Canonical valid role names, in acceptance order.
    /// (Exercised by unit tests; the binary reports roles via `as_str`.)
    #[allow(dead_code)]
    pub const VALID: [&'static str; 3] = ["standalone", "edge", "hub"];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Standalone => "standalone",
            Role::Edge => "edge",
            Role::Hub => "hub",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Role, ConfigError> {
        match s {
            "standalone" => Ok(Role::Standalone),
            "edge" => Ok(Role::Edge),
            "hub" => Ok(Role::Hub),
            _ => Err(ConfigError::UnknownRole { got: s.to_string() }),
        }
    }
}

/// Opaque local credential. Redacted in every Display/Debug rendering and
/// best-effort zeroized on drop. Revocation is file/env replacement: point
/// `secret_env` at a new value (or remove it) and restart; PR01 keeps no copy.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    fn new(value: String) -> Secret {
        Secret(value)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// (Exercised by unit tests.)
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(<redacted, {} chars>)", self.0.len())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Best-effort zeroization of the owned buffer (std-only).
        unsafe {
            let bytes = self.0.as_bytes_mut();
            for b in bytes.iter_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

/// PR01-local issuance ceiling for an opaque credential: over-long values are
/// refused rather than truncated or hashed into something else.
pub const MAX_SECRET_LEN: usize = 256;

/// Validated PR01 configuration. `field_listener_requested` is always false
/// after validation: requesting a field listener is a refusal, not a flag.
#[derive(Debug, Clone)]
pub struct Config {
    pub role: Role,
    pub durable_path: PathBuf,
    pub secret_env: Option<String>,
    pub secret: Option<Secret>,
    /// Always false after validation: requesting a listener is a refusal.
    /// (Read by unit tests; the binary guarantees it by construction.)
    #[allow(dead_code)]
    pub field_listener_requested: bool,
}

impl Config {
    /// One-line redacted summary safe for logs and health output.
    /// (Exercised by unit tests.)
    #[allow(dead_code)]
    pub fn summary_redacted(&self) -> String {
        let secret = match (&self.secret_env, &self.secret) {
            (Some(var), Some(s)) => format!("env:{var}=present({} chars, redacted)", s.len()),
            _ => "unconfigured".to_string(),
        };
        format!(
            "role={} durable_path={} secret={} listener=none field_capability=absent",
            self.role.as_str(),
            self.durable_path.display(),
            secret,
        )
    }
}

/// Machine-readable failure codes; stable for tests and evidence mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Io { path: String, message: String },
    Parse { line: usize, message: String },
    UnknownKey { key: String },
    UnknownSection { section: String },
    MissingField { field: &'static str },
    UnknownRole { got: String },
    MissingDurablePath { path: String },
    NotADirectory { path: String },
    UnresolvedSecret { var: String },
    InvalidSecretEnv,
    SecretTooLong { var: String, len: usize },
    FieldCapabilityAbsent,
    ListenerNotSupported,
}

impl ConfigError {
    pub fn code(&self) -> &'static str {
        match self {
            ConfigError::Io { .. } => "io",
            ConfigError::Parse { .. } => "parse",
            ConfigError::UnknownKey { .. } => "unknown-key",
            ConfigError::UnknownSection { .. } => "unknown-section",
            ConfigError::MissingField { .. } => "missing-field",
            ConfigError::UnknownRole { .. } => "unknown-role",
            ConfigError::MissingDurablePath { .. } => "missing-durable-path",
            ConfigError::NotADirectory { .. } => "not-a-directory",
            ConfigError::UnresolvedSecret { .. } => "unresolved-secret",
            ConfigError::InvalidSecretEnv => "invalid-secret-env",
            ConfigError::SecretTooLong { .. } => "secret-too-long",
            ConfigError::FieldCapabilityAbsent => "field-capability-absent",
            ConfigError::ListenerNotSupported => "listener-not-supported",
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, message } => {
                write!(f, "cannot read config '{path}': {message}")
            }
            ConfigError::Parse { line, message } => {
                write!(f, "config parse error at line {line}: {message}")
            }
            ConfigError::UnknownKey { key } => write!(
                f,
                "unknown key '{key}'; allowed keys: role, durable_path, secret_env, field_listener"
            ),
            ConfigError::UnknownSection { section } => write!(
                f,
                "unknown section '[{section}]'; PR01 accepts only flat keys (no sections)"
            ),
            ConfigError::MissingField { field } => write!(f, "missing required field '{field}'"),
            ConfigError::UnknownRole { got } => write!(
                f,
                "unknown role '{got}'; expected one of: standalone, edge, hub"
            ),
            ConfigError::MissingDurablePath { path } => write!(
                f,
                "missing durable path '{path}'; create the directory first \
                 (PR01 never creates it implicitly; durable stores arrive in M01-PR03)"
            ),
            ConfigError::NotADirectory { path } => {
                write!(f, "durable path '{path}' exists but is not a directory")
            }
            ConfigError::UnresolvedSecret { var } => write!(
                f,
                "unresolved secret: environment variable '{var}' is unset or empty"
            ),
            ConfigError::InvalidSecretEnv => write!(
                f,
                "invalid secret_env: variable name must be a non-empty string"
            ),
            ConfigError::SecretTooLong { var, len } => write!(
                f,
                "secret from '{var}' is {len} chars; PR01 local issuance ceiling is {MAX_SECRET_LEN} chars"
            ),
            ConfigError::FieldCapabilityAbsent => write!(
                f,
                "field capability absent: 'field_listener = true' requested but PR01 \
                 starts no field listener (native engine deferred to M01-PR05); \
                 omit the setting or set it to false"
            ),
            ConfigError::ListenerNotSupported => write!(
                f,
                "remote listener '[listener]' is not supported in PR01 \
                 (local-only; no anonymous remote listener per D04)"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Flat keys PR01 accepts. Everything else is an `unknown-key` refusal.
const ALLOWED_KEYS: [&str; 4] = ["role", "durable_path", "secret_env", "field_listener"];

struct Entry {
    line: usize,
    value: String,
    quoted: bool,
}

/// Load and validate a config file. Filesystem and environment are consulted:
/// the durable path must already exist as a directory, and `secret_env` must
/// resolve. No sockets are opened and no directories are created.
pub fn load_from_path(path: &Path) -> Result<Config, ConfigError> {
    let src = fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    load_str(&src)
}

/// Load and validate config from a string (same rules as files; used by
/// callers and tests that manage their own fixtures).
pub fn load_str(src: &str) -> Result<Config, ConfigError> {
    let map = parse_kv(src)?;
    for key in map.keys() {
        if !ALLOWED_KEYS.contains(&key.as_str()) {
            return Err(ConfigError::UnknownKey { key: key.clone() });
        }
    }

    let role_raw = required(&map, "role")?;
    let role: Role = role_raw.value.parse()?;

    let durable_raw = required(&map, "durable_path")?;
    if durable_raw.value.is_empty() {
        return Err(ConfigError::MissingField {
            field: "durable_path",
        });
    }
    let durable_path = PathBuf::from(&durable_raw.value);
    if !durable_path.exists() {
        return Err(ConfigError::MissingDurablePath {
            path: durable_raw.value.clone(),
        });
    }
    if !durable_path.is_dir() {
        return Err(ConfigError::NotADirectory {
            path: durable_raw.value.clone(),
        });
    }

    let (secret_env, secret) = match map.get("secret_env") {
        None => (None, None),
        Some(entry) => {
            if entry.value.is_empty() {
                return Err(ConfigError::InvalidSecretEnv);
            }
            match env::var(&entry.value) {
                Ok(value) if !value.is_empty() => {
                    if value.len() > MAX_SECRET_LEN {
                        return Err(ConfigError::SecretTooLong {
                            var: entry.value.clone(),
                            len: value.len(),
                        });
                    }
                    (Some(entry.value.clone()), Some(Secret::new(value)))
                }
                _ => {
                    return Err(ConfigError::UnresolvedSecret {
                        var: entry.value.clone(),
                    })
                }
            }
        }
    };

    if let Some(entry) = map.get("field_listener") {
        if entry.quoted {
            return Err(ConfigError::Parse {
                line: entry.line,
                message: "field_listener expects bare true/false, not a quoted string".to_string(),
            });
        }
        match entry.value.as_str() {
            "true" => return Err(ConfigError::FieldCapabilityAbsent),
            "false" => {}
            _ => {
                return Err(ConfigError::Parse {
                    line: entry.line,
                    message: format!(
                        "field_listener expects true/false, got '{}'",
                        entry.value
                    ),
                })
            }
        }
    }

    Ok(Config {
        role,
        durable_path,
        secret_env,
        secret,
        field_listener_requested: false,
    })
}

fn required<'a>(
    map: &'a BTreeMap<String, Entry>,
    field: &'static str,
) -> Result<&'a Entry, ConfigError> {
    map.get(field)
        .ok_or(ConfigError::MissingField { field })
}

fn parse_kv(src: &str) -> Result<BTreeMap<String, Entry>, ConfigError> {
    let mut map: BTreeMap<String, Entry> = BTreeMap::new();
    for (index, raw_line) in src.lines().enumerate() {
        let line_no = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if line.ends_with(']') {
                let section = line[1..line.len() - 1].trim();
                match section {
                    "field" => return Err(ConfigError::FieldCapabilityAbsent),
                    "listener" => return Err(ConfigError::ListenerNotSupported),
                    _ => {
                        return Err(ConfigError::UnknownSection {
                            section: section.to_string(),
                        })
                    }
                }
            }
            return Err(ConfigError::Parse {
                line: line_no,
                message: "malformed section header (expected '[name]')".to_string(),
            });
        }
        let eq = line.find('=').ok_or(ConfigError::Parse {
            line: line_no,
            message: "expected 'key = value'".to_string(),
        })?;
        let key = line[..eq].trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ConfigError::Parse {
                line: line_no,
                message: format!("invalid key '{key}'"),
            });
        }
        let rest = line[eq + 1..].trim();
        let entry = parse_value(rest, line_no)?;
        if map.insert(key.to_string(), entry).is_some() {
            return Err(ConfigError::Parse {
                line: line_no,
                message: format!("duplicate key '{key}'"),
            });
        }
    }
    Ok(map)
}

fn parse_value(rest: &str, line: usize) -> Result<Entry, ConfigError> {
    if rest.starts_with('"') {
        let mut out = String::new();
        let mut chars = rest[1..].char_indices();
        let mut closed = false;
        while let Some((_, c)) = chars.next() {
            match c {
                '"' => {
                    closed = true;
                    break;
                }
                '\\' => match chars.next() {
                    Some((_, 'n')) => out.push('\n'),
                    Some((_, 't')) => out.push('\t'),
                    Some((_, 'r')) => out.push('\r'),
                    Some((_, '\\')) => out.push('\\'),
                    Some((_, '"')) => out.push('"'),
                    _ => {
                        return Err(ConfigError::Parse {
                            line,
                            message: "invalid escape (use \\\\, \\\", \\n, \\t, \\r)".to_string(),
                        })
                    }
                },
                _ => out.push(c),
            }
        }
        if !closed {
            return Err(ConfigError::Parse {
                line,
                message: "unterminated quoted string".to_string(),
            });
        }
        // Anything after the closing quote must be blank or a comment.
        let consumed = rest.len() - chars.as_str().len();
        let tail = rest[consumed..].trim();
        if !tail.is_empty() && !tail.starts_with('#') {
            return Err(ConfigError::Parse {
                line,
                message: "trailing characters after value".to_string(),
            });
        }
        Ok(Entry {
            line,
            value: out,
            quoted: true,
        })
    } else if rest.starts_with('\'') {
        Err(ConfigError::Parse {
            line,
            message: "single quotes are not supported; use double quotes".to_string(),
        })
    } else {
        // Bare token; a '#' starts an inline comment.
        let token = rest.split('#').next().unwrap_or("").trim();
        if token.is_empty() {
            return Err(ConfigError::Parse {
                line,
                message: "missing value after '='".to_string(),
            });
        }
        Ok(Entry {
            line,
            value: token.to_string(),
            quoted: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn unique_env(test: &str) -> String {
        let id = SEQ.fetch_add(1, Ordering::SeqCst);
        format!(
            "VERDANT_PR01_UNIT_{}_{}_{}",
            test,
            std::process::id(),
            id
        )
    }

    fn existing_dir_config(role: &str, extra: &str) -> String {
        let dir = env::temp_dir().display().to_string();
        format!("role = \"{role}\"\ndurable_path = \"{dir}\"\n{extra}")
    }

    #[test]
    fn valid_roles_parse() {
        for (name, expected) in [
            ("standalone", Role::Standalone),
            ("edge", Role::Edge),
            ("hub", Role::Hub),
        ] {
            let cfg = load_str(&existing_dir_config(name, "")).expect("valid role loads");
            assert_eq!(cfg.role, expected);
            assert_eq!(cfg.role.as_str(), name);
            assert!(!cfg.field_listener_requested);
            assert!(cfg.secret.is_none());
        }
        assert_eq!(Role::VALID, ["standalone", "edge", "hub"]);
    }

    #[test]
    fn unknown_role_fails_usefully() {
        let err = load_str(&existing_dir_config("superhub", "")).unwrap_err();
        assert_eq!(err.code(), "unknown-role");
        let msg = err.to_string();
        assert!(msg.contains("superhub"), "names the bad value: {msg}");
        assert!(msg.contains("standalone") && msg.contains("edge") && msg.contains("hub"));
    }

    #[test]
    fn role_is_case_sensitive() {
        let err = load_str(&existing_dir_config("Standalone", "")).unwrap_err();
        assert_eq!(err.code(), "unknown-role");
    }

    #[test]
    fn unknown_key_is_refused() {
        let src = existing_dir_config("standalone", "bogus_key = \"1\"\n");
        let err = load_str(&src).unwrap_err();
        assert_eq!(err.code(), "unknown-key");
        assert!(err.to_string().contains("bogus_key"));
    }

    #[test]
    fn missing_role_and_durable_path_are_refused() {
        let dir = env::temp_dir().display().to_string();
        let err = load_str(&format!("durable_path = \"{dir}\"\n")).unwrap_err();
        assert_eq!(err.code(), "missing-field");
        let err = load_str("role = \"edge\"\n").unwrap_err();
        assert_eq!(err.code(), "missing-field");
    }

    #[test]
    fn missing_durable_path_fails_without_creating_it() {
        let missing = env::temp_dir().join(format!(
            "verdant-pr01-unit-missing-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        assert!(!missing.exists());
        let src = format!(
            "role = \"edge\"\ndurable_path = \"{}\"\n",
            missing.display()
        );
        let err = load_str(&src).unwrap_err();
        assert_eq!(err.code(), "missing-durable-path");
        assert!(!missing.exists(), "PR01 must not create the durable path");
    }

    #[test]
    fn file_durable_path_is_refused() {
        let file = env::temp_dir().join(format!(
            "verdant-pr01-unit-file-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::write(&file, b"synthetic").unwrap();
        let src = format!(
            "role = \"standalone\"\ndurable_path = \"{}\"\n",
            file.display()
        );
        let err = load_str(&src).unwrap_err();
        assert_eq!(err.code(), "not-a-directory");
        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn unresolved_secret_env_fails() {
        let var = unique_env("unresolved");
        env::remove_var(&var);
        let src = existing_dir_config("hub", &format!("secret_env = \"{var}\"\n"));
        let err = load_str(&src).unwrap_err();
        assert_eq!(err.code(), "unresolved-secret");
        assert!(err.to_string().contains(&var));
        assert!(!err.to_string().contains("secret-value"), "no secret material in errors");
    }

    #[test]
    fn empty_secret_env_value_is_unresolved() {
        let var = unique_env("empty");
        env::set_var(&var, "");
        let src = existing_dir_config("hub", &format!("secret_env = \"{var}\"\n"));
        let err = load_str(&src).unwrap_err();
        assert_eq!(err.code(), "unresolved-secret");
        env::remove_var(&var);
    }

    #[test]
    fn resolved_secret_is_opaque_and_redacted() {
        let var = unique_env("resolved");
        env::set_var(&var, "synthetic-test-credential-0123456789");
        let src = existing_dir_config("edge", &format!("secret_env = \"{var}\"\n"));
        let cfg = load_str(&src).expect("resolves");
        assert_eq!(cfg.secret_env.as_deref(), Some(var.as_str()));
        let secret = cfg.secret.as_ref().expect("secret present");
        assert!(!secret.is_empty());
        let debug = format!("{secret:?}");
        assert!(debug.contains("<redacted"), "debug redacts: {debug}");
        assert!(!debug.contains("synthetic-test-credential"), "no leak: {debug}");
        let summary = cfg.summary_redacted();
        assert!(summary.contains(&var));
        assert!(!summary.contains("synthetic-test-credential"), "summary redacts");
        env::remove_var(&var);
    }

    #[test]
    fn overlong_secret_hits_issuance_ceiling() {
        let var = unique_env("toolong");
        env::set_var(&var, "x".repeat(MAX_SECRET_LEN + 1));
        let src = existing_dir_config("standalone", &format!("secret_env = \"{var}\"\n"));
        let err = load_str(&src).unwrap_err();
        assert_eq!(err.code(), "secret-too-long");
        env::remove_var(&var);
    }

    #[test]
    fn empty_secret_env_name_is_invalid() {
        let src = existing_dir_config("standalone", "secret_env = \"\"\n");
        let err = load_str(&src).unwrap_err();
        assert_eq!(err.code(), "invalid-secret-env");
    }

    #[test]
    fn field_listener_true_is_refused_capability_absent() {
        let src = existing_dir_config("standalone", "field_listener = true\n");
        let err = load_str(&src).unwrap_err();
        assert_eq!(err.code(), "field-capability-absent");
    }

    #[test]
    fn field_section_is_refused_capability_absent() {
        let src = existing_dir_config("edge", "[field]\nlistener = true\n");
        let err = load_str(&src).unwrap_err();
        assert_eq!(err.code(), "field-capability-absent");
    }

    #[test]
    fn listener_section_is_refused() {
        let dir = env::temp_dir().display().to_string();
        let src = format!("role = \"hub\"\ndurable_path = \"{dir}\"\n[listener]\nbind = \"0.0.0.0:8080\"\n");
        let err = load_str(&src).unwrap_err();
        assert_eq!(err.code(), "listener-not-supported");
    }

    #[test]
    fn unknown_section_is_refused() {
        let src = existing_dir_config("hub", "[telemetry]\nrate = 1\n");
        let err = load_str(&src).unwrap_err();
        assert_eq!(err.code(), "unknown-section");
    }

    #[test]
    fn omitted_field_setting_starts_no_listener() {
        let cfg = load_str(&existing_dir_config("standalone", "")).expect("loads");
        assert!(!cfg.field_listener_requested);
        let cfg = load_str(&existing_dir_config("hub", "field_listener = false\n")).expect("loads");
        assert!(!cfg.field_listener_requested);
    }

    #[test]
    fn malformed_inputs_fail_with_line_numbers() {
        for (src, fragment) in [
            ("role standalone\n", "expected 'key = value'"),
            ("role = 'standalone'\n", "single quotes"),
            ("= 1\n", "invalid key"),
            (
                "role = \"standalone\"\nrole = \"edge\"\n",
                "duplicate key",
            ),
            ("role = \"standalone\n", "unterminated"),
            ("role = \"a\" trailing\n", "trailing characters"),
            ("[broken\n", "malformed section"),
            ("role = \n", "missing value"),
            ("role = \"standalone\" # comment, durable_path still required\n", "missing required field"),
        ] {
            let err = load_str(src).unwrap_err();
            assert!(
                err.to_string().contains(fragment),
                "input {src:?} should mention '{fragment}', got: {err}"
            );
        }
    }
}
