//! Executable boundary: API wiring must not change the PR01 shell's bytes.
use std::process::{Command, Stdio};

#[test]
fn api_wiring_keeps_shell_smoke_markers_byte_identical() {
    let dir = std::env::temp_dir().join(format!("verdant-pr09-api-smoke-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let durable = dir.join("durable");
    std::fs::create_dir(&durable).unwrap();
    let config = dir.join("ok.conf");
    std::fs::write(
        &config,
        format!(
            "role = \"standalone\"\ndurable_path = \"{}\"\n",
            durable.display()
        ),
    )
    .unwrap();
    let bin = env!("CARGO_BIN_EXE_verdant");
    let health = Command::new(bin)
        .args(["health", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(health.status.code(), Some(0));
    assert!(health.stderr.is_empty());
    let listener = b"listener: none (local-only; PR01 binds no socket)\n";
    assert!(health
        .stdout
        .windows(listener.len())
        .any(|bytes| bytes == listener));
    let child = Command::new(bin)
        .args(["run", "--config"])
        .arg(&config)
        .arg("--once")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let run = child.wait_with_output().unwrap();
    assert_eq!(run.status.code(), Some(0));
    assert!(run.stderr.is_empty());
    // Independent PR01 literals; only the fixture path and observed PID vary.
    let expected = format!("verdant starting role=standalone durable_path={} listener=none field_capability=absent pid={pid}\nverdant stopped reason=once role=standalone exit=0\n", durable.display());
    assert_eq!(run.stdout, expected.as_bytes());
    let invalid = dir.join("bad.conf");
    std::fs::write(
        &invalid,
        format!(
            "role = \"nope\"\ndurable_path = \"{}\"\n",
            durable.display()
        ),
    )
    .unwrap();
    let refusal = Command::new(bin)
        .args(["run", "--config"])
        .arg(&invalid)
        .arg("--once")
        .output()
        .unwrap();
    assert_eq!(refusal.status.code(), Some(1));
    assert!(refusal.stdout.is_empty());
    assert!(String::from_utf8(refusal.stderr)
        .unwrap()
        .contains("[unknown-role]"));
    assert_eq!(std::fs::read_dir(&durable).unwrap().count(), 0);
    println!("smoke: observed exits 0/0/1; listener none; start/stop bytes identical; invalid role refused; no stores activated");
}
