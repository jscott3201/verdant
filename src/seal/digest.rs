//! System SHA-256 only. Fixed executable/argv, stdin bytes, no shell and no
//! dependency. A known-answer probe and version are required at every seal-open.
//! One child per hash, bounded pipes/input/deadline; kill and reap on failure.
use super::{Result, SealError, MAX_ARTIFACT_BYTES};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Digest(String);
impl Digest {
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() != 64
            || !raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SealError::Invalid("SHA-256 hex"));
        }
        Ok(Self(raw.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Sha256 {
    executable: PathBuf,
    version: String,
}
impl Sha256 {
    pub fn open() -> Result<Self> {
        Self::probe(Path::new("/usr/bin/shasum"))
    }
    fn probe(executable: &Path) -> Result<Self> {
        let version = run(executable, &["--version"], b"")?;
        let version =
            String::from_utf8(version).map_err(|_| SealError::HashTool("version UTF-8".into()))?;
        let version = super::codec::text(version.trim())
            .map_err(|_| SealError::HashTool("version unavailable".into()))?;
        let tool = Self {
            executable: executable.into(),
            version,
        };
        if tool.hash(b"abc")?.as_str()
            != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        {
            return Err(SealError::HashTool(
                "SHA-256 known-answer probe failed".into(),
            ));
        }
        Ok(tool)
    }
    pub fn reference(&self) -> String {
        format!(
            "{} -a 256; version={}",
            self.executable.display(),
            self.version
        )
    }
    pub fn hash(&self, bytes: &[u8]) -> Result<Digest> {
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(SealError::Limit("hash input bytes"));
        }
        let output = run(&self.executable, &["-a", "256"], bytes)?;
        let raw =
            std::str::from_utf8(&output).map_err(|_| SealError::HashTool("digest UTF-8".into()))?;
        let hex = raw
            .strip_suffix("  -\n")
            .ok_or_else(|| SealError::HashTool("unexpected stdin digest response".into()))?;
        Digest::parse(hex).map_err(|_| SealError::HashTool("invalid digest response".into()))
    }
}

fn run(executable: &Path, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new(executable)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| SealError::HashTool(format!("{}: {e}", executable.display())))?;
    // Piped handles are configured above. Even an unexpected missing pipe kills
    // and reaps the child; no input-path unwrap or detached work.
    let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let (Some(mut stdin), Some(stdout), Some(stderr)) = pipes else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(SealError::HashTool("missing process pipes".into()));
    };
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(input));
        let output = scope.spawn(move || bounded_read(stdout));
        let errors = scope.spawn(move || bounded_read(stderr));
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Ok(None) => {
                    break Err(SealError::HashTool(
                        "deadline; child killed and reaped".into(),
                    ))
                }
                Err(e) => break Err(SealError::HashTool(e.to_string())),
            }
        };
        if status.is_err() {
            let _ = child.kill();
        }
        let reaped = child.wait();
        let written = writer.join();
        let out = output.join();
        let err = errors.join();
        let status = status?;
        reaped.map_err(|e| SealError::HashTool(e.to_string()))?;
        written
            .map_err(|_| SealError::HashTool("stdin worker failed".into()))?
            .map_err(|e| SealError::HashTool(e.to_string()))?;
        let out = out.map_err(|_| SealError::HashTool("stdout worker failed".into()))??;
        let err = err.map_err(|_| SealError::HashTool("stderr worker failed".into()))??;
        if !status.success() || !err.is_empty() {
            return Err(SealError::HashTool(format!("non-clean exit {status}")));
        }
        Ok(out)
    })
}
fn bounded_read(mut stream: impl Read) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0; 512];
    let mut overflow = false;
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if out.len() + n <= 512 {
            out.extend_from_slice(&chunk[..n]);
        } else {
            overflow = true;
        }
    }
    if overflow {
        Err(SealError::HashTool("output limit".into()))
    } else {
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_hash_tool_refuses_at_open() {
        assert_eq!(
            Sha256::probe(Path::new("/nonexistent/verdant-shasum"))
                .unwrap_err()
                .code(),
            "seal-sha256-unavailable"
        );
    }
    #[test]
    fn independent_sha256_vectors_and_canonical_codec() {
        let sha = Sha256::open().unwrap();
        assert_eq!(
            sha.hash(b"").unwrap().as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            super::super::codec::encode(&["a:b".into(), "é".into()]),
            "3:a:b2:é"
        );
        assert!(super::super::codec::decode("01:a", 10, 2).is_err());
    }
}
