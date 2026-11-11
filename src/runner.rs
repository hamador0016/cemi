//! Running a command with secrets injected, and hiding them in its output.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use aho_corasick::{AhoCorasick, MatchKind};
use anyhow::{Context, Result, bail};
use data_encoding::{BASE64, BASE64URL_NOPAD, HEXLOWER};
use zeroize::Zeroizing;

use crate::project::Project;
use crate::resolve::{self, Resolved};
use crate::workspace::Workspace;

pub struct Plan {
    pub env: Vec<(String, Zeroizing<String>)>,
    pub files: Vec<(String, String, Zeroizing<Vec<u8>>)>,
    /// (name, value) of every secret, for redaction.
    pub secrets: Vec<(String, Zeroizing<Vec<u8>>)>,
}

/// Resolves every `[env]` and `[files]` entry of the project for `env`.
pub fn plan(ws: &mut Workspace, project: &Project, env: Option<&str>) -> Result<Plan> {
    let mut plan = Plan {
        env: Vec::new(),
        files: Vec::new(),
        secrets: Vec::new(),
    };
    let mut problems = Vec::new();
    for (var, spec) in &project.file.env {
        let r = project.resolve_ref(spec.text())?;
        match resolve::resolve(ws, &r, env) {
            Ok(v) => {
                let text = v.text().with_context(|| format!("{var} ({r})"))?;
                if v.secret {
                    plan.secrets.push((var.clone(), v.bytes.clone()));
                }
                plan.env.push((var.clone(), text));
            }
            Err(e) => problems.push(format!("{var}: {e}")),
        }
    }
    for (var, spec) in &project.file.files {
        let r = project.resolve_ref(spec.text())?;
        match resolve::resolve(ws, &r, env) {
            Ok(Resolved {
                bytes,
                secret,
                file_name,
                ..
            }) => {
                let name = file_name.unwrap_or_else(|| var.to_lowercase());
                if secret {
                    plan.secrets.push((var.clone(), bytes.clone()));
                }
                plan.files.push((var.clone(), name, bytes));
            }
            Err(e) => problems.push(format!("{var}: {e}")),
        }
    }
    if !problems.is_empty() {
        bail!("some values are missing:\n  {}", problems.join("\n  "));
    }
    Ok(plan)
}

pub struct Prepared {
    pub env: Vec<(String, Zeroizing<String>)>,
    /// Deleted (with the secret files) when dropped.
    _dir: Option<tempfile::TempDir>,
}

impl Prepared {
    pub fn from_env(env: Vec<(String, Zeroizing<String>)>) -> Prepared {
        Prepared { env, _dir: None }
    }
}

/// Finds a program on PATH. On Windows this also tries PATHEXT (`npm` → `npm.cmd`),
/// which the standard library does not do by itself.
pub fn resolve_program(name: &str) -> PathBuf {
    let p = std::path::Path::new(name);
    if p.components().count() > 1 || !cfg!(windows) {
        return p.to_path_buf();
    }
    let exts: Vec<String> = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
        .split(';')
        .filter(|e| !e.is_empty())
        .map(|e| e.to_lowercase())
        .collect();
    let has_ext = p
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| exts.contains(&format!(".{}", e.to_lowercase())));
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            if has_ext {
                let c = dir.join(name);
                if c.is_file() {
                    return c;
                }
                continue;
            }
            for ext in &exts {
                let c = dir.join(format!("{name}{ext}"));
                if c.is_file() {
                    return c;
                }
            }
        }
    }
    p.to_path_buf()
}

/// Writes file secrets to a private temporary folder.
pub fn prepare(plan: &Plan) -> Result<Prepared> {
    let mut env = plan.env.clone();
    let dir = if plan.files.is_empty() {
        None
    } else {
        let dir = tempfile::Builder::new().prefix("cemi-").tempdir()?;
        restrict(dir.path());
        for (var, name, bytes) in &plan.files {
            let safe_name: String = name
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || ".-_".contains(c) {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            let sub = dir.path().join(var);
            std::fs::create_dir(&sub)?;
            let path: PathBuf = sub.join(safe_name);
            std::fs::write(&path, bytes.as_slice())?;
            env.push((
                var.clone(),
                Zeroizing::new(path.to_string_lossy().into_owned()),
            ));
        }
        Some(dir)
    };
    Ok(Prepared { env, _dir: dir })
}

#[cfg(unix)]
fn restrict(p: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn restrict(_p: &std::path::Path) {}

fn command(argv: &[String], env: &[(String, Zeroizing<String>)]) -> Result<Command> {
    let Some((program, args)) = argv.split_first() else {
        bail!("no command given. Usage: cemi run -e dev -- <command>");
    };
    let mut cmd = Command::new(resolve_program(program));
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v.as_str());
    }
    Ok(cmd)
}

/// Runs interactively (terminal passed through). Returns the exit code.
pub fn run_interactive(
    argv: &[String],
    prepared: &Prepared,
    redactor: Option<&Redactor>,
) -> Result<i32> {
    // Ctrl+C goes to the child; we stay alive to clean up the temporary files.
    let _ = ctrlc::set_handler(|| {});
    let mut cmd = command(argv, &prepared.env)?;
    if let Some(redactor) = redactor {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("cannot start {:?}", argv[0]))?;
        let out = child.stdout.take().expect("piped");
        let err = child.stderr.take().expect("piped");
        std::thread::scope(|s| {
            s.spawn(|| redactor.copy(out, std::io::stdout()));
            s.spawn(|| redactor.copy(err, std::io::stderr()));
        });
        let status = child.wait()?;
        return Ok(status.code().unwrap_or(1));
    }
    let status = cmd
        .status()
        .with_context(|| format!("cannot start {:?}", argv[0]))?;
    Ok(status.code().unwrap_or(1))
}

pub struct Captured {
    pub exit_code: Option<i32>,
    pub output: String,
    pub truncated: bool,
    pub timed_out: bool,
}

/// Runs without a terminal (for AI clients): output captured, redacted and capped.
pub fn run_captured(
    argv: &[String],
    cwd: &std::path::Path,
    prepared: &Prepared,
    redactor: &Redactor,
    timeout: Duration,
    max_bytes: usize,
) -> Result<Captured> {
    let mut cmd = command(argv, &prepared.env)?;
    cmd.current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("cannot start {:?}", argv[0]))?;
    let out = child.stdout.take().expect("piped");
    let err = child.stderr.take().expect("piped");
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let tx2 = tx.clone();
    let r1 = redactor.clone();
    let r2 = redactor.clone();
    let h1 = std::thread::spawn(move || {
        let mut buf = Vec::new();
        r1.copy(out, &mut buf);
        let _ = tx.send(buf);
    });
    let h2 = std::thread::spawn(move || {
        let mut buf = Vec::new();
        r2.copy(err, &mut buf);
        let _ = tx2.send(buf);
    });
    let started = std::time::Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break Some(s);
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            timed_out = true;
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = h1.join();
    let _ = h2.join();
    let mut all = Vec::new();
    for part in rx.try_iter() {
        all.extend_from_slice(&part);
    }
    let truncated = all.len() > max_bytes;
    if truncated {
        let cut = all.len() - max_bytes;
        all.drain(..cut);
    }
    Ok(Captured {
        exit_code: status.and_then(|s| s.code()),
        output: String::from_utf8_lossy(&all).into_owned(),
        truncated,
        timed_out,
    })
}

/// Replaces known secret values (and their common encodings) in a byte stream.
#[derive(Clone)]
pub struct Redactor {
    matcher: Option<AhoCorasick>,
    labels: Vec<String>,
    longest: usize,
}

impl Redactor {
    pub fn new(secrets: &[(String, Zeroizing<Vec<u8>>)]) -> Redactor {
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut labels = Vec::new();
        let mut seen = BTreeMap::new();
        for (name, value) in secrets {
            for variant in variants(value) {
                // Very short values would hide ordinary text; they are skipped.
                if variant.len() < 6 || seen.contains_key(variant.as_slice()) {
                    continue;
                }
                seen.insert(variant.to_vec(), ());
                patterns.push(variant);
                labels.push(format!("[hidden:{name}]"));
            }
        }
        let longest = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        let matcher = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(patterns.iter().map(|p| p.as_slice()))
                    .expect("patterns are valid"),
            )
        };
        Redactor {
            matcher,
            labels,
            longest,
        }
    }

    pub fn redact(&self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.copy(input, &mut out);
        out
    }

    /// Streams `reader` to `writer`, holding back just enough bytes to catch
    /// a secret split across two reads.
    pub fn copy(&self, mut reader: impl Read, mut writer: impl Write) {
        let mut pending: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 8192];
        loop {
            let n = reader.read(&mut chunk).unwrap_or(0);
            let eof = n == 0;
            pending.extend_from_slice(&chunk[..n]);
            let safe_end = if eof {
                pending.len()
            } else {
                pending.len().saturating_sub(self.longest.saturating_sub(1))
            };
            let mut out = Vec::with_capacity(pending.len());
            let mut last = 0;
            if let Some(m) = &self.matcher {
                for found in m.find_iter(&pending) {
                    if found.start() >= safe_end {
                        break;
                    }
                    out.extend_from_slice(&pending[last..found.start()]);
                    out.extend_from_slice(self.labels[found.pattern().as_usize()].as_bytes());
                    last = found.end();
                }
            }
            let emit_to = safe_end.max(last);
            if emit_to > last {
                out.extend_from_slice(&pending[last..emit_to]);
            }
            pending.drain(..emit_to);
            let _ = writer.write_all(&out);
            let _ = writer.flush();
            if eof {
                break;
            }
        }
    }
}

fn variants(value: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut v = vec![Zeroizing::new(value.to_vec())];
    v.push(Zeroizing::new(BASE64.encode(value).into_bytes()));
    v.push(Zeroizing::new(BASE64URL_NOPAD.encode(value).into_bytes()));
    v.push(Zeroizing::new(HEXLOWER.encode(value).into_bytes()));
    let encoded: String = value
        .iter()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(b) {
                (*b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    v.push(Zeroizing::new(encoded.into_bytes()));
    // Values with a trailing newline (files) also show up without it.
    if let Some(trimmed) = value.strip_suffix(b"\n") {
        v.push(Zeroizing::new(trimmed.to_vec()));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::new(&[("TOKEN".into(), Zeroizing::new(b"sk_live_abc123".to_vec()))])
    }

    #[test]
    fn hides_plain_and_encoded_values() {
        let out = r().redact(
            b"token=sk_live_abc123 b64=c2tfbGl2ZV9hYmMxMjM= hex=736b5f6c6976655f616263313233",
        );
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("sk_live_abc123"));
        assert!(!s.contains("c2tfbGl2ZV9hYmMxMjM"));
        assert!(!s.contains("736b5f6c6976655f616263313233"));
        assert_eq!(s.matches("[hidden:TOKEN]").count(), 3);
    }

    #[test]
    fn catches_values_split_across_reads() {
        struct Slow<'a>(&'a [u8]);
        impl Read for Slow<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                let n = 3.min(self.0.len()).min(buf.len());
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let mut out = Vec::new();
        r().copy(Slow(b"aa sk_live_abc123 bb"), &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "aa [hidden:TOKEN] bb");
    }

    #[test]
    fn no_secrets_passes_through() {
        let red = Redactor::new(&[]);
        assert_eq!(red.redact(b"hello"), b"hello");
    }
}
