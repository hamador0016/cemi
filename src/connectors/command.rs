//! Commands as origins or destinations, and external connectors.
//!
//! - Origin command: Cemí runs `<command> create` and reads the new value from
//!   stdout; `<command> revoke` gets the old value on stdin.
//! - Destination command: Cemí runs `<command>` with the value on stdin.
//! - External connector `cemi-connector-<name>`: one JSON request on stdin,
//!   one JSON answer on stdout (docs/connectors.md).
//!
//! Output is shown with the value hidden.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{NewKey, Observed, Revoked};
use crate::runner::{Redactor, resolve_program};

pub const PROTOCOL: u32 = 1;

pub fn validate_connector_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        bail!("connector names use lowercase letters, digits and -, got {name:?}");
    }
    Ok(())
}

pub fn connector_program(name: &str) -> PathBuf {
    resolve_program(&format!("cemi-connector-{name}"))
}

pub(super) struct Ran {
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: Vec<u8>,
}

/// Runs a program, writing `input` to its stdin from another thread so large
/// outputs cannot block it.
pub(super) fn run(
    argv: &[String],
    extra: &[&str],
    input: &[u8],
    envs: &[(&str, &str)],
) -> Result<Ran> {
    let program = argv.first().ok_or_else(|| anyhow!("empty command"))?;
    let mut cmd = Command::new(resolve_program(program));
    cmd.args(&argv[1..])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("cannot start {program}"))?;
    let mut stdin = child.stdin.take().expect("piped");
    let input = Zeroizing::new(input.to_vec());
    let writer = std::thread::spawn(move || {
        // A program that does not read its input closes the pipe: not an error.
        let _ = stdin.write_all(&input);
    });
    let out = child.wait_with_output()?;
    let _ = writer.join();
    Ok(Ran {
        ok: out.status.success(),
        code: out.status.code(),
        stdout: Zeroizing::new(out.stdout),
        stderr: out.stderr,
    })
}

/// Prints a program's output with `secrets` hidden.
pub(super) fn show(label: &str, bytes: &[u8], secrets: &[&[u8]]) {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return;
    }
    let pairs: Vec<(String, Zeroizing<Vec<u8>>)> = secrets
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| ("VALUE".to_string(), Zeroizing::new(s.to_vec())))
        .collect();
    let text = Redactor::new(&pairs).redact(bytes);
    for line in String::from_utf8_lossy(&text).lines() {
        eprintln!("  {label}| {line}");
    }
}

fn failed(argv: &[String], ran: &Ran) -> anyhow::Error {
    crate::errors::external(format!(
        "`{}` failed{}",
        argv.join(" "),
        ran.code
            .map(|c| format!(" with exit code {c}"))
            .unwrap_or_default()
    ))
}

pub fn origin_create(argv: &[String]) -> Result<NewKey> {
    let ran = run(argv, &["create"], b"", &[])?;
    show(&argv[0], &ran.stderr, &[]);
    if !ran.ok {
        return Err(failed(argv, &ran));
    }
    let mut text = String::from_utf8(ran.stdout.to_vec())
        .map_err(|_| anyhow!("`{} create` printed something that is not text", argv[0]))?;
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    let value = Zeroizing::new(text);
    if value.is_empty() {
        bail!(
            "`{} create` printed nothing: it must print the new value",
            argv[0]
        );
    }
    Ok(NewKey {
        value,
        provider_id: None,
    })
}

pub fn origin_revoke(argv: &[String], old: &[u8], compromised: bool) -> Result<Revoked> {
    let flag = if compromised { "1" } else { "0" };
    let ran = run(argv, &["revoke"], old, &[("CEMI_COMPROMISED", flag)])?;
    show(&argv[0], &ran.stdout, &[old]);
    show(&argv[0], &ran.stderr, &[old]);
    if !ran.ok {
        return Err(failed(argv, &ran));
    }
    Ok(Revoked::Done)
}

pub fn dest_write(argv: &[String], value: &[u8]) -> Result<()> {
    let ran = run(argv, &[], value, &[])?;
    show(&argv[0], &ran.stdout, &[value]);
    show(&argv[0], &ran.stderr, &[value]);
    if !ran.ok {
        return Err(failed(argv, &ran));
    }
    Ok(())
}

#[derive(Deserialize, Default)]
struct Answer {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    provider_id: Option<String>,
    #[serde(default)]
    remote: Option<String>,
    #[serde(default)]
    missing: bool,
    #[serde(default)]
    manual: Option<String>,
}

fn external(
    name: &str,
    action: &str,
    config: &BTreeMap<String, String>,
    secrets: &BTreeMap<String, Zeroizing<String>>,
    extra: serde_json::Map<String, serde_json::Value>,
    hide: &[&[u8]],
) -> Result<Answer> {
    let program = connector_program(name);
    let mut req = serde_json::Map::new();
    req.insert("protocol".into(), PROTOCOL.into());
    req.insert("action".into(), action.into());
    req.insert("config".into(), serde_json::to_value(config)?);
    let secrets_json: serde_json::Map<String, serde_json::Value> = secrets
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.to_string())))
        .collect();
    req.insert("secrets".into(), secrets_json.into());
    req.extend(extra);
    let input = Zeroizing::new(serde_json::to_vec(&req)?);
    let argv = [program.display().to_string()];
    let ran = run(&argv, &[], &input, &[]).map_err(|_| {
        anyhow!(
            "connector {name:?} is not installed: Cemí looks for a program called cemi-connector-{name} in your PATH"
        )
    })?;
    let mut hidden: Vec<&[u8]> = hide.to_vec();
    hidden.extend(secrets.values().map(|s| s.as_bytes()));
    show(name, &ran.stderr, &hidden);
    let answer: Answer = serde_json::from_slice(&ran.stdout).map_err(|_| {
        anyhow!("connector {name:?} did not answer with JSON on stdout (protocol {PROTOCOL})")
    })?;
    if !answer.ok || !ran.ok {
        bail!(
            "connector {name:?} failed: {}",
            answer.error.as_deref().unwrap_or("no reason given")
        );
    }
    Ok(answer)
}

pub fn external_create(
    name: &str,
    config: &BTreeMap<String, String>,
    secrets: &BTreeMap<String, Zeroizing<String>>,
) -> Result<NewKey> {
    let a = external(name, "create", config, secrets, Default::default(), &[])?;
    let value = Zeroizing::new(
        a.value
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("connector {name:?} did not return a value"))?,
    );
    Ok(NewKey {
        value,
        provider_id: a.provider_id,
    })
}

pub fn external_revoke(
    name: &str,
    config: &BTreeMap<String, String>,
    secrets: &BTreeMap<String, Zeroizing<String>>,
    provider_id: Option<&str>,
    old: &[u8],
    compromised: bool,
) -> Result<Revoked> {
    let mut extra = serde_json::Map::new();
    extra.insert(
        "value".into(),
        String::from_utf8_lossy(old).into_owned().into(),
    );
    if let Some(id) = provider_id {
        extra.insert("provider_id".into(), id.into());
    }
    extra.insert("compromised".into(), compromised.into());
    let a = external(name, "revoke", config, secrets, extra, &[old])?;
    Ok(match a.manual {
        Some(m) => Revoked::Manual(m),
        None => Revoked::Done,
    })
}

pub fn external_write(
    name: &str,
    config: &BTreeMap<String, String>,
    secrets: &BTreeMap<String, Zeroizing<String>>,
    value: &[u8],
) -> Result<()> {
    let text = std::str::from_utf8(value)
        .map_err(|_| anyhow!("this value is binary; connectors take text"))?;
    let mut extra = serde_json::Map::new();
    extra.insert("value".into(), text.into());
    external(name, "write", config, secrets, extra, &[value])?;
    Ok(())
}

pub fn external_observe(
    name: &str,
    config: &BTreeMap<String, String>,
    secrets: &BTreeMap<String, Zeroizing<String>>,
) -> Result<Observed> {
    let a = external(name, "observe", config, secrets, Default::default(), &[])?;
    Ok(if a.missing {
        Observed::Missing
    } else {
        match a.remote {
            Some(r) => Observed::Remote(r),
            None => Observed::Unknown,
        }
    })
}
