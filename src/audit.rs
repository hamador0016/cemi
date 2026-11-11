//! Audit log: who used what, when. Values are never written.
//!
//! Each line is one entry encrypted to the vault key (so writing needs no
//! unlock, and reading needs it). Every entry carries the SHA-256 of the
//! previous line, so deleted or reordered lines show up in `cemi log --verify`.
//! This catches accidents and partial tampering; someone with write access to
//! the folder could still rewrite the whole file.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use data_encoding::BASE64;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::crypto::{self, AgeKey};
use crate::vault::Header;

pub const FILE: &str = "audit.log";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub at: Timestamp,
    /// "cli", or "mcp:<token name>".
    pub actor: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub prev: String,
}

pub struct Event<'a> {
    pub actor: &'a str,
    pub action: &'a str,
    pub target: Option<String>,
    pub env: Option<String>,
    pub detail: Option<String>,
}

fn last_line_hash(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok(String::new());
    }
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|l| crypto::sha256_hex(l.trim().as_bytes()))
        .unwrap_or_default())
}

pub fn append(dir: &Path, header: &Header, event: Event<'_>) -> Result<()> {
    let path = dir.join(FILE);
    let entry = Entry {
        at: Timestamp::now(),
        actor: event.actor.to_string(),
        action: event.action.to_string(),
        target: event.target,
        env: event.env,
        detail: event.detail,
        prev: last_line_hash(&path)?,
    };
    let recipient = crypto::parse_recipient(&header.recipient)?;
    let ct = crypto::age_encrypt(&recipient, &serde_json::to_vec(&entry)?)?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    writeln!(f, "{}", BASE64.encode(&ct))?;
    Ok(())
}

pub struct Read {
    pub entries: Vec<Entry>,
    /// Line numbers (1-based) where the chain is broken or the line is unreadable.
    pub broken: Vec<usize>,
}

pub fn read(dir: &Path, key: &AgeKey) -> Result<Read> {
    let path = dir.join(FILE);
    let mut out = Read {
        entries: Vec::new(),
        broken: Vec::new(),
    };
    if !path.exists() {
        return Ok(out);
    }
    let text = std::fs::read_to_string(&path)?;
    let mut prev = String::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry = BASE64
            .decode(line.as_bytes())
            .ok()
            .and_then(|ct| crypto::age_decrypt_any(&[key], &ct).ok().flatten())
            .and_then(|plain| serde_json::from_slice::<Entry>(&plain).ok());
        match entry {
            Some(e) => {
                if e.prev != prev {
                    out.broken.push(i + 1);
                }
                out.entries.push(e);
            }
            None => out.broken.push(i + 1),
        }
        prev = crypto::sha256_hex(line.as_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::vault::{Scope, Vault};

    #[test]
    fn chain_detects_removed_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("v");
        let c = Vault::create(
            &dir,
            Scope::Global,
            Some("pw"),
            None,
            &[],
            KdfParams::INSECURE_FAST,
        )
        .unwrap();
        let v = c.vault;
        for i in 0..3 {
            append(
                &dir,
                &v.header,
                Event {
                    actor: "cli",
                    action: "test",
                    target: Some(format!("t{i}")),
                    env: None,
                    detail: None,
                },
            )
            .unwrap();
        }
        let r = read(&dir, v.master()).unwrap();
        assert_eq!(r.entries.len(), 3);
        assert!(r.broken.is_empty());

        let text = std::fs::read_to_string(dir.join(FILE)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(dir.join(FILE), format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        let r = read(&dir, v.master()).unwrap();
        assert_eq!(r.broken, vec![2]);
    }
}
