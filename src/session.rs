//! Unlocked sessions. After the password is typed once, the vault key is kept
//! in the operating system's credential store (Windows Credential Manager,
//! macOS Keychain, Linux kernel keyring) for a short, sliding period.
//! `cemi lock` removes it right away.
//!
//! The same store keeps AI tokens, so MCP client configurations only hold a
//! token's name, never the token.

use std::path::PathBuf;

use anyhow::{Result, bail};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use crate::crypto::AgeKey;
use crate::model::Sensitive;

const SERVICE: &str = "cemi";

#[derive(Serialize, Deserialize)]
struct Stored {
    identity: Sensitive,
    expires: Timestamp,
}

enum Backend {
    Keyring,
    /// Debug builds only: a folder of files, so tests never touch the real store.
    Files(PathBuf),
    /// `CEMI_NO_SESSION`: always ask for the password.
    Disabled,
}

fn backend() -> Backend {
    if cfg!(debug_assertions)
        && let Some(dir) = std::env::var_os("CEMI_TEST_SESSION_DIR")
    {
        return Backend::Files(PathBuf::from(dir));
    }
    if std::env::var_os("CEMI_NO_SESSION").is_some() {
        return Backend::Disabled;
    }
    Backend::Keyring
}

fn file_name(entry: &str) -> String {
    entry.replace(':', "_")
}

fn read(entry: &str) -> Option<String> {
    match backend() {
        Backend::Keyring => keyring::Entry::new(SERVICE, entry)
            .ok()?
            .get_password()
            .ok(),
        Backend::Files(dir) => std::fs::read_to_string(dir.join(file_name(entry))).ok(),
        Backend::Disabled => None,
    }
}

fn write(entry: &str, text: &str) -> Result<()> {
    match backend() {
        Backend::Keyring => keyring::Entry::new(SERVICE, entry)?.set_password(text)?,
        Backend::Files(dir) => {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join(file_name(entry)), text)?;
        }
        Backend::Disabled => {}
    }
    Ok(())
}

fn delete(entry: &str) {
    match backend() {
        Backend::Keyring => {
            if let Ok(e) = keyring::Entry::new(SERVICE, entry) {
                let _ = e.delete_credential();
            }
        }
        Backend::Files(dir) => {
            let _ = std::fs::remove_file(dir.join(file_name(entry)));
        }
        Backend::Disabled => {}
    }
}

/// Minutes a session stays open without use (`CEMI_SESSION_MINUTES`, default 15).
pub fn ttl() -> SignedDuration {
    let minutes = std::env::var("CEMI_SESSION_MINUTES")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|m| *m > 0 && *m <= 24 * 60)
        .unwrap_or(15);
    SignedDuration::from_mins(minutes)
}

fn session_entry(vault_id: &str) -> String {
    format!("session:{vault_id}")
}

fn read_session(vault_id: &str) -> Option<Stored> {
    serde_json::from_str(&read(&session_entry(vault_id))?).ok()
}

/// Returns the vault key if a session is open, and extends it.
pub fn load(vault_id: &str) -> Option<AgeKey> {
    let stored = read_session(vault_id)?;
    if stored.expires <= Timestamp::now() {
        clear(vault_id);
        return None;
    }
    let key = AgeKey::parse(stored.identity.expose()).ok()?;
    let _ = store(vault_id, &key);
    Some(key)
}

pub fn store(vault_id: &str, key: &AgeKey) -> Result<()> {
    let stored = Stored {
        identity: Sensitive::new(key.secret_text().as_str()),
        expires: Timestamp::now() + ttl(),
    };
    let text = zeroize::Zeroizing::new(serde_json::to_string(&stored)?);
    write(&session_entry(vault_id), &text)
}

pub fn clear(vault_id: &str) {
    delete(&session_entry(vault_id));
}

pub fn is_open(vault_id: &str) -> bool {
    read_session(vault_id).is_some_and(|s| s.expires > Timestamp::now())
}

fn token_entry(name: &str) -> String {
    format!("token:{name}")
}

pub fn store_token(name: &str, token: &str) -> Result<()> {
    if matches!(backend(), Backend::Disabled) {
        bail!(
            "the credential store is disabled (CEMI_NO_SESSION); use `cemi token create --print` and CEMI_TOKEN"
        );
    }
    write(&token_entry(name), token)
}

pub fn load_token(name: &str) -> Option<String> {
    read(&token_entry(name))
}

pub fn clear_token(name: &str) {
    delete(&token_entry(name));
}
