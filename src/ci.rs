//! Secrets for CI without copying them by hand. `cemi ci export` encrypts a
//! project's variables for one environment to a key made only for CI; the
//! file is committed, and `cemi ci load` (or the GitHub action) opens it
//! with that key, which lives in the CI's own secret store.
//!
//! The file is text: comment lines, then the age ciphertext in base64.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, AgeKey};

pub const DEFAULT_FILE: &str = "cemi.ci.age";
/// The variable that holds the CI key in CI.
pub const KEY_VAR: &str = "CEMI_CI_KEY";
/// Where `cemi ci setup` keeps the CI key in the vault.
pub const KEY_RECORD: &str = "cemi-ci";
pub const KEY_FIELD: &str = "key";

const FORMAT: u32 = 1;

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub format: u32,
    pub env: String,
    pub created: jiff::Timestamp,
    pub vars: BTreeMap<String, String>,
    /// Variable → (file name, base64 contents).
    #[serde(default)]
    pub files: BTreeMap<String, CiFile>,
}

#[derive(Serialize, Deserialize)]
pub struct CiFile {
    pub name: String,
    pub data: String,
}

impl Drop for Payload {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for v in self.vars.values_mut() {
            v.zeroize();
        }
        for f in self.files.values_mut() {
            f.data.zeroize();
        }
    }
}

impl Payload {
    pub fn new(env: &str) -> Payload {
        Payload {
            format: FORMAT,
            env: env.to_string(),
            created: jiff::Timestamp::now(),
            vars: BTreeMap::new(),
            files: BTreeMap::new(),
        }
    }
}

/// The text of the file: a header people can read, then the ciphertext.
pub fn seal(p: &Payload, recipient: &age::x25519::Recipient) -> Result<String> {
    let json = Zeroizing::new(serde_json::to_vec(p)?);
    let cipher = crypto::age_encrypt(recipient, &json)?;
    let b64 = BASE64.encode(&cipher);
    let mut out = format!(
        "# Cemí: secrets for CI ({}), encrypted to the key in cemi.toml [ci].\n\
         # Safe to commit. In CI, `cemi ci load` opens it with the secret {KEY_VAR}.\n\
         # Variables: {}\n",
        p.env,
        p.vars
            .keys()
            .chain(p.files.keys())
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );
    for chunk in b64.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    Ok(out)
}

pub fn open(text: &str, key: &AgeKey) -> Result<Payload> {
    let b64: String = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let cipher = BASE64
        .decode(b64.as_bytes())
        .map_err(|_| anyhow!("this is not a file written by `cemi ci export`"))?;
    let json = crypto::age_decrypt_any(&[key], &cipher)?.ok_or_else(|| {
        anyhow!(
            "{KEY_VAR} does not open this file: it was encrypted to another key. Run `cemi ci export` again, or update the secret"
        )
    })?;
    let p: Payload = serde_json::from_slice(&json).context("the decrypted file is not valid")?;
    if p.format != FORMAT {
        bail!(
            "this file has format {}; this cemi reads format {FORMAT}. Update cemi",
            p.format
        );
    }
    Ok(p)
}

/// The CI key from the environment.
pub fn key_from_env() -> Result<AgeKey> {
    let text = Zeroizing::new(std::env::var(KEY_VAR).map_err(|_| {
        crate::errors::not_found(format!(
            "{KEY_VAR} is not set. In GitHub Actions: env: {KEY_VAR}: ${{{{ secrets.{KEY_VAR} }}}}"
        ))
    })?);
    AgeKey::parse(text.trim()).with_context(|| format!("{KEY_VAR} is not a valid key"))
}

/// Writes the files of a payload into `dir` (private to this user) and
/// returns (variable, path).
pub fn write_files(p: &Payload, dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    if p.files.is_empty() {
        return Ok(out);
    }
    std::fs::create_dir_all(dir)?;
    for (var, f) in &p.files {
        let data = Zeroizing::new(
            BASE64
                .decode(f.data.as_bytes())
                .map_err(|_| anyhow!("{var}: damaged file data"))?,
        );
        // Only the file name: never a path out of `dir`.
        let name = Path::new(&f.name)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| var.to_lowercase());
        let path = dir.join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&path)?.write_all(&data)?;
        out.push((var.clone(), path));
    }
    Ok(out)
}

/// GitHub Actions: masks every value in the log (workflow commands on
/// stdout) and appends the variables to `$GITHUB_ENV` for the next steps.
pub fn to_github_env(p: &Payload, files: &[(String, PathBuf)], env_file: &Path) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    for value in p.vars.values() {
        for line in value.lines().filter(|l| !l.trim().is_empty()) {
            writeln!(stdout, "::add-mask::{line}")?;
        }
    }
    stdout.flush()?;
    let mut text = Zeroizing::new(String::new());
    let mut add = |name: &str, value: &str| -> Result<()> {
        // A delimiter that cannot appear in the value.
        let delim = loop {
            let d = format!("CEMI_EOF_{}", crypto::new_id());
            if !value.contains(&d) {
                break d;
            }
        };
        text.push_str(&format!("{name}<<{delim}\n{value}\n{delim}\n"));
        Ok(())
    };
    for (k, v) in &p.vars {
        add(k, v)?;
    }
    for (k, path) in files {
        add(k, &path.display().to_string())?;
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(env_file)
        .with_context(|| format!("cannot write {}", env_file.display()))?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_open() {
        let key = AgeKey::generate();
        let mut p = Payload::new("prod");
        p.vars.insert("API_TOKEN".into(), "s3cret\nline two".into());
        p.files.insert(
            "GCP_KEY".into(),
            CiFile {
                name: "../../etc/key.json".into(),
                data: BASE64.encode(b"{}"),
            },
        );
        let text = seal(&p, &key.recipient()).unwrap();
        assert!(text.starts_with("# Cemí: secrets for CI (prod)"));
        assert!(text.contains("# Variables: API_TOKEN, GCP_KEY"));
        assert!(!text.contains("s3cret"));
        let back = open(&text, &key).unwrap();
        assert_eq!(back.env, "prod");
        assert_eq!(back.vars["API_TOKEN"], "s3cret\nline two");
        // Another key cannot open it.
        assert!(open(&text, &AgeKey::generate()).is_err());

        // Files stay inside the folder they are written to.
        let dir = tempfile::tempdir().unwrap();
        let written = write_files(&back, dir.path()).unwrap();
        assert_eq!(written[0].1, dir.path().join("key.json"));
    }

    #[test]
    fn github_env_masks_and_uses_delimiters() {
        let mut p = Payload::new("prod");
        p.vars.insert("A".into(), "one\ntwo".into());
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join("env");
        to_github_env(&p, &[], &env_file).unwrap();
        let text = std::fs::read_to_string(&env_file).unwrap();
        let mut lines = text.lines();
        let first = lines.next().unwrap();
        let delim = first.strip_prefix("A<<").unwrap();
        assert!(delim.starts_with("CEMI_EOF_"));
        assert_eq!(lines.next(), Some("one"));
        assert_eq!(lines.next(), Some("two"));
        assert_eq!(lines.next(), Some(delim));
    }
}
