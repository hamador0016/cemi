//! GitHub Actions secrets (repository and environment secrets).
//!
//! GitHub only accepts secrets encrypted to the repository's public key with a
//! libsodium sealed box, and never returns them. Changes made outside Cemí are
//! noticed through the secret's `updated_at`.

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::BASE64;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::Observed;
use super::http::{self, segment};
use crate::workspace::Workspace;

const DEFAULT_API: &str = "https://api.github.com";

pub fn validate(repo: &str, name: &str) -> Result<()> {
    let parts: Vec<&str> = repo.split('/').collect();
    if parts.len() != 2 || parts.iter().any(|p| p.is_empty()) {
        bail!("--repo must look like owner/name, got {repo:?}");
    }
    let ok = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.to_ascii_uppercase().starts_with("GITHUB_");
    if !ok {
        bail!(
            "{name:?} is not a valid GitHub secret name (letters, digits and _, not starting with a digit or GITHUB_)"
        );
    }
    Ok(())
}

/// The token: a vault reference, or the GitHub CLI's own login.
pub fn token(
    ws: &mut Workspace,
    reference: Option<&str>,
    api_url: Option<&str>,
    env: Option<&str>,
) -> Result<Zeroizing<String>> {
    if let Some(r) = reference {
        return super::credential(ws, r, env);
    }
    let mut cmd = std::process::Command::new(crate::runner::resolve_program("gh"));
    cmd.args(["auth", "token"]);
    if let Some(url) = api_url {
        let host = url
            .split('/')
            .nth(2)
            .ok_or_else(|| anyhow!("bad API URL {url}"))?;
        let host = host.strip_prefix("api.").unwrap_or(host);
        cmd.args(["--hostname", host]);
    }
    let out = cmd
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|_| {
            anyhow!(
                "no GitHub token: give one with --token <record#field>, or install the GitHub CLI and run `gh auth login`"
            )
        })?;
    let token = Zeroizing::new(String::from_utf8_lossy(&out.stdout).trim().to_string());
    if !out.status.success() || token.is_empty() {
        bail!(
            "the GitHub CLI is not signed in: run `gh auth login`, or give --token <record#field>"
        );
    }
    Ok(token)
}

fn base(api_url: Option<&str>, repo: &str, environment: Option<&str>) -> String {
    let api = api_url.unwrap_or(DEFAULT_API).trim_end_matches('/');
    let (owner, name) = repo.split_once('/').unwrap_or((repo, ""));
    let repo_path = format!("{api}/repos/{}/{}", segment(owner), segment(name));
    match environment {
        Some(e) => format!("{repo_path}/environments/{}/secrets", segment(e)),
        None => format!("{repo_path}/actions/secrets"),
    }
}

fn headers(token: &str) -> [(&'static str, String); 3] {
    [
        ("authorization", format!("Bearer {token}")),
        ("accept", "application/vnd.github+json".into()),
        ("x-github-api-version", "2022-11-28".into()),
    ]
}

fn call(
    method: &str,
    url: &str,
    token: &str,
    body: Option<&serde_json::Value>,
) -> Result<http::Response> {
    let h = headers(token);
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    http::request(method, url, &h, body)
}

#[derive(Deserialize)]
struct PublicKey {
    key_id: String,
    key: String,
}

pub fn put_secret(
    api_url: Option<&str>,
    token: &str,
    repo: &str,
    environment: Option<&str>,
    name: &str,
    value: &str,
) -> Result<()> {
    let base = base(api_url, repo, environment);
    let resp = call("GET", &format!("{base}/public-key"), token, None)?;
    if !resp.ok() {
        return Err(resp.error(&format!("reading the public key of {repo}")));
    }
    let pk: PublicKey = resp.json()?;
    let raw = BASE64
        .decode(pk.key.as_bytes())
        .context("GitHub sent a public key that is not base64")?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("GitHub sent a public key of the wrong size"))?;
    let sealed = seal(&raw, value.as_bytes())?;
    let body = serde_json::json!({
        "encrypted_value": BASE64.encode(&sealed),
        "key_id": pk.key_id,
    });
    let resp = call(
        "PUT",
        &format!("{base}/{}", segment(name)),
        token,
        Some(&body),
    )?;
    if !resp.ok() {
        return Err(resp.error(&format!("setting the secret {name} in {repo}")));
    }
    Ok(())
}

/// libsodium `crypto_box_seal`, as GitHub requires.
fn seal(public_key: &[u8; 32], message: &[u8]) -> Result<Vec<u8>> {
    let pk = crypto_box::PublicKey::from(*public_key);
    pk.seal(&mut crypto_box::aead::OsRng, message)
        .map_err(|_| anyhow!("cannot encrypt the secret for GitHub"))
}

#[derive(Deserialize)]
struct SecretInfo {
    updated_at: String,
}

pub fn secret_updated_at(
    api_url: Option<&str>,
    token: &str,
    repo: &str,
    environment: Option<&str>,
    name: &str,
) -> Result<Observed> {
    let base = base(api_url, repo, environment);
    let resp = call("GET", &format!("{base}/{}", segment(name)), token, None)?;
    if resp.status == 404 {
        return Ok(Observed::Missing);
    }
    if !resp.ok() {
        return Err(resp.error(&format!("reading the secret {name} in {repo}")));
    }
    let info: SecretInfo = resp.json()?;
    Ok(Observed::Remote(format!("updated {}", info.updated_at)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_box_opens_with_the_secret_key() {
        let sk = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
        let pk = sk.public_key();
        let sealed = seal(pk.as_bytes(), b"hello").unwrap();
        assert_eq!(sk.unseal(&sealed).unwrap(), b"hello");
    }

    #[test]
    fn names_and_paths() {
        assert!(validate("acme/shop", "STRIPE_KEY").is_ok());
        assert!(validate("acme", "X").is_err());
        assert!(validate("acme/shop", "GITHUB_TOKEN").is_err());
        assert!(validate("acme/shop", "1X").is_err());
        assert_eq!(
            base(None, "acme/shop", Some("prod env")),
            "https://api.github.com/repos/acme/shop/environments/prod%20env/secrets"
        );
    }
}
