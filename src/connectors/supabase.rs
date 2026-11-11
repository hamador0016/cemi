//! Supabase Management API: secret API keys (origin) and Edge Function
//! secrets (destination).
//!
//! Listing function secrets returns a digest of each value, never the value.
//! Cemí does not assume how the digest is made: it remembers the digest seen
//! right after its own write and compares later ones with it.

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::http::{self, segment};
use super::{NewKey, Observed};

const DEFAULT_API: &str = "https://api.supabase.com";

pub fn validate_project(project: &str) -> Result<()> {
    if project.is_empty() || !project.chars().all(|c| c.is_ascii_lowercase()) {
        bail!(
            "{project:?} does not look like a Supabase project ref (the lowercase id in your project URL)"
        );
    }
    Ok(())
}

pub fn validate_secret_name(name: &str) -> Result<()> {
    crate::dotenv::check_var_name(name)?;
    if name.to_ascii_uppercase().starts_with("SUPABASE_") {
        bail!("Supabase function secret names cannot start with SUPABASE_");
    }
    Ok(())
}

/// Base name of keys Cemí creates; a date is appended (`name_20261111153000`).
pub fn validate_key_name(name: &str) -> Result<()> {
    let ok = (1..=48).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !ok {
        bail!("key names use lowercase letters, digits and _ (up to 48), got {name:?}");
    }
    Ok(())
}

fn api(api_url: Option<&str>) -> &str {
    api_url.unwrap_or(DEFAULT_API).trim_end_matches('/')
}

fn call(
    method: &str,
    url: &str,
    token: &str,
    body: Option<&serde_json::Value>,
) -> Result<http::Response> {
    let auth = format!("Bearer {token}");
    http::request(
        method,
        url,
        &[("authorization", &auth), ("accept", "application/json")],
        body,
    )
}

#[derive(Deserialize)]
struct ApiKey {
    api_key: Option<String>,
    id: Option<String>,
}

pub fn create_key(api_url: Option<&str>, token: &str, project: &str, name: &str) -> Result<NewKey> {
    let stamp = jiff::Timestamp::now().strftime("%Y%m%d%H%M%S").to_string();
    let full = format!("{name}_{stamp}");
    let url = format!(
        "{}/v1/projects/{}/api-keys?reveal=true",
        api(api_url),
        segment(project)
    );
    let body = serde_json::json!({
        "type": "secret",
        "name": full,
        "description": "Created by Cemí",
    });
    let resp = call("POST", &url, token, Some(&body))?;
    if !resp.ok() {
        return Err(resp.error(&format!("creating a secret API key in project {project}")));
    }
    let key: ApiKey = resp.json()?;
    let value = key
        .api_key
        .ok_or_else(|| anyhow!("Supabase created the key but did not return it"))?;
    Ok(NewKey {
        value: Zeroizing::new(value),
        provider_id: key.id,
    })
}

pub fn delete_key(
    api_url: Option<&str>,
    token: &str,
    project: &str,
    id: &str,
    compromised: bool,
) -> Result<()> {
    let url = format!(
        "{}/v1/projects/{}/api-keys/{}?was_compromised={compromised}&reason={}",
        api(api_url),
        segment(project),
        segment(id),
        if compromised {
            "leaked"
        } else {
            "rotating_key"
        }
    );
    let resp = call("DELETE", &url, token, None)?;
    if resp.status == 404 || resp.ok() {
        return Ok(());
    }
    Err(resp.error(&format!("deleting the old API key in project {project}")))
}

pub fn key_exists(api_url: Option<&str>, token: &str, project: &str, id: &str) -> Result<bool> {
    let url = format!(
        "{}/v1/projects/{}/api-keys/{}",
        api(api_url),
        segment(project),
        segment(id)
    );
    let resp = call("GET", &url, token, None)?;
    match resp.status {
        404 => Ok(false),
        _ if resp.ok() => Ok(true),
        _ => Err(resp.error(&format!("reading an API key of project {project}"))),
    }
}

pub fn set_secret(
    api_url: Option<&str>,
    token: &str,
    project: &str,
    name: &str,
    value: &str,
) -> Result<()> {
    let url = format!("{}/v1/projects/{}/secrets", api(api_url), segment(project));
    let body = serde_json::json!([{ "name": name, "value": value }]);
    let resp = call("POST", &url, token, Some(&body))?;
    if !resp.ok() {
        return Err(resp.error(&format!(
            "setting the function secret {name} in project {project}"
        )));
    }
    Ok(())
}

#[derive(Deserialize)]
struct Secret {
    name: String,
    value: String,
    #[serde(default)]
    updated_at: Option<String>,
}

pub fn secret_digest(
    api_url: Option<&str>,
    token: &str,
    project: &str,
    name: &str,
) -> Result<Observed> {
    let url = format!("{}/v1/projects/{}/secrets", api(api_url), segment(project));
    let resp = call("GET", &url, token, None)?;
    if !resp.ok() {
        return Err(resp.error(&format!(
            "listing the function secrets of project {project}"
        )));
    }
    let list: Vec<Secret> = resp.json()?;
    Ok(match list.into_iter().find(|s| s.name == name) {
        Some(s) => Observed::Remote(match s.updated_at {
            Some(at) => format!("digest {} updated {at}", s.value),
            None => format!("digest {}", s.value),
        }),
        None => Observed::Missing,
    })
}
