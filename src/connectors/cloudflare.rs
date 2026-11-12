//! Cloudflare: API tokens (origin) and Workers secrets (destination).
//!
//! A new token is created with the same permissions as the one it replaces,
//! so both work until the old one is deleted. Rolling a token in place
//! (`PUT …/tokens/{id}/value`) is not used: it kills the old value at once,
//! which leaves no way back if a destination fails.
//!
//! Docs: <https://developers.cloudflare.com/api/resources/user/subresources/tokens/>,
//! <https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/>,
//! <https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/>.

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::http::{self, segment};
use super::{NewKey, Observed, OriginState};

const DEFAULT_API: &str = "https://api.cloudflare.com/client/v4";

pub fn validate_account(account: &str) -> Result<()> {
    if account.len() != 32 || !account.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!(
            "{account:?} is not a Cloudflare account id (32 hexadecimal characters, shown in the dashboard sidebar)"
        );
    }
    Ok(())
}

pub fn validate_script(script: &str) -> Result<()> {
    let ok = (1..=63).contains(&script.len())
        && script
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        bail!("{script:?} is not a Worker name (letters, digits, - and _)");
    }
    Ok(())
}

pub fn validate_secret_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$');
    if !ok {
        bail!("{name:?} is not a valid Worker secret name (letters, digits and _)");
    }
    Ok(())
}

/// Base name for new tokens; Cemí adds the date.
pub fn validate_token_name(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.len() > 100 {
        bail!("token names have 1 to 100 characters");
    }
    Ok(())
}

fn api(api_url: Option<&str>) -> &str {
    api_url.unwrap_or(DEFAULT_API).trim_end_matches('/')
}

/// `…/user/tokens` or `…/accounts/{id}/tokens` (account-owned tokens).
fn tokens(api_url: Option<&str>, account: Option<&str>) -> String {
    match account {
        Some(a) => format!("{}/accounts/{}/tokens", api(api_url), segment(a)),
        None => format!("{}/user/tokens", api(api_url)),
    }
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
struct Envelope<T> {
    result: Option<T>,
}

#[derive(Deserialize)]
struct Verified {
    id: String,
}

#[derive(Deserialize)]
struct TokenInfo {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    policies: Vec<serde_json::Value>,
    #[serde(default)]
    condition: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Created {
    id: String,
    value: Option<String>,
}

/// The id of the token whose value is `value`, asked to Cloudflare with that
/// same token. None when Cloudflare no longer accepts it.
fn id_of(api_url: Option<&str>, account: Option<&str>, value: &str) -> Result<Option<String>> {
    let resp = call(
        "GET",
        &format!("{}/verify", tokens(api_url, account)),
        value,
        None,
    )?;
    if resp.status == 401 {
        return Ok(None);
    }
    if !resp.ok() {
        return Err(resp.error("identifying the Cloudflare token"));
    }
    let v: Envelope<Verified> = resp.json()?;
    Ok(v.result.map(|r| r.id))
}

/// Creates a token with the permissions of the current one.
pub fn create_token(
    api_url: Option<&str>,
    admin: &str,
    account: Option<&str>,
    name: &str,
    current: Option<&str>,
) -> Result<NewKey> {
    let Some(current) = current else {
        bail!(
            "Cemí copies the permissions of the current Cloudflare token, and there is none yet. \
             Create the first token in the dashboard and save it with `cemi set`"
        );
    };
    let id = id_of(api_url, account, current)?.ok_or_else(|| {
        anyhow!(
            "Cloudflare does not accept the current token, so Cemí cannot copy its permissions. \
             Create a new token in the dashboard and save it with `cemi set`"
        )
    })?;
    let base = tokens(api_url, account);
    let resp = call("GET", &format!("{base}/{}", segment(&id)), admin, None)?;
    if !resp.ok() {
        return Err(resp.error("reading the permissions of the current Cloudflare token"));
    }
    let info: Envelope<TokenInfo> = resp.json()?;
    let info = info
        .result
        .ok_or_else(|| anyhow!("Cloudflare did not describe the current token"))?;
    if info.policies.is_empty() {
        bail!("the current Cloudflare token has no permissions to copy");
    }
    let stamp = jiff::Timestamp::now()
        .strftime("%Y-%m-%d %H:%M")
        .to_string();
    let mut body = serde_json::json!({
        "name": format!("{name} {stamp}"),
        "policies": info.policies.iter().map(policy).collect::<Vec<_>>(),
    });
    if let Some(c) = info.condition.filter(|c| !c.is_null()) {
        body["condition"] = c;
    }
    let resp = call("POST", &base, admin, Some(&body))?;
    if !resp.ok() {
        let old = info.name.unwrap_or(id);
        return Err(resp.error(&format!("creating a token like \"{old}\"")));
    }
    let created: Envelope<Created> = resp.json()?;
    let created = created
        .result
        .ok_or_else(|| anyhow!("Cloudflare created the token but did not describe it"))?;
    let value = created
        .value
        .ok_or_else(|| anyhow!("Cloudflare created the token but did not return it"))?;
    Ok(NewKey {
        value: Zeroizing::new(value),
        provider_id: Some(created.id),
    })
}

/// A policy as Cloudflare accepts it back: its effect, resources and the ids
/// of its permission groups (responses also carry names and ids that a
/// create request does not take).
fn policy(p: &serde_json::Value) -> serde_json::Value {
    let groups: Vec<serde_json::Value> = p["permission_groups"]
        .as_array()
        .map(|g| {
            g.iter()
                .map(|g| {
                    let mut out = serde_json::json!({ "id": g["id"] });
                    if !g["meta"].is_null() {
                        out["meta"] = g["meta"].clone();
                    }
                    out
                })
                .collect()
        })
        .unwrap_or_default();
    serde_json::json!({
        "effect": p["effect"],
        "resources": p["resources"],
        "permission_groups": groups,
    })
}

/// Deletes a token: by the id Cemí got when it created it, or by asking
/// Cloudflare which token the old value is.
pub fn delete_token(
    api_url: Option<&str>,
    admin: &str,
    account: Option<&str>,
    provider_id: Option<&str>,
    old_value: &str,
) -> Result<()> {
    let id = match provider_id {
        Some(id) => id.to_string(),
        None => match id_of(api_url, account, old_value)? {
            Some(id) => id,
            // Cloudflare no longer accepts it: nothing left to revoke.
            None => return Ok(()),
        },
    };
    let url = format!("{}/{}", tokens(api_url, account), segment(&id));
    let resp = call("DELETE", &url, admin, None)?;
    if resp.status == 404 || resp.ok() {
        return Ok(());
    }
    Err(resp.error("deleting the old Cloudflare token"))
}

pub fn token_state(
    api_url: Option<&str>,
    admin: &str,
    account: Option<&str>,
    id: &str,
) -> Result<OriginState> {
    let url = format!("{}/{}", tokens(api_url, account), segment(id));
    let resp = call("GET", &url, admin, None)?;
    if resp.status == 404 {
        return Ok(OriginState::Gone);
    }
    if !resp.ok() {
        return Err(resp.error("reading a Cloudflare token"));
    }
    let info: Envelope<TokenInfo> = resp.json()?;
    Ok(match info.result.and_then(|i| i.status).as_deref() {
        Some("active") => OriginState::Alive,
        // Disabled or expired: Cloudflare no longer accepts it.
        Some(_) => OriginState::Gone,
        None => OriginState::Unknown,
    })
}

fn secrets(api_url: Option<&str>, account: &str, script: &str) -> String {
    format!(
        "{}/accounts/{}/workers/scripts/{}/secrets",
        api(api_url),
        segment(account),
        segment(script)
    )
}

pub fn put_secret(
    api_url: Option<&str>,
    token: &str,
    account: &str,
    script: &str,
    name: &str,
    value: &str,
) -> Result<()> {
    let body = serde_json::json!({ "name": name, "text": value, "type": "secret_text" });
    let resp = call(
        "PUT",
        &secrets(api_url, account, script),
        token,
        Some(&body),
    )?;
    if !resp.ok() {
        return Err(resp.error(&format!("setting the secret {name} of the Worker {script}")));
    }
    Ok(())
}

/// Cloudflare tells whether the secret exists, but nothing that changes with
/// its value: a present secret cannot be compared.
pub fn secret_present(
    api_url: Option<&str>,
    token: &str,
    account: &str,
    script: &str,
    name: &str,
) -> Result<Observed> {
    let url = format!("{}/{}", secrets(api_url, account, script), segment(name));
    let resp = call("GET", &url, token, None)?;
    match resp.status {
        404 => Ok(Observed::Missing),
        _ if resp.ok() => Ok(Observed::Unknown),
        _ => Err(resp.error(&format!("reading the secret {name} of the Worker {script}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_paths() {
        assert!(validate_account("0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_account("acme").is_err());
        assert!(validate_script("shop-api").is_ok());
        assert!(validate_script("shop/api").is_err());
        assert!(validate_secret_name("STRIPE_KEY").is_ok());
        assert!(validate_secret_name("1KEY").is_err());
        assert_eq!(
            tokens(None, None),
            "https://api.cloudflare.com/client/v4/user/tokens"
        );
        assert_eq!(
            tokens(Some("http://127.0.0.1:1/"), Some("ab")),
            "http://127.0.0.1:1/accounts/ab/tokens"
        );
    }

    #[test]
    fn policies_keep_only_what_create_takes() {
        let p = serde_json::json!({
            "id": "p1",
            "effect": "allow",
            "resources": {"com.cloudflare.api.account.zone.*": "*"},
            "permission_groups": [{"id": "g1", "name": "Zone Read", "meta": {"label": "x"}}],
        });
        let out = policy(&p);
        assert_eq!(
            out["permission_groups"][0],
            serde_json::json!({"id": "g1", "meta": {"label": "x"}})
        );
        assert!(out.get("id").is_none());
        assert_eq!(out["effect"], "allow");
    }
}
