//! Resend API keys (origin).
//!
//! Docs: <https://resend.com/docs/api-reference/api-keys/create-api-key>,
//! <https://resend.com/docs/api-reference/api-keys/list-api-keys>,
//! <https://resend.com/docs/api-reference/api-keys/delete-api-key>.

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::http::{self, segment};
use super::{NewKey, OriginState};

const DEFAULT_API: &str = "https://api.resend.com";

/// Base name for new keys; Cemí adds the date. Resend allows 50 characters
/// in all, and the date takes 17.
pub fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.chars().count() > 32 {
        bail!("key names have 1 to 32 characters (Cemí adds the date)");
    }
    Ok(())
}

pub fn validate_permission(permission: &str, domain: Option<&str>) -> Result<()> {
    match permission {
        "full_access" if domain.is_some() => {
            bail!("--domain only works with --permission sending_access")
        }
        "full_access" | "sending_access" => Ok(()),
        other => bail!("--permission is full_access or sending_access, got {other:?}"),
    }
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
struct Created {
    id: String,
    token: Option<String>,
}

pub fn create_key(
    api_url: Option<&str>,
    admin: &str,
    name: &str,
    permission: &str,
    domain: Option<&str>,
) -> Result<NewKey> {
    let stamp = jiff::Timestamp::now()
        .strftime("%Y-%m-%d %H:%M")
        .to_string();
    let mut body = serde_json::json!({
        "name": format!("{name} {stamp}"),
        "permission": permission,
    });
    if let Some(d) = domain {
        body["domain_id"] = d.into();
    }
    let resp = call(
        "POST",
        &format!("{}/api-keys", api(api_url)),
        admin,
        Some(&body),
    )?;
    if !resp.ok() {
        return Err(resp.error("creating a Resend API key"));
    }
    let k: Created = resp.json()?;
    let value = k
        .token
        .ok_or_else(|| anyhow!("Resend created the key but did not return it"))?;
    Ok(NewKey {
        value: Zeroizing::new(value),
        provider_id: Some(k.id),
    })
}

pub fn delete_key(api_url: Option<&str>, admin: &str, id: &str) -> Result<()> {
    let url = format!("{}/api-keys/{}", api(api_url), segment(id));
    let resp = call("DELETE", &url, admin, None)?;
    if resp.status == 404 || resp.ok() {
        return Ok(());
    }
    Err(resp.error("deleting the old Resend API key"))
}

#[derive(Deserialize)]
struct List {
    data: Vec<Listed>,
}

#[derive(Deserialize)]
struct Listed {
    id: String,
}

pub fn key_state(api_url: Option<&str>, admin: &str, id: &str) -> Result<OriginState> {
    // Without `limit`, Resend returns every key at once.
    let resp = call("GET", &format!("{}/api-keys", api(api_url)), admin, None)?;
    if !resp.ok() {
        return Err(resp.error("listing the Resend API keys"));
    }
    let list: List = resp.json()?;
    Ok(if list.data.iter().any(|k| k.id == id) {
        OriginState::Alive
    } else {
        OriginState::Gone
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options() {
        assert!(validate_name("shop").is_ok());
        assert!(validate_name(&"x".repeat(40)).is_err());
        assert!(validate_permission("sending_access", Some("d1")).is_ok());
        assert!(validate_permission("full_access", Some("d1")).is_err());
        assert!(validate_permission("admin", None).is_err());
    }
}
