//! Fly.io app secrets (destination), through the Machines API.
//!
//! Docs: <https://docs.fly.io/api/machines/openapi.json> (Secret_create,
//! Secret_get) and <https://fly.io/docs/apps/secrets/>.
//!
//! Setting a secret stores it for the app; running Machines only see it
//! after they are updated or restarted (`fly secrets deploy`, `fly deploy`),
//! which this connector does not do. Reading a secret returns a digest of
//! its value, never the value.

use anyhow::{Result, bail};
use serde::Deserialize;

use super::Observed;
use super::http::{self, segment};

const DEFAULT_API: &str = "https://api.machines.dev";

pub fn validate(app: &str, name: &str) -> Result<()> {
    let ok = !app.is_empty()
        && app.len() <= 63
        && app
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        bail!("{app:?} is not a Fly app name (lowercase letters, digits and -)");
    }
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("{name:?} is not a Fly secret name (letters, digits and _)");
    }
    Ok(())
}

fn api(api_url: Option<&str>) -> &str {
    api_url.unwrap_or(DEFAULT_API).trim_end_matches('/')
}

fn secret_url(api_url: Option<&str>, app: &str, name: &str) -> String {
    format!(
        "{}/v1/apps/{}/secrets/{}",
        api(api_url),
        segment(app),
        segment(name)
    )
}

/// Tokens from `fly tokens create` start with their scheme, `FlyV1 `; other
/// tokens go as bearer tokens.
fn auth_header(token: &str) -> String {
    if token.starts_with("FlyV1 ") {
        token.to_string()
    } else {
        format!("Bearer {token}")
    }
}

fn call(
    method: &str,
    url: &str,
    token: &str,
    body: Option<&serde_json::Value>,
) -> Result<http::Response> {
    let auth = auth_header(token);
    http::request(
        method,
        url,
        &[("authorization", &auth), ("accept", "application/json")],
        body,
    )
}

pub fn set_secret(
    api_url: Option<&str>,
    token: &str,
    app: &str,
    name: &str,
    value: &str,
) -> Result<()> {
    let body = serde_json::json!({ "value": value });
    let resp = call("POST", &secret_url(api_url, app, name), token, Some(&body))?;
    if !resp.ok() {
        return Err(resp.error(&format!("setting the secret {name} of the Fly app {app}")));
    }
    Ok(())
}

#[derive(Deserialize)]
struct Secret {
    #[serde(default)]
    digest: Option<String>,
}

/// The digest Fly reports for the secret.
pub fn observe(api_url: Option<&str>, token: &str, app: &str, name: &str) -> Result<Observed> {
    let resp = call("GET", &secret_url(api_url, app, name), token, None)?;
    if resp.status == 404 {
        return Ok(Observed::Missing);
    }
    if !resp.ok() {
        return Err(resp.error(&format!("reading the secret {name} of the Fly app {app}")));
    }
    let s: Secret = resp.json()?;
    Ok(match s.digest {
        Some(d) if !d.is_empty() => Observed::Remote(format!("digest {d}")),
        _ => Observed::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_and_requests() {
        assert!(validate("shop-api", "STRIPE_KEY").is_ok());
        assert!(validate("Shop", "STRIPE_KEY").is_err());
        assert!(validate("shop", "STRIPE-KEY").is_err());
        assert_eq!(
            secret_url(None, "shop-api", "STRIPE_KEY"),
            "https://api.machines.dev/v1/apps/shop-api/secrets/STRIPE_KEY"
        );
        assert_eq!(auth_header("FlyV1 fm2_x"), "FlyV1 fm2_x");
        assert_eq!(auth_header("abc"), "Bearer abc");
    }
}
