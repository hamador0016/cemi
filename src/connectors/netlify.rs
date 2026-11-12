//! Netlify environment variables (destination), of a site or of a whole
//! team (account).
//!
//! Docs: <https://open-api.netlify.com/> (createEnvVars, setEnvVarValue,
//! getEnvVar) and <https://docs.netlify.com/build/environment-variables/secrets-controller/>.

use anyhow::{Result, bail};
use serde::Deserialize;

use super::Observed;
use super::http::{self, segment};

const DEFAULT_API: &str = "https://api.netlify.com/api/v1";

pub const CONTEXTS: &[&str] = &[
    "production",
    "deploy-preview",
    "branch-deploy",
    "dev",
    "all",
];

pub fn validate(account: &str, site: Option<&str>, key: &str, context: &str) -> Result<()> {
    let slug = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    };
    if !slug(account) {
        bail!("{account:?} is not a Netlify team slug (the name in app.netlify.com/teams/<slug>)");
    }
    if let Some(s) = site
        && !slug(s)
    {
        bail!("{s:?} is not a Netlify site id (Site configuration → Site details)");
    }
    crate::dotenv::check_var_name(key)?;
    if !CONTEXTS.contains(&context) {
        bail!(
            "--context is one of {}, got {context:?}",
            CONTEXTS.join(", ")
        );
    }
    Ok(())
}

fn api(api_url: Option<&str>) -> &str {
    api_url.unwrap_or(DEFAULT_API).trim_end_matches('/')
}

fn query(site: Option<&str>) -> String {
    site.map(|s| format!("?site_id={}", segment(s)))
        .unwrap_or_default()
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

fn place(site: Option<&str>, account: &str) -> String {
    match site {
        Some(s) => format!("site {s}"),
        None => format!("team {account}"),
    }
}

/// Sets the value for one context; creates the variable when it is new.
#[allow(clippy::too_many_arguments)]
pub fn set_var(
    api_url: Option<&str>,
    token: &str,
    account: &str,
    site: Option<&str>,
    key: &str,
    context: &str,
    secret: bool,
    value: &str,
) -> Result<()> {
    let base = format!("{}/accounts/{}/env", api(api_url), segment(account));
    let url = format!("{base}/{}{}", segment(key), query(site));
    let body = serde_json::json!({ "context": context, "value": value });
    let resp = call("PATCH", &url, token, Some(&body))?;
    if resp.ok() {
        return Ok(());
    }
    if resp.status != 404 {
        return Err(resp.error(&format!(
            "setting {key} in Netlify {}",
            place(site, account)
        )));
    }
    // New variable. Secret values are not available to post-processing.
    let mut var = serde_json::json!({
        "key": key,
        "values": [{ "context": context, "value": value }],
        "is_secret": secret,
    });
    if secret {
        var["scopes"] = serde_json::json!(["builds", "functions", "runtime"]);
    }
    let resp = call(
        "POST",
        &format!("{base}{}", query(site)),
        token,
        Some(&serde_json::json!([var])),
    )?;
    if !resp.ok() {
        return Err(resp.error(&format!(
            "creating {key} in Netlify {}",
            place(site, account)
        )));
    }
    Ok(())
}

#[derive(Deserialize)]
struct Var {
    #[serde(default)]
    values: Vec<VarValue>,
    #[serde(default)]
    updated_at: Option<String>,
}

#[derive(Deserialize)]
struct VarValue {
    context: String,
}

/// Netlify keeps one update time for the whole variable, so a change to
/// another context of the same variable also shows as a change.
pub fn observe(
    api_url: Option<&str>,
    token: &str,
    account: &str,
    site: Option<&str>,
    key: &str,
    context: &str,
) -> Result<Observed> {
    let url = format!(
        "{}/accounts/{}/env/{}{}",
        api(api_url),
        segment(account),
        segment(key),
        query(site)
    );
    let resp = call("GET", &url, token, None)?;
    if resp.status == 404 {
        return Ok(Observed::Missing);
    }
    if !resp.ok() {
        return Err(resp.error(&format!(
            "reading {key} in Netlify {}",
            place(site, account)
        )));
    }
    let var: Var = resp.json()?;
    if !var.values.iter().any(|v| v.context == context) {
        return Ok(Observed::Missing);
    }
    Ok(match var.updated_at {
        Some(at) => Observed::Remote(format!("updated {at}")),
        None => Observed::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options() {
        assert!(validate("acme", Some("site-1"), "API_KEY", "production").is_ok());
        assert!(validate("acme", None, "API_KEY", "staging").is_err());
        assert!(validate("ac me", None, "API_KEY", "dev").is_err());
        assert!(validate("acme", None, "1KEY", "dev").is_err());
        assert_eq!(query(Some("a b")), "?site_id=a%20b");
    }
}
