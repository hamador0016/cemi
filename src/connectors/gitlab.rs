//! GitLab CI/CD variables of a project (destination), on GitLab.com or a
//! self-managed GitLab.
//!
//! Docs: <https://docs.gitlab.com/api/project_level_variables/> and
//! <https://docs.gitlab.com/ci/variables/> (masked and hidden variables).
//!
//! GitLab's API returns the value of a variable when it is read (except for
//! hidden ones). To notice changes, Cemí hashes that value in memory and keeps
//! only the SHA-256 digest, the same kind of fingerprint it keeps of every
//! value it sends; the value itself is never stored or shown.

use anyhow::{Result, bail};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::Observed;
use super::http::{self, segment};

const DEFAULT_API: &str = "https://gitlab.com/api/v4";

/// `project` is a numeric id or a path like `acme/shop`.
pub fn validate(project: &str, key: &str, scope: &str) -> Result<()> {
    let ok = !project.is_empty()
        && !project.starts_with('/')
        && !project.ends_with('/')
        && project
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c));
    if !ok {
        bail!("{project:?} is not a GitLab project id or path (like 1234 or acme/shop)");
    }
    if key.is_empty()
        || key.len() > 255
        || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        bail!("{key:?} is not a GitLab variable name (letters, digits and _, up to 255)");
    }
    if scope.is_empty() || scope.chars().any(char::is_whitespace) {
        bail!("{scope:?} is not an environment scope (* for every environment)");
    }
    Ok(())
}

/// What GitLab requires of masked values.
fn check_maskable(value: &str) -> Result<()> {
    if value.chars().count() < 8 || value.chars().any(char::is_whitespace) {
        bail!(
            "GitLab masks only values of 8 or more characters on one line without spaces; this value is not one (add the destination with --no-mask to store it unmasked)"
        );
    }
    Ok(())
}

fn api(api_url: Option<&str>) -> &str {
    api_url.unwrap_or(DEFAULT_API).trim_end_matches('/')
}

fn var_url(api_url: Option<&str>, project: &str, key: &str, scope: &str) -> String {
    format!(
        "{}/projects/{}/variables/{}?filter%5Benvironment_scope%5D={}",
        api(api_url),
        segment(project),
        segment(key),
        segment(scope)
    )
}

fn call(
    method: &str,
    url: &str,
    token: &str,
    body: Option<&serde_json::Value>,
) -> Result<http::Response> {
    http::request(
        method,
        url,
        &[("private-token", token), ("accept", "application/json")],
        body,
    )
}

/// The options of a variable Cemí writes.
pub struct Options<'a> {
    pub scope: &'a str,
    pub masked: bool,
    pub protected: bool,
    /// Masked and hidden: never shown again, not even to the API.
    pub hidden: bool,
}

fn update_body(value: &str, o: &Options) -> serde_json::Value {
    let mut b = serde_json::json!({
        "value": value,
        "protected": o.protected,
        "raw": true,
        "variable_type": "env_var",
    });
    // Hidden variables stay masked; GitLab does not allow unmasking them.
    if !o.hidden {
        b["masked"] = o.masked.into();
    }
    b
}

fn create_body(key: &str, value: &str, o: &Options) -> serde_json::Value {
    let mut b = serde_json::json!({
        "key": key,
        "value": value,
        "protected": o.protected,
        "raw": true,
        "variable_type": "env_var",
        "environment_scope": o.scope,
        "description": "Set by Cemí",
    });
    if o.hidden {
        b["masked_and_hidden"] = true.into();
    } else {
        b["masked"] = o.masked.into();
    }
    b
}

/// Updates the variable, or creates it when it does not exist.
pub fn set_var(
    api_url: Option<&str>,
    token: &str,
    project: &str,
    key: &str,
    o: &Options,
    value: &str,
) -> Result<()> {
    if o.masked || o.hidden {
        check_maskable(value)?;
    }
    let what = format!(
        "setting {key} ({}) in the GitLab project {project}",
        o.scope
    );
    let resp = call(
        "PUT",
        &var_url(api_url, project, key, o.scope),
        token,
        Some(&update_body(value, o)),
    )?;
    if resp.ok() {
        return Ok(());
    }
    if resp.status != 404 {
        return Err(resp.error(&what));
    }
    let url = format!("{}/projects/{}/variables", api(api_url), segment(project));
    let resp = call("POST", &url, token, Some(&create_body(key, value, o)))?;
    if !resp.ok() {
        return Err(resp.error(&what));
    }
    Ok(())
}

#[derive(Deserialize)]
struct Var {
    #[serde(default)]
    value: Option<Zeroizing<String>>,
    #[serde(default)]
    hidden: bool,
}

/// A digest of the current value (hidden variables only report that they exist).
pub fn observe(
    api_url: Option<&str>,
    token: &str,
    project: &str,
    key: &str,
    scope: &str,
) -> Result<Observed> {
    let resp = call("GET", &var_url(api_url, project, key, scope), token, None)?;
    if resp.status == 404 {
        return Ok(Observed::Missing);
    }
    if !resp.ok() {
        return Err(resp.error(&format!("reading {key} in the GitLab project {project}")));
    }
    let body = Zeroizing::new(resp.body);
    let var: Var = serde_json::from_str(&body)
        .map_err(|_| anyhow::anyhow!("GitLab answered with unexpected JSON"))?;
    Ok(match var.value {
        Some(v) if !var.hidden => Observed::Remote(format!(
            "sha256 {}",
            crate::crypto::sha256_hex(v.as_bytes())
        )),
        _ => Observed::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_and_requests() {
        assert!(validate("acme/shop", "STRIPE_KEY", "*").is_ok());
        assert!(validate("1234", "STRIPE_KEY", "production").is_ok());
        assert!(validate("acme shop", "K", "*").is_err());
        assert!(validate("acme/shop", "STRIPE-KEY", "*").is_err());
        assert!(validate("acme/shop", "K", "").is_err());
        assert!(check_maskable("long-enough-value").is_ok());
        assert!(check_maskable("short").is_err());
        assert!(check_maskable("has a space").is_err());
        assert_eq!(
            var_url(None, "acme/shop", "K", "*"),
            "https://gitlab.com/api/v4/projects/acme%2Fshop/variables/K?filter%5Benvironment_scope%5D=%2A"
        );
        let o = Options {
            scope: "production",
            masked: true,
            protected: true,
            hidden: false,
        };
        let u = update_body("v", &o);
        assert_eq!(u["masked"], true);
        assert_eq!(u["raw"], true);
        let c = create_body("K", "v", &o);
        assert_eq!(c["environment_scope"], "production");
        assert!(c.get("masked_and_hidden").is_none());
        let h = Options { hidden: true, ..o };
        assert!(update_body("v", &h).get("masked").is_none());
        assert_eq!(create_body("K", "v", &h)["masked_and_hidden"], true);
    }
}
