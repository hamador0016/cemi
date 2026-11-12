//! Vercel project environment variables (destination).
//!
//! Docs: <https://vercel.com/docs/rest-api/reference/endpoints/projects/create-one-or-more-environment-variables>
//! and <https://vercel.com/docs/rest-api/reference/endpoints/projects/retrieve-the-environment-variables-of-a-project-by-id-or-name>.

use anyhow::{Result, bail};
use serde::Deserialize;

use super::Observed;
use super::http::{self, segment};

const DEFAULT_API: &str = "https://api.vercel.com";

pub const TARGETS: &[&str] = &["production", "preview", "development"];

pub fn validate(project: &str, key: &str, target: &str, team: Option<&str>) -> Result<()> {
    let ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    };
    if !ok(project) {
        bail!("{project:?} is not a Vercel project name or id");
    }
    if let Some(t) = team
        && !ok(t)
    {
        bail!("{t:?} is not a Vercel team id");
    }
    crate::dotenv::check_var_name(key)?;
    if !TARGETS.contains(&target) {
        bail!("--target is one of {}, got {target:?}", TARGETS.join(", "));
    }
    Ok(())
}

fn api(api_url: Option<&str>) -> &str {
    api_url.unwrap_or(DEFAULT_API).trim_end_matches('/')
}

fn env_url(api_url: Option<&str>, project: &str, team: Option<&str>, upsert: bool) -> String {
    let mut q: Vec<String> = Vec::new();
    if upsert {
        q.push("upsert=true".into());
    }
    if let Some(t) = team {
        q.push(format!("teamId={}", segment(t)));
    }
    let q = if q.is_empty() {
        String::new()
    } else {
        format!("?{}", q.join("&"))
    };
    format!("{}/v10/projects/{}/env{q}", api(api_url), segment(project))
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
    #[serde(default)]
    failed: Vec<serde_json::Value>,
}

/// Sensitive variables cannot be read back, not even in the dashboard;
/// Vercel does not allow them for development.
pub fn set_var(
    api_url: Option<&str>,
    token: &str,
    project: &str,
    team: Option<&str>,
    key: &str,
    target: &str,
    value: &str,
) -> Result<()> {
    let kind = if target == "development" {
        "encrypted"
    } else {
        "sensitive"
    };
    let body = serde_json::json!({
        "key": key,
        "value": value,
        "type": kind,
        "target": [target],
        "comment": "Set by Cemí",
    });
    let resp = call(
        "POST",
        &env_url(api_url, project, team, true),
        token,
        Some(&body),
    )?;
    let what = format!("setting {key} ({target}) in the Vercel project {project}");
    if !resp.ok() {
        return Err(resp.error(&what));
    }
    let created: Created = resp.json()?;
    if let Some(f) = created.failed.first() {
        let msg = f["error"]["message"].as_str().unwrap_or("no message");
        return Err(crate::errors::external(format!("{what} failed: {msg}")));
    }
    Ok(())
}

#[derive(Deserialize)]
struct List {
    #[serde(default)]
    envs: Vec<Listed>,
}

#[derive(Deserialize)]
struct Listed {
    key: String,
    #[serde(default)]
    target: serde_json::Value,
    #[serde(default, rename = "gitBranch")]
    git_branch: Option<String>,
    #[serde(default, rename = "updatedAt")]
    updated_at: Option<serde_json::Value>,
}

impl Listed {
    fn targets(&self, target: &str) -> bool {
        match &self.target {
            serde_json::Value::String(s) => s == target,
            serde_json::Value::Array(a) => a.iter().any(|t| t == target),
            _ => false,
        }
    }
}

/// The variable's update time. Values are never asked for (no `decrypt`).
pub fn observe(
    api_url: Option<&str>,
    token: &str,
    project: &str,
    team: Option<&str>,
    key: &str,
    target: &str,
) -> Result<Observed> {
    let resp = call("GET", &env_url(api_url, project, team, false), token, None)?;
    if !resp.ok() {
        return Err(resp.error(&format!(
            "listing the variables of the Vercel project {project}"
        )));
    }
    let list: List = resp.json()?;
    let found = list
        .envs
        .iter()
        .find(|e| e.key == key && e.git_branch.is_none() && e.targets(target));
    Ok(match found {
        None => Observed::Missing,
        Some(e) => match &e.updated_at {
            Some(at) if !at.is_null() => Observed::Remote(format!("updated {at}")),
            _ => Observed::Unknown,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_and_urls() {
        assert!(validate("shop", "API_KEY", "production", None).is_ok());
        assert!(validate("shop", "API_KEY", "prod", None).is_err());
        assert!(validate("shop/x", "API_KEY", "preview", None).is_err());
        assert_eq!(
            env_url(None, "shop", Some("team_1"), true),
            "https://api.vercel.com/v10/projects/shop/env?upsert=true&teamId=team_1"
        );
        assert_eq!(
            env_url(None, "shop", None, false),
            "https://api.vercel.com/v10/projects/shop/env"
        );
    }
}
