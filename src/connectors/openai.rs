//! OpenAI API keys of a project service account (origin), through the
//! Admin API.
//!
//! Docs: <https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/service_accounts/subresources/api_keys/methods/create>,
//! <https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/api_keys>
//! and <https://developers.openai.com/api/docs/guides/api-keys>.
//!
//! Each new value is a new key of the same service account; the old key is
//! deleted with the project API key endpoints. The value is only returned
//! when the key is created.

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::http::{self, segment};
use super::{NewKey, OriginState};

const DEFAULT_API: &str = "https://api.openai.com/v1";

pub fn validate(project: &str, service_account: &str, name: &str) -> Result<()> {
    let id = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    };
    if !id(project) || !project.starts_with("proj_") {
        bail!("{project:?} is not an OpenAI project id (proj_…)");
    }
    if !id(service_account) {
        bail!("{service_account:?} is not an OpenAI service account id");
    }
    if name.trim().is_empty() || name.chars().count() > 40 {
        bail!("key names have 1 to 40 characters (Cemí adds the date)");
    }
    Ok(())
}

fn api(api_url: Option<&str>) -> &str {
    api_url.unwrap_or(DEFAULT_API).trim_end_matches('/')
}

fn call(
    method: &str,
    url: &str,
    admin: &str,
    body: Option<&serde_json::Value>,
) -> Result<http::Response> {
    let auth = format!("Bearer {admin}");
    http::request(
        method,
        url,
        &[("authorization", &auth), ("accept", "application/json")],
        body,
    )
}

fn create_url(api_url: Option<&str>, project: &str, service_account: &str) -> String {
    format!(
        "{}/organization/projects/{}/service_accounts/{}/api_keys",
        api(api_url),
        segment(project),
        segment(service_account)
    )
}

fn key_url(api_url: Option<&str>, project: &str, id: &str) -> String {
    format!(
        "{}/organization/projects/{}/api_keys/{}",
        api(api_url),
        segment(project),
        segment(id)
    )
}

#[derive(Deserialize)]
struct Created {
    id: String,
    value: Option<Zeroizing<String>>,
}

pub fn create_key(
    api_url: Option<&str>,
    admin: &str,
    project: &str,
    service_account: &str,
    name: &str,
) -> Result<NewKey> {
    let stamp = jiff::Timestamp::now()
        .strftime("%Y-%m-%d %H:%M")
        .to_string();
    let body = serde_json::json!({ "name": format!("{name} {stamp}") });
    let resp = call(
        "POST",
        &create_url(api_url, project, service_account),
        admin,
        Some(&body),
    )?;
    if !resp.ok() {
        return Err(resp.error(&format!(
            "creating an API key for the service account {service_account} (OpenAI project {project})"
        )));
    }
    let body = Zeroizing::new(resp.body);
    let k: Created =
        serde_json::from_str(&body).map_err(|_| anyhow!("OpenAI answered with unexpected JSON"))?;
    let value = k
        .value
        .ok_or_else(|| anyhow!("OpenAI created the key {} but did not return it", k.id))?;
    Ok(NewKey {
        value,
        provider_id: Some(k.id),
    })
}

pub fn delete_key(api_url: Option<&str>, admin: &str, project: &str, id: &str) -> Result<()> {
    let resp = call("DELETE", &key_url(api_url, project, id), admin, None)?;
    if resp.ok() || resp.status == 404 {
        return Ok(());
    }
    Err(resp.error(&format!(
        "deleting the old API key {id} (OpenAI project {project})"
    )))
}

pub fn key_state(
    api_url: Option<&str>,
    admin: &str,
    project: &str,
    id: &str,
) -> Result<OriginState> {
    let resp = call("GET", &key_url(api_url, project, id), admin, None)?;
    if resp.status == 404 {
        return Ok(OriginState::Gone);
    }
    if !resp.ok() {
        return Err(resp.error(&format!(
            "reading the API key {id} (OpenAI project {project})"
        )));
    }
    Ok(OriginState::Alive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_and_urls() {
        assert!(validate("proj_abc123", "svc_acct_abc", "shop").is_ok());
        assert!(validate("abc123", "svc_acct_abc", "shop").is_err());
        assert!(validate("proj_abc", "svc acct", "shop").is_err());
        assert!(validate("proj_abc", "svc", &"x".repeat(41)).is_err());
        assert_eq!(
            create_url(None, "proj_1", "svc_2"),
            "https://api.openai.com/v1/organization/projects/proj_1/service_accounts/svc_2/api_keys"
        );
        assert_eq!(
            key_url(None, "proj_1", "key_3"),
            "https://api.openai.com/v1/organization/projects/proj_1/api_keys/key_3"
        );
    }
}
