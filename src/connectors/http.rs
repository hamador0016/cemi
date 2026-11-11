//! A small HTTPS client for provider APIs.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;

pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_str(&self.body).context("the provider answered with unexpected JSON")
    }

    /// An error with the provider's message (cut short; it never contains what
    /// Cemí sent, but it is redacted again by the caller).
    pub fn error(&self, what: &str) -> anyhow::Error {
        let mut msg: String = self.body.chars().take(300).collect();
        if msg.trim().is_empty() {
            msg = "(no message)".into();
        }
        let hint = match self.status {
            401 => " The token is wrong or expired.",
            403 => " The token does not have permission for this.",
            404 => " Not found: check the names, or the token cannot see it.",
            429 => " Too many requests: try again in a minute.",
            _ => "",
        };
        crate::errors::external(format!(
            "{what} failed (HTTP {}): {msg}.{hint}",
            self.status
        ))
    }
}

/// Values go over the network only with TLS. Plain http is accepted for this
/// computer alone (local tests and mock servers).
pub fn check_url(url: &str) -> Result<()> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split(['/', '?']).next().unwrap_or("");
        let host = match host.rsplit_once(':') {
            Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        };
        if matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
            return Ok(());
        }
    }
    bail!("{url} must start with https:// (plain http is only allowed for localhost)")
}

pub fn request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&serde_json::Value>,
) -> Result<Response> {
    check_url(url)?;
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .http_status_as_error(false)
        .user_agent(concat!("cemi/", env!("CARGO_PKG_VERSION")))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut builder = ureq::http::Request::builder().method(method).uri(url);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let payload = match body {
        Some(b) => {
            builder = builder.header("content-type", "application/json");
            serde_json::to_vec(b)?
        }
        None => Vec::new(),
    };
    let req = builder.body(payload).context("bad request")?;
    let host = url.split('/').nth(2).unwrap_or(url).to_string();
    let mut resp = agent
        .run(req)
        .map_err(|e| crate::errors::external(format!("cannot reach {host}: {e}")))?;
    let status = resp.status().as_u16();
    let body = resp
        .body_mut()
        .read_to_string()
        .with_context(|| format!("cannot read the answer from {host}"))?;
    Ok(Response { status, body })
}

/// Percent-encodes one path segment.
pub fn segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tls_or_localhost() {
        assert!(check_url("https://api.github.com").is_ok());
        assert!(check_url("http://127.0.0.1:8080/x").is_ok());
        assert!(check_url("http://localhost/x").is_ok());
        assert!(check_url("http://api.github.com").is_err());
        assert!(check_url("http://localhost.evil.com/").is_err());
        assert!(check_url("ftp://x").is_err());
        assert_eq!(segment("prod env/1"), "prod%20env%2F1");
    }
}
