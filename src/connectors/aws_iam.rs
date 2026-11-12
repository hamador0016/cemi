//! AWS IAM access keys (origin).
//!
//! Docs: <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html>,
//! <https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteAccessKey.html> and
//! <https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html>.
//!
//! IAM uses the query protocol: form-encoded POSTs to its global endpoint,
//! signed for us-east-1, with XML answers. The new key's secret access key
//! is the value Cemí stores; its access key id is the provider id (to delete
//! it later), and can also be written to another field of the record.
//! An IAM user has at most two access keys, so a rotation needs one free.

use anyhow::{Result, anyhow, bail};
use zeroize::Zeroizing;

use super::aws::{self, Credentials};
use super::{NewKey, OriginState};

const DEFAULT_API: &str = "https://iam.amazonaws.com";
const REGION: &str = "us-east-1";
const SERVICE: &str = "iam";
const VERSION: &str = "2010-05-08";

pub fn validate_user(user: &str) -> Result<()> {
    let ok = (1..=128).contains(&user.len())
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_+=,.@-".contains(c));
    if !ok {
        bail!("{user:?} is not an IAM user name (letters, digits and _+=,.@-)");
    }
    Ok(())
}

fn url(api_url: Option<&str>) -> String {
    api_url
        .unwrap_or(DEFAULT_API)
        .trim_end_matches('/')
        .to_string()
        + "/"
}

fn user_param(user: Option<&str>) -> Vec<(&str, &str)> {
    user.map(|u| vec![("UserName", u)]).unwrap_or_default()
}

fn call(
    api_url: Option<&str>,
    creds: &Credentials,
    action: &str,
    params: &[(&str, &str)],
) -> Result<super::http::Response> {
    aws::query_call(
        &url(api_url),
        creds,
        REGION,
        SERVICE,
        action,
        VERSION,
        params,
    )
}

fn who(user: Option<&str>) -> String {
    match user {
        Some(u) => format!("the IAM user {u}"),
        None => "the IAM user of the signing key".into(),
    }
}

pub fn create_key(
    api_url: Option<&str>,
    creds: &Credentials,
    user: Option<&str>,
) -> Result<NewKey> {
    let resp = call(api_url, creds, "CreateAccessKey", &user_param(user))?;
    if !resp.ok() {
        let mut err = aws::query_error(&resp, &format!("creating an access key for {}", who(user)));
        if resp.status == 409 {
            err = err.context(
                "an IAM user has at most two access keys: delete the one that is not in use, then rotate again",
            );
        }
        return Err(err);
    }
    let body = Zeroizing::new(resp.body);
    let id = aws::xml_text(&body, "AccessKeyId")
        .ok_or_else(|| anyhow!("IAM created a key but its answer has no AccessKeyId"))?;
    let secret = Zeroizing::new(
        aws::xml_text(&body, "SecretAccessKey")
            .ok_or_else(|| anyhow!("IAM created the key {id} but did not return its secret"))?,
    );
    Ok(NewKey {
        value: secret,
        provider_id: Some(id),
    })
}

/// Deletes a key. AWS has no way to mark a key as leaked: it is deleted
/// either way, which stops it at once.
pub fn delete_key(
    api_url: Option<&str>,
    creds: &Credentials,
    user: Option<&str>,
    id: &str,
) -> Result<()> {
    let mut params = user_param(user);
    params.push(("AccessKeyId", id));
    let resp = call(api_url, creds, "DeleteAccessKey", &params)?;
    if resp.ok() || resp.status == 404 {
        return Ok(());
    }
    Err(aws::query_error(
        &resp,
        &format!("deleting the access key {id} of {}", who(user)),
    ))
}

/// Alive while the key exists and is active; an inactive key no longer
/// signs in, so it counts as gone.
pub fn key_state(
    api_url: Option<&str>,
    creds: &Credentials,
    user: Option<&str>,
    id: &str,
) -> Result<OriginState> {
    let mut marker: Option<String> = None;
    loop {
        let mut params = user_param(user);
        if let Some(m) = &marker {
            params.push(("Marker", m.as_str()));
        }
        let resp = call(api_url, creds, "ListAccessKeys", &params)?;
        if !resp.ok() {
            return Err(aws::query_error(
                &resp,
                &format!("listing the access keys of {}", who(user)),
            ));
        }
        for m in aws::xml_blocks(&resp.body, "member") {
            if aws::xml_text(m, "AccessKeyId").as_deref() == Some(id) {
                return Ok(match aws::xml_text(m, "Status").as_deref() {
                    Some("Active") => OriginState::Alive,
                    _ => OriginState::Gone,
                });
            }
        }
        if aws::xml_text(&resp.body, "IsTruncated").as_deref() != Some("true") {
            return Ok(OriginState::Gone);
        }
        marker = aws::xml_text(&resp.body, "Marker");
        if marker.is_none() {
            return Ok(OriginState::Gone);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options() {
        assert!(validate_user("deploy-bot").is_ok());
        assert!(validate_user("ci+shop@acme.com").is_ok());
        assert!(validate_user("").is_err());
        assert!(validate_user("deploy bot").is_err());
        assert!(validate_user(&"x".repeat(129)).is_err());
        assert_eq!(url(None), "https://iam.amazonaws.com/");
        assert!(user_param(None).is_empty());
        assert_eq!(user_param(Some("bob")), [("UserName", "bob")]);
    }
}
