//! AWS Secrets Manager secrets (destination).
//!
//! Docs: <https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html>,
//! <https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html> and
//! <https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html>.
//!
//! Each write stores a new version and moves the `AWSCURRENT` label to it.
//! Observing reads the secret's description only (never its value): the id
//! of the version labelled `AWSCURRENT` changes with every new value.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::Deserialize;

use super::Observed;
use super::aws::{self, Credentials};

const SERVICE: &str = "secretsmanager";

/// A secret name (`prod/shop/stripe`) or its ARN.
pub fn validate(secret_id: &str, kms_key: Option<&str>) -> Result<()> {
    let ok = !secret_id.is_empty()
        && secret_id.len() <= 2048
        && secret_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/_+=.@-:".contains(c));
    if !ok {
        bail!(
            "{secret_id:?} is not a Secrets Manager secret name or ARN (letters, digits and /_+=.@-)"
        );
    }
    if let Some(k) = kms_key
        && (k.is_empty() || k.chars().any(char::is_whitespace))
    {
        bail!("{k:?} is not a KMS key id, ARN or alias");
    }
    Ok(())
}

fn url(api_url: Option<&str>, region: &str) -> String {
    match api_url {
        Some(u) => u.trim_end_matches('/').to_string() + "/",
        None => aws::endpoint(SERVICE, region) + "/",
    }
}

fn call(
    api_url: Option<&str>,
    creds: &Credentials,
    region: &str,
    action: &str,
    body: &serde_json::Value,
) -> Result<super::http::Response> {
    aws::json_call(
        &url(api_url, region),
        creds,
        region,
        SERVICE,
        &format!("secretsmanager.{action}"),
        body,
    )
}

/// Body of PutSecretValue: a new version that becomes `AWSCURRENT`.
fn put_body(secret_id: &str, value: &str, token: &str) -> serde_json::Value {
    serde_json::json!({
        "SecretId": secret_id,
        "SecretString": value,
        "ClientRequestToken": token,
    })
}

fn create_body(name: &str, value: &str, kms_key: Option<&str>, token: &str) -> serde_json::Value {
    let mut b = serde_json::json!({
        "Name": name,
        "SecretString": value,
        "ClientRequestToken": token,
        "Description": "Set by Cemí",
    });
    if let Some(k) = kms_key {
        b["KmsKeyId"] = k.into();
    }
    b
}

/// Stores a new version; creates the secret when it does not exist yet.
pub fn put(
    api_url: Option<&str>,
    creds: &Credentials,
    region: &str,
    secret_id: &str,
    kms_key: Option<&str>,
    value: &str,
) -> Result<()> {
    let token = aws::request_token();
    let what = format!("storing the secret {secret_id} in AWS Secrets Manager ({region})");
    let resp = call(
        api_url,
        creds,
        region,
        "PutSecretValue",
        &put_body(secret_id, value, &token),
    )?;
    if resp.ok() {
        return Ok(());
    }
    if aws::json_error_code(&resp) != "ResourceNotFoundException" {
        return Err(aws::json_error(&resp, &what));
    }
    if secret_id.starts_with("arn:") {
        bail!(
            "the secret {secret_id} does not exist; create it first, or give its name instead of its ARN"
        );
    }
    let resp = call(
        api_url,
        creds,
        region,
        "CreateSecret",
        &create_body(secret_id, value, kms_key, &token),
    )?;
    if !resp.ok() {
        return Err(aws::json_error(
            &resp,
            &format!("creating the secret {secret_id} in AWS Secrets Manager ({region})"),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct Described {
    #[serde(default, rename = "VersionIdsToStages")]
    versions: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "DeletedDate")]
    deleted: Option<serde_json::Value>,
}

/// The id of the version labelled `AWSCURRENT`.
pub fn observe(
    api_url: Option<&str>,
    creds: &Credentials,
    region: &str,
    secret_id: &str,
) -> Result<Observed> {
    let resp = call(
        api_url,
        creds,
        region,
        "DescribeSecret",
        &serde_json::json!({ "SecretId": secret_id }),
    )?;
    if !resp.ok() {
        if aws::json_error_code(&resp) == "ResourceNotFoundException" {
            return Ok(Observed::Missing);
        }
        return Err(aws::json_error(
            &resp,
            &format!("describing the secret {secret_id} in AWS Secrets Manager ({region})"),
        ));
    }
    let d: Described = resp.json()?;
    // Scheduled for deletion: its value can no longer be read or changed.
    if d.deleted.is_some_and(|x| !x.is_null()) {
        return Ok(Observed::Missing);
    }
    let current = d
        .versions
        .iter()
        .find(|(_, stages)| stages.iter().any(|s| s == "AWSCURRENT"));
    Ok(match current {
        Some((id, _)) => Observed::Remote(format!("version {id}")),
        None => Observed::Missing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_and_bodies() {
        assert!(validate("prod/shop/stripe", None).is_ok());
        assert!(
            validate(
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:shop-AbCdEf",
                Some("alias/shop")
            )
            .is_ok()
        );
        assert!(validate("shop secret", None).is_err());
        assert!(validate("", None).is_err());
        assert!(validate("shop", Some("a b")).is_err());
        let b = put_body("shop", "v", "t-1");
        assert_eq!(b["SecretId"], "shop");
        assert_eq!(b["SecretString"], "v");
        assert_eq!(b["ClientRequestToken"], "t-1");
        let c = create_body("shop", "v", Some("alias/k"), "t-1");
        assert_eq!(c["Name"], "shop");
        assert_eq!(c["KmsKeyId"], "alias/k");
        assert!(
            create_body("shop", "v", None, "t")
                .get("KmsKeyId")
                .is_none()
        );
        assert_eq!(
            url(None, "eu-west-1"),
            "https://secretsmanager.eu-west-1.amazonaws.com/"
        );
        assert_eq!(url(Some("http://127.0.0.1:9/"), "x"), "http://127.0.0.1:9/");
    }
}
