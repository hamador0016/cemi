//! AWS Systems Manager Parameter Store parameters (destination).
//!
//! Docs: <https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html>
//! and <https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeParameters.html>.
//!
//! Values are written as `SecureString` (encrypted with KMS). Observing uses
//! DescribeParameters, which returns metadata and never the value (not even
//! encrypted); the parameter's version grows with every write.

use anyhow::{Result, bail};
use serde::Deserialize;

use super::Observed;
use super::aws::{self, Credentials};

const SERVICE: &str = "ssm";

/// `/shop/prod/stripe-key` or `shop.stripe_key`.
pub fn validate(name: &str, kms_key: Option<&str>) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 1011
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-/".contains(c))
        && !name.ends_with('/')
        && !name.contains("//");
    if !ok {
        bail!("{name:?} is not a Parameter Store name (letters, digits, _ . - and / for levels)");
    }
    let first = name.trim_start_matches('/').to_ascii_lowercase();
    if first.starts_with("aws") || first.starts_with("ssm") {
        bail!("Parameter Store names cannot start with \"aws\" or \"ssm\"");
    }
    if name.matches('/').count() > 15 {
        bail!("Parameter Store names have at most 15 levels");
    }
    if let Some(k) = kms_key
        && (k.is_empty()
            || !k
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ":/_-".contains(c)))
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

fn put_body(name: &str, value: &str, kms_key: Option<&str>) -> serde_json::Value {
    let mut b = serde_json::json!({
        "Name": name,
        "Value": value,
        "Type": "SecureString",
        "Overwrite": true,
    });
    if let Some(k) = kms_key {
        b["KeyId"] = k.into();
    }
    b
}

fn describe_body(name: &str) -> serde_json::Value {
    serde_json::json!({
        "ParameterFilters": [{ "Key": "Name", "Option": "Equals", "Values": [name] }],
    })
}

pub fn put(
    api_url: Option<&str>,
    creds: &Credentials,
    region: &str,
    name: &str,
    kms_key: Option<&str>,
    value: &str,
) -> Result<()> {
    let resp = aws::json_call(
        &url(api_url, region),
        creds,
        region,
        SERVICE,
        "AmazonSSM.PutParameter",
        &put_body(name, value, kms_key),
    )?;
    if !resp.ok() {
        return Err(aws::json_error(
            &resp,
            &format!("setting the parameter {name} in AWS Parameter Store ({region})"),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct Described {
    #[serde(default, rename = "Parameters")]
    parameters: Vec<Meta>,
}

#[derive(Deserialize)]
struct Meta {
    #[serde(rename = "Name")]
    name: String,
    #[serde(default, rename = "Version")]
    version: Option<u64>,
}

/// The parameter's version, from its metadata.
pub fn observe(
    api_url: Option<&str>,
    creds: &Credentials,
    region: &str,
    name: &str,
) -> Result<Observed> {
    let resp = aws::json_call(
        &url(api_url, region),
        creds,
        region,
        SERVICE,
        "AmazonSSM.DescribeParameters",
        &describe_body(name),
    )?;
    if !resp.ok() {
        return Err(aws::json_error(
            &resp,
            &format!("describing the parameter {name} in AWS Parameter Store ({region})"),
        ));
    }
    let d: Described = resp.json()?;
    Ok(match d.parameters.iter().find(|p| p.name == name) {
        None => Observed::Missing,
        Some(p) => match p.version {
            Some(v) => Observed::Remote(format!("version {v}")),
            None => Observed::Unknown,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_and_bodies() {
        assert!(validate("/shop/prod/stripe-key", None).is_ok());
        assert!(validate("shop.stripe_key", Some("alias/shop")).is_ok());
        assert!(validate("/aws/reserved", None).is_err());
        assert!(validate("SSM-x", None).is_err());
        assert!(validate("shop key", None).is_err());
        assert!(validate("/shop/", None).is_err());
        assert!(validate("/shop", Some("bad key")).is_err());
        let b = put_body("/shop/k", "v", None);
        assert_eq!(b["Type"], "SecureString");
        assert_eq!(b["Overwrite"], true);
        assert!(b.get("KeyId").is_none());
        assert_eq!(put_body("/k", "v", Some("alias/x"))["KeyId"], "alias/x");
        assert_eq!(
            describe_body("/shop/k")["ParameterFilters"][0],
            serde_json::json!({"Key": "Name", "Option": "Equals", "Values": ["/shop/k"]})
        );
        assert_eq!(
            url(None, "us-east-2"),
            "https://ssm.us-east-2.amazonaws.com/"
        );
    }
}
