//! What the AWS connectors share: request signing (Signature Version 4),
//! the JSON protocol of Secrets Manager and Systems Manager, the query
//! protocol of IAM, and a small reader for IAM's XML answers.
//!
//! Signing follows <https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html>;
//! the unit tests check it against AWS's Signature Version 4 test suite
//! (`get-vanilla` and `post-x-www-form-urlencoded`). No AWS SDK is used.

use anyhow::{Result, bail};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::http;

/// Credentials that sign requests (values resolved from the vault).
pub struct Credentials {
    pub access_key_id: Zeroizing<String>,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

/// `us-east-1`, `eu-central-2`, `us-gov-west-1`, `cn-north-1`…
pub fn validate_region(region: &str) -> Result<()> {
    let parts: Vec<&str> = region.split('-').collect();
    let ok = parts.len() >= 3
        && parts[..parts.len() - 1]
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase()))
        && parts[parts.len() - 1].chars().all(|c| c.is_ascii_digit())
        && !parts[parts.len() - 1].is_empty();
    if !ok {
        bail!("{region:?} is not an AWS region (like us-east-1)");
    }
    Ok(())
}

/// The regional endpoint of a service (China regions use amazonaws.com.cn).
pub fn endpoint(service: &str, region: &str) -> String {
    let suffix = if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    };
    format!("https://{service}.{region}.{suffix}")
}

/// SigV4's UriEncode: everything but `A-Z a-z 0-9 - . _ ~` is percent-encoded.
pub fn uri_encode(s: &str) -> String {
    http::segment(s)
}

fn hex_sha256(data: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(data))
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// The key derived from the secret access key for one day, region and service.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Zeroizing<Vec<u8>> {
    let start = Zeroizing::new(format!("AWS4{secret}"));
    let k_date = Zeroizing::new(hmac(start.as_bytes(), date.as_bytes()));
    let k_region = Zeroizing::new(hmac(&k_date, region.as_bytes()));
    let k_service = Zeroizing::new(hmac(&k_region, service.as_bytes()));
    Zeroizing::new(hmac(&k_service, b"aws4_request"))
}

/// One request to sign. `headers` are the headers to sign besides `host`
/// and `x-amz-date` (names in lowercase).
pub struct Request<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    /// Already in canonical form (sorted, encoded); empty when there is none.
    pub query: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub payload: &'a [u8],
}

/// Signs a request and returns its `Authorization` header. `amz_date` is
/// `YYYYMMDDTHHMMSSZ`, and must also be sent as `x-amz-date`.
pub fn authorization(
    req: &Request,
    creds: &Credentials,
    region: &str,
    service: &str,
    amz_date: &str,
) -> String {
    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), req.host.to_string()),
        ("x-amz-date".into(), amz_date.to_string()),
    ];
    for (k, v) in req.headers {
        headers.push((k.to_ascii_lowercase(), v.to_string()));
    }
    headers.sort();
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| {
            let v = v.split_whitespace().collect::<Vec<_>>().join(" ");
            format!("{k}:{v}\n")
        })
        .collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{}",
        req.method,
        req.path,
        req.query,
        hex_sha256(req.payload)
    );
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex_sha256(canonical_request.as_bytes())
    );
    let key = signing_key(&creds.secret_access_key, date, region, service);
    let signature = data_encoding::HEXLOWER.encode(&hmac(&key, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id.as_str()
    )
}

/// Host (with its port, when there is one) and path of an `https://` or
/// local `http://` address.
fn split_url(url: &str) -> (&str, &str) {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    }
}

/// Signs and sends a POST. Values only travel in `payload`.
fn post(
    url: &str,
    creds: &Credentials,
    region: &str,
    service: &str,
    content_type: &str,
    extra: &[(&str, &str)],
    payload: &[u8],
) -> Result<http::Response> {
    http::check_url(url)?;
    let (host, path) = split_url(url);
    let amz_date = jiff::Timestamp::now()
        .strftime("%Y%m%dT%H%M%SZ")
        .to_string();
    let mut headers: Vec<(&str, &str)> = vec![("content-type", content_type)];
    headers.extend_from_slice(extra);
    if let Some(t) = &creds.session_token {
        headers.push(("x-amz-security-token", t.as_str()));
    }
    let auth = authorization(
        &Request {
            method: "POST",
            host,
            path,
            query: "",
            headers: &headers,
            payload,
        },
        creds,
        region,
        service,
        &amz_date,
    );
    headers.push(("x-amz-date", &amz_date));
    headers.push(("authorization", &auth));
    headers.push(("accept", "application/json"));
    http::send("POST", url, &headers, payload)
}

/// An AWS JSON 1.1 call (Secrets Manager, Systems Manager): `target` is
/// like `secretsmanager.PutSecretValue`.
pub fn json_call(
    url: &str,
    creds: &Credentials,
    region: &str,
    service: &str,
    target: &str,
    body: &serde_json::Value,
) -> Result<http::Response> {
    let payload = Zeroizing::new(serde_json::to_vec(body)?);
    post(
        url,
        creds,
        region,
        service,
        "application/x-amz-json-1.1",
        &[("x-amz-target", target)],
        &payload,
    )
}

/// The error code of a JSON 1.1 answer (`ResourceNotFoundException`), without
/// the namespace some services put before `#`.
pub fn json_error_code(resp: &http::Response) -> String {
    let v: serde_json::Value = serde_json::from_str(&resp.body).unwrap_or_default();
    let code = v["__type"].as_str().unwrap_or("");
    code.rsplit('#').next().unwrap_or("").to_string()
}

/// A readable error for a failed JSON 1.1 call.
pub fn json_error(resp: &http::Response, what: &str) -> anyhow::Error {
    let v: serde_json::Value = serde_json::from_str(&resp.body).unwrap_or_default();
    let code = json_error_code(resp);
    let message = v["message"]
        .as_str()
        .or_else(|| v["Message"].as_str())
        .unwrap_or("");
    aws_error(what, resp.status, &code, message)
}

fn aws_error(what: &str, status: u16, code: &str, message: &str) -> anyhow::Error {
    if code.is_empty() {
        return crate::errors::external(format!(
            "{what} failed (HTTP {status}): {}",
            if message.is_empty() {
                "(no message)"
            } else {
                message
            }
        ));
    }
    let message: String = message.chars().take(300).collect();
    let hint = match code {
        "UnrecognizedClientException"
        | "InvalidClientTokenId"
        | "SignatureDoesNotMatch"
        | "InvalidSignatureException" => {
            " The access key id or secret access key is wrong, or the key is no longer active."
        }
        "ExpiredTokenException" | "ExpiredToken" => " The session token has expired.",
        "AccessDeniedException" | "AccessDenied" => {
            " The credentials do not have permission for this (see docs/connectors.md for the policy)."
        }
        "ThrottlingException" | "Throttling" => " Too many requests: try again in a minute.",
        _ => "",
    };
    crate::errors::external(format!("{what} failed: {code}: {message}.{hint}"))
}

/// An AWS query protocol call (IAM): a form-encoded POST. `params` must not
/// include `Action` or `Version`.
pub fn query_call(
    url: &str,
    creds: &Credentials,
    region: &str,
    service: &str,
    action: &str,
    version: &str,
    params: &[(&str, &str)],
) -> Result<http::Response> {
    let body = form(action, version, params);
    post(
        url,
        creds,
        region,
        service,
        "application/x-www-form-urlencoded; charset=utf-8",
        &[],
        body.as_bytes(),
    )
}

fn form(action: &str, version: &str, params: &[(&str, &str)]) -> String {
    let mut pairs = vec![("Action", action), ("Version", version)];
    pairs.extend_from_slice(params);
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// A readable error for a failed query protocol call (XML answer).
pub fn query_error(resp: &http::Response, what: &str) -> anyhow::Error {
    let code = xml_text(&resp.body, "Code").unwrap_or_default();
    let message = xml_text(&resp.body, "Message").unwrap_or_default();
    aws_error(what, resp.status, &code, &message)
}

/// The text of the first `<tag>…</tag>` in `xml`, unescaped and trimmed.
/// Enough for IAM's answers, which have no attributes on these elements.
pub fn xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let len = xml[start..].find(&close)?;
    Some(unescape(xml[start..start + len].trim()))
}

/// Every `<tag>…</tag>` block in `xml` (their inner text, not unescaped).
pub fn xml_blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find(&open) {
        let after = &rest[s + open.len()..];
        let Some(e) = after.find(&close) else { break };
        out.push(&after[..e]);
        rest = &after[e + close.len()..];
    }
    out
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// A random version id for Secrets Manager (`ClientRequestToken`), shaped
/// like a UUID.
pub fn request_token() -> String {
    let b = crate::crypto::random_bytes::<16>();
    let h = data_encoding::HEXLOWER.encode(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example credentials of AWS's test suite (not a real key).
    fn example() -> Credentials {
        Credentials {
            access_key_id: Zeroizing::new("AKIDEXAMPLE".into()),
            secret_access_key: Zeroizing::new(
                ["wJalrXUtnFEMI", "/K7MDENG+bPxRfiCY", "EXAMPLEKEY"].concat(),
            ),
            session_token: None,
        }
    }

    #[test]
    fn sigv4_test_suite_get_vanilla() {
        let auth = authorization(
            &Request {
                method: "GET",
                host: "example.amazonaws.com",
                path: "/",
                query: "",
                headers: &[],
                payload: b"",
            },
            &example(),
            "us-east-1",
            "service",
            "20150830T123600Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn sigv4_test_suite_post_form() {
        let auth = authorization(
            &Request {
                method: "POST",
                host: "example.amazonaws.com",
                path: "/",
                query: "",
                headers: &[("Content-Type", "application/x-www-form-urlencoded")],
                payload: b"Param1=value1",
            },
            &example(),
            "us-east-1",
            "service",
            "20150830T123600Z",
        );
        assert!(
            auth.ends_with(
                "SignedHeaders=content-type;host;x-amz-date, \
                 Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"
            ),
            "{auth}"
        );
    }

    #[test]
    fn regions_endpoints_and_forms() {
        assert!(validate_region("us-east-1").is_ok());
        assert!(validate_region("us-gov-west-1").is_ok());
        assert!(validate_region("eu-central-2").is_ok());
        assert!(validate_region("us-east").is_err());
        assert!(validate_region("US-EAST-1").is_err());
        assert!(validate_region("us-east-1.evil.com/").is_err());
        assert_eq!(
            endpoint("secretsmanager", "eu-west-1"),
            "https://secretsmanager.eu-west-1.amazonaws.com"
        );
        assert_eq!(
            endpoint("ssm", "cn-north-1"),
            "https://ssm.cn-north-1.amazonaws.com.cn"
        );
        assert_eq!(
            form("DeleteAccessKey", "2010-05-08", &[("UserName", "a+b@c")]),
            "Action=DeleteAccessKey&Version=2010-05-08&UserName=a%2Bb%40c"
        );
        assert_eq!(split_url("http://127.0.0.1:9/"), ("127.0.0.1:9", "/"));
        assert_eq!(
            split_url("https://iam.amazonaws.com"),
            ("iam.amazonaws.com", "/")
        );
        let t = request_token();
        assert_eq!(t.len(), 36);
        assert_ne!(t, request_token());
    }

    #[test]
    fn xml_answers() {
        let xml = "<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code>\
                   <Message>The user with name bob &amp; co cannot be found.</Message></Error></ErrorResponse>";
        assert_eq!(xml_text(xml, "Code").as_deref(), Some("NoSuchEntity"));
        assert_eq!(
            xml_text(xml, "Message").as_deref(),
            Some("The user with name bob & co cannot be found.")
        );
        let list = "<AccessKeyMetadata><member><AccessKeyId>A1</AccessKeyId></member>\
                    <member><AccessKeyId>A2</AccessKeyId></member></AccessKeyMetadata>";
        let ids: Vec<String> = xml_blocks(list, "member")
            .iter()
            .filter_map(|m| xml_text(m, "AccessKeyId"))
            .collect();
        assert_eq!(ids, ["A1", "A2"]);
    }
}
