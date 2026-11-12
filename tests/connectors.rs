//! End-to-end tests of the connectors: Cloudflare, Resend, Netlify, Vercel,
//! AWS (IAM, Secrets Manager, Parameter Store), GitLab, Fly.io and OpenAI
//! against a local mock of their APIs, and `.env` files over SSH with a
//! stand-in for the ssh program.

mod common;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use common::*;

/// Runs a command that must succeed; returns stdout and stderr together.
fn both(env: &Env, args: &[&str]) -> String {
    let (code, out, err) = env.run(args, "");
    assert_eq!(
        code, 0,
        "cemi {args:?} failed:
{out}
{err}"
    );
    format!("{out}{err}")
}

const ACCOUNT: &str = "0123456789abcdef0123456789abcdef";

struct CfToken {
    value: String,
    status: String,
    policies: serde_json::Value,
}

#[derive(Default)]
struct State {
    auth: Vec<String>,
    cf_tokens: BTreeMap<String, CfToken>,
    cf_created_bodies: Vec<serde_json::Value>,
    cf_deleted: Vec<String>,
    cf_secrets: BTreeMap<String, String>,
    resend_keys: BTreeMap<String, String>,
    resend_bodies: Vec<serde_json::Value>,
    resend_deleted: Vec<String>,
    /// key → (is_secret, scopes, context → value)
    netlify: BTreeMap<String, (bool, serde_json::Value, BTreeMap<String, String>)>,
    netlify_updated: u32,
    /// key → (value, type, updatedAt)
    vercel: BTreeMap<String, (String, String, u64)>,
    vercel_writes: u64,
    /// AWS: the Authorization header of every call, with its service.
    aws_auth: Vec<String>,
    /// Secrets Manager: name → (value, AWSCURRENT version id, KMS key)
    aws_secrets: BTreeMap<String, (String, String, Option<String>)>,
    /// Parameter Store: name → (value, version, type)
    aws_params: BTreeMap<String, (String, u64, String)>,
    /// A parameter whose writes fail.
    fail_param: Option<String>,
    /// IAM: access key id → (user, secret, status)
    iam_keys: BTreeMap<String, (String, String, String)>,
    iam_deleted: Vec<String>,
    /// GitLab: (key, scope) → (value, masked, protected, hidden)
    gitlab: BTreeMap<(String, String), (String, bool, bool, bool)>,
    /// Fly.io: name → (value, digest)
    fly: BTreeMap<String, (String, String)>,
    /// OpenAI: key id → value
    openai_keys: BTreeMap<String, String>,
    openai_bodies: Vec<serde_json::Value>,
    openai_deleted: Vec<String>,
    next: u32,
}

fn aws_json(status: u16, v: serde_json::Value) -> (u16, serde_json::Value) {
    (status, v)
}

fn aws_not_found(kind: &str) -> (u16, serde_json::Value) {
    (
        400,
        serde_json::json!({"__type": kind, "message": "not found"}),
    )
}

/// Decodes a form body (`a=b&c=d`, percent-encoded).
fn form(body: &str) -> BTreeMap<String, String> {
    let decode = |s: &str| {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() + 1 {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                out.push(if b[i] == b'+' { b' ' } else { b[i] });
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    };
    body.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

/// Answers in XML (IAM); the mock always says JSON in the header, which
/// Cemí ignores.
fn xml(status: u16, text: String) -> (u16, serde_json::Value) {
    (status, serde_json::Value::String(text))
}

struct Mock {
    url: String,
    state: Arc<Mutex<State>>,
}

impl Mock {
    fn start() -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let s = state.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                handle(conn, &s);
            }
        });
        Mock { url, state }
    }
}

fn ok(result: serde_json::Value) -> (u16, serde_json::Value) {
    (
        200,
        serde_json::json!({"success": true, "errors": [], "messages": [], "result": result}),
    )
}

fn handle(mut conn: TcpStream, state: &Arc<Mutex<State>>) {
    let mut reader = BufReader::new(conn.try_clone().unwrap());
    let mut first = String::new();
    if reader.read_line(&mut first).is_err() {
        return;
    }
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let mut length = 0;
    let mut auth = String::new();
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':').unwrap();
        let k = k.to_ascii_lowercase();
        match k.as_str() {
            "content-length" => length = v.trim().parse().unwrap(),
            "authorization" => auth = v.trim().to_string(),
            _ => {}
        }
        headers.insert(k, v.trim().to_string());
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let raw = String::from_utf8_lossy(&body).to_string();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let target_header = headers.get("x-amz-target").cloned().unwrap_or_default();
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let bearer = auth.strip_prefix("Bearer ").unwrap_or("").to_string();
    let mut st = state.lock().unwrap();
    st.auth.push(format!("{method} {path} {auth}"));
    let workers = format!("/accounts/{ACCOUNT}/workers/scripts/shop-api/secrets");
    let (status, answer) = match (method.as_str(), path) {
        // ----- Cloudflare tokens -----
        ("GET", "/user/tokens/verify") => {
            match st
                .cf_tokens
                .iter()
                .find(|(_, t)| t.value == bearer && t.status == "active")
            {
                Some((id, _)) => ok(serde_json::json!({"id": id, "status": "active"})),
                None => (
                    401,
                    serde_json::json!({"success": false, "errors": [{"code": 1000, "message": "Invalid API Token"}]}),
                ),
            }
        }
        ("POST", "/user/tokens") => {
            assert_eq!(bearer, "cf-admin-token");
            st.next += 1;
            let id = format!("cf{}", st.next);
            let value = format!("cf-new-token-{}", st.next);
            st.cf_created_bodies.push(body.clone());
            st.cf_tokens.insert(
                id.clone(),
                CfToken {
                    value: value.clone(),
                    status: "active".into(),
                    policies: body["policies"].clone(),
                },
            );
            ok(
                serde_json::json!({"id": id, "name": body["name"], "status": "active", "value": value}),
            )
        }
        ("GET", p) if p.starts_with("/user/tokens/") => {
            assert_eq!(bearer, "cf-admin-token");
            let id = p.rsplit('/').next().unwrap();
            match st.cf_tokens.get(id) {
                Some(t) => ok(serde_json::json!({
                    "id": id,
                    "name": "shop deploy",
                    "status": t.status,
                    "policies": t.policies,
                    "condition": {"request_ip": {"in": ["192.0.2.0/24"]}},
                })),
                None => (
                    404,
                    serde_json::json!({"success": false, "errors": [{"code": 1003, "message": "Not found"}]}),
                ),
            }
        }
        ("DELETE", p) if p.starts_with("/user/tokens/") => {
            assert_eq!(bearer, "cf-admin-token");
            let id = p.rsplit('/').next().unwrap().to_string();
            st.cf_tokens.remove(&id);
            st.cf_deleted.push(id.clone());
            ok(serde_json::json!({"id": id}))
        }
        // ----- Cloudflare Workers secrets -----
        ("PUT", p) if p == workers => {
            assert_eq!(body["type"], "secret_text");
            st.cf_secrets.insert(
                body["name"].as_str().unwrap().into(),
                body["text"].as_str().unwrap().into(),
            );
            ok(serde_json::json!({"name": body["name"], "type": "secret_text"}))
        }
        ("GET", p) if p.starts_with(&format!("{workers}/")) => {
            let name = p.rsplit('/').next().unwrap();
            if st.cf_secrets.contains_key(name) {
                ok(serde_json::json!({"name": name, "type": "secret_text"}))
            } else {
                (
                    404,
                    serde_json::json!({"success": false, "errors": [{"code": 10056, "message": "not found"}]}),
                )
            }
        }
        // ----- Resend -----
        ("POST", "/api-keys") => {
            assert_eq!(bearer, "re_admin_key");
            st.next += 1;
            let id = format!("rk{}", st.next);
            let token = format!("re_new_{}", st.next);
            st.resend_keys.insert(id.clone(), token.clone());
            st.resend_bodies.push(body.clone());
            (
                201,
                serde_json::json!({"id": id, "object": "api_key", "token": token}),
            )
        }
        ("GET", "/api-keys") => {
            let data: Vec<serde_json::Value> = st
                .resend_keys
                .keys()
                .map(|id| serde_json::json!({"id": id, "name": "x", "created_at": "2026-11-11 00:00:00+00"}))
                .collect();
            (
                200,
                serde_json::json!({"object": "list", "has_more": false, "data": data}),
            )
        }
        ("DELETE", p) if p.starts_with("/api-keys/") => {
            let id = p.rsplit('/').next().unwrap().to_string();
            st.resend_keys.remove(&id);
            st.resend_deleted.push(id.clone());
            (
                200,
                serde_json::json!({"object": "api_key", "id": id, "deleted": true}),
            )
        }
        // ----- Netlify -----
        ("PATCH", p) if p.starts_with("/accounts/acme/env/") => {
            assert_eq!(query, "site_id=site-1");
            let key = p.rsplit('/').next().unwrap().to_string();
            if st.netlify.contains_key(&key) {
                let ctx = body["context"].as_str().unwrap().to_string();
                let val = body["value"].as_str().unwrap().to_string();
                st.netlify.get_mut(&key).unwrap().2.insert(ctx, val);
                st.netlify_updated += 1;
                (201, serde_json::json!({"key": key}))
            } else {
                (
                    404,
                    serde_json::json!({"code": 404, "message": "Not Found"}),
                )
            }
        }
        ("POST", "/accounts/acme/env") => {
            assert_eq!(query, "site_id=site-1");
            for v in body.as_array().unwrap() {
                let mut values = BTreeMap::new();
                for x in v["values"].as_array().unwrap() {
                    values.insert(
                        x["context"].as_str().unwrap().to_string(),
                        x["value"].as_str().unwrap().to_string(),
                    );
                }
                st.netlify.insert(
                    v["key"].as_str().unwrap().to_string(),
                    (
                        v["is_secret"].as_bool().unwrap(),
                        v["scopes"].clone(),
                        values,
                    ),
                );
            }
            st.netlify_updated += 1;
            (201, body.clone())
        }
        ("GET", p) if p.starts_with("/accounts/acme/env/") => {
            let key = p.rsplit('/').next().unwrap();
            match st.netlify.get(key) {
                Some((secret, scopes, values)) => {
                    let values: Vec<serde_json::Value> = values
                        .keys()
                        .map(|c| serde_json::json!({"id": "v1", "context": c, "value": "**masked**"}))
                        .collect();
                    (
                        200,
                        serde_json::json!({
                            "key": key,
                            "is_secret": secret,
                            "scopes": scopes,
                            "values": values,
                            "updated_at": format!("2026-11-11T00:00:{:02}Z", st.netlify_updated),
                        }),
                    )
                }
                None => (
                    404,
                    serde_json::json!({"code": 404, "message": "Not Found"}),
                ),
            }
        }
        // ----- Vercel -----
        ("POST", "/v10/projects/shop/env") => {
            assert_eq!(query, "upsert=true&teamId=team_1");
            assert_eq!(body["target"], serde_json::json!(["production"]));
            st.vercel_writes += 1;
            let at = 1_762_000_000_000 + st.vercel_writes;
            st.vercel.insert(
                body["key"].as_str().unwrap().into(),
                (
                    body["value"].as_str().unwrap().into(),
                    body["type"].as_str().unwrap().into(),
                    at,
                ),
            );
            (
                201,
                serde_json::json!({"created": {"key": body["key"], "type": body["type"], "value": "enc"}, "failed": []}),
            )
        }
        ("GET", "/v10/projects/shop/env") => {
            assert_eq!(query, "teamId=team_1");
            let envs: Vec<serde_json::Value> = st
                .vercel
                .iter()
                .map(|(k, (_, t, at))| {
                    serde_json::json!({"key": k, "type": t, "value": "enc", "target": ["production"], "updatedAt": at, "securityIssues": []})
                })
                .collect();
            (200, serde_json::json!({"envs": envs}))
        }
        // ----- AWS Secrets Manager (JSON 1.1) -----
        ("POST", "/sm/") => {
            st.aws_auth.push(format!("secretsmanager {auth}"));
            assert_eq!(headers["content-type"], "application/x-amz-json-1.1");
            assert!(headers.contains_key("x-amz-date"));
            let id = body["SecretId"]
                .as_str()
                .or(body["Name"].as_str())
                .unwrap_or("")
                .to_string();
            match target_header.as_str() {
                "secretsmanager.PutSecretValue" => match st.aws_secrets.get_mut(&id) {
                    Some(s) => {
                        let version = body["ClientRequestToken"].as_str().unwrap().to_string();
                        assert!(version.len() >= 32);
                        s.0 = body["SecretString"].as_str().unwrap().into();
                        s.1 = version.clone();
                        aws_json(
                            200,
                            serde_json::json!({"ARN": "arn:x", "Name": id, "VersionId": version, "VersionStages": ["AWSCURRENT"]}),
                        )
                    }
                    None => aws_not_found("ResourceNotFoundException"),
                },
                "secretsmanager.CreateSecret" => {
                    let version = body["ClientRequestToken"].as_str().unwrap().to_string();
                    st.aws_secrets.insert(
                        id.clone(),
                        (
                            body["SecretString"].as_str().unwrap().into(),
                            version.clone(),
                            body["KmsKeyId"].as_str().map(String::from),
                        ),
                    );
                    aws_json(
                        200,
                        serde_json::json!({"ARN": "arn:x", "Name": id, "VersionId": version}),
                    )
                }
                "secretsmanager.DescribeSecret" => match st.aws_secrets.get(&id) {
                    Some((_, version, _)) => {
                        let mut stages = serde_json::Map::new();
                        stages.insert(version.clone(), serde_json::json!(["AWSCURRENT"]));
                        stages.insert(
                            "old-version-00000000000000000000".into(),
                            serde_json::json!(["AWSPREVIOUS"]),
                        );
                        aws_json(
                            200,
                            serde_json::json!({
                                "ARN": "arn:x",
                                "Name": id,
                                "LastChangedDate": 1523477145.729,
                                "VersionIdsToStages": stages,
                            }),
                        )
                    }
                    None => aws_not_found("ResourceNotFoundException"),
                },
                t => panic!("unexpected target {t}"),
            }
        }
        // ----- AWS Parameter Store (JSON 1.1) -----
        ("POST", "/ssm/") => {
            st.aws_auth.push(format!("ssm {auth}"));
            match target_header.as_str() {
                "AmazonSSM.PutParameter" => {
                    assert_eq!(body["Type"], "SecureString");
                    assert_eq!(body["Overwrite"], true);
                    let name = body["Name"].as_str().unwrap().to_string();
                    let value = body["Value"].as_str().unwrap().to_string();
                    if st.fail_param.as_deref() == Some(name.as_str()) {
                        return respond(
                            &mut conn,
                            400,
                            serde_json::json!({"__type": "TooManyUpdates", "message": "busy"}),
                        );
                    }
                    let e = st
                        .aws_params
                        .entry(name)
                        .or_insert((String::new(), 0, String::new()));
                    e.0 = value;
                    e.1 += 1;
                    e.2 = "SecureString".into();
                    let v = e.1;
                    aws_json(200, serde_json::json!({"Version": v, "Tier": "Standard"}))
                }
                "AmazonSSM.DescribeParameters" => {
                    let f = &body["ParameterFilters"][0];
                    assert_eq!(f["Key"], "Name");
                    assert_eq!(f["Option"], "Equals");
                    let name = f["Values"][0].as_str().unwrap();
                    let params: Vec<serde_json::Value> = st
                        .aws_params
                        .get(name)
                        .map(|(_, v, t)| {
                            serde_json::json!({"Name": name, "Type": t, "Version": v, "LastModifiedDate": 1521160696.821, "Tier": "Standard"})
                        })
                        .into_iter()
                        .collect();
                    aws_json(200, serde_json::json!({"Parameters": params}))
                }
                t => panic!("unexpected target {t}"),
            }
        }
        // ----- AWS IAM (query protocol, XML) -----
        ("POST", "/iam/") => {
            st.aws_auth.push(format!("iam {auth}"));
            assert!(
                headers["content-type"].starts_with("application/x-www-form-urlencoded"),
                "{headers:?}"
            );
            let f = form(&raw);
            assert_eq!(f["Version"], "2010-05-08");
            let user = f.get("UserName").cloned().unwrap_or_default();
            assert_eq!(user, "deploy-bot");
            match f["Action"].as_str() {
                "CreateAccessKey" => {
                    if st.iam_keys.values().filter(|k| k.0 == user).count() >= 2 {
                        xml(
                            409,
                            "<ErrorResponse><Error><Type>Sender</Type><Code>LimitExceeded</Code>\
                             <Message>Cannot exceed quota for AccessKeysPerUser: 2</Message></Error></ErrorResponse>"
                                .into(),
                        )
                    } else {
                        st.next += 1;
                        let id = format!("TESTAKID{:04}", st.next);
                        let secret = format!("iam-secret-{}", st.next);
                        st.iam_keys
                            .insert(id.clone(), (user.clone(), secret.clone(), "Active".into()));
                        xml(
                            200,
                            format!(
                                "<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey>\
                                 <UserName>{user}</UserName><AccessKeyId>{id}</AccessKeyId>\
                                 <Status>Active</Status><SecretAccessKey>{secret}\n      </SecretAccessKey>\
                                 </AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>"
                            ),
                        )
                    }
                }
                "DeleteAccessKey" => {
                    let id = f["AccessKeyId"].clone();
                    if st.iam_keys.remove(&id).is_some() {
                        st.iam_deleted.push(id);
                        xml(200, "<DeleteAccessKeyResponse/>".into())
                    } else {
                        xml(
                            404,
                            "<ErrorResponse><Error><Code>NoSuchEntity</Code><Message>no key</Message></Error></ErrorResponse>"
                                .into(),
                        )
                    }
                }
                "ListAccessKeys" => {
                    let members: String = st
                        .iam_keys
                        .iter()
                        .filter(|(_, k)| k.0 == user)
                        .map(|(id, k)| {
                            format!(
                                "<member><UserName>{user}</UserName><AccessKeyId>{id}</AccessKeyId><Status>{}</Status></member>",
                                k.2
                            )
                        })
                        .collect();
                    xml(
                        200,
                        format!(
                            "<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>{members}</AccessKeyMetadata>\
                             <IsTruncated>false</IsTruncated></ListAccessKeysResult></ListAccessKeysResponse>"
                        ),
                    )
                }
                a => panic!("unexpected action {a}"),
            }
        }
        // ----- GitLab -----
        (m, p) if p.starts_with("/gitlab/projects/acme%2Fshop/variables") => {
            assert_eq!(headers["private-token"], "gitlab-test-token");
            let scope_q = query
                .strip_prefix("filter%5Benvironment_scope%5D=")
                .unwrap_or("")
                .replace("%2A", "*");
            let key = p.strip_prefix("/gitlab/projects/acme%2Fshop/variables/");
            match (m, key) {
                ("PUT", Some(key)) => {
                    let k = (key.to_string(), scope_q);
                    match st.gitlab.get_mut(&k) {
                        Some(v) => {
                            assert_eq!(body["raw"], true);
                            v.0 = body["value"].as_str().unwrap().into();
                            v.2 = body["protected"].as_bool().unwrap();
                            if let Some(masked) = body["masked"].as_bool() {
                                v.1 = masked;
                            }
                            (200, serde_json::json!({"key": key}))
                        }
                        None => (
                            404,
                            serde_json::json!({"message": "404 Variable Not Found"}),
                        ),
                    }
                }
                ("POST", None) => {
                    assert_eq!(body["raw"], true);
                    let hidden = body["masked_and_hidden"].as_bool().unwrap_or(false);
                    st.gitlab.insert(
                        (
                            body["key"].as_str().unwrap().into(),
                            body["environment_scope"].as_str().unwrap().into(),
                        ),
                        (
                            body["value"].as_str().unwrap().into(),
                            hidden || body["masked"].as_bool().unwrap(),
                            body["protected"].as_bool().unwrap(),
                            hidden,
                        ),
                    );
                    (201, serde_json::json!({"key": body["key"]}))
                }
                ("GET", Some(key)) => match st.gitlab.get(&(key.to_string(), scope_q.clone())) {
                    Some((value, masked, protected, hidden)) => (
                        200,
                        serde_json::json!({
                            "key": key,
                            "value": if *hidden { serde_json::Value::Null } else { value.clone().into() },
                            "masked": masked,
                            "protected": protected,
                            "hidden": hidden,
                            "environment_scope": scope_q.replace("%2A", "*"),
                        }),
                    ),
                    None => (
                        404,
                        serde_json::json!({"message": "404 Variable Not Found"}),
                    ),
                },
                _ => (404, serde_json::json!({"message": "no route"})),
            }
        }
        // ----- Fly.io -----
        (m, p) if p.starts_with("/v1/apps/shop-api/secrets/") => {
            assert_eq!(bearer, "fly-test-token");
            let name = p.rsplit('/').next().unwrap().to_string();
            match m {
                "POST" => {
                    st.next += 1;
                    let digest = format!("d{:04}", st.next);
                    st.fly.insert(
                        name.clone(),
                        (body["value"].as_str().unwrap().into(), digest.clone()),
                    );
                    (
                        201,
                        serde_json::json!({"name": name, "digest": digest, "value": body["value"], "version": st.next}),
                    )
                }
                "GET" => match st.fly.get(&name) {
                    Some((_, digest)) => (
                        200,
                        serde_json::json!({"name": name, "digest": digest, "created_at": "2026-11-11T00:00:00Z"}),
                    ),
                    None => (404, serde_json::json!({"error": "secret not found"})),
                },
                _ => (404, serde_json::json!({"error": "no route"})),
            }
        }
        // ----- OpenAI Admin API -----
        (
            "POST",
            "/openai/organization/projects/proj_shop/service_accounts/svc_acct_1/api_keys",
        ) => {
            assert_eq!(bearer, "openai-admin-test");
            st.next += 1;
            let id = format!("key_{}", st.next);
            let value = format!("openai-new-{}", st.next);
            st.openai_keys.insert(id.clone(), value.clone());
            st.openai_bodies.push(body.clone());
            (
                200,
                serde_json::json!({"object": "organization.project.service_account.api_key", "value": value, "name": body["name"], "created_at": 1711471533, "id": id}),
            )
        }
        (m, p) if p.starts_with("/openai/organization/projects/proj_shop/api_keys/") => {
            assert_eq!(bearer, "openai-admin-test");
            let id = p.rsplit('/').next().unwrap().to_string();
            match (m, st.openai_keys.contains_key(&id)) {
                ("GET", true) => (
                    200,
                    serde_json::json!({"object": "organization.project.api_key", "id": id, "redacted_value": "x...y"}),
                ),
                ("DELETE", true) => {
                    st.openai_keys.remove(&id);
                    st.openai_deleted.push(id.clone());
                    (
                        200,
                        serde_json::json!({"object": "organization.project.api_key.deleted", "id": id, "deleted": true}),
                    )
                }
                _ => (404, serde_json::json!({"error": {"message": "not found"}})),
            }
        }
        _ => (
            404,
            serde_json::json!({"message": format!("no route {method} {path}")}),
        ),
    };
    drop(st);
    respond(&mut conn, status, answer)
}

fn respond(conn: &mut TcpStream, status: u16, answer: serde_json::Value) {
    let text = match answer {
        serde_json::Value::String(xml) => xml,
        other => other.to_string(),
    };
    let _ = write!(
        conn,
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = conn.flush();
}

#[test]
fn cloudflare_tokens_and_workers_secrets() {
    let mock = Mock::start();
    let env = Env::new();
    env.setup();
    env.ok(&["add", "accounts/cloudflare"], "");
    env.ok(
        &["set", "accounts/cloudflare#admin", "--stdin"],
        "cf-admin-token",
    );
    // A token made in the dashboard: Cemí only has its value.
    let policies = serde_json::json!([{
        "id": "pol-1",
        "effect": "allow",
        "resources": {"com.cloudflare.api.account.zone.*": "*"},
        "permission_groups": [{"id": "grp-dns-edit", "name": "DNS Write"}],
    }]);
    mock.state.lock().unwrap().cf_tokens.insert(
        "orig".into(),
        CfToken {
            value: "cf-first-token".into(),
            status: "active".into(),
            policies,
        },
    );
    env.ok(&["add", "cf"], "");
    env.ok(
        &["set", "cf#token", "-e", "dev", "--stdin"],
        "cf-first-token",
    );
    let url = mock.url.as_str();
    env.ok(
        &[
            "origin",
            "set",
            "cf#token",
            "-e",
            "dev",
            "cloudflare-token",
            "--token",
            "accounts/cloudflare#admin",
            "--name",
            "shop deploy",
            "--api-url",
            url,
        ],
        "",
    );
    env.ok(
        &[
            "dest",
            "add",
            "cf#token",
            "-e",
            "dev",
            "cloudflare-worker",
            "--account",
            ACCOUNT,
            "--script",
            "shop-api",
            "--name",
            "CF_TOKEN",
            "--token",
            "accounts/cloudflare#admin",
            "--api-url",
            url,
        ],
        "",
    );
    // Before anything is sent the secret is missing; after, it cannot be compared.
    let out = both(&env, &["push"]);
    assert!(out.contains("Cloudflare Worker shop-api"), "{out}");
    assert_eq!(
        mock.state.lock().unwrap().cf_secrets["CF_TOKEN"],
        "cf-first-token"
    );
    let out = env.ok(&["check", "cf#token"], "");
    assert!(out.contains("cannot be checked"), "{out}");

    // Rotation: a new token with the same permissions, then the old one goes.
    env.ok(&["rotate", "cf#token", "-e", "dev", "--yes"], "");
    {
        let st = mock.state.lock().unwrap();
        let created = &st.cf_created_bodies[0];
        assert!(
            created["name"]
                .as_str()
                .unwrap()
                .starts_with("shop deploy ")
        );
        assert_eq!(
            created["policies"][0],
            serde_json::json!({
                "effect": "allow",
                "resources": {"com.cloudflare.api.account.zone.*": "*"},
                "permission_groups": [{"id": "grp-dns-edit"}],
            })
        );
        assert_eq!(created["condition"]["request_ip"]["in"][0], "192.0.2.0/24");
        assert_eq!(st.cf_secrets["CF_TOKEN"], "cf-new-token-1");
        // Found by asking Cloudflare which token the old value is.
        assert_eq!(st.cf_deleted, ["orig"]);
        assert!(!st.cf_tokens.contains_key("orig"));
    }
    // The second rotation copies the token the first one made, and deletes it by id.
    env.ok(&["rotate", "cf#token", "-e", "dev", "--yes"], "");
    {
        let st = mock.state.lock().unwrap();
        assert_eq!(st.cf_secrets["CF_TOKEN"], "cf-new-token-2");
        assert_eq!(st.cf_deleted, ["orig", "cf1"]);
        assert_eq!(
            st.cf_created_bodies[1]["policies"][0]["permission_groups"][0]["id"],
            "grp-dns-edit"
        );
    }
    // The token is gone at Cloudflare: check says so.
    mock.state.lock().unwrap().cf_tokens.clear();
    let (code, out, _) = env.run(&["check", "cf#token"], "");
    assert_eq!(code, 1);
    assert!(out.contains("no longer exists"), "{out}");
    // A Worker secret deleted by hand.
    mock.state.lock().unwrap().cf_secrets.clear();
    let (_, out, _) = env.run(&["check", "cf#token"], "");
    assert!(out.contains("missing at the destination"), "{out}");
    // Bad options are refused before anything is saved.
    let (code, _, err) = env.run(
        &[
            "dest",
            "add",
            "cf#token",
            "cloudflare-worker",
            "--account",
            "acme",
            "--script",
            "shop-api",
            "--name",
            "X",
            "--token",
            "accounts/cloudflare#admin",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("account id"), "{err}");
}

#[test]
fn resend_keys_to_netlify_and_vercel() {
    let mock = Mock::start();
    let env = Env::new();
    env.setup();
    env.ok(&["add", "accounts/resend"], "");
    env.ok(&["set", "accounts/resend#admin", "--stdin"], "re_admin_key");
    env.ok(&["add", "accounts/netlify"], "");
    env.ok(&["set", "accounts/netlify#token", "--stdin"], "nfp_test");
    env.ok(&["add", "accounts/vercel"], "");
    env.ok(&["set", "accounts/vercel#token", "--stdin"], "vc_test");
    env.ok(&["add", "mail"], "");
    env.ok(&["set", "mail#key", "-e", "dev", "--stdin"], "re_first_key");
    let url = mock.url.as_str();
    env.ok(
        &[
            "origin",
            "set",
            "mail#key",
            "-e",
            "dev",
            "resend-key",
            "--token",
            "accounts/resend#admin",
            "--name",
            "shop",
            "--domain",
            "dom-1",
            "--api-url",
            url,
        ],
        "",
    );
    env.ok(
        &[
            "dest",
            "add",
            "mail#key",
            "-e",
            "dev",
            "netlify",
            "--account",
            "acme",
            "--site",
            "site-1",
            "--key",
            "RESEND_API_KEY",
            "--token",
            "accounts/netlify#token",
            "--api-url",
            url,
        ],
        "",
    );
    env.ok(
        &[
            "dest",
            "add",
            "mail#key",
            "-e",
            "dev",
            "vercel",
            "--project",
            "shop",
            "--team",
            "team_1",
            "--key",
            "RESEND_API_KEY",
            "--token",
            "accounts/vercel#token",
            "--api-url",
            url,
        ],
        "",
    );
    env.ok(&["push"], "");
    {
        let st = mock.state.lock().unwrap();
        let (secret, scopes, values) = &st.netlify["RESEND_API_KEY"];
        assert!(*secret);
        assert_eq!(
            *scopes,
            serde_json::json!(["builds", "functions", "runtime"])
        );
        assert_eq!(values["production"], "re_first_key");
        let (value, kind, _) = &st.vercel["RESEND_API_KEY"];
        assert_eq!(value, "re_first_key");
        assert_eq!(kind, "sensitive");
        assert!(
            st.auth
                .iter()
                .filter(|a| a.contains("/v10/"))
                .all(|a| a.ends_with("Bearer vc_test"))
        );
    }
    let out = env.ok(&["check", "mail#key"], "");
    assert_eq!(out.matches("up to date").count(), 2, "{out}");

    // Someone changes the variables in the dashboards.
    mock.state.lock().unwrap().netlify_updated += 7;
    mock.state
        .lock()
        .unwrap()
        .vercel
        .get_mut("RESEND_API_KEY")
        .unwrap()
        .2 += 60_000;
    let (code, out, _) = env.run(&["check", "mail#key"], "");
    assert_eq!(code, 1);
    assert_eq!(out.matches("changed outside").count(), 2, "{out}");

    // Rotation: Resend makes the key, both variables get it (Netlify by
    // updating the existing variable).
    let (_, _, err) = env.run(&["rotate", "mail#key", "-e", "dev", "--yes"], "");
    assert!(err.contains("Resend dashboard"), "{err}");
    {
        let st = mock.state.lock().unwrap();
        assert_eq!(st.resend_bodies[0]["permission"], "sending_access");
        assert_eq!(st.resend_bodies[0]["domain_id"], "dom-1");
        assert!(
            st.resend_bodies[0]["name"]
                .as_str()
                .unwrap()
                .starts_with("shop ")
        );
        assert_eq!(st.netlify["RESEND_API_KEY"].2["production"], "re_new_1");
        assert_eq!(st.vercel["RESEND_API_KEY"].0, "re_new_1");
    }
    env.ok(&["rotate", "mail#key", "-e", "dev", "--yes"], "");
    assert_eq!(mock.state.lock().unwrap().resend_deleted, ["rk1"]);
    let out = env.ok(&["check", "mail#key"], "");
    assert_eq!(out.matches("up to date").count(), 2, "{out}");
    mock.state.lock().unwrap().resend_keys.clear();
    let (code, out, _) = env.run(&["check", "mail#key"], "");
    assert_eq!(code, 1);
    assert!(out.contains("no longer exists"), "{out}");
    // Option checks.
    let (code, _, err) = env.run(
        &[
            "dest",
            "add",
            "mail#key",
            "vercel",
            "--project",
            "shop",
            "--key",
            "K",
            "--target",
            "prod",
            "--token",
            "accounts/vercel#token",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("--target"), "{err}");
    let (code, _, err) = env.run(
        &[
            "origin",
            "set",
            "mail#key",
            "resend-key",
            "--token",
            "accounts/resend#admin",
            "--permission",
            "full_access",
            "--domain",
            "dom-1",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("sending_access"), "{err}");
}

/// A stand-in for ssh: checks the options, logs the arguments, and runs the
/// remote command with the local `sh` (on Windows, the one from Git).
fn fake_ssh(dir: &Path) -> (Vec<String>, std::path::PathBuf) {
    let log = dir.join("ssh-args.log");
    let script = dir.join("fake-ssh.sh");
    std::fs::write(
        &script,
        format!(
            "printf '%s\\n' \"$*\" >> '{}'\n\
             case \" $* \" in *' BatchMode=yes '*) ;; *) exit 9 ;; esac\n\
             while [ \"$#\" -gt 0 ] && [ \"$1\" != \"--\" ]; do shift; done\n\
             shift\n\
             [ \"$1\" = down ] && exit 255\n\
             shift\n\
             exec sh -c \"$*\"\n",
            slash(&log)
        ),
    )
    .unwrap();
    (vec!["sh".into(), slash(&script)], log)
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

#[test]
fn dotenv_on_a_server_over_ssh() {
    let env = Env::new();
    env.setup();
    let server = env.project.parent().unwrap().join("server");
    std::fs::create_dir_all(server.join("app")).unwrap();
    let file = server.join("app").join(".env");
    std::fs::write(&file, "# app settings\nOTHER=keep me\nAPI_KEY=old\n").unwrap();
    let marker = server.join("restarted");
    let (program, log) = fake_ssh(env.project.parent().unwrap());

    env.ok(&["add", "api"], "");
    env.ok(
        &["set", "api#key", "-e", "dev", "--stdin"],
        "it's a \"secret\" $value",
    );
    let file_arg = slash(&file);
    let restart = format!("echo done > '{}'", slash(&marker));
    let mut args = vec![
        "dest",
        "add",
        "api#key",
        "-e",
        "dev",
        "ssh",
        "--host",
        "deploy@web-1",
        "--port",
        "2222",
        "--file",
        &file_arg,
        "--key",
        "API_KEY",
        "--restart",
        &restart,
    ];
    for p in &program {
        args.extend(["--ssh-program", p.as_str()]);
    }
    env.ok(&args, "");
    let out = both(&env, &["push"]);
    assert!(out.contains("deploy@web-1:"), "{out}");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(
        text.starts_with("# app settings\nOTHER=keep me\n"),
        "{text}"
    );
    assert_eq!(
        cemi::dotenv::get(&text, "API_KEY").unwrap().as_deref(),
        Some("it's a \"secret\" $value")
    );
    assert!(marker.exists());
    // The value never appears in the ssh command line.
    let logged = std::fs::read_to_string(&log).unwrap();
    assert!(logged.contains("-p 2222 -- deploy@web-1"), "{logged}");
    assert!(!logged.contains("secret"), "{logged}");

    let out = env.ok(&["check", "api#key"], "");
    assert!(out.contains("up to date"), "{out}");
    // Changed on the server by hand.
    std::fs::write(&file, "OTHER=keep me\nAPI_KEY=typed-by-hand\n").unwrap();
    let (code, out, _) = env.run(&["check", "api#key"], "");
    assert_eq!(code, 1);
    assert!(out.contains("changed outside"), "{out}");
    // Gone: push writes it again (and creates the file).
    std::fs::remove_file(&file).unwrap();
    let (_, out, _) = env.run(&["check", "api#key"], "");
    assert!(out.contains("missing at the destination"), "{out}");
    env.ok(&["push", "api#key"], "");
    let text = std::fs::read_to_string(&file).unwrap();
    assert_eq!(
        cemi::dotenv::get(&text, "API_KEY").unwrap().as_deref(),
        Some("it's a \"secret\" $value")
    );

    // A server that cannot be reached.
    let mut args = vec![
        "dest",
        "add",
        "api#key",
        "-e",
        "dev",
        "ssh",
        "--host",
        "down",
        "--file",
        "/srv/.env",
        "--key",
        "API_KEY",
    ];
    for p in &program {
        args.extend(["--ssh-program", p.as_str()]);
    }
    env.ok(&args, "");
    let (code, out, err) = env.run(&["push", "api#key"], "");
    assert_ne!(code, 0);
    let all = format!("{out}{err}");
    assert!(all.contains("cannot connect to down"), "{all}");

    // Hosts that look like ssh options are refused.
    let (code, _, err) = env.run(
        &[
            "dest",
            "add",
            "api#key",
            "ssh",
            "--host=-oProxyCommand=x",
            "--file",
            "/srv/.env",
            "--key",
            "API_KEY",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("ssh host"), "{err}");
}

/// Fake AWS credentials for the mock (not in any real key format).
fn aws_account(env: &Env) {
    env.ok(&["add", "accounts/aws"], "");
    env.ok(
        &["set", "accounts/aws#access_key_id", "--stdin"],
        "TESTKEYID0001",
    );
    env.ok(
        &["set", "accounts/aws#secret_access_key", "--stdin"],
        "test-secret-access-key",
    );
}

const AWS_CREDS: [&str; 4] = [
    "--access-key-id",
    "accounts/aws#access_key_id",
    "--secret-access-key",
    "accounts/aws#secret_access_key",
];

#[test]
fn aws_iam_key_to_secrets_manager_and_parameter_store() {
    let mock = Mock::start();
    let env = Env::new();
    env.setup();
    aws_account(&env);
    // A key made in the AWS console: Cemí has its secret and, in another
    // field, its id.
    mock.state.lock().unwrap().iam_keys.insert(
        "TESTAKID0000".into(),
        ("deploy-bot".into(), "iam-secret-0".into(), "Active".into()),
    );
    env.ok(&["add", "deploy"], "");
    env.ok(
        &["set", "deploy#secret_access_key", "-e", "dev", "--stdin"],
        "iam-secret-0",
    );
    env.ok(
        &["set", "deploy#access_key_id", "-e", "dev", "--stdin"],
        "TESTAKID0000",
    );
    let iam = format!("{}/iam", mock.url);
    let sm = format!("{}/sm", mock.url);
    let ssm = format!("{}/ssm", mock.url);
    let mut args = vec![
        "origin",
        "set",
        "deploy#secret_access_key",
        "-e",
        "dev",
        "aws-access-key",
        "--user",
        "deploy-bot",
        "--id-field",
        "access_key_id",
        "--api-url",
        &iam,
    ];
    args.extend(AWS_CREDS);
    env.ok(&args, "");
    let mut args = vec![
        "dest",
        "add",
        "deploy#secret_access_key",
        "-e",
        "dev",
        "aws-secret",
        "--secret-id",
        "shop/deploy",
        "--region",
        "us-east-1",
        "--kms-key",
        "alias/shop",
        "--api-url",
        &sm,
    ];
    args.extend(AWS_CREDS);
    env.ok(&args, "");
    for (field, name) in [
        ("deploy#secret_access_key", "/shop/deploy/secret"),
        ("deploy#access_key_id", "/shop/deploy/id"),
    ] {
        let mut args = vec![
            "dest",
            "add",
            field,
            "-e",
            "dev",
            "aws-parameter",
            "--name",
            name,
            "--region",
            "eu-west-1",
            "--api-url",
            &ssm,
        ];
        args.extend(AWS_CREDS);
        env.ok(&args, "");
    }

    // The secret does not exist yet: Cemí creates it.
    let out = both(&env, &["push"]);
    assert!(out.contains("AWS Secrets Manager (us-east-1)"), "{out}");
    {
        let st = mock.state.lock().unwrap();
        let (value, _, kms) = &st.aws_secrets["shop/deploy"];
        assert_eq!(value, "iam-secret-0");
        assert_eq!(kms.as_deref(), Some("alias/shop"));
        assert_eq!(st.aws_params["/shop/deploy/secret"].0, "iam-secret-0");
        assert_eq!(st.aws_params["/shop/deploy/id"].0, "TESTAKID0000");
        // Every call is signed, for its own service and region.
        assert!(!st.aws_auth.is_empty());
        for a in &st.aws_auth {
            let (service, auth) = a.split_once(' ').unwrap();
            let region = if service == "ssm" {
                "eu-west-1"
            } else {
                "us-east-1"
            };
            assert!(
                auth.starts_with("AWS4-HMAC-SHA256 Credential=TESTKEYID0001/"),
                "{auth}"
            );
            let scope = format!(
                "/{region}/{service}/aws4_request, SignedHeaders=content-type;host;x-amz-date"
            );
            assert!(auth.contains(&scope), "{auth}");
            assert!(!auth.contains("test-secret-access-key"));
        }
        // Values only travel in bodies.
        assert!(st.auth.iter().all(|a| !a.contains("iam-secret")));
    }
    let out = env.ok(&["check", "deploy#secret_access_key"], "");
    assert_eq!(out.matches("up to date").count(), 2, "{out}");

    // Someone stores new values in the AWS console.
    {
        let mut st = mock.state.lock().unwrap();
        st.aws_secrets.get_mut("shop/deploy").unwrap().1 =
            "changed-by-hand-0000000000000000".into();
        st.aws_params.get_mut("/shop/deploy/secret").unwrap().1 += 1;
    }
    let (code, out, _) = env.run(&["check", "deploy#secret_access_key"], "");
    assert_eq!(code, 1);
    assert_eq!(out.matches("changed outside").count(), 2, "{out}");
    assert!(out.contains("AWSCURRENT"), "{out}");
    assert!(out.contains("version 2"), "{out}");
    env.ok(
        &["push", "--force", "deploy#secret_access_key", "-e", "dev"],
        "",
    );

    // The plan names the destination of the id too.
    let (_, plan, _) = env.run(&["rotate", "deploy#secret_access_key", "-e", "dev"], "n\n");
    assert!(plan.contains("the new key's id"), "{plan}");

    // Rotation: IAM makes a key; its secret and its id go out together; the
    // old key (known by the id field) is deleted.
    env.ok(
        &["rotate", "deploy#secret_access_key", "-e", "dev", "--yes"],
        "",
    );
    {
        let st = mock.state.lock().unwrap();
        assert_eq!(st.aws_secrets["shop/deploy"].0, "iam-secret-1");
        assert_eq!(st.aws_params["/shop/deploy/secret"].0, "iam-secret-1");
        assert_eq!(st.aws_params["/shop/deploy/id"].0, "TESTAKID0001");
        assert_eq!(st.iam_deleted, ["TESTAKID0000"]);
    }
    let out = env.ok(&["check", "deploy#access_key_id"], "");
    assert!(out.contains("up to date"), "{out}");
    // The second rotation deletes the key the first one made, by its id.
    env.ok(
        &["rotate", "deploy#secret_access_key", "-e", "dev", "--yes"],
        "",
    );
    {
        let st = mock.state.lock().unwrap();
        assert_eq!(st.iam_deleted, ["TESTAKID0000", "TESTAKID0001"]);
        assert_eq!(st.aws_params["/shop/deploy/id"].0, "TESTAKID0002");
    }
    let out = env.ok(&["check", "deploy#secret_access_key"], "");
    assert_eq!(out.matches("up to date").count(), 2, "{out}");

    // The id cannot be written: everything goes back, and the unused new key
    // is deleted.
    mock.state.lock().unwrap().fail_param = Some("/shop/deploy/id".into());
    let (code, _, err) = env.run(
        &["rotate", "deploy#secret_access_key", "-e", "dev", "--yes"],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("TooManyUpdates"), "{err}");
    {
        let mut st = mock.state.lock().unwrap();
        assert_eq!(st.aws_secrets["shop/deploy"].0, "iam-secret-2");
        assert_eq!(st.aws_params["/shop/deploy/secret"].0, "iam-secret-2");
        assert_eq!(st.aws_params["/shop/deploy/id"].0, "TESTAKID0002");
        assert_eq!(
            st.iam_deleted.last().map(String::as_str),
            Some("TESTAKID0003")
        );
        st.fail_param = None;
    }
    let out = env.ok(&["check", "deploy#access_key_id"], "");
    assert!(out.contains("up to date"), "{out}");
    let out = env.ok(&["check", "deploy#secret_access_key"], "");
    assert_eq!(out.matches("up to date").count(), 2, "{out}");

    // A user with two keys already: the rotation stops before anything changes.
    mock.state.lock().unwrap().iam_keys.insert(
        "TESTAKID9999".into(),
        ("deploy-bot".into(), "spare".into(), "Active".into()),
    );
    let (code, _, err) = env.run(
        &["rotate", "deploy#secret_access_key", "-e", "dev", "--yes"],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("two access keys"), "{err}");
    assert_eq!(
        mock.state.lock().unwrap().aws_params["/shop/deploy/id"].0,
        "TESTAKID0002"
    );

    // A key made inactive in the console no longer counts as alive.
    mock.state
        .lock()
        .unwrap()
        .iam_keys
        .get_mut("TESTAKID0002")
        .unwrap()
        .2 = "Inactive".into();
    let (code, out, _) = env.run(&["check", "deploy#secret_access_key"], "");
    assert_eq!(code, 1);
    assert!(out.contains("no longer exists"), "{out}");
    // A deleted secret is missing.
    mock.state.lock().unwrap().aws_secrets.clear();
    let (_, out, _) = env.run(&["check", "deploy#secret_access_key"], "");
    assert!(out.contains("missing at the destination"), "{out}");

    // Option checks.
    let mut args = vec![
        "dest",
        "add",
        "deploy#secret_access_key",
        "aws-parameter",
        "--name",
        "/aws/reserved",
        "--region",
        "us-east-1",
    ];
    args.extend(AWS_CREDS);
    let (code, _, err) = env.run(&args, "");
    assert_ne!(code, 0);
    assert!(err.contains("\"aws\""), "{err}");
    let mut args = vec![
        "dest",
        "add",
        "deploy#secret_access_key",
        "aws-secret",
        "--secret-id",
        "shop",
        "--region",
        "useast1",
    ];
    args.extend(AWS_CREDS);
    let (code, _, err) = env.run(&args, "");
    assert_ne!(code, 0);
    assert!(err.contains("AWS region"), "{err}");
    let mut args = vec![
        "origin",
        "set",
        "deploy#secret_access_key",
        "aws-access-key",
        "--id-field",
        "secret_access_key",
    ];
    args.extend(AWS_CREDS);
    let (code, _, err) = env.run(&args, "");
    assert_ne!(code, 0);
    assert!(err.contains("--id-field"), "{err}");
}

#[test]
fn openai_keys_to_gitlab_and_fly() {
    let mock = Mock::start();
    let env = Env::new();
    env.setup();
    env.ok(&["add", "accounts/openai"], "");
    env.ok(
        &["set", "accounts/openai#admin", "--stdin"],
        "openai-admin-test",
    );
    env.ok(&["add", "accounts/gitlab"], "");
    env.ok(
        &["set", "accounts/gitlab#token", "--stdin"],
        "gitlab-test-token",
    );
    env.ok(&["add", "accounts/fly"], "");
    env.ok(&["set", "accounts/fly#token", "--stdin"], "fly-test-token");
    env.ok(&["add", "ai"], "");
    env.ok(
        &["set", "ai#key", "-e", "dev", "--stdin"],
        "openai-first-key",
    );
    let openai = format!("{}/openai", mock.url);
    let gitlab = format!("{}/gitlab", mock.url);
    let url = mock.url.as_str();
    env.ok(
        &[
            "origin",
            "set",
            "ai#key",
            "-e",
            "dev",
            "openai-key",
            "--project",
            "proj_shop",
            "--service-account",
            "svc_acct_1",
            "--token",
            "accounts/openai#admin",
            "--name",
            "shop",
            "--api-url",
            &openai,
        ],
        "",
    );
    env.ok(
        &[
            "dest",
            "add",
            "ai#key",
            "-e",
            "dev",
            "gitlab",
            "--project",
            "acme/shop",
            "--key",
            "OPENAI_API_KEY",
            "--environment-scope",
            "production",
            "--protected",
            "--token",
            "accounts/gitlab#token",
            "--api-url",
            &gitlab,
        ],
        "",
    );
    env.ok(
        &[
            "dest",
            "add",
            "ai#key",
            "-e",
            "dev",
            "fly",
            "--app",
            "shop-api",
            "--name",
            "OPENAI_API_KEY",
            "--token",
            "accounts/fly#token",
            "--api-url",
            url,
        ],
        "",
    );
    env.ok(&["push"], "");
    let gl_key = ("OPENAI_API_KEY".to_string(), "production".to_string());
    {
        let st = mock.state.lock().unwrap();
        let (value, masked, protected, hidden) = &st.gitlab[&gl_key];
        assert_eq!(value, "openai-first-key");
        assert!(*masked && *protected && !*hidden);
        assert_eq!(st.fly["OPENAI_API_KEY"].0, "openai-first-key");
        assert!(st.auth.iter().all(|a| !a.contains("openai-first-key")));
    }
    let out = env.ok(&["check", "ai#key"], "");
    assert_eq!(out.matches("up to date").count(), 2, "{out}");

    // Changed by hand in both places. Cemí never shows what GitLab returned.
    {
        let mut st = mock.state.lock().unwrap();
        st.gitlab.get_mut(&gl_key).unwrap().0 = "typed-in-gitlab".into();
        st.fly.get_mut("OPENAI_API_KEY").unwrap().1 = "d-by-hand".into();
    }
    let (code, out, err) = env.run(&["check", "ai#key"], "");
    assert_eq!(code, 1);
    assert_eq!(out.matches("changed outside").count(), 2, "{out}");
    assert!(out.contains("another value"), "{out}");
    assert!(!format!("{out}{err}").contains("typed-in-gitlab"));

    // Rotation: a new key of the same service account goes to both. The
    // first key was made in the dashboard, so it is deleted there by hand.
    let (code, _, err) = env.run(&["rotate", "ai#key", "-e", "dev", "--yes"], "");
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("OpenAI dashboard"), "{err}");
    {
        let st = mock.state.lock().unwrap();
        assert!(
            st.openai_bodies[0]["name"]
                .as_str()
                .unwrap()
                .starts_with("shop ")
        );
        assert!(st.gitlab[&gl_key].0.starts_with("openai-new-"));
        assert_eq!(st.fly["OPENAI_API_KEY"].0, st.gitlab[&gl_key].0);
    }
    env.ok(&["rotate", "ai#key", "-e", "dev", "--yes"], "");
    assert_eq!(mock.state.lock().unwrap().openai_deleted.len(), 1);
    let out = env.ok(&["check", "ai#key"], "");
    assert_eq!(out.matches("up to date").count(), 2, "{out}");
    mock.state.lock().unwrap().openai_keys.clear();
    let (code, out, _) = env.run(&["check", "ai#key"], "");
    assert_eq!(code, 1);
    assert!(out.contains("no longer exists"), "{out}");

    // GitLab masks only values of 8 characters or more, without spaces.
    env.ok(&["add", "short"], "");
    env.ok(&["set", "short#pin", "-e", "dev", "--stdin"], "1234");
    env.ok(
        &[
            "dest",
            "add",
            "short#pin",
            "-e",
            "dev",
            "gitlab",
            "--project",
            "acme/shop",
            "--key",
            "PIN",
            "--token",
            "accounts/gitlab#token",
            "--api-url",
            &gitlab,
        ],
        "",
    );
    let (code, out, err) = env.run(&["push", "short#pin"], "");
    assert_ne!(code, 0);
    let all = format!("{out}{err}");
    assert!(all.contains("--no-mask"), "{all}");
    // Hidden variables: Cemí can only see that they exist.
    env.ok(
        &[
            "dest",
            "add",
            "ai#key",
            "-e",
            "dev",
            "gitlab",
            "--project",
            "acme/shop",
            "--key",
            "OPENAI_HIDDEN",
            "--hidden",
            "--token",
            "accounts/gitlab#token",
            "--api-url",
            &gitlab,
        ],
        "",
    );
    env.ok(&["push", "ai#key"], "");
    {
        let st = mock.state.lock().unwrap();
        let (_, masked, _, hidden) = &st.gitlab[&("OPENAI_HIDDEN".to_string(), "*".to_string())];
        assert!(*masked && *hidden);
    }
    // Option checks.
    let (code, _, err) = env.run(
        &[
            "dest",
            "add",
            "ai#key",
            "gitlab",
            "--project",
            "acme/shop",
            "--key",
            "K",
            "--hidden",
            "--no-mask",
            "--token",
            "accounts/gitlab#token",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("always masked"), "{err}");
    let (code, _, err) = env.run(
        &[
            "dest",
            "add",
            "ai#key",
            "fly",
            "--app",
            "Shop_API",
            "--name",
            "K",
            "--token",
            "accounts/fly#token",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("Fly app"), "{err}");
    let (code, _, err) = env.run(
        &[
            "origin",
            "set",
            "ai#key",
            "openai-key",
            "--project",
            "shop",
            "--service-account",
            "svc_acct_1",
            "--token",
            "accounts/openai#admin",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("proj_"), "{err}");
}

/// A key that rotates itself: its own fields sign the IAM calls. The old key
/// signs the creation and the new one the deletion of the old.
#[test]
fn aws_iam_key_rotates_itself() {
    let mock = Mock::start();
    let env = Env::new();
    env.setup();
    mock.state.lock().unwrap().iam_keys.insert(
        "TESTAKID0000".into(),
        ("deploy-bot".into(), "iam-secret-0".into(), "Active".into()),
    );
    env.ok(&["add", "bot"], "");
    env.ok(
        &["set", "bot#secret", "-e", "dev", "--stdin"],
        "iam-secret-0",
    );
    env.ok(&["set", "bot#id", "-e", "dev", "--stdin"], "TESTAKID0000");
    let iam = format!("{}/iam", mock.url);
    env.ok(
        &[
            "origin",
            "set",
            "bot#secret",
            "-e",
            "dev",
            "aws-access-key",
            "--user",
            "deploy-bot",
            "--access-key-id",
            "bot#id",
            "--secret-access-key",
            "bot#secret",
            "--id-field",
            "id",
            "--api-url",
            &iam,
        ],
        "",
    );
    env.ok(&["rotate", "bot#secret", "-e", "dev", "--yes"], "");
    let st = mock.state.lock().unwrap();
    assert_eq!(st.iam_deleted, ["TESTAKID0000"]);
    let signers: Vec<&str> = st
        .aws_auth
        .iter()
        .map(|a| {
            a.split("Credential=")
                .nth(1)
                .unwrap()
                .split('/')
                .next()
                .unwrap()
        })
        .collect();
    assert_eq!(signers.first(), Some(&"TESTAKID0000"));
    assert_eq!(signers.last(), Some(&"TESTAKID0001"));
}
