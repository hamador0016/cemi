//! End-to-end tests of the v0.4 connectors: Cloudflare, Resend, Netlify and
//! Vercel against a local mock of their APIs, and `.env` files over SSH with a
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
    next: u32,
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
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':').unwrap();
        match k.to_ascii_lowercase().as_str() {
            "content-length" => length = v.trim().parse().unwrap(),
            "authorization" => auth = v.trim().to_string(),
            _ => {}
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
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
        _ => (
            404,
            serde_json::json!({"message": format!("no route {method} {path}")}),
        ),
    };
    drop(st);
    let text = answer.to_string();
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
