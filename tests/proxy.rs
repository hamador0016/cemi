//! The credential proxy: `cemi api`, the MCP `call_api` tool, and AI runs in
//! protected environments, against a local mock API.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use common::*;

const KEY: &str = "sk_live_REALKEY_123456789";

#[derive(Default)]
struct Seen {
    /// (method, target, authorization) of every request that arrived.
    requests: Vec<(String, String, String)>,
}

struct MockApi {
    url: String,
    seen: Arc<Mutex<Seen>>,
}

impl MockApi {
    fn start() -> MockApi {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Seen::default()));
        let s = seen.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let s = s.clone();
                std::thread::spawn(move || answer(conn, &s));
            }
        });
        MockApi { url, seen }
    }

    fn requests(&self) -> Vec<(String, String, String)> {
        self.seen.lock().unwrap().requests.clone()
    }
}

/// Answers every request with JSON that echoes the path and the
/// Authorization header, so tests can see that the proxy hides the key.
fn answer(mut conn: TcpStream, seen: &Arc<Mutex<Seen>>) {
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
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            match k.to_ascii_lowercase().as_str() {
                "content-length" => length = v.trim().parse().unwrap_or(0),
                "authorization" => auth = v.trim().to_string(),
                _ => {}
            }
        }
    }
    let mut body = vec![0; length];
    let _ = reader.read_exact(&mut body);
    seen.lock()
        .unwrap()
        .requests
        .push((method.clone(), target.clone(), auth.clone()));
    let text = serde_json::json!({"path": target, "you_sent": auth}).to_string();
    let _ = write!(
        conn,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = conn.flush();
}

fn setup(env: &Env, mock: &MockApi) {
    env.setup();
    // Only the proxied key in [env]: prod has no database password.
    env.ok(&["var", "rm", "DATABASE_URL"], "");
    env.ok(&["add", "stripe"], "");
    env.ok(&["field", "add", "stripe", "secret", "--secret"], "");
    env.ok(&["set", "stripe#secret", "-e", "prod", "--stdin"], KEY);
    // prod is protected: giving its key an address needs the password.
    env.ok(
        &[
            "--password-stdin",
            "api",
            "add",
            "stripe#secret",
            "-e",
            "prod",
            "--base",
            &mock.url,
            "--auth",
            "bearer",
            "--allow",
            "GET /v1/**",
        ],
        &format!("{PASSWORD}\n"),
    );
}

#[test]
fn api_calls_add_the_key_and_follow_the_rules() {
    let env = Env::new();
    let mock = MockApi::start();
    setup(&env, &mock);

    let out = env.ok(&["show", "stripe"], "");
    assert!(
        out.contains("API (prod)") && out.contains("GET /v1/**"),
        "{out}"
    );
    let out = env.ok(&["api", "ls"], "");
    assert!(
        out.contains("stripe#secret (prod)") && out.contains("GET /v1/**"),
        "{out}"
    );

    let out = env.ok(
        &[
            "api",
            "call",
            "stripe#secret",
            "-e",
            "prod",
            "GET",
            "/v1/balance?limit=2",
        ],
        "",
    );
    assert!(!out.contains(KEY), "{out}");
    assert!(
        out.contains("[hidden:key]") && out.contains("/v1/balance?limit=2"),
        "{out}"
    );
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].2, format!("Bearer {KEY}"));

    // Not in the rules: refused before anything is sent.
    for (method, path) in [
        ("POST", "/v1/refunds"),
        ("GET", "/v2/balance"),
        ("GET", "/v1/../admin"),
        ("GET", "/v1/%2e%2e/admin"),
    ] {
        let (code, out, err) = env.run(
            &["api", "call", "stripe#secret", "-e", "prod", method, path],
            "",
        );
        assert_ne!(code, 0, "{method} {path}: {out}");
        assert!(!err.contains(KEY));
    }
    assert_eq!(mock.requests().len(), 1);

    // No API for dev.
    let (code, _, err) = env.run(
        &["api", "call", "stripe#secret", "-e", "dev", "GET", "/v1/x"],
        "",
    );
    assert_eq!(code, 4, "{err}");

    // The audit log names the call, never the key.
    let log = env.ok(&["log"], "");
    assert!(
        log.contains("api.call") && log.contains("GET /v1/balance"),
        "{log}"
    );
}

#[test]
fn ai_uses_production_apis_without_the_key() {
    let env = Env::new();
    let mock = MockApi::start();
    setup(&env, &mock);

    // A command that calls the API with whatever key and address it was given.
    env.ok(&["var", "add", "STRIPE_KEY", "stripe#secret"], "");
    let call = if cfg!(windows) {
        r#"["cmd", "/C", "curl -s %STRIPE_API%/v1/charges"]"#.to_string()
    } else {
        r#"["sh", "-c", "curl -s \"$STRIPE_API/v1/charges\""]"#.to_string()
    };
    let leak = if cfg!(windows) {
        r#"["cmd", "/C", "echo %STRIPE_KEY%"]"#
    } else {
        r#"["sh", "-c", "echo $STRIPE_KEY"]"#
    };
    let toml = std::fs::read_to_string(env.project.join("cemi.toml")).unwrap();
    let toml = toml.replace(
        "[ai.commands]",
        &format!(
            "[ai.commands]\ncharges = {{ cmd = {call}, envs = [\"prod\"] }}\nleak = {{ cmd = {leak}, envs = [\"prod\"] }}"
        ),
    );
    let toml = format!("{toml}\n[proxy]\nSTRIPE_API = \"stripe#secret\"\n");
    std::fs::write(env.project.join("cemi.toml"), toml).unwrap();

    env.ok(
        &[
            "token", "create", "bot", "--allow", "read", "--allow", "api", "--allow", "run",
            "--env", "prod",
        ],
        "",
    );
    env.ok(&["token", "create", "reader"], "");

    let mut m = Mcp::start(&env, "reader");
    let (err, msg) = m.call(
        2,
        "call_api",
        serde_json::json!({"reference": "stripe#secret", "env": "prod", "method": "GET", "path": "/v1/balance"}),
    );
    assert!(err && msg.contains("does not allow `api`"), "{msg}");
    drop(m);

    let mut m = Mcp::start(&env, "bot");
    let (err, out) = m.call(
        2,
        "call_api",
        serde_json::json!({"reference": "stripe#secret", "env": "prod", "method": "GET", "path": "/v1/balance"}),
    );
    assert!(!err, "{out}");
    assert!(out.starts_with("HTTP 200") && !out.contains(KEY), "{out}");
    assert!(out.contains("[hidden:key]"), "{out}");
    let (err, out) = m.call(
        3,
        "call_api",
        serde_json::json!({"reference": "stripe#secret", "env": "prod", "method": "DELETE", "path": "/v1/customers/c1"}),
    );
    assert!(err && out.contains("not allowed"), "{out}");

    // A run in prod: the command gets a placeholder and the proxy's address.
    let (err, out) = m.call(
        4,
        "run",
        serde_json::json!({"command": "leak", "env": "prod"}),
    );
    assert!(!err, "{out}");
    assert!(
        out.contains("cemi-proxy-STRIPE_KEY") && !out.contains(KEY),
        "{out}"
    );
    let before = mock.requests().len();
    let (err, out) = m.call(
        5,
        "run",
        serde_json::json!({"command": "charges", "env": "prod"}),
    );
    assert!(!err, "{out}");
    assert!(
        out.contains("Exit code: 0") && out.contains("/v1/charges"),
        "{out}"
    );
    assert!(!out.contains(KEY), "{out}");
    let reqs = mock.requests();
    assert_eq!(reqs.len(), before + 1, "{reqs:?}");
    // The API got the real key; the program only had the placeholder.
    assert_eq!(reqs.last().unwrap().2, format!("Bearer {KEY}"));

    // A secret without an API: an AI may not run it in prod.
    env.ok(
        &["set", "db#password", "-e", "prod", "--stdin"],
        "prod-db-pass-1",
    );
    env.ok(&["var", "add", "DB_PASS", "db#password"], "");
    let (err, out) = m.call(
        6,
        "run",
        serde_json::json!({"command": "leak", "env": "prod"}),
    );
    assert!(
        err && out.contains("DB_PASS") && out.contains("proxy"),
        "{out}"
    );
    assert!(!out.contains("prod-db-pass-1"), "{out}");
}
