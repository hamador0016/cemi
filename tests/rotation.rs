//! End-to-end tests of v0.2: destinations, push, check, rotate, revoke,
//! approvals, and the GitHub/Supabase connectors against a local mock server.

mod common;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::*;
use data_encoding::BASE64;
use sha2::Digest;

/// The value of `key` in a .env file.
fn dotenv_value(path: &Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    cemi::dotenv::get(&text, key).unwrap()
}

/// A small executable script: `sh` on Unix, `.cmd` on Windows.
fn script(dir: &Path, name: &str, unix: &str, windows: &str) -> PathBuf {
    if cfg!(windows) {
        let p = dir.join(format!("{name}.cmd"));
        std::fs::write(&p, windows.replace('\n', "\r\n")).unwrap();
        p
    } else {
        let p = dir.join(name);
        std::fs::write(&p, unix).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }
}

fn exit_with(code: i32) -> Vec<String> {
    if cfg!(windows) {
        vec!["cmd".into(), "/C".into(), format!("exit {code}")]
    } else {
        vec![
            "sh".into(),
            "-c".into(),
            format!("cat >/dev/null; exit {code}"),
        ]
    }
}

fn args<'a>(base: &[&'a str], extra: &'a [String]) -> Vec<&'a str> {
    let mut v = base.to_vec();
    v.extend(extra.iter().map(String::as_str));
    v
}

#[test]
fn dotenv_destinations_push_check_and_rotate() {
    let env = Env::new();
    env.setup();
    let file = env.project.join(".env.local");
    env.ok(
        &[
            "dest",
            "add",
            "db#password",
            "-e",
            "dev",
            "dotenv",
            "--file",
            ".env.local",
            "--key",
            "DB_PASSWORD",
        ],
        "",
    );
    env.ok(
        &[
            "dest",
            "add",
            "db#url",
            "-e",
            "dev",
            "dotenv",
            "--file",
            ".env.local",
            "--key",
            "DATABASE_URL",
        ],
        "",
    );
    let (code, out, _) = env.run(&["check", "--offline"], "");
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("never sent"), "{out}");

    env.ok(&["push"], "");
    assert_eq!(dotenv_value(&file, "DB_PASSWORD").as_deref(), Some(SECRET));
    assert_eq!(
        dotenv_value(&file, "DATABASE_URL").unwrap(),
        format!("postgres://app:{SECRET}@localhost/app")
    );
    let out = env.ok(&["check"], "");
    assert!(out.contains("up to date"), "{out}");

    // Someone edits the file by hand.
    let text = std::fs::read_to_string(&file)
        .unwrap()
        .replace(SECRET, "edited-by-hand");
    std::fs::write(&file, text).unwrap();
    let (code, out, _) = env.run(&["check"], "");
    assert_eq!(code, 1);
    assert!(out.contains("changed outside"), "{out}");
    assert!(
        out.contains("cemi push --force local:db#password -e dev"),
        "{out}"
    );
    // A plain push does not overwrite it: it may be a newer key set by hand.
    let (code, _, err) = env.run(&["push"], "");
    assert_eq!(code, 1);
    assert!(err.contains("not overwritten"), "{err}");
    assert_eq!(
        dotenv_value(&file, "DB_PASSWORD").as_deref(),
        Some("edited-by-hand")
    );
    env.ok(&["push", "--force"], "");
    assert_eq!(dotenv_value(&file, "DB_PASSWORD").as_deref(), Some(SECRET));

    // Someone deletes it: push asks the destination and sends it again.
    let text: String = std::fs::read_to_string(&file)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("DB_PASSWORD="))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&file, text).unwrap();
    let (code, out, _) = env.run(&["check"], "");
    assert_eq!(code, 1);
    assert!(out.contains("missing at the destination"), "{out}");
    env.ok(&["push"], "");
    assert_eq!(dotenv_value(&file, "DB_PASSWORD").as_deref(), Some(SECRET));
    env.ok(&["check"], "");

    // Rotation with a generated value reaches the template too.
    let (_, _, err) = env.run(
        &["rotate", "db#password", "-e", "dev", "--generate", "--yes"],
        "",
    );
    let new = dotenv_value(&file, "DB_PASSWORD").unwrap();
    assert_ne!(new, SECRET, "{err}");
    assert_eq!(new.len(), 40);
    assert_eq!(
        dotenv_value(&file, "DATABASE_URL").unwrap(),
        format!("postgres://app:{new}@localhost/app")
    );
    assert!(
        err.contains("! Revoke the old key at its provider by hand"),
        "{err}"
    );
    assert!(!err.contains(&new), "the new value was printed: {err}");
    let hist = env.ok(&["history", "db#password", "-e", "dev"], "");
    assert!(
        hist.contains("v1  archived") && hist.contains("v2  active"),
        "{hist}"
    );
    let status = env.ok(&["status"], "");
    assert!(!status.contains("out of date"), "{status}");
}

#[test]
fn failed_verification_puts_the_old_value_back() {
    let env = Env::new();
    env.setup();
    let file = env.project.join(".env");
    env.ok(
        &[
            "dest",
            "add",
            "db#password",
            "-e",
            "dev",
            "dotenv",
            "--key",
            "DB_PASSWORD",
        ],
        "",
    );
    env.ok(&["push"], "");
    let fail = exit_with(1);
    env.ok(
        &args(&["verify", "db#password", "-e", "dev", "--"], &fail),
        "",
    );
    let (code, _, err) = env.run(
        &["rotate", "db#password", "-e", "dev", "--generate", "--yes"],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("failed and was undone"), "{err}");
    assert!(err.contains("! Problem: verification failed"), "{err}");
    // Each step is shown once, marked; the final error does not repeat them.
    assert_eq!(err.matches("✓ Put the old value back").count(), 1, "{err}");
    assert_eq!(err.matches("Put the old value back").count(), 1, "{err}");
    assert_eq!(dotenv_value(&file, "DB_PASSWORD").as_deref(), Some(SECRET));
    let hist = env.ok(&["history", "db#password", "-e", "dev"], "");
    assert!(
        hist.contains("v1  active") && hist.contains("v2  pending"),
        "{hist}"
    );
    let status = env.ok(&["status"], "");
    assert!(status.contains("did not finish"), "{status}");

    // Discard the pending value, fix the check, rotate again.
    env.ok(&["revoke", "db#password", "-e", "dev", "--pending"], "");
    let pass = exit_with(0);
    env.ok(
        &args(&["verify", "db#password", "-e", "dev", "--"], &pass),
        "",
    );
    env.ok(
        &["rotate", "db#password", "-e", "dev", "--generate", "--yes"],
        "",
    );
    assert_ne!(dotenv_value(&file, "DB_PASSWORD").as_deref(), Some(SECRET));
    let hist = env.ok(&["history", "db#password", "-e", "dev"], "");
    assert!(
        hist.contains("v2  retired") && hist.contains("v3  active"),
        "{hist}"
    );
}

#[test]
fn command_origin_creates_and_revokes() {
    let env = Env::new();
    env.setup();
    let tools = env.project.join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    std::fs::write(tools.join("next.txt"), "origin-key-0002").unwrap();
    let origin = script(
        &tools,
        "new-key",
        "#!/bin/sh\ndir=$(dirname \"$0\")\ncase \"$1\" in\n  create) cat \"$dir/next.txt\";;\n  revoke) cat > \"$dir/revoked.txt\";;\n  *) exit 1;;\nesac\n",
        "@echo off\nif \"%1\"==\"create\" (\n  type \"%~dp0next.txt\"\n  exit /b 0\n)\nif \"%1\"==\"revoke\" (\n  more > \"%~dp0revoked.txt\"\n  exit /b 0\n)\nexit /b 1\n",
    );
    let origin = origin.display().to_string();
    env.ok(
        &[
            "origin",
            "set",
            "db#password",
            "-e",
            "dev",
            "command",
            "--",
            &origin,
        ],
        "",
    );
    env.ok(
        &[
            "dest",
            "add",
            "db#password",
            "-e",
            "dev",
            "dotenv",
            "--key",
            "DB_PASSWORD",
        ],
        "",
    );
    env.ok(&["rotate", "db#password", "-e", "dev", "--yes"], "");
    assert_eq!(
        dotenv_value(&env.project.join(".env"), "DB_PASSWORD").as_deref(),
        Some("origin-key-0002")
    );
    let revoked = std::fs::read_to_string(tools.join("revoked.txt")).unwrap();
    assert!(revoked.contains(SECRET), "{revoked:?}");
    let hist = env.ok(&["history", "db#password", "-e", "dev"], "");
    assert!(
        hist.contains("v1  retired") && hist.contains("v2  active"),
        "{hist}"
    );
}

#[test]
fn external_connectors_speak_json() {
    let env = Env::new();
    env.setup();
    let bin = env.project.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    script(
        &bin,
        "cemi-connector-fake",
        "#!/bin/sh\ndir=$(dirname \"$0\")\ncat >> \"$dir/requests.txt\"\necho >> \"$dir/requests.txt\"\necho '{\"ok\":true,\"value\":\"external-key-0001\",\"provider_id\":\"ext-1\"}'\n",
        "@echo off\nmore >> \"%~dp0requests.txt\"\necho {\"ok\":true,\"value\":\"external-key-0001\",\"provider_id\":\"ext-1\"}\n",
    );
    let path = std::env::join_paths(
        std::iter::once(bin.clone())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let run = |a: &[&str]| {
        let out = env.cmd(a).env("PATH", &path).output().unwrap();
        assert!(
            out.status.success(),
            "cemi {a:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    run(&[
        "origin",
        "set",
        "db#password",
        "-e",
        "dev",
        "external",
        "fake",
        "--set",
        "project=demo",
    ]);
    run(&[
        "dest",
        "add",
        "db#password",
        "-e",
        "dev",
        "external",
        "fake",
        "--set",
        "where=vault-x",
    ]);
    run(&["rotate", "db#password", "-e", "dev", "--yes"]);
    let requests = std::fs::read_to_string(bin.join("requests.txt")).unwrap();
    let reqs: Vec<serde_json::Value> = requests
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let actions: Vec<&str> = reqs.iter().map(|r| r["action"].as_str().unwrap()).collect();
    assert_eq!(
        actions,
        ["create", "write", "observe", "revoke"],
        "{requests}"
    );
    assert_eq!(reqs[0]["config"]["project"], "demo");
    assert_eq!(reqs[1]["value"], "external-key-0001");
    assert_eq!(reqs[1]["config"]["where"], "vault-x");
    assert_eq!(reqs[3]["value"], SECRET);
    assert_eq!(reqs[3]["compromised"], false);
}

#[test]
fn protected_environments_need_a_person() {
    let env = Env::new();
    env.setup();
    env.ok(
        &["set", "db#password", "-e", "prod", "--stdin"],
        "prod-secret-value-1",
    );
    env.ok(
        &[
            "dest",
            "add",
            "db#password",
            "-e",
            "prod",
            "dotenv",
            "--file",
            ".env.prod",
            "--key",
            "DB_PASSWORD",
        ],
        "",
    );
    env.ok(
        &[
            "dest",
            "add",
            "db#password",
            "-e",
            "dev",
            "dotenv",
            "--file",
            ".env.dev",
            "--key",
            "DB_PASSWORD",
        ],
        "",
    );
    let prod = env.project.join(".env.prod");
    let dev = env.project.join(".env.dev");
    let out = env.ok(&["env", "ls"], "");
    assert!(out.contains("prod (protected)"), "{out}");

    // A wrong password stops the push; the right one lets it through.
    let (code, _, err) = env.run(
        &["--password-stdin", "push", "-e", "prod"],
        "wrong password!!\n",
    );
    assert_ne!(code, 0);
    assert!(err.contains("wrong password"), "{err}");
    assert!(!prod.exists());
    env.ok(
        &["--password-stdin", "push", "-e", "prod"],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(
        dotenv_value(&prod, "DB_PASSWORD").as_deref(),
        Some("prod-secret-value-1")
    );
    env.ok(&["push", "-e", "dev"], "");

    env.ok(
        &[
            "token", "create", "bot", "--allow", "read", "--allow", "push", "--allow", "rotate",
        ],
        "",
    );
    env.ok(&["token", "create", "reader"], "");
    let mut m = Mcp::start(&env, "reader");
    let (err, msg) = m.call(
        2,
        "rotate",
        serde_json::json!({"reference": "db#password", "env": "dev", "generate": true}),
    );
    assert!(err && msg.contains("does not allow `rotate`"), "{msg}");
    drop(m);

    let mut m = Mcp::start(&env, "bot");
    // dev is not protected: the AI rotates it directly, without seeing the value.
    let (err, msg) = m.call(
        2,
        "rotate",
        serde_json::json!({"reference": "db#password", "env": "dev", "generate": true}),
    );
    assert!(!err, "{msg}");
    let new_dev = dotenv_value(&dev, "DB_PASSWORD").unwrap();
    assert_ne!(new_dev, SECRET);
    assert!(!msg.contains(&new_dev), "{msg}");
    // prod is protected: only a request.
    let (err, msg) = m.call(
        3,
        "rotate",
        serde_json::json!({"reference": "db#password", "env": "prod", "generate": true}),
    );
    assert!(!err, "{msg}");
    assert!(msg.contains("cemi approve"), "{msg}");
    let id = msg
        .split("cemi approve ")
        .nth(1)
        .unwrap()
        .split('`')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(
        dotenv_value(&prod, "DB_PASSWORD").as_deref(),
        Some("prod-secret-value-1")
    );
    let (err, check) = m.call(4, "check", serde_json::json!({}));
    assert!(!err && check.contains("up to date"), "{check}");
    assert!(
        !check.contains("prod-secret-value-1") && !check.contains(&new_dev),
        "{check}"
    );
    drop(m);

    let list = env.ok(&["approve"], "");
    assert!(list.contains(&id) && list.contains("mcp:bot"), "{list}");
    env.ok(
        &["--password-stdin", "approve", &id],
        &format!("{PASSWORD}\n"),
    );
    let new_prod = dotenv_value(&prod, "DB_PASSWORD").unwrap();
    assert_ne!(new_prod, "prod-secret-value-1");
    // A request works once.
    let (code, _, _) = env.run(
        &["--password-stdin", "approve", &id],
        &format!("{PASSWORD}\n"),
    );
    assert_ne!(code, 0);
    let log = env.ok(&["log"], "");
    assert!(log.contains("mcp:bot (approved)"), "{log}");
}

// ----- a mock of the GitHub and Supabase APIs -----

#[derive(Default)]
struct State {
    gh_auth: Vec<String>,
    gh_sealed: Option<String>,
    gh_updated: u32,
    supa_auth: Vec<String>,
    supa_secrets: BTreeMap<String, String>,
    supa_keys: BTreeMap<String, String>,
    supa_deleted: Vec<String>,
    next_key: u32,
}

struct Mock {
    url: String,
    state: Arc<Mutex<State>>,
    gh_key: crypto_box::SecretKey,
}

impl Mock {
    fn start() -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let gh_key = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
        let public = BASE64.encode(gh_key.public_key().as_bytes());
        let s = state.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                handle(conn, &s, &public);
            }
        });
        Mock { url, state, gh_key }
    }
}

fn handle(mut conn: TcpStream, state: &Arc<Mutex<State>>, public: &str) {
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
    let mut st = state.lock().unwrap();
    let (status, answer) = match (method.as_str(), path) {
        ("GET", "/repos/acme/shop/actions/secrets/public-key") => {
            st.gh_auth.push(auth);
            (200, serde_json::json!({"key_id": "k1", "key": public}))
        }
        ("PUT", "/repos/acme/shop/actions/secrets/STRIPE_KEY") => {
            assert_eq!(body["key_id"], "k1");
            st.gh_sealed = Some(body["encrypted_value"].as_str().unwrap().to_string());
            st.gh_updated += 1;
            (201, serde_json::json!({}))
        }
        ("GET", "/repos/acme/shop/actions/secrets/STRIPE_KEY") => match st.gh_sealed {
            Some(_) => (
                200,
                serde_json::json!({
                    "name": "STRIPE_KEY",
                    "created_at": "2026-11-11T00:00:00Z",
                    "updated_at": format!("2026-11-11T00:00:{:02}Z", st.gh_updated),
                }),
            ),
            None => (404, serde_json::json!({"message": "Not Found"})),
        },
        ("POST", "/v1/projects/abcdefgh/api-keys") => {
            assert_eq!(query, "reveal=true");
            assert_eq!(body["type"], "secret");
            st.supa_auth.push(auth);
            st.next_key += 1;
            let id = format!("id-{}", st.next_key);
            let key = format!("sb_secret_NEW{}", st.next_key);
            st.supa_keys.insert(id.clone(), key.clone());
            (
                201,
                serde_json::json!({"api_key": key, "id": id, "name": body["name"]}),
            )
        }
        ("DELETE", p) if p.starts_with("/v1/projects/abcdefgh/api-keys/") => {
            let id = p.rsplit('/').next().unwrap().to_string();
            st.supa_keys.remove(&id);
            st.supa_deleted.push(format!("{id}?{query}"));
            (200, serde_json::json!({}))
        }
        ("GET", p) if p.starts_with("/v1/projects/abcdefgh/api-keys/") => {
            let id = p.rsplit('/').next().unwrap();
            if st.supa_keys.contains_key(id) {
                (200, serde_json::json!({"id": id, "name": "x"}))
            } else {
                (
                    404,
                    serde_json::json!({"message": "API key not found for project"}),
                )
            }
        }
        ("POST", "/v1/projects/abcdefgh/secrets") => {
            for s in body.as_array().unwrap() {
                st.supa_secrets.insert(
                    s["name"].as_str().unwrap().into(),
                    s["value"].as_str().unwrap().into(),
                );
            }
            (201, serde_json::json!({}))
        }
        ("GET", "/v1/projects/abcdefgh/secrets") => {
            let list: Vec<serde_json::Value> = st
                .supa_secrets
                .iter()
                .map(|(k, v)| {
                    let digest =
                        data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(v.as_bytes()));
                    serde_json::json!({"name": k, "value": digest})
                })
                .collect();
            (200, serde_json::Value::Array(list))
        }
        _ => (404, serde_json::json!({"message": "Not Found"})),
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
fn github_and_supabase_connectors() {
    let mock = Mock::start();
    let env = Env::new();
    env.setup();
    env.ok(&["add", "accounts/github"], "");
    env.ok(
        &["set", "accounts/github#token", "--stdin"],
        "gh-test-token-123",
    );
    env.ok(&["add", "accounts/supabase"], "");
    env.ok(
        &["set", "accounts/supabase#token", "--stdin"],
        "sbp-test-token-456",
    );

    // GitHub: the secret is sealed to the repository key.
    env.ok(&["add", "shop/stripe"], "");
    env.ok(
        &["set", "shop/stripe#key", "-e", "dev", "--stdin"],
        "sk_old_value_123",
    );
    env.ok(
        &[
            "dest",
            "add",
            "shop/stripe#key",
            "-e",
            "dev",
            "github",
            "--repo",
            "acme/shop",
            "--name",
            "STRIPE_KEY",
            "--token",
            "accounts/github#token",
            "--api-url",
            &mock.url,
        ],
        "",
    );
    env.ok(&["push"], "");
    {
        let st = mock.state.lock().unwrap();
        assert_eq!(st.gh_auth, ["Bearer gh-test-token-123"]);
        let sealed = BASE64
            .decode(st.gh_sealed.as_ref().unwrap().as_bytes())
            .unwrap();
        assert_eq!(mock.gh_key.unseal(&sealed).unwrap(), b"sk_old_value_123");
    }
    let out = env.ok(&["check", "shop/stripe#key"], "");
    assert!(out.contains("up to date"), "{out}");
    mock.state.lock().unwrap().gh_updated += 5;
    let (code, out, _) = env.run(&["check", "shop/stripe#key"], "");
    assert_eq!(code, 1);
    assert!(out.contains("changed outside"), "{out}");

    // Supabase: the key is created at the origin and copied to a function secret.
    env.ok(&["add", "supa"], "");
    env.ok(
        &["set", "supa#key", "-e", "dev", "--stdin"],
        "sb_secret_FIRST",
    );
    let url = mock.url.as_str();
    env.ok(
        &[
            "origin",
            "set",
            "supa#key",
            "-e",
            "dev",
            "supabase-key",
            "--project",
            "abcdefgh",
            "--token",
            "accounts/supabase#token",
            "--api-url",
            url,
        ],
        "",
    );
    env.ok(
        &[
            "dest",
            "add",
            "supa#key",
            "-e",
            "dev",
            "supabase-secret",
            "--project",
            "abcdefgh",
            "--name",
            "SERVICE_KEY",
            "--token",
            "accounts/supabase#token",
            "--api-url",
            url,
        ],
        "",
    );
    let (_, _, err) = env.run(&["rotate", "supa#key", "-e", "dev", "--yes"], "");
    assert!(err.contains("Cemí did not create this key"), "{err}");
    assert_eq!(
        mock.state.lock().unwrap().supa_secrets["SERVICE_KEY"],
        "sb_secret_NEW1"
    );
    // The second rotation deletes the key the first one created.
    env.ok(&["rotate", "supa#key", "-e", "dev", "--yes"], "");
    {
        let st = mock.state.lock().unwrap();
        assert_eq!(st.supa_secrets["SERVICE_KEY"], "sb_secret_NEW2");
        assert_eq!(
            st.supa_deleted,
            ["id-1?was_compromised=false&reason=rotating_key"]
        );
        assert!(
            st.supa_auth
                .iter()
                .all(|a| a == "Bearer sbp-test-token-456")
        );
    }
    // A leak: the provider is told.
    env.ok(
        &["rotate", "supa#key", "-e", "dev", "--leaked", "--yes"],
        "",
    );
    assert_eq!(
        mock.state.lock().unwrap().supa_deleted[1],
        "id-2?was_compromised=true&reason=leaked"
    );
    let out = env.ok(&["check", "supa#key"], "");
    assert!(out.contains("up to date"), "{out}");
    // The key disappears at the provider: check notices.
    mock.state.lock().unwrap().supa_keys.clear();
    let (code, out, _) = env.run(&["check", "supa#key"], "");
    assert_eq!(code, 1);
    assert!(out.contains("no longer exists"), "{out}");
    // Plain http is refused for anything but this computer.
    let (code, _, err) = env.run(
        &[
            "dest",
            "add",
            "supa#key",
            "supabase-secret",
            "--project",
            "abcdefgh",
            "--name",
            "X",
            "--token",
            "accounts/supabase#token",
            "--api-url",
            "http://example.com",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("https://"), "{err}");
}
