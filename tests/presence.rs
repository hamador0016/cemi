//! Approvals confirmed with the device (Windows Hello / Touch ID). Tests
//! stand in for the person with CEMI_TEST_PRESENCE, which only debug builds
//! read, so no system dialog opens.

mod common;

use std::io::Write;
use std::process::Stdio;

use common::*;

/// Runs cemi with CEMI_TEST_PRESENCE set; returns (code, stdout, stderr).
fn run_as(env: &Env, presence: &str, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut c = env.cmd(args);
    c.env("CEMI_TEST_PRESENCE", presence)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn dotenv_value(path: &std::path::Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")).map(str::to_string))
}

fn request_push(m: &mut Mcp, id: u64) -> String {
    let (err, msg) = m.call(
        id,
        "push",
        serde_json::json!({"reference": "db#password", "env": "prod"}),
    );
    assert!(!err && msg.contains("cemi approve"), "{msg}");
    msg.split("cemi approve ")
        .nth(1)
        .unwrap()
        .split('`')
        .next()
        .unwrap()
        .to_string()
}

#[test]
fn approvals_with_the_device() {
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
    let prod = env.project.join(".env.prod");
    let requests = env.project.join(".cemi").join("requests");

    // Without a device, the setting is refused and nothing changes.
    let (code, _, err) = run_as(
        &env,
        "none",
        &["--password-stdin", "approve-with", "device"],
        &format!("{PASSWORD}\n"),
    );
    assert_ne!(code, 0);
    assert!(err.contains("not available"), "{err}");
    // A person who cancels the check does not change it either.
    let (code, _, _) = run_as(
        &env,
        "no",
        &["--password-stdin", "approve-with", "device"],
        &format!("{PASSWORD}\n"),
    );
    assert_ne!(code, 0);
    let (code, _, err) = run_as(
        &env,
        "yes",
        &["--password-stdin", "approve-with", "device"],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(code, 0, "{err}");

    env.ok(
        &[
            "token", "create", "bot", "--allow", "read", "--allow", "push",
        ],
        "",
    );
    let mut m = Mcp::start(&env, "bot");
    let id = request_push(&mut m, 2);
    // The tray reads only how many requests wait.
    assert_eq!(std::fs::read_to_string(&requests).unwrap().trim(), "1");

    // The person says no at the device: nothing is sent, and the request is used up.
    let (code, _, err) = run_as(&env, "no", &["approve", &id], "");
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("not confirmed"), "{err}");
    assert!(!prod.exists());
    assert_eq!(std::fs::read_to_string(&requests).unwrap().trim(), "0");

    // The person confirms at the device: no password needed.
    let id = request_push(&mut m, 3);
    let (code, _, err) = run_as(&env, "yes", &["approve", &id], "");
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        dotenv_value(&prod, "DB_PASSWORD").as_deref(),
        Some("prod-secret-value-1")
    );

    // No device at the moment: it falls back to the password.
    env.ok(
        &["set", "db#password", "-e", "prod", "--stdin"],
        "prod-secret-value-2",
    );
    let id = request_push(&mut m, 4);
    let (code, _, err) = run_as(&env, "none", &["--no-input", "approve", &id], "");
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("Asking for the password instead"), "{err}");
    let id = request_push(&mut m, 5);
    let (code, _, err) = run_as(
        &env,
        "none",
        &["--password-stdin", "approve", &id],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        dotenv_value(&prod, "DB_PASSWORD").as_deref(),
        Some("prod-secret-value-2")
    );
    drop(m);

    // Back to the password: confirmed with the device.
    let (code, _, err) = run_as(&env, "yes", &["approve-with", "password"], "");
    assert_eq!(code, 0, "{err}");
    let log = env.ok(&["log"], "");
    assert!(log.contains("approve.with"), "{log}");
}
