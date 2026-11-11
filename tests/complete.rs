//! Shell completion: names come from unlocked vaults only.

mod common;

use std::process::Stdio;

use common::*;

fn complete(env: &Env, line: &[&str]) -> String {
    let mut args = vec!["--", "cemi"];
    args.extend_from_slice(line);
    let out = env
        .cmd(&args)
        .env("COMPLETE", "fish")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn completes_names_from_unlocked_vaults() {
    let env = Env::new();
    env.setup();
    let out = complete(&env, &["copy", "db#"]);
    assert!(out.contains("db#password"), "{out}");
    assert!(out.contains("db#url"), "{out}");
    let out = complete(&env, &["show", "d"]);
    assert!(out.lines().any(|l| l == "db"), "{out}");
    let out = complete(&env, &["run", "-e", ""]);
    assert!(out.contains("dev") && out.contains("prod"), "{out}");
    let out = complete(&env, &["rot"]);
    assert!(out.starts_with("rotate"), "{out}");
    // Never a value.
    assert!(!out.contains(SECRET));

    // Locked: no names, and no password prompt.
    env.ok(&["lock"], "");
    let out = complete(&env, &["copy", "db#"]);
    assert!(!out.contains("db#password"), "{out}");
}

#[test]
fn completion_setup_line() {
    let env = Env::new();
    let out = env.ok(&["completion", "bash"], "");
    assert_eq!(out.trim(), "source <(COMPLETE=bash cemi)");
}
