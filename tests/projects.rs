//! `cemi deps` across projects: the vault remembers every project that uses
//! it, so one question finds them all.

mod common;

use std::io::Write;
use std::path::Path;
use std::process::Stdio;

use common::*;

const TOKEN: &str = "global:accounts/cloudflare#token";

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// Runs cemi in `dir` and returns (exit code, stdout, stderr).
fn run_in(env: &Env, dir: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut c = env.cmd(args);
    c.current_dir(dir)
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

fn ok_in(env: &Env, dir: &Path, args: &[&str], stdin: &str) -> String {
    let (code, out, err) = run_in(env, dir, args, stdin);
    assert_eq!(code, 0, "cemi {args:?} in {}:\n{out}\n{err}", dir.display());
    out
}

#[test]
fn deps_finds_every_project() {
    let env = Env::new();
    env.setup();
    env.ok(&["-g", "add", "accounts/cloudflare"], "");
    env.ok(
        &[
            "-g",
            "field",
            "add",
            "accounts/cloudflare",
            "token",
            "--secret",
        ],
        "",
    );
    env.ok(
        &["-g", "set", "accounts/cloudflare#token", "--stdin"],
        "cf-token-value-1",
    );

    // Projects outside the folder of the local vault, so plain references
    // mean the global vault.
    let code = env.project.parent().unwrap().join("code");
    let shop = code.join("shop");
    write(
        &shop.join("cemi.toml"),
        "[env]\nCLOUDFLARE_API_TOKEN = \"global:accounts/cloudflare#token\"\n",
    );
    let blog = code.join("blog");
    write(
        &blog.join("cemi.toml"),
        "vault = \"global\"\nentity = \"accounts\"\n[files]\nCF_TOKEN_FILE = \"cloudflare#token\"\n",
    );
    let other = code.join("other");
    write(
        &other.join("cemi.toml"),
        "[env]\nDB = \"global:accounts/other#url\"\n",
    );

    // Nothing has run in those folders yet.
    let out = env.ok(&["deps", TOKEN], "");
    assert!(out.contains("Nothing Cemí knows uses"), "{out}");

    // Opening the vault from a project notes it; `project add` notes another.
    ok_in(&env, &shop, &["status"], "");
    env.ok(&["project", "add", blog.to_str().unwrap()], "");
    let out = env.ok(&["-g", "project", "ls"], "");
    assert!(out.contains("shop") && out.contains("blog"), "{out}");
    assert!(!out.contains("other"), "{out}");

    let (code_, out, err) = env.run(&["deps", TOKEN], "");
    assert_eq!(code_, 0, "{err}");
    assert!(out.contains("shop: CLOUDFLARE_API_TOKEN"), "{out}");
    assert!(out.contains("blog: CF_TOKEN_FILE (as a file)"), "{out}");
    assert!(err.contains("Searched 2 projects"), "{err}");
    // A record: every field, named.
    let out = env.ok(&["deps", "global:accounts/cloudflare"], "");
    assert!(out.contains("#token shop: CLOUDFLARE_API_TOKEN"), "{out}");

    let json: serde_json::Value =
        serde_json::from_str(&env.ok(&["--json", "deps", TOKEN], "")).unwrap();
    let used = json["data"]["used_by"].as_array().unwrap();
    assert_eq!(used.len(), 2, "{json}");
    assert_eq!(used[0]["project"], "blog");
    assert_eq!(used[0]["as_file"], true);

    // A copy in CI: up to date, then out of date when the value changes.
    ok_in(&env, &shop, &["ci", "setup"], "");
    ok_in(&env, &shop, &["ci", "export", "-e", "dev"], "");
    let out = env.ok(&["deps", TOKEN], "");
    assert!(
        out.contains("copied to cemi.ci.age (dev): up to date"),
        "{out}"
    );
    std::thread::sleep(std::time::Duration::from_millis(20));
    env.ok(
        &["-g", "set", "accounts/cloudflare#token", "--stdin"],
        "cf-token-value-2",
    );
    let out = env.ok(&["deps", TOKEN], "");
    assert!(
        out.contains("copied to cemi.ci.age (dev): out of date")
            && out.contains("cemi ci export -e dev"),
        "{out}"
    );
    let (_, out, _) = env.run(&["-g", "status"], "");
    assert!(
        out.contains("cemi.ci.age in shop (dev)") && out.contains("CLOUDFLARE_API_TOKEN"),
        "{out}"
    );
    // The rotation plan says Cemí does not rewrite that file.
    // A shared value reaches prod, so a person types the password.
    let out = env.ok(
        &["--password-stdin", "rotate", TOKEN, "--generate", "--yes"],
        &format!("{PASSWORD}\n"),
    );
    assert!(
        out.contains("Not updated by Cemí: cemi.ci.age in shop"),
        "{out}"
    );

    // A project that moved away is reported, and can be forgotten.
    std::fs::remove_file(blog.join("cemi.toml")).unwrap();
    let (_, out, err) = env.run(&["deps", TOKEN], "");
    assert!(!out.contains("blog:"), "{out}");
    assert!(err.contains("Not found:") && err.contains("blog"), "{err}");
    let out = env.ok(&["-g", "project", "ls"], "");
    assert!(out.contains("missing"), "{out}");
    env.ok(&["-g", "project", "rm", "blog"], "");
    let out = env.ok(&["-g", "project", "ls"], "");
    assert!(!out.contains("blog"), "{out}");
}

#[test]
fn a_project_is_noted_once() {
    let env = Env::new();
    env.setup();
    for _ in 0..3 {
        env.ok(&["status"], "");
    }
    let json: serde_json::Value =
        serde_json::from_str(&env.ok(&["--json", "project", "ls"], "")).unwrap();
    let projects = json["data"]["projects"].as_array().unwrap();
    assert_eq!(projects.len(), 1, "{json}");
    assert_eq!(projects[0]["state"], "ok");
    // The local template uses db#password: this project shows up.
    let out = env.ok(&["deps", "db#url"], "");
    assert!(out.contains("DATABASE_URL"), "{out}");
    let out = env.ok(&["deps", "db#password"], "");
    assert!(
        out.contains("Templates:") && out.contains("db#url"),
        "{out}"
    );
}
