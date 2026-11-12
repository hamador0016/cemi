//! End-to-end tests of the `cemi` binary. Every test uses its own temporary
//! folders: a fake home (CEMI_HOME), a fake credential store and a project.

mod common;

use std::process::Command;

use common::*;

#[test]
fn init_prints_recovery_code_and_protects_the_project() {
    let env = Env::new();
    let out = env.ok(
        &["--password-stdin", "init", "--global"],
        &format!("{PASSWORD}\n"),
    );
    let code = out.trim();
    assert!(
        code.len() > 50 && code.contains('-'),
        "recovery code: {code:?}"
    );
    env.ok(&["init"], "");
    let gitignore = std::fs::read_to_string(env.project.join(".gitignore")).unwrap();
    assert!(gitignore.contains(".cemi/"));
    assert!(env.project.join("cemi.toml").exists());
    assert_eq!(
        std::fs::read_to_string(env.project.join(".cemi/.gitignore")).unwrap(),
        "*\n"
    );
    // The recovery code opens the global vault.
    env.ok(
        &["-g", "recovery", "verify", "--password-stdin"],
        &format!("{code}\n"),
    );
    let (c, _, _) = env.run(
        &["-g", "recovery", "verify", "--password-stdin"],
        "AAAA-BBBB\n",
    );
    assert_ne!(c, 0);
}

#[test]
fn values_never_reach_the_disk_or_listings() {
    let env = Env::new();
    env.setup();
    for dir in [env.home.clone(), env.project.join(".cemi")] {
        for f in files_under(&dir) {
            let bytes = std::fs::read(&f).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(SECRET), "secret found in {}", f.display());
            assert!(
                !text.contains("localhost"),
                "template found in {}",
                f.display()
            );
        }
    }
    let show = env.ok(&["show", "db"], "");
    assert!(!show.contains(SECRET));
    assert!(show.contains("password"));
    let ls = env.ok(&["ls"], "");
    assert!(ls.contains("password*"));
    let doc = env.ok(&["doc"], "");
    assert!(!doc.contains(SECRET));
    assert!(doc.contains("`password` (secret)"));
}

#[test]
fn run_injects_values_and_can_hide_them() {
    let env = Env::new();
    env.setup();
    let mut args = vec!["run", "-e", "dev", "--"];
    let cmd = print_var_command("DATABASE_URL");
    args.extend(cmd.iter().map(String::as_str));
    let out = env.ok(&args, "");
    assert!(
        out.contains(&format!("postgres://app:{SECRET}@localhost/app")),
        "{out}"
    );

    let mut args = vec!["run", "-e", "dev", "--redact", "--"];
    args.extend(cmd.iter().map(String::as_str));
    let out = env.ok(&args, "");
    assert!(!out.contains(SECRET), "{out}");
    assert!(out.contains("[hidden:DATABASE_URL]"), "{out}");

    // prod has no password: run refuses and says why.
    let mut args = vec!["run", "-e", "prod", "--"];
    args.extend(cmd.iter().map(String::as_str));
    let (code, _, err) = env.run(&args, "");
    assert_ne!(code, 0);
    assert!(err.contains("no value for environment prod"), "{err}");
}

#[test]
fn locked_vault_needs_the_password() {
    let env = Env::new();
    env.setup();
    env.ok(&["lock"], "");
    // (Without --password-stdin, cemi asks on the console, like git does; not testable here.)
    let (code, _, err) = env.run(
        &["--password-stdin", "show", "db"],
        "wrong password!!\nwrong again!!!\nnope nope nope\n",
    );
    assert_ne!(code, 0, "{err}");
    // The local vault opens with the global vault's password.
    env.ok(
        &["--password-stdin", "show", "db"],
        &format!("{PASSWORD}\n"),
    );
}

#[test]
fn scan_finds_secrets_in_files() {
    let env = Env::new();
    env.setup();
    std::fs::write(
        env.project.join("config.js"),
        format!("const pw = \"{SECRET}\";\n"),
    )
    .unwrap();
    let (code, out, _) = env.run(&["scan"], "");
    assert_eq!(code, 1);
    assert!(out.contains("config.js:1"), "{out}");
    assert!(out.contains("db#password [dev]"), "{out}");
    assert!(!out.contains(SECRET));
    // One file, as editors call it: where the value starts and how long it is.
    let (code, out, _) = env.run(&["--json", "--no-input", "scan", "config.js"], "");
    assert_eq!(code, 1);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    let f = &v["data"]["findings"][0];
    assert_eq!(f["place"], "config.js");
    assert_eq!(
        (f["line"].clone(), f["column"].clone()),
        (1.into(), 13.into())
    );
    assert_eq!(f["length"], SECRET.len());
    assert!(!out.contains(SECRET));
    std::fs::remove_file(env.project.join("config.js")).unwrap();
    env.ok(&["scan"], "");
}

#[test]
fn import_dotenv_and_history() {
    let env = Env::new();
    env.setup();
    std::fs::write(
        env.project.join(".env"),
        "API_KEY=abc123abc123\nPUBLIC_URL=https://example.com\n",
    )
    .unwrap();
    env.ok(
        &["import", ".env", "--plain", "PUBLIC_URL", "-e", "dev"],
        "",
    );
    let toml = std::fs::read_to_string(env.project.join("cemi.toml")).unwrap();
    assert!(toml.contains("API_KEY = \"API_KEY#value\""), "{toml}");
    let show = env.ok(&["show", "PUBLIC_URL"], "");
    assert!(
        show.contains("https://example.com"),
        "non-secret values are shown: {show}"
    );
    let show = env.ok(&["show", "API_KEY"], "");
    assert!(!show.contains("abc123abc123"));

    env.ok(
        &[
            "set",
            "API_KEY#value",
            "-e",
            "dev",
            "--stdin",
            "--note",
            "rotated",
        ],
        "zzz999zzz999",
    );
    let hist = env.ok(&["history", "API_KEY#value", "-e", "dev"], "");
    assert!(
        hist.contains("v1") && hist.contains("archived") && hist.contains("rotated"),
        "{hist}"
    );
    env.ok(&["revert", "API_KEY#value", "1", "-e", "dev"], "");
    let mut args = vec!["run", "-e", "dev", "--"];
    let cmd = print_var_command("API_KEY");
    args.extend(cmd.iter().map(String::as_str));
    assert!(env.ok(&args, "").contains("abc123abc123"));
}

#[test]
fn status_and_memory() {
    let env = Env::new();
    env.setup();
    let out = env.ok(&["status"], "");
    assert!(out.contains("db: no purpose noted"), "{out}");
    assert!(out.contains("DATABASE_URL"), "prod is missing: {out}");
    env.ok(
        &[
            "note",
            "db",
            "--purpose",
            "app database",
            "--backup",
            "password manager",
            "--expires",
            "2000-01-01",
        ],
        "",
    );
    let out = env.ok(&["status"], "");
    assert!(!out.contains("no purpose noted"), "{out}");
    assert!(out.contains("expired on 2000-01-01"), "{out}");
    let memory = env.ok(&["note", "db"], "");
    assert!(memory.contains("purpose: app database"));
}

#[test]
fn audit_log_records_actions() {
    let env = Env::new();
    env.setup();
    let log = env.ok(&["log", "--verify"], "");
    assert!(
        log.contains("value.set") && log.contains("db#password"),
        "{log}"
    );
    assert!(!log.contains(SECRET));
}

#[test]
fn mcp_server_uses_secrets_without_returning_them() {
    let env = Env::new();
    env.setup();
    let cmd = print_var_command("DATABASE_URL");
    let toml_cmd = cmd
        .iter()
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = std::fs::read_to_string(env.project.join("cemi.toml")).unwrap();
    let toml = toml.replace(
        "[ai.commands]",
        &format!("[ai.commands]\nshow-db = {{ cmd = [{toml_cmd}], envs = [\"dev\"] }}"),
    );
    std::fs::write(env.project.join("cemi.toml"), toml).unwrap();

    env.ok(&["token", "create", "reader"], "");
    env.ok(
        &[
            "token", "create", "runner", "--allow", "read", "--allow", "run", "--allow",
            "generate", "--env", "dev",
        ],
        "",
    );

    let mut m = Mcp::start(&env, "reader");
    let (err, list) = m.call(2, "list", serde_json::json!({}));
    assert!(!err, "{list}");
    assert!(list.contains("db [password*, url]"), "{list}");
    let (err, show) = m.call(3, "show", serde_json::json!({"record": "db"}));
    assert!(!err && !show.contains(SECRET), "{show}");
    assert!(show.contains("set (hidden)"), "{show}");
    // Where it is used, from the project's cemi.toml and the template.
    assert!(
        show.contains("used by:") && show.contains("#url project: DATABASE_URL"),
        "{show}"
    );
    assert!(show.contains("#password db#url"), "{show}");
    let (err, msg) = m.call(
        4,
        "run",
        serde_json::json!({"command": "show-db", "env": "dev"}),
    );
    assert!(err && msg.contains("does not allow `run`"), "{msg}");
    drop(m);

    let mut m = Mcp::start(&env, "runner");
    let (err, out) = m.call(
        2,
        "run",
        serde_json::json!({"command": "show-db", "env": "dev"}),
    );
    assert!(!err, "{out}");
    assert!(out.contains("Exit code: 0"), "{out}");
    assert!(!out.contains(SECRET), "{out}");
    assert!(out.contains("[hidden:DATABASE_URL]"), "{out}");
    let (err, msg) = m.call(
        3,
        "run",
        serde_json::json!({"command": "show-db", "env": "prod"}),
    );
    assert!(err && msg.contains("may only run in"), "{msg}");
    let (err, msg) = m.call(
        4,
        "generate",
        serde_json::json!({"reference": "db#api", "env": "dev"}),
    );
    assert!(!err, "{msg}");
    drop(m);
    let show = env.ok(&["show", "db"], "");
    assert!(show.contains("api") && show.contains("dev: set"), "{show}");

    // A revoked token stops working.
    env.ok(&["token", "revoke", "runner"], "");
    let (code, _, err) = env.run(&["mcp", "serve", "--token-name", "runner"], "");
    assert_ne!(code, 0);
    assert!(err.contains("no token"), "{err}");

    // A locked vault: tools ask for `cemi unlock` instead of prompting.
    env.ok(&["lock"], "");
    let mut m = Mcp::start(&env, "reader");
    let (err, msg) = m.call(2, "list", serde_json::json!({}));
    assert!(err && msg.contains("cemi unlock"), "{msg}");
}

#[test]
fn mcp_launch_injects_keys_into_other_servers() {
    let env = Env::new();
    env.setup();
    let cmd = print_var_command("DB_PASSWORD");
    let mut args = vec![
        "mcp",
        "add",
        "fake",
        "--env",
        "DB_PASSWORD=db#password",
        "--",
    ];
    args.extend(cmd.iter().map(String::as_str));
    env.ok(&args, "");
    // launch uses the shared value: there is none (only dev), so it explains.
    let (code, _, err) = env.run(&["mcp", "launch", "fake"], "");
    assert_ne!(code, 0);
    assert!(err.contains("DB_PASSWORD"), "{err}");
    env.ok(&["set", "db#password", "--stdin"], SECRET);
    let out = env.ok(&["mcp", "launch", "fake"], "");
    assert!(out.contains(SECRET));
}

#[test]
fn pre_commit_hook_blocks_secrets() {
    let env = Env::new();
    env.setup();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(&env.project)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    assert!(git(&["init", "-q"]).0);
    env.ok(&["hook", "install"], "");
    std::fs::write(env.project.join("app.txt"), format!("password={SECRET}\n")).unwrap();
    assert!(git(&["add", "app.txt", "cemi.toml", ".gitignore"]).0);
    let (code, out, _) = env.run(&["scan", "--staged"], "");
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("app.txt:1"), "{out}");
    std::fs::write(env.project.join("app.txt"), "password from cemi\n").unwrap();
    assert!(git(&["add", "app.txt"]).0);
    env.ok(&["scan", "--staged"], "");
    // The vault folder itself is never staged.
    let (_, status) = git(&["status", "--porcelain", "--ignored"]);
    assert!(status.contains("!! .cemi/"), "{status}");
}

#[test]
fn copy_without_a_reference_needs_a_terminal() {
    let env = Env::new();
    env.setup();
    let (code, _, err) = env.run(&["copy"], "");
    assert_ne!(code, 0);
    assert!(err.contains("Give a reference"), "{err}");
}

#[test]
fn types_follow_cemi_toml() {
    let env = Env::new();
    env.setup();
    let out = env.ok(&["types"], "");
    assert!(out.contains("      DATABASE_URL: string;"), "{out}");
    let out = env.ok(&["types", "--format", "zod"], "");
    assert!(out.contains("  DATABASE_URL: z.string().min(1),"), "{out}");
    env.ok(&["types", "-o", "src/env.d.ts"], "");
    env.ok(&["types", "-o", "src/env.d.ts", "--check"], "");
    env.ok(&["var", "add", "DB_PASSWORD", "db#password"], "");
    let (code, _, err) = env.run(&["types", "-o", "src/env.d.ts", "--check"], "");
    assert_eq!(code, 1);
    assert!(err.contains("not up to date"), "{err}");
}

#[test]
fn prompt_shows_only_what_is_due() {
    let env = Env::new();
    env.setup();
    // Missing notes are not urgent: nothing to show.
    assert_eq!(env.ok(&["prompt"], ""), "");
    let soon = jiff::Zoned::now()
        .date()
        .checked_add(jiff::Span::new().days(3))
        .unwrap();
    env.ok(&["note", "db", "--expires", &soon.to_string()], "");
    assert_eq!(env.ok(&["prompt"], "").trim(), "cemi !1");
    // Locked: it says so, and never asks for the password.
    env.ok(&["lock"], "");
    let out = env
        .cmd(&["prompt"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "cemi locked");
}
