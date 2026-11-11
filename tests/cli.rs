//! End-to-end tests of the `cemi` binary. Every test uses its own temporary
//! folders: a fake home (CEMI_HOME), a fake credential store and a project.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use assert_cmd::cargo::cargo_bin;

const PASSWORD: &str = "correct horse battery staple";
const SECRET: &str = "s3cr3t-Pa55word-xyz";

struct Env {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    sessions: PathBuf,
    project: PathBuf,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let sessions = tmp.path().join("sessions");
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        Env {
            home,
            sessions,
            project,
            _tmp: tmp,
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(cargo_bin("cemi"));
        c.args(args)
            .current_dir(&self.project)
            .env("CEMI_HOME", &self.home)
            .env("CEMI_TEST_SESSION_DIR", &self.sessions)
            .env("CEMI_INSECURE_FAST_KDF", "1")
            .env_remove("CEMI_ENV")
            .env_remove("CEMI_TOKEN");
        c
    }

    /// Runs and returns (exit code, stdout, stderr).
    fn run(&self, args: &[&str], stdin: &str) -> (i32, String, String) {
        let mut c = self.cmd(args);
        c.stdin(Stdio::piped())
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

    fn ok(&self, args: &[&str], stdin: &str) -> String {
        let (code, out, err) = self.run(args, stdin);
        assert_eq!(code, 0, "cemi {args:?} failed:\n{out}\n{err}");
        out
    }

    /// A global vault plus a project vault linked to it, with one template variable.
    fn setup(&self) {
        self.ok(
            &["--password-stdin", "init", "--global"],
            &format!("{PASSWORD}\n"),
        );
        self.ok(&["init"], "");
        self.ok(&["add", "db"], "");
        self.ok(&["field", "add", "db", "password", "--secret"], "");
        self.ok(&["set", "db#password", "-e", "dev", "--stdin"], SECRET);
        self.ok(&["field", "add", "db", "url", "--type", "template"], "");
        self.ok(
            &["set", "db#url", "--stdin"],
            "postgres://app:{{db#password}}@localhost/app",
        );
        self.ok(&["var", "add", "DATABASE_URL", "db#url"], "");
    }
}

fn print_var_command(var: &str) -> Vec<String> {
    if cfg!(windows) {
        vec!["cmd".into(), "/C".into(), format!("echo %{var}%")]
    } else {
        vec!["sh".into(), "-c".into(), format!("echo ${var}")]
    }
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out
}

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

struct Mcp {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: std::sync::mpsc::Receiver<String>,
}

impl Mcp {
    fn start(env: &Env, token: &str) -> Mcp {
        let mut c = env.cmd(&["mcp", "serve", "--token-name", token]);
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = c.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut m = Mcp {
            child,
            stdin,
            lines: rx,
        };
        m.send(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#);
        m.wait_for(1);
        m.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        m
    }

    fn send(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn wait_for(&mut self, id: u64) -> serde_json::Value {
        loop {
            let line = self
                .lines
                .recv_timeout(std::time::Duration::from_secs(60))
                .expect("MCP server answered");
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            if v["id"] == id {
                return v;
            }
        }
    }

    fn call(&mut self, id: u64, tool: &str, args: serde_json::Value) -> (bool, String) {
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": tool, "arguments": args }
        });
        self.send(&req.to_string());
        let v = self.wait_for(id);
        let result = &v["result"];
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        (result["isError"].as_bool().unwrap_or(false), text)
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
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
