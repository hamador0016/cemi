//! Helpers shared by the end-to-end tests.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use assert_cmd::cargo::cargo_bin;

pub const PASSWORD: &str = "correct horse battery staple";
pub const SECRET: &str = "s3cr3t-Pa55word-xyz";

pub struct Env {
    _tmp: tempfile::TempDir,
    pub home: PathBuf,
    pub sessions: PathBuf,
    pub project: PathBuf,
}

impl Env {
    pub fn new() -> Env {
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

    pub fn cmd(&self, args: &[&str]) -> Command {
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
    pub fn run(&self, args: &[&str], stdin: &str) -> (i32, String, String) {
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

    pub fn ok(&self, args: &[&str], stdin: &str) -> String {
        let (code, out, err) = self.run(args, stdin);
        assert_eq!(code, 0, "cemi {args:?} failed:\n{out}\n{err}");
        out
    }

    /// A global vault plus a project vault linked to it, with one template variable.
    pub fn setup(&self) {
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

pub fn print_var_command(var: &str) -> Vec<String> {
    if cfg!(windows) {
        vec!["cmd".into(), "/C".into(), format!("echo %{var}%")]
    } else {
        vec!["sh".into(), "-c".into(), format!("echo ${var}")]
    }
}

pub fn files_under(dir: &Path) -> Vec<PathBuf> {
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

pub struct Mcp {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: std::sync::mpsc::Receiver<String>,
}

impl Mcp {
    pub fn start(env: &Env, token: &str) -> Mcp {
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

    pub fn send(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
    }

    pub fn wait_for(&mut self, id: u64) -> serde_json::Value {
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

    pub fn call(&mut self, id: u64, tool: &str, args: serde_json::Value) -> (bool, String) {
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
