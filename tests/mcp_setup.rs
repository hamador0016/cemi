//! `cemi mcp setup <client>`: writing each client's configuration file.

mod common;

use std::path::{Path, PathBuf};
use std::process::Stdio;

use common::*;

/// A test environment whose home and configuration folders are temporary.
struct Setup {
    env: Env,
    user: PathBuf,
}

impl Setup {
    fn new() -> Setup {
        let env = Env::new();
        env.setup();
        let user = env.project.parent().unwrap().join("user");
        std::fs::create_dir_all(&user).unwrap();
        env.ok(&["token", "create", "claude", "--allow", "read"], "");
        env.ok(
            &["--global", "token", "create", "claude", "--allow", "read"],
            "",
        );
        Setup { env, user }
    }

    fn app_data(&self) -> PathBuf {
        self.user.join("AppData").join("Roaming")
    }

    fn xdg(&self) -> PathBuf {
        self.user.join("xdg")
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let mut c = self.env.cmd(args);
        c.env("HOME", &self.user)
            .env("USERPROFILE", &self.user)
            .env("APPDATA", self.app_data())
            .env("XDG_CONFIG_HOME", self.xdg())
            .env_remove("CODEX_HOME")
            .env_remove("COPILOT_HOME")
            .stdin(Stdio::null());
        let out = c.output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn ok(&self, args: &[&str]) -> String {
        let (code, out, err) = self.run(args);
        assert_eq!(code, 0, "cemi {args:?} failed:\n{out}\n{err}");
        err
    }
}

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

const LOCAL_ARGS: [&str; 4] = ["mcp", "serve", "--token-name", "claude"];
const GLOBAL_ARGS: [&str; 5] = ["--global", "mcp", "serve", "--token-name", "claude"];

#[test]
fn project_vault_writes_project_files() {
    let s = Setup::new();
    let p = &s.env.project;

    s.ok(&["mcp", "setup", "cursor", "--token-name", "claude"]);
    let v = read_json(&p.join(".cursor/mcp.json"));
    assert_eq!(v["mcpServers"]["cemi"]["command"], "cemi");
    assert_eq!(
        v["mcpServers"]["cemi"]["args"],
        serde_json::json!(LOCAL_ARGS)
    );

    s.ok(&["mcp", "setup", "vscode", "--token-name", "claude"]);
    let v = read_json(&p.join(".mcp.json"));
    assert_eq!(v["mcpServers"]["cemi"]["type"], "stdio");
    assert_eq!(
        v["mcpServers"]["cemi"]["args"],
        serde_json::json!(LOCAL_ARGS)
    );

    s.ok(&["mcp", "setup", "gemini", "--token-name", "claude"]);
    let v = read_json(&p.join(".gemini/settings.json"));
    assert_eq!(
        v["mcpServers"]["cemi"]["args"],
        serde_json::json!(LOCAL_ARGS)
    );

    s.ok(&["mcp", "setup", "zed", "--token-name", "claude"]);
    let v = read_json(&p.join(".zed/settings.json"));
    assert_eq!(v["context_servers"]["cemi"]["command"], "cemi");

    s.ok(&["mcp", "setup", "devin", "--token-name", "claude"]);
    let v = read_json(&p.join(".devin/mcp_config.json"));
    assert_eq!(v["mcpServers"]["cemi"]["command"], "cemi");

    let err = s.ok(&["mcp", "setup", "codex", "--token-name", "claude"]);
    assert!(err.contains("trust"), "{err}");
    let text = std::fs::read_to_string(p.join(".codex/config.toml")).unwrap();
    let v: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(v["mcp_servers"]["cemi"]["command"].as_str(), Some("cemi"));
    assert_eq!(
        v["mcp_servers"]["cemi"]["args"].as_array().unwrap().len(),
        LOCAL_ARGS.len()
    );

    // Running it again changes nothing.
    let before = std::fs::read_to_string(p.join(".cursor/mcp.json")).unwrap();
    let err = s.ok(&["mcp", "setup", "cursor", "--token-name", "claude"]);
    assert!(err.contains("already"), "{err}");
    assert_eq!(
        before,
        std::fs::read_to_string(p.join(".cursor/mcp.json")).unwrap()
    );

    // Nothing was written in the user's folders.
    assert!(
        files_under(&s.user).is_empty(),
        "{:?}",
        files_under(&s.user)
    );
}

#[test]
fn global_vault_writes_user_files() {
    let s = Setup::new();
    let u = &s.user;
    let setup =
        |client: &str| s.ok(&["--global", "mcp", "setup", client, "--token-name", "claude"]);

    setup("cursor");
    let v = read_json(&u.join(".cursor/mcp.json"));
    assert_eq!(
        v["mcpServers"]["cemi"]["args"],
        serde_json::json!(GLOBAL_ARGS)
    );

    setup("windsurf");
    let v = read_json(&u.join(".codeium/windsurf/mcp_config.json"));
    assert_eq!(
        v["mcpServers"]["cemi"]["args"],
        serde_json::json!(GLOBAL_ARGS)
    );

    setup("vscode");
    let v = read_json(&u.join(".copilot/mcp-config.json"));
    assert_eq!(v["mcpServers"]["cemi"]["tools"], serde_json::json!(["*"]));

    setup("gemini");
    read_json(&u.join(".gemini/settings.json"));

    setup("codex");
    let text = std::fs::read_to_string(u.join(".codex/config.toml")).unwrap();
    assert!(text.contains("[mcp_servers.cemi]"), "{text}");

    setup("claude-desktop");
    let desktop = if cfg!(windows) {
        s.app_data().join("Claude")
    } else if cfg!(target_os = "macos") {
        u.join("Library/Application Support/Claude")
    } else {
        s.xdg().join("Claude")
    };
    let v = read_json(&desktop.join("claude_desktop_config.json"));
    assert_eq!(
        v["mcpServers"]["cemi"]["args"],
        serde_json::json!(GLOBAL_ARGS)
    );

    setup("zed");
    let zed = if cfg!(windows) {
        s.app_data().join("Zed")
    } else if cfg!(target_os = "macos") {
        u.join(".config/zed")
    } else {
        s.xdg().join("zed")
    };
    read_json(&zed.join("settings.json"));

    setup("devin");
    let devin = if cfg!(windows) {
        s.app_data().join("devin")
    } else {
        s.xdg().join("devin")
    };
    read_json(&devin.join("mcp_config.json"));

    // Nothing in the project.
    for dir in [
        ".cursor",
        ".gemini",
        ".zed",
        ".codex",
        ".devin",
        ".mcp.json",
    ] {
        assert!(!s.env.project.join(dir).exists(), "{dir}");
    }
}

#[test]
fn merges_into_existing_files() {
    let s = Setup::new();
    let file = s.user.join(".gemini").join("settings.json");
    write(
        &file,
        r#"{
  "theme": "GitHub",
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "server-github"]
    },
    "cemi": {
      "command": "old-cemi"
    }
  },
  "general": { "vimMode": true }
}
"#,
    );
    let err = s.ok(&[
        "--global",
        "mcp",
        "setup",
        "gemini",
        "--token-name",
        "claude",
    ]);
    assert!(err.contains(&file.display().to_string()), "{err}");
    assert!(err.contains("Replaced"), "{err}");
    let text = std::fs::read_to_string(&file).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["theme"], "GitHub");
    assert_eq!(v["general"]["vimMode"], true);
    assert_eq!(v["mcpServers"]["github"]["command"], "npx");
    assert_eq!(v["mcpServers"]["cemi"]["command"], "cemi");
    assert_eq!(
        v["mcpServers"]["cemi"]["args"],
        serde_json::json!(GLOBAL_ARGS)
    );
    // Members keep their order and their text.
    assert!(text.find("theme").unwrap() < text.find("general").unwrap());
    assert!(text.contains(r#""general": { "vimMode": true }"#), "{text}");

    // TOML keeps comments and other tables.
    let codex = s.user.join(".codex/config.toml");
    write(
        &codex,
        "# my Codex settings\nmodel = \"gpt-5\"\n\n[mcp_servers.docs]\ncommand = \"npx\" # docs server\nargs = [\"-y\", \"docs-mcp\"]\n",
    );
    s.ok(&[
        "--global",
        "mcp",
        "setup",
        "codex",
        "--token-name",
        "claude",
    ]);
    let text = std::fs::read_to_string(&codex).unwrap();
    assert!(
        text.starts_with("# my Codex settings\nmodel = \"gpt-5\""),
        "{text}"
    );
    assert!(text.contains("command = \"npx\" # docs server"), "{text}");
    let v: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(v["mcp_servers"]["cemi"]["command"].as_str(), Some("cemi"));
    assert_eq!(v["mcp_servers"]["docs"]["command"].as_str(), Some("npx"));
}

#[test]
fn refuses_to_rewrite_json_with_comments() {
    let s = Setup::new();
    let file = s.env.project.join(".zed/settings.json");
    let original = "// Zed settings\n{\n  \"theme\": \"One Dark\", // the theme\n  \"context_servers\": {},\n}\n";
    write(&file, original);
    let (code, out, err) = s.run(&["mcp", "setup", "zed", "--token-name", "claude"]);
    assert_eq!(code, 1, "{out}\n{err}");
    // (The project folder may be shown through a symbolic link, as on macOS.)
    assert!(err.contains("settings.json"), "{err}");
    assert!(err.contains("left as it was"), "{err}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
    // The snippet to paste.
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["context_servers"]["cemi"]["command"], "cemi");
}

#[test]
fn print_only_prints() {
    let s = Setup::new();
    let (code, out, err) = s.run(&[
        "mcp",
        "setup",
        "cursor",
        "--token-name",
        "claude",
        "--print",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains(".cursor"), "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v["mcpServers"]["cemi"]["args"],
        serde_json::json!(LOCAL_ARGS)
    );
    assert!(!s.env.project.join(".cursor").exists());

    let out = s.run(&[
        "--global",
        "mcp",
        "setup",
        "codex",
        "--token-name",
        "claude",
        "--print",
    ]);
    assert!(out.1.contains("[mcp_servers.cemi]"), "{out:?}");
    assert!(files_under(&s.user).is_empty());

    let out = s.run(&[
        "mcp",
        "setup",
        "claude-code",
        "--token-name",
        "claude",
        "--print",
    ]);
    assert!(
        out.1
            .contains("claude mcp add --scope project cemi -- cemi mcp serve"),
        "{out:?}"
    );

    // `other` still prints the generic snippet.
    let out = s.run(&["mcp", "setup", "other", "--token-name", "claude"]);
    assert_eq!(out.0, 0);
    let v: serde_json::Value = serde_json::from_str(&out.1).unwrap();
    assert_eq!(v["mcpServers"]["cemi"]["command"], "cemi");
}

#[test]
fn user_only_clients_need_the_global_vault() {
    let s = Setup::new();
    let (code, _, err) = s.run(&["mcp", "setup", "claude-desktop", "--token-name", "claude"]);
    assert_ne!(code, 0);
    assert!(err.contains("--global"), "{err}");
    assert!(files_under(&s.user).is_empty());

    let (code, _, err) = s.run(&["mcp", "setup", "no-such-client", "--token-name", "claude"]);
    assert_ne!(code, 0);
    assert!(err.contains("claude-desktop"), "{err}");

    let (code, _, err) = s.run(&["mcp", "setup", "cursor", "--token-name", "missing"]);
    assert_ne!(code, 0);
    assert!(err.contains("no token"), "{err}");
}
