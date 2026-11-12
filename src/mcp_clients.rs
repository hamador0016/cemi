//! `cemi mcp setup`: where each AI client keeps its MCP servers, and how to
//! add Cemí to that file without touching anything else in it.
//!
//! The entry holds no secret: only the command that starts `cemi mcp serve`.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::Value;
use serde_json::value::RawValue;

/// The name of the server in every client's configuration.
pub const SERVER: &str = "cemi";

/// Every name `cemi mcp setup` accepts.
pub const CLIENT_NAMES: [&str; 10] = [
    "claude-code",
    "claude-desktop",
    "cursor",
    "vscode",
    "windsurf",
    "devin",
    "zed",
    "codex",
    "gemini",
    "other",
];

/// A client whose configuration file Cemí edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    ClaudeDesktop,
    Cursor,
    VsCode,
    Windsurf,
    Devin,
    Zed,
    Codex,
    Gemini,
}

/// How a client's file is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A JSON object whose member `key` maps server names to servers.
    Json(&'static str),
    /// `[mcp_servers.<name>]` tables in TOML.
    Toml,
}

impl Client {
    pub fn parse(name: &str) -> Option<Client> {
        Some(match name {
            "claude-desktop" => Client::ClaudeDesktop,
            "cursor" => Client::Cursor,
            "vscode" => Client::VsCode,
            "windsurf" => Client::Windsurf,
            "devin" => Client::Devin,
            "zed" => Client::Zed,
            "codex" => Client::Codex,
            "gemini" => Client::Gemini,
            _ => return None,
        })
    }

    pub fn title(self) -> &'static str {
        match self {
            Client::ClaudeDesktop => "Claude Desktop",
            Client::Cursor => "Cursor",
            Client::VsCode => "VS Code (GitHub Copilot)",
            Client::Windsurf => "Windsurf",
            Client::Devin => "Devin",
            Client::Zed => "Zed",
            Client::Codex => "Codex",
            Client::Gemini => "Gemini CLI",
        }
    }

    pub fn format(self) -> Format {
        match self {
            Client::Zed => Format::Json("context_servers"),
            Client::Codex => Format::Toml,
            _ => Format::Json("mcpServers"),
        }
    }

    /// The project-level file, relative to the project folder, for clients
    /// that read one.
    pub fn project_file(self) -> Option<&'static str> {
        match self {
            Client::ClaudeDesktop | Client::Windsurf => None,
            Client::Cursor => Some(".cursor/mcp.json"),
            Client::VsCode => Some(".mcp.json"),
            Client::Devin => Some(".devin/mcp_config.json"),
            Client::Zed => Some(".zed/settings.json"),
            Client::Codex => Some(".codex/config.toml"),
            Client::Gemini => Some(".gemini/settings.json"),
        }
    }

    /// The file for every project of this user.
    pub fn user_file(self) -> Result<PathBuf> {
        Ok(match self {
            Client::ClaudeDesktop => {
                let dir = if cfg!(windows) {
                    app_data()?
                } else if cfg!(target_os = "macos") {
                    home()?.join("Library").join("Application Support")
                } else {
                    xdg_config()?
                };
                dir.join("Claude").join("claude_desktop_config.json")
            }
            Client::Cursor => home()?.join(".cursor").join("mcp.json"),
            Client::VsCode => env_dir("COPILOT_HOME")
                .map_or_else(|| home().map(|h| h.join(".copilot")), Ok)?
                .join("mcp-config.json"),
            Client::Windsurf => home()?
                .join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
            Client::Devin => {
                let dir = if cfg!(windows) {
                    app_data()?
                } else {
                    xdg_config()?
                };
                dir.join("devin").join("mcp_config.json")
            }
            Client::Zed => {
                let dir = if cfg!(windows) {
                    app_data()?.join("Zed")
                } else if cfg!(target_os = "macos") {
                    home()?.join(".config").join("zed")
                } else {
                    xdg_config()?.join("zed")
                };
                dir.join("settings.json")
            }
            Client::Codex => env_dir("CODEX_HOME")
                .map_or_else(|| home().map(|h| h.join(".codex")), Ok)?
                .join("config.toml"),
            Client::Gemini => home()?.join(".gemini").join("settings.json"),
        })
    }

    /// The server entry, in the shape this client documents.
    pub fn entry(self, args: &[String]) -> Value {
        match self {
            Client::Cursor => serde_json::json!({
                "type": "stdio", "command": SERVER, "args": args,
            }),
            Client::VsCode => serde_json::json!({
                "type": "stdio", "command": SERVER, "args": args, "tools": ["*"],
            }),
            Client::Zed => serde_json::json!({
                "command": SERVER, "args": args, "env": {},
            }),
            _ => serde_json::json!({ "command": SERVER, "args": args }),
        }
    }

    /// What to add to the client's file, for people to paste.
    pub fn snippet(self, args: &[String]) -> String {
        match self.format() {
            Format::Json(key) => {
                let v = serde_json::json!({ key: { SERVER: self.entry(args) } });
                serde_json::to_string_pretty(&v).expect("a JSON value")
            }
            Format::Toml => {
                let mut doc = toml_edit::DocumentMut::new();
                set_toml_server(&mut doc, args).expect("an empty document");
                doc.to_string()
            }
        }
    }
}

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn home() -> Result<PathBuf> {
    std::env::home_dir().context("cannot find your home folder")
}

fn app_data() -> Result<PathBuf> {
    env_dir("APPDATA").map_or_else(|| home().map(|h| h.join("AppData").join("Roaming")), Ok)
}

fn xdg_config() -> Result<PathBuf> {
    env_dir("XDG_CONFIG_HOME").map_or_else(|| home().map(|h| h.join(".config")), Ok)
}

/// What [`write`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Created,
    Added,
    Replaced,
    Unchanged,
    /// The file could not be edited safely and was left as it was.
    Refused(String),
}

/// Adds or replaces the Cemí server in `path`, keeping everything else.
pub fn write(client: Client, path: &Path, args: &[String]) -> Result<Outcome> {
    let existing = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let text = match &existing {
        Some(bytes) => match std::str::from_utf8(bytes) {
            Ok(t) => t.to_string(),
            Err(_) => return Ok(Outcome::Refused("it is not UTF-8 text".into())),
        },
        None => String::new(),
    };
    let edited = match client.format() {
        Format::Json(key) => merge_json(&text, key, &client.entry(args)),
        Format::Toml => merge_toml(&text, args),
    };
    let (new_text, replaced) = match edited {
        Ok(Some(e)) => e,
        Ok(None) => return Ok(Outcome::Unchanged),
        Err(reason) => return Ok(Outcome::Refused(reason)),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    crate::vault::atomic_write(path, new_text.as_bytes())?;
    Ok(if existing.is_none() {
        Outcome::Created
    } else if replaced {
        Outcome::Replaced
    } else {
        Outcome::Added
    })
}

/// A JSON object's members in their order, each value as written.
struct Ordered(Vec<(String, Box<RawValue>)>);

impl<'de> Deserialize<'de> for Ordered {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Ordered, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Ordered, A::Error> {
                let mut out = Vec::new();
                while let Some(entry) = map.next_entry::<String, Box<RawValue>>()? {
                    out.push(entry);
                }
                Ok(Ordered(out))
            }
        }
        d.deserialize_map(V)
    }
}

impl Ordered {
    fn parse(text: &str) -> Option<Ordered> {
        if text.trim().is_empty() {
            return Some(Ordered(Vec::new()));
        }
        serde_json::from_str(text).ok()
    }

    /// Writes the object with `indent` before each member; values keep their
    /// own text.
    fn render(&self, indent: &str, close: &str) -> String {
        if self.0.is_empty() {
            return "{}".into();
        }
        let members: Vec<String> = self
            .0
            .iter()
            .map(|(k, v)| {
                format!(
                    "{indent}{}: {}",
                    serde_json::to_string(k).expect("a string"),
                    v.get()
                )
            })
            .collect();
        format!("{{\n{}\n{close}}}", members.join(",\n"))
    }
}

fn indent_lines(text: &str, indent: &str) -> String {
    text.replace('\n', &format!("\n{indent}"))
}

/// Puts `entry` as the server [`SERVER`] under `key`. `Ok(None)` when it is
/// already there; `Err` says why the file cannot be edited safely.
fn merge_json(
    text: &str,
    key: &str,
    entry: &Value,
) -> std::result::Result<Option<(String, bool)>, String> {
    let bom = text.starts_with('\u{feff}');
    let crlf = text.contains("\r\n");
    // JSON whitespace is the only place a raw line break can be.
    let body = text.trim_start_matches('\u{feff}').replace("\r\n", "\n");
    let mut top = Ordered::parse(&body).ok_or_else(|| {
        "it is not plain JSON (it may have comments or trailing commas)".to_string()
    })?;
    let at = top.0.iter().position(|(k, _)| k == key);
    let mut servers = match at {
        Some(i) => Ordered::parse(top.0[i].1.get())
            .ok_or_else(|| format!("its \"{key}\" is not an object"))?,
        None => Ordered(Vec::new()),
    };
    let new_raw = RawValue::from_string(indent_lines(
        &serde_json::to_string_pretty(entry).expect("a JSON value"),
        "    ",
    ))
    .expect("valid JSON");
    let mut replaced = false;
    match servers.0.iter().position(|(k, _)| k == SERVER) {
        Some(i) => {
            let old: Option<Value> = serde_json::from_str(servers.0[i].1.get()).ok();
            if old.as_ref() == Some(entry) {
                return Ok(None);
            }
            servers.0[i].1 = new_raw;
            replaced = true;
            let mut seen = false;
            servers.0.retain(|(k, _)| {
                let dup = k == SERVER && seen;
                seen |= k == SERVER;
                !dup
            });
        }
        None => servers.0.push((SERVER.to_string(), new_raw)),
    }
    let servers_raw = RawValue::from_string(servers.render("    ", "  ")).expect("valid JSON");
    match at {
        Some(i) => top.0[i].1 = servers_raw,
        None => top.0.push((key.to_string(), servers_raw)),
    }
    let mut out = top.render("  ", "");
    out.push('\n');
    serde_json::from_str::<Value>(&out).map_err(|e| format!("the result would not parse: {e}"))?;
    if crlf {
        out = out.replace('\n', "\r\n");
    }
    if bom {
        out.insert(0, '\u{feff}');
    }
    Ok(Some((out, replaced)))
}

fn set_toml_server(
    doc: &mut toml_edit::DocumentMut,
    args: &[String],
) -> std::result::Result<bool, String> {
    use toml_edit::{Array, Item, Table, value};
    let servers = doc.entry("mcp_servers").or_insert_with(|| {
        let mut t = Table::new();
        t.set_implicit(true);
        Item::Table(t)
    });
    let servers = servers
        .as_table_mut()
        .ok_or_else(|| "its mcp_servers is not a table".to_string())?;
    let mut t = Table::new();
    t["command"] = value(SERVER);
    t["args"] = value(args.iter().map(String::as_str).collect::<Array>());
    let replaced = servers.contains_key(SERVER);
    servers.insert(SERVER, Item::Table(t));
    Ok(replaced)
}

fn merge_toml(text: &str, args: &[String]) -> std::result::Result<Option<(String, bool)>, String> {
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| format!("it is not valid TOML: {e}"))?;
    if let Some(old) = doc
        .get("mcp_servers")
        .and_then(|s| s.get(SERVER))
        .and_then(|s| s.as_table_like())
    {
        let same_args = old.get("args").and_then(|a| a.as_array()).is_some_and(|a| {
            a.iter()
                .map(|v| v.as_str())
                .eq(args.iter().map(|s| Some(s.as_str())))
        });
        let same_command = old.get("command").and_then(|c| c.as_str()) == Some(SERVER);
        if same_args && same_command && old.len() == 2 {
            return Ok(None);
        }
    }
    let replaced = set_toml_server(&mut doc, args)?;
    Ok(Some((doc.to_string(), replaced)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<String> {
        ["mcp", "serve", "--token-name", "claude"]
            .map(String::from)
            .to_vec()
    }

    #[test]
    fn json_keeps_other_keys_and_their_order() {
        let text = "{\n  \"zeta\": 1,\n  \"mcpServers\": {\n    \"other\": {\n      \"command\": \"x\"\n    }\n  },\n  \"alpha\": [1, 2]\n}\n";
        let entry = Client::ClaudeDesktop.entry(&args());
        let (out, replaced) = merge_json(text, "mcpServers", &entry).unwrap().unwrap();
        assert!(!replaced);
        let zeta = out.find("zeta").unwrap();
        let alpha = out.find("alpha").unwrap();
        assert!(zeta < alpha, "{out}");
        assert!(out.contains("\"alpha\": [1, 2]"), "{out}");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert_eq!(v["mcpServers"]["cemi"], entry);
        // A second run changes nothing.
        assert!(merge_json(&out, "mcpServers", &entry).unwrap().is_none());
    }

    #[test]
    fn json_replaces_the_old_entry() {
        let text = r#"{"mcpServers":{"cemi":{"command":"old"},"b":{}}}"#;
        let entry = Client::Gemini.entry(&args());
        let (out, replaced) = merge_json(text, "mcpServers", &entry).unwrap().unwrap();
        assert!(replaced);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["mcpServers"]["cemi"], entry);
        assert!(v["mcpServers"]["b"].is_object());
    }

    #[test]
    fn json_with_comments_is_refused() {
        let text = "// settings\n{\n  \"theme\": \"One Dark\",\n}\n";
        assert!(merge_json(text, "context_servers", &Value::Null).is_err());
        assert!(merge_json("[]", "mcpServers", &Value::Null).is_err());
        assert!(merge_json(r#"{"mcpServers": 3}"#, "mcpServers", &Value::Null).is_err());
    }

    #[test]
    fn json_keeps_crlf_and_bom() {
        let text = "\u{feff}{\r\n  \"a\": 1\r\n}\r\n";
        let entry = Client::Cursor.entry(&args());
        let (out, _) = merge_json(text, "mcpServers", &entry).unwrap().unwrap();
        assert!(out.starts_with('\u{feff}'));
        assert!(!out.replace("\r\n", "").contains('\n'), "{out:?}");
    }

    #[test]
    fn toml_keeps_the_rest() {
        let text = "# my settings\nmodel = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\" # keep\n";
        let (out, replaced) = merge_toml(text, &args()).unwrap().unwrap();
        assert!(!replaced);
        assert!(out.starts_with("# my settings\nmodel = \"o3\""), "{out}");
        assert!(out.contains("command = \"x\" # keep"), "{out}");
        assert!(out.contains("[mcp_servers.cemi]"), "{out}");
        assert!(!out.contains("[mcp_servers]\n"), "{out}");
        let v: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(v["mcp_servers"]["cemi"]["command"].as_str(), Some("cemi"));
        assert!(merge_toml(&out, &args()).unwrap().is_none());
        assert!(merge_toml("not = [valid", &args()).is_err());
    }

    #[test]
    fn snippets_parse() {
        for c in [
            Client::ClaudeDesktop,
            Client::Cursor,
            Client::VsCode,
            Client::Windsurf,
            Client::Devin,
            Client::Zed,
            Client::Gemini,
        ] {
            let _: Value = serde_json::from_str(&c.snippet(&args())).unwrap();
        }
        let s = Client::Codex.snippet(&args());
        assert!(s.contains("[mcp_servers.cemi]"), "{s}");
        for name in CLIENT_NAMES {
            assert!(
                Client::parse(name).is_some() || name == "claude-code" || name == "other",
                "{name}"
            );
        }
    }
}
