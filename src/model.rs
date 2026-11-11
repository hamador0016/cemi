//! Data model. Everything here is stored encrypted; nothing is a fixed schema.
//! Users name their own entities, records and fields.

use std::collections::BTreeMap;
use std::fmt;

use jiff::Timestamp;
use jiff::civil::Date;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Key used in `Field::values` for a value shared by every environment.
pub const SHARED: &str = "*";

/// Memory keys that Cemí understands. Users can add any other key.
pub mod memory_keys {
    pub const PURPOSE: &str = "purpose";
    pub const USED_IN: &str = "used_in";
    pub const ROTATE: &str = "rotate";
    pub const IF_LOST: &str = "if_lost";
    pub const IF_LEAKED: &str = "if_leaked";
    pub const EXPIRES: &str = "expires";
    pub const BACKUP: &str = "backup";
    pub const LINKS: &str = "links";
    pub const DELICATE: &str = "delicate";

    pub const ALL: &[&str] = &[
        PURPOSE, USED_IN, ROTATE, IF_LOST, IF_LEAKED, EXPIRES, BACKUP, LINKS, DELICATE,
    ];
}

/// Text that must never show up in logs or debug output.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct Sensitive(Zeroizing<String>);

impl Sensitive {
    pub fn new(text: impl Into<String>) -> Sensitive {
        Sensitive(Zeroizing::new(text.into()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Sensitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[hidden]")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub id: String,
    /// Empty for the root entity of a vault.
    pub name: String,
    pub parent: Option<String>,
    /// age identity that encrypts this entity's records and child entities.
    pub identity: Sensitive,
    #[serde(default)]
    pub envs: Vec<String>,
    #[serde(default)]
    pub memory: BTreeMap<String, String>,
    #[serde(default)]
    pub tasks: Vec<Task>,
    pub created: Timestamp,
    pub updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub name: String,
    pub every: Every,
    pub last_done: Option<Date>,
    pub created: Date,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Every {
    Day,
    Week,
    Month,
    Year,
}

impl Task {
    pub fn due(&self) -> Date {
        let base = self.last_done.unwrap_or(self.created);
        let span = match self.every {
            Every::Day => jiff::Span::new().days(1),
            Every::Week => jiff::Span::new().weeks(1),
            Every::Month => jiff::Span::new().months(1),
            Every::Year => jiff::Span::new().years(1),
        };
        base.checked_add(span).unwrap_or(base)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    /// Id of the entity that holds this record.
    pub entity: String,
    pub name: String,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub memory: BTreeMap<String, String>,
    #[serde(default)]
    pub archived: bool,
    pub created: Timestamp,
    pub updated: Timestamp,
}

impl Record {
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    pub fn field_mut(&mut self, name: &str) -> Option<&mut Field> {
        self.fields.iter_mut().find(|f| f.name == name)
    }

    pub fn has_secrets(&self) -> bool {
        self.fields.iter().any(|f| f.secret)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    Multiline,
    File,
    Url,
    Date,
    Number,
    /// Built from other fields: `postgres://app:{{db#password}}@{{db#host}}/x`.
    Template,
}

impl fmt::Display for FieldKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            FieldKind::Text => "text",
            FieldKind::Multiline => "multiline",
            FieldKind::File => "file",
            FieldKind::Url => "url",
            FieldKind::Date => "date",
            FieldKind::Number => "number",
            FieldKind::Template => "template",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
    pub secret: bool,
    /// Environment name (or [`SHARED`]) to its value slot.
    #[serde(default)]
    pub values: BTreeMap<String, Slot>,
}

impl Field {
    /// The slot that applies to `env`: its own, or the shared one.
    pub fn slot_for(&self, env: Option<&str>) -> Option<(&str, &Slot)> {
        if let Some(env) = env
            && let Some((k, s)) = self.values.get_key_value(env)
        {
            return Some((k.as_str(), s));
        }
        self.values
            .get_key_value(SHARED)
            .map(|(k, s)| (k.as_str(), s))
    }

    pub fn current(&self, env: Option<&str>) -> Option<&Value> {
        self.slot_for(env).and_then(|(_, s)| s.current())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Slot {
    #[serde(default)]
    pub versions: Vec<Version>,
    /// Set when the value is intentionally not stored here, e.g.
    /// "lives only in GitHub environment production".
    #[serde(default)]
    pub external: Option<String>,
}

impl Slot {
    pub fn current(&self) -> Option<&Value> {
        self.versions
            .iter()
            .rev()
            .find(|v| v.state == VersionState::Active)
            .map(|v| &v.value)
    }

    pub fn current_version(&self) -> Option<&Version> {
        self.versions
            .iter()
            .rev()
            .find(|v| v.state == VersionState::Active)
    }

    /// Adds a new active version and archives the previous one (never deletes it).
    pub fn push(&mut self, value: Value, actor: &str, note: Option<String>) {
        for v in self.versions.iter_mut() {
            if v.state == VersionState::Active {
                v.state = VersionState::Archived;
            }
        }
        self.external = None;
        self.versions.push(Version {
            value,
            state: VersionState::Active,
            at: Timestamp::now(),
            actor: actor.to_string(),
            note,
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub value: Value,
    pub state: VersionState,
    pub at: Timestamp,
    pub actor: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VersionState {
    Active,
    Pending,
    /// Replaced by a newer value but kept (e.g. an old key that opens old backups).
    Archived,
    /// Revoked at the provider.
    Retired,
}

impl fmt::Display for VersionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            VersionState::Active => "active",
            VersionState::Pending => "pending",
            VersionState::Archived => "archived",
            VersionState::Retired => "retired",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Value {
    Text {
        text: Sensitive,
    },
    /// File contents, base64 encoded.
    File {
        name: String,
        data: Sensitive,
    },
}

impl Value {
    pub fn text(t: impl Into<String>) -> Value {
        Value::Text {
            text: Sensitive::new(t),
        }
    }

    /// Raw bytes of the value.
    pub fn bytes(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Value::Text { text } => Zeroizing::new(text.expose().as_bytes().to_vec()),
            Value::File { data, .. } => Zeroizing::new(
                data_encoding::BASE64
                    .decode(data.expose().as_bytes())
                    .unwrap_or_default(),
            ),
        }
    }
}

/// Access granted to an AI client (or any program) through `cemi mcp serve`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub name: String,
    /// SHA-256 of the token text. The token itself is never stored.
    pub hash: String,
    /// Entity paths this token can see. Empty means the whole vault.
    #[serde(default)]
    pub entities: Vec<String>,
    /// Environments this token can use. Empty means all.
    #[serde(default)]
    pub envs: Vec<String>,
    pub allow: Vec<Permission>,
    pub expires: Option<Timestamp>,
    pub created: Timestamp,
    #[serde(default)]
    pub revoked: Option<Timestamp>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// List and search structure, read memory. Never values.
    Read,
    /// Generate new random values (without seeing them).
    Generate,
    /// Run allowlisted project commands with values injected.
    Run,
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Permission::Read => "read",
            Permission::Generate => "generate",
            Permission::Run => "run",
        })
    }
}

/// A third-party MCP server started by `cemi mcp launch` with secrets injected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Launcher {
    pub id: String,
    pub name: String,
    pub command: Vec<String>,
    /// Environment variable name to a Cemí reference.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub created: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Object {
    Entity(Entity),
    Record(Record),
    Token(Token),
    Launcher(Launcher),
}

impl Object {
    pub fn id(&self) -> &str {
        match self {
            Object::Entity(e) => &e.id,
            Object::Record(r) => &r.id,
            Object::Token(t) => &t.id,
            Object::Launcher(l) => &l.id,
        }
    }
}

/// What is written (encrypted) to each object file.
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub format: u32,
    pub object: Object,
}

pub const OBJECT_FORMAT: u32 = 1;

/// Validates a user-chosen name for an entity, record, field or environment.
pub fn validate_name(name: &str, what: &str) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("{what} name cannot be empty");
    }
    if name != name.trim() {
        anyhow::bail!("{what} name cannot start or end with spaces");
    }
    if name.contains(['/', '#']) || name.chars().any(char::is_control) {
        anyhow::bail!("{what} name cannot contain '/', '#' or control characters: {name:?}");
    }
    if name.starts_with("global:") || name.starts_with("local:") {
        anyhow::bail!("{what} name cannot start with 'global:' or 'local:'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_debug_is_hidden() {
        assert_eq!(format!("{:?}", Sensitive::new("abc")), "[hidden]");
        assert!(!format!("{:?}", Value::text("abc")).contains("abc"));
    }

    #[test]
    fn slot_keeps_history() {
        let mut slot = Slot::default();
        slot.push(Value::text("one"), "test", None);
        slot.push(Value::text("two"), "test", None);
        assert_eq!(slot.versions.len(), 2);
        assert_eq!(slot.versions[0].state, VersionState::Archived);
        match slot.current().unwrap() {
            Value::Text { text } => assert_eq!(text.expose(), "two"),
            _ => panic!(),
        }
    }

    #[test]
    fn env_falls_back_to_shared() {
        let mut f = Field {
            name: "x".into(),
            kind: FieldKind::Text,
            secret: true,
            values: BTreeMap::new(),
        };
        f.values
            .entry(SHARED.into())
            .or_default()
            .push(Value::text("all"), "t", None);
        f.values
            .entry("prod".into())
            .or_default()
            .push(Value::text("p"), "t", None);
        assert_eq!(f.slot_for(Some("dev")).unwrap().0, SHARED);
        assert_eq!(f.slot_for(Some("prod")).unwrap().0, "prod");
    }

    #[test]
    fn names_are_validated() {
        assert!(validate_name("id de la llave", "field").is_ok());
        assert!(validate_name("a/b", "field").is_err());
        assert!(validate_name(" a", "field").is_err());
        assert!(validate_name("", "field").is_err());
    }
}
