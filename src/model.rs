//! Data model. Everything here is stored encrypted; nothing is a fixed schema.
//! Users name their own entities, records and fields.

use std::collections::BTreeMap;
use std::fmt;

use jiff::Timestamp;
use jiff::civil::Date;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::connectors::{DestSpec, OriginSpec};

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
    /// Only on the root entity: environments whose changes need a person's
    /// approval. `None` means the default ([`DEFAULT_PROTECTED`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<Vec<String>>,
    pub created: Timestamp,
    pub updated: Timestamp,
}

/// Environments protected when a vault has not chosen its own.
pub const DEFAULT_PROTECTED: &[&str] = &["prod", "production"];

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
    /// Set when the record came from another developer (`cemi share accept`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<Received>,
    pub created: Timestamp,
    pub updated: Timestamp,
}

/// Where a received record came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Received {
    /// The sender's public key.
    pub from: String,
    /// The share, so a newer bundle of the same share updates it.
    pub share: String,
    /// When the newest bundle accepted was made.
    pub at: Timestamp,
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
    /// Where a new value is created, per slot (environment or [`SHARED`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub origins: BTreeMap<String, Origin>,
    /// Every place the value is copied to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<Destination>,
    /// Command that checks a value works, per slot. Gets the value on stdin.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub verify: BTreeMap<String, Vec<String>>,
    /// HTTP APIs this value signs in to, called through Cemí's proxy so the
    /// caller never holds the value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apis: Vec<Api>,
}

impl Field {
    pub fn new(name: impl Into<String>, kind: FieldKind, secret: bool) -> Field {
        Field {
            name: name.into(),
            kind,
            secret,
            values: BTreeMap::new(),
            origins: BTreeMap::new(),
            destinations: Vec::new(),
            verify: BTreeMap::new(),
            apis: Vec::new(),
        }
    }

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

/// Where new values of a slot are created (a provider, or a command).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Origin {
    pub spec: OriginSpec,
    pub created: Timestamp,
}

/// A place a value is copied to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    /// Short id, unique within the field.
    pub id: String,
    /// Environment whose value goes here, or [`SHARED`].
    pub env: String,
    pub spec: DestSpec,
    /// The last successful delivery.
    #[serde(default)]
    pub last: Option<Delivery>,
    pub created: Timestamp,
}

impl Destination {
    /// The environment to resolve the value with.
    pub fn env_opt(&self) -> Option<&str> {
        (self.env != SHARED).then_some(self.env.as_str())
    }
}

/// An HTTP API that a value signs in to. Cemí's proxy adds the value to
/// requests for `base`, and only for the methods and paths in `allow`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Api {
    /// Short id, unique within the field.
    pub id: String,
    /// Environment whose value is used, or [`SHARED`].
    pub env: String,
    /// `https://host[/path]`. Requests never go anywhere else.
    pub base: String,
    /// Where the value goes in each request.
    pub auth: Vec<ApiAuth>,
    /// Rules like `GET /v1/*`. Nothing else is allowed.
    pub allow: Vec<String>,
    pub created: Timestamp,
}

impl Api {
    pub fn env_opt(&self) -> Option<&str> {
        (self.env != SHARED).then_some(self.env.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApiAuth {
    /// `Authorization: Bearer <value>`
    Bearer,
    /// `<name>: <value>`
    Header { name: String },
    /// HTTP basic authentication with the value as the user name and an
    /// empty password (Stripe's style).
    Basic,
    /// `?<name>=<value>` in the URL.
    Query { name: String },
}

impl fmt::Display for ApiAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiAuth::Bearer => f.write_str("bearer"),
            ApiAuth::Header { name } => write!(f, "header:{name}"),
            ApiAuth::Basic => f.write_str("basic"),
            ApiAuth::Query { name } => write!(f, "query:{name}"),
        }
    }
}

impl std::str::FromStr for ApiAuth {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<ApiAuth> {
        let valid_name = |n: &str| {
            !n.is_empty()
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        };
        Ok(match s.split_once(':') {
            None if s == "bearer" => ApiAuth::Bearer,
            None if s == "basic" => ApiAuth::Basic,
            Some(("header", n)) if valid_name(n) => ApiAuth::Header { name: n.into() },
            Some(("query", n)) if valid_name(n) => ApiAuth::Query { name: n.into() },
            _ => {
                anyhow::bail!("--auth must be bearer, basic, header:NAME or query:NAME, got {s:?}")
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delivery {
    /// SHA-256 of the value that was sent.
    pub fingerprint: String,
    /// What the destination reported afterwards (a digest or an update time),
    /// to notice changes made outside Cemí. Opaque.
    #[serde(default)]
    pub remote: Option<String>,
    pub at: Timestamp,
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
        self.archive_active();
        self.external = None;
        self.versions.push(Version {
            value,
            state: VersionState::Active,
            at: Timestamp::now(),
            actor: actor.to_string(),
            note,
            provider_id: None,
        });
    }

    fn archive_active(&mut self) {
        for v in self.versions.iter_mut() {
            if v.state == VersionState::Active {
                v.state = VersionState::Archived;
            }
        }
    }

    /// Index of the newest pending version (an unfinished rotation).
    pub fn pending_index(&self) -> Option<usize> {
        self.versions
            .iter()
            .rposition(|v| v.state == VersionState::Pending)
    }

    /// Index of the current active version.
    pub fn active_index(&self) -> Option<usize> {
        self.versions
            .iter()
            .rposition(|v| v.state == VersionState::Active)
    }

    /// Makes version `i` the active one; the previous active one is archived.
    pub fn activate(&mut self, i: usize) {
        self.archive_active();
        self.versions[i].state = VersionState::Active;
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
    /// The provider's id for this key (to revoke it later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
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
    /// Send current values to their destinations (protected environments
    /// still need a person's approval).
    Push,
    /// Replace a key: create, propagate, verify, revoke the old one
    /// (protected environments still need a person's approval).
    Rotate,
    /// Call HTTP APIs through Cemí's proxy, within each API's rules, without
    /// receiving the key.
    Api,
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Permission::Read => "read",
            Permission::Generate => "generate",
            Permission::Run => "run",
            Permission::Push => "push",
            Permission::Rotate => "rotate",
            Permission::Api => "api",
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

/// A project folder whose `cemi.toml` uses this vault. Cemí remembers it the
/// first time it opens the vault from there, so `cemi deps` can search every
/// project, not only the current one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownProject {
    pub id: String,
    /// The folder that holds `cemi.toml`, as an absolute path.
    pub path: String,
    pub added: Timestamp,
}

/// What this vault gave another developer with `cemi share`, so `cemi status`
/// can say when a shared value changed afterwards. No values, only digests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentShare {
    pub id: String,
    /// The entity shared (its id in this vault).
    pub entity: String,
    /// The receiver's public key.
    pub to: String,
    /// A name for the receiver, given with `--name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub envs: Vec<String>,
    /// `<record id>#<field>#<env>` to the SHA-256 of the value sent.
    pub sent: BTreeMap<String, String>,
    pub at: Timestamp,
}

/// A change an AI client asked for in a protected environment. Nothing
/// happens until a person runs `cemi approve`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub requested_by: String,
    pub action: ApprovalAction,
    pub created: Timestamp,
    pub expires: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalAction {
    Push {
        /// `record#field`, with its vault prefix.
        reference: String,
        env: String,
    },
    Rotate {
        reference: String,
        env: String,
        leaked: bool,
        generate: bool,
    },
}

impl fmt::Display for ApprovalAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalAction::Push { reference, env } => write!(f, "push {reference} in {env}"),
            ApprovalAction::Rotate {
                reference,
                env,
                leaked,
                generate,
            } => {
                write!(f, "rotate {reference} in {env}")?;
                if *leaked {
                    f.write_str(" (leaked: the old key is revoked at once)")?;
                }
                if *generate {
                    f.write_str(" (new value generated by Cemí)")?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Object {
    Entity(Entity),
    Record(Record),
    Token(Token),
    Launcher(Launcher),
    Approval(Approval),
    Project(KnownProject),
    Share(SentShare),
}

impl Object {
    pub fn id(&self) -> &str {
        match self {
            Object::Entity(e) => &e.id,
            Object::Record(r) => &r.id,
            Object::Token(t) => &t.id,
            Object::Launcher(l) => &l.id,
            Object::Approval(a) => &a.id,
            Object::Project(p) => &p.id,
            Object::Share(s) => &s.id,
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
        let mut f = Field::new("x", FieldKind::Text, true);
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
