//! Everything the app does with a vault, without a window, so it can be
//! tested: unlocking, the views of the vault and of a record, and the
//! decision to show or copy a value.
//!
//! The vault is never kept open: each call loads it read-only (taking the
//! vault's shared lock only for that call), so the command line can write to
//! it while the app is open. Only the vault key stays in memory, zeroed when
//! the vault closes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use cemi::cmd_shared;
use cemi::crypto::AgeKey;
use cemi::model::{ApproveWith, FieldKind, Record, SHARED, Value, memory_keys};
use cemi::presence::Check;
use cemi::refs::{Ref, VaultSel};
use cemi::resolve::{self, Resolved};
use cemi::session;
use cemi::vault::{HEADER_FILE, Header, Vault};
use cemi::workspace::Workspace;
use jiff::Timestamp;
use serde::Serialize;
use zeroize::Zeroizing;

/// Name written to the audit log for what the app does.
pub const ACTOR: &str = "desktop";

/// Wrong passwords in a row before the app waits.
pub const MAX_TRIES: u32 = 3;
/// How long the app waits after [`MAX_TRIES`] wrong passwords.
pub const LOCKOUT: Duration = Duration::from_secs(30);
/// The pause after each wrong password.
pub const WRONG_PASSWORD_DELAY: Duration = Duration::from_secs(1);

// ----- the global vault and its session -----

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub exists: bool,
    pub dir: String,
    /// Minutes a session stays open without use (the command line's setting).
    pub ttl_minutes: i64,
}

pub fn vault_info(global_dir: &Path) -> VaultInfo {
    VaultInfo {
        exists: global_dir.join(HEADER_FILE).is_file(),
        dir: global_dir.display().to_string(),
        ttl_minutes: session::ttl().as_mins(),
    }
}

/// The open vault: its folder and its key. The key text is zeroed on drop.
pub struct Opened {
    pub dir: PathBuf,
    pub vault_id: String,
    identity: Zeroizing<String>,
    /// The key is also in the system's credential store, shared with the
    /// command line, which keeps it open for the same time.
    pub shared: bool,
    /// When the vault closes if the session is not shared.
    own_expiry: Timestamp,
}

impl Opened {
    fn new(dir: &Path, vault_id: &str, key: &AgeKey, shared: bool) -> Opened {
        Opened {
            dir: dir.to_path_buf(),
            vault_id: vault_id.to_string(),
            identity: key.secret_text(),
            shared,
            own_expiry: Timestamp::now() + session::ttl(),
        }
    }

    fn key(&self) -> Result<AgeKey> {
        AgeKey::parse(&self.identity)
    }

    /// When the vault closes, or `None` if it already has: the session ended,
    /// or `cemi lock` ended it.
    pub fn expires(&self) -> Option<Timestamp> {
        if self.shared {
            session::expires(&self.vault_id)
        } else {
            Some(self.own_expiry).filter(|e| *e > Timestamp::now())
        }
    }

    /// Seconds until the vault closes (0 when it has).
    pub fn remaining_secs(&self) -> i64 {
        self.expires()
            .map(|e| e.duration_since(Timestamp::now()).as_secs().max(0))
            .unwrap_or(0)
    }

    /// Restarts the countdown, like any use of the vault from the command line.
    pub fn touch(&mut self) {
        if self.shared
            && let Ok(key) = self.key()
        {
            let _ = session::store(&self.vault_id, &key);
        }
        self.own_expiry = Timestamp::now() + session::ttl();
    }

    /// Loads the vault read-only, after checking it is still open.
    pub fn load(&mut self) -> Result<Vault> {
        if self.expires().is_none() {
            return Err(locked_error());
        }
        let vault = Vault::load(&self.dir, self.key()?, false)?;
        if vault.header.id != self.vault_id {
            bail!("the vault in {} was replaced", self.dir.display());
        }
        self.touch();
        Ok(vault)
    }

    /// Closes the vault: the key leaves memory and, with `end_session`, the
    /// shared session ends too (like `cemi lock`).
    pub fn close(self, end_session: bool) {
        if end_session {
            session::clear(&self.vault_id);
        }
    }
}

/// The error text the interface recognises as "the vault closed".
pub const LOCKED: &str = "locked";

fn locked_error() -> anyhow::Error {
    anyhow!(LOCKED)
}

/// An open session of the global vault, if there is one (opened by the
/// command line or by an earlier run of the app).
pub fn resume(global_dir: &Path) -> Option<Opened> {
    let header = Header::read(global_dir).ok()?;
    let key = session::load(&header.id)?;
    Some(Opened::new(global_dir, &header.id, &key, true))
}

/// Counts wrong passwords: after [`MAX_TRIES`] in a row, nothing is tried
/// for [`LOCKOUT`].
#[derive(Debug, Default)]
pub struct Limiter {
    failures: u32,
    blocked_until: Option<Instant>,
}

impl Limiter {
    /// `Err(seconds)` while blocked.
    pub fn check(&self, now: Instant) -> std::result::Result<(), u64> {
        match self.blocked_until {
            Some(until) if until > now => Err((until - now).as_secs_f64().ceil() as u64),
            _ => Ok(()),
        }
    }

    pub fn failed(&mut self, now: Instant) {
        self.failures += 1;
        if self.failures >= MAX_TRIES {
            self.failures = 0;
            self.blocked_until = Some(now + LOCKOUT);
        }
    }

    pub fn succeeded(&mut self) {
        self.failures = 0;
        self.blocked_until = None;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnlockError {
    NoVault,
    WrongPassword,
    /// Too many wrong passwords: seconds to wait.
    Wait(u64),
    Other(String),
}

/// Opens the global vault with its password. With `keep`, the key goes to
/// the system's credential store like `cemi` does, so the command line and
/// the app share the session and its countdown.
pub fn unlock(
    global_dir: &Path,
    password: &str,
    keep: bool,
    limiter: &mut Limiter,
    now: Instant,
) -> std::result::Result<Opened, UnlockError> {
    if !global_dir.join(HEADER_FILE).is_file() {
        return Err(UnlockError::NoVault);
    }
    limiter.check(now).map_err(UnlockError::Wait)?;
    let header = Header::read(global_dir).map_err(|e| UnlockError::Other(format!("{e:#}")))?;
    let key = match header.unlock_with_password(password) {
        Ok(Some(key)) => key,
        Ok(None) => {
            limiter.failed(now);
            return Err(UnlockError::WrongPassword);
        }
        Err(e) => return Err(UnlockError::Other(format!("{e:#}"))),
    };
    limiter.succeeded();
    let shared = keep && session::enabled() && session::store(&header.id, &key).is_ok();
    Ok(Opened::new(global_dir, &header.id, &key, shared))
}

// ----- the vault view -----

#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Nothing to do.
    Ok,
    /// Something to look at soon (`cemi status` lists it).
    Warn,
    /// Expired, expiring this week, or an unfinished rotation.
    Bad,
    /// No notes yet.
    Bare,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityItem {
    pub id: String,
    /// Empty for the root of the vault.
    pub name: String,
    pub parent: Option<String>,
    pub depth: usize,
    pub path: String,
    pub has_children: bool,
    pub records: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordItem {
    pub id: String,
    pub entity: String,
    pub name: String,
    pub path: String,
    pub purpose: Option<String>,
    /// Every note, for searching.
    pub notes: String,
    pub status: Status,
    pub attention: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultView {
    pub root: String,
    /// In tree order: each entity comes right before its children.
    pub entities: Vec<EntityItem>,
    pub records: Vec<RecordItem>,
    pub unreadable: usize,
}

pub fn vault_view(v: &Vault) -> VaultView {
    let root = v.root_id();
    let mut entities = Vec::new();
    let mut stack = vec![(root.clone(), 0usize)];
    while let Some((id, depth)) = stack.pop() {
        let e = &v.entities[&id];
        let children = v.children(&id);
        entities.push(EntityItem {
            id: id.clone(),
            name: e.name.clone(),
            parent: e.parent.clone(),
            depth,
            path: v.entity_path_string(&id),
            has_children: !children.is_empty(),
            records: v
                .records
                .values()
                .filter(|r| r.entity == id && !r.archived)
                .count(),
        });
        for c in children.iter().rev() {
            stack.push((c.id.clone(), depth + 1));
        }
    }

    let mut attention: BTreeMap<String, (bool, Vec<String>)> = BTreeMap::new();
    let records_by_path: BTreeMap<String, &Record> = v
        .records
        .values()
        .filter(|r| !r.archived)
        .map(|r| (v.record_path(r), r))
        .collect();
    for a in cmd_shared::attention(v, None) {
        let record_path = a.what.split('#').next().unwrap_or_default();
        if records_by_path.contains_key(record_path) {
            let slot = attention.entry(record_path.to_string()).or_default();
            slot.0 |= a.urgent;
            let field = a.what.split_once('#').map(|(_, f)| f);
            slot.1.push(match field {
                Some(f) => format!("{f}: {}", a.detail),
                None => a.detail,
            });
        }
    }

    let records = records_by_path
        .iter()
        .map(|(path, r)| {
            let purpose = r.memory.get(memory_keys::PURPOSE).cloned();
            let (urgent, items) = attention.remove(path).unwrap_or_default();
            let status = if urgent {
                Status::Bad
            } else if purpose.is_none() {
                Status::Bare
            } else if !items.is_empty() {
                Status::Warn
            } else {
                Status::Ok
            };
            RecordItem {
                id: r.id.clone(),
                entity: r.entity.clone(),
                name: r.name.clone(),
                path: path.clone(),
                purpose,
                notes: r.memory.values().cloned().collect::<Vec<_>>().join("\n"),
                status,
                attention: items,
            }
        })
        .collect();

    VaultView {
        root,
        entities,
        records,
        unreadable: v.unreadable.len(),
    }
}

// ----- one record -----

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldView {
    pub name: String,
    pub kind: String,
    pub secret: bool,
    /// Showing or copying it needs the person to confirm.
    pub confirm: bool,
    /// "value", "empty" or "external".
    pub state: &'static str,
    /// Only for fields that are not secret: the value itself.
    pub value: Option<String>,
    pub file_name: Option<String>,
    /// The number of the current version (1 is the first).
    pub version: Option<usize>,
    /// Where the value lives when it is not stored here.
    pub external: Option<String>,
    /// The value is the one shared by every environment.
    pub shared: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryItem {
    pub key: String,
    pub text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestinationView {
    pub field: String,
    /// `None` for the value shared by every environment.
    pub env: Option<String>,
    pub kind: String,
    pub description: String,
    pub last_sent: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordView {
    pub id: String,
    pub name: String,
    pub path: String,
    pub entity_path: String,
    pub envs: Vec<String>,
    pub env: Option<String>,
    pub protected: bool,
    pub purpose: Option<String>,
    pub fields: Vec<FieldView>,
    /// Known notes first, in their usual order, then any other.
    pub memory: Vec<MemoryItem>,
    pub destinations: Vec<DestinationView>,
}

fn needs_confirm(secret: bool, kind: FieldKind) -> bool {
    secret || kind == FieldKind::Template
}

fn find_record<'a>(v: &'a Vault, record_id: &str) -> Result<&'a Record> {
    v.records
        .get(record_id)
        .filter(|r| !r.archived)
        .ok_or_else(|| anyhow!("that record is no longer in the vault"))
}

/// The environment to show: the one asked for if the record has it,
/// otherwise its first environment.
fn pick_env(envs: &[String], wanted: Option<&str>) -> Option<String> {
    match wanted {
        Some(w) if envs.iter().any(|e| e == w) => Some(w.to_string()),
        _ => envs.first().cloned(),
    }
}

pub fn record_view(v: &Vault, record_id: &str, env: Option<&str>) -> Result<RecordView> {
    let r = find_record(v, record_id)?;
    let envs = v.effective_envs(&r.entity);
    let env = pick_env(&envs, env);
    let fields = r
        .fields
        .iter()
        .map(|f| {
            let confirm = needs_confirm(f.secret, f.kind);
            let slot = f.slot_for(env.as_deref());
            let current = slot.and_then(|(_, s)| s.current_version());
            let external = slot.and_then(|(_, s)| s.external.clone());
            let state = match (current, &external) {
                (Some(_), _) => "value",
                (None, Some(_)) => "external",
                (None, None) => "empty",
            };
            let (value, file_name) = match current.map(|c| &c.value) {
                Some(Value::File { name, .. }) => (None, Some(name.clone())),
                Some(Value::Text { text }) if !confirm => (Some(text.expose().to_string()), None),
                _ => (None, None),
            };
            FieldView {
                name: f.name.clone(),
                kind: f.kind.to_string(),
                secret: f.secret,
                confirm,
                state,
                value,
                file_name,
                version: slot.and_then(|(_, s)| s.active_index()).map(|i| i + 1),
                external,
                shared: slot.is_some_and(|(k, _)| k == SHARED),
            }
        })
        .collect();

    let mut memory: Vec<MemoryItem> = memory_keys::ALL
        .iter()
        .filter_map(|k| {
            r.memory.get(*k).map(|t| MemoryItem {
                key: k.to_string(),
                text: t.clone(),
            })
        })
        .collect();
    memory.extend(
        r.memory
            .iter()
            .filter(|(k, _)| !memory_keys::ALL.contains(&k.as_str()))
            .map(|(k, t)| MemoryItem {
                key: k.clone(),
                text: t.clone(),
            }),
    );

    let destinations = r
        .fields
        .iter()
        .flat_map(|f| {
            f.destinations.iter().map(|d| DestinationView {
                field: f.name.clone(),
                env: d.env_opt().map(str::to_string),
                kind: destination_kind(&d.spec),
                description: d.spec.describe(),
                last_sent: d.last.as_ref().map(|l| l.at.to_string()),
            })
        })
        .collect();

    Ok(RecordView {
        id: r.id.clone(),
        name: r.name.clone(),
        path: v.record_path(r),
        entity_path: v.entity_path_string(&r.entity),
        protected: env.as_deref().is_some_and(|e| v.is_protected(e)),
        envs,
        env,
        purpose: r.memory.get(memory_keys::PURPOSE).cloned(),
        fields,
        memory,
        destinations,
    })
}

fn destination_kind(spec: &cemi::connectors::DestSpec) -> String {
    use cemi::connectors::DestSpec as D;
    match spec {
        D::Github { .. } => "GitHub",
        D::SupabaseSecret { .. } => "Supabase",
        D::CloudflareWorker { .. } => "Cloudflare",
        D::Netlify { .. } => "Netlify",
        D::Vercel { .. } => "Vercel",
        D::Gitlab { .. } => "GitLab",
        D::Fly { .. } => "Fly.io",
        D::AwsSecret { .. } => "AWS Secrets Manager",
        D::AwsParameter { .. } => "AWS Parameter Store",
        D::Dotenv { .. } => ".env",
        D::Ssh { .. } => "SSH",
        D::Command { .. } => "command",
        D::External { name, .. } => return name.clone(),
    }
    .to_string()
}

// ----- showing and copying a value -----

/// How the person confirms before a value leaves the vault.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Method {
    /// The field is not secret: nothing to confirm (like `cemi reveal`).
    None,
    Password,
    /// Windows Hello or Touch ID, with the password when the device cannot.
    Device,
}

/// What a value request needs: the field's secrecy and the vault's
/// `approve_with` setting, as the command line decides it.
pub fn method_for(v: &Vault, record_id: &str, field: &str) -> Result<Method> {
    let r = find_record(v, record_id)?;
    let f = r
        .field(field)
        .ok_or_else(|| anyhow!("{} has no field {field:?}", r.name))?;
    if !needs_confirm(f.secret, f.kind) {
        return Ok(Method::None);
    }
    Ok(
        match v.root().approve_with.unwrap_or(ApproveWith::Password) {
            ApproveWith::Password => Method::Password,
            ApproveWith::Device => Method::Device,
        },
    )
}

/// The answer to a request to show or copy a value.
#[derive(Debug, PartialEq, Eq)]
pub enum Auth {
    Granted {
        by: Method,
    },
    /// Ask for the password (with the reason the device check could not run).
    NeedPassword {
        reason: Option<String>,
    },
    /// The person cancelled the device check.
    Refused,
    WrongPassword,
    /// Too many wrong passwords: seconds to wait.
    Wait(u64),
}

/// Decides whether a value may leave the vault. `presence` asks the
/// operating system for the person (only called for [`Method::Device`]
/// without a password); `password_ok` checks a typed password.
pub fn authorize(
    method: Method,
    password: Option<&str>,
    limiter: &mut Limiter,
    now: Instant,
    presence: impl FnOnce() -> Check,
    password_ok: impl FnOnce(&str) -> Result<bool>,
) -> Result<Auth> {
    if method == Method::None {
        return Ok(Auth::Granted { by: Method::None });
    }
    let Some(password) = password else {
        if method == Method::Password {
            return Ok(Auth::NeedPassword { reason: None });
        }
        return Ok(match presence() {
            Check::Verified => Auth::Granted { by: Method::Device },
            Check::Refused => Auth::Refused,
            Check::Unavailable(why) => Auth::NeedPassword { reason: Some(why) },
        });
    };
    if let Err(secs) = limiter.check(now) {
        return Ok(Auth::Wait(secs));
    }
    if password_ok(password)? {
        limiter.succeeded();
        Ok(Auth::Granted {
            by: Method::Password,
        })
    } else {
        limiter.failed(now);
        Ok(Auth::WrongPassword)
    }
}

/// Checks the vault password again, without opening anything.
pub fn password_matches(dir: &Path, password: &str) -> Result<bool> {
    Ok(Header::read(dir)?.unlock_with_password(password)?.is_some())
}

/// Which value: a field of a record, in an environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueRequest {
    pub record_id: String,
    pub field: String,
    pub env: Option<String>,
}

/// How long a value stays on screen after it is revealed.
pub const REVEAL_TIME: Duration = Duration::from_secs(20);

/// While a revealed value is on screen, copying that same value does not ask
/// again (the person just confirmed). Nothing else is covered.
#[derive(Debug)]
pub struct Grace {
    req: ValueRequest,
    by: Method,
    until: Instant,
}

impl Grace {
    pub fn new(req: &ValueRequest, by: Method, now: Instant) -> Grace {
        Grace {
            req: req.clone(),
            by,
            until: now + REVEAL_TIME,
        }
    }

    /// How the person confirmed, if this covers `req` at `now`.
    pub fn covers(&self, req: &ValueRequest, now: Instant) -> Option<Method> {
        (self.req == *req && now < self.until).then_some(self.by)
    }
}

pub struct Released {
    pub reference: String,
    pub env: Option<String>,
    pub text: Zeroizing<String>,
    pub file_name: Option<String>,
    pub version: Option<usize>,
}

/// Resolves the value (templates included), hands it to `deliver` and writes
/// `action` to the audit log. Call only after [`authorize`] granted it.
pub fn release(
    v: Vault,
    req: &ValueRequest,
    action: &str,
    deliver: impl FnOnce(&str) -> Result<()>,
) -> Result<Released> {
    let (reference, env, version) = {
        let r = find_record(&v, &req.record_id)?;
        let f = r
            .field(&req.field)
            .ok_or_else(|| anyhow!("{} has no field {:?}", r.name, req.field))?;
        let envs = v.effective_envs(&r.entity);
        let env = match req.env.as_deref() {
            Some(e) if !envs.iter().any(|x| x == e) => {
                bail!("environment {e:?} does not exist for {}", v.record_path(r))
            }
            other => other.map(str::to_string),
        };
        let version = f
            .slot_for(env.as_deref())
            .and_then(|(_, s)| s.active_index())
            .map(|i| i + 1);
        let reference = Ref {
            vault: VaultSel::Global,
            entities: v.entity_path(&r.entity),
            record: r.name.clone(),
            field: Some(f.name.clone()),
        };
        (reference, env, version)
    };
    let dir = v.dir.clone();
    let mut ws = Workspace::at(&dir, false)?;
    ws.adopt(v);
    let resolved: Resolved = resolve::resolve(&mut ws, &reference, env.as_deref())?;
    let text = resolved
        .text()
        .context("this value is a binary file; save it with `cemi reveal` in a terminal")?;
    deliver(&text)?;
    let v = ws.get(cemi::vault::Scope::Global).expect("adopted");
    // Like the command line: a log that cannot be written is reported, but
    // does not take back what was already done.
    let audited = cemi::audit::append(
        &v.dir,
        &v.header,
        cemi::audit::Event {
            actor: ACTOR,
            action,
            target: Some(reference.to_string()),
            env: env.clone(),
            detail: None,
        },
    );
    if let Err(e) = audited {
        eprintln!("could not write the audit log: {e:#}");
    }
    Ok(Released {
        reference: reference.to_string(),
        env,
        text,
        file_name: resolved.file_name,
        version,
    })
}

#[cfg(test)]
mod tests;
