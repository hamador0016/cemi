//! Connectors: where a key is created (origins) and where it is copied to
//! (destinations).
//!
//! Built in: Supabase API keys (origin), GitHub Actions secrets, Supabase
//! function secrets and `.env` files (destinations), and commands (both).
//! Anyone can add a provider as an external program, `cemi-connector-<name>`,
//! that speaks JSON on stdin/stdout (see docs/connectors.md).
//!
//! Values travel only in request bodies and stdin, never as arguments.
//! Credentials for providers are references to other records of the vault.

mod command;
mod github;
mod http;
mod supabase;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::refs::Ref;
use crate::resolve;
use crate::workspace::Workspace;

pub use command::connector_program;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "connector", rename_all = "kebab-case")]
pub enum OriginSpec {
    /// A Supabase secret API key (`sb_secret_…`), created and deleted through
    /// the Management API.
    SupabaseKey {
        project: String,
        /// Reference to a Supabase access token.
        token: String,
        /// Base name for the keys; Cemí adds the date.
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// A program of yours: `<command> create` prints a new value;
    /// `<command> revoke` gets the old value on stdin.
    Command { command: Vec<String> },
    /// `cemi-connector-<name>`.
    External {
        name: String,
        #[serde(default)]
        config: BTreeMap<String, String>,
        /// Option name to a reference; resolved when the connector runs.
        #[serde(default)]
        secrets: BTreeMap<String, String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "connector", rename_all = "kebab-case")]
pub enum DestSpec {
    /// A GitHub Actions secret of a repository, or of one of its environments.
    Github {
        /// owner/name
        repo: String,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        environment: Option<String>,
        /// Reference to a token. None: ask the GitHub CLI (`gh auth token`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// A Supabase Edge Function secret.
    SupabaseSecret {
        project: String,
        name: String,
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// One variable of a `.env` file on this computer.
    Dotenv { file: PathBuf, key: String },
    /// A program that receives the value on stdin, like
    /// `gh secret set NAME` or `wrangler secret put NAME`.
    Command { command: Vec<String> },
    External {
        name: String,
        #[serde(default)]
        config: BTreeMap<String, String>,
        #[serde(default)]
        secrets: BTreeMap<String, String>,
    },
}

/// A value created by an origin.
pub struct NewKey {
    pub value: Zeroizing<String>,
    /// The provider's id for it, to delete it later.
    pub provider_id: Option<String>,
}

pub enum OriginState {
    Alive,
    /// The provider no longer has this key.
    Gone,
    Unknown,
}

pub enum Revoked {
    Done,
    /// The connector cannot revoke; the reason says what to do by hand.
    Manual(String),
}

/// What a destination reports about its current value, without the value.
pub enum Observed {
    /// An opaque marker: a digest, a hash or an update time.
    Remote(String),
    Missing,
    /// This kind of destination cannot be observed.
    Unknown,
}

impl OriginSpec {
    pub fn describe(&self) -> String {
        match self {
            OriginSpec::SupabaseKey { project, name, .. } => {
                format!("Supabase project {project}: secret API key \"{name}_…\"")
            }
            OriginSpec::Command { command } => format!("command `{}`", command.join(" ")),
            OriginSpec::External { name, .. } => format!("connector {name}"),
        }
    }

    /// Credentials this origin reads from the vault.
    pub fn references(&self) -> Vec<&str> {
        match self {
            OriginSpec::SupabaseKey { token, .. } => vec![token.as_str()],
            OriginSpec::External { secrets, .. } => secrets.values().map(String::as_str).collect(),
            OriginSpec::Command { .. } => vec![],
        }
    }
}

impl DestSpec {
    pub fn describe(&self) -> String {
        match self {
            DestSpec::Github {
                repo,
                name,
                environment,
                ..
            } => match environment {
                Some(e) => format!("GitHub {repo}: secret {name} (environment {e})"),
                None => format!("GitHub {repo}: secret {name}"),
            },
            DestSpec::SupabaseSecret { project, name, .. } => {
                format!("Supabase project {project}: function secret {name}")
            }
            DestSpec::Dotenv { file, key } => format!("{} ({key})", file.display()),
            DestSpec::Command { command } => format!("command `{}`", command.join(" ")),
            DestSpec::External { name, .. } => format!("connector {name}"),
        }
    }

    pub fn references(&self) -> Vec<&str> {
        match self {
            DestSpec::Github { token, .. } => token.iter().map(String::as_str).collect(),
            DestSpec::SupabaseSecret { token, .. } => vec![token.as_str()],
            DestSpec::External { secrets, .. } => secrets.values().map(String::as_str).collect(),
            DestSpec::Dotenv { .. } | DestSpec::Command { .. } => vec![],
        }
    }

    /// Checks the options before the destination is saved.
    pub fn validate(&self) -> Result<()> {
        match self {
            DestSpec::Github {
                repo,
                name,
                api_url,
                ..
            } => {
                github::validate(repo, name)?;
                if let Some(u) = api_url {
                    http::check_url(u)?;
                }
            }
            DestSpec::SupabaseSecret {
                project,
                name,
                api_url,
                ..
            } => {
                supabase::validate_project(project)?;
                supabase::validate_secret_name(name)?;
                if let Some(u) = api_url {
                    http::check_url(u)?;
                }
            }
            DestSpec::Dotenv { file, key } => {
                crate::dotenv::check_var_name(key)?;
                if !file.is_absolute() {
                    bail!("internal error: .env paths are stored absolute");
                }
            }
            DestSpec::Command { command } => {
                if command.is_empty() {
                    bail!("give the command after --");
                }
            }
            DestSpec::External { name, .. } => command::validate_connector_name(name)?,
        }
        Ok(())
    }
}

impl OriginSpec {
    pub fn validate(&self) -> Result<()> {
        match self {
            OriginSpec::SupabaseKey {
                project,
                name,
                api_url,
                ..
            } => {
                supabase::validate_project(project)?;
                supabase::validate_key_name(name)?;
                if let Some(u) = api_url {
                    http::check_url(u)?;
                }
            }
            OriginSpec::Command { command } => {
                if command.is_empty() {
                    bail!("give the command after --");
                }
            }
            OriginSpec::External { name, .. } => command::validate_connector_name(name)?,
        }
        Ok(())
    }
}

/// Resolves a credential reference stored in a connector.
fn credential(ws: &mut Workspace, reference: &str, env: Option<&str>) -> Result<Zeroizing<String>> {
    let r = Ref::parse(reference)?;
    let v = resolve::resolve(ws, &r, env)
        .with_context(|| format!("cannot read the credential {reference}"))?;
    let text = v.text()?;
    Ok(Zeroizing::new(text.trim().to_string()))
}

fn resolve_secrets(
    ws: &mut Workspace,
    secrets: &BTreeMap<String, String>,
    env: Option<&str>,
) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let mut out = BTreeMap::new();
    for (k, r) in secrets {
        out.insert(k.clone(), credential(ws, r, env)?);
    }
    Ok(out)
}

/// Creates a new value at the origin.
pub fn create(spec: &OriginSpec, ws: &mut Workspace, env: Option<&str>) -> Result<NewKey> {
    match spec {
        OriginSpec::SupabaseKey {
            project,
            token,
            name,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            supabase::create_key(api_url.as_deref(), &token, project, name)
        }
        OriginSpec::Command { command } => command::origin_create(command),
        OriginSpec::External {
            name,
            config,
            secrets,
        } => {
            let secrets = resolve_secrets(ws, secrets, env)?;
            command::external_create(name, config, &secrets)
        }
    }
}

/// Revokes an old value at the origin.
pub fn revoke(
    spec: &OriginSpec,
    ws: &mut Workspace,
    env: Option<&str>,
    provider_id: Option<&str>,
    old_value: &[u8],
    compromised: bool,
) -> Result<Revoked> {
    match spec {
        OriginSpec::SupabaseKey {
            project,
            token,
            api_url,
            ..
        } => {
            let Some(id) = provider_id else {
                return Ok(Revoked::Manual(format!(
                    "Cemí did not create this key, so it does not know its id. Delete it in the Supabase dashboard (project {project}, API keys)."
                )));
            };
            let token = credential(ws, token, env)?;
            supabase::delete_key(api_url.as_deref(), &token, project, id, compromised)?;
            Ok(Revoked::Done)
        }
        OriginSpec::Command { command } => command::origin_revoke(command, old_value, compromised),
        OriginSpec::External {
            name,
            config,
            secrets,
        } => {
            let secrets = resolve_secrets(ws, secrets, env)?;
            command::external_revoke(name, config, &secrets, provider_id, old_value, compromised)
        }
    }
}

/// Whether the provider still has the key.
pub fn origin_state(
    spec: &OriginSpec,
    ws: &mut Workspace,
    env: Option<&str>,
    provider_id: Option<&str>,
) -> Result<OriginState> {
    match (spec, provider_id) {
        (
            OriginSpec::SupabaseKey {
                project,
                token,
                api_url,
                ..
            },
            Some(id),
        ) => {
            let token = credential(ws, token, env)?;
            supabase::key_exists(api_url.as_deref(), &token, project, id).map(|alive| {
                if alive {
                    OriginState::Alive
                } else {
                    OriginState::Gone
                }
            })
        }
        _ => Ok(OriginState::Unknown),
    }
}

/// Sends a value to a destination.
pub fn write(spec: &DestSpec, ws: &mut Workspace, env: Option<&str>, value: &[u8]) -> Result<()> {
    match spec {
        DestSpec::Github {
            repo,
            name,
            environment,
            token,
            api_url,
        } => {
            let token = github::token(ws, token.as_deref(), api_url.as_deref(), env)?;
            github::put_secret(
                api_url.as_deref(),
                &token,
                repo,
                environment.as_deref(),
                name,
                text(value)?,
            )
        }
        DestSpec::SupabaseSecret {
            project,
            name,
            token,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            supabase::set_secret(api_url.as_deref(), &token, project, name, text(value)?)
        }
        DestSpec::Dotenv { file, key } => write_dotenv(file, key, text(value)?),
        DestSpec::Command { command } => command::dest_write(command, value),
        DestSpec::External {
            name,
            config,
            secrets,
        } => {
            let secrets = resolve_secrets(ws, secrets, env)?;
            command::external_write(name, config, &secrets, value)
        }
    }
}

/// What the destination holds now (without reading a value back).
pub fn observe(spec: &DestSpec, ws: &mut Workspace, env: Option<&str>) -> Result<Observed> {
    match spec {
        DestSpec::Github {
            repo,
            name,
            environment,
            token,
            api_url,
        } => {
            let token = github::token(ws, token.as_deref(), api_url.as_deref(), env)?;
            github::secret_updated_at(
                api_url.as_deref(),
                &token,
                repo,
                environment.as_deref(),
                name,
            )
        }
        DestSpec::SupabaseSecret {
            project,
            name,
            token,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            supabase::secret_digest(api_url.as_deref(), &token, project, name)
        }
        DestSpec::Dotenv { file, key } => observe_dotenv(file, key),
        DestSpec::Command { .. } => Ok(Observed::Unknown),
        DestSpec::External {
            name,
            config,
            secrets,
        } => {
            let secrets = resolve_secrets(ws, secrets, env)?;
            command::external_observe(name, config, &secrets)
        }
    }
}

/// Explains, for people, a remote marker that differs from the one Cemí saw
/// after its own write. The marker itself stays opaque for comparisons.
pub fn describe_change(spec: &DestSpec, marker: &str) -> String {
    match spec {
        DestSpec::Github { .. } => match marker
            .strip_prefix("updated ")
            .and_then(|t| t.parse::<jiff::Timestamp>().ok())
        {
            Some(at) => format!("updated {}", crate::ui::when(at, "%Y-%m-%d %H:%M")),
            None => marker.to_string(),
        },
        DestSpec::SupabaseSecret { .. } => "its digest changed".into(),
        DestSpec::Dotenv { .. } => "the file has another value".into(),
        DestSpec::Command { .. } | DestSpec::External { .. } => marker.to_string(),
    }
}

/// Runs a verification command with the value on stdin; exit code 0 means
/// the value works.
pub fn verify(command: &[String], value: &[u8]) -> Result<()> {
    command::dest_write(command, value)
}

fn text(value: &[u8]) -> Result<&str> {
    std::str::from_utf8(value)
        .map_err(|_| anyhow!("this value is binary; this destination only takes text"))
}

fn write_dotenv(file: &Path, key: &str, value: &str) -> Result<()> {
    let old = match std::fs::read_to_string(file) {
        Ok(t) => Zeroizing::new(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Zeroizing::new(String::new()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", file.display())),
    };
    let new = Zeroizing::new(crate::dotenv::set(&old, key, value)?);
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    crate::vault::atomic_write(file, new.as_bytes())
        .with_context(|| format!("cannot write {}", file.display()))
}

fn observe_dotenv(file: &Path, key: &str) -> Result<Observed> {
    let text = match std::fs::read_to_string(file) {
        Ok(t) => Zeroizing::new(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Observed::Missing),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", file.display())),
    };
    Ok(match crate::dotenv::get(&text, key)? {
        Some(v) => Observed::Remote(crate::crypto::sha256_hex(v.as_bytes())),
        None => Observed::Missing,
    })
}

/// True when `file` is tracked by git (a `.env` with real values should not be).
pub fn tracked_by_git(file: &Path) -> bool {
    let Some(dir) = file.parent() else {
        return false;
    };
    let Some(name) = file.file_name() else {
        return false;
    };
    std::process::Command::new(crate::runner::resolve_program("git"))
        .arg("ls-files")
        .arg("--error-unmatch")
        .arg(name)
        .current_dir(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
