//! Connectors: where a key is created (origins) and where it is copied to
//! (destinations).
//!
//! Built in: Supabase, Cloudflare, Resend and OpenAI API keys and AWS IAM
//! access keys (origins); GitHub Actions secrets, Supabase function secrets,
//! Cloudflare Workers secrets, Netlify, Vercel and GitLab variables, Fly.io
//! secrets, AWS Secrets Manager secrets and Parameter Store parameters,
//! `.env` files here or on a server over SSH (destinations); and commands
//! (both).
//! Anyone can add a provider as an external program, `cemi-connector-<name>`,
//! that speaks JSON on stdin/stdout (see docs/connectors.md).
//!
//! Values travel only in request bodies and stdin, never as arguments.
//! Credentials for providers are references to other records of the vault.

mod aws;
mod aws_iam;
mod aws_secrets;
mod aws_ssm;
mod cloudflare;
mod command;
mod fly;
mod github;
mod gitlab;
mod http;
mod netlify;
mod openai;
mod resend;
mod ssh;
mod supabase;
mod vercel;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::refs::Ref;
use crate::resolve;
use crate::workspace::Workspace;

pub use command::connector_program;
/// Plain http only for this computer; used for API addresses too.
pub use http::check_url;
/// Percent-encodes text for a URL path segment or a query value.
pub use http::segment as query_escape;

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
    /// A Cloudflare API token. A new one copies the permissions of the
    /// current one; the old one is deleted when the rotation is done.
    CloudflareToken {
        /// Reference to a token allowed to create and delete tokens.
        token: String,
        /// For account-owned tokens; None: tokens of your user.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
        /// Base name for the tokens; Cemí adds the date.
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// A Resend API key.
    ResendKey {
        /// Reference to a full-access Resend key.
        token: String,
        name: String,
        /// full_access or sending_access.
        permission: String,
        /// For sending_access: the only domain it may send from.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// An AWS IAM access key. The value is the secret access key; the access
    /// key id is the provider id, and optionally goes to `id_field`.
    AwsAccessKey {
        /// None: the user that owns the signing key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        /// References to the credentials that sign IAM requests.
        access_key_id: String,
        secret_access_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
        /// A field of the same record that gets each new key's access key id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id_field: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// An OpenAI API key of a project service account.
    OpenaiKey {
        project: String,
        service_account: String,
        /// Reference to an OpenAI Admin API key.
        token: String,
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
    /// A Cloudflare Workers secret.
    CloudflareWorker {
        account: String,
        script: String,
        name: String,
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// A Netlify environment variable of a site (or of the whole team), for
    /// one deploy context.
    Netlify {
        /// Team slug.
        account: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        site: Option<String>,
        key: String,
        context: String,
        /// Netlify's "contains secret values" (write-only once set).
        secret: bool,
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// A Vercel project environment variable for one target.
    Vercel {
        project: String,
        key: String,
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        team: Option<String>,
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// A GitLab CI/CD variable of a project.
    Gitlab {
        /// Numeric id or path (`acme/shop`).
        project: String,
        key: String,
        environment_scope: String,
        masked: bool,
        protected: bool,
        /// Masked and hidden (only when GitLab creates the variable).
        hidden: bool,
        token: String,
        /// For self-managed GitLab: https://HOST/api/v4.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// A Fly.io app secret.
    Fly {
        app: String,
        name: String,
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// An AWS Secrets Manager secret.
    AwsSecret {
        /// Name or ARN.
        secret_id: String,
        region: String,
        /// KMS key for a secret Cemí creates (default: aws/secretsmanager).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kms_key: Option<String>,
        access_key_id: String,
        secret_access_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// An AWS Systems Manager Parameter Store parameter (SecureString).
    AwsParameter {
        name: String,
        region: String,
        /// KMS key (default: the account's aws/ssm key).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kms_key: Option<String>,
        access_key_id: String,
        secret_access_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    /// One variable of a `.env` file on this computer.
    Dotenv { file: PathBuf, key: String },
    /// One variable of a `.env` file on a server, over SSH.
    Ssh {
        /// user@server, or a Host of ~/.ssh/config.
        host: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// Path on the server.
        file: String,
        key: String,
        /// Run on the server after the file changes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        restart: Option<String>,
        /// Another ssh program and its first arguments (tests).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        program: Option<Vec<String>>,
    },
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
            OriginSpec::CloudflareToken { account, name, .. } => match account {
                Some(a) => format!("Cloudflare account {a}: API token \"{name} …\""),
                None => format!("Cloudflare: API token \"{name} …\""),
            },
            OriginSpec::ResendKey { name, .. } => format!("Resend: API key \"{name} …\""),
            OriginSpec::AwsAccessKey { user, .. } => match user {
                Some(u) => format!("AWS IAM: access key of the user {u}"),
                None => "AWS IAM: access key of the signing user".into(),
            },
            OriginSpec::OpenaiKey {
                project,
                service_account,
                ..
            } => format!(
                "OpenAI project {project}: API key of the service account {service_account}"
            ),
            OriginSpec::Command { command } => format!("command `{}`", command.join(" ")),
            OriginSpec::External { name, .. } => format!("connector {name}"),
        }
    }

    /// Credentials this origin reads from the vault.
    pub fn references(&self) -> Vec<&str> {
        match self {
            OriginSpec::SupabaseKey { token, .. }
            | OriginSpec::CloudflareToken { token, .. }
            | OriginSpec::ResendKey { token, .. }
            | OriginSpec::OpenaiKey { token, .. } => vec![token.as_str()],
            OriginSpec::AwsAccessKey {
                access_key_id,
                secret_access_key,
                session_token,
                ..
            } => aws_refs(access_key_id, secret_access_key, session_token),
            OriginSpec::External { secrets, .. } => secrets.values().map(String::as_str).collect(),
            OriginSpec::Command { .. } => vec![],
        }
    }

    /// A field of the same record that a rotation fills with the new key's
    /// provider id (the AWS access key id), with its own destinations.
    pub fn id_field(&self) -> Option<&str> {
        match self {
            OriginSpec::AwsAccessKey { id_field, .. } => id_field.as_deref(),
            _ => None,
        }
    }
}

fn aws_refs<'a>(
    access_key_id: &'a str,
    secret_access_key: &'a str,
    session_token: &'a Option<String>,
) -> Vec<&'a str> {
    let mut out = vec![access_key_id, secret_access_key];
    out.extend(session_token.as_deref());
    out
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
            DestSpec::CloudflareWorker { script, name, .. } => {
                format!("Cloudflare Worker {script}: secret {name}")
            }
            DestSpec::Netlify {
                account,
                site,
                key,
                context,
                ..
            } => match site {
                Some(s) => format!("Netlify site {s}: {key} ({context})"),
                None => format!("Netlify team {account}: {key} ({context})"),
            },
            DestSpec::Vercel {
                project,
                key,
                target,
                ..
            } => format!("Vercel project {project}: {key} ({target})"),
            DestSpec::Gitlab {
                project,
                key,
                environment_scope,
                ..
            } => format!("GitLab project {project}: {key} ({environment_scope})"),
            DestSpec::Fly { app, name, .. } => format!("Fly app {app}: secret {name}"),
            DestSpec::AwsSecret {
                secret_id, region, ..
            } => format!("AWS Secrets Manager ({region}): {secret_id}"),
            DestSpec::AwsParameter { name, region, .. } => {
                format!("AWS Parameter Store ({region}): {name}")
            }
            DestSpec::Dotenv { file, key } => format!("{} ({key})", file.display()),
            DestSpec::Ssh {
                host, file, key, ..
            } => format!("{host}:{file} ({key})"),
            DestSpec::Command { command } => format!("command `{}`", command.join(" ")),
            DestSpec::External { name, .. } => format!("connector {name}"),
        }
    }

    pub fn references(&self) -> Vec<&str> {
        match self {
            DestSpec::Github { token, .. } => token.iter().map(String::as_str).collect(),
            DestSpec::SupabaseSecret { token, .. }
            | DestSpec::CloudflareWorker { token, .. }
            | DestSpec::Netlify { token, .. }
            | DestSpec::Vercel { token, .. }
            | DestSpec::Gitlab { token, .. }
            | DestSpec::Fly { token, .. } => vec![token.as_str()],
            DestSpec::AwsSecret {
                access_key_id,
                secret_access_key,
                session_token,
                ..
            }
            | DestSpec::AwsParameter {
                access_key_id,
                secret_access_key,
                session_token,
                ..
            } => aws_refs(access_key_id, secret_access_key, session_token),
            DestSpec::External { secrets, .. } => secrets.values().map(String::as_str).collect(),
            DestSpec::Dotenv { .. } | DestSpec::Ssh { .. } | DestSpec::Command { .. } => vec![],
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
            DestSpec::CloudflareWorker {
                account,
                script,
                name,
                api_url,
                ..
            } => {
                cloudflare::validate_account(account)?;
                cloudflare::validate_script(script)?;
                cloudflare::validate_secret_name(name)?;
                check_api(api_url)?;
            }
            DestSpec::Netlify {
                account,
                site,
                key,
                context,
                api_url,
                ..
            } => {
                netlify::validate(account, site.as_deref(), key, context)?;
                check_api(api_url)?;
            }
            DestSpec::Vercel {
                project,
                key,
                target,
                team,
                api_url,
                ..
            } => {
                vercel::validate(project, key, target, team.as_deref())?;
                check_api(api_url)?;
            }
            DestSpec::Gitlab {
                project,
                key,
                environment_scope,
                masked,
                hidden,
                api_url,
                ..
            } => {
                gitlab::validate(project, key, environment_scope)?;
                if *hidden && !*masked {
                    bail!("hidden GitLab variables are always masked: drop --no-mask");
                }
                check_api(api_url)?;
            }
            DestSpec::Fly {
                app, name, api_url, ..
            } => {
                fly::validate(app, name)?;
                check_api(api_url)?;
            }
            DestSpec::AwsSecret {
                secret_id,
                region,
                kms_key,
                api_url,
                ..
            } => {
                aws::validate_region(region)?;
                aws_secrets::validate(secret_id, kms_key.as_deref())?;
                check_api(api_url)?;
            }
            DestSpec::AwsParameter {
                name,
                region,
                kms_key,
                api_url,
                ..
            } => {
                aws::validate_region(region)?;
                aws_ssm::validate(name, kms_key.as_deref())?;
                check_api(api_url)?;
            }
            DestSpec::Dotenv { file, key } => {
                crate::dotenv::check_var_name(key)?;
                if !file.is_absolute() {
                    bail!("internal error: .env paths are stored absolute");
                }
            }
            DestSpec::Ssh {
                host,
                file,
                key,
                restart,
                program,
                ..
            } => {
                ssh::validate(host, file, restart.as_deref())?;
                crate::dotenv::check_var_name(key)?;
                if program.as_ref().is_some_and(Vec::is_empty) {
                    bail!("the ssh program cannot be empty");
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
            OriginSpec::CloudflareToken {
                account,
                name,
                api_url,
                ..
            } => {
                if let Some(a) = account {
                    cloudflare::validate_account(a)?;
                }
                cloudflare::validate_token_name(name)?;
                check_api(api_url)?;
            }
            OriginSpec::ResendKey {
                name,
                permission,
                domain,
                api_url,
                ..
            } => {
                resend::validate_name(name)?;
                resend::validate_permission(permission, domain.as_deref())?;
                check_api(api_url)?;
            }
            OriginSpec::AwsAccessKey {
                user,
                id_field,
                api_url,
                ..
            } => {
                if let Some(u) = user {
                    aws_iam::validate_user(u)?;
                }
                if let Some(f) = id_field {
                    crate::model::validate_name(f, "field")?;
                }
                check_api(api_url)?;
            }
            OriginSpec::OpenaiKey {
                project,
                service_account,
                name,
                api_url,
                ..
            } => {
                openai::validate(project, service_account, name)?;
                check_api(api_url)?;
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

fn check_api(api_url: &Option<String>) -> Result<()> {
    if let Some(u) = api_url {
        http::check_url(u)?;
    }
    Ok(())
}

/// Resolves a credential reference stored in a connector.
fn credential(ws: &mut Workspace, reference: &str, env: Option<&str>) -> Result<Zeroizing<String>> {
    let r = Ref::parse(reference)?;
    let v = resolve::resolve(ws, &r, env)
        .with_context(|| format!("cannot read the credential {reference}"))?;
    let text = v.text()?;
    Ok(Zeroizing::new(text.trim().to_string()))
}

/// Resolves the references of AWS credentials.
fn aws_credentials(
    ws: &mut Workspace,
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    env: Option<&str>,
) -> Result<aws::Credentials> {
    Ok(aws::Credentials {
        access_key_id: credential(ws, access_key_id, env)?,
        secret_access_key: credential(ws, secret_access_key, env)?,
        session_token: session_token.map(|t| credential(ws, t, env)).transpose()?,
    })
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

/// Creates a new value at the origin. `current` is the value in use now
/// (Cloudflare copies its permissions to the new token).
pub fn create(
    spec: &OriginSpec,
    ws: &mut Workspace,
    env: Option<&str>,
    current: Option<&[u8]>,
) -> Result<NewKey> {
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
        OriginSpec::CloudflareToken {
            token,
            account,
            name,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            let current = current.map(text).transpose()?;
            cloudflare::create_token(
                api_url.as_deref(),
                &token,
                account.as_deref(),
                name,
                current,
            )
        }
        OriginSpec::ResendKey {
            token,
            name,
            permission,
            domain,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            resend::create_key(
                api_url.as_deref(),
                &token,
                name,
                permission,
                domain.as_deref(),
            )
        }
        OriginSpec::AwsAccessKey {
            user,
            access_key_id,
            secret_access_key,
            session_token,
            api_url,
            ..
        } => {
            let creds = aws_credentials(
                ws,
                access_key_id,
                secret_access_key,
                session_token.as_deref(),
                env,
            )?;
            aws_iam::create_key(api_url.as_deref(), &creds, user.as_deref())
        }
        OriginSpec::OpenaiKey {
            project,
            service_account,
            token,
            name,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            openai::create_key(api_url.as_deref(), &token, project, service_account, name)
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
        OriginSpec::CloudflareToken {
            token,
            account,
            api_url,
            ..
        } => {
            let token = credential(ws, token, env)?;
            cloudflare::delete_token(
                api_url.as_deref(),
                &token,
                account.as_deref(),
                provider_id,
                text(old_value)?,
            )?;
            Ok(Revoked::Done)
        }
        OriginSpec::ResendKey { token, api_url, .. } => {
            let Some(id) = provider_id else {
                return Ok(Revoked::Manual(
                    "Cemí did not create this key, so it does not know its id. Delete it in the Resend dashboard (API Keys).".into(),
                ));
            };
            let token = credential(ws, token, env)?;
            resend::delete_key(api_url.as_deref(), &token, id)?;
            Ok(Revoked::Done)
        }
        OriginSpec::AwsAccessKey {
            user,
            access_key_id,
            secret_access_key,
            session_token,
            api_url,
            ..
        } => {
            let Some(id) = provider_id else {
                return Ok(Revoked::Manual(format!(
                    "Cemí did not create this key, so it does not know its access key id. Delete it in the IAM console ({}, Security credentials); with --id-field, Cemí reads the id of the key in use from that field.",
                    match user {
                        Some(u) => format!("user {u}"),
                        None => "the user of the signing key".into(),
                    }
                )));
            };
            let creds = aws_credentials(
                ws,
                access_key_id,
                secret_access_key,
                session_token.as_deref(),
                env,
            )?;
            aws_iam::delete_key(api_url.as_deref(), &creds, user.as_deref(), id)?;
            Ok(Revoked::Done)
        }
        OriginSpec::OpenaiKey {
            project,
            token,
            api_url,
            ..
        } => {
            let Some(id) = provider_id else {
                return Ok(Revoked::Manual(format!(
                    "Cemí did not create this key, so it does not know its id. Delete it in the OpenAI dashboard (project {project}, API keys)."
                )));
            };
            let token = credential(ws, token, env)?;
            openai::delete_key(api_url.as_deref(), &token, project, id)?;
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
        (
            OriginSpec::CloudflareToken {
                token,
                account,
                api_url,
                ..
            },
            Some(id),
        ) => {
            let token = credential(ws, token, env)?;
            cloudflare::token_state(api_url.as_deref(), &token, account.as_deref(), id)
        }
        (OriginSpec::ResendKey { token, api_url, .. }, Some(id)) => {
            let token = credential(ws, token, env)?;
            resend::key_state(api_url.as_deref(), &token, id)
        }
        (
            OriginSpec::AwsAccessKey {
                user,
                access_key_id,
                secret_access_key,
                session_token,
                api_url,
                ..
            },
            Some(id),
        ) => {
            let creds = aws_credentials(
                ws,
                access_key_id,
                secret_access_key,
                session_token.as_deref(),
                env,
            )?;
            aws_iam::key_state(api_url.as_deref(), &creds, user.as_deref(), id)
        }
        (
            OriginSpec::OpenaiKey {
                project,
                token,
                api_url,
                ..
            },
            Some(id),
        ) => {
            let token = credential(ws, token, env)?;
            openai::key_state(api_url.as_deref(), &token, project, id)
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
        DestSpec::CloudflareWorker {
            account,
            script,
            name,
            token,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            cloudflare::put_secret(
                api_url.as_deref(),
                &token,
                account,
                script,
                name,
                text(value)?,
            )
        }
        DestSpec::Netlify {
            account,
            site,
            key,
            context,
            secret,
            token,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            netlify::set_var(
                api_url.as_deref(),
                &token,
                account,
                site.as_deref(),
                key,
                context,
                *secret,
                text(value)?,
            )
        }
        DestSpec::Vercel {
            project,
            key,
            target,
            team,
            token,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            vercel::set_var(
                api_url.as_deref(),
                &token,
                project,
                team.as_deref(),
                key,
                target,
                text(value)?,
            )
        }
        DestSpec::Gitlab {
            project,
            key,
            environment_scope,
            masked,
            protected,
            hidden,
            token,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            gitlab::set_var(
                api_url.as_deref(),
                &token,
                project,
                key,
                &gitlab::Options {
                    scope: environment_scope,
                    masked: *masked,
                    protected: *protected,
                    hidden: *hidden,
                },
                text(value)?,
            )
        }
        DestSpec::Fly {
            app,
            name,
            token,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            fly::set_secret(api_url.as_deref(), &token, app, name, text(value)?)
        }
        DestSpec::AwsSecret {
            secret_id,
            region,
            kms_key,
            access_key_id,
            secret_access_key,
            session_token,
            api_url,
        } => {
            let creds = aws_credentials(
                ws,
                access_key_id,
                secret_access_key,
                session_token.as_deref(),
                env,
            )?;
            aws_secrets::put(
                api_url.as_deref(),
                &creds,
                region,
                secret_id,
                kms_key.as_deref(),
                text(value)?,
            )
        }
        DestSpec::AwsParameter {
            name,
            region,
            kms_key,
            access_key_id,
            secret_access_key,
            session_token,
            api_url,
        } => {
            let creds = aws_credentials(
                ws,
                access_key_id,
                secret_access_key,
                session_token.as_deref(),
                env,
            )?;
            aws_ssm::put(
                api_url.as_deref(),
                &creds,
                region,
                name,
                kms_key.as_deref(),
                text(value)?,
            )
        }
        DestSpec::Dotenv { file, key } => write_dotenv(file, key, text(value)?),
        DestSpec::Ssh {
            host,
            port,
            file,
            key,
            restart,
            program,
        } => ssh::write(
            &ssh::Server {
                host,
                port: *port,
                program: program.as_deref(),
            },
            file,
            key,
            text(value)?,
            restart.as_deref(),
        ),
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
        DestSpec::CloudflareWorker {
            account,
            script,
            name,
            token,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            cloudflare::secret_present(api_url.as_deref(), &token, account, script, name)
        }
        DestSpec::Netlify {
            account,
            site,
            key,
            context,
            token,
            api_url,
            ..
        } => {
            let token = credential(ws, token, env)?;
            netlify::observe(
                api_url.as_deref(),
                &token,
                account,
                site.as_deref(),
                key,
                context,
            )
        }
        DestSpec::Vercel {
            project,
            key,
            target,
            team,
            token,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            vercel::observe(
                api_url.as_deref(),
                &token,
                project,
                team.as_deref(),
                key,
                target,
            )
        }
        DestSpec::Gitlab {
            project,
            key,
            environment_scope,
            token,
            api_url,
            ..
        } => {
            let token = credential(ws, token, env)?;
            gitlab::observe(api_url.as_deref(), &token, project, key, environment_scope)
        }
        DestSpec::Fly {
            app,
            name,
            token,
            api_url,
        } => {
            let token = credential(ws, token, env)?;
            fly::observe(api_url.as_deref(), &token, app, name)
        }
        DestSpec::AwsSecret {
            secret_id,
            region,
            access_key_id,
            secret_access_key,
            session_token,
            api_url,
            ..
        } => {
            let creds = aws_credentials(
                ws,
                access_key_id,
                secret_access_key,
                session_token.as_deref(),
                env,
            )?;
            aws_secrets::observe(api_url.as_deref(), &creds, region, secret_id)
        }
        DestSpec::AwsParameter {
            name,
            region,
            access_key_id,
            secret_access_key,
            session_token,
            api_url,
            ..
        } => {
            let creds = aws_credentials(
                ws,
                access_key_id,
                secret_access_key,
                session_token.as_deref(),
                env,
            )?;
            aws_ssm::observe(api_url.as_deref(), &creds, region, name)
        }
        DestSpec::Dotenv { file, key } => observe_dotenv(file, key),
        DestSpec::Ssh {
            host,
            port,
            file,
            key,
            program,
            ..
        } => ssh::observe(
            &ssh::Server {
                host,
                port: *port,
                program: program.as_deref(),
            },
            file,
            key,
        ),
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
        DestSpec::Github { .. } | DestSpec::Netlify { .. } => updated(marker),
        // Vercel gives milliseconds since 1970.
        DestSpec::Vercel { .. } => match marker
            .strip_prefix("updated ")
            .and_then(|t| t.parse::<i64>().ok())
            .and_then(|ms| jiff::Timestamp::from_millisecond(ms).ok())
        {
            Some(at) => format!("updated {}", crate::ui::when(at, "%Y-%m-%d %H:%M")),
            None => marker.to_string(),
        },
        DestSpec::SupabaseSecret { .. } | DestSpec::Fly { .. } => "its digest changed".into(),
        DestSpec::AwsSecret { .. } => "it has a new current version (AWSCURRENT)".into(),
        DestSpec::AwsParameter { .. } => match marker.strip_prefix("version ") {
            Some(v) => format!("it is now at version {v}"),
            None => marker.to_string(),
        },
        DestSpec::Gitlab { .. } => "it has another value".into(),
        DestSpec::Dotenv { .. } | DestSpec::Ssh { .. } => "the file has another value".into(),
        DestSpec::CloudflareWorker { .. }
        | DestSpec::Command { .. }
        | DestSpec::External { .. } => marker.to_string(),
    }
}

fn updated(marker: &str) -> String {
    match marker
        .strip_prefix("updated ")
        .and_then(|t| t.parse::<jiff::Timestamp>().ok())
    {
        Some(at) => format!("updated {}", crate::ui::when(at, "%Y-%m-%d %H:%M")),
        None => marker.to_string(),
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
