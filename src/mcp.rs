//! MCP server: lets AI clients use the vault without ever receiving a secret
//! value. No tool returns a secret. `run` injects values into an allowlisted
//! project command and hides them in its output.
//!
//! The server never asks for the password. If the vault is locked, tools fail
//! and ask the human to run `cemi unlock`: a person stays in the loop. Pushes
//! and rotations in protected environments become requests that a person
//! approves with `cemi approve`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
use rmcp::{ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::audit;
use crate::cmd_shared::{attention, generate_value, record_summary};
use crate::crypto;
use crate::model::{Approval, ApprovalAction, Permission, Record, Token};
use crate::project::Project;
use crate::refs::{Ref, VaultSel};
use crate::rotation::{self, DestStatus, FieldRef, NewValue, RotateOptions};
use crate::runner;
use crate::ui;
use crate::vault::{Header, Scope, Vault};
use crate::workspace::{self, Workspace};

#[derive(Clone)]
pub struct CemiServer {
    cwd: PathBuf,
    sel: VaultSel,
    token: std::sync::Arc<Zeroizing<String>>,
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, schemars::JsonSchema, Default)]
pub struct ListParams {
    /// Entity path to list, like "acme/shop". Empty for everything you can see.
    #[serde(default)]
    pub entity: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ShowParams {
    /// Record path, like "acme/shop/stripe".
    pub record: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct SearchParams {
    /// Text to look for in names, field names and notes.
    pub text: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct GenerateParams {
    /// "record#field". The field is created (as secret) if it does not exist.
    pub reference: String,
    /// Environment, like "dev". Omit for a value shared by all environments.
    #[serde(default)]
    pub env: Option<String>,
    /// Number of characters (default 40).
    #[serde(default)]
    pub length: Option<usize>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct RunParams {
    /// Name of a command listed under [ai.commands] in the project's cemi.toml.
    pub command: String,
    /// Environment to run in, like "dev".
    pub env: String,
}

#[derive(Deserialize, schemars::JsonSchema, Default)]
pub struct CheckParams {
    /// "record#field". Omit to check every destination you can see.
    #[serde(default)]
    pub reference: Option<String>,
    /// Only destinations of this environment.
    #[serde(default)]
    pub env: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct PushParams {
    /// "record#field" whose destinations should get the current value.
    pub reference: String,
    pub env: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct RotateParams {
    /// "record#field" to replace.
    pub reference: String,
    pub env: String,
    /// True when the old key leaked: it is revoked as soon as the new one works.
    #[serde(default)]
    pub leaked: bool,
    /// True to let Cemí make a random value instead of asking the key's origin
    /// (only for services that accept any value, like a webhook secret you define).
    #[serde(default)]
    pub generate: bool,
}

fn text(s: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s.into())])
}

fn failure(e: anyhow::Error) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(format!("{e:#}"))])
}

struct Access {
    ws: Workspace,
    scope: Scope,
    token: Token,
}

impl Access {
    fn vault(&mut self) -> &mut Vault {
        self.ws
            .open(self.scope)
            .expect("opened when access was checked")
    }

    /// Entity ids this token may see.
    fn allowed_entities(&mut self) -> Vec<String> {
        let token = self.token.clone();
        let v = self.vault();
        if token.entities.is_empty() {
            return v.entities.keys().cloned().collect();
        }
        let mut out = Vec::new();
        for p in &token.entities {
            if let Ok(path) = crate::refs::entity_path(p)
                && let Some(e) = v.find_entity(&path)
            {
                out.extend(v.subtree(&e.id.clone()));
            }
        }
        out
    }

    fn require(&self, p: Permission) -> Result<()> {
        if !self.token.allow.contains(&p) {
            bail!(
                "this token does not allow `{p}`. The human can create one that does: cemi token create <name> --allow {p}"
            );
        }
        Ok(())
    }

    fn require_env(&self, env: Option<&str>) -> Result<()> {
        if let Some(env) = env
            && !self.token.envs.is_empty()
            && !self.token.envs.iter().any(|e| e == env)
        {
            bail!("this token cannot use the {env} environment");
        }
        Ok(())
    }

    /// A field the token may see, in this server's vault.
    fn field(&mut self, reference: &str) -> Result<FieldRef> {
        let mut r = Ref::parse(reference)?;
        r.require_field()?;
        let rec = self.record(&r.record_path())?;
        r.vault = crate::resolve::sel_for(self.scope);
        let fr = FieldRef::find(&mut self.ws, &r)?;
        debug_assert_eq!(fr.record_id, rec.id);
        Ok(fr)
    }

    /// Stores a request for a person to approve.
    fn request(&mut self, action: ApprovalAction) -> Result<String> {
        let now = jiff::Timestamp::now();
        let a = Approval {
            id: crypto::new_id()[..8].to_string(),
            requested_by: format!("mcp:{}", self.token.name),
            action: action.clone(),
            created: now,
            expires: now
                .checked_add(jiff::SignedDuration::from_hours(1))
                .unwrap_or(now),
        };
        let id = a.id.clone();
        let v = self.vault();
        v.put_approval(a);
        v.save()?;
        self.audit(
            "approve.request",
            Some(action.to_string()),
            None,
            Some(id.clone()),
        );
        Ok(id)
    }

    fn record(&mut self, path: &str) -> Result<Record> {
        let r = Ref::parse(path)?;
        let allowed = self.allowed_entities();
        let v = self.vault();
        let rec = v.find_record(&r.entities, &r.record)?.clone();
        if !allowed.contains(&rec.entity) || rec.archived {
            bail!("record not found: {}", r.record_path());
        }
        Ok(rec)
    }

    fn audit(
        &mut self,
        action: &str,
        target: Option<String>,
        env: Option<&str>,
        detail: Option<String>,
    ) {
        let actor = format!("mcp:{}", self.token.name);
        let v = self.vault();
        let _ = audit::append(
            &v.dir,
            &v.header,
            audit::Event {
                actor: &actor,
                action,
                target,
                env: env.map(str::to_string),
                detail,
            },
        );
    }
}

impl CemiServer {
    pub fn new(cwd: PathBuf, sel: VaultSel, token: Zeroizing<String>) -> CemiServer {
        CemiServer {
            cwd,
            sel,
            token: std::sync::Arc::new(token),
            tool_router: Self::tool_router(),
        }
    }

    /// Opens the vault (only through an open session) and checks the token.
    fn access(&self, write: bool) -> Result<Access> {
        let mut ws = Workspace::at(&self.cwd, write)?;
        let scope = ws.scope_for(self.sel)?;
        ws.open(scope).map_err(|e| {
            anyhow!("{e:#}\nThe vault is locked. Ask the human to run `cemi unlock` in a terminal, then try again.")
        })?;
        let hash = crypto::sha256_hex(self.token.as_bytes());
        let v = ws.get(scope).expect("opened");
        let token = v
            .tokens
            .values()
            .find(|t| crypto::ct_eq(t.hash.as_bytes(), hash.as_bytes()))
            .cloned()
            .ok_or_else(|| anyhow!("this MCP token is not valid for this vault"))?;
        if token.revoked.is_some() {
            bail!("this MCP token was revoked");
        }
        if token.expires.is_some_and(|e| e <= jiff::Timestamp::now()) {
            bail!(
                "this MCP token expired. The human can create a new one with `cemi token create`"
            );
        }
        Ok(Access { ws, scope, token })
    }

    fn do_list(&self, p: ListParams) -> Result<String> {
        let mut a = self.access(false)?;
        a.require(Permission::Read)?;
        let allowed = a.allowed_entities();
        let v = a.vault();
        let start = match p.entity.as_deref().filter(|s| !s.trim().is_empty()) {
            Some(e) => v.find_entity_id(&crate::refs::entity_path(e)?)?,
            None => v.root_id(),
        };
        let subtree = v.subtree(&start);
        let mut recs: Vec<&Record> = v
            .records
            .values()
            .filter(|r| !r.archived && subtree.contains(&r.entity) && allowed.contains(&r.entity))
            .collect();
        recs.sort_by_key(|r| v.record_path(r));
        let mut out =
            String::from("Records (secret values are never shown; * marks secret fields):\n");
        for r in recs {
            let fields: Vec<String> = r
                .fields
                .iter()
                .map(|f| {
                    if f.secret {
                        format!("{}*", f.name)
                    } else {
                        f.name.clone()
                    }
                })
                .collect();
            let purpose = r
                .memory
                .get(crate::model::memory_keys::PURPOSE)
                .map(|p| format!(" — {p}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "- {} [{}]{purpose}\n",
                v.record_path(r),
                fields.join(", ")
            ));
        }
        out.push_str(&format!(
            "Environments: {}\n",
            v.effective_envs(&start).join(", ")
        ));
        Ok(out)
    }

    fn do_show(&self, p: ShowParams) -> Result<String> {
        let mut a = self.access(false)?;
        a.require(Permission::Read)?;
        let rec = a.record(&p.record)?;
        let v = a.vault();
        Ok(record_summary(v, &rec))
    }

    fn do_search(&self, p: SearchParams) -> Result<String> {
        let mut a = self.access(false)?;
        a.require(Permission::Read)?;
        let allowed = a.allowed_entities();
        let v = a.vault();
        let needle = p.text.to_lowercase();
        let mut hits = Vec::new();
        for r in v
            .records
            .values()
            .filter(|r| !r.archived && allowed.contains(&r.entity))
        {
            let path = v.record_path(r);
            let in_memory = r
                .memory
                .values()
                .any(|m| m.to_lowercase().contains(&needle));
            let in_fields = r
                .fields
                .iter()
                .any(|f| f.name.to_lowercase().contains(&needle));
            if path.to_lowercase().contains(&needle) || in_memory || in_fields {
                hits.push(path);
            }
        }
        hits.sort();
        Ok(if hits.is_empty() {
            format!("Nothing matches {:?}", p.text)
        } else {
            hits.join("\n")
        })
    }

    fn do_status(&self) -> Result<String> {
        let mut a = self.access(false)?;
        a.require(Permission::Read)?;
        let allowed = a.allowed_entities();
        let v = a.vault();
        let mut items = attention(v, Some(&allowed));
        let scope = a.scope;
        items.extend(rotation::attention(&mut a.ws, scope, Some(&allowed)));
        if items.is_empty() {
            return Ok("Nothing needs attention.".into());
        }
        Ok(items
            .iter()
            .map(|i| format!("- {}: {}", i.what, i.detail))
            .collect::<Vec<_>>()
            .join("\n"))
    }

    fn do_project(&self) -> Result<String> {
        let Some(path) = workspace::find_project_file(&self.cwd) else {
            return Ok("There is no cemi.toml in this project.".into());
        };
        let p = Project::load(&path)?;
        let mut out = format!(
            "Project file: {}\nVariables injected by `run`:\n",
            path.display()
        );
        for (k, v) in p.file.env.iter() {
            out.push_str(&format!("- {k} = {}\n", v.text()));
        }
        for (k, v) in p.file.files.iter() {
            out.push_str(&format!("- {k} = {} (file path)\n", v.text()));
        }
        out.push_str("Commands you can run (tool `run`):\n");
        if p.file.ai.commands.is_empty() {
            out.push_str("- none. The human can add some under [ai.commands] in cemi.toml.\n");
        }
        for (name, c) in &p.file.ai.commands {
            out.push_str(&format!(
                "- {name}: {:?} (environments: {})\n",
                c.cmd,
                c.envs.join(", ")
            ));
        }
        Ok(out)
    }

    fn do_generate(&self, p: GenerateParams) -> Result<String> {
        let mut a = self.access(true)?;
        a.require(Permission::Generate)?;
        a.require_env(p.env.as_deref())?;
        let r = Ref::parse(&p.reference)?;
        let rec = a.record(&r.record_path())?;
        let length = p.length.unwrap_or(40);
        let actor = format!("mcp:{}", a.token.name);
        let v = a.vault();
        if let Some(env) = &p.env
            && !v.effective_envs(&rec.entity).contains(env)
        {
            bail!("environment {env:?} does not exist for {}", r.record_path());
        }
        generate_value(v, &rec.id, &r, p.env.as_deref(), length, &actor)?;
        v.save()?;
        a.audit(
            "value.generate",
            Some(r.to_string()),
            p.env.as_deref(),
            None,
        );
        Ok(format!(
            "Generated and stored a new {length}-character value for {r}{}. You will not see it; use it through `run`.",
            p.env.map(|e| format!(" in {e}")).unwrap_or_default()
        ))
    }

    fn do_check(&self, p: CheckParams) -> Result<String> {
        let mut a = self.access(false)?;
        a.require(Permission::Read)?;
        a.require_env(p.env.as_deref())?;
        let only = match &p.reference {
            Some(r) => Some(a.field(r)?),
            None => None,
        };
        let allowed = a.allowed_entities();
        let scope = a.scope;
        let dests: Vec<_> = rotation::all_destinations(&mut a.ws, only.as_ref(), p.env.as_deref())?
            .into_iter()
            .filter(|d| d.field.scope == scope)
            .filter(|d| {
                a.ws.get(scope)
                    .and_then(|v| v.records.get(&d.field.record_id))
                    .is_some_and(|r| allowed.contains(&r.entity))
            })
            .collect();
        if dests.is_empty() {
            return Ok(
                "No destinations to check. The human adds them with `cemi dest add`.".into(),
            );
        }
        let mut out = String::new();
        for d in &dests {
            let line = rotation::check_one(&mut a.ws, d, true);
            out.push_str(&format!(
                "- {} ({}) → {}: {}\n",
                line.field,
                line.env,
                line.describe,
                line.status.label()
            ));
        }
        Ok(out)
    }

    fn do_push(&self, p: PushParams) -> Result<String> {
        let mut a = self.access(true)?;
        a.require(Permission::Push)?;
        a.require_env(Some(&p.env))?;
        let fr = a.field(&p.reference)?;
        let name = fr.text(&mut a.ws);
        let dests = rotation::all_destinations(&mut a.ws, Some(&fr), Some(&p.env))?;
        if dests.is_empty() {
            bail!(
                "{name} has no destinations for {}. The human adds them with `cemi dest add`",
                p.env
            );
        }
        if !rotation::needs_approval(&mut a.ws, Some(&p.env), &dests).is_empty() {
            let id = a.request(ApprovalAction::Push {
                reference: name.clone(),
                env: p.env.clone(),
            })?;
            return Ok(format!(
                "{} is protected, so this needs a person. Ask the human to run `cemi approve {id}` in a terminal (the request expires in 1 hour).",
                p.env
            ));
        }
        let actor = format!("mcp:{}", a.token.name);
        let mut out = String::new();
        for d in &dests {
            let line = rotation::check_one(&mut a.ws, d, true);
            match &line.status {
                s if s.needs_push() => match rotation::push_one(&mut a.ws, d, &actor) {
                    Ok(()) => out.push_str(&format!("- sent to {}\n", line.describe)),
                    Err(e) => out.push_str(&format!("- {} failed: {e:#}\n", line.describe)),
                },
                s if s.is_ok() => out.push_str(&format!("- {} already had it\n", line.describe)),
                DestStatus::ChangedOutside(m) => out.push_str(&format!(
                    "- {} changed outside Cemí ({m}): not overwritten. A person decides: `{}` in a terminal puts the vault's value back, or `cemi set` saves the new one\n",
                    line.describe,
                    line.force_command()
                )),
                other => out.push_str(&format!("- {}: {}\n", line.describe, other.label())),
            }
        }
        Ok(out)
    }

    fn do_rotate(&self, p: RotateParams) -> Result<String> {
        let mut a = self.access(true)?;
        a.require(Permission::Rotate)?;
        a.require_env(Some(&p.env))?;
        let fr = a.field(&p.reference)?;
        let name = fr.text(&mut a.ws);
        let slot = rotation::slot_key(&mut a.ws, &fr, Some(&p.env))?;
        if slot == crate::model::SHARED && !a.token.envs.is_empty() {
            bail!(
                "{name} has one value shared by every environment, and this token is limited to {}. The human can rotate it with `cemi rotate {name}`",
                a.token.envs.join(", ")
            );
        }
        let dests = rotation::affected(&mut a.ws, &fr, &slot)?;
        let opts = RotateOptions {
            new_value: if p.generate {
                NewValue::Generate {
                    length: 40,
                    charset: crate::cli::Charset::Alnum,
                }
            } else {
                NewValue::Origin
            },
            leaked: p.leaked,
            keep_old: false,
        };
        let plan = rotation::describe_plan(&mut a.ws, &fr, Some(&p.env), &opts)?;
        if !rotation::needs_approval(&mut a.ws, Some(&slot), &dests).is_empty() {
            let id = a.request(ApprovalAction::Rotate {
                reference: name.clone(),
                env: p.env.clone(),
                leaked: p.leaked,
                generate: p.generate,
            })?;
            return Ok(format!(
                "This touches a protected environment, so it needs a person. Ask the human to run `cemi approve {id}` in a terminal (the request expires in 1 hour). Plan:\n{}",
                plan.join("\n")
            ));
        }
        let actor = format!("mcp:{}", a.token.name);
        let mut steps: Vec<String> = Vec::new();
        let mut collect = |step: rotation::Step, text: &str| {
            let mark = match step {
                rotation::Step::Done => "✓",
                rotation::Step::Attention => "!",
            };
            steps.push(format!("{mark} {text}"));
        };
        match rotation::rotate(&mut a.ws, &fr, Some(&p.env), opts, &actor, &mut collect) {
            Ok(()) => Ok(steps.join("\n")),
            Err(e) => bail!("{e:#}\nSteps:\n{}", steps.join("\n")),
        }
    }

    fn do_run(&self, p: RunParams) -> Result<String> {
        let path = workspace::find_project_file(&self.cwd)
            .ok_or_else(|| anyhow!("there is no cemi.toml in this project"))?;
        let project = Project::load(&path)?;
        let cmd = project
            .file
            .ai
            .commands
            .get(&p.command)
            .ok_or_else(|| {
                anyhow!(
                    "{:?} is not in [ai.commands] of cemi.toml. Allowed: {}",
                    p.command,
                    project
                        .file
                        .ai
                        .commands
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?
            .clone();
        if !cmd.envs.iter().any(|e| e == &p.env) {
            bail!(
                "{:?} may only run in: {}. The human decides this in cemi.toml",
                p.command,
                if cmd.envs.is_empty() {
                    "no environment".to_string()
                } else {
                    cmd.envs.join(", ")
                }
            );
        }
        let mut a = self.access(false)?;
        a.require(Permission::Run)?;
        a.require_env(Some(&p.env))?;
        let plan = runner::plan(&mut a.ws, &project, Some(&p.env))?;
        a.audit(
            "run",
            Some(p.command.clone()),
            Some(&p.env),
            Some(format!("{:?}", cmd.cmd)),
        );
        drop(a);
        let redactor = runner::Redactor::new(&plan.secrets);
        let prepared = runner::prepare(&plan)?;
        drop(plan);
        let timeout = Duration::from_secs(cmd.timeout_secs.unwrap_or(300).min(3600));
        let out = runner::run_captured(
            &cmd.cmd,
            project.dir(),
            &prepared,
            &redactor,
            timeout,
            32 * 1024,
        )?;
        let mut s = String::new();
        if out.timed_out {
            s.push_str(&format!("Stopped after {} seconds.\n", timeout.as_secs()));
        }
        s.push_str(&format!(
            "Exit code: {}\n",
            out.exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "none".into())
        ));
        if out.truncated {
            s.push_str("(output cut: only the last 32 KB)\n");
        }
        s.push_str("Output (secret values replaced with [hidden:NAME]):\n");
        s.push_str(&out.output);
        Ok(s)
    }
}

#[tool_router]
impl CemiServer {
    #[tool(
        description = "List the records you can see: names, fields (secret ones marked with *) and purpose. Never values."
    )]
    fn list(&self, Parameters(p): Parameters<ListParams>) -> CallToolResult {
        self.do_list(p).map(text).unwrap_or_else(failure)
    }

    #[tool(
        description = "Show one record: what it is for, where it is used, how to rotate it, and which environments have a value. Secret values are never included."
    )]
    fn show(&self, Parameters(p): Parameters<ShowParams>) -> CallToolResult {
        self.do_show(p).map(text).unwrap_or_else(failure)
    }

    #[tool(description = "Search record names, field names and notes.")]
    fn search(&self, Parameters(p): Parameters<SearchParams>) -> CallToolResult {
        self.do_search(p).map(text).unwrap_or_else(failure)
    }

    #[tool(
        description = "What needs attention: missing values, expirations, overdue tasks, missing notes."
    )]
    fn status(&self) -> CallToolResult {
        self.do_status().map(text).unwrap_or_else(failure)
    }

    #[tool(
        description = "The current project's cemi.toml: which variables it injects and which commands you may run."
    )]
    fn project(&self) -> CallToolResult {
        self.do_project().map(text).unwrap_or_else(failure)
    }

    #[tool(description = "Generate a random secret and store it. You do not get the value back.")]
    fn generate(&self, Parameters(p): Parameters<GenerateParams>) -> CallToolResult {
        self.do_generate(p).map(text).unwrap_or_else(failure)
    }

    #[tool(
        description = "Run one of the project's allowed commands (see `project`) with its secrets injected. Secret values in the output are replaced with [hidden:NAME]."
    )]
    fn run(&self, Parameters(p): Parameters<RunParams>) -> CallToolResult {
        self.do_run(p).map(text).unwrap_or_else(failure)
    }

    #[tool(
        description = "Check where secrets are copied (GitHub, Supabase, .env files…): up to date, out of date, changed outside Cemí, or missing. Never shows values."
    )]
    fn check(&self, Parameters(p): Parameters<CheckParams>) -> CallToolResult {
        self.do_check(p).map(text).unwrap_or_else(failure)
    }

    #[tool(
        description = "Send the current value of a secret to its destinations that do not have it. In protected environments (like prod) this creates a request that the human approves with `cemi approve`."
    )]
    fn push(&self, Parameters(p): Parameters<PushParams>) -> CallToolResult {
        self.do_push(p).map(text).unwrap_or_else(failure)
    }

    #[tool(
        description = "Replace a secret: create a new one at its origin, send it to every destination, verify it, and revoke the old one. Undone automatically if something fails. Use leaked=true when the old key leaked. In protected environments this creates a request that the human approves with `cemi approve`. You never see the new value."
    )]
    fn rotate(&self, Parameters(p): Parameters<RotateParams>) -> CallToolResult {
        self.do_rotate(p).map(text).unwrap_or_else(failure)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for CemiServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Cemí keeps the user's API keys and secrets. You can see names, notes and status, \
             generate new secrets, run allowed project commands with secrets injected, check and \
             update the places where secrets are copied, and rotate leaked keys, but you never \
             receive secret values. Changes in protected environments wait for the human to run \
             `cemi approve <id>`. Never ask the user to paste a secret into the chat: tell them to \
             run `cemi set <record>#<field>` in their terminal instead.",
        )
    }
}

pub fn serve(cwd: PathBuf, sel: VaultSel, token: Zeroizing<String>) -> Result<i32> {
    ui::set_non_interactive();
    let server = CemiServer::new(cwd, sel, token);
    // Fail fast with a clear message if the token is wrong (a locked vault is fine).
    if let Err(e) = server.access(false) {
        let msg = format!("{e:#}");
        if !msg.contains("locked") {
            bail!(msg);
        }
        eprintln!("cemi mcp: the vault is locked; tools will ask for `cemi unlock`.");
    }
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let service = server
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|e| anyhow!("cannot start the MCP server: {e}"))?;
        service
            .waiting()
            .await
            .map_err(|e| anyhow!("MCP server stopped: {e}"))?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(0)
}

/// Used by `cemi mcp serve`: finds the vault id for keyring lookups.
pub fn vault_id(cwd: &std::path::Path, sel: VaultSel) -> Result<String> {
    let ws = Workspace::at(cwd, false)?;
    let scope = ws.scope_for(sel)?;
    Ok(Header::read(&ws.dir(scope)?)?.id)
}
