use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use jiff::{SignedDuration, Timestamp};
use zeroize::Zeroizing;

use super::Ctx;
use crate::cli::{McpCmd, TokenCmd};
use crate::crypto;
use crate::mcp;
use crate::model::{Launcher, Token, validate_name};
use crate::refs::Ref;
use crate::resolve;
use crate::runner;
use crate::session;
use crate::ui;

fn parse_expiry(text: &str) -> Result<Option<Timestamp>> {
    let t = text.trim().to_lowercase();
    if t == "never" {
        return Ok(None);
    }
    let (num, unit) = t.split_at(t.len().saturating_sub(1));
    let n: i64 = num
        .parse()
        .map_err(|_| anyhow!("use something like 7d, 24h or never (got {text:?})"))?;
    if n <= 0 {
        bail!("the expiry must be positive");
    }
    let d = match unit {
        "d" => SignedDuration::from_hours(n * 24),
        "h" => SignedDuration::from_hours(n),
        _ => bail!("use d (days) or h (hours), like 7d"),
    };
    Ok(Some(Timestamp::now() + d))
}

fn token_key(vault_id: &str, name: &str) -> String {
    format!("{vault_id}:{name}")
}

pub fn token(ctx: &mut Ctx, cmd: TokenCmd) -> Result<i32> {
    let scope = ctx.scope()?;
    match cmd {
        TokenCmd::Create {
            name,
            entities,
            envs,
            allow,
            expires,
            print,
        } => {
            validate_name(&name, "token")?;
            let expires = parse_expiry(&expires)?;
            let v = ctx.ws.open(scope)?;
            if v.tokens
                .values()
                .any(|t| t.name == name && t.revoked.is_none())
            {
                bail!("there is already a token {name:?}; revoke it first");
            }
            for e in &entities {
                v.find_entity_id(&crate::refs::entity_path(e)?)?;
            }
            let root = v.root_id();
            let known_envs: Vec<String> = v
                .entities
                .keys()
                .flat_map(|id| v.effective_envs(id))
                .collect();
            for e in &envs {
                if !known_envs.contains(e) && !v.effective_envs(&root).contains(e) {
                    bail!("there is no environment {e:?} in this vault");
                }
            }
            let secret = Zeroizing::new(format!(
                "cemi_{}",
                data_encoding::BASE32_NOPAD
                    .encode(&crypto::random_bytes::<32>())
                    .to_lowercase()
            ));
            let t = Token {
                id: crypto::new_id(),
                name: name.clone(),
                hash: crypto::sha256_hex(secret.as_bytes()),
                entities,
                envs,
                allow,
                expires,
                created: Timestamp::now(),
                revoked: None,
            };
            let summary = describe(&t);
            let vault_id = v.header.id.clone();
            v.put_token(t);
            v.save()?;
            session::store_token(&token_key(&vault_id, &name), &secret)
                .context("cannot keep the token in this computer's credential store")?;
            ctx.audit_detail(
                scope,
                "token.create",
                Some(name.clone()),
                None,
                Some(summary.clone()),
            );
            ui::ok(format!("Token {name:?} created: {summary}"));
            eprintln!("  It is kept in this computer's credential store. Connect a client with:");
            eprintln!("    cemi mcp setup claude-code --token-name {name}");
            if print {
                eprintln!("  The token (shown once; treat it like a password):");
                println!("{}", secret.as_str());
            }
            Ok(0)
        }
        TokenCmd::Ls => {
            let v = ctx.ws.open(scope)?;
            let mut tokens: Vec<&Token> = v.tokens.values().collect();
            tokens.sort_by_key(|t| t.created);
            if tokens.is_empty() {
                println!(
                    "No tokens. Create one: cemi token create claude --allow read --allow run"
                );
            }
            for t in tokens {
                let state = if t.revoked.is_some() {
                    "revoked".to_string()
                } else if t.expires.is_some_and(|e| e <= Timestamp::now()) {
                    "expired".to_string()
                } else {
                    "active".to_string()
                };
                println!("{}  [{state}]  {}", t.name, describe(t));
            }
            Ok(0)
        }
        TokenCmd::Revoke { name } => {
            let v = ctx.ws.open(scope)?;
            let id = v
                .tokens
                .values()
                .find(|t| t.name == name && t.revoked.is_none())
                .map(|t| t.id.clone())
                .ok_or_else(|| anyhow!("no active token {name:?}"))?;
            let mut t = v.tokens[&id].clone();
            t.revoked = Some(Timestamp::now());
            let vault_id = v.header.id.clone();
            v.put_token(t);
            v.save()?;
            session::clear_token(&token_key(&vault_id, &name));
            ctx.audit(scope, "token.revoke", Some(name.clone()), None);
            ui::ok(format!(
                "Revoked {name:?}. Clients using it lose access right away."
            ));
            Ok(0)
        }
    }
}

fn describe(t: &Token) -> String {
    let allow: Vec<String> = t.allow.iter().map(|p| p.to_string()).collect();
    format!(
        "can {}; entities: {}; environments: {}; expires: {}",
        allow.join(", "),
        if t.entities.is_empty() {
            "all".into()
        } else {
            t.entities.join(", ")
        },
        if t.envs.is_empty() {
            "all".into()
        } else {
            t.envs.join(", ")
        },
        t.expires
            .map(|e| ui::when(e, "%Y-%m-%d %H:%M"))
            .unwrap_or_else(|| "never".into())
    )
}

pub fn mcp(mut ctx: Ctx, cmd: McpCmd) -> Result<i32> {
    match cmd {
        McpCmd::Serve { token_name } => {
            let sel = ctx.sel();
            let cwd = ctx.ws.cwd.clone();
            drop(ctx);
            let token = match (token_name, std::env::var("CEMI_TOKEN").ok()) {
                (Some(name), _) => {
                    let vault_id = mcp::vault_id(&cwd, sel)?;
                    Zeroizing::new(session::load_token(&token_key(&vault_id, &name)).ok_or_else(|| {
                        anyhow!("no token {name:?} on this computer. Create it with `cemi token create {name}`")
                    })?)
                }
                (None, Some(t)) => Zeroizing::new(t),
                (None, None) => bail!("give --token-name (or set CEMI_TOKEN)"),
            };
            mcp::serve(cwd, sel, token)
        }
        McpCmd::Setup { client, token_name } => {
            let scope = ctx.scope()?;
            let vault_id = mcp::vault_id(&ctx.ws.cwd, ctx.sel())?;
            if session::load_token(&token_key(&vault_id, &token_name)).is_none() {
                bail!(
                    "no token {token_name:?} on this computer. Create it first: cemi token create {token_name} --allow read --allow run"
                );
            }
            let mut args: Vec<String> = vec![
                "mcp".into(),
                "serve".into(),
                "--token-name".into(),
                token_name.clone(),
            ];
            if ctx.global {
                args.insert(0, "--global".into());
            }
            match client.as_str() {
                "claude-code" => {
                    let claude_scope = if scope == crate::vault::Scope::Local {
                        "project"
                    } else {
                        "user"
                    };
                    let mut cmd = std::process::Command::new(runner::resolve_program("claude"));
                    cmd.args(["mcp", "add", "--scope", claude_scope, "cemi", "--", "cemi"])
                        .args(&args)
                        .current_dir(&ctx.ws.cwd);
                    match cmd.status() {
                        Ok(s) if s.success() => {
                            ui::ok(format!("Claude Code now uses Cemí ({claude_scope} scope)"));
                            Ok(0)
                        }
                        _ => {
                            ui::warn("could not run `claude mcp add`. Run it yourself:");
                            println!(
                                "claude mcp add --scope {claude_scope} cemi -- cemi {}",
                                args.join(" ")
                            );
                            Ok(1)
                        }
                    }
                }
                _ => {
                    let snippet = serde_json::json!({
                        "mcpServers": { "cemi": { "command": "cemi", "args": args } }
                    });
                    eprintln!("Add this to your client's MCP configuration (it holds no secret):");
                    println!("{}", serde_json::to_string_pretty(&snippet)?);
                    if scope == crate::vault::Scope::Local {
                        eprintln!(
                            "This uses the project vault: the client must start it from this project folder."
                        );
                    }
                    Ok(0)
                }
            }
        }
        McpCmd::Add { name, env, command } => {
            validate_name(&name, "MCP server")?;
            let scope = ctx.scope()?;
            let mut map = BTreeMap::new();
            for kv in &env {
                let (k, r) = kv
                    .split_once('=')
                    .ok_or_else(|| anyhow!("--env needs VAR=record#field, got {kv:?}"))?;
                Ref::parse(r)?.require_field()?;
                map.insert(k.trim().to_string(), r.trim().to_string());
            }
            let v = ctx.ws.open(scope)?;
            if let Some(old) = v
                .launchers
                .values()
                .find(|l| l.name == name)
                .map(|l| l.id.clone())
            {
                v.delete_launcher(&old);
            }
            v.put_launcher(Launcher {
                id: crypto::new_id(),
                name: name.clone(),
                command: command.clone(),
                env: map,
                created: Timestamp::now(),
            });
            v.save()?;
            ctx.audit(scope, "mcp.add", Some(name.clone()), None);
            ui::ok(format!(
                "Registered {name}. In your AI client, use the command: cemi mcp launch {name}"
            ));
            Ok(0)
        }
        McpCmd::Ls => {
            let scope = ctx.scope()?;
            let v = ctx.ws.open(scope)?;
            for l in v.launchers.values() {
                let vars: Vec<String> = l.env.iter().map(|(k, r)| format!("{k}={r}")).collect();
                println!("{}: {}  [{}]", l.name, l.command.join(" "), vars.join(", "));
            }
            Ok(0)
        }
        McpCmd::Rm { name } => {
            let scope = ctx.scope()?;
            let v = ctx.ws.open(scope)?;
            let id = v
                .launchers
                .values()
                .find(|l| l.name == name)
                .map(|l| l.id.clone())
                .ok_or_else(|| anyhow!("no MCP server {name:?}"))?;
            v.delete_launcher(&id);
            v.save()?;
            ui::ok(format!("Removed {name}"));
            Ok(0)
        }
        McpCmd::Launch { name } => {
            // Started by an AI client: never prompt, the human unlocks in a terminal.
            ui::set_non_interactive();
            let scope = ctx.scope()?;
            let launcher = {
                let v = ctx.ws.open(scope)?;
                v.launchers
                    .values()
                    .find(|l| l.name == name)
                    .cloned()
                    .ok_or_else(|| anyhow!("no MCP server {name:?}; see `cemi mcp ls`"))?
            };
            let mut env = Vec::new();
            for (var, r) in &launcher.env {
                let mut parsed = Ref::parse(r)?;
                if ctx.global && parsed.vault == crate::refs::VaultSel::Default {
                    parsed.vault = crate::refs::VaultSel::Global;
                }
                let val = resolve::resolve(&mut ctx.ws, &parsed, None)
                    .with_context(|| format!("{var} ({r})"))?;
                env.push((var.clone(), val.text()?));
            }
            ctx.audit(scope, "mcp.launch", Some(name.clone()), None);
            drop(ctx);
            let prepared = runner::Prepared::from_env(env);
            runner::run_interactive(&launcher.command, &prepared, None)
        }
    }
}
