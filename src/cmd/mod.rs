//! Command implementations.

mod ci_cmds;
mod mcp_cmds;
mod memory;
mod project_cmds;
mod rotation_cmds;
mod scan_cmds;
mod structure;
mod values;
mod vault_cmds;

use anyhow::Result;

use crate::audit::{self, Event};
use crate::cli::{Cli, Cmd};
use crate::model::Record;
use crate::project::Project;
use crate::refs::{self, Ref, VaultSel};
use crate::ui;
use crate::vault::{Header, Scope, Vault};
use crate::workspace::{self, Workspace};

pub struct Ctx {
    pub ws: Workspace,
    pub global: bool,
}

impl Ctx {
    fn new(global: bool, write: bool) -> Result<Ctx> {
        Ok(Ctx {
            ws: Workspace::new(write)?,
            global,
        })
    }

    pub fn sel(&self) -> VaultSel {
        if self.global {
            VaultSel::Global
        } else {
            VaultSel::Default
        }
    }

    pub fn scope(&self) -> Result<Scope> {
        self.ws.scope_for(self.sel())
    }

    pub fn vault(&mut self) -> Result<&mut Vault> {
        let sel = self.sel();
        self.ws.open_sel(sel)
    }

    pub fn parse_ref(&self, text: &str) -> Result<Ref> {
        let mut r = Ref::parse(text)?;
        if self.global && r.vault == VaultSel::Default {
            r.vault = VaultSel::Global;
        }
        Ok(r)
    }

    pub fn entity_path(&self, text: Option<&str>) -> Result<(VaultSel, Vec<String>)> {
        let text = text.unwrap_or("");
        let (sel, rest) = if let Some(r) = text.strip_prefix("global:") {
            (VaultSel::Global, r)
        } else if let Some(r) = text.strip_prefix("local:") {
            (VaultSel::Local, r)
        } else {
            (self.sel(), text)
        };
        Ok((sel, refs::entity_path(rest)?))
    }

    /// Finds a record from a reference, returning (scope, record id).
    pub fn record_id(&mut self, r: &Ref) -> Result<(Scope, String)> {
        let scope = self.ws.scope_for(r.vault)?;
        let v = self.ws.open(scope)?;
        Ok((scope, v.find_record_id(&r.entities, &r.record)?))
    }

    pub fn record(&mut self, r: &Ref) -> Result<(Scope, Record)> {
        let (scope, id) = self.record_id(r)?;
        Ok((
            scope,
            self.ws.get(scope).expect("opened").records[&id].clone(),
        ))
    }

    pub fn audit(&self, scope: Scope, action: &str, target: Option<String>, env: Option<&str>) {
        self.audit_detail(scope, action, target, env, None);
    }

    pub fn audit_detail(
        &self,
        scope: Scope,
        action: &str,
        target: Option<String>,
        env: Option<&str>,
        detail: Option<String>,
    ) {
        let Some(v) = self.ws.get(scope) else { return };
        if let Err(e) = audit::append(
            &v.dir,
            &v.header,
            Event {
                actor: "cli",
                action,
                target,
                env: env.map(str::to_string),
                detail,
            },
        ) {
            ui::warn(format!("could not write the audit log: {e}"));
        }
    }

    pub fn project(&self) -> Result<Option<Project>> {
        match workspace::find_project_file(&self.ws.cwd) {
            Some(p) => Ok(Some(Project::load(&p)?)),
            None => Ok(None),
        }
    }

    pub fn require_project(&self) -> Result<Project> {
        self.project()?.ok_or_else(|| {
            crate::errors::not_found("no cemi.toml in this folder or its parents. Create one with `cemi init` or `cemi link`")
        })
    }
}

/// Asks for the master password again: before showing a secret, or changing
/// a protected environment. A person has to type it; AI clients cannot.
pub(crate) fn reauthenticate(ctx: &Ctx, scope: Scope, why: &str) -> Result<()> {
    let dir = ctx.ws.dir(scope)?;
    let header = Header::read(&dir)?;
    let (header, label) = if header.password.is_some() {
        (header, scope.to_string())
    } else {
        (Header::read(&ctx.ws.global_dir)?, "global".to_string())
    };
    let pw = ui::password(&format!("{why}: password for the {label} vault: "))?;
    if header.unlock_with_password(&pw)?.is_none() {
        return Err(crate::errors::locked("wrong password"));
    }
    Ok(())
}

/// The line that turns on completion in a shell. The shell asks `cemi`
/// itself each time, so completion stays right after updates.
fn print_completion_setup(shell: crate::cli::Shell) {
    use crate::cli::Shell;
    let (file, line) = match shell {
        Shell::Bash => ("~/.bashrc", "source <(COMPLETE=bash cemi)"),
        Shell::Zsh => ("~/.zshrc", "source <(COMPLETE=zsh cemi)"),
        Shell::Fish => (
            "~/.config/fish/completions/cemi.fish",
            "COMPLETE=fish cemi | source",
        ),
        Shell::Powershell => (
            "$PROFILE",
            r#"$env:COMPLETE = "powershell"; cemi | Out-String | Invoke-Expression; Remove-Item Env:\COMPLETE"#,
        ),
        Shell::Elvish => (
            "~/.config/elvish/rc.elv",
            "eval (E:COMPLETE=elvish cemi | slurp)",
        ),
    };
    eprintln!("Add this line to {file}, then open a new terminal:");
    crate::outln!("{line}");
}

/// Commands that change a vault take its lock for writing.
fn writes(cmd: &Cmd) -> bool {
    use crate::cli::*;
    match cmd {
        Cmd::Status
        | Cmd::Prompt
        | Cmd::Doctor
        | Cmd::Ls { .. }
        | Cmd::Find { .. }
        | Cmd::Show { .. }
        | Cmd::Copy { .. }
        | Cmd::Reveal { .. }
        | Cmd::History { .. }
        | Cmd::Deps { .. }
        | Cmd::Doc { .. }
        | Cmd::Run { .. }
        | Cmd::Export { .. }
        | Cmd::Types { .. }
        | Cmd::Log { .. }
        | Cmd::Scan { .. }
        | Cmd::Unlock
        | Cmd::Lock => false,
        Cmd::Env(EnvCmd::Ls { .. } | EnvCmd::Diff { .. }) => false,
        Cmd::Dest(DestCmd::Ls { .. }) | Cmd::Check { .. } => false,
        Cmd::Incident { rotate, .. } => *rotate,
        Cmd::Task(TaskCmd::Ls) => false,
        Cmd::Preset(PresetCmd::Ls) => false,
        Cmd::Ci(CiCmd::Export { .. } | CiCmd::Load { .. }) => false,
        Cmd::Token(TokenCmd::Ls) => false,
        Cmd::Mcp(
            McpCmd::Ls | McpCmd::Launch { .. } | McpCmd::Setup { .. } | McpCmd::Serve { .. },
        ) => false,
        Cmd::Var(_) => false,
        Cmd::Note(n) => {
            n.purpose.is_some()
                || n.used_in.is_some()
                || n.rotate.is_some()
                || n.if_lost.is_some()
                || n.if_leaked.is_some()
                || n.expires.is_some()
                || n.backup.is_some()
                || n.links.is_some()
                || n.delicate.is_some()
                || !n.set.is_empty()
                || !n.unset.is_empty()
        }
        _ => true,
    }
}

pub fn run(cli: Cli) -> Result<i32> {
    if cli.password_stdin {
        ui::use_password_stdin();
    }
    if cli.json {
        use crate::cli::McpCmd;
        const OTHER: &str = "its output belongs to another program";
        let name = match &cli.command {
            Cmd::Run { .. } => Some(("run", OTHER)),
            Cmd::Mcp(McpCmd::Serve { .. }) => Some(("mcp serve", OTHER)),
            Cmd::Mcp(McpCmd::Launch { .. }) => Some(("mcp launch", OTHER)),
            Cmd::Completion { .. } => Some(("completion", OTHER)),
            Cmd::Ci(crate::cli::CiCmd::Load { .. }) => Some(("ci load", OTHER)),
            Cmd::Reveal { .. } => Some(("reveal", "it prints the value alone, ready for a script")),
            Cmd::ClipboardHelper { .. } => Some(("__clipboard", OTHER)),
            _ => None,
        };
        if let Some((name, why)) = name {
            anyhow::bail!("--json does not apply to `cemi {name}`: {why}");
        }
    }
    // Loading in CI needs no vault: nothing is opened.
    if let Cmd::Ci(crate::cli::CiCmd::Load {
        file,
        github_env,
        command,
    }) = &cli.command
    {
        return ci_cmds::load(file.clone(), *github_env, command);
    }
    if let crate::cli::Cmd::Completion { shell } = cli.command {
        print_completion_setup(shell);
        return Ok(0);
    }
    let write = writes(&cli.command);
    let global = cli.global;
    let mut ctx = Ctx::new(global, write)?;
    use crate::cli::Cmd as C;
    match cli.command {
        C::Init {
            envs,
            own_password,
            preset,
        } => vault_cmds::init(&mut ctx, &envs, own_password, &preset),
        C::Preset(c) => project_cmds::preset(&mut ctx, c),
        C::Ci(crate::cli::CiCmd::Setup {
            repo,
            environment,
            new_key,
        }) => ci_cmds::setup(&mut ctx, repo, environment, new_key),
        C::Ci(crate::cli::CiCmd::Export { env, only, output }) => {
            ci_cmds::export(&mut ctx, &env, &only, output)
        }
        C::Ci(crate::cli::CiCmd::Load { .. }) => unreachable!("handled before opening anything"),
        C::Unlock => vault_cmds::unlock(&mut ctx),
        C::Lock => vault_cmds::lock(&mut ctx),
        C::Status => memory::status(&mut ctx),
        C::Prompt => memory::prompt(&mut ctx),
        C::Recovery(c) => vault_cmds::recovery(&mut ctx, c),
        C::Passwd => vault_cmds::passwd(&mut ctx),
        C::Doctor => vault_cmds::doctor(&mut ctx),
        C::Ls { path, all } => structure::ls(&mut ctx, path.as_deref(), all),
        C::Add { path } => structure::add(&mut ctx, &path),
        C::Mv { from, to } => structure::mv(&mut ctx, &from, &to),
        C::Rm { path, purge } => structure::rm(&mut ctx, &path, purge),
        C::Field(c) => structure::field(&mut ctx, c),
        C::Find { text } => structure::find(&mut ctx, &text),
        C::Show { reference } => structure::show(&mut ctx, &reference),
        C::Set {
            reference,
            env,
            stdin,
            from_file,
            external,
            note,
        } => values::set(
            &mut ctx,
            &reference,
            env.as_deref(),
            stdin,
            from_file,
            external,
            note,
        ),
        C::Generate {
            reference,
            env,
            length,
            charset,
            note,
        } => values::generate(&mut ctx, &reference, env.as_deref(), length, charset, note),
        C::Copy { reference, env } => values::copy(&mut ctx, reference.as_deref(), env.as_deref()),
        C::Reveal { reference, env } => values::reveal(&mut ctx, &reference, env.as_deref()),
        C::History { reference, env } => values::history(&mut ctx, &reference, env.as_deref()),
        C::Revert {
            reference,
            number,
            env,
        } => values::revert(&mut ctx, &reference, number, env.as_deref()),
        C::Note(args) => memory::note(&mut ctx, args),
        C::Task(c) => memory::task(&mut ctx, c),
        C::Deps { reference } => memory::deps(&mut ctx, &reference),
        C::Doc { entity, output } => memory::doc(&mut ctx, entity.as_deref(), output),
        C::Env(c) => structure::env(&mut ctx, c),
        C::Link { entity } => project_cmds::link(&mut ctx, entity.as_deref()),
        C::Var(c) => project_cmds::var(&mut ctx, c),
        C::Run {
            env,
            redact,
            command,
        } => project_cmds::run(ctx, env.as_deref(), redact, &command),
        C::Export { output } => project_cmds::export(&mut ctx, output),
        C::Types {
            format,
            output,
            check,
        } => project_cmds::types(&mut ctx, format, output, check),
        C::Import {
            path,
            discover,
            into,
            env,
            plain,
            no_link,
            depth,
            yes,
        } => {
            if discover {
                let root = path.unwrap_or_else(|| ctx.ws.cwd.clone());
                project_cmds::discover(
                    &mut ctx,
                    project_cmds::DiscoverOptions {
                        root: &root,
                        into: into.as_deref(),
                        env: env.as_deref(),
                        plain: &plain,
                        depth,
                        yes,
                        no_link,
                    },
                )
            } else {
                project_cmds::import(
                    &mut ctx,
                    &path.expect("required by clap"),
                    into.as_deref(),
                    env.as_deref(),
                    &plain,
                    no_link,
                )
            }
        }
        C::Origin(c) => rotation_cmds::origin(&mut ctx, c),
        C::Dest(c) => rotation_cmds::dest(&mut ctx, c),
        C::Verify {
            reference,
            env,
            clear,
            command,
        } => rotation_cmds::verify(&mut ctx, &reference, env.as_deref(), clear, command),
        C::Push {
            reference,
            env,
            force,
        } => rotation_cmds::push(&mut ctx, reference.as_deref(), env.as_deref(), force),
        C::Check {
            reference,
            env,
            offline,
        } => rotation_cmds::check(&mut ctx, reference.as_deref(), env.as_deref(), offline),
        C::Rotate {
            reference,
            env,
            leaked,
            generate,
            paste,
            length,
            charset,
            keep_old,
            yes,
        } => rotation_cmds::rotate(
            &mut ctx,
            &reference,
            env.as_deref(),
            leaked,
            generate,
            paste,
            length,
            charset,
            keep_old,
            yes,
        ),
        C::Revoke {
            reference,
            env,
            number,
            pending,
            leaked,
        } => rotation_cmds::revoke(
            &mut ctx,
            &reference,
            env.as_deref(),
            number,
            pending,
            leaked,
        ),
        C::Incident {
            references,
            env,
            rotate,
            yes,
        } => rotation_cmds::incident(&mut ctx, &references, env.as_deref(), rotate, yes),
        C::Approve { id, deny } => rotation_cmds::approve(&mut ctx, id.as_deref(), deny),
        C::Token(c) => mcp_cmds::token(&mut ctx, c),
        C::Mcp(c) => mcp_cmds::mcp(ctx, c),
        C::Log { limit, verify } => vault_cmds::log(&mut ctx, limit, verify),
        C::Scan {
            path,
            staged,
            history,
        } => scan_cmds::scan(&mut ctx, path, staged, history),
        C::Hook(c) => scan_cmds::hook(&mut ctx, c),
        C::Completion { .. } => unreachable!("handled before opening anything"),
        C::ClipboardHelper { seconds } => values::clipboard_helper(seconds),
    }
}
