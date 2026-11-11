use std::io::Write;

use anyhow::{Context, Result, bail};

use super::Ctx;
use crate::audit;
use crate::cli::RecoveryCmd;
use crate::crypto::KdfParams;
use crate::project;
use crate::session;
use crate::ui;
use crate::vault::{HEADER_FILE, Header, Scope, Vault};
use crate::workspace;

fn show_recovery_code(code: &str) {
    eprintln!();
    eprintln!("RECOVERY CODE — shown only this once:");
    eprintln!();
    // The code goes to stdout so it can be piped straight into a password manager.
    println!("{code}");
    eprintln!();
    eprintln!("Keep it in your password manager or on paper. With it you can open the vault");
    eprintln!("if you forget the password. Without both, the vault cannot be opened by anyone.");
    eprintln!();
}

pub fn init(ctx: &mut Ctx, envs: &str, own_password: bool) -> Result<i32> {
    let envs: Vec<&str> = envs
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    for e in &envs {
        crate::model::validate_name(e, "environment")?;
    }
    let kdf = KdfParams::for_new_vault();
    if ctx.global {
        let dir = ctx.ws.global_dir.clone();
        if dir.join(HEADER_FILE).exists() {
            bail!(
                "this computer already has a global vault in {}",
                dir.display()
            );
        }
        let pw = ui::new_password("the global vault")?;
        let created = Vault::create(&dir, Scope::Global, Some(&pw), None, &envs, kdf)?;
        session::store(&created.vault.header.id, created.vault.master())?;
        audit::append(&dir, &created.vault.header, event("init"))?;
        ui::ok(format!("Global vault created in {}", dir.display()));
        if let Some(code) = &created.recovery_code {
            show_recovery_code(code);
        }
        eprintln!(
            "Next: `cemi add <entity>/<record>` and `cemi set`, or `cemi init` inside a project."
        );
        return Ok(0);
    }

    let dir = ctx.ws.cwd.join(".cemi");
    if dir.join(HEADER_FILE).exists() {
        bail!("this folder already has a vault ({})", dir.display());
    }
    if let Some(other) = &ctx.ws.local_dir {
        ui::warn(format!(
            "a parent folder already has a vault ({}); this one will be separate",
            other.display()
        ));
    }
    let link_global = ctx.ws.global_exists() && !own_password;
    let created = if link_global {
        let gkey = ctx.ws.master_key(Scope::Global)?;
        let gheader = Header::read(&ctx.ws.global_dir)?;
        Vault::create(
            &dir,
            Scope::Local,
            None,
            Some((&gheader, &gkey)),
            &envs,
            kdf,
        )?
    } else {
        if !own_password {
            eprintln!(
                "There is no global vault on this computer, so this vault gets its own password."
            );
            eprintln!(
                "(Tip: `cemi init --global` first lets every project vault open with one password.)"
            );
        }
        let pw = ui::new_password("this project's vault")?;
        Vault::create(&dir, Scope::Local, Some(&pw), None, &envs, kdf)?
    };
    session::store(&created.vault.header.id, created.vault.master())?;
    audit::append(&dir, &created.vault.header, event("init"))?;
    ui::ok(format!("Project vault created in {}", dir.display()));
    if link_global {
        eprintln!("  It opens with your global vault's password.");
    }
    add_to_gitignore(&ctx.ws.cwd)?;
    let toml = ctx.ws.cwd.join(project::FILE);
    if !toml.exists() {
        std::fs::write(&toml, project::template(Some("local"), None))?;
        ui::ok("Created cemi.toml (safe to commit: it only has references)");
    }
    if let Some(code) = &created.recovery_code {
        show_recovery_code(code);
    }
    eprintln!(
        "Next: `cemi add stripe`, `cemi field add stripe secret --secret`, `cemi set stripe#secret -e dev`."
    );
    Ok(0)
}

fn event(action: &str) -> audit::Event<'_> {
    audit::Event {
        actor: "cli",
        action,
        target: None,
        env: None,
        detail: None,
    }
}

/// Makes sure `.cemi/` is in the project's .gitignore.
fn add_to_gitignore(dir: &std::path::Path) -> Result<()> {
    let path = dir.join(".gitignore");
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    let already = current
        .lines()
        .any(|l| matches!(l.trim(), ".cemi" | ".cemi/" | "/.cemi" | "/.cemi/"));
    if already {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    if !current.is_empty() && !current.ends_with('\n') {
        writeln!(f)?;
    }
    writeln!(
        f,
        "# Cemí project vault (encrypted, but it never belongs in git)\n.cemi/"
    )?;
    ui::ok("Added .cemi/ to .gitignore");
    Ok(())
}

pub fn unlock(ctx: &mut Ctx) -> Result<i32> {
    let scope = ctx.scope()?;
    let dir = ctx.ws.dir(scope)?;
    let header = Header::read(&dir)?;
    let key = ctx.ws.master_key(scope)?;
    session::store(&header.id, &key)?;
    ui::ok(format!(
        "The {scope} vault is open for {} minutes of inactivity. `cemi lock` closes it now.",
        session::ttl().as_mins()
    ));
    Ok(0)
}

pub fn lock(ctx: &mut Ctx) -> Result<i32> {
    let mut closed = 0;
    for dir in [Some(ctx.ws.global_dir.clone()), ctx.ws.local_dir.clone()]
        .into_iter()
        .flatten()
    {
        if let Ok(h) = Header::read(&dir) {
            session::clear(&h.id);
            closed += 1;
        }
    }
    if closed == 0 {
        ui::warn("no vault found");
    } else {
        ui::ok("Locked");
    }
    Ok(0)
}

pub fn recovery(ctx: &mut Ctx, cmd: RecoveryCmd) -> Result<i32> {
    let scope = ctx.scope()?;
    let dir = ctx.ws.dir(scope)?;
    match cmd {
        RecoveryCmd::Verify => {
            let header = Header::read(&dir)?;
            let code = ui::password("Recovery code: ")?;
            match header.unlock_with_recovery(&code)? {
                Some(_) => {
                    ui::ok("That recovery code opens the vault.");
                    Ok(0)
                }
                None => {
                    ui::warn("That recovery code does NOT open this vault.");
                    Ok(1)
                }
            }
        }
        RecoveryCmd::Reset => {
            let header = Header::read(&dir)?;
            let code = ui::password("Recovery code: ")?;
            let Some(key) = header.unlock_with_recovery(&code)? else {
                bail!("that recovery code does not open this vault");
            };
            let vault = Vault::load(&dir, key, true)?;
            let mut header = vault.header.clone();
            let pw = ui::new_password(&format!("the {scope} vault"))?;
            header.set_password(vault.master(), &pw)?;
            let new_code = header.new_recovery(vault.master())?;
            header.write(&dir)?;
            session::store(&header.id, vault.master())?;
            audit::append(&dir, &header, event("recovery.reset"))?;
            ui::ok("New password set. The old recovery code no longer works; here is the new one.");
            show_recovery_code(&new_code);
            Ok(0)
        }
        RecoveryCmd::New => {
            let vault = ctx.ws.open(scope)?;
            if vault.header.password.is_none() {
                bail!("this vault opens through the global vault; use `cemi recovery new -g`");
            }
            let mut header = vault.header.clone();
            let code = header.new_recovery(vault.master())?;
            header.write(&dir)?;
            vault.header = header;
            ctx.audit(scope, "recovery.new", None, None);
            ui::ok("New recovery code created. The old one no longer works.");
            show_recovery_code(&code);
            Ok(0)
        }
    }
}

pub fn passwd(ctx: &mut Ctx) -> Result<i32> {
    let scope = ctx.scope()?;
    let dir = ctx.ws.dir(scope)?;
    let vault = ctx.ws.open(scope)?;
    let mut header = vault.header.clone();
    let had_password = header.password.is_some();
    let pw = ui::new_password(&format!("the {scope} vault"))?;
    header.set_password(vault.master(), &pw)?;
    let code = if header.recovery.is_none() {
        Some(header.new_recovery(vault.master())?)
    } else {
        None
    };
    header.write(&dir)?;
    vault.header = header;
    ctx.audit(scope, "passwd", None, None);
    ui::ok(if had_password {
        "Password changed"
    } else {
        "This vault now also opens with its own password"
    });
    if let Some(code) = code {
        show_recovery_code(&code);
    }
    Ok(0)
}

pub fn doctor(ctx: &mut Ctx) -> Result<i32> {
    let mut problems = 0;
    println!("cemi {}", env!("CARGO_PKG_VERSION"));
    let gdir = &ctx.ws.global_dir;
    if ctx.ws.global_exists() {
        let h = Header::read(gdir)?;
        println!(
            "Global vault: {} ({})",
            gdir.display(),
            if session::is_open(&h.id) {
                "open"
            } else {
                "locked"
            }
        );
    } else {
        println!("Global vault: none (create with `cemi init --global`)");
    }
    match &ctx.ws.local_dir {
        Some(dir) => {
            let h = Header::read(dir)?;
            let how = if h.global.is_some() && h.password.is_some() {
                "opens with the global vault or its own password"
            } else if h.global.is_some() {
                "opens with the global vault"
            } else {
                "has its own password"
            };
            println!(
                "Local vault: {} ({}; {how})",
                dir.display(),
                if session::is_open(&h.id) {
                    "open"
                } else {
                    "locked"
                }
            );
            if !dir.join(".gitignore").exists() {
                println!(
                    "  ! {}/.gitignore is missing; git could pick the vault up",
                    dir.display()
                );
                problems += 1;
            }
        }
        None => println!("Local vault: none in this folder"),
    }
    match workspace::find_project_file(&ctx.ws.cwd) {
        Some(p) => match project::Project::load(&p) {
            Ok(proj) => println!(
                "Project: {} ({} variables, {} files, {} AI commands)",
                p.display(),
                proj.file.env.len(),
                proj.file.files.len(),
                proj.file.ai.commands.len()
            ),
            Err(e) => {
                println!("Project: {} — ! {e:#}", p.display());
                problems += 1;
            }
        },
        None => println!("Project: no cemi.toml here"),
    }
    for scope in [Scope::Global, Scope::Local] {
        if ctx.ws.dir(scope).is_err() {
            continue;
        }
        let dir = ctx.ws.dir(scope)?;
        let h = Header::read(&dir)?;
        if !session::is_open(&h.id) {
            continue;
        }
        let v = ctx.ws.open(scope)?;
        println!(
            "  {scope}: {} entities, {} records, {} tokens",
            v.entities.len() - 1,
            v.records.len(),
            v.tokens.len()
        );
        if !v.unreadable.is_empty() {
            problems += 1;
            println!(
                "  ! {} object file(s) cannot be opened: {}",
                v.unreadable.len(),
                v.unreadable.join(", ")
            );
            println!(
                "    They may be damaged or come from another vault. Restore them from a backup of the folder."
            );
        }
        if v.header.kdf != KdfParams::STRONG {
            println!("  ! weak password-derivation settings (test vault?)");
        }
    }
    if problems == 0 {
        ui::ok("No problems found");
    }
    Ok(if problems == 0 { 0 } else { 1 })
}

pub fn log(ctx: &mut Ctx, limit: usize, verify: bool) -> Result<i32> {
    let scope = ctx.scope()?;
    let dir = ctx.ws.dir(scope)?;
    let key = ctx.ws.master_key(scope)?;
    let read = audit::read(&dir, &key).context("cannot read the audit log")?;
    let start = read.entries.len().saturating_sub(limit);
    for e in &read.entries[start..] {
        let mut line = format!(
            "{}  {:<14} {:<18}",
            e.at.strftime("%Y-%m-%d %H:%M:%S"),
            e.actor,
            e.action
        );
        if let Some(t) = &e.target {
            line.push_str(&format!(" {t}"));
        }
        if let Some(env) = &e.env {
            line.push_str(&format!(" [{env}]"));
        }
        if let Some(d) = &e.detail {
            line.push_str(&format!(" — {d}"));
        }
        println!("{line}");
    }
    if verify {
        if read.broken.is_empty() {
            ui::ok(format!("{} entries, chain intact", read.entries.len()));
        } else {
            ui::warn(format!(
                "the chain is broken at line(s) {:?}: entries were removed, reordered or damaged",
                read.broken
            ));
            return Ok(1);
        }
    }
    Ok(0)
}
