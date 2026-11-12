//! `cemi share` and `cemi sync`.

use anyhow::{Context, Result, bail};
use serde_json::json;

use super::Ctx;
use crate::cli::{ShareArgs, ShareCmd, SyncArgs, SyncCmd};
use crate::share;
use crate::sync;
use crate::ui;
use crate::vault::Header;

pub fn share(ctx: &mut Ctx, args: ShareArgs) -> Result<i32> {
    match args.cmd {
        Some(ShareCmd::Key) => key(ctx),
        Some(ShareCmd::Ls) => ls(ctx),
        Some(ShareCmd::Accept { file, as_path }) => accept(ctx, &file, as_path.as_deref()),
        None => {
            let Some(entity) = args.entity else {
                bail!(
                    "give an entity and a receiver: cemi share acme/shop --with <their key> -e dev (see `cemi share --help`)"
                );
            };
            let to = args.with.unwrap_or_default();
            send(ctx, &entity, &to, &args.envs, args.name, args.output)
        }
    }
}

fn key(ctx: &mut Ctx) -> Result<i32> {
    let scope = ctx.scope()?;
    let header = Header::read(&ctx.ws.dir(scope)?)?;
    ui::data(json!({ "vault": scope.to_string(), "key": header.recipient }));
    crate::outln!("{}", header.recipient);
    eprintln!(
        "This is the public key of your {scope} vault. Give it to whoever shares with you; it opens nothing by itself."
    );
    Ok(0)
}

fn send(
    ctx: &mut Ctx,
    entity: &str,
    to: &str,
    envs: &[String],
    name: Option<String>,
    output: Option<std::path::PathBuf>,
) -> Result<i32> {
    crate::crypto::parse_recipient(to)
        .context("--with must be the receiver's key, from `cemi share key` (age1…)")?;
    let (sel, path) = ctx.entity_path(Some(entity))?;
    if path.is_empty() {
        bail!("share an entity, like acme/shop, not the whole vault");
    }
    let scope = ctx.ws.scope_for(sel)?;
    let v = ctx.ws.open(scope)?;
    if v.header.recipient == to.trim() {
        bail!("that is this vault's own key");
    }
    let entity_id = v.find_entity_id(&path)?;
    let available = v.effective_envs(&entity_id);
    for e in envs {
        if !available.contains(e) {
            return Err(crate::errors::not_found(format!(
                "{} has no environment {e:?} (it has: {})",
                path.join("/"),
                available.join(", ")
            )));
        }
    }
    let protected: Vec<String> = envs.iter().filter(|e| v.is_protected(e)).cloned().collect();
    if !protected.is_empty() {
        super::reauthenticate(
            ctx,
            scope,
            &format!("This gives {} values to someone else", protected.join(", ")),
        )?;
    }
    let v = ctx.ws.open(scope)?;
    let (bundle, record, left) = share::make(v, &entity_id, to.trim(), name, envs)?;
    let text = share::seal(&bundle, to.trim())?;
    let file = match output {
        Some(p) => ctx.ws.cwd.join(p),
        None => ctx.ws.cwd.join(format!("{}.share.age", path.join("-"))),
    };
    std::fs::write(&file, text).with_context(|| format!("cannot write {}", file.display()))?;
    let records = bundle.records.len();
    let values: usize = bundle
        .records
        .iter()
        .flat_map(|r| r.fields.iter())
        .map(|f| f.values.len())
        .sum();
    let receiver = share::receiver(&record);
    let v = ctx.ws.open(scope)?;
    v.put_share(record);
    v.save()?;
    ctx.audit_detail(
        scope,
        "share",
        Some(path.join("/")),
        Some(&envs.join(",")),
        Some(format!("to {receiver}")),
    );
    ui::ok(format!(
        "{} → {}: {records} records, {values} values ({}). Only {receiver} can open it",
        path.join("/"),
        file.display(),
        envs.join(", ")
    ));
    let left = left.lines();
    if !left.is_empty() {
        eprintln!("Left out: {}.", left.join(", "));
    }
    eprintln!(
        "Send the file any way you like; on their computer: cemi share accept {}",
        file.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    );
    Ok(0)
}

fn accept(ctx: &mut Ctx, file: &std::path::Path, as_path: Option<&str>) -> Result<i32> {
    let text = std::fs::read(ctx.ws.cwd.join(file))
        .with_context(|| format!("cannot read {}", file.display()))?;
    let scope = ctx.scope()?;
    let v = ctx.ws.open(scope)?;
    let bundle = share::open(&text, &[v.master()])?;
    let target = match as_path {
        Some(p) => crate::refs::entity_path(p)?,
        None => bundle.entity.clone(),
    };
    if target.is_empty() {
        bail!("--as needs an entity path, like acme/shop");
    }
    let done = share::accept(v, &bundle, &target)?;
    v.save()?;
    let from = share::short_key(&bundle.from);
    ctx.audit_detail(
        scope,
        "share.accept",
        Some(target.join("/")),
        Some(&bundle.envs.join(",")),
        Some(format!("from {from}")),
    );
    ui::data(json!({
        "entity": target.join("/"),
        "from": bundle.from,
        "envs": bundle.envs,
        "created": bundle.created.to_string(),
        "records": done.records,
        "new_values": done.new_values,
        "kept_newer": done.kept_newer,
    }));
    ui::ok(format!(
        "{} from {from} ({}): {} records, {} new values",
        target.join("/"),
        bundle.envs.join(", "),
        done.records,
        done.new_values
    ));
    if done.kept_newer > 0 {
        eprintln!(
            "{} values were left as they are: this vault has newer ones.",
            done.kept_newer
        );
    }
    Ok(0)
}

fn ls(ctx: &mut Ctx) -> Result<i32> {
    let scope = ctx.scope()?;
    let v = ctx.ws.open(scope)?;
    let mut shares: Vec<_> = v.shares.values().collect();
    shares.sort_by_key(|s| s.at);
    let mut rows = Vec::new();
    for sh in &shares {
        let entity = v.entity_path_string(&sh.entity);
        let changed = share::changed_since(v, sh);
        rows.push(json!({
            "entity": entity,
            "to": sh.to,
            "name": sh.name,
            "envs": sh.envs,
            "at": sh.at.to_string(),
            "changed_since": changed,
        }));
        crate::outln!(
            "{entity}  → {}  ({}, {})",
            share::receiver(sh),
            sh.envs.join(", "),
            ui::when(sh.at, "%Y-%m-%d %H:%M")
        );
        if !changed.is_empty() {
            crate::outln!("  changed since: {}", changed.join(", "));
        }
    }
    ui::data(json!({ "shares": rows }));
    if shares.is_empty() {
        crate::outln!("Nothing shared yet.");
    }
    Ok(0)
}

pub fn sync(ctx: &mut Ctx, args: SyncArgs) -> Result<i32> {
    match args.cmd {
        Some(SyncCmd::Clone { remote }) => {
            let (dir, label) = if ctx.global {
                (ctx.ws.global_dir.clone(), "global")
            } else {
                (ctx.ws.cwd.join(".cemi"), "local")
            };
            sync::clone(&remote, &dir)?;
            if !ctx.global {
                super::vault_cmds::add_to_gitignore(&ctx.ws.cwd)?;
            }
            ui::ok(format!(
                "Copied the vault to {} ({label}). It opens with the same password; `cemi sync{}` keeps it up to date",
                dir.display(),
                if ctx.global { " -g" } else { "" }
            ));
            Ok(0)
        }
        Some(SyncCmd::Init { remote }) => {
            let scope = ctx.scope()?;
            let v = ctx.ws.open(scope)?;
            sync::init(v, &remote)?;
            ctx.audit_detail(scope, "sync.init", None, None, None);
            ui::ok(format!(
                "The {scope} vault now syncs to {remote}. On another computer: cemi sync clone {remote}{}",
                if scope == crate::vault::Scope::Global {
                    " -g"
                } else {
                    ""
                }
            ));
            Ok(0)
        }
        None => {
            let scope = ctx.scope()?;
            let v = ctx.ws.open(scope)?;
            let report = sync::sync(v)?;
            ctx.audit_detail(
                scope,
                "sync",
                None,
                None,
                Some(format!(
                    "received {}, merged {}",
                    report.received, report.merged
                )),
            );
            ui::data(json!({
                "sent": report.sent,
                "received": report.received,
                "merged": report.merged,
                "header_changed": report.header_changed,
            }));
            let mut parts = Vec::new();
            if report.received > 0 {
                parts.push(format!("received {} changes", report.received));
            }
            if report.merged > 0 {
                parts.push(format!(
                    "merged {} edited on both computers (every version kept)",
                    report.merged
                ));
            }
            if report.sent {
                parts.push("sent this computer's changes".into());
            }
            if parts.is_empty() {
                ui::ok("Already up to date");
            } else {
                ui::ok(format!("Synced: {}", parts.join("; ")));
            }
            if report.header_changed {
                ui::warn(
                    "the password or recovery code changed on another computer: use the new one from now on",
                );
            }
            Ok(0)
        }
    }
}
