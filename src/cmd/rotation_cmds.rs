//! `origin`, `dest`, `verify`, `push`, `check`, `rotate`, `revoke`,
//! `incident`, `approve` and protected environments.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use jiff::Timestamp;
use serde_json::{Value as Json, json};
use zeroize::Zeroizing;

use super::Ctx;
use crate::cli::{Charset, DestCmd, DestKind, OriginCmd, OriginKind};
use crate::connectors::{DestSpec, OriginSpec, Revoked};
use crate::crypto;
use crate::model::{ApprovalAction, Destination, Origin, SHARED, VersionState, memory_keys};
use crate::refs::{Ref, VaultSel};
use crate::resolve;
use crate::rotation::{
    self, DestRef, DestStatus, FieldRef, NewValue, RotateOptions, Step, env_label,
};
use crate::ui;
use crate::vault::Scope;

const ACTOR: &str = "cli";

fn field_ref(ctx: &mut Ctx, reference: &str) -> Result<(Ref, FieldRef)> {
    let r = ctx.parse_ref(reference)?;
    let fr = FieldRef::find(&mut ctx.ws, &r)?;
    let full = fr.to_ref(&mut ctx.ws)?;
    Ok((full, fr))
}

fn check_env(ctx: &mut Ctx, fr: &FieldRef, env: Option<&str>) -> Result<()> {
    super::values::check_env(ctx, fr.scope, &fr.record_id, env)
}

/// A credential reference, stored with its vault prefix. Without a prefix it
/// means the key's own vault, then the global one.
fn credential_ref(ctx: &mut Ctx, text: &str, key_scope: Scope) -> Result<String> {
    let mut r = Ref::parse(text)?;
    r.require_field()?;
    if r.vault == VaultSel::Default {
        r.vault = resolve::sel_for(key_scope);
        let here = ctx
            .ws
            .open(key_scope)?
            .find_record(&r.entities, &r.record)
            .is_ok();
        if !here && key_scope == Scope::Local && ctx.ws.global_exists() {
            r.vault = VaultSel::Global;
        }
    }
    let scope = ctx.ws.scope_for(r.vault)?;
    if key_scope == Scope::Global && scope == Scope::Local {
        bail!(
            "a key in the global vault cannot use a credential from a project's local vault: move {text} to the global vault"
        );
    }
    let v = ctx.ws.open(scope)?;
    let rec = v.find_record(&r.entities, &r.record)?;
    let f = r.require_field()?;
    let field = rec.field(f).ok_or_else(|| {
        crate::errors::not_found(format!("{} has no field {f:?}", r.record_path()))
    })?;
    if !field.secret {
        ui::warn(format!(
            "{r} is not marked secret; credentials usually are (cemi field edit {r} --secret true)"
        ));
    }
    Ok(r.to_string())
}

fn pairs(list: &[String], what: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for item in list {
        let (k, v) = item
            .split_once('=')
            .ok_or_else(|| anyhow!("{what} must look like KEY=VALUE, got {item:?}"))?;
        out.insert(k.trim().to_string(), v.trim().to_string());
    }
    Ok(out)
}

fn secret_pairs(
    ctx: &mut Ctx,
    list: &[String],
    key_scope: Scope,
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (k, r) in pairs(list, "--secret")? {
        out.insert(k, credential_ref(ctx, &r, key_scope)?);
    }
    Ok(out)
}

/// Asks for the password when protected environments are involved, or for a
/// yes/no otherwise (unless `yes`).
fn approve_here(
    ctx: &Ctx,
    scope: Scope,
    protected: &[String],
    what: &str,
    yes: bool,
    ask: bool,
) -> Result<()> {
    if !protected.is_empty() {
        super::reauthenticate(
            ctx,
            scope,
            &format!("{what} changes {} (protected)", protected.join(", ")),
        )?;
    } else if ask && !yes {
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            return Err(crate::errors::needs_person(format!(
                "{what} needs a yes: run it in a terminal, or pass --yes"
            )));
        }
        if !ui::confirm("Go ahead?") {
            bail!("cancelled");
        }
    }
    Ok(())
}

// ----- origin, dest, verify -----

pub fn origin(ctx: &mut Ctx, cmd: OriginCmd) -> Result<i32> {
    match cmd {
        OriginCmd::Set {
            reference,
            env,
            kind,
        } => {
            let (r, fr) = field_ref(ctx, &reference)?;
            check_env(ctx, &fr, env.as_deref())?;
            let spec = match kind {
                OriginKind::SupabaseKey {
                    project,
                    token,
                    name,
                    api_url,
                } => OriginSpec::SupabaseKey {
                    project,
                    token: credential_ref(ctx, &token, fr.scope)?,
                    name,
                    api_url,
                },
                OriginKind::CloudflareToken {
                    token,
                    account,
                    name,
                    api_url,
                } => OriginSpec::CloudflareToken {
                    token: credential_ref(ctx, &token, fr.scope)?,
                    account,
                    name,
                    api_url,
                },
                OriginKind::ResendKey {
                    token,
                    name,
                    permission,
                    domain,
                    api_url,
                } => OriginSpec::ResendKey {
                    token: credential_ref(ctx, &token, fr.scope)?,
                    name,
                    permission,
                    domain,
                    api_url,
                },
                OriginKind::AwsAccessKey {
                    user,
                    access_key_id,
                    secret_access_key,
                    session_token,
                    id_field,
                    api_url,
                } => {
                    if id_field.as_deref() == Some(fr.field.as_str()) {
                        bail!(
                            "--id-field names another field of the record, for the access key id; {r} holds the secret access key"
                        );
                    }
                    OriginSpec::AwsAccessKey {
                        user,
                        access_key_id: credential_ref(ctx, &access_key_id, fr.scope)?,
                        secret_access_key: credential_ref(ctx, &secret_access_key, fr.scope)?,
                        session_token: session_token
                            .map(|t| credential_ref(ctx, &t, fr.scope))
                            .transpose()?,
                        id_field,
                        api_url,
                    }
                }
                OriginKind::OpenaiKey {
                    project,
                    service_account,
                    token,
                    name,
                    api_url,
                } => OriginSpec::OpenaiKey {
                    project,
                    service_account,
                    token: credential_ref(ctx, &token, fr.scope)?,
                    name,
                    api_url,
                },
                OriginKind::Command { command } => OriginSpec::Command { command },
                OriginKind::External { name, set, secret } => OriginSpec::External {
                    name,
                    config: pairs(&set, "--set")?,
                    secrets: secret_pairs(ctx, &secret, fr.scope)?,
                },
            };
            spec.validate()?;
            let key = env.clone().unwrap_or_else(|| SHARED.into());
            let describe = spec.describe();
            fr.field_mut(&mut ctx.ws)?.origins.insert(
                key.clone(),
                Origin {
                    spec,
                    created: Timestamp::now(),
                },
            );
            ctx.ws.open(fr.scope)?.save()?;
            ctx.audit_detail(
                fr.scope,
                "origin.set",
                Some(r.to_string()),
                env.as_deref(),
                Some(describe.clone()),
            );
            ui::ok(format!(
                "New values of {r} ({}) will be created at {describe}",
                env_label(&key)
            ));
            Ok(0)
        }
        OriginCmd::Rm { reference, env } => {
            let (r, fr) = field_ref(ctx, &reference)?;
            let key = env.clone().unwrap_or_else(|| SHARED.into());
            if fr.field_mut(&mut ctx.ws)?.origins.remove(&key).is_none() {
                bail!("{r} has no origin for {}", env_label(&key));
            }
            ctx.ws.open(fr.scope)?.save()?;
            ctx.audit(fr.scope, "origin.rm", Some(r.to_string()), env.as_deref());
            ui::ok(format!("Removed the origin of {r} ({})", env_label(&key)));
            Ok(0)
        }
    }
}

pub fn dest(ctx: &mut Ctx, cmd: DestCmd) -> Result<i32> {
    match cmd {
        DestCmd::Add {
            reference,
            env,
            kind,
        } => {
            let (r, fr) = field_ref(ctx, &reference)?;
            check_env(ctx, &fr, env.as_deref())?;
            let spec = match kind {
                DestKind::Github {
                    repo,
                    name,
                    environment,
                    token,
                    api_url,
                } => DestSpec::Github {
                    repo,
                    name,
                    environment,
                    token: token
                        .map(|t| credential_ref(ctx, &t, fr.scope))
                        .transpose()?,
                    api_url,
                },
                DestKind::SupabaseSecret {
                    project,
                    name,
                    token,
                    api_url,
                } => DestSpec::SupabaseSecret {
                    project,
                    name,
                    token: credential_ref(ctx, &token, fr.scope)?,
                    api_url,
                },
                DestKind::CloudflareWorker {
                    account,
                    script,
                    name,
                    token,
                    api_url,
                } => DestSpec::CloudflareWorker {
                    account,
                    script,
                    name,
                    token: credential_ref(ctx, &token, fr.scope)?,
                    api_url,
                },
                DestKind::Netlify {
                    account,
                    site,
                    key,
                    context,
                    plain,
                    token,
                    api_url,
                } => DestSpec::Netlify {
                    account,
                    site,
                    key,
                    context,
                    secret: !plain,
                    token: credential_ref(ctx, &token, fr.scope)?,
                    api_url,
                },
                DestKind::Vercel {
                    project,
                    key,
                    target,
                    team,
                    token,
                    api_url,
                } => DestSpec::Vercel {
                    project,
                    key,
                    target,
                    team,
                    token: credential_ref(ctx, &token, fr.scope)?,
                    api_url,
                },
                DestKind::Gitlab {
                    project,
                    key,
                    environment_scope,
                    protected,
                    no_mask,
                    hidden,
                    token,
                    api_url,
                } => DestSpec::Gitlab {
                    project,
                    key,
                    environment_scope,
                    masked: !no_mask,
                    protected,
                    hidden,
                    token: credential_ref(ctx, &token, fr.scope)?,
                    api_url,
                },
                DestKind::Fly {
                    app,
                    name,
                    token,
                    api_url,
                } => DestSpec::Fly {
                    app,
                    name,
                    token: credential_ref(ctx, &token, fr.scope)?,
                    api_url,
                },
                DestKind::AwsSecret {
                    secret_id,
                    region,
                    kms_key,
                    access_key_id,
                    secret_access_key,
                    session_token,
                    api_url,
                } => DestSpec::AwsSecret {
                    secret_id,
                    region,
                    kms_key,
                    access_key_id: credential_ref(ctx, &access_key_id, fr.scope)?,
                    secret_access_key: credential_ref(ctx, &secret_access_key, fr.scope)?,
                    session_token: session_token
                        .map(|t| credential_ref(ctx, &t, fr.scope))
                        .transpose()?,
                    api_url,
                },
                DestKind::AwsParameter {
                    name,
                    region,
                    kms_key,
                    access_key_id,
                    secret_access_key,
                    session_token,
                    api_url,
                } => DestSpec::AwsParameter {
                    name,
                    region,
                    kms_key,
                    access_key_id: credential_ref(ctx, &access_key_id, fr.scope)?,
                    secret_access_key: credential_ref(ctx, &secret_access_key, fr.scope)?,
                    session_token: session_token
                        .map(|t| credential_ref(ctx, &t, fr.scope))
                        .transpose()?,
                    api_url,
                },
                DestKind::Dotenv { file, key } => {
                    let file = std::path::absolute(ctx.ws.cwd.join(file))?;
                    DestSpec::Dotenv { file, key }
                }
                DestKind::Ssh {
                    host,
                    port,
                    file,
                    key,
                    restart,
                    ssh_program,
                } => DestSpec::Ssh {
                    host,
                    port,
                    file,
                    key,
                    restart,
                    program: (!ssh_program.is_empty()).then_some(ssh_program),
                },
                DestKind::Command { command } => DestSpec::Command { command },
                DestKind::External { name, set, secret } => DestSpec::External {
                    name,
                    config: pairs(&set, "--set")?,
                    secrets: secret_pairs(ctx, &secret, fr.scope)?,
                },
            };
            spec.validate()?;
            if let DestSpec::Dotenv { file, .. } = &spec
                && crate::connectors::tracked_by_git(file)
            {
                ui::warn(format!(
                    "{} is tracked by git: real values would be committed. Remove it from git and add it to .gitignore",
                    file.display()
                ));
            }
            let env_key = env.clone().unwrap_or_else(|| SHARED.into());
            let describe = spec.describe();
            let id = add_destination(ctx, &fr, &r.to_string(), &env_key, spec)?;
            ui::ok(format!(
                "{r} ({}) → {describe}  [id {id}]. Send it now with `cemi push {r}`",
                env_label(&env_key)
            ));
            Ok(0)
        }
        DestCmd::Ls { reference } => {
            let only = match reference {
                Some(t) => Some(field_ref(ctx, &t)?.1),
                None => None,
            };
            let dests = rotation::all_destinations(&mut ctx.ws, only.as_ref(), None)?;
            if dests.is_empty() {
                crate::outln!(
                    "No destinations yet. Add one with `cemi dest add <record#field> -e <env> <kind> …`"
                );
                return Ok(0);
            }
            print_destinations(ctx, &dests)?;
            Ok(0)
        }
        DestCmd::Rm { reference, id } => {
            let (r, fr) = field_ref(ctx, &reference)?;
            let field = fr.field_mut(&mut ctx.ws)?;
            let before = field.destinations.len();
            field.destinations.retain(|d| d.id != id);
            if field.destinations.len() == before {
                bail!("{r} has no destination {id}; see `cemi dest ls {r}`");
            }
            ctx.ws.open(fr.scope)?.save()?;
            ctx.audit_detail(
                fr.scope,
                "dest.rm",
                Some(r.to_string()),
                None,
                Some(id.clone()),
            );
            ui::ok(format!(
                "Cemí no longer sends {r} to destination {id} (nothing was deleted there)"
            ));
            Ok(0)
        }
    }
}

fn print_destinations(ctx: &mut Ctx, dests: &[DestRef]) -> Result<()> {
    let mut last_field = String::new();
    let mut list: Vec<Json> = Vec::new();
    for d in dests {
        let name = d.field.text(&mut ctx.ws);
        if name != last_field {
            crate::outln!("{name}");
            last_field = name;
        }
        let field = d.field.field(&mut ctx.ws)?;
        let Some(x) = field.destinations.iter().find(|x| x.id == d.id) else {
            continue;
        };
        let sent = match &x.last {
            Some(l) => format!("last sent {}", ui::when(l.at, "%Y-%m-%d %H:%M")),
            None => "never sent".into(),
        };
        crate::outln!(
            "  [{}] {:<16} {}  ({sent})",
            x.id,
            env_label(&x.env),
            x.spec.describe()
        );
        list.push(json!({
            "field": last_field,
            "id": x.id,
            "env": env_label(&x.env),
            "destination": x.spec.describe(),
            "last_sent": x.last.as_ref().map(|l| l.at.to_string()),
        }));
    }
    ui::data(json!({ "destinations": list }));
    Ok(())
}

pub fn verify(
    ctx: &mut Ctx,
    reference: &str,
    env: Option<&str>,
    clear: bool,
    command: Vec<String>,
) -> Result<i32> {
    let (r, fr) = field_ref(ctx, reference)?;
    check_env(ctx, &fr, env)?;
    let key = env.unwrap_or(SHARED).to_string();
    let field = fr.field_mut(&mut ctx.ws)?;
    if clear {
        if field.verify.remove(&key).is_none() {
            bail!("{r} has no check for {}", env_label(&key));
        }
    } else {
        field.verify.insert(key.clone(), command.clone());
    }
    ctx.ws.open(fr.scope)?.save()?;
    ctx.audit(fr.scope, "verify.set", Some(r.to_string()), env);
    if clear {
        ui::ok(format!("Removed the check of {r} ({})", env_label(&key)));
    } else {
        ui::ok(format!(
            "After each rotation of {r} ({}), Cemí runs `{}` with the new value on stdin",
            env_label(&key),
            command.join(" ")
        ));
    }
    Ok(0)
}

// ----- push, check -----

pub fn push(ctx: &mut Ctx, reference: Option<&str>, env: Option<&str>, force: bool) -> Result<i32> {
    let only = match reference {
        Some(t) => Some(field_ref(ctx, t)?.1),
        None => None,
    };
    let dests = rotation::all_destinations(&mut ctx.ws, only.as_ref(), env)?;
    if dests.is_empty() {
        crate::outln!("No destinations. Add one with `cemi dest add`");
        return Ok(0);
    }
    // Each destination is asked what it holds, so a value deleted or changed
    // there is noticed, not only a vault that changed since the last push.
    let mut todo: Vec<DestRef> = Vec::new();
    let mut failed = 0;
    for d in dests {
        if force {
            todo.push(d);
            continue;
        }
        let line = rotation::check_one(&mut ctx.ws, &d, true);
        match &line.status {
            s if s.needs_push() => todo.push(d),
            s if s.is_ok() => {}
            DestStatus::ChangedOutside(m) => {
                failed += 1;
                ui::warn(format!(
                    "{} ({}) → {}: changed outside Cemí ({m}), not overwritten. {}",
                    line.field,
                    line.env,
                    line.describe,
                    line.changed_outside_hint()
                ));
            }
            other => {
                failed += 1;
                ui::warn(format!(
                    "{} ({}) → {}: {}. `{}` sends it without checking",
                    line.field,
                    line.env,
                    line.describe,
                    other.label(),
                    line.force_command()
                ));
            }
        }
    }
    if todo.is_empty() {
        if failed == 0 {
            ui::ok("Every destination already has the current value");
        }
        return Ok(if failed > 0 { 1 } else { 0 });
    }
    let protected = rotation::needs_approval(&mut ctx.ws, None, &todo);
    let scope = todo[0].field.scope;
    if !protected.is_empty() {
        crate::outln!("Will send:");
        print_destinations(ctx, &todo)?;
    }
    approve_here(ctx, scope, &protected, "This push", true, false)?;
    for d in &todo {
        let label = rotation::check_one(&mut ctx.ws, d, false);
        match rotation::push_one(&mut ctx.ws, d, ACTOR) {
            Ok(()) => ui::ok(format!(
                "{} ({}) → {}",
                label.field, label.env, label.describe
            )),
            Err(e) => {
                failed += 1;
                ui::warn(format!(
                    "{} ({}) → {}: {e:#}",
                    label.field, label.env, label.describe
                ));
            }
        }
    }
    Ok(if failed > 0 { 1 } else { 0 })
}

pub fn check(
    ctx: &mut Ctx,
    reference: Option<&str>,
    env: Option<&str>,
    offline: bool,
) -> Result<i32> {
    let only = match reference {
        Some(t) => Some(field_ref(ctx, t)?.1),
        None => None,
    };
    let dests = rotation::all_destinations(&mut ctx.ws, only.as_ref(), env)?;
    let mut problems = 0;
    let mut checks: Vec<Json> = Vec::new();
    let mut origins: Vec<Json> = Vec::new();
    let mut last_field = String::new();
    let mut fields: Vec<FieldRef> = Vec::new();
    for d in &dests {
        if !fields.contains(&d.field) {
            fields.push(d.field.clone());
        }
        let line = rotation::check_one(&mut ctx.ws, d, !offline);
        checks.push(json!({
            "field": line.field,
            "env": line.env,
            "id": line.id,
            "destination": line.describe,
            "status": line.status.key(),
            "ok": line.status.is_ok(),
            "detail": line.status.label(),
        }));
        if line.field != last_field {
            crate::outln!("{}", line.field);
            last_field = line.field.clone();
        }
        let mark = if line.status.is_ok() { "✓" } else { "!" };
        if !line.status.is_ok() {
            problems += 1;
        }
        crate::outln!(
            "  {mark} [{}] {:<16} {} — {}",
            line.id,
            line.env,
            line.describe,
            line.status.label()
        );
        if matches!(line.status, DestStatus::ChangedOutside(_)) {
            crate::outln!("      {}", line.changed_outside_hint());
        }
    }
    if let Some(f) = &only
        && !fields.contains(f)
    {
        fields.push(f.clone());
    }
    if !offline {
        for fr in &fields {
            let slots: Vec<String> = fr.field(&mut ctx.ws)?.origins.keys().cloned().collect();
            for slot in slots {
                if env.is_some_and(|e| e != slot) {
                    continue;
                }
                match rotation::origin_problem(&mut ctx.ws, fr, &slot) {
                    Ok(Some(p)) => {
                        problems += 1;
                        let name = fr.text(&mut ctx.ws);
                        crate::outln!("  ! {name}: {p}");
                        origins.push(json!({ "field": name, "problem": p }));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        problems += 1;
                        let name = fr.text(&mut ctx.ws);
                        crate::outln!("  ! {name} origin: {e:#}");
                        origins.push(json!({ "field": name, "problem": format!("{e:#}") }));
                    }
                }
            }
        }
    }
    if dests.is_empty() {
        crate::outln!("No destinations to check. Add one with `cemi dest add`");
    } else if problems == 0 {
        ui::ok("Every destination has the current value");
    }
    ui::data(json!({ "problems": problems, "destinations": checks, "origins": origins }));
    Ok(if problems > 0 { 1 } else { 0 })
}

// ----- rotate, revoke, incident -----

#[allow(clippy::too_many_arguments)]
pub fn rotate(
    ctx: &mut Ctx,
    reference: &str,
    env: Option<&str>,
    leaked: bool,
    generate: bool,
    paste: bool,
    length: usize,
    charset: Charset,
    keep_old: bool,
    yes: bool,
) -> Result<i32> {
    let (r, fr) = field_ref(ctx, reference)?;
    check_env(ctx, &fr, env)?;
    let mut opts = RotateOptions {
        new_value: if generate {
            NewValue::Generate { length, charset }
        } else if paste {
            NewValue::Given(Zeroizing::new(String::new()))
        } else {
            NewValue::Origin
        },
        leaked,
        keep_old,
    };
    for line in rotation::describe_plan(&mut ctx.ws, &fr, env, &opts)? {
        crate::outln!("{line}");
    }
    let slot = rotation::slot_key(&mut ctx.ws, &fr, env)?;
    let dests = rotation::affected(&mut ctx.ws, &fr, &slot)?;
    let protected = rotation::needs_approval(&mut ctx.ws, Some(&slot), &dests);
    approve_here(ctx, fr.scope, &protected, "This rotation", yes, true)?;
    if paste {
        let v = ui::secret_value(&format!("New value for {r} (hidden): "), false)?;
        if v.is_empty() {
            bail!("empty value; nothing changed");
        }
        opts.new_value = NewValue::Given(v);
    }
    let mut progress = show_step;
    rotation::rotate(&mut ctx.ws, &fr, env, opts, ACTOR, &mut progress)?;
    Ok(0)
}

pub fn revoke(
    ctx: &mut Ctx,
    reference: &str,
    env: Option<&str>,
    version: Option<usize>,
    pending: bool,
    leaked: bool,
) -> Result<i32> {
    let (r, fr) = field_ref(ctx, reference)?;
    let slot = rotation::slot_key(&mut ctx.ws, &fr, env)?;
    let field = fr.field(&mut ctx.ws)?.clone();
    let s = field
        .values
        .get(&slot)
        .ok_or_else(|| anyhow!("{r} has no value for {}", env_label(&slot)))?;
    let index = if pending {
        s.pending_index()
            .ok_or_else(|| anyhow!("{r} has no pending value"))?
    } else {
        let n = version.expect("clap requires it");
        if n == 0 || n > s.versions.len() {
            bail!("there is no v{n}; see `cemi history {r}`");
        }
        n - 1
    };
    let protected = rotation::needs_approval(&mut ctx.ws, Some(&slot), &[]);
    let Some(origin) = field.origins.get(&slot) else {
        if s.versions[index].state != VersionState::Pending {
            bail!(
                "{r} has no origin, so Cemí cannot revoke the old key: do it at the provider. It is kept as an archived version"
            );
        }
        approve_here(ctx, fr.scope, &protected, "Discarding", true, false)?;
        fr.field_mut(&mut ctx.ws)?
            .values
            .get_mut(&slot)
            .expect("exists")
            .versions[index]
            .state = VersionState::Retired;
        ctx.ws.open(fr.scope)?.save()?;
        ctx.audit_detail(
            fr.scope,
            "revoke",
            Some(r.to_string()),
            env,
            Some("pending value discarded".into()),
        );
        ui::ok(format!("Discarded the pending value of {r}"));
        return Ok(0);
    };
    approve_here(ctx, fr.scope, &protected, "Revoking", true, false)?;
    match rotation::revoke_version(&mut ctx.ws, &fr, &slot, index, &origin.spec, leaked, ACTOR)? {
        Revoked::Done => ui::ok(format!(
            "Revoked v{} of {r} at {}",
            index + 1,
            origin.spec.describe()
        )),
        Revoked::Manual(m) => ui::warn(m),
    }
    Ok(0)
}

pub fn incident(
    ctx: &mut Ctx,
    references: &[String],
    env: Option<&str>,
    rotate: bool,
    yes: bool,
) -> Result<i32> {
    let mut targets = Vec::new();
    for t in references {
        let (r, fr) = field_ref(ctx, t)?;
        check_env(ctx, &fr, env)?;
        targets.push((r, fr));
    }
    for (r, fr) in &targets {
        let slot = rotation::slot_key(&mut ctx.ws, fr, env)?;
        crate::outln!("{r} ({})", env_label(&slot));
        let field = fr.field(&mut ctx.ws)?.clone();
        match field.origins.get(&slot) {
            Some(o) => crate::outln!("  created at: {}", o.spec.describe()),
            None => crate::outln!("  origin: unknown to Cemí (rotate with --paste or --generate)"),
        }
        let dests = rotation::affected(&mut ctx.ws, fr, &slot)?;
        if dests.is_empty() {
            crate::outln!("  copied to: no destinations known to Cemí");
        } else {
            crate::outln!("  copied to:");
            for d in &dests {
                let line = rotation::check_one(&mut ctx.ws, d, false);
                let via = if d.field == *fr {
                    String::new()
                } else {
                    format!(" (inside {})", line.field)
                };
                crate::outln!("    - {} ({}){via}", line.describe, line.env);
            }
        }
        for dep in rotation::dependents(&mut ctx.ws, fr)? {
            crate::outln!("  part of: {}", dep.text(&mut ctx.ws));
        }
        if let Some(p) = ctx.project()? {
            for (var, spec) in p.file.env.iter().chain(p.file.files.iter()) {
                if let Ok(pr) = p.resolve_ref(spec.text())
                    && ctx.ws.scope_for(pr.vault).ok() == Some(fr.scope)
                    && pr.entities == r.entities
                    && pr.record == r.record
                    && pr.field == r.field
                {
                    crate::outln!("  this project: ${var} ({})", p.path.display());
                }
            }
        }
        print_usage(ctx, fr.scope, r)?;
        let note = {
            let v = ctx.ws.open(fr.scope)?;
            v.records[&fr.record_id]
                .memory
                .get(memory_keys::IF_LEAKED)
                .cloned()
        };
        if let Some(n) = note {
            crate::outln!("  your note if it leaks: {n}");
        }
    }
    if !rotate {
        crate::outln!(
            "\nA leaked key stays dangerous until it is replaced. Rotate: cemi incident {} {}--rotate",
            references.join(" "),
            env.map(|e| format!("-e {e} ")).unwrap_or_default()
        );
        return Ok(0);
    }
    let mut all_dests = Vec::new();
    for (_, fr) in &targets {
        let slot = rotation::slot_key(&mut ctx.ws, fr, env)?;
        all_dests.extend(rotation::affected(&mut ctx.ws, fr, &slot)?);
    }
    let protected = rotation::needs_approval(&mut ctx.ws, env.or(Some(SHARED)), &all_dests);
    approve_here(ctx, targets[0].1.scope, &protected, "Rotating", yes, true)?;
    let mut failed = 0;
    for (r, fr) in &targets {
        crate::outln!("\nRotating {r}");
        let opts = RotateOptions {
            new_value: NewValue::Origin,
            leaked: true,
            keep_old: false,
        };
        let mut progress = show_step;
        if let Err(e) = rotation::rotate(&mut ctx.ws, fr, env, opts, ACTOR, &mut progress) {
            failed += 1;
            ui::warn(format!("{e:#}"));
        }
    }
    Ok(if failed > 0 { 1 } else { 0 })
}

/// Who used a record recently, from the audit log.
fn print_usage(ctx: &mut Ctx, scope: Scope, r: &Ref) -> Result<()> {
    let (dir, key) = {
        let v = ctx.ws.open(scope)?;
        (v.dir.clone(), v.master().clone())
    };
    let log = crate::audit::read(&dir, &key)?;
    let record = r.record_path();
    let since = Timestamp::now()
        .checked_sub(jiff::SignedDuration::from_hours(24 * 90))
        .unwrap_or(Timestamp::UNIX_EPOCH);
    let mut by_actor: BTreeMap<String, (usize, Timestamp)> = BTreeMap::new();
    for e in log.entries.iter().filter(|e| e.at >= since) {
        let hits = e.target.as_deref().is_some_and(|t| {
            let t = t
                .strip_prefix("global:")
                .or_else(|| t.strip_prefix("local:"))
                .unwrap_or(t);
            t == record || t.starts_with(&format!("{record}#"))
        });
        if hits {
            let slot = by_actor.entry(e.actor.clone()).or_insert((0, e.at));
            slot.0 += 1;
            slot.1 = slot.1.max(e.at);
        }
    }
    if by_actor.is_empty() {
        crate::outln!("  used through Cemí in the last 90 days: no record");
    } else {
        crate::outln!("  used through Cemí in the last 90 days:");
        for (actor, (n, last)) in by_actor {
            crate::outln!(
                "    - {actor}: {n} time(s), last {}",
                ui::when(last, "%Y-%m-%d %H:%M")
            );
        }
    }
    Ok(())
}

// ----- approvals -----

pub fn approve(ctx: &mut Ctx, id: Option<&str>, deny: bool) -> Result<i32> {
    let mut scopes = Vec::new();
    if ctx.ws.global_exists() {
        scopes.push(Scope::Global);
    }
    if ctx.ws.local_dir.is_some() {
        scopes.push(Scope::Local);
    }
    // Expired requests are dropped.
    let now = Timestamp::now();
    for scope in &scopes {
        let v = ctx.ws.open(*scope)?;
        let expired: Vec<String> = v
            .approvals
            .values()
            .filter(|a| a.expires <= now)
            .map(|a| a.id.clone())
            .collect();
        if !expired.is_empty() {
            for e in &expired {
                v.delete_approval(e);
            }
            v.save()?;
        }
    }
    let Some(id) = id else {
        let mut n = 0;
        let mut requests: Vec<Json> = Vec::new();
        for scope in &scopes {
            let v = ctx.ws.open(*scope)?;
            let mut list: Vec<_> = v.approvals.values().cloned().collect();
            list.sort_by_key(|a| a.created);
            for a in list {
                n += 1;
                requests.push(json!({
                    "id": a.id,
                    "requested_by": a.requested_by,
                    "action": a.action.to_string(),
                    "created": a.created.to_string(),
                    "expires": a.expires.to_string(),
                }));
                crate::outln!(
                    "{}  {} asked to {}  ({}, expires {})",
                    a.id,
                    a.requested_by,
                    a.action,
                    ui::when(a.created, "%Y-%m-%d %H:%M"),
                    ui::when(a.expires, "%H:%M")
                );
            }
        }
        ui::data(json!({ "requests": requests }));
        if n == 0 {
            crate::outln!("No requests waiting.");
            return Ok(0);
        }
        let pick = std::io::IsTerminal::is_terminal(&std::io::stdin())
            && std::io::IsTerminal::is_terminal(&std::io::stderr())
            && !ui::json_mode()
            && !ui::password_from_stdin();
        if !pick {
            crate::outln!(
                "\nApprove one with `cemi approve <id>`, or refuse it with `cemi approve <id> --deny`."
            );
            return Ok(0);
        }
        let ids: Vec<String> = requests
            .iter()
            .filter_map(|r| r["id"].as_str().map(str::to_string))
            .collect();
        let mut items: Vec<String> = requests
            .iter()
            .map(|r| {
                format!(
                    "Approve: {} asked to {}",
                    r["requested_by"].as_str().unwrap_or(""),
                    r["action"].as_str().unwrap_or("")
                )
            })
            .collect();
        items.extend(requests.iter().map(|r| {
            format!(
                "Refuse:  {} asked to {}",
                r["requested_by"].as_str().unwrap_or(""),
                r["action"].as_str().unwrap_or("")
            )
        }));
        items.push("Nothing now".into());
        let choice = dialoguer::Select::new()
            .with_prompt("What do you want to do?")
            .items(&items)
            .default(items.len() - 1)
            .interact_opt()
            .map_err(|e| anyhow!("cannot show the list: {e}"))?;
        return match choice {
            Some(i) if i < ids.len() => approve(ctx, Some(&ids[i].clone()), false),
            Some(i) if i < 2 * ids.len() => approve(ctx, Some(&ids[i - ids.len()].clone()), true),
            _ => Ok(0),
        };
    };
    let mut found = None;
    for scope in &scopes {
        let v = ctx.ws.open(*scope)?;
        if let Some(a) = v.approvals.get(id) {
            found = Some((*scope, a.clone()));
        }
    }
    let (scope, request) = found.ok_or_else(|| {
        crate::errors::not_found(format!(
            "no request {id} (it may have expired); see `cemi approve`"
        ))
    })?;
    // A request is used once, whatever happens next.
    {
        let v = ctx.ws.open(scope)?;
        v.delete_approval(id);
        v.save()?;
    }
    if deny {
        ctx.audit_detail(
            scope,
            "approve.deny",
            Some(request.action.to_string()),
            None,
            Some(request.requested_by.clone()),
        );
        ui::ok(format!(
            "Refused: {} asked to {}",
            request.requested_by, request.action
        ));
        return Ok(0);
    }
    let actor = format!("{} (approved)", request.requested_by);
    crate::outln!("{} asks to {}", request.requested_by, request.action);
    match request.action.clone() {
        ApprovalAction::Push { reference, env } => {
            let r = Ref::parse(&reference)?;
            let fr = FieldRef::find(&mut ctx.ws, &r)?;
            let dests = rotation::all_destinations(&mut ctx.ws, Some(&fr), Some(&env))?;
            print_destinations(ctx, &dests)?;
            super::reauthenticate(ctx, fr.scope, "Approving")?;
            ctx.audit_detail(
                scope,
                "approve",
                Some(request.action.to_string()),
                Some(&env),
                Some(request.requested_by.clone()),
            );
            let mut failed = 0;
            for d in &dests {
                let line = rotation::check_one(&mut ctx.ws, d, true);
                match &line.status {
                    s if s.needs_push() => match rotation::push_one(&mut ctx.ws, d, &actor) {
                        Ok(()) => ui::ok(format!("{} → {}", line.field, line.describe)),
                        Err(e) => {
                            failed += 1;
                            ui::warn(format!("{}: {e:#}", line.describe));
                        }
                    },
                    s if s.is_ok() => ui::ok(format!("{} already had it", line.describe)),
                    DestStatus::ChangedOutside(m) => {
                        failed += 1;
                        ui::warn(format!(
                            "{}: changed outside Cemí ({m}), not overwritten. {}",
                            line.describe,
                            line.changed_outside_hint()
                        ));
                    }
                    other => {
                        failed += 1;
                        ui::warn(format!("{}: {}", line.describe, other.label()));
                    }
                }
            }
            Ok(if failed > 0 { 1 } else { 0 })
        }
        ApprovalAction::Rotate {
            reference,
            env,
            leaked,
            generate,
        } => {
            let r = Ref::parse(&reference)?;
            let fr = FieldRef::find(&mut ctx.ws, &r)?;
            let env_opt = (env != SHARED).then_some(env.as_str());
            let opts = RotateOptions {
                new_value: if generate {
                    NewValue::Generate {
                        length: 40,
                        charset: Charset::Alnum,
                    }
                } else {
                    NewValue::Origin
                },
                leaked,
                keep_old: false,
            };
            for line in rotation::describe_plan(&mut ctx.ws, &fr, env_opt, &opts)? {
                crate::outln!("{line}");
            }
            super::reauthenticate(ctx, fr.scope, "Approving")?;
            ctx.audit_detail(
                scope,
                "approve",
                Some(request.action.to_string()),
                Some(&env),
                Some(request.requested_by.clone()),
            );
            let mut progress = show_step;
            rotation::rotate(&mut ctx.ws, &fr, env_opt, opts, &actor, &mut progress)?;
            Ok(0)
        }
    }
}

// ----- protected environments -----

pub fn approve_with(ctx: &mut Ctx, method: crate::model::ApproveWith) -> Result<i32> {
    use crate::model::ApproveWith;
    use crate::presence::{self, Check};
    let scope = ctx.scope()?;
    ctx.ws.open(scope)?;
    let name = presence::name();
    if method == ApproveWith::Device {
        presence::available().map_err(|why| anyhow!("{name}: {why}"))?;
    }
    // Changing how changes are confirmed is confirmed the current way.
    super::reauthenticate(ctx, scope, "Changing how changes are confirmed")?;
    if method == ApproveWith::Device {
        match presence::verify(&format!("Cemí: use {name} to confirm changes")) {
            Check::Verified => {}
            Check::Refused => bail!("not confirmed with {name}; nothing changed"),
            Check::Unavailable(why) => bail!("{name}: {why}"),
        }
    }
    let v = ctx.ws.open(scope)?;
    let root = v.root_id();
    v.entity_mut(&root).approve_with = Some(method);
    v.save()?;
    ctx.audit_detail(
        scope,
        "approve.with",
        None,
        None,
        Some(format!("{method:?}").to_lowercase()),
    );
    ui::ok(match method {
        ApproveWith::Device => format!(
            "Approvals, protected environments and `reveal` now ask for {name}. If it is not available, Cemí asks for the password"
        ),
        ApproveWith::Password => "Approvals and protected environments ask for the password".into(),
    });
    Ok(0)
}

pub fn protect(ctx: &mut Ctx, name: &str, on: bool) -> Result<i32> {
    let scope = ctx.scope()?;
    let mut list = ctx.ws.open(scope)?.protected_envs();
    if on {
        if list.iter().any(|e| e == name) {
            ui::ok(format!("{name} is already protected"));
            return Ok(0);
        }
        list.push(name.to_string());
    } else {
        if !list.iter().any(|e| e == name) {
            bail!("{name} is not protected");
        }
        super::reauthenticate(ctx, scope, &format!("Unprotecting {name}"))?;
        list.retain(|e| e != name);
    }
    let v = ctx.ws.open(scope)?;
    let root = v.root_id();
    v.entity_mut(&root).protected = Some(list);
    v.save()?;
    ctx.audit(
        scope,
        if on { "env.protect" } else { "env.unprotect" },
        Some(name.to_string()),
        None,
    );
    ui::ok(if on {
        format!("Changes in {name} now need the password; AI clients need `cemi approve`")
    } else {
        format!("{name} is no longer protected")
    });
    Ok(0)
}

/// Prints one step of a rotation: ✓ when done, ! when it needs a person.
fn show_step(step: Step, text: &str) {
    match step {
        Step::Done => ui::ok(text),
        Step::Attention => ui::warn(text),
    }
}

/// Adds a destination to a field (env_key is an environment or SHARED),
/// saves, and returns its id.
pub(super) fn add_destination(
    ctx: &mut Ctx,
    fr: &FieldRef,
    shown: &str,
    env_key: &str,
    spec: DestSpec,
) -> Result<String> {
    let field = fr.field_mut(&mut ctx.ws)?;
    if field
        .destinations
        .iter()
        .any(|d| d.spec == spec && d.env == env_key)
    {
        bail!("{shown} already goes to {}", spec.describe());
    }
    let id = loop {
        let id = crypto::new_id()[..6].to_string();
        if !field.destinations.iter().any(|d| d.id == id) {
            break id;
        }
    };
    let describe = spec.describe();
    field.destinations.push(Destination {
        id: id.clone(),
        env: env_key.to_string(),
        spec,
        last: None,
        created: Timestamp::now(),
    });
    ctx.ws.open(fr.scope)?.save()?;
    ctx.audit_detail(
        fr.scope,
        "dest.add",
        Some(shown.to_string()),
        (env_key != SHARED).then_some(env_key),
        Some(describe),
    );
    Ok(id)
}
