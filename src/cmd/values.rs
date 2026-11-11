use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::BASE64;

use super::Ctx;
use crate::cli::Charset;
use crate::cmd_shared::{ensure_field, random_string};
use crate::model::{FieldKind, SHARED, Value};
use crate::refs::Ref;
use crate::resolve;
use crate::ui;
use crate::vault::Scope;

pub(super) fn check_env(
    ctx: &mut Ctx,
    scope: Scope,
    record_id: &str,
    env: Option<&str>,
) -> Result<()> {
    let Some(env) = env else { return Ok(()) };
    let v = ctx.ws.open(scope)?;
    let entity = v.records[record_id].entity.clone();
    let envs = v.effective_envs(&entity);
    if !envs.iter().any(|e| e == env) {
        bail!(
            "environment {env:?} does not exist here (available: {}). Add it with `cemi env add {env}`",
            if envs.is_empty() {
                "none".to_string()
            } else {
                envs.join(", ")
            }
        );
    }
    Ok(())
}

fn validate_kind(kind: FieldKind, text: &str) -> Result<()> {
    match kind {
        FieldKind::Date => {
            text.trim()
                .parse::<jiff::civil::Date>()
                .map_err(|_| anyhow!("this field is a date: use YYYY-MM-DD"))?;
        }
        FieldKind::Number => {
            text.trim()
                .parse::<f64>()
                .map_err(|_| anyhow!("this field is a number"))?;
        }
        FieldKind::Url => {
            if !text.contains("://") {
                bail!("this field is a URL (like https://…)");
            }
        }
        FieldKind::Text if text.contains('\n') => {
            bail!(
                "this value has several lines; make the field multiline: cemi field edit <ref> --type multiline"
            );
        }
        _ => {}
    }
    Ok(())
}

pub fn set(
    ctx: &mut Ctx,
    reference: &str,
    env: Option<&str>,
    stdin: bool,
    from_file: Option<std::path::PathBuf>,
    external: Option<String>,
    note: Option<String>,
) -> Result<i32> {
    let r = ctx.parse_ref(reference)?;
    let fname = r.require_field()?.to_string();
    let (scope, id) = ctx.record_id(&r)?;
    check_env(ctx, scope, &id, env)?;
    let existing_kind = ctx.ws.get(scope).expect("opened").records[&id]
        .field(&fname)
        .map(|f| f.kind);

    let value = if external.is_some() {
        None
    } else if let Some(path) = from_file {
        let bytes =
            std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        if existing_kind != Some(FieldKind::File) && std::str::from_utf8(&bytes).is_err() {
            bail!(
                "that file is binary; make the field a file field: cemi field edit {r} --type file"
            );
        }
        Some(match existing_kind {
            Some(FieldKind::File) | None => Value::File {
                name,
                data: crate::model::Sensitive::new(BASE64.encode(&bytes)),
            },
            Some(_) => Value::text(String::from_utf8(bytes).expect("checked above")),
        })
    } else {
        let label = env.map(|e| format!(" [{e}]")).unwrap_or_default();
        let text = ui::secret_value(&format!("Value for {r}{label} (hidden): "), stdin)?;
        if text.is_empty() {
            bail!("empty value; nothing stored");
        }
        if let Some(k) = existing_kind {
            validate_kind(k, &text)?;
        }
        Some(Value::text(text.as_str()))
    };

    let v = ctx.ws.open(scope)?;
    let rec = v.record_mut(&id);
    let created = rec.field(&fname).is_none();
    let field = ensure_field(rec, &r, true)?;
    if created && matches!(value, Some(Value::File { .. })) {
        field.kind = FieldKind::File;
    }
    let key = env.unwrap_or(SHARED).to_string();
    let slot = field.values.entry(key).or_default();
    match (&external, value) {
        (Some(place), _) => slot.external = Some(place.clone()),
        (None, Some(val)) => slot.push(val, "cli", note),
        (None, None) => unreachable!("a value is always read when not external"),
    }
    v.save()?;
    ctx.audit(
        scope,
        if external.is_some() {
            "value.external"
        } else {
            "value.set"
        },
        Some(r.to_string()),
        env,
    );
    if created {
        ui::ok(format!(
            "Created secret field {fname:?} on {}",
            r.record_path()
        ));
    }
    match external {
        Some(place) => ui::ok(format!("Noted that {r} lives in: {place}")),
        None => ui::ok(format!(
            "Stored {r}{}",
            env.map(|e| format!(" for {e}"))
                .unwrap_or_else(|| " for all environments".into())
        )),
    }
    Ok(0)
}

pub fn generate(
    ctx: &mut Ctx,
    reference: &str,
    env: Option<&str>,
    length: usize,
    charset: Charset,
    note: Option<String>,
) -> Result<i32> {
    if !(8..=4096).contains(&length) {
        bail!("length must be between 8 and 4096");
    }
    let r = ctx.parse_ref(reference)?;
    let (scope, id) = ctx.record_id(&r)?;
    check_env(ctx, scope, &id, env)?;
    let value = zeroize::Zeroizing::new(random_string(length, charset));
    let v = ctx.ws.open(scope)?;
    let rec = v.record_mut(&id);
    let field = ensure_field(rec, &r, true)?;
    field
        .values
        .entry(env.unwrap_or(SHARED).to_string())
        .or_default()
        .push(
            Value::text(value.as_str()),
            "cli",
            note.or(Some("generated".into())),
        );
    v.save()?;
    ctx.audit(scope, "value.generate", Some(r.to_string()), env);
    ui::ok(format!(
        "Generated a {length}-character value for {r} (not shown). `cemi copy` puts it on the clipboard."
    ));
    Ok(0)
}

fn resolve_for_human(
    ctx: &mut Ctx,
    r: &Ref,
    env: Option<&str>,
) -> Result<(Scope, resolve::Resolved)> {
    let scope = ctx.ws.scope_for(r.vault)?;
    let val = resolve::resolve(&mut ctx.ws, r, env)?;
    Ok((scope, val))
}

pub fn copy(ctx: &mut Ctx, reference: Option<&str>, env: Option<&str>) -> Result<i32> {
    let picked;
    let (reference, env) = match reference {
        Some(r) => (r, env),
        None => match pick(ctx, env)? {
            Some(p) => {
                picked = p;
                (picked.0.as_str(), picked.1.as_deref())
            }
            None => return Ok(1),
        },
    };
    let r = ctx.parse_ref(reference)?;
    r.require_field()?;
    let (scope, val) = resolve_for_human(ctx, &r, env)?;
    let text = val.text()?;
    let exe = std::env::current_exe().context("cannot find the cemi executable")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["__clipboard", "30"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = cmd.spawn().context("cannot start the clipboard helper")?;
    {
        let mut stdin = child.stdin.take().expect("piped");
        stdin.write_all(text.as_bytes())?;
    }
    ctx.audit(scope, "value.copy", Some(r.to_string()), env);
    ui::ok(format!(
        "Copied {r} to the clipboard. It is cleared in 30 seconds."
    ));
    Ok(0)
}

/// The picker of `cemi copy` without a reference: every value of the vaults
/// here, found by typing part of its name, environment or purpose. Returns
/// the reference and environment chosen, or `None` when cancelled.
fn pick(ctx: &mut Ctx, env: Option<&str>) -> Result<Option<(String, Option<String>)>> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        bail!(
            "which value? Give a reference: cemi copy <record#field> (the picker needs a terminal)"
        );
    }
    let mut items: Vec<(String, String, Option<String>)> = Vec::new();
    for scope in [Scope::Local, Scope::Global] {
        if ctx.ws.dir(scope).is_err() {
            continue;
        }
        let v = ctx.ws.open(scope)?;
        for rec in v.records.values().filter(|r| !r.archived) {
            let path = v.record_path(rec);
            let purpose = rec
                .memory
                .get(crate::model::memory_keys::PURPOSE)
                .map(String::as_str)
                .unwrap_or("");
            for f in &rec.fields {
                let reference = format!("{scope}:{path}#{}", f.name);
                let mut add = |slot_env: Option<&str>| {
                    let shown = slot_env.unwrap_or("all");
                    let label = format!("{scope}:{path}#{}  [{shown}]  {purpose}", f.name);
                    items.push((
                        label.trim_end().to_string(),
                        reference.clone(),
                        slot_env.map(str::to_string),
                    ));
                };
                match env {
                    Some(e) => {
                        if let Some((_, slot)) = f.slot_for(Some(e))
                            && matches!(slot.current(), Some(Value::Text { .. }))
                        {
                            add(Some(e));
                        }
                    }
                    None => {
                        for (key, slot) in &f.values {
                            if matches!(slot.current(), Some(Value::Text { .. })) {
                                add((key != SHARED).then_some(key.as_str()));
                            }
                        }
                    }
                }
            }
        }
    }
    if items.is_empty() {
        bail!(
            "there is nothing to copy{}",
            env.map(|e| format!(" in {e}")).unwrap_or_default()
        );
    }
    items.sort();
    let labels: Vec<&str> = items.iter().map(|(l, _, _)| l.as_str()).collect();
    let choice = dialoguer::FuzzySelect::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Copy which value? Type to search, Enter to copy, Esc to cancel")
        .items(&labels)
        .default(0)
        .max_length(15)
        .interact_opt()
        .context("the picker failed")?;
    Ok(choice.map(|i| (items[i].1.clone(), items[i].2.clone())))
}

/// Runs in a background process: sets the clipboard, waits, clears it if unchanged.
pub fn clipboard_helper(seconds: u64) -> Result<i32> {
    let mut value = zeroize::Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut value)?;
    let mut cb = arboard::Clipboard::new().map_err(|e| anyhow!("no clipboard: {e}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    {
        let set = cb.set();
        #[cfg(windows)]
        let set = {
            use arboard::SetExtWindows;
            set.exclude_from_history()
                .exclude_from_cloud()
                .exclude_from_monitoring()
        };
        #[cfg(target_os = "macos")]
        let set = {
            use arboard::SetExtApple;
            set.exclude_from_history()
        };
        #[cfg(all(unix, not(target_os = "macos")))]
        let set = {
            use arboard::SetExtLinux;
            set.exclude_from_history().wait_until(deadline)
        };
        set.text(value.as_str())
            .map_err(|e| anyhow!("cannot copy: {e}"))?;
    }
    let now = std::time::Instant::now();
    if deadline > now {
        std::thread::sleep(deadline - now);
    }
    if cb.get_text().map(|t| t == *value).unwrap_or(false) {
        let _ = cb.clear();
    }
    Ok(0)
}

pub fn reveal(ctx: &mut Ctx, reference: &str, env: Option<&str>) -> Result<i32> {
    let r = ctx.parse_ref(reference)?;
    r.require_field()?;
    let scope = ctx.ws.scope_for(r.vault)?;
    let is_secret = {
        let (_, rec) = ctx.record(&r)?;
        rec.field(r.require_field()?)
            .is_some_and(|f| f.secret || f.kind == FieldKind::Template)
    };
    if is_secret {
        super::reauthenticate(ctx, scope, "Showing a secret")?;
    }
    let (_, val) = resolve_for_human(ctx, &r, env)?;
    ctx.audit(scope, "value.reveal", Some(r.to_string()), env);
    let mut out = std::io::stdout().lock();
    out.write_all(&val.bytes)?;
    if val.file_name.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        writeln!(out)?;
    }
    Ok(0)
}

pub fn history(ctx: &mut Ctx, reference: &str, env: Option<&str>) -> Result<i32> {
    let r = ctx.parse_ref(reference)?;
    let fname = r.require_field()?.to_string();
    let (_, rec) = ctx.record(&r)?;
    let f = rec
        .field(&fname)
        .ok_or_else(|| anyhow!("no field {fname:?}"))?;
    let Some((key, slot)) = f.slot_for(env) else {
        bail!(
            "{r} has no value{}",
            env.map(|e| format!(" for {e}")).unwrap_or_default()
        );
    };
    println!(
        "{r} ({})",
        if key == SHARED {
            "all environments"
        } else {
            key
        }
    );
    if let Some(ext) = &slot.external {
        println!("  not stored here: {ext}");
    }
    for (i, ver) in slot.versions.iter().enumerate() {
        println!(
            "  v{}  {:<9} {}  by {}{}",
            i + 1,
            ver.state.to_string(),
            ui::when(ver.at, "%Y-%m-%d %H:%M"),
            ver.actor,
            ver.note
                .as_ref()
                .map(|n| format!("  — {n}"))
                .unwrap_or_default()
        );
    }
    Ok(0)
}

pub fn revert(ctx: &mut Ctx, reference: &str, version: usize, env: Option<&str>) -> Result<i32> {
    let r = ctx.parse_ref(reference)?;
    let fname = r.require_field()?.to_string();
    let (scope, id) = ctx.record_id(&r)?;
    let v = ctx.ws.open(scope)?;
    let rec = v.record_mut(&id);
    let f = rec
        .field_mut(&fname)
        .ok_or_else(|| anyhow!("no field {fname:?}"))?;
    let key = match f.slot_for(env) {
        Some((k, _)) => k.to_string(),
        None => bail!("{r} has no value"),
    };
    let slot = f.values.get_mut(&key).expect("found above");
    let old = slot
        .versions
        .get(version.wrapping_sub(1))
        .ok_or_else(|| anyhow!("there is no v{version}; see `cemi history {r}`"))?
        .value
        .clone();
    slot.push(old, "cli", Some(format!("revert to v{version}")));
    v.save()?;
    ctx.audit_detail(
        scope,
        "value.revert",
        Some(r.to_string()),
        env,
        Some(format!("v{version}")),
    );
    ui::ok(format!(
        "{r} is back to the value of v{version} (saved as a new version)"
    ));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_strings_use_the_charset() {
        let s = random_string(200, Charset::Hex);
        assert_eq!(s.len(), 200);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(
            random_string(40, Charset::Alnum),
            random_string(40, Charset::Alnum)
        );
    }
}
