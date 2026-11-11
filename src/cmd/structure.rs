use anyhow::{Result, anyhow, bail};

use super::Ctx;
use crate::cli::{EnvCmd, FieldCmd};
use crate::crypto;
use crate::model::{Field, FieldKind, Record, SHARED, Value, validate_name};
use crate::ui;
use crate::vault::{Vault, display_path};

pub fn ls(ctx: &mut Ctx, path: Option<&str>, all: bool) -> Result<i32> {
    let (sel, path) = ctx.entity_path(path)?;
    let scope = ctx.ws.scope_for(sel)?;
    let v = ctx.ws.open(scope)?;
    let start = v.find_entity_id(&path)?;
    println!("{scope} vault: {}", display_path(&path));
    print_tree(v, &start, 1, all);
    Ok(0)
}

fn print_tree(v: &Vault, entity: &str, depth: usize, all: bool) {
    let pad = "  ".repeat(depth);
    let mut records: Vec<&Record> = v
        .records
        .values()
        .filter(|r| r.entity == entity && (all || !r.archived))
        .collect();
    records.sort_by(|a, b| a.name.cmp(&b.name));
    for r in records {
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
        let archived = if r.archived { " (archived)" } else { "" };
        println!("{pad}{}{archived}  [{}]", r.name, fields.join(", "));
    }
    for c in v.children(entity) {
        let envs = if c.envs.is_empty() {
            String::new()
        } else {
            format!("  envs: +{}", c.envs.join(", +"))
        };
        println!("{pad}{}/{envs}", c.name);
        print_tree(v, &c.id, depth + 1, all);
    }
}

pub fn add(ctx: &mut Ctx, path: &str) -> Result<i32> {
    let r = ctx.parse_ref(path)?;
    if r.field.is_some() {
        bail!("`cemi add` creates a record; add fields with `cemi field add`");
    }
    let scope = ctx.ws.scope_for(r.vault)?;
    let v = ctx.ws.open(scope)?;
    let entity = v.ensure_entity(&r.entities)?;
    v.add_record(&entity, &r.record)?;
    v.save()?;
    ctx.audit(scope, "record.add", Some(r.record_path()), None);
    ui::ok(format!("Created {} in the {scope} vault", r.record_path()));
    eprintln!(
        "  Next: cemi field add {} <name> [--secret] [--type file|url|template…]",
        r.record_path()
    );
    Ok(0)
}

pub fn mv(ctx: &mut Ctx, from: &str, to: &str) -> Result<i32> {
    let a = ctx.parse_ref(from)?;
    let b = ctx.parse_ref(to)?;
    let sa = ctx.ws.scope_for(a.vault)?;
    let sb = ctx.ws.scope_for(b.vault)?;
    if sa != sb {
        bail!("moving between the global and local vaults is not supported yet");
    }
    let v = ctx.ws.open(sa)?;
    let id = v.find_record_id(&a.entities, &a.record)?;
    let entity = v.ensure_entity(&b.entities)?;
    v.move_record(&id, &entity, &b.record)?;
    v.save()?;
    ctx.audit_detail(
        sa,
        "record.move",
        Some(a.record_path()),
        None,
        Some(b.record_path()),
    );
    ui::ok(format!("Moved {} to {}", a.record_path(), b.record_path()));
    Ok(0)
}

pub fn rm(ctx: &mut Ctx, path: &str, purge: bool) -> Result<i32> {
    let r = ctx.parse_ref(path)?;
    let (scope, id) = ctx.record_id(&r)?;
    let v = ctx.ws.open(scope)?;
    if purge {
        if !ui::confirm(&format!(
            "Delete {} and every value in its history for good? This cannot be undone.",
            r.record_path()
        )) {
            bail!("cancelled (nothing deleted)");
        }
        v.delete_record(&id);
        v.save()?;
        ctx.audit(scope, "record.purge", Some(r.record_path()), None);
        ui::ok(format!("Deleted {}", r.record_path()));
    } else {
        v.record_mut(&id).archived = true;
        v.save()?;
        ctx.audit(scope, "record.archive", Some(r.record_path()), None);
        ui::ok(format!(
            "Archived {} (still in the vault; `cemi ls --all` shows it, --purge deletes it)",
            r.record_path()
        ));
    }
    Ok(0)
}

pub fn field(ctx: &mut Ctx, cmd: FieldCmd) -> Result<i32> {
    match cmd {
        FieldCmd::Add {
            record,
            name,
            kind,
            secret,
        } => {
            validate_name(&name, "field")?;
            let r = ctx.parse_ref(&record)?;
            if r.field.is_some() {
                bail!(
                    "give the record path and the field name separately: cemi field add {} {}",
                    r.record_path(),
                    name
                );
            }
            let (scope, id) = ctx.record_id(&r)?;
            let v = ctx.ws.open(scope)?;
            let rec = v.record_mut(&id);
            if rec.field(&name).is_some() {
                bail!("{} already has a field {name:?}", r.record_path());
            }
            rec.fields.push(Field::new(name.clone(), kind, secret));
            v.save()?;
            ctx.audit(
                scope,
                "field.add",
                Some(format!("{}#{name}", r.record_path())),
                None,
            );
            ui::ok(format!(
                "Added {} field {name:?}{}",
                kind,
                if secret { " (secret)" } else { "" }
            ));
            if kind == FieldKind::Template {
                eprintln!(
                    "  Set it like: cemi set {}#{name} --stdin <<< 'postgres://app:{{{{db#password}}}}@host/db'",
                    r.record_path()
                );
            }
            Ok(0)
        }
        FieldCmd::Rm { reference } => {
            let r = ctx.parse_ref(&reference)?;
            let fname = r.require_field()?.to_string();
            let (scope, id) = ctx.record_id(&r)?;
            if !ui::confirm(&format!("Remove the field {r} and all its values?")) {
                bail!("cancelled");
            }
            let v = ctx.ws.open(scope)?;
            let rec = v.record_mut(&id);
            let before = rec.fields.len();
            rec.fields.retain(|f| f.name != fname);
            if rec.fields.len() == before {
                bail!("no field {fname:?}");
            }
            v.save()?;
            ctx.audit(scope, "field.remove", Some(r.to_string()), None);
            ui::ok(format!("Removed {r}"));
            Ok(0)
        }
        FieldCmd::Edit {
            reference,
            kind,
            secret,
            rename,
        } => {
            let r = ctx.parse_ref(&reference)?;
            let fname = r.require_field()?.to_string();
            let (scope, id) = ctx.record_id(&r)?;
            let v = ctx.ws.open(scope)?;
            let rec = v.record_mut(&id);
            if let Some(new) = &rename {
                validate_name(new, "field")?;
                if rec.field(new).is_some() {
                    bail!("there is already a field {new:?}");
                }
            }
            let f = rec
                .field_mut(&fname)
                .ok_or_else(|| anyhow!("no field {fname:?}"))?;
            if let Some(k) = kind {
                f.kind = k;
            }
            if let Some(s) = secret {
                f.secret = s;
            }
            if let Some(new) = rename {
                f.name = new;
            }
            v.save()?;
            ctx.audit(scope, "field.edit", Some(r.to_string()), None);
            ui::ok("Updated");
            Ok(0)
        }
    }
}

pub fn find(ctx: &mut Ctx, text: &str) -> Result<i32> {
    let needle = text.to_lowercase();
    let scope = ctx.scope()?;
    let v = ctx.ws.open(scope)?;
    let mut hits = 0;
    let mut recs: Vec<&Record> = v.records.values().collect();
    recs.sort_by_key(|r| v.record_path(r));
    for r in recs {
        let path = v.record_path(r);
        let mut why = Vec::new();
        if path.to_lowercase().contains(&needle) {
            why.push("name".to_string());
        }
        for f in &r.fields {
            if f.name.to_lowercase().contains(&needle) {
                why.push(format!("field {}", f.name));
            }
        }
        for (k, val) in &r.memory {
            if val.to_lowercase().contains(&needle) {
                why.push(k.clone());
            }
        }
        if !why.is_empty() {
            hits += 1;
            println!("{path}  ({})", why.join(", "));
        }
    }
    for e in v.entities.values() {
        if e.memory
            .values()
            .any(|m| m.to_lowercase().contains(&needle))
        {
            hits += 1;
            println!("{}/  (entity memory)", v.entity_path_string(&e.id));
        }
    }
    if hits == 0 {
        eprintln!("Nothing found for {text:?}");
        return Ok(1);
    }
    Ok(0)
}

fn describe_value(f: &Field, env_key: &str) -> String {
    let slot = &f.values[env_key];
    if let Some(ext) = &slot.external {
        return format!("not stored here: {ext}");
    }
    match slot.current_version() {
        None => "—".to_string(),
        Some(ver) => {
            let when = ui::when(ver.at, "%Y-%m-%d");
            let n = slot.versions.len();
            if f.secret {
                format!("set ({when}, v{n})")
            } else {
                match &ver.value {
                    Value::Text { text } => {
                        let t = text.expose();
                        let shown: String = t.chars().take(60).collect();
                        if t.chars().count() > 60 {
                            format!("{shown}…")
                        } else {
                            shown
                        }
                    }
                    Value::File { name, .. } => format!("file {name}"),
                }
            }
        }
    }
}

pub fn show(ctx: &mut Ctx, reference: &str) -> Result<i32> {
    let r = ctx.parse_ref(reference)?;
    let (scope, rec) = ctx.record(&r)?;
    let v = ctx.ws.get(scope).expect("opened");
    let envs = v.effective_envs(&rec.entity);
    println!(
        "{} ({scope} vault){}",
        v.record_path(&rec),
        if rec.archived { " — archived" } else { "" }
    );
    if !rec.memory.is_empty() {
        println!();
        for (k, val) in &rec.memory {
            println!("  {k}: {val}");
        }
    }
    println!();
    if rec.fields.is_empty() {
        println!(
            "  (no fields yet: cemi field add {} <name> [--secret])",
            v.record_path(&rec)
        );
    }
    for f in &rec.fields {
        let flag = if f.secret { "secret" } else { "" };
        println!(
            "  {}  [{}{}{}]",
            f.name,
            f.kind,
            if f.secret { ", " } else { "" },
            flag
        );
        if f.values.is_empty() {
            println!("      no value");
        }
        let mut keys: Vec<&String> = f.values.keys().collect();
        keys.sort_by_key(|k| (k.as_str() != SHARED, envs.iter().position(|e| e == *k)));
        for k in keys {
            let label = if k == SHARED { "all envs" } else { k.as_str() };
            println!("      {label}: {}", describe_value(f, k));
        }
        let env_name = |e: &str| {
            if e == SHARED {
                "all envs".to_string()
            } else {
                e.to_string()
            }
        };
        for (e, o) in &f.origins {
            println!("      new values ({}): {}", env_name(e), o.spec.describe());
        }
        for d in &f.destinations {
            let sent = match &d.last {
                Some(l) => format!("last sent {}", ui::when(l.at, "%Y-%m-%d %H:%M")),
                None => "never sent".to_string(),
            };
            println!(
                "      copied to ({}): {}  [{}, {sent}]",
                env_name(&d.env),
                d.spec.describe(),
                d.id
            );
        }
        for (e, cmd) in &f.verify {
            println!("      checked by ({}): {}", env_name(e), cmd.join(" "));
        }
    }
    if !envs.is_empty() {
        println!();
        println!("  environments: {}", envs.join(", "));
    }
    Ok(0)
}

pub fn env(ctx: &mut Ctx, cmd: EnvCmd) -> Result<i32> {
    match cmd {
        EnvCmd::Ls { at } => {
            let (sel, path) = ctx.entity_path(at.as_deref())?;
            let scope = ctx.ws.scope_for(sel)?;
            let v = ctx.ws.open(scope)?;
            let id = v.find_entity_id(&path)?;
            for e in v.effective_envs(&id) {
                if v.is_protected(&e) {
                    println!("{e} (protected)");
                } else {
                    println!("{e}");
                }
            }
            Ok(0)
        }
        EnvCmd::Protect { name } => super::rotation_cmds::protect(ctx, &name, true),
        EnvCmd::Unprotect { name } => super::rotation_cmds::protect(ctx, &name, false),
        EnvCmd::Add { name, at } => {
            validate_name(&name, "environment")?;
            if name == SHARED {
                bail!("{SHARED:?} is reserved");
            }
            let (sel, path) = ctx.entity_path(at.as_deref())?;
            let scope = ctx.ws.scope_for(sel)?;
            let v = ctx.ws.open(scope)?;
            let id = v.find_entity_id(&path)?;
            if v.effective_envs(&id).contains(&name) {
                bail!("{name:?} already exists here");
            }
            v.entity_mut(&id).envs.push(name.clone());
            v.save()?;
            ctx.audit(scope, "env.add", Some(display_path(&path)), Some(&name));
            ui::ok(format!(
                "Added environment {name} to {}",
                display_path(&path)
            ));
            Ok(0)
        }
        EnvCmd::Rm { name, at } => {
            let (sel, path) = ctx.entity_path(at.as_deref())?;
            let scope = ctx.ws.scope_for(sel)?;
            let v = ctx.ws.open(scope)?;
            let id = v.find_entity_id(&path)?;
            if !v.entities[&id].envs.contains(&name) {
                bail!(
                    "{name:?} is not defined on {} (it may be inherited from a parent)",
                    display_path(&path)
                );
            }
            let subtree = v.subtree(&id);
            let with_values = v
                .records
                .values()
                .filter(|r| subtree.contains(&r.entity))
                .filter(|r| r.fields.iter().any(|f| f.values.contains_key(&name)))
                .count();
            if with_values > 0
                && !ui::confirm(&format!(
                    "{with_values} record(s) have values for {name}. They stay stored but unused. Remove the environment?"
                ))
            {
                bail!("cancelled");
            }
            v.entity_mut(&id).envs.retain(|e| e != &name);
            v.save()?;
            ctx.audit(scope, "env.remove", Some(display_path(&path)), Some(&name));
            ui::ok(format!("Removed environment {name}"));
            Ok(0)
        }
        EnvCmd::Diff { a, b, at } => {
            let (sel, path) = ctx.entity_path(at.as_deref())?;
            let scope = ctx.ws.scope_for(sel)?;
            let v = ctx.ws.open(scope)?;
            let id = v.find_entity_id(&path)?;
            let subtree = v.subtree(&id);
            let mut recs: Vec<&Record> = v
                .records
                .values()
                .filter(|r| subtree.contains(&r.entity) && !r.archived)
                .collect();
            recs.sort_by_key(|r| v.record_path(r));
            let mut lines = 0;
            for r in recs {
                for f in &r.fields {
                    let va = f.current(Some(&a));
                    let vb = f.current(Some(&b));
                    let ext_a = f
                        .slot_for(Some(&a))
                        .is_some_and(|(_, s)| s.external.is_some());
                    let ext_b = f
                        .slot_for(Some(&b))
                        .is_some_and(|(_, s)| s.external.is_some());
                    let name = format!("{}#{}", v.record_path(r), f.name);
                    match (va, vb) {
                        (Some(_), None) if !ext_b => {
                            println!("  missing in {b}: {name}");
                            lines += 1;
                        }
                        (None, Some(_)) if !ext_a => {
                            println!("  missing in {a}: {name}");
                            lines += 1;
                        }
                        (Some(x), Some(y)) => {
                            let shared_a = f.slot_for(Some(&a)).is_some_and(|(k, _)| k == SHARED);
                            if f.secret && !shared_a && crypto::ct_eq(&x.bytes(), &y.bytes()) {
                                println!("  ! same secret in {a} and {b}: {name}");
                                lines += 1;
                            }
                        }
                        _ => {}
                    }
                }
            }
            if lines == 0 {
                ui::ok(format!(
                    "{a} and {b} have the same fields set, and no secret is repeated"
                ));
            }
            Ok(if lines == 0 { 0 } else { 1 })
        }
    }
}
