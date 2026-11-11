use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use super::Ctx;
use crate::cli::VarCmd;
use crate::dotenv::{self, check_var_name};
use crate::model::{Field, FieldKind, SHARED, Value, memory_keys as mk};
use crate::project::{self, Project};
use crate::refs::VaultSel;
use crate::runner;
use crate::ui;
use crate::vault::{Scope, display_path};

pub fn link(ctx: &mut Ctx, entity: Option<&str>) -> Result<i32> {
    let (sel, path) = ctx.entity_path(entity)?;
    let scope = ctx.ws.scope_for(sel)?;
    {
        let v = ctx.ws.open(scope)?;
        v.find_entity_id(&path).map_err(|_| {
            anyhow!(
                "the {scope} vault has no entity {}. Create a record in it first (cemi add {}/<record>)",
                display_path(&path),
                path.join("/")
            )
        })?;
    }
    let file = match crate::workspace::find_project_file(&ctx.ws.cwd) {
        Some(f) => f,
        None => ctx.ws.cwd.join(project::FILE),
    };
    let vault_name = scope.to_string();
    let entity_text = path.join("/");
    if file.exists() {
        Project::edit(&file, |doc| {
            doc["vault"] = toml_edit::value(vault_name.as_str());
            if entity_text.is_empty() {
                doc.remove("entity");
            } else {
                doc["entity"] = toml_edit::value(entity_text.as_str());
            }
            Ok(())
        })?;
    } else {
        let entity = if entity_text.is_empty() {
            None
        } else {
            Some(entity_text.as_str())
        };
        std::fs::write(&file, project::template(Some(&vault_name), entity))?;
    }
    ui::ok(format!(
        "{} now points at {} in the {scope} vault",
        file.display(),
        display_path(&path)
    ));
    Ok(0)
}

pub fn var(ctx: &mut Ctx, cmd: VarCmd) -> Result<i32> {
    let project = ctx.require_project()?;
    match cmd {
        VarCmd::Ls => {
            for (k, v) in &project.file.env {
                println!("{k} = {}", v.text());
            }
            for (k, v) in &project.file.files {
                println!("{k} = {}  (file)", v.text());
            }
            Ok(0)
        }
        VarCmd::Add {
            name,
            reference,
            file,
        } => {
            check_var_name(&name)?;
            let r = project.resolve_ref(&reference)?;
            // Fail early on typos: the record has to exist.
            let scope = ctx.ws.scope_for(r.vault)?;
            let v = ctx.ws.open(scope)?;
            let rec = v.find_record(&r.entities, &r.record)?;
            if rec.field(r.require_field()?).is_none() {
                bail!(
                    "{} has no field {:?}",
                    r.record_path(),
                    r.field.as_deref().unwrap_or("")
                );
            }
            let table = if file { "files" } else { "env" };
            let other = if file { "env" } else { "files" };
            Project::edit(&project.path, |doc| {
                if doc.get(table).is_none() {
                    doc[table] = toml_edit::table();
                }
                doc[table][name.as_str()] = toml_edit::value(reference.as_str());
                if let Some(t) = doc.get_mut(other).and_then(|t| t.as_table_like_mut()) {
                    t.remove(&name);
                }
                Ok(())
            })?;
            ui::ok(format!("{name} → {r}"));
            Ok(0)
        }
        VarCmd::Rm { name } => {
            let mut removed = false;
            Project::edit(&project.path, |doc| {
                for table in ["env", "files"] {
                    if let Some(t) = doc.get_mut(table).and_then(|t| t.as_table_like_mut()) {
                        removed |= t.remove(&name).is_some();
                    }
                }
                Ok(())
            })?;
            if !removed {
                bail!("{name} is not in {}", project.path.display());
            }
            ui::ok(format!("Removed {name}"));
            Ok(0)
        }
    }
}

pub fn run(mut ctx: Ctx, env: Option<&str>, redact: bool, command: &[String]) -> Result<i32> {
    let project = ctx.require_project()?;
    let plan = runner::plan(&mut ctx.ws, &project, env)?;
    // Audit, then release the vault before the command starts: it may run for hours.
    for scope in [Scope::Global, Scope::Local] {
        if ctx.ws.get(scope).is_some() {
            ctx.audit_detail(
                scope,
                "run",
                Some(project.path.display().to_string()),
                env,
                Some(command.first().cloned().unwrap_or_default()),
            );
        }
    }
    drop(ctx);
    let redactor = if redact {
        Some(runner::Redactor::new(&plan.secrets))
    } else {
        None
    };
    let prepared = runner::prepare(&plan)?;
    drop(plan);
    runner::run_interactive(command, &prepared, redactor.as_ref())
}

pub fn export(ctx: &mut Ctx, output: Option<std::path::PathBuf>) -> Result<i32> {
    let project = ctx.require_project()?;
    let mut out = String::from(
        "# Generated by `cemi export`. Values come from Cemí: run with `cemi run -e <env> -- <command>`.\n",
    );
    for (k, v) in &project.file.env {
        if let Some(p) = v.purpose() {
            out.push_str(&format!("# {p}\n"));
        }
        out.push_str(&format!("{k}=\n"));
    }
    for (k, v) in &project.file.files {
        out.push_str(&format!(
            "# path to a file ({})\n",
            v.purpose().unwrap_or("from Cemí")
        ));
        out.push_str(&format!("{k}=\n"));
    }
    match output {
        Some(p) => {
            std::fs::write(&p, out)?;
            ui::ok(format!("Wrote {}", p.display()));
        }
        None => print!("{out}"),
    }
    Ok(0)
}

pub fn import(
    ctx: &mut Ctx,
    file: &Path,
    into: Option<&str>,
    env: Option<&str>,
    plain: &str,
    no_link: bool,
) -> Result<i32> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?;
    let pairs = dotenv::parse(&text)?;
    if pairs.is_empty() {
        bail!("{} has no variables", file.display());
    }
    let plain: Vec<&str> = plain
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let project = if no_link { None } else { ctx.project()? };

    // Default destination: the project's base entity.
    let (sel, path) = match (into, &project) {
        (Some(i), _) => ctx.entity_path(Some(i))?,
        (None, Some(p)) => {
            let (s, e) = p.base()?;
            (if ctx.global { VaultSel::Global } else { s }, e)
        }
        (None, None) => ctx.entity_path(None)?,
    };
    let scope = ctx.ws.scope_for(sel)?;
    let v = ctx.ws.open(scope)?;
    let entity = v.ensure_entity(&path)?;
    if let Some(e) = env
        && !v.effective_envs(&entity).iter().any(|x| x == e)
    {
        bail!("environment {e:?} does not exist there; add it with `cemi env add {e}`");
    }
    let mut created = 0;
    let mut updated = 0;
    for (key, value) in &pairs {
        let id = match v.find_record_in(&entity, key) {
            Some(r) => {
                updated += 1;
                r.id.clone()
            }
            None => {
                created += 1;
                v.add_record(&entity, key)?
            }
        };
        let rec = v.record_mut(&id);
        if rec.field("value").is_none() {
            let kind = if value.contains('\n') {
                FieldKind::Multiline
            } else {
                FieldKind::Text
            };
            rec.fields
                .push(Field::new("value", kind, !plain.contains(&key.as_str())));
        }
        rec.memory
            .entry(mk::USED_IN.to_string())
            .or_insert_with(|| format!("imported from {}", file.display()));
        let f = rec.field_mut("value").expect("ensured");
        f.values
            .entry(env.unwrap_or(SHARED).to_string())
            .or_default()
            .push(
                Value::text(value.as_str()),
                "cli",
                Some(format!("import {}", file.display())),
            );
    }
    v.save()?;
    ctx.audit_detail(
        scope,
        "import",
        Some(display_path(&path)),
        env,
        Some(format!("{} variables", pairs.len())),
    );
    ui::ok(format!(
        "Imported {} variables into {} ({created} new, {updated} updated)",
        pairs.len(),
        display_path(&path)
    ));

    if let Some(p) = project {
        let (base_sel, base) = p.base()?;
        let base_scope = ctx.ws.scope_for(base_sel)?;
        Project::edit(&p.path, |doc| {
            if doc.get("env").is_none() {
                doc["env"] = toml_edit::table();
            }
            for (key, _) in &pairs {
                let reference = if base_scope == scope && path.starts_with(&base) {
                    let mut rel: Vec<String> = path[base.len()..].to_vec();
                    rel.push(key.clone());
                    format!("{}#value", rel.join("/"))
                } else {
                    let mut abs = path.clone();
                    abs.push(key.clone());
                    format!("{scope}:{}#value", abs.join("/"))
                };
                doc["env"][key.as_str()] = toml_edit::value(reference);
            }
            Ok(())
        })?;
        ui::ok(format!("Added them to {}", p.path.display()));
    }
    ui::warn(format!(
        "{} still has the plain values. Delete it once `cemi run` works for you.",
        file.display()
    ));
    Ok(0)
}
