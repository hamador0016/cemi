//! Memory: what each secret is for, plus status, tasks, dependencies and the inventory.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use anyhow::{Result, anyhow, bail};
use jiff::Zoned;
use jiff::civil::Date;
use serde_json::{Value as Json, json};

use super::Ctx;
use crate::cli::{NoteArgs, TaskCmd};
use crate::model::{FieldKind, Record, Task, memory_keys as mk};
use crate::refs::{Ref, VaultSel};
use crate::resolve;
use crate::ui;
use crate::vault::{Scope, display_path};

fn today() -> Date {
    Zoned::now().date()
}

pub fn status(ctx: &mut Ctx) -> Result<i32> {
    let mut problems = 0;
    let mut vaults_json: Vec<Json> = Vec::new();
    let mut project_json: Json = Json::Null;
    let project = ctx.project()?;
    let main = ctx.scope()?;
    let mut scopes = vec![main];
    if let Some(p) = &project {
        for spec in p.file.env.values().chain(p.file.files.values()) {
            if let Ok(r) = p.resolve_ref(spec.text())
                && let Ok(s) = ctx.ws.scope_for(r.vault)
                && !scopes.contains(&s)
            {
                scopes.push(s);
            }
        }
    }
    for scope in scopes {
        let dir = ctx.ws.dir(scope)?;
        let v = ctx.ws.open(scope)?;
        let root = v.root_id();
        crate::outln!(
            "{scope} vault ({}) — {} records, environments: {}",
            dir.display(),
            v.records.values().filter(|r| !r.archived).count(),
            v.effective_envs(&root).join(", ")
        );
        let mut items = crate::cmd_shared::attention(v, None);
        items.extend(crate::rotation::attention(&mut ctx.ws, scope, None));
        for a in &items {
            crate::outln!("  ! {}: {}", a.what, a.detail);
        }
        problems += items.len();
        let v = ctx.ws.get(scope).expect("opened");
        vaults_json.push(json!({
            "vault": scope.to_string(),
            "dir": dir.display().to_string(),
            "records": v.records.values().filter(|r| !r.archived).count(),
            "environments": v.effective_envs(&v.root_id()),
            "attention": items.iter().map(|a| json!({ "what": a.what, "detail": a.detail })).collect::<Vec<_>>(),
        }));
    }
    if let Some(p) = project {
        let mut project_problems: Vec<Json> = Vec::new();
        crate::outln!("project ({})", p.path.display());
        let (sel, base) = p.base()?;
        let scope = ctx.ws.scope_for(sel)?;
        let envs = {
            let v = ctx.ws.open(scope)?;
            match v.find_entity(&base) {
                Some(e) => v.effective_envs(&e.id.clone()),
                None => {
                    crate::outln!("  ! entity {} does not exist", display_path(&base));
                    project_problems.push(json!({
                        "problem": format!("entity {} does not exist", display_path(&base)),
                    }));
                    problems += 1;
                    Vec::new()
                }
            }
        };
        let mut env_list: Vec<Option<&str>> = envs.iter().map(|e| Some(e.as_str())).collect();
        if env_list.is_empty() {
            env_list.push(None);
        }
        for (var, spec) in p.file.env.iter().chain(p.file.files.iter()) {
            let r = match p.resolve_ref(spec.text()) {
                Ok(r) => r,
                Err(e) => {
                    crate::outln!("  ! {var}: {e}");
                    project_problems.push(json!({ "variable": var, "problem": e.to_string() }));
                    problems += 1;
                    continue;
                }
            };
            let mut missing = Vec::new();
            for env in &env_list {
                if let Err(e) = resolve::resolve(&mut ctx.ws, &r, *env) {
                    missing.push(format!("{}: {e:#}", env.unwrap_or("all")));
                }
            }
            if missing.len() == env_list.len() && !missing.is_empty() {
                let why = missing[0].split_once(": ").map(|x| x.1).unwrap_or("");
                crate::outln!("  ! {var} ({r}): {why}");
                project_problems.push(json!({
                    "variable": var, "reference": r.to_string(), "problem": why,
                }));
                problems += 1;
            } else {
                for m in missing {
                    crate::outln!("  ! {var} ({r}) — {m}");
                    project_problems.push(json!({
                        "variable": var, "reference": r.to_string(), "problem": m,
                    }));
                    problems += 1;
                }
            }
        }
        if p.file.env.is_empty() && p.file.files.is_empty() {
            crate::outln!("  no variables yet: `cemi var add NAME record#field`");
        }
        project_json = json!({
            "path": p.path.display().to_string(),
            "variables": p.file.env.len() + p.file.files.len(),
            "problems": project_problems,
        });
    }
    if problems == 0 {
        ui::ok("Nothing needs attention");
    }
    ui::data(json!({
        "needs_attention": problems,
        "vaults": vaults_json,
        "project": project_json,
    }));
    Ok(0)
}

/// Finds a record or an entity from a path.
enum Target {
    Record(Scope, String),
    Entity(Scope, String),
}

fn target(ctx: &mut Ctx, path: &str) -> Result<Target> {
    if path.contains('#') {
        bail!("give a record or entity path, without #field");
    }
    let r = ctx.parse_ref(path)?;
    let scope = ctx.ws.scope_for(r.vault)?;
    let v = ctx.ws.open(scope)?;
    if let Ok(id) = v.find_record_id(&r.entities, &r.record) {
        return Ok(Target::Record(scope, id));
    }
    let mut epath = r.entities.clone();
    epath.push(r.record.clone());
    if let Some(e) = v.find_entity(&epath) {
        return Ok(Target::Entity(scope, e.id.clone()));
    }
    bail!("no record or entity called {path}")
}

pub fn note(ctx: &mut Ctx, a: NoteArgs) -> Result<i32> {
    let mut changes: Vec<(String, Option<String>)> = Vec::new();
    for (k, v) in [
        (mk::PURPOSE, &a.purpose),
        (mk::USED_IN, &a.used_in),
        (mk::ROTATE, &a.rotate),
        (mk::IF_LOST, &a.if_lost),
        (mk::IF_LEAKED, &a.if_leaked),
        (mk::EXPIRES, &a.expires),
        (mk::BACKUP, &a.backup),
        (mk::LINKS, &a.links),
        (mk::DELICATE, &a.delicate),
    ] {
        if let Some(v) = v {
            changes.push((
                k.to_string(),
                if v.is_empty() { None } else { Some(v.clone()) },
            ));
        }
    }
    for kv in &a.set {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow!("--set needs KEY=VALUE, got {kv:?}"))?;
        crate::model::validate_name(k.trim(), "memory key")?;
        changes.push((k.trim().to_string(), Some(v.to_string())));
    }
    for k in &a.unset {
        changes.push((k.clone(), None));
    }
    if let Some((_, Some(d))) = changes.iter().find(|(k, _)| k == mk::EXPIRES) {
        d.trim()
            .parse::<Date>()
            .map_err(|_| anyhow!("--expires must be a date like 2027-11-09"))?;
    }
    let t = target(ctx, &a.path)?;
    let (scope, memory) = match &t {
        Target::Record(s, id) => (
            *s,
            ctx.ws.get(*s).expect("opened").records[id].memory.clone(),
        ),
        Target::Entity(s, id) => (
            *s,
            ctx.ws.get(*s).expect("opened").entities[id].memory.clone(),
        ),
    };
    if changes.is_empty() {
        if memory.is_empty() {
            crate::outln!("(no memory yet)");
            crate::outln!(
                "Add some: cemi note {} --purpose \"…\" --used-in \"…\" --rotate \"…\" --if-lost \"…\" --backup \"…\"",
                a.path
            );
        }
        for (k, v) in &memory {
            crate::outln!("{k}: {v}");
        }
        return Ok(0);
    }
    let v = ctx.ws.open(scope)?;
    let mem = match &t {
        Target::Record(_, id) => &mut v.record_mut(id).memory,
        Target::Entity(_, id) => &mut v.entity_mut(id).memory,
    };
    for (k, val) in &changes {
        match val {
            Some(val) => {
                mem.insert(k.clone(), val.clone());
            }
            None => {
                mem.remove(k);
            }
        }
    }
    v.save()?;
    let keys: Vec<&str> = changes.iter().map(|(k, _)| k.as_str()).collect();
    ctx.audit_detail(
        scope,
        "memory.edit",
        Some(a.path.clone()),
        None,
        Some(keys.join(", ")),
    );
    ui::ok(format!("Updated {} of {}", keys.join(", "), a.path));
    Ok(0)
}

pub fn task(ctx: &mut Ctx, cmd: TaskCmd) -> Result<i32> {
    match cmd {
        TaskCmd::Ls => {
            let scope = ctx.scope()?;
            let v = ctx.ws.open(scope)?;
            let mut any = false;
            let mut list: Vec<Json> = Vec::new();
            for e in v.entities.values() {
                for t in &e.tasks {
                    any = true;
                    list.push(json!({
                        "entity": v.entity_path_string(&e.id),
                        "name": t.name,
                        "every": format!("{:?}", t.every).to_lowercase(),
                        "next": t.due().to_string(),
                        "due": t.due() <= today(),
                    }));
                    crate::outln!(
                        "{}/  {}  every {:?}, next {}{}",
                        v.entity_path_string(&e.id),
                        t.name,
                        t.every,
                        t.due(),
                        if t.due() <= today() { "  (due)" } else { "" }
                    );
                }
            }
            if !any {
                crate::outln!(
                    "No tasks. Add one: cemi task add <entity> \"monthly restore test\" --every month"
                );
            }
            ui::data(json!({ "tasks": list }));
            Ok(0)
        }
        TaskCmd::Add {
            entity,
            name,
            every,
        } => {
            let (sel, path) = ctx.entity_path(Some(&entity))?;
            let scope = ctx.ws.scope_for(sel)?;
            let v = ctx.ws.open(scope)?;
            let id = v.find_entity_id(&path)?;
            let e = v.entity_mut(&id);
            if e.tasks.iter().any(|t| t.name == name) {
                bail!("there is already a task {name:?} there");
            }
            e.tasks.push(Task {
                name: name.clone(),
                every,
                last_done: None,
                created: today(),
            });
            v.save()?;
            ctx.audit(
                scope,
                "task.add",
                Some(format!("{}: {name}", display_path(&path))),
                None,
            );
            ui::ok(format!("Added task {name:?}"));
            Ok(0)
        }
        TaskCmd::Done { entity, name } => {
            let (sel, path) = ctx.entity_path(Some(&entity))?;
            let scope = ctx.ws.scope_for(sel)?;
            let v = ctx.ws.open(scope)?;
            let id = v.find_entity_id(&path)?;
            let e = v.entity_mut(&id);
            let t = e
                .tasks
                .iter_mut()
                .find(|t| t.name == name)
                .ok_or_else(|| anyhow!("no task {name:?}"))?;
            t.last_done = Some(today());
            let next = t.due();
            v.save()?;
            ctx.audit(
                scope,
                "task.done",
                Some(format!("{}: {name}", display_path(&path))),
                None,
            );
            ui::ok(format!("Done. Next time: {next}"));
            Ok(0)
        }
        TaskCmd::Rm { entity, name } => {
            let (sel, path) = ctx.entity_path(Some(&entity))?;
            let scope = ctx.ws.scope_for(sel)?;
            let v = ctx.ws.open(scope)?;
            let id = v.find_entity_id(&path)?;
            let e = v.entity_mut(&id);
            let before = e.tasks.len();
            e.tasks.retain(|t| t.name != name);
            if e.tasks.len() == before {
                bail!("no task {name:?}");
            }
            v.save()?;
            ui::ok("Removed");
            Ok(0)
        }
    }
}

/// References inside a template text.
pub fn deps(ctx: &mut Ctx, reference: &str) -> Result<i32> {
    let r = ctx.parse_ref(reference)?;
    let fname = r.require_field()?.to_string();
    let (scope, rec) = ctx.record(&r)?;
    let mut found = 0;
    let mut used_by: Vec<Json> = Vec::new();
    {
        let v = ctx.ws.get(scope).expect("opened");
        let target_entity = v.entity_path(&rec.entity);
        for other in v.records.values() {
            let other_entity = v.entity_path(&other.entity);
            for f in &other.fields {
                if f.kind != FieldKind::Template {
                    continue;
                }
                for slot in f.values.values() {
                    let Some(val) = slot.current() else { continue };
                    let text = String::from_utf8_lossy(&val.bytes()).into_owned();
                    for part in crate::resolve::template_refs(&text) {
                        let parsed = if let Some(abs) = part.strip_prefix('/') {
                            Ref::parse(abs).ok()
                        } else {
                            Ref::parse(&part).ok().map(|p| {
                                let mut ents = other_entity.clone();
                                ents.extend(p.entities.clone());
                                Ref {
                                    entities: ents,
                                    ..p
                                }
                            })
                        };
                        if let Some(p) = parsed
                            && p.vault == VaultSel::Default
                            && p.entities == target_entity
                            && p.record == rec.name
                            && p.field.as_deref() == Some(fname.as_str())
                        {
                            found += 1;
                            crate::outln!("template {}#{}", v.record_path(other), f.name);
                            used_by.push(json!({
                                "kind": "template",
                                "reference": format!("{}#{}", v.record_path(other), f.name),
                            }));
                        }
                    }
                }
            }
        }
    }
    if let Some(p) = ctx.project()? {
        for (var, spec) in p.file.env.iter().chain(p.file.files.iter()) {
            if let Ok(pr) = p.resolve_ref(spec.text())
                && ctx.ws.scope_for(pr.vault).ok() == Some(scope)
                && pr.entities == r.entities
                && pr.record == r.record
                && pr.field == r.field
            {
                found += 1;
                crate::outln!("cemi.toml {var} ({})", p.path.display());
                used_by.push(json!({
                    "kind": "project",
                    "variable": var,
                    "file": p.path.display().to_string(),
                }));
            }
        }
    }
    if let Some(used) = rec.memory.get(mk::USED_IN) {
        crate::outln!("noted as used in: {used}");
    }
    if found == 0 {
        eprintln!("Nothing in this vault or project uses {r}.");
    }
    ui::data(json!({
        "used_by": used_by,
        "noted_used_in": rec.memory.get(mk::USED_IN),
    }));
    Ok(0)
}

pub fn doc(ctx: &mut Ctx, entity: Option<&str>, output: Option<std::path::PathBuf>) -> Result<i32> {
    let (sel, path) = ctx.entity_path(entity)?;
    let scope = ctx.ws.scope_for(sel)?;
    let v = ctx.ws.open(scope)?;
    let start = v.find_entity_id(&path)?;
    let subtree = v.subtree(&start);
    let mut md = String::new();
    let title = if path.is_empty() {
        format!("{scope} vault")
    } else {
        path.join("/")
    };
    writeln!(md, "# Secrets inventory — {title}\n")?;
    writeln!(
        md,
        "Generated by `cemi doc` on {}. **It contains no secret values**: only names, purpose, where they are used and how to replace them.\n",
        today()
    )?;
    let mut by_entity: BTreeMap<String, Vec<&Record>> = BTreeMap::new();
    for r in v
        .records
        .values()
        .filter(|r| subtree.contains(&r.entity) && !r.archived)
    {
        by_entity
            .entry(v.entity_path_string(&r.entity))
            .or_default()
            .push(r);
    }
    for (epath, mut recs) in by_entity {
        recs.sort_by(|a, b| a.name.cmp(&b.name));
        writeln!(
            md,
            "## {}\n",
            if epath.is_empty() {
                "(root)".to_string()
            } else {
                epath.clone()
            }
        )?;
        if let Some(e) = v.find_entity(&crate::refs::entity_path(&epath)?) {
            let envs = v.effective_envs(&e.id);
            if !envs.is_empty() {
                writeln!(md, "Environments: {}\n", envs.join(", "))?;
            }
            for (k, val) in &e.memory {
                writeln!(md, "- **{k}**: {val}")?;
            }
            for t in &e.tasks {
                writeln!(
                    md,
                    "- Task: {} (every {:?}, next {})",
                    t.name,
                    t.every,
                    t.due()
                )?;
            }
            if !e.memory.is_empty() || !e.tasks.is_empty() {
                writeln!(md)?;
            }
        }
        writeln!(
            md,
            "| Record | Fields | Purpose | Used in | If lost or leaked | Expires | Backup |"
        )?;
        writeln!(md, "|---|---|---|---|---|---|---|")?;
        for r in recs {
            let fields: Vec<String> = r
                .fields
                .iter()
                .map(|f| {
                    let mut s = format!("`{}`", f.name);
                    if f.secret {
                        s.push_str(" (secret)");
                    }
                    let ext: Vec<&String> = f
                        .values
                        .values()
                        .filter_map(|s| s.external.as_ref())
                        .collect();
                    if !ext.is_empty() {
                        s.push_str(&format!(
                            " — lives in {}",
                            ext.iter()
                                .map(|e| e.as_str())
                                .collect::<Vec<_>>()
                                .join("; ")
                        ));
                    }
                    s
                })
                .collect();
            let m = |k: &str| cell(r.memory.get(k).map(String::as_str).unwrap_or(""));
            let lost = [
                r.memory.get(mk::IF_LOST),
                r.memory.get(mk::IF_LEAKED),
                r.memory.get(mk::ROTATE),
            ]
            .into_iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>()
            .join(" / ");
            writeln!(
                md,
                "| **{}** | {} | {} | {} | {} | {} | {} |",
                cell(&r.name),
                cell(&fields.join("<br>")),
                m(mk::PURPOSE),
                m(mk::USED_IN),
                cell(&lost),
                m(mk::EXPIRES),
                m(mk::BACKUP)
            )?;
        }
        writeln!(md)?;
    }
    match output {
        Some(p) => {
            std::fs::write(&p, md)?;
            ui::ok(format!("Wrote {}", p.display()));
        }
        None => crate::out!("{md}"),
    }
    Ok(0)
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', "<br>")
}

/// `cemi prompt`: one short line for a shell prompt. Only what needs doing
/// soon counts (see `Attention::urgent`). It never asks for a password and
/// never uses the network: a locked vault shows as "locked" in a project,
/// and as nothing elsewhere.
pub fn prompt(ctx: &mut Ctx) -> Result<i32> {
    ui::set_non_interactive();
    let in_project =
        ctx.ws.local_dir.is_some() || crate::workspace::find_project_file(&ctx.ws.cwd).is_some();
    let mut scopes = Vec::new();
    if ctx.ws.local_dir.is_some() {
        scopes.push(Scope::Local);
    }
    if ctx.ws.global_exists() {
        scopes.push(Scope::Global);
    }
    let mut locked = false;
    let mut items: Vec<crate::cmd_shared::Attention> = Vec::new();
    for scope in scopes {
        match ctx.ws.open(scope) {
            Ok(v) => {
                items.extend(crate::cmd_shared::attention(v, None));
                items.extend(crate::rotation::attention(&mut ctx.ws, scope, None));
            }
            Err(_) => locked = true,
        }
    }
    items.retain(|a| a.urgent);
    let line = if !items.is_empty() {
        format!("cemi !{}", items.len())
    } else if locked && in_project {
        "cemi locked".to_string()
    } else {
        String::new()
    };
    if !line.is_empty() {
        crate::outln!("{line}");
    }
    ui::data(json!({
        "locked": locked,
        "urgent": items.iter().map(|a| json!({ "what": a.what, "detail": a.detail })).collect::<Vec<_>>(),
    }));
    Ok(0)
}
