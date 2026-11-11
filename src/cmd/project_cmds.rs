use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use zeroize::Zeroizing;

use super::Ctx;
use crate::cli::VarCmd;
use crate::discover::{self, FoundProject, GitState};
use crate::dotenv::{self, check_var_name};
use crate::model::{Field, FieldKind, SHARED, Value, memory_keys as mk, validate_name};
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
    let text = Zeroizing::new(
        std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?,
    );
    let pairs: Vec<(String, Zeroizing<String>)> = dotenv::parse(&text)?
        .into_iter()
        .map(|(k, v)| (k, Zeroizing::new(v)))
        .collect();
    if pairs.is_empty() {
        bail!("{} has no variables", file.display());
    }
    let plain = plain_list(plain);
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
    let source = file.display().to_string();
    let n = store_vars(v, &entity, env, &pairs, &plain, &source)?;
    v.save()?;
    ctx.audit_detail(
        scope,
        "import",
        Some(display_path(&path)),
        env,
        Some(format!("{} variables", pairs.len())),
    );
    ui::ok(format!(
        "Imported {} variables into {} ({})",
        pairs.len(),
        display_path(&path),
        n.summary()
    ));

    if let Some(p) = project {
        let entries: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, _)| (k.clone(), format!("{k}#value")))
            .collect();
        let linked = link_vars(ctx, &p.path, scope, &path, &entries)?;
        ui::ok(format!(
            "Added {} variables to {}",
            linked.added.len(),
            p.path.display()
        ));
        for k in &linked.kept {
            ui::warn(format!(
                "{k} was already in {}; left as it was",
                p.path.display()
            ));
        }
    }
    ui::warn(format!(
        "{} still has the plain values. Delete it once `cemi run` works for you.",
        file.display()
    ));
    Ok(0)
}

fn plain_list(plain: &str) -> Vec<String> {
    plain
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(Default)]
struct Stored {
    created: usize,
    updated: usize,
    unchanged: usize,
}

impl Stored {
    fn summary(&self) -> String {
        let mut parts = vec![
            format!("{} new", self.created),
            format!("{} updated", self.updated),
        ];
        if self.unchanged > 0 {
            parts.push(format!("{} already there", self.unchanged));
        }
        parts.join(", ")
    }
}

/// Stores variables as records of `entity`, one record per variable with a
/// field "value" (secret unless listed in `plain`). A variable whose current
/// value is already the same gets no new version.
fn store_vars(
    v: &mut crate::vault::Vault,
    entity: &str,
    env: Option<&str>,
    pairs: &[(String, Zeroizing<String>)],
    plain: &[String],
    source: &str,
) -> Result<Stored> {
    let mut n = Stored::default();
    for (key, value) in pairs {
        let (id, new) = match v.find_record_in(entity, key) {
            Some(r) => (r.id.clone(), false),
            None => (v.add_record(entity, key)?, true),
        };
        let rec = v.record_mut(&id);
        if rec.field("value").is_none() {
            let kind = if value.contains('\n') {
                FieldKind::Multiline
            } else {
                FieldKind::Text
            };
            rec.fields
                .push(Field::new("value", kind, !plain.contains(key)));
        }
        rec.memory
            .entry(mk::USED_IN.to_string())
            .or_insert_with(|| format!("imported from {source}"));
        let f = rec.field_mut("value").expect("ensured");
        let slot = f
            .values
            .entry(env.unwrap_or(SHARED).to_string())
            .or_default();
        let same = match slot.current() {
            Some(Value::Text { text }) => text.expose() == value.as_str(),
            _ => false,
        };
        if same {
            n.unchanged += 1;
            continue;
        }
        slot.push(
            Value::text(value.as_str()),
            "cli",
            Some(format!("import {source}")),
        );
        if new {
            n.created += 1;
        } else {
            n.updated += 1;
        }
    }
    Ok(n)
}

pub(super) struct Linked {
    pub added: Vec<String>,
    /// Variables the file already had; they are not changed.
    pub kept: Vec<String>,
}

/// Adds variables to the [env] table of a project file, creating the file if
/// needed. Each entry is (variable, reference relative to the entity `path`
/// of `scope`); in the file it is written relative when the file's base is
/// that entity, absolute otherwise. Variables already in the file are kept.
pub(super) fn link_vars(
    ctx: &Ctx,
    file: &Path,
    scope: Scope,
    path: &[String],
    entries: &[(String, String)],
) -> Result<Linked> {
    if !file.exists() {
        let entity = (!path.is_empty()).then(|| path.join("/"));
        crate::vault::atomic_write(
            file,
            project::template(Some(&scope.to_string()), entity.as_deref()).as_bytes(),
        )?;
    }
    let p = Project::load(file)?;
    let (base_sel, base) = p.base()?;
    let base_scope = match base_sel {
        // A file without `vault =` uses the project's local vault if there is
        // one: look from the project's own folder.
        VaultSel::Default => {
            if crate::workspace::find_local(p.dir(), &ctx.ws.global_dir).is_some() {
                Scope::Local
            } else {
                Scope::Global
            }
        }
        VaultSel::Global => Scope::Global,
        VaultSel::Local => Scope::Local,
    };
    let mut linked = Linked {
        added: Vec::new(),
        kept: Vec::new(),
    };
    Project::edit(file, |doc| {
        if doc.get("env").is_none() {
            doc["env"] = toml_edit::table();
        }
        for (key, target) in entries {
            let reference = if base_scope == scope && path.starts_with(&base) {
                let mut rel: Vec<String> = path[base.len()..].to_vec();
                rel.push(target.clone());
                rel.join("/")
            } else {
                let mut abs = path.to_vec();
                abs.push(target.clone());
                format!("{scope}:{}", abs.join("/"))
            };
            let existing = ["env", "files"].iter().find_map(|t| {
                let item = doc.get(t)?.as_table_like()?.get(key)?;
                // Short form ("db#url") or full form ({ ref = "db#url", … }).
                let text = item
                    .as_str()
                    .or_else(|| item.as_table_like()?.get("ref")?.as_str())
                    .unwrap_or_default();
                Some(text.to_string())
            });
            match existing {
                Some(text) if text == reference => continue,
                Some(_) => {
                    linked.kept.push(key.clone());
                    continue;
                }
                None => {}
            }
            doc["env"][key.as_str()] = toml_edit::value(reference);
            linked.added.push(key.clone());
        }
        Ok(())
    })?;
    Ok(linked)
}

pub struct DiscoverOptions<'a> {
    pub root: &'a Path,
    pub into: Option<&'a str>,
    pub env: Option<&'a str>,
    pub plain: &'a str,
    pub depth: usize,
    pub yes: bool,
    pub no_link: bool,
}

/// `cemi import --discover`: finds the .env files under a folder, shows what
/// it found and what looks wrong, and imports them after a yes.
pub fn discover(ctx: &mut Ctx, o: DiscoverOptions) -> Result<i32> {
    let root = std::fs::canonicalize(o.root)
        .with_context(|| format!("cannot open {}", o.root.display()))?;
    let root = without_verbatim_prefix(root);
    let projects = discover::find(&root, o.depth)?;
    if projects.is_empty() {
        println!(
            "No .env files under {} (looked {} folders deep; change it with --depth)",
            root.display(),
            o.depth
        );
        return Ok(0);
    }
    if let Some(e) = o.env {
        validate_name(e, "environment")?;
    }
    let (sel, base) = ctx.entity_path(o.into)?;
    // Projects live all over the disk: their keys go to the global vault
    // unless --into names the local one.
    let sel = match sel {
        VaultSel::Default => VaultSel::Global,
        s => s,
    };
    let scope = ctx.ws.scope_for(sel)?;
    let target = |p: &FoundProject| -> Vec<String> {
        let mut t = base.clone();
        t.push(p.name.clone());
        t
    };

    // What was found.
    let files: usize = projects.iter().map(|p| p.files.len()).sum();
    println!(
        "Found {files} .env file{} in {} folder{} under {}",
        plural(files),
        projects.len(),
        plural(projects.len()),
        root.display()
    );
    let shown_dir = |p: &FoundProject| relative(&root, &p.dir);
    for p in &projects {
        println!();
        println!("  {}  →  {scope}:{}", shown_dir(p), target(p).join("/"));
        for f in &p.files {
            let env = env_shown(o.env.unwrap_or(&f.env));
            match &f.error {
                Some(e) => println!("    {:<26} cannot be read: {e}", f.name()),
                None => println!(
                    "    {:<26} {:<10} {} variable{}",
                    f.name(),
                    env,
                    f.vars.len(),
                    plural(f.vars.len())
                ),
            }
        }
    }

    // What looks wrong.
    let now = jiff::Timestamp::now();
    let mut warnings: Vec<String> = Vec::new();
    for p in &projects {
        for f in &p.files {
            let shown = format!("{}/{}", p.name, f.name());
            match f.git {
                GitState::Tracked => warnings.push(format!(
                    "{shown} is committed to git: anyone with the repository has these keys. \
                     After importing, replace them (`cemi incident <ref> --rotate`) and remove the file from git"
                )),
                GitState::Unprotected => warnings.push(format!(
                    "{shown} is not in .gitignore: one `git add .` away from being committed"
                )),
                GitState::Ignored | GitState::NoRepo => {}
            }
            if f.is_old(now)
                && let Some(m) = f.modified
            {
                warnings.push(format!(
                    "{shown} has not changed since {}: its keys may be due for rotation",
                    ui::when(m, "%Y-%m-%d")
                ));
            }
        }
    }
    for r in discover::repeated(&projects) {
        let places: Vec<String> = r
            .places
            .iter()
            .map(|(p, f, k)| format!("{k} in {p}/{f}"))
            .collect();
        warnings.push(format!(
            "The same value is in {}: keep it once and point the projects at it, \
             so a rotation reaches all of them",
            places.join(", ")
        ));
    }
    if !warnings.is_empty() {
        println!();
        for w in &warnings {
            println!("! {w}");
        }
    }

    let readable: Vec<&FoundProject> = projects
        .iter()
        .filter(|p| {
            p.files
                .iter()
                .any(|f| f.error.is_none() && !f.vars.is_empty())
        })
        .collect();
    if readable.is_empty() {
        return Ok(0);
    }
    println!();
    let vault_exists = match scope {
        Scope::Global => ctx.ws.global_exists(),
        Scope::Local => ctx.ws.dir(scope).is_ok(),
    };
    if !vault_exists {
        println!(
            "To import them, create the {scope} vault first ({}), then run this again.",
            match scope {
                Scope::Global => "`cemi init --global`",
                Scope::Local => "`cemi init`",
            }
        );
        return Ok(0);
    }
    let question = format!(
        "Import them into the {scope} vault{}?",
        if o.no_link {
            ""
        } else {
            " and add the variables to each folder's cemi.toml"
        }
    );
    if !o.yes && !ui::confirm(&question) {
        println!("Nothing imported. Run it again with --yes to import.");
        return Ok(0);
    }

    // Import. Unlocking once up front stops here on a wrong password, instead
    // of failing once per project.
    ctx.ws.open(scope)?;
    let plain = plain_list(o.plain);
    let mut failed = 0;
    for p in readable {
        let path = target(p);
        let shown = shown_dir(p);
        if let Err(e) = import_project(ctx, scope, &path, p, &shown, o.env, &plain, o.no_link) {
            failed += 1;
            ui::warn(format!("{shown}: {e:#}"));
        }
    }
    if failed == 0 {
        println!();
        println!(
            "Next: in each folder, `cemi run -e dev -- <your command>`. Once it works, delete the .env files."
        );
    }
    Ok(if failed > 0 { 1 } else { 0 })
}

/// Windows' canonical paths start with \\?\, which people do not write.
fn without_verbatim_prefix(p: std::path::PathBuf) -> std::path::PathBuf {
    let text = p.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return std::path::PathBuf::from(format!(r"\\{rest}"));
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) => std::path::PathBuf::from(rest),
        None => p,
    }
}

#[allow(clippy::too_many_arguments)]
fn import_project(
    ctx: &mut Ctx,
    scope: Scope,
    path: &[String],
    p: &FoundProject,
    shown: &str,
    env_override: Option<&str>,
    plain: &[String],
    no_link: bool,
) -> Result<()> {
    // Variables per environment; with --env, every file goes to one.
    let mut merged: std::collections::BTreeMap<String, Vec<(String, Zeroizing<String>)>> =
        std::collections::BTreeMap::new();
    for (env, vars) in p.merged() {
        let env = env_override.map(str::to_string).unwrap_or(env);
        let list = merged.entry(env).or_default();
        for (k, v) in vars {
            match list.iter_mut().find(|(key, _)| *key == k) {
                Some(slot) => slot.1 = v,
                None => list.push((k, v)),
            }
        }
    }
    let source = p.dir.display().to_string();
    let v = ctx.ws.open(scope)?;
    let entity = v.ensure_entity(path)?;
    let mut added_envs = Vec::new();
    for env in merged.keys() {
        if env != SHARED && !v.effective_envs(&entity).contains(env) {
            v.entity_mut(&entity).envs.push(env.clone());
            added_envs.push(env.clone());
        }
    }
    let mut total = Stored::default();
    for (env, pairs) in &merged {
        let n = store_vars(v, &entity, Some(env), pairs, plain, &source)?;
        total.created += n.created;
        total.updated += n.updated;
        total.unchanged += n.unchanged;
    }
    v.save()?;
    for (env, pairs) in &merged {
        ctx.audit_detail(
            scope,
            "import",
            Some(display_path(path)),
            (env != SHARED).then_some(env.as_str()),
            Some(format!("{} variables from {source}", pairs.len())),
        );
    }
    let envs: Vec<&str> = merged.keys().map(|e| env_shown(e)).collect();
    ui::ok(format!(
        "{shown} → {scope}:{} ({}; {})",
        path.join("/"),
        envs.join(", "),
        total.summary()
    ));
    if !added_envs.is_empty() {
        ui::ok(format!(
            "  Added environment{} {} to {}",
            plural(added_envs.len()),
            added_envs.join(", "),
            display_path(path)
        ));
    }
    if !no_link {
        let mut keys: Vec<String> = merged
            .values()
            .flat_map(|pairs| pairs.iter().map(|(k, _)| k.clone()))
            .collect();
        keys.sort();
        keys.dedup();
        let file = p.dir.join(project::FILE);
        let entries: Vec<(String, String)> = keys
            .iter()
            .map(|k| (k.clone(), format!("{k}#value")))
            .collect();
        let linked = link_vars(ctx, &file, scope, path, &entries)?;
        let file_shown = Path::new(shown).join(project::FILE);
        if !linked.added.is_empty() {
            ui::ok(format!(
                "  Added {} variable{} to {}",
                linked.added.len(),
                plural(linked.added.len()),
                file_shown.display()
            ));
        }
        if !linked.kept.is_empty() {
            ui::warn(format!(
                "  {} already had {}; left as it was",
                file_shown.display(),
                linked.kept.join(", ")
            ));
        }
    }
    Ok(())
}

fn env_shown(env: &str) -> &str {
    if env == SHARED { "all" } else { env }
}

/// `dir` as people read it under the folder they searched.
fn relative(root: &Path, dir: &Path) -> String {
    match dir.strip_prefix(root) {
        Ok(rel) if rel.as_os_str().is_empty() => ".".to_string(),
        Ok(rel) => rel.display().to_string(),
        Err(_) => dir.display().to_string(),
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Applies presets to the entity `path` of `scope`, and adds their variables
/// to this project's cemi.toml when there is one.
pub fn apply_presets(ctx: &mut Ctx, scope: Scope, path: &[String], names: &[String]) -> Result<()> {
    let presets = names
        .iter()
        .map(|n| crate::presets::get(n))
        .collect::<Result<Vec<_>>>()?;
    let project = ctx.project()?;
    let v = ctx.ws.open(scope)?;
    let entity = v.ensure_entity(path)?;
    let mut total = crate::presets::Applied::default();
    for p in &presets {
        let n = crate::presets::apply(v, &entity, p)?;
        total.records += n.records;
        total.fields += n.fields;
        total.notes += n.notes;
    }
    v.save()?;
    ctx.audit_detail(
        scope,
        "preset",
        Some(display_path(path)),
        None,
        Some(names.join(", ")),
    );
    let place = if path.is_empty() {
        format!("the {scope} vault")
    } else {
        format!("{scope}:{}", path.join("/"))
    };
    ui::ok(format!(
        "Preset {} in {place}: {} record{}, {} field{}, {} note{} added",
        names.join(" + "),
        total.records,
        plural(total.records),
        total.fields,
        plural(total.fields),
        total.notes,
        plural(total.notes)
    ));
    if let Some(proj) = project {
        let shown = proj
            .path
            .strip_prefix(&ctx.ws.cwd)
            .unwrap_or(&proj.path)
            .display()
            .to_string();
        let entries: Vec<(String, String)> = presets
            .iter()
            .flat_map(|p| p.env.iter().map(|(k, r)| (k.clone(), r.clone())))
            .collect();
        let linked = link_vars(ctx, &proj.path, scope, path, &entries)?;
        if !linked.added.is_empty() {
            ui::ok(format!("Added {} to {shown}", linked.added.join(", ")));
        }
        if !linked.kept.is_empty() {
            ui::warn(format!(
                "{shown} already had {} pointing elsewhere; left as it was",
                linked.kept.join(", ")
            ));
        }
    }
    let prefix = if path.is_empty() {
        String::new()
    } else {
        format!("{}/", path.join("/"))
    };
    // Fields that still have no value at all.
    let v = ctx.ws.open(scope)?;
    let mut fill: Vec<String> = presets
        .iter()
        .flat_map(|p| p.to_fill())
        .filter(|reference| {
            let (rec, field) = reference.split_once('#').expect("record#field");
            v.find_record_in(&entity, rec)
                .and_then(|r| r.field(field))
                .is_none_or(|f| f.values.values().all(|s| s.current().is_none()))
        })
        .collect();
    fill.sort();
    fill.dedup();
    if !fill.is_empty() {
        eprintln!("Next, store the values (each command asks for it, hidden):");
        for f in fill {
            eprintln!("  cemi set {prefix}{f} -e dev");
        }
    }
    Ok(())
}

pub fn preset(ctx: &mut Ctx, cmd: crate::cli::PresetCmd) -> Result<i32> {
    use crate::cli::PresetCmd;
    match cmd {
        PresetCmd::Ls => {
            for name in crate::presets::names() {
                let p = crate::presets::get(name)?;
                println!("{name:<16} {}", p.description);
            }
            Ok(0)
        }
        PresetCmd::Add { names, into } => {
            let (sel, path) = ctx.entity_path(into.as_deref())?;
            let scope = ctx.ws.scope_for(sel)?;
            apply_presets(ctx, scope, &path, &names)?;
            Ok(0)
        }
    }
}

pub fn types(
    ctx: &mut Ctx,
    format: crate::types_gen::Format,
    output: Option<std::path::PathBuf>,
    check: bool,
) -> Result<i32> {
    let project = ctx.require_project()?;
    let text = crate::types_gen::generate(&project.file, format);
    let Some(path) = output else {
        print!("{text}");
        return Ok(0);
    };
    // Line endings may differ after a checkout on Windows.
    let current = std::fs::read_to_string(&path)
        .ok()
        .map(|t| t.replace("\r\n", "\n"));
    if check {
        if current.as_deref() == Some(text.as_str()) {
            ui::ok(format!("{} is up to date", path.display()));
            return Ok(0);
        }
        ui::warn(format!(
            "{} is not up to date with cemi.toml. Run: cemi types{} -o {}",
            path.display(),
            match format {
                crate::types_gen::Format::Ts => "",
                crate::types_gen::Format::Zod => " --format zod",
            },
            path.display()
        ));
        return Ok(1);
    }
    if current.as_deref() == Some(text.as_str()) {
        ui::ok(format!("{} was already up to date", path.display()));
        return Ok(0);
    }
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    crate::vault::atomic_write(&path, text.as_bytes())?;
    let n = project.file.env.len() + project.file.files.len();
    ui::ok(format!(
        "Wrote {} ({n} variable{})",
        path.display(),
        plural(n)
    ));
    Ok(0)
}
