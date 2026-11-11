//! `cemi ci`: secrets for CI. See `crate::ci` for the file format.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use data_encoding::BASE64;

use super::Ctx;
use crate::ci::{self, CiFile, KEY_FIELD, KEY_RECORD, KEY_VAR, Payload};
use crate::connectors::DestSpec;
use crate::crypto::AgeKey;
use crate::model::{Field, FieldKind, SHARED, Value, memory_keys as mk};
use crate::project::Project;
use crate::refs::{Ref, VaultSel};
use crate::rotation::{self, DestRef, FieldRef};
use crate::runner;
use crate::ui;
use crate::vault::Scope;

const ACTOR: &str = "cli";

/// The scope and entity a project's references start from.
fn project_base(ctx: &Ctx, project: &Project) -> Result<(Scope, Vec<String>)> {
    let (sel, base) = project.base()?;
    let sel = if ctx.global { VaultSel::Global } else { sel };
    Ok((ctx.ws.scope_for(sel)?, base))
}

fn key_ref(scope: Scope, base: &[String]) -> Result<Ref> {
    let mut path = base.to_vec();
    path.push(KEY_RECORD.to_string());
    Ref::parse(&format!("{scope}:{}#{KEY_FIELD}", path.join("/")))
}

pub fn setup(
    ctx: &mut Ctx,
    repo: Option<String>,
    environment: Option<String>,
    new_key: bool,
) -> Result<i32> {
    let project = ctx.require_project()?;
    if project.file.ci.is_some() && !new_key {
        bail!(
            "this project already has a CI key ({} [ci]). `cemi ci setup --new-key` replaces it",
            project.path.display()
        );
    }
    let (scope, base) = project_base(ctx, &project)?;
    let key = AgeKey::generate();
    let recipient = key.recipient().to_string();

    // The key lives in the vault, as a secret, next to the project's records.
    {
        let v = ctx.ws.open(scope)?;
        let entity = v.ensure_entity(&base)?;
        let id = match v.find_record_in(&entity, KEY_RECORD) {
            Some(r) => r.id.clone(),
            None => v.add_record(&entity, KEY_RECORD)?,
        };
        let rec = v.record_mut(&id);
        for (k, text) in [
            (mk::PURPOSE, format!("Opens {} in CI (the secret {KEY_VAR})", ci::DEFAULT_FILE)),
            (mk::ROTATE, "`cemi ci setup --new-key`, then `cemi ci export` again".to_string()),
            (
                mk::IF_LEAKED,
                "Replace it (`cemi ci setup --new-key`) and every value in the CI file: old copies of the file stay in git history".to_string(),
            ),
        ] {
            rec.memory.entry(k.to_string()).or_insert(text);
        }
        if rec.field(KEY_FIELD).is_none() {
            rec.fields
                .push(Field::new(KEY_FIELD, FieldKind::Text, true));
        }
        let f = rec.field_mut(KEY_FIELD).expect("just ensured");
        f.values.entry(SHARED.to_string()).or_default().push(
            Value::text(key.secret_text().as_str()),
            ACTOR,
            Some(if new_key { "new CI key" } else { "CI key" }.to_string()),
        );
        v.save()?;
    }
    let reference = key_ref(scope, &base)?;
    ctx.audit(scope, "ci.setup", Some(reference.to_string()), None);

    Project::edit(&project.path, |doc| {
        if doc.get("ci").is_none() {
            doc["ci"] = toml_edit::table();
        }
        doc["ci"]["recipient"] = toml_edit::value(recipient.as_str());
        if doc["ci"].get("file").is_none() {
            doc["ci"]["file"] = toml_edit::value(ci::DEFAULT_FILE);
        }
        Ok(())
    })?;
    ui::ok(format!(
        "{} CI key: the private half is {reference} in the vault, the public half is in {} [ci]",
        if new_key { "New" } else { "Created the" },
        project.path.display()
    ));

    // The CI needs the private half: Cemí can put it in GitHub itself.
    let fr = FieldRef::find(&mut ctx.ws, &reference)?;
    if let Some(repo) = repo {
        let spec = DestSpec::Github {
            repo,
            name: KEY_VAR.to_string(),
            environment,
            token: None,
            api_url: None,
        };
        spec.validate()?;
        let exists = fr
            .field(&mut ctx.ws)?
            .destinations
            .iter()
            .find(|d| d.spec == spec)
            .map(|d| d.id.clone());
        let id = match exists {
            Some(id) => id,
            None => super::rotation_cmds::add_destination(
                ctx,
                &fr,
                &reference.to_string(),
                SHARED,
                spec,
            )?,
        };
        let d = DestRef {
            field: fr.clone(),
            id,
        };
        let shown = rotation::check_one(&mut ctx.ws, &d, false).describe;
        rotation::push_one(&mut ctx.ws, &d, ACTOR)?;
        ui::ok(format!("Sent the CI key to {shown}"));
    } else {
        let has_dest = !fr.field(&mut ctx.ws)?.destinations.is_empty();
        if has_dest {
            super::rotation_cmds::push(ctx, Some(&reference.to_string()), None, true)?;
        } else {
            eprintln!(
                "Put the private half in your CI as the secret {KEY_VAR}: `cemi copy {reference}`, or let Cemí do it for GitHub: `cemi ci setup --new-key --repo owner/name`"
            );
        }
    }
    if new_key {
        ui::warn(
            "Files exported with the old key cannot be opened anymore: run `cemi ci export` again",
        );
    }
    eprintln!(
        "Next: `cemi ci export -e prod`, then commit {}.",
        ci::DEFAULT_FILE
    );
    Ok(0)
}

pub fn export(ctx: &mut Ctx, env: &str, only: &[String], output: Option<PathBuf>) -> Result<i32> {
    let mut project = ctx.require_project()?;
    let Some(conf) = project.file.ci.clone() else {
        return Err(crate::errors::not_found(
            "this project has no CI key yet: run `cemi ci setup`",
        ));
    };
    let recipient = crate::crypto::parse_recipient(&conf.recipient)?;
    // Only what CI needs: --only, else [ci] vars, else every variable.
    let wanted: Vec<String> = if !only.is_empty() {
        only.to_vec()
    } else {
        conf.vars.clone().unwrap_or_default()
    };
    if !wanted.is_empty() {
        for w in &wanted {
            if !project.file.env.contains_key(w) && !project.file.files.contains_key(w) {
                return Err(crate::errors::not_found(format!(
                    "{w} is not a variable of {}",
                    project.path.display()
                )));
            }
        }
        project.file.env.retain(|k, _| wanted.contains(k));
        project.file.files.retain(|k, _| wanted.contains(k));
    }
    if project.file.env.is_empty() && project.file.files.is_empty() {
        bail!("there are no variables to export");
    }
    let (scope, _) = project_base(ctx, &project)?;
    // Writing production values to a file asks for the password, like any
    // change in a protected environment.
    if ctx.ws.open(scope)?.is_protected(env) {
        super::reauthenticate(ctx, scope, &format!("Exporting {env} (protected) for CI"))?;
    }
    let plan = runner::plan(&mut ctx.ws, &project, Some(env))?;
    let mut payload = Payload::new(env);
    for (k, v) in &plan.env {
        payload.vars.insert(k.clone(), v.to_string());
    }
    for (k, name, bytes) in &plan.files {
        payload.files.insert(
            k.clone(),
            CiFile {
                name: name.clone(),
                data: BASE64.encode(bytes),
            },
        );
    }
    let text = ci::seal(&payload, &recipient)?;
    let path = output.unwrap_or_else(|| {
        project
            .dir()
            .join(conf.file.as_deref().unwrap_or(ci::DEFAULT_FILE))
    });
    crate::vault::atomic_write(&path, text.as_bytes())?;
    let names: Vec<String> = payload
        .vars
        .keys()
        .chain(payload.files.keys())
        .cloned()
        .collect();
    ctx.audit_detail(
        scope,
        "ci.export",
        Some(path.display().to_string()),
        Some(env),
        Some(names.join(", ")),
    );
    ui::ok(format!(
        "Wrote {} with {} variable{} for {env}: {}",
        path.display(),
        names.len(),
        if names.len() == 1 { "" } else { "s" },
        names.join(", ")
    ));
    eprintln!(
        "Commit it. In GitHub Actions, the cemi action loads it; in other CIs, `cemi ci load -- <command>` with {KEY_VAR} set."
    );
    Ok(0)
}

/// In CI: opens the file with `CEMI_CI_KEY` and gives the values to the next
/// steps (`--github-env`) or to one command. Needs no vault and no password.
pub fn load(file: Option<PathBuf>, github_env: bool, command: &[String]) -> Result<i32> {
    let path = match file {
        Some(f) => f,
        None => default_file()?,
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| crate::errors::not_found(format!("cannot read {}: {e}", path.display())))?;
    let key = ci::key_from_env()?;
    let payload = ci::open(&text, &key)?;
    let files_dir = std::env::var_os("RUNNER_TEMP")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("cemi-{}", std::process::id()));
    if github_env {
        let env_file = std::env::var_os("GITHUB_ENV")
            .map(PathBuf::from)
            .ok_or_else(|| {
                crate::errors::not_found(
                    "GITHUB_ENV is not set: --github-env works inside GitHub Actions",
                )
            })?;
        let files = ci::write_files(&payload, &files_dir)?;
        ci::to_github_env(&payload, &files, &env_file)?;
        ui::ok(format!(
            "Loaded {} variable{} for {} (values hidden in the log)",
            payload.vars.len() + files.len(),
            if payload.vars.len() + files.len() == 1 {
                ""
            } else {
                "s"
            },
            payload.env
        ));
        return Ok(0);
    }
    if command.is_empty() {
        bail!(
            "say where the values go: `cemi ci load --github-env`, or `cemi ci load -- <command>`"
        );
    }
    // Run one command with the values, hiding them in its output.
    let mut plan = runner::Plan {
        env: Vec::new(),
        files: Vec::new(),
        secrets: Vec::new(),
    };
    for (k, v) in &payload.vars {
        plan.env
            .push((k.clone(), zeroize::Zeroizing::new(v.clone())));
        plan.secrets
            .push((k.clone(), zeroize::Zeroizing::new(v.as_bytes().to_vec())));
    }
    for (k, f) in &payload.files {
        let data = zeroize::Zeroizing::new(
            BASE64
                .decode(f.data.as_bytes())
                .context("damaged file data")?,
        );
        plan.files.push((k.clone(), f.name.clone(), data));
    }
    let redactor = runner::Redactor::new(&plan.secrets);
    let prepared = runner::prepare(&plan)?;
    drop(plan);
    runner::run_interactive(command, &prepared, Some(&redactor))
}

/// [ci] file of the cemi.toml here, or the default name.
fn default_file() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    if let Some(p) = crate::workspace::find_project_file(&cwd) {
        let project = Project::load(&p)?;
        let name = project
            .file
            .ci
            .as_ref()
            .and_then(|c| c.file.clone())
            .unwrap_or_else(|| ci::DEFAULT_FILE.to_string());
        return Ok(project.dir().join(name));
    }
    Ok(Path::new(ci::DEFAULT_FILE).to_path_buf())
}
