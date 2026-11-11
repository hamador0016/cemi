//! Where a value is used: the projects Cemí knows, templates, connectors that
//! sign in with it, MCP servers started by `cemi mcp launch`, the places it is
//! copied to, and the copies in `cemi.ci.age` files.
//!
//! Projects are found through the list each vault keeps (see
//! [`crate::model::KnownProject`]). Each project's `cemi.toml` is read again
//! every time, so the answer follows the files as they are now.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use jiff::Timestamp;

use crate::ci;
use crate::cmd_shared::Attention;
use crate::model::{FieldKind, Record, VersionState};
use crate::project::{self, Project};
use crate::refs::{Ref, VaultSel};
use crate::vault::{Header, Scope, Vault};
use crate::workspace::{self, Workspace};

/// A record, or one of its fields, inside one vault.
pub struct Target {
    pub entities: Vec<String>,
    pub record: String,
    /// `None`: any field of the record.
    pub field: Option<String>,
}

impl Target {
    pub fn of(v: &Vault, rec: &Record, field: Option<&str>) -> Target {
        Target {
            entities: v.entity_path(&rec.entity),
            record: rec.name.clone(),
            field: field.map(str::to_string),
        }
    }

    /// The field of `r` this target covers, if any.
    fn matches(&self, r: &Ref) -> Option<String> {
        if r.entities != self.entities || r.record != self.record {
            return None;
        }
        let f = r.field.as_ref()?;
        match &self.field {
            Some(want) if want != f => None,
            _ => Some(f.clone()),
        }
    }
}

pub enum Place {
    /// A variable in a project's `cemi.toml`.
    Project {
        name: String,
        dir: String,
        var: String,
        /// Under `[files]`: the program gets a file path.
        as_file: bool,
        ci: Option<CiCopy>,
    },
    /// A template field built from this value.
    Template { reference: String },
    /// An origin or destination that signs in with this value.
    Connector {
        reference: String,
        role: &'static str,
        describe: String,
    },
    /// An MCP server started by `cemi mcp launch`.
    Launcher { name: String, var: String },
    /// A place this value is copied to (`cemi dest`).
    Destination { env: String, describe: String },
}

/// A copy of the value in a project's `cemi.ci.age`.
pub struct CiCopy {
    pub file: PathBuf,
    pub exists: bool,
    pub env: Option<String>,
    pub exported: Option<Timestamp>,
    /// The value changed after the file was written.
    pub outdated: bool,
    /// The value in the file was revoked since.
    pub revoked: bool,
}

pub struct Use {
    pub field: String,
    /// The entity of the record that holds a template or connector, so
    /// limited MCP tokens only see what they may.
    pub owner: Option<String>,
    pub place: Place,
}

#[derive(Default)]
pub struct Report {
    pub uses: Vec<Use>,
    /// Projects searched.
    pub projects: usize,
    /// Known project folders without a `cemi.toml` now.
    pub missing: Vec<String>,
    /// Known projects whose `cemi.toml` could not be read.
    pub unreadable: Vec<(String, String)>,
}

impl Report {
    pub fn project_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .uses
            .iter()
            .filter_map(|u| match &u.place {
                Place::Project { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        names.dedup();
        names
    }
}

/// Whether an explicit vault prefix inside vault `v` means `v` itself. Plain
/// references inside a vault (templates, connectors, launchers) mean the
/// vault they are stored in.
fn same_vault(sel: VaultSel, v: &Vault) -> bool {
    match sel {
        VaultSel::Default => true,
        VaultSel::Global => v.scope() == Scope::Global,
        VaultSel::Local => v.scope() == Scope::Local,
    }
}

/// Vault ids by folder, so each header is read once.
#[derive(Default)]
struct Ids(BTreeMap<PathBuf, Option<String>>);

impl Ids {
    fn of(&mut self, dir: &Path) -> Option<String> {
        self.0
            .entry(dir.to_path_buf())
            .or_insert_with(|| Header::read(dir).ok().map(|h| h.id))
            .clone()
    }
}

/// The vault a project reference points to, seen from the project's folder.
fn vault_id_of(ws: &Workspace, r: &Ref, ids: &mut Ids) -> Option<String> {
    let scope = ws.scope_for(r.vault).ok()?;
    ids.of(&ws.dir(scope).ok()?)
}

pub fn project_name(dir: &str) -> String {
    Path::new(dir)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| dir.to_string())
}

/// Whether some reference of `project` points to the vault with `vault_id`.
pub fn project_uses_vault(project: &Project, vault_id: &str) -> bool {
    let Ok(ws) = Workspace::at(project.dir(), false) else {
        return false;
    };
    let mut ids = Ids::default();
    project
        .file
        .env
        .values()
        .chain(project.file.files.values())
        .any(|spec| {
            project
                .resolve_ref(spec.text())
                .ok()
                .and_then(|r| vault_id_of(&ws, &r, &mut ids))
                .as_deref()
                == Some(vault_id)
        })
}

/// The folders to search: the vault's known projects, plus `extra`.
fn project_dirs(v: &Vault, extra: Option<&Path>) -> Vec<String> {
    let mut dirs: Vec<String> = v.projects.values().map(|p| p.path.clone()).collect();
    if let Some(dir) = extra
        && let Ok(key) = workspace::project_key(dir)
        && !dirs.contains(&key)
        && Project::load(&dir.join(project::FILE))
            .is_ok_and(|p| project_uses_vault(&p, &v.header.id))
    {
        dirs.push(key);
    }
    dirs.sort_by_key(|d| project_name(d).to_lowercase());
    dirs
}

/// Everything that uses `target` in vault `v`. `current` is the folder of
/// the current project, searched even if the vault does not know it yet.
pub fn find(v: &Vault, target: &Target, current: Option<&Path>) -> Report {
    let mut report = Report::default();
    let mut ids = Ids::default();
    for dir in project_dirs(v, current) {
        let file = Path::new(&dir).join(project::FILE);
        if !file.is_file() {
            report.missing.push(dir);
            continue;
        }
        let p = match Project::load(&file) {
            Ok(p) => p,
            Err(e) => {
                report.unreadable.push((dir, format!("{e:#}")));
                continue;
            }
        };
        report.projects += 1;
        let Ok(ws) = Workspace::at(p.dir(), false) else {
            continue;
        };
        let ci = p.file.ci.as_ref();
        let entries = p
            .file
            .env
            .iter()
            .map(|(k, s)| (k, s, false))
            .chain(p.file.files.iter().map(|(k, s)| (k, s, true)));
        for (var, spec, as_file) in entries {
            let Ok(r) = p.resolve_ref(spec.text()) else {
                continue;
            };
            let Some(field) = target.matches(&r) else {
                continue;
            };
            if vault_id_of(&ws, &r, &mut ids).as_deref() != Some(v.header.id.as_str()) {
                continue;
            }
            let ci = ci
                .filter(|c| c.vars.as_ref().is_none_or(|vars| vars.contains(var)))
                .map(|c| ci_copy(v, target, &field, &p, c.file.as_deref()));
            report.uses.push(Use {
                field,
                owner: None,
                place: Place::Project {
                    name: project_name(&dir),
                    dir: dir.clone(),
                    var: var.clone(),
                    as_file,
                    ci,
                },
            });
        }
    }
    inside_vault(v, target, &mut report);
    report
}

fn ci_copy(v: &Vault, target: &Target, field: &str, p: &Project, file: Option<&str>) -> CiCopy {
    let path = p.dir().join(file.unwrap_or(ci::DEFAULT_FILE));
    let header = std::fs::read_to_string(&path)
        .ok()
        .map(|t| ci::read_header(&t));
    let exists = header.is_some();
    let env = header.as_ref().and_then(|h| h.env.clone());
    let exported = header.as_ref().and_then(|h| h.exported);
    let (outdated, revoked) = match (&env, exported) {
        (Some(env), Some(at)) => staleness(v, target, field, env, at),
        _ => (false, false),
    };
    CiCopy {
        file: path,
        exists,
        env,
        exported,
        outdated,
        revoked,
    }
}

/// (changed since `at`, the value of `at` was revoked) for one environment.
fn staleness(v: &Vault, target: &Target, field: &str, env: &str, at: Timestamp) -> (bool, bool) {
    let Ok(rec) = v.find_record(&target.entities, &target.record) else {
        return (false, false);
    };
    let Some((_, slot)) = rec.field(field).and_then(|f| f.slot_for(Some(env))) else {
        return (false, false);
    };
    let Some(current) = slot.current_version() else {
        return (false, false);
    };
    if current.at <= at {
        return (false, false);
    }
    let then = slot
        .versions
        .iter()
        .rev()
        .find(|ver| ver.at <= at && ver.state != VersionState::Pending);
    (
        true,
        then.is_some_and(|ver| ver.state == VersionState::Retired),
    )
}

/// Templates, connectors, launchers and destinations, all inside `v`.
fn inside_vault(v: &Vault, target: &Target, report: &mut Report) {
    let mut records: Vec<&Record> = v.records.values().filter(|r| !r.archived).collect();
    records.sort_by_key(|r| v.record_path(r));
    for other in &records {
        let other_entity = v.entity_path(&other.entity);
        for f in &other.fields {
            if f.kind == FieldKind::Template {
                let mut found: Vec<String> = Vec::new();
                for slot in f.values.values() {
                    let Some(val) = slot.current() else { continue };
                    let text = String::from_utf8_lossy(&val.bytes()).into_owned();
                    for part in crate::resolve::template_refs(&text) {
                        let parsed = match part.strip_prefix('/') {
                            Some(abs) => Ref::parse(abs).ok(),
                            None => Ref::parse(&part).ok().map(|p| {
                                let mut ents = other_entity.clone();
                                ents.extend(p.entities.clone());
                                Ref {
                                    entities: ents,
                                    ..p
                                }
                            }),
                        };
                        if let Some(p) = parsed
                            && same_vault(p.vault, v)
                            && let Some(field) = target.matches(&p)
                            && !found.contains(&field)
                        {
                            found.push(field);
                        }
                    }
                }
                for field in found {
                    report.uses.push(Use {
                        field,
                        owner: Some(other.entity.clone()),
                        place: Place::Template {
                            reference: format!("{}#{}", v.record_path(other), f.name),
                        },
                    });
                }
            }
            let connectors = f
                .origins
                .values()
                .map(|o| ("origin", o.spec.describe(), o.spec.references()))
                .chain(
                    f.destinations
                        .iter()
                        .map(|d| ("destination", d.spec.describe(), d.spec.references())),
                );
            for (role, describe, refs) in connectors {
                for text in refs {
                    if let Ok(p) = Ref::parse(text)
                        && same_vault(p.vault, v)
                        && let Some(field) = target.matches(&p)
                    {
                        report.uses.push(Use {
                            field,
                            owner: Some(other.entity.clone()),
                            place: Place::Connector {
                                reference: format!("{}#{}", v.record_path(other), f.name),
                                role,
                                describe: describe.clone(),
                            },
                        });
                    }
                }
            }
        }
    }
    let mut launchers: Vec<_> = v.launchers.values().collect();
    launchers.sort_by(|a, b| a.name.cmp(&b.name));
    for l in launchers {
        for (var, text) in &l.env {
            if let Ok(p) = Ref::parse(text)
                && same_vault(p.vault, v)
                && let Some(field) = target.matches(&p)
            {
                report.uses.push(Use {
                    field,
                    owner: None,
                    place: Place::Launcher {
                        name: l.name.clone(),
                        var: var.clone(),
                    },
                });
            }
        }
    }
    if let Ok(rec) = v.find_record(&target.entities, &target.record) {
        for f in &rec.fields {
            if target.field.as_ref().is_some_and(|want| *want != f.name) {
                continue;
            }
            for d in &f.destinations {
                report.uses.push(Use {
                    field: f.name.clone(),
                    owner: None,
                    place: Place::Destination {
                        env: d.env.clone(),
                        describe: d.spec.describe(),
                    },
                });
            }
        }
    }
}

/// `cemi.ci.age` files in known projects that hold old values of this
/// vault: CI keeps using them until someone exports again.
/// With `only`, just the values of records in those entities.
pub fn ci_attention(v: &Vault, only: Option<&[String]>) -> Vec<Attention> {
    let mut out = Vec::new();
    let mut ids = Ids::default();
    for dir in project_dirs(v, None) {
        let file = Path::new(&dir).join(project::FILE);
        let Ok(p) = Project::load(&file) else {
            continue;
        };
        let Some(ci) = p.file.ci.as_ref() else {
            continue;
        };
        let path = p.dir().join(ci.file.as_deref().unwrap_or(ci::DEFAULT_FILE));
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let header = ci::read_header(&text);
        let (Some(env), Some(at)) = (header.env.as_deref(), header.exported) else {
            continue;
        };
        let Ok(ws) = Workspace::at(p.dir(), false) else {
            continue;
        };
        let mut outdated = Vec::new();
        let mut revoked = false;
        for (var, spec) in p.file.env.iter().chain(p.file.files.iter()) {
            if !header.vars.contains(var) {
                continue;
            }
            let Ok(r) = p.resolve_ref(spec.text()) else {
                continue;
            };
            if vault_id_of(&ws, &r, &mut ids).as_deref() != Some(v.header.id.as_str()) {
                continue;
            }
            let target = Target {
                entities: r.entities.clone(),
                record: r.record.clone(),
                field: r.field.clone(),
            };
            if let Some(only) = only
                && !v
                    .find_record(&target.entities, &target.record)
                    .is_ok_and(|rec| only.contains(&rec.entity))
            {
                continue;
            }
            let field = r.field.clone().unwrap_or_default();
            let (old, gone) = staleness(v, &target, &field, env, at);
            if old {
                outdated.push(var.clone());
                revoked |= gone;
            }
        }
        if outdated.is_empty() {
            continue;
        }
        let shown = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        out.push(Attention {
            what: format!("{shown} in {} ({env})", project_name(&dir)),
            detail: format!(
                "{} changed after it was exported{}. Run `cemi ci export -e {env}` in {dir} and commit it",
                outdated.join(", "),
                if revoked {
                    "; CI still has a revoked value"
                } else {
                    ""
                }
            ),
            urgent: revoked,
        });
    }
    out
}

fn env_shown(env: &str) -> String {
    if env == crate::model::SHARED {
        "all environments".into()
    } else {
        env.to_string()
    }
}

/// The report as text, in sections. `show_field` adds the field name to each
/// line, for a whole record.
pub fn lines(report: &Report, show_field: bool) -> Vec<String> {
    let label = |u: &Use| {
        if show_field {
            format!("#{} ", u.field)
        } else {
            String::new()
        }
    };
    let mut sections: Vec<(&str, Vec<String>)> = vec![
        ("Projects:", Vec::new()),
        ("Templates:", Vec::new()),
        ("Connectors that sign in with it:", Vec::new()),
        ("MCP servers (cemi mcp launch):", Vec::new()),
        ("Copied to:", Vec::new()),
    ];
    for u in &report.uses {
        let l = label(u);
        let (i, mut text) = match &u.place {
            Place::Project {
                name,
                dir,
                var,
                as_file,
                ci,
            } => {
                let mut t = format!(
                    "{l}{name}: {var}{} ({dir})",
                    if *as_file { " (as a file)" } else { "" }
                );
                if let Some(c) = ci {
                    t.push_str(&format!("\n    {}", ci_text(c)));
                }
                (0, t)
            }
            Place::Template { reference } => (1, format!("{l}{reference}")),
            Place::Connector {
                reference,
                role,
                describe,
            } => (2, format!("{l}{describe} ({role} of {reference})")),
            Place::Launcher { name, var } => (3, format!("{l}{name} ({var})")),
            Place::Destination { env, describe } => {
                (4, format!("{l}{describe} ({})", env_shown(env)))
            }
        };
        text.insert_str(0, "  ");
        sections[i].1.push(text);
    }
    let mut out = Vec::new();
    for (title, items) in sections {
        if items.is_empty() {
            continue;
        }
        out.push(title.to_string());
        out.extend(items);
    }
    out
}

fn ci_text(c: &CiCopy) -> String {
    let name = c
        .file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !c.exists {
        return format!("listed for CI, but {name} has not been exported yet");
    }
    let env = c.env.as_deref().unwrap_or("?");
    if c.outdated {
        format!(
            "copied to {name} ({env}): out of date{}; run `cemi ci export -e {env}` in that folder and commit it",
            if c.revoked {
                ", and the value in it was revoked"
            } else {
                ""
            }
        )
    } else if c.exported.is_some() {
        format!("copied to {name} ({env}): up to date")
    } else {
        format!("copied to {name} ({env})")
    }
}

/// What was searched, and known folders that are gone.
pub fn footer(report: &Report) -> Vec<String> {
    let mut out = vec![format!(
        "Searched {} project{} that use{} this vault (`cemi project ls`).",
        report.projects,
        if report.projects == 1 { "" } else { "s" },
        if report.projects == 1 { "s" } else { "" }
    )];
    for dir in &report.missing {
        out.push(format!(
            "Not found: {dir} has no cemi.toml now. If it moved, run any cemi command there; `cemi project rm {dir}` forgets it."
        ));
    }
    for (dir, err) in &report.unreadable {
        out.push(format!("Could not read {dir}: {err}"));
    }
    out
}

pub fn json(report: &Report) -> serde_json::Value {
    use serde_json::json;
    let uses: Vec<serde_json::Value> = report
        .uses
        .iter()
        .map(|u| match &u.place {
            Place::Project {
                name,
                dir,
                var,
                as_file,
                ci,
            } => json!({
                "kind": "project",
                "field": u.field,
                "project": name,
                "dir": dir,
                "file": Path::new(dir).join(project::FILE).display().to_string(),
                "variable": var,
                "as_file": as_file,
                "ci": ci.as_ref().map(|c| json!({
                    "file": c.file.display().to_string(),
                    "exported": c.exists,
                    "env": c.env,
                    "exported_at": c.exported.map(|t| t.to_string()),
                    "outdated": c.outdated,
                    "revoked": c.revoked,
                })),
            }),
            Place::Template { reference } => json!({
                "kind": "template",
                "field": u.field,
                "reference": reference,
            }),
            Place::Connector {
                reference,
                role,
                describe,
            } => json!({
                "kind": "connector",
                "field": u.field,
                "role": role,
                "reference": reference,
                "describe": describe,
            }),
            Place::Launcher { name, var } => json!({
                "kind": "mcp_server",
                "field": u.field,
                "name": name,
                "variable": var,
            }),
            Place::Destination { env, describe } => json!({
                "kind": "destination",
                "field": u.field,
                "env": env,
                "describe": describe,
            }),
        })
        .collect();
    json!({
        "used_by": uses,
        "projects_searched": report.projects,
        "projects_missing": report.missing,
        "projects_unreadable": report.unreadable.iter().map(|(d, e)| json!({"dir": d, "error": e})).collect::<Vec<_>>(),
    })
}
