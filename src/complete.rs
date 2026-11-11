//! Shell completion. Commands and options come from the command definitions;
//! entity, record and environment names come from the vaults, but only from
//! vaults that are already unlocked: completing never asks for a password,
//! and never shows a value.
//!
//! Set up with `COMPLETE=<shell> cemi` (see `cemi completion --help`).

use std::ffi::OsStr;

use clap_complete::engine::CompletionCandidate;

use crate::model::memory_keys;
use crate::refs::VaultSel;
use crate::ui;
use crate::vault::Scope;
use crate::workspace::Workspace;

#[derive(Default)]
struct Names {
    /// (text, purpose) for `record#field` references.
    references: Vec<(String, Option<String>)>,
    /// (text, purpose) for record paths.
    records: Vec<(String, Option<String>)>,
    /// Entity paths, ending in `/`.
    entities: Vec<String>,
    envs: Vec<String>,
}

fn names() -> Names {
    ui::set_non_interactive();
    let mut out = Names::default();
    let Ok(mut ws) = Workspace::new(false) else {
        return out;
    };
    let default = ws.scope_for(VaultSel::Default).ok();
    for scope in [Scope::Local, Scope::Global] {
        // Missing or locked vaults give nothing.
        let Ok(v) = ws.open(scope) else { continue };
        let prefix = if Some(scope) == default {
            String::new()
        } else {
            format!("{scope}:")
        };
        for id in v.subtree(&v.root_id()) {
            let path = v.entity_path(&id);
            if !path.is_empty() {
                out.entities.push(format!("{prefix}{}/", path.join("/")));
            }
            for env in &v.entities[&id].envs {
                if !out.envs.contains(env) {
                    out.envs.push(env.clone());
                }
            }
        }
        for rec in v.records.values().filter(|r| !r.archived) {
            let path = format!("{prefix}{}", v.record_path(rec));
            let purpose = rec.memory.get(memory_keys::PURPOSE).cloned();
            for f in &rec.fields {
                out.references
                    .push((format!("{path}#{}", f.name), purpose.clone()));
            }
            out.records.push((path, purpose));
        }
    }
    out.references.sort();
    out.records.sort();
    out.entities.sort();
    out.envs.sort();
    out
}

fn matching(
    current: &OsStr,
    items: impl IntoIterator<Item = (String, Option<String>)>,
) -> Vec<CompletionCandidate> {
    let current = current.to_string_lossy();
    items
        .into_iter()
        .filter(|(text, _)| text.starts_with(current.as_ref()))
        .map(|(text, help)| CompletionCandidate::new(text).help(help.map(Into::into)))
        .collect()
}

/// `record#field` references.
pub fn references(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, names().references)
}

/// Record paths (some commands also take an entity, so entities come too).
pub fn records(current: &OsStr) -> Vec<CompletionCandidate> {
    let n = names();
    let entities = n.entities.into_iter().map(|e| (e, None));
    matching(current, n.records.into_iter().chain(entities))
}

/// Entity paths.
pub fn entities(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, names().entities.into_iter().map(|e| (e, None)))
}

/// Environment names.
pub fn envs(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, names().envs.into_iter().map(|e| (e, None)))
}
