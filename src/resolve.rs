//! Turns a reference into a value, expanding template fields.

use anyhow::{Result, anyhow, bail};
use zeroize::Zeroizing;

use crate::model::{FieldKind, Value};
use crate::refs::{Ref, VaultSel};
use crate::vault::Scope;
use crate::workspace::Workspace;

pub struct Resolved {
    pub bytes: Zeroizing<Vec<u8>>,
    pub secret: bool,
    pub kind: FieldKind,
    /// Original file name, for file fields.
    pub file_name: Option<String>,
}

impl Resolved {
    pub fn text(&self) -> Result<Zeroizing<String>> {
        let s = std::str::from_utf8(&self.bytes)
            .map_err(|_| anyhow!("this value is binary; use it as a file instead"))?;
        Ok(Zeroizing::new(s.to_string()))
    }
}

const MAX_DEPTH: usize = 8;

pub fn resolve(ws: &mut Workspace, r: &Ref, env: Option<&str>) -> Result<Resolved> {
    resolve_depth(ws, r, env, 0)
}

pub fn sel_for(scope: Scope) -> VaultSel {
    match scope {
        Scope::Global => VaultSel::Global,
        Scope::Local => VaultSel::Local,
    }
}

fn resolve_depth(ws: &mut Workspace, r: &Ref, env: Option<&str>, depth: usize) -> Result<Resolved> {
    if depth > MAX_DEPTH {
        bail!("template references go too deep (a loop?) at {r}");
    }
    let field_name = r.require_field()?.to_string();
    let scope = ws.scope_for(r.vault)?;
    let vault = ws.open(scope)?;
    let record = vault.find_record(&r.entities, &r.record)?;
    let entity_path = vault.entity_path(&record.entity);
    let field = record
        .field(&field_name)
        .ok_or_else(|| {
            crate::errors::not_found(format!("{} has no field {field_name:?}", r.record_path()))
        })?
        .clone();
    let env_label = env.unwrap_or("(shared)");
    let Some((_, slot)) = field.slot_for(env) else {
        bail!("{r} has no value for environment {env_label}");
    };
    let Some(value) = slot.current() else {
        if let Some(external) = &slot.external {
            bail!("{r} is not stored in Cemí (it lives in: {external})");
        }
        bail!("{r} has no value for environment {env_label}");
    };

    if field.kind == FieldKind::Template {
        let template = value.bytes();
        let template = std::str::from_utf8(&template)
            .map_err(|_| anyhow!("template {r} is not text"))?
            .to_string();
        let mut secret = field.secret;
        let mut out = Zeroizing::new(String::new());
        let mut rest = template.as_str();
        while let Some(start) = rest.find("{{") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let end = after
                .find("}}")
                .ok_or_else(|| anyhow!("template {r} has an unclosed {{{{"))?;
            let inner = after[..end].trim();
            let part_ref = template_ref(inner, scope, &entity_path)?;
            let part = resolve_depth(ws, &part_ref, env, depth + 1)?;
            secret |= part.secret;
            out.push_str(&part.text()?);
            rest = &after[end + 2..];
        }
        out.push_str(rest);
        return Ok(Resolved {
            bytes: Zeroizing::new(out.as_bytes().to_vec()),
            secret,
            kind: FieldKind::Template,
            file_name: None,
        });
    }

    let file_name = match value {
        Value::File { name, .. } => Some(name.clone()),
        Value::Text { .. } => None,
    };
    Ok(Resolved {
        bytes: value.bytes(),
        secret: field.secret,
        kind: field.kind,
        file_name,
    })
}

/// The `{{…}}` parts of a template, trimmed.
pub fn template_refs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(s) = rest.find("{{") {
        let after = &rest[s + 2..];
        let Some(e) = after.find("}}") else { break };
        out.push(after[..e].trim().to_string());
        rest = &after[e + 2..];
    }
    out
}

/// Template parts are relative to the template's own entity, unless they
/// start with `/` (absolute in the same vault) or `global:`/`local:`.
pub fn template_ref(text: &str, scope: Scope, entity_path: &[String]) -> Result<Ref> {
    if let Some(abs) = text.strip_prefix('/') {
        let mut r = Ref::parse(abs)?;
        r.vault = sel_for(scope);
        return Ok(r);
    }
    Ok(Ref::parse(text)?.relative_to(sel_for(scope), entity_path))
}
