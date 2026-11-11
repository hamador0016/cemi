//! Presets: the usual records of a stack (fields, memory notes and the
//! variables a project reads), so a new project starts with the structure
//! instead of a blank vault. They are data files in `presets/`, built into
//! the binary. They never contain values, only non-secret templates.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::model::{Field, FieldKind, SHARED, Value, validate_name};
use crate::refs::Ref;
use crate::vault::Vault;

const FILES: &[(&str, &str)] = &[
    (
        "next-supabase",
        include_str!("../presets/next-supabase.toml"),
    ),
    ("postgres", include_str!("../presets/postgres.toml")),
    ("resend", include_str!("../presets/resend.toml")),
    ("stripe", include_str!("../presets/stripe.toml")),
    ("supabase", include_str!("../presets/supabase.toml")),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    #[serde(skip)]
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub records: BTreeMap<String, PresetRecord>,
    /// Variable name → reference (relative to where the preset is applied).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetRecord {
    #[serde(default)]
    pub memory: BTreeMap<String, String>,
    pub fields: Vec<PresetField>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetField {
    pub name: String,
    #[serde(rename = "type", default)]
    pub kind: Option<FieldKind>,
    #[serde(default)]
    pub secret: bool,
    /// A starting value for every environment, for non-secret fields only
    /// (like a template).
    #[serde(default)]
    pub value: Option<String>,
}

pub fn names() -> Vec<&'static str> {
    FILES.iter().map(|(n, _)| *n).collect()
}

pub fn get(name: &str) -> Result<Preset> {
    let (n, text) = FILES.iter().find(|(n, _)| *n == name).ok_or_else(|| {
        anyhow!(
            "there is no preset {name:?}. Available: {}",
            names().join(", ")
        )
    })?;
    let mut p: Preset = toml::from_str(text).with_context(|| format!("preset {n} is invalid"))?;
    p.name = n.to_string();
    p.check()?;
    Ok(p)
}

impl Preset {
    fn check(&self) -> Result<()> {
        for (rec, r) in &self.records {
            validate_name(rec, "record")?;
            for f in &r.fields {
                validate_name(&f.name, "field")?;
                if f.secret && f.value.is_some() {
                    bail!(
                        "preset {}: {rec}#{} is secret and has a value",
                        self.name,
                        f.name
                    );
                }
            }
        }
        for (var, reference) in &self.env {
            crate::dotenv::check_var_name(var)?;
            let r = Ref::parse(reference)?;
            let field = r.require_field()?;
            let known = r.entities.is_empty()
                && self
                    .records
                    .get(&r.record)
                    .is_some_and(|rec| rec.fields.iter().any(|f| f.name == field));
            if !known {
                bail!(
                    "preset {}: {var} points at {reference}, which the preset does not define",
                    self.name
                );
            }
        }
        Ok(())
    }

    /// Fields that need a value from you after applying the preset.
    pub fn to_fill(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (rec, r) in &self.records {
            for f in &r.fields {
                if f.value.is_none() {
                    out.push(format!("{rec}#{}", f.name));
                }
            }
        }
        out
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Applied {
    pub records: usize,
    pub fields: usize,
    pub notes: usize,
}

/// Adds the preset's records to an entity. What already exists stays as it
/// is: a field with the same name is not changed, and a memory note is only
/// added where there is none.
pub fn apply(v: &mut Vault, entity: &str, p: &Preset) -> Result<Applied> {
    let mut n = Applied::default();
    for (name, rec) in &p.records {
        let id = match v.find_record_in(entity, name) {
            Some(r) => r.id.clone(),
            None => {
                n.records += 1;
                v.add_record(entity, name)?
            }
        };
        let r = v.record_mut(&id);
        for (k, val) in &rec.memory {
            if !r.memory.contains_key(k) {
                r.memory.insert(k.clone(), val.clone());
                n.notes += 1;
            }
        }
        for f in &rec.fields {
            if r.field(&f.name).is_some() {
                continue;
            }
            let mut field = Field::new(&f.name, f.kind.unwrap_or(FieldKind::Text), f.secret);
            if let Some(value) = &f.value {
                field.values.entry(SHARED.to_string()).or_default().push(
                    Value::text(value.as_str()),
                    "cli",
                    Some(format!("preset {}", p.name)),
                );
            }
            r.fields.push(field);
            n.fields += 1;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_preset_is_valid() {
        for name in names() {
            let p = get(name).unwrap();
            assert!(!p.description.is_empty(), "{name}");
            assert!(!p.records.is_empty(), "{name}");
        }
        assert!(get("nope").is_err());
    }
}
