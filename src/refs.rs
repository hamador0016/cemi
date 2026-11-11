//! References to records and fields: `[global:|local:]entity/sub/record#field`.

use std::fmt;

use anyhow::{Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VaultSel {
    /// Local vault if the current project has one, otherwise the global vault.
    Default,
    Global,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ref {
    pub vault: VaultSel,
    /// Entity names from the root, without the record.
    pub entities: Vec<String>,
    pub record: String,
    pub field: Option<String>,
}

impl Ref {
    pub fn parse(text: &str) -> Result<Ref> {
        let text = text.trim();
        let text = text.strip_prefix("cemi://").unwrap_or(text);
        let (vault, rest) = if let Some(r) = text.strip_prefix("global:") {
            (VaultSel::Global, r)
        } else if let Some(r) = text.strip_prefix("local:") {
            (VaultSel::Local, r)
        } else {
            (VaultSel::Default, text)
        };
        let (path, field) = match rest.split_once('#') {
            Some((p, f)) => {
                if f.is_empty() {
                    bail!("empty field name in reference {text:?}");
                }
                (p, Some(f.to_string()))
            }
            None => (rest, None),
        };
        let mut parts: Vec<String> = path.split('/').map(|s| s.to_string()).collect();
        if parts.iter().any(|p| p.trim().is_empty()) {
            bail!("invalid reference {text:?}: expected entity/record#field");
        }
        let record = parts.pop().expect("split always yields one part");
        Ok(Ref {
            vault,
            entities: parts,
            record,
            field,
        })
    }

    /// Resolves a reference written relative to a base entity (as in `cemi.toml`).
    /// References with an explicit `global:`/`local:` prefix are absolute.
    pub fn relative_to(mut self, base_vault: VaultSel, base_entity: &[String]) -> Ref {
        if self.vault == VaultSel::Default {
            self.vault = base_vault;
            let mut entities = base_entity.to_vec();
            entities.append(&mut self.entities);
            self.entities = entities;
        }
        self
    }

    pub fn require_field(&self) -> Result<&str> {
        match &self.field {
            Some(f) => Ok(f),
            None => bail!("reference {self} needs a field: add #field-name"),
        }
    }

    pub fn record_path(&self) -> String {
        let mut p = self.entities.join("/");
        if !p.is_empty() {
            p.push('/');
        }
        p.push_str(&self.record);
        p
    }
}

impl fmt::Display for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.vault {
            VaultSel::Global => f.write_str("global:")?,
            VaultSel::Local => f.write_str("local:")?,
            VaultSel::Default => {}
        }
        f.write_str(&self.record_path())?;
        if let Some(field) = &self.field {
            write!(f, "#{field}")?;
        }
        Ok(())
    }
}

/// Splits an entity path like `acme/shop` into names. Empty means the root.
pub fn entity_path(text: &str) -> Result<Vec<String>> {
    let text = text.trim().trim_matches('/');
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let parts: Vec<String> = text.split('/').map(|s| s.to_string()).collect();
    if parts.iter().any(|p| p.trim().is_empty()) {
        bail!("invalid entity path {text:?}");
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_reference() {
        let r = Ref::parse("global:acme/shop/stripe#secret key").unwrap();
        assert_eq!(r.vault, VaultSel::Global);
        assert_eq!(r.entities, vec!["acme", "shop"]);
        assert_eq!(r.record, "stripe");
        assert_eq!(r.field.as_deref(), Some("secret key"));
        assert_eq!(r.to_string(), "global:acme/shop/stripe#secret key");
    }

    #[test]
    fn parses_record_at_root() {
        let r = Ref::parse("stripe").unwrap();
        assert!(r.entities.is_empty());
        assert_eq!(r.field, None);
    }

    #[test]
    fn rejects_bad_references() {
        assert!(Ref::parse("a//b").is_err());
        assert!(Ref::parse("a#").is_err());
        assert!(Ref::parse("").is_err());
    }

    #[test]
    fn relative_references() {
        let base = vec!["acme".to_string()];
        let r = Ref::parse("db#url")
            .unwrap()
            .relative_to(VaultSel::Global, &base);
        assert_eq!(r.to_string(), "global:acme/db#url");
        let r = Ref::parse("local:x#y")
            .unwrap()
            .relative_to(VaultSel::Global, &base);
        assert_eq!(r.to_string(), "local:x#y");
    }
}
