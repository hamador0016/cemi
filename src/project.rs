//! `cemi.toml`: what a project needs, as references. It never holds values
//! and is meant to be committed.
//!
//! ```toml
//! vault = "global"          # optional: "local" or "global"
//! entity = "acme/shop"      # optional: base for relative references
//!
//! [env]
//! DATABASE_URL = "db#url"
//! STRIPE_SECRET_KEY = { ref = "stripe#secret", purpose = "payments" }
//!
//! [files]
//! GOOGLE_APPLICATION_CREDENTIALS = "gcp#service-account"
//!
//! [ai.commands]
//! test = { cmd = ["npm", "test"], envs = ["dev"] }
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::refs::{self, Ref, VaultSel};

pub const FILE: &str = "cemi.toml";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cemi_version: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, RefSpec>,
    #[serde(default)]
    pub files: BTreeMap<String, RefSpec>,
    #[serde(default)]
    pub ai: Ai,
    /// Secrets for CI (`cemi ci`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci: Option<CiConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiConfig {
    /// Public half of the CI key: `cemi ci export` encrypts to it.
    pub recipient: String,
    /// The encrypted file, relative to cemi.toml (default cemi.ci.age).
    #[serde(default)]
    pub file: Option<String>,
    /// Only these variables go to CI (default: all of them).
    #[serde(default)]
    pub vars: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RefSpec {
    Short(String),
    Full {
        r#ref: String,
        #[serde(default)]
        purpose: Option<String>,
    },
}

impl RefSpec {
    pub fn text(&self) -> &str {
        match self {
            RefSpec::Short(s) => s,
            RefSpec::Full { r#ref, .. } => r#ref,
        }
    }

    pub fn purpose(&self) -> Option<&str> {
        match self {
            RefSpec::Short(_) => None,
            RefSpec::Full { purpose, .. } => purpose.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ai {
    #[serde(default)]
    pub commands: BTreeMap<String, AiCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiCommand {
    pub cmd: Vec<String>,
    /// Environments where an AI may run this command. Empty means none.
    #[serde(default)]
    pub envs: Vec<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

pub struct Project {
    pub path: PathBuf,
    pub file: ProjectFile,
}

impl Project {
    pub fn load(path: &Path) -> Result<Project> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let file: ProjectFile =
            toml::from_str(&text).with_context(|| format!("{} is not valid", path.display()))?;
        let p = Project {
            path: path.to_path_buf(),
            file,
        };
        p.check_version()?;
        Ok(p)
    }

    pub fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new("."))
    }

    fn check_version(&self) -> Result<()> {
        let Some(req) = &self.file.cemi_version else {
            return Ok(());
        };
        let req = semver::VersionReq::parse(req)
            .with_context(|| format!("invalid cemi_version {req:?} in {}", self.path.display()))?;
        let me = semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("valid package version");
        if !req.matches(&me) {
            bail!(
                "{} needs cemi {req}, but this is cemi {me}. Update cemi.",
                self.path.display()
            );
        }
        Ok(())
    }

    /// The vault and entity that relative references start from.
    pub fn base(&self) -> Result<(VaultSel, Vec<String>)> {
        let vault = match self.file.vault.as_deref() {
            None => VaultSel::Default,
            Some("global") => VaultSel::Global,
            Some("local") => VaultSel::Local,
            Some(other) => bail!("vault must be \"local\" or \"global\", not {other:?}"),
        };
        let entity = refs::entity_path(self.file.entity.as_deref().unwrap_or(""))?;
        Ok((vault, entity))
    }

    pub fn resolve_ref(&self, text: &str) -> Result<Ref> {
        let (vault, entity) = self.base()?;
        let r = Ref::parse(text)?.relative_to(vault, &entity);
        r.require_field()?;
        Ok(r)
    }

    /// Edits one table of the file, keeping the user's comments and order.
    pub fn edit(
        path: &Path,
        f: impl FnOnce(&mut toml_edit::DocumentMut) -> Result<()>,
    ) -> Result<()> {
        let text = if path.exists() {
            std::fs::read_to_string(path)?
        } else {
            String::new()
        };
        let mut doc: toml_edit::DocumentMut = text
            .parse()
            .with_context(|| format!("{} is not valid TOML", path.display()))?;
        f(&mut doc)?;
        let out = doc.to_string();
        // Make sure the result still parses as a project file before writing it.
        toml::from_str::<ProjectFile>(&out).context("the edited cemi.toml would be invalid")?;
        crate::vault::atomic_write(path, out.as_bytes())
    }
}

pub fn template(vault: Option<&str>, entity: Option<&str>) -> String {
    let mut s = String::from(
        "# Cemí project file: which secrets this project needs, as references.\n\
         # It never contains values, so it is safe to commit.\n",
    );
    if let Some(v) = vault {
        s.push_str(&format!("vault = \"{v}\"\n"));
    }
    if let Some(e) = entity {
        s.push_str(&format!("entity = {}\n", toml_edit::Value::from(e)));
    }
    s.push_str(concat!(
        "\n# Variables for `cemi run`: NAME = \"record#field\" (or `cemi var add NAME record#field`)\n",
        "[env]\n",
        "\n# Variables that get a file path instead of the value\n",
        "[files]\n",
        "\n# Commands an AI client may run, and in which environments:\n",
        "# test = { cmd = [\"npm\", \"test\"], envs = [\"dev\"] }\n",
        "[ai.commands]\n",
    ));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_project_file() {
        let f: ProjectFile = toml::from_str(
            r#"
            vault = "global"
            entity = "acme/shop"
            [env]
            A = "db#url"
            B = { ref = "local:x#y", purpose = "test" }
            [ai.commands]
            test = { cmd = ["npm", "test"], envs = ["dev"] }
            "#,
        )
        .unwrap();
        let p = Project {
            path: PathBuf::from("cemi.toml"),
            file: f,
        };
        assert_eq!(
            p.resolve_ref("db#url").unwrap().to_string(),
            "global:acme/shop/db#url"
        );
        assert_eq!(p.resolve_ref("local:x#y").unwrap().to_string(), "local:x#y");
        assert!(p.resolve_ref("db").is_err());
    }

    #[test]
    fn template_is_valid() {
        let t = template(Some("global"), Some("acme/shop"));
        let f: ProjectFile = toml::from_str(&t).unwrap();
        assert_eq!(f.entity.as_deref(), Some("acme/shop"));
    }
}
