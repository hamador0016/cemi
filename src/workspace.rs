//! Finding and opening vaults: the global one (`~/.cemi`, or `CEMI_HOME`) and
//! the local one of the current project (`.cemi/` in this folder or a parent).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::crypto::AgeKey;
use crate::refs::VaultSel;
use crate::session;
use crate::ui;
use crate::vault::{HEADER_FILE, Header, Scope, Vault};

pub fn global_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("CEMI_HOME") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::home_dir().context("cannot find your home folder; set CEMI_HOME")?;
    Ok(home.join(".cemi"))
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// The nearest `.cemi/` vault in `start` or its parents (never the global one).
pub fn find_local(start: &Path, global: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        let candidate = dir.join(".cemi");
        if candidate.join(HEADER_FILE).is_file() && !same_dir(&candidate, global) {
            return Some(candidate);
        }
        cur = dir.parent();
    }
    None
}

/// The nearest `cemi.toml` in `start` or its parents.
pub fn find_project_file(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        let candidate = dir.join("cemi.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        cur = dir.parent();
    }
    None
}

pub struct Workspace {
    pub cwd: PathBuf,
    pub global_dir: PathBuf,
    pub local_dir: Option<PathBuf>,
    write: bool,
    global: Option<Vault>,
    local: Option<Vault>,
}

impl Workspace {
    pub fn new(write: bool) -> Result<Workspace> {
        let cwd = std::env::current_dir().context("cannot read the current folder")?;
        Self::at(&cwd, write)
    }

    pub fn at(cwd: &Path, write: bool) -> Result<Workspace> {
        let global_dir = global_dir()?;
        let local_dir = find_local(cwd, &global_dir);
        Ok(Workspace {
            cwd: cwd.to_path_buf(),
            global_dir,
            local_dir,
            write,
            global: None,
            local: None,
        })
    }

    pub fn global_exists(&self) -> bool {
        self.global_dir.join(HEADER_FILE).is_file()
    }

    /// Which vault a selector means here.
    pub fn scope_for(&self, sel: VaultSel) -> Result<Scope> {
        match sel {
            VaultSel::Global => Ok(Scope::Global),
            VaultSel::Local => {
                if self.local_dir.is_none() {
                    bail!(
                        "there is no local vault here. Create one with `cemi init` in your project"
                    );
                }
                Ok(Scope::Local)
            }
            VaultSel::Default => {
                if self.local_dir.is_some() {
                    Ok(Scope::Local)
                } else if self.global_exists() {
                    Ok(Scope::Global)
                } else {
                    bail!(
                        "no vault yet. Create one with `cemi init --global` (for this computer) or `cemi init` (for this project)"
                    )
                }
            }
        }
    }

    pub fn dir(&self, scope: Scope) -> Result<PathBuf> {
        match scope {
            Scope::Global => {
                if !self.global_exists() {
                    bail!("there is no global vault yet. Create it with `cemi init --global`");
                }
                Ok(self.global_dir.clone())
            }
            Scope::Local => self
                .local_dir
                .clone()
                .ok_or_else(|| anyhow!("there is no local vault here")),
        }
    }

    /// Opens (unlocking if needed) and returns the vault.
    pub fn open(&mut self, scope: Scope) -> Result<&mut Vault> {
        let loaded = match scope {
            Scope::Global => self.global.is_some(),
            Scope::Local => self.local.is_some(),
        };
        if !loaded {
            let dir = self.dir(scope)?;
            let key = self.master_key(scope)?;
            let vault = Vault::load(&dir, key, self.write)?;
            if !vault.unreadable.is_empty() {
                ui::warn(format!(
                    "{} object(s) in the {scope} vault could not be opened (damaged or tampered). Run `cemi doctor`.",
                    vault.unreadable.len()
                ));
            }
            match scope {
                Scope::Global => self.global = Some(vault),
                Scope::Local => self.local = Some(vault),
            }
        }
        Ok(match scope {
            Scope::Global => self.global.as_mut().expect("just loaded"),
            Scope::Local => self.local.as_mut().expect("just loaded"),
        })
    }

    pub fn open_sel(&mut self, sel: VaultSel) -> Result<&mut Vault> {
        let scope = self.scope_for(sel)?;
        self.open(scope)
    }

    pub fn get(&self, scope: Scope) -> Option<&Vault> {
        match scope {
            Scope::Global => self.global.as_ref(),
            Scope::Local => self.local.as_ref(),
        }
    }

    /// Gets the vault key: open session, then the global vault (for linked
    /// local vaults), then the password.
    pub fn master_key(&self, scope: Scope) -> Result<AgeKey> {
        let dir = self.dir(scope)?;
        let header = Header::read(&dir)?;
        if let Some(key) = session::load(&header.id) {
            return Ok(key);
        }
        if scope == Scope::Local
            && let Some(wrap) = &header.global
            && self.global_exists()
        {
            let gheader = Header::read(&self.global_dir)?;
            if gheader.id == wrap.vault_id {
                let gkey = self.master_key(Scope::Global)?;
                if let Some(key) = header.unlock_with_global(&gkey)? {
                    session::store(&header.id, &key)?;
                    return Ok(key);
                }
            }
        }
        if header.password.is_none() {
            bail!(
                "the local vault in {} is linked to a global vault that is not on this computer. Use `cemi recovery` with the global vault's recovery code, or restore that vault",
                dir.display()
            );
        }
        for attempt in 0..3 {
            let pw = ui::password(&format!("Password for the {scope} vault: "))?;
            if let Some(key) = header.unlock_with_password(&pw)? {
                session::store(&header.id, &key)?;
                return Ok(key);
            }
            if attempt < 2 {
                eprintln!("Wrong password.");
            }
        }
        Err(crate::errors::locked("wrong password"))
    }

    pub fn save_all(&mut self) -> Result<()> {
        if let Some(v) = self.global.as_mut() {
            v.save()?;
        }
        if let Some(v) = self.local.as_mut() {
            v.save()?;
        }
        Ok(())
    }
}
