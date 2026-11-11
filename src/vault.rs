//! On-disk vault: a folder with a plaintext header and one age file per object.
//!
//! ```text
//! .cemi/
//!   vault.json        header: id, KDF parameters, the wrapped vault key
//!   objects/<id>.age  entities, records, tokens, launchers and approvals (names included)
//!   audit.log         one age-encrypted entry per line
//!   lock              taken while reading or writing
//!   .gitignore        "*", so git never picks the folder up
//! ```
//!
//! Key hierarchy: password (Argon2id) or recovery code or the global vault
//! unwraps the vault key. The vault key opens the root entity; each entity's
//! own key opens its records and child entities.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::BASE64;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, AgeKey, KdfParams, Sealed};
use crate::model::{
    Approval, DEFAULT_PROTECTED, Entity, Envelope, Launcher, OBJECT_FORMAT, Object, Record,
    Sensitive, Token, validate_name,
};

pub const HEADER_FILE: &str = "vault.json";
pub const OBJECTS_DIR: &str = "objects";
pub const VAULT_FORMAT: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Global,
    Local,
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scope::Global => "global",
            Scope::Local => "local",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub cemi_vault: u32,
    pub id: String,
    pub scope: Scope,
    pub created: Timestamp,
    /// Public age recipient of the vault key.
    pub recipient: String,
    pub kdf: KdfParams,
    pub salt: String,
    #[serde(default)]
    pub password: Option<Sealed>,
    #[serde(default)]
    pub recovery: Option<Sealed>,
    /// For local vaults: the vault key encrypted to the global vault, so
    /// unlocking the global vault also unlocks this one.
    #[serde(default)]
    pub global: Option<GlobalWrap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalWrap {
    pub vault_id: String,
    pub ciphertext: String,
}

impl Header {
    pub fn read(dir: &Path) -> Result<Header> {
        let path = dir.join(HEADER_FILE);
        let text =
            fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let header: Header = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a valid Cemí vault header", path.display()))?;
        if header.cemi_vault != VAULT_FORMAT {
            bail!(
                "{} uses vault format {}, but this version of cemi understands format {}. Update cemi.",
                dir.display(),
                header.cemi_vault,
                VAULT_FORMAT
            );
        }
        Ok(header)
    }

    fn aad(&self, purpose: &str) -> Vec<u8> {
        format!("cemi-vault-v1:{}:{purpose}", self.id).into_bytes()
    }

    fn salt_bytes(&self) -> Result<Vec<u8>> {
        BASE64
            .decode(self.salt.as_bytes())
            .context("corrupt vault header (salt)")
    }

    /// Opens the vault key with the master password. `Ok(None)` = wrong password.
    pub fn unlock_with_password(&self, password: &str) -> Result<Option<AgeKey>> {
        let Some(sealed) = &self.password else {
            bail!("this vault has no password; it is unlocked through the global vault");
        };
        let key = crypto::derive_password_key(password, &self.salt_bytes()?, self.kdf)?;
        self.open_sealed(&key, "password", sealed)
    }

    pub fn unlock_with_recovery(&self, code: &str) -> Result<Option<AgeKey>> {
        let Some(sealed) = &self.recovery else {
            bail!("this vault has no recovery code");
        };
        let key = crypto::derive_recovery_key(code, &self.salt_bytes()?)?;
        self.open_sealed(&key, "recovery", sealed)
    }

    pub fn unlock_with_global(&self, global_key: &AgeKey) -> Result<Option<AgeKey>> {
        let Some(wrap) = &self.global else {
            bail!("this vault is not linked to the global vault");
        };
        let ct = BASE64
            .decode(wrap.ciphertext.as_bytes())
            .context("corrupt vault header (global wrap)")?;
        match crypto::age_decrypt_any(&[global_key], &ct)? {
            Some(secret) => {
                let text = std::str::from_utf8(&secret).context("corrupt vault key")?;
                Ok(Some(self.check_key(AgeKey::parse(text)?)?))
            }
            None => Ok(None),
        }
    }

    fn open_sealed(
        &self,
        key: &[u8; 32],
        purpose: &str,
        sealed: &Sealed,
    ) -> Result<Option<AgeKey>> {
        match crypto::open(key, &self.aad(purpose), sealed)? {
            Some(secret) => {
                let text = std::str::from_utf8(&secret).context("corrupt vault key")?;
                Ok(Some(self.check_key(AgeKey::parse(text)?)?))
            }
            None => Ok(None),
        }
    }

    fn check_key(&self, key: AgeKey) -> Result<AgeKey> {
        if key.recipient().to_string() != self.recipient {
            bail!("the vault key does not match this vault's header");
        }
        Ok(key)
    }

    pub fn set_password(&mut self, master: &AgeKey, password: &str) -> Result<()> {
        let salt = self.salt_bytes()?;
        let key = crypto::derive_password_key(password, &salt, self.kdf)?;
        self.password = Some(crypto::seal(
            &key,
            &self.aad("password"),
            master.secret_text().as_bytes(),
        ));
        Ok(())
    }

    /// Creates (or replaces) the recovery code and returns it.
    pub fn new_recovery(&mut self, master: &AgeKey) -> Result<Zeroizing<String>> {
        let code = crypto::new_recovery_code();
        let key = crypto::derive_recovery_key(&code, &self.salt_bytes()?)?;
        self.recovery = Some(crypto::seal(
            &key,
            &self.aad("recovery"),
            master.secret_text().as_bytes(),
        ));
        Ok(code)
    }

    pub fn write(&self, dir: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        atomic_write(&dir.join(HEADER_FILE), text.as_bytes())
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("cannot write in {}", dir.display()))?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|e| anyhow!("cannot write {}: {}", path.display(), e.error))?;
    Ok(())
}

/// Takes the vault lock: exclusive for writers, shared for readers.
fn take_lock(dir: &Path, exclusive: bool) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("lock"))
        .with_context(|| format!("cannot open lock file in {}", dir.display()))?;
    if exclusive {
        file.lock()?;
    } else {
        file.lock_shared()?;
    }
    Ok(file)
}

pub struct Vault {
    pub dir: PathBuf,
    pub header: Header,
    master: AgeKey,
    pub entities: BTreeMap<String, Entity>,
    pub records: BTreeMap<String, Record>,
    pub tokens: BTreeMap<String, Token>,
    pub launchers: BTreeMap<String, Launcher>,
    pub approvals: BTreeMap<String, Approval>,
    /// Objects that could not be opened (corrupt, or encrypted to an unknown key).
    pub unreadable: Vec<String>,
    dirty: BTreeSet<String>,
    deleted: BTreeSet<String>,
    _lock: File,
}

pub struct Created {
    pub vault: Vault,
    pub recovery_code: Option<Zeroizing<String>>,
}

impl Vault {
    /// Creates a new vault in `dir`. A password is required unless the vault
    /// is a local one linked to the global vault.
    pub fn create(
        dir: &Path,
        scope: Scope,
        password: Option<&str>,
        global: Option<(&Header, &AgeKey)>,
        default_envs: &[&str],
        kdf: KdfParams,
    ) -> Result<Created> {
        if dir.join(HEADER_FILE).exists() {
            bail!("there is already a vault in {}", dir.display());
        }
        if password.is_none() && global.is_none() {
            bail!("a new vault needs a password");
        }
        fs::create_dir_all(dir.join(OBJECTS_DIR))
            .with_context(|| format!("cannot create {}", dir.display()))?;
        // Belt and braces: even if the project .gitignore is missing, git skips the vault.
        fs::write(dir.join(".gitignore"), "*\n")?;
        restrict_permissions(dir);

        let master = AgeKey::generate();
        let mut header = Header {
            cemi_vault: VAULT_FORMAT,
            id: crypto::new_id(),
            scope,
            created: Timestamp::now(),
            recipient: master.recipient().to_string(),
            kdf,
            salt: BASE64.encode(&crypto::random_bytes::<16>()),
            password: None,
            recovery: None,
            global: None,
        };
        let mut recovery_code = None;
        if let Some(pw) = password {
            header.set_password(&master, pw)?;
            recovery_code = Some(header.new_recovery(&master)?);
        }
        if let Some((gh, gkey)) = global {
            let recipient = crypto::parse_recipient(&gh.recipient)?;
            debug_assert_eq!(gkey.recipient().to_string(), gh.recipient);
            let ct = crypto::age_encrypt(&recipient, master.secret_text().as_bytes())?;
            header.global = Some(GlobalWrap {
                vault_id: gh.id.clone(),
                ciphertext: BASE64.encode(&ct),
            });
        }
        let lock = take_lock(dir, true)?;
        let now = Timestamp::now();
        let root_key = AgeKey::generate();
        let root = Entity {
            id: crypto::new_id(),
            name: String::new(),
            parent: None,
            identity: Sensitive::new(root_key.secret_text().as_str()),
            envs: default_envs.iter().map(|s| s.to_string()).collect(),
            memory: BTreeMap::new(),
            tasks: Vec::new(),
            protected: None,
            created: now,
            updated: now,
        };
        let mut vault = Vault {
            dir: dir.to_path_buf(),
            header,
            master,
            entities: BTreeMap::new(),
            records: BTreeMap::new(),
            tokens: BTreeMap::new(),
            launchers: BTreeMap::new(),
            approvals: BTreeMap::new(),
            unreadable: Vec::new(),
            dirty: BTreeSet::new(),
            deleted: BTreeSet::new(),
            _lock: lock,
        };
        vault.dirty.insert(root.id.clone());
        vault.entities.insert(root.id.clone(), root);
        vault.save()?;
        vault.header.write(dir)?;
        Ok(Created {
            vault,
            recovery_code,
        })
    }

    /// Loads every object. `write` takes the exclusive lock for the whole
    /// lifetime of the returned vault.
    pub fn load(dir: &Path, master: AgeKey, write: bool) -> Result<Vault> {
        let lock = take_lock(dir, write)?;
        // Read the header after locking, so it matches the objects.
        let header = Header::read(dir)?;
        if master.recipient().to_string() != header.recipient {
            bail!("wrong key for the vault in {}", dir.display());
        }
        let mut pending: Vec<(String, Vec<u8>)> = Vec::new();
        let objects_dir = dir.join(OBJECTS_DIR);
        for entry in fs::read_dir(&objects_dir)
            .with_context(|| format!("cannot read {}", objects_dir.display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("age") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            pending.push((id, fs::read(&path)?));
        }

        let mut vault = Vault {
            dir: dir.to_path_buf(),
            header,
            master,
            entities: BTreeMap::new(),
            records: BTreeMap::new(),
            tokens: BTreeMap::new(),
            launchers: BTreeMap::new(),
            approvals: BTreeMap::new(),
            unreadable: Vec::new(),
            dirty: BTreeSet::new(),
            deleted: BTreeSet::new(),
            _lock: lock,
        };

        // Entities unlock other objects, so keep trying until nothing new opens.
        let mut keys: Vec<AgeKey> = vec![vault.master.clone()];
        loop {
            let before = pending.len();
            let key_refs: Vec<&AgeKey> = keys.iter().collect();
            let mut still: Vec<(String, Vec<u8>)> = Vec::new();
            let mut new_keys = Vec::new();
            for (id, ct) in pending {
                match crypto::age_decrypt_any(&key_refs, &ct) {
                    Ok(Some(plain)) => {
                        let env: Envelope = match serde_json::from_slice(&plain) {
                            Ok(e) => e,
                            Err(_) => {
                                vault.unreadable.push(id);
                                continue;
                            }
                        };
                        if env.format != OBJECT_FORMAT {
                            bail!("object {id} uses format {}; update cemi", env.format);
                        }
                        if env.object.id() != id {
                            // A file renamed or swapped on disk: refuse to trust it.
                            vault.unreadable.push(id);
                            continue;
                        }
                        match env.object {
                            Object::Entity(e) => {
                                new_keys.push(AgeKey::parse(e.identity.expose())?);
                                vault.entities.insert(id, e);
                            }
                            Object::Record(r) => {
                                vault.records.insert(id, r);
                            }
                            Object::Token(t) => {
                                vault.tokens.insert(id, t);
                            }
                            Object::Launcher(l) => {
                                vault.launchers.insert(id, l);
                            }
                            Object::Approval(a) => {
                                vault.approvals.insert(id, a);
                            }
                        }
                    }
                    Ok(None) => still.push((id, ct)),
                    Err(_) => vault.unreadable.push(id),
                }
            }
            keys.extend(new_keys);
            pending = still;
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        vault
            .unreadable
            .extend(pending.into_iter().map(|(id, _)| id));
        vault.check_tree()?;
        Ok(vault)
    }

    fn check_tree(&self) -> Result<()> {
        let roots = self
            .entities
            .values()
            .filter(|e| e.parent.is_none())
            .count();
        if roots != 1 {
            bail!(
                "the vault in {} is damaged: expected one root entity, found {roots}",
                self.dir.display()
            );
        }
        Ok(())
    }

    pub fn master(&self) -> &AgeKey {
        &self.master
    }

    pub fn scope(&self) -> Scope {
        self.header.scope
    }

    /// Writes every changed object and removes deleted ones.
    pub fn save(&mut self) -> Result<()> {
        let objects = self.dir.join(OBJECTS_DIR);
        for id in std::mem::take(&mut self.dirty) {
            let (object, recipient) = self.object_and_recipient(&id)?;
            let envelope = Envelope {
                format: OBJECT_FORMAT,
                object,
            };
            let plain = Zeroizing::new(serde_json::to_vec(&envelope)?);
            let ct = crypto::age_encrypt(&recipient, &plain)?;
            atomic_write(&objects.join(format!("{id}.age")), &ct)?;
        }
        for id in std::mem::take(&mut self.deleted) {
            let path = objects.join(format!("{id}.age"));
            if path.exists() {
                fs::remove_file(&path)?;
            }
        }
        Ok(())
    }

    fn object_and_recipient(&self, id: &str) -> Result<(Object, age::x25519::Recipient)> {
        let vault_recipient = crypto::parse_recipient(&self.header.recipient)?;
        if let Some(e) = self.entities.get(id) {
            let recipient = match &e.parent {
                None => vault_recipient,
                Some(p) => self.entity_key(p)?.recipient(),
            };
            return Ok((Object::Entity(e.clone()), recipient));
        }
        if let Some(r) = self.records.get(id) {
            return Ok((
                Object::Record(r.clone()),
                self.entity_key(&r.entity)?.recipient(),
            ));
        }
        if let Some(t) = self.tokens.get(id) {
            return Ok((Object::Token(t.clone()), vault_recipient));
        }
        if let Some(l) = self.launchers.get(id) {
            return Ok((Object::Launcher(l.clone()), vault_recipient));
        }
        if let Some(a) = self.approvals.get(id) {
            return Ok((Object::Approval(a.clone()), vault_recipient));
        }
        bail!("internal error: object {id} not found")
    }

    fn entity_key(&self, id: &str) -> Result<AgeKey> {
        let e = self
            .entities
            .get(id)
            .ok_or_else(|| anyhow!("internal error: entity {id} not found"))?;
        AgeKey::parse(e.identity.expose())
    }

    pub fn mark_dirty(&mut self, id: &str) {
        self.dirty.insert(id.to_string());
    }

    // ----- entities -----

    pub fn root(&self) -> &Entity {
        self.entities
            .values()
            .find(|e| e.parent.is_none())
            .expect("checked on load")
    }

    pub fn root_id(&self) -> String {
        self.root().id.clone()
    }

    pub fn children(&self, id: &str) -> Vec<&Entity> {
        let mut v: Vec<&Entity> = self
            .entities
            .values()
            .filter(|e| e.parent.as_deref() == Some(id))
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn entity_path(&self, id: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut cur = self.entities.get(id);
        while let Some(e) = cur {
            if e.parent.is_none() {
                break;
            }
            names.push(e.name.clone());
            cur = e.parent.as_deref().and_then(|p| self.entities.get(p));
        }
        names.reverse();
        names
    }

    pub fn entity_path_string(&self, id: &str) -> String {
        self.entity_path(id).join("/")
    }

    pub fn find_entity(&self, path: &[String]) -> Option<&Entity> {
        let mut cur = self.root();
        for name in path {
            cur = self
                .entities
                .values()
                .find(|e| e.parent.as_deref() == Some(cur.id.as_str()) && &e.name == name)?;
        }
        Some(cur)
    }

    pub fn find_entity_id(&self, path: &[String]) -> Result<String> {
        self.find_entity(path)
            .map(|e| e.id.clone())
            .ok_or_else(|| anyhow!("entity not found: {}", display_path(path)))
    }

    /// Returns the entity at `path`, creating any missing entity on the way.
    pub fn ensure_entity(&mut self, path: &[String]) -> Result<String> {
        let mut cur = self.root_id();
        for name in path {
            let existing = self
                .entities
                .values()
                .find(|e| e.parent.as_deref() == Some(cur.as_str()) && &e.name == name)
                .map(|e| e.id.clone());
            cur = match existing {
                Some(id) => id,
                None => {
                    validate_name(name, "entity")?;
                    if self.find_record_in(&cur, name).is_some() {
                        bail!("{name:?} is already a record; an entity cannot have the same name");
                    }
                    let now = Timestamp::now();
                    let key = AgeKey::generate();
                    let e = Entity {
                        id: crypto::new_id(),
                        name: name.clone(),
                        parent: Some(cur.clone()),
                        identity: Sensitive::new(key.secret_text().as_str()),
                        envs: Vec::new(),
                        memory: BTreeMap::new(),
                        tasks: Vec::new(),
                        protected: None,
                        created: now,
                        updated: now,
                    };
                    let id = e.id.clone();
                    self.entities.insert(id.clone(), e);
                    self.dirty.insert(id.clone());
                    id
                }
            };
        }
        Ok(cur)
    }

    /// Environments of an entity, including those inherited from its parents.
    pub fn effective_envs(&self, id: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut cur = self.entities.get(id);
        while let Some(e) = cur {
            chain.push(e);
            cur = e.parent.as_deref().and_then(|p| self.entities.get(p));
        }
        let mut envs: Vec<String> = Vec::new();
        for e in chain.iter().rev() {
            for env in &e.envs {
                if !envs.contains(env) {
                    envs.push(env.clone());
                }
            }
        }
        envs
    }

    /// The entity itself and every entity below it.
    pub fn subtree(&self, id: &str) -> Vec<String> {
        let mut out = vec![id.to_string()];
        let mut i = 0;
        while i < out.len() {
            let cur = out[i].clone();
            for c in self.children(&cur) {
                out.push(c.id.clone());
            }
            i += 1;
        }
        out
    }

    // ----- records -----

    pub fn find_record_in(&self, entity_id: &str, name: &str) -> Option<&Record> {
        self.records
            .values()
            .find(|r| r.entity == entity_id && r.name == name)
    }

    pub fn find_record(&self, entities: &[String], name: &str) -> Result<&Record> {
        let entity = self
            .find_entity(entities)
            .ok_or_else(|| anyhow!("entity not found: {}", display_path(entities)))?;
        self.find_record_in(&entity.id, name).ok_or_else(|| {
            anyhow!(
                "record not found: {}",
                display_path(&[entities, &[name.to_string()]].concat())
            )
        })
    }

    pub fn find_record_id(&self, entities: &[String], name: &str) -> Result<String> {
        self.find_record(entities, name).map(|r| r.id.clone())
    }

    pub fn record_mut(&mut self, id: &str) -> &mut Record {
        self.dirty.insert(id.to_string());
        let r = self.records.get_mut(id).expect("record id from this vault");
        r.updated = Timestamp::now();
        r
    }

    pub fn entity_mut(&mut self, id: &str) -> &mut Entity {
        self.dirty.insert(id.to_string());
        let e = self
            .entities
            .get_mut(id)
            .expect("entity id from this vault");
        e.updated = Timestamp::now();
        e
    }

    pub fn add_record(&mut self, entity_id: &str, name: &str) -> Result<String> {
        validate_name(name, "record")?;
        if self.find_record_in(entity_id, name).is_some() {
            bail!("record {name:?} already exists");
        }
        if self
            .entities
            .values()
            .any(|e| e.parent.as_deref() == Some(entity_id) && e.name == name)
        {
            bail!("{name:?} is already an entity; a record cannot have the same name");
        }
        let now = Timestamp::now();
        let r = Record {
            id: crypto::new_id(),
            entity: entity_id.to_string(),
            name: name.to_string(),
            fields: Vec::new(),
            memory: BTreeMap::new(),
            archived: false,
            created: now,
            updated: now,
        };
        let id = r.id.clone();
        self.records.insert(id.clone(), r);
        self.dirty.insert(id.clone());
        Ok(id)
    }

    pub fn record_path(&self, r: &Record) -> String {
        let mut p = self.entity_path_string(&r.entity);
        if !p.is_empty() {
            p.push('/');
        }
        p.push_str(&r.name);
        p
    }

    /// Moves a record to another entity; it is re-encrypted to the new entity's key.
    pub fn move_record(&mut self, id: &str, entity_id: &str, name: &str) -> Result<()> {
        validate_name(name, "record")?;
        if let Some(other) = self.find_record_in(entity_id, name)
            && other.id != id
        {
            bail!("record {name:?} already exists there");
        }
        let r = self.record_mut(id);
        r.entity = entity_id.to_string();
        r.name = name.to_string();
        Ok(())
    }

    pub fn delete_record(&mut self, id: &str) {
        self.records.remove(id);
        self.dirty.remove(id);
        self.deleted.insert(id.to_string());
    }

    // ----- tokens and launchers -----

    pub fn put_token(&mut self, t: Token) {
        self.dirty.insert(t.id.clone());
        self.tokens.insert(t.id.clone(), t);
    }

    pub fn put_launcher(&mut self, l: Launcher) {
        self.dirty.insert(l.id.clone());
        self.launchers.insert(l.id.clone(), l);
    }

    pub fn delete_launcher(&mut self, id: &str) {
        self.launchers.remove(id);
        self.dirty.remove(id);
        self.deleted.insert(id.to_string());
    }

    // ----- approvals and protected environments -----

    pub fn put_approval(&mut self, a: Approval) {
        self.dirty.insert(a.id.clone());
        self.approvals.insert(a.id.clone(), a);
    }

    pub fn delete_approval(&mut self, id: &str) {
        self.approvals.remove(id);
        self.dirty.remove(id);
        self.deleted.insert(id.to_string());
    }

    /// Environments whose changes need a person's approval.
    pub fn protected_envs(&self) -> Vec<String> {
        match &self.root().protected {
            Some(list) => list.clone(),
            None => DEFAULT_PROTECTED.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn is_protected(&self, env: &str) -> bool {
        self.protected_envs().iter().any(|e| e == env)
    }
}

pub fn display_path(path: &[String]) -> String {
    if path.is_empty() {
        "(root)".to_string()
    } else {
        path.join("/")
    }
}

#[cfg(unix)]
fn restrict_permissions(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_permissions(_dir: &Path) {
    // On Windows, folders under the user profile are already private to the user.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Field, FieldKind, SHARED, Value};

    fn new_vault(dir: &Path) -> (Vault, Zeroizing<String>) {
        let c = Vault::create(
            dir,
            Scope::Global,
            Some("pw"),
            None,
            &["dev", "prod"],
            KdfParams::INSECURE_FAST,
        )
        .unwrap();
        (c.vault, c.recovery_code.unwrap())
    }

    #[test]
    fn create_save_and_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".cemi");
        let (mut v, code) = new_vault(&dir);
        let ent = v.ensure_entity(&["acme".into(), "shop".into()]).unwrap();
        let rid = v.add_record(&ent, "stripe").unwrap();
        let r = v.record_mut(&rid);
        let mut f = Field::new("secret", FieldKind::Text, true);
        f.values
            .entry(SHARED.into())
            .or_default()
            .push(Value::text("sk_test_123"), "t", None);
        r.fields.push(f);
        v.save().unwrap();
        drop(v);

        // Nothing readable on disk.
        for entry in fs::read_dir(dir.join(OBJECTS_DIR)).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("sk_test_123"));
            assert!(!text.contains("stripe"));
            assert!(!text.contains("acme"));
        }

        let header = Header::read(&dir).unwrap();
        assert!(header.unlock_with_password("wrong").unwrap().is_none());
        let key = header.unlock_with_password("pw").unwrap().unwrap();
        let v = Vault::load(&dir, key, false).unwrap();
        assert!(v.unreadable.is_empty());
        let r = v
            .find_record(&["acme".into(), "shop".into()], "stripe")
            .unwrap();
        assert_eq!(v.record_path(r), "acme/shop/stripe");
        drop(v);

        let key = header.unlock_with_recovery(&code).unwrap().unwrap();
        assert!(Vault::load(&dir, key, false).is_ok());
    }

    #[test]
    fn swapped_object_files_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".cemi");
        let (mut v, _) = new_vault(&dir);
        let root = v.root_id();
        let a = v.add_record(&root, "a").unwrap();
        let b = v.add_record(&root, "b").unwrap();
        v.save().unwrap();
        let key = v.master().clone();
        drop(v);
        let objs = dir.join(OBJECTS_DIR);
        let pa = objs.join(format!("{a}.age"));
        let pb = objs.join(format!("{b}.age"));
        let ca = fs::read(&pa).unwrap();
        fs::write(&pa, fs::read(&pb).unwrap()).unwrap();
        fs::write(&pb, ca).unwrap();
        let v = Vault::load(&dir, key, false).unwrap();
        assert_eq!(v.unreadable.len(), 2);
        assert!(v.records.is_empty());
    }

    #[test]
    fn local_vault_opens_with_global_key() {
        let tmp = tempfile::tempdir().unwrap();
        let (g, _) = new_vault(&tmp.path().join("global"));
        let local_dir = tmp.path().join("proj/.cemi");
        let c = Vault::create(
            &local_dir,
            Scope::Local,
            None,
            Some((&g.header, g.master())),
            &["dev"],
            KdfParams::INSECURE_FAST,
        )
        .unwrap();
        assert!(c.recovery_code.is_none());
        drop(c);
        let h = Header::read(&local_dir).unwrap();
        let key = h.unlock_with_global(g.master()).unwrap().unwrap();
        let v = Vault::load(&local_dir, key, false).unwrap();
        assert_eq!(v.scope(), Scope::Local);
        assert_eq!(v.effective_envs(&v.root_id()), vec!["dev"]);
    }

    #[test]
    fn names_cannot_collide() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut v, _) = new_vault(&tmp.path().join("v"));
        let root = v.root_id();
        v.add_record(&root, "db").unwrap();
        assert!(v.ensure_entity(&["db".into()]).is_err());
        v.ensure_entity(&["acme".into()]).unwrap();
        assert!(v.add_record(&root, "acme").is_err());
        assert!(v.add_record(&root, "db").is_err());
    }
}
