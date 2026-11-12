//! Sharing one entity with another developer, without a server.
//!
//! `cemi share` writes a bundle: the entity's records, fields and notes, and
//! the values of the chosen environments only, encrypted with age to the
//! receiver's public key (`cemi share key` on their side). The receiver
//! imports it with `cemi share accept`. Origins, destinations, APIs and
//! verify commands stay behind: they hold the sender's credentials and places.
//!
//! The sender's vault keeps a digest of every value sent, so `cemi status`
//! says when a shared value changed and the bundle should be sent again.
//! Nothing can be taken back: whoever received a value keeps it.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow, bail};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cmd_shared::Attention;
use crate::crypto::{self, AgeKey};
use crate::model::{FieldKind, Received, Record, SHARED, SentShare, Value, Version, VersionState};
use crate::vault::Vault;

pub const FORMAT: u32 = 1;

#[derive(Serialize, Deserialize)]
pub struct Bundle {
    pub cemi_share: u32,
    /// The same for every bundle of one entity to one receiver.
    pub id: String,
    /// The sender's public key.
    pub from: String,
    pub created: Timestamp,
    /// Path of the shared entity in the sender's vault.
    pub entity: Vec<String>,
    pub envs: Vec<String>,
    pub entities: Vec<SharedEntity>,
    pub records: Vec<SharedRecord>,
}

#[derive(Serialize, Deserialize)]
pub struct SharedEntity {
    /// Below the shared entity; empty for the entity itself.
    pub path: Vec<String>,
    pub envs: Vec<String>,
    pub memory: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct SharedRecord {
    /// Entity path below the shared entity.
    pub entity: Vec<String>,
    pub name: String,
    pub memory: BTreeMap<String, String>,
    pub fields: Vec<SharedField>,
}

#[derive(Serialize, Deserialize)]
pub struct SharedField {
    pub name: String,
    pub kind: FieldKind,
    pub secret: bool,
    /// Environment to its value.
    pub values: BTreeMap<String, SharedValue>,
}

#[derive(Serialize, Deserialize)]
pub struct SharedValue {
    pub value: Value,
    /// When the sender set it; an older value never replaces a newer one.
    pub at: Timestamp,
}

/// What `make` left out, for the sender to read.
#[derive(Default)]
pub struct LeftOut {
    pub origins: usize,
    pub destinations: usize,
    pub apis: usize,
    pub verify: usize,
    pub other_envs: usize,
}

impl LeftOut {
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (n, what) in [
            (self.other_envs, "values of other environments"),
            (self.origins, "origins (where new keys are created)"),
            (
                self.destinations,
                "destinations (places values are copied to)",
            ),
            (self.apis, "APIs for the credential proxy"),
            (self.verify, "verify commands"),
        ] {
            if n > 0 {
                out.push(format!("{n} {what}"));
            }
        }
        out
    }
}

/// A stable id for the bundles of one entity to one receiver.
fn share_id(entity_id: &str, to: &str) -> String {
    crypto::sha256_hex(format!("cemi-share:{entity_id}:{to}").as_bytes())[..32].to_string()
}

fn slot_key(record_id: &str, field: &str, env: &str) -> String {
    format!("{record_id}#{field}#{env}")
}

/// The current value of a field for an environment, with its time.
fn value_for<'a>(f: &'a crate::model::Field, env: &str) -> Option<&'a Version> {
    f.slot_for(Some(env)).and_then(|(_, s)| s.current_version())
}

/// Builds the bundle of `entity_id` for `envs`, and what this vault should
/// remember about it.
pub fn make(
    v: &Vault,
    entity_id: &str,
    to: &str,
    name: Option<String>,
    envs: &[String],
) -> Result<(Bundle, SentShare, LeftOut)> {
    let base = v.entity_path(entity_id);
    let now = Timestamp::now();
    let id = share_id(entity_id, to);
    let mut left = LeftOut::default();
    let subtree = v.subtree(entity_id);
    let mut entities = Vec::new();
    for eid in &subtree {
        let e = &v.entities[eid];
        let path = v.entity_path(eid)[base.len()..].to_vec();
        entities.push(SharedEntity {
            path,
            envs: e
                .envs
                .iter()
                .filter(|x| envs.contains(x))
                .cloned()
                .collect(),
            memory: e.memory.clone(),
        });
    }
    let mut records = Vec::new();
    let mut sent = BTreeMap::new();
    let mut recs: Vec<&Record> = v
        .records
        .values()
        .filter(|r| !r.archived && subtree.contains(&r.entity))
        .collect();
    recs.sort_by_key(|r| v.record_path(r));
    for r in recs {
        let mut fields = Vec::new();
        for f in &r.fields {
            left.origins += f.origins.len();
            left.destinations += f.destinations.len();
            left.apis += f.apis.len();
            left.verify += f.verify.len();
            left.other_envs += f
                .values
                .keys()
                .filter(|k| k.as_str() != SHARED && !envs.contains(k))
                .count();
            let mut values = BTreeMap::new();
            for env in envs {
                if let Some(ver) = value_for(f, env) {
                    sent.insert(
                        slot_key(&r.id, &f.name, env),
                        crypto::sha256_hex(&ver.value.bytes()),
                    );
                    values.insert(
                        env.clone(),
                        SharedValue {
                            value: ver.value.clone(),
                            at: ver.at,
                        },
                    );
                }
            }
            fields.push(SharedField {
                name: f.name.clone(),
                kind: f.kind,
                secret: f.secret,
                values,
            });
        }
        records.push(SharedRecord {
            entity: v.entity_path(&r.entity)[base.len()..].to_vec(),
            name: r.name.clone(),
            memory: r.memory.clone(),
            fields,
        });
    }
    let bundle = Bundle {
        cemi_share: FORMAT,
        id: id.clone(),
        from: v.header.recipient.clone(),
        created: now,
        entity: base,
        envs: envs.to_vec(),
        entities,
        records,
    };
    let record = SentShare {
        id,
        entity: entity_id.to_string(),
        to: to.to_string(),
        name,
        envs: envs.to_vec(),
        sent,
        at: now,
    };
    Ok((bundle, record, left))
}

/// The bundle as armored age text, readable only by `to`.
pub fn seal(bundle: &Bundle, to: &str) -> Result<String> {
    let recipient = crypto::parse_recipient(to)?;
    let plain = Zeroizing::new(serde_json::to_vec(bundle)?);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| anyhow!("encryption failed: {e}"))?;
    let mut out = Vec::new();
    let armor = age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)
        .map_err(|e| anyhow!("encryption failed: {e}"))?;
    let mut w = encryptor
        .wrap_output(armor)
        .map_err(|e| anyhow!("encryption failed: {e}"))?;
    w.write_all(&plain)?;
    w.finish()
        .and_then(|armor| armor.finish())
        .map_err(|e| anyhow!("encryption failed: {e}"))?;
    Ok(String::from_utf8(out).expect("armored text"))
}

/// Opens a bundle with one of `keys` (the vault keys of this computer).
pub fn open(text: &[u8], keys: &[&AgeKey]) -> Result<Bundle> {
    let reader = age::armor::ArmoredReader::new(text);
    let decryptor =
        age::Decryptor::new(reader).map_err(|_| anyhow!("this is not a Cemí share file"))?;
    let identities = keys.iter().map(|k| k.identity() as &dyn age::Identity);
    let mut plain = Zeroizing::new(Vec::new());
    match decryptor.decrypt(identities) {
        Ok(mut r) => {
            r.read_to_end(&mut plain)
                .context("the share file is damaged")?;
        }
        Err(age::DecryptError::NoMatchingKeys) => {
            return Err(crate::errors::not_found(
                "this share was made for another vault: the sender needs the key from `cemi share key` on this computer",
            ));
        }
        Err(e) => bail!("cannot open the share file: {e}"),
    }
    let bundle: Bundle =
        serde_json::from_slice(&plain).context("the share file is not a Cemí share")?;
    if bundle.cemi_share != FORMAT {
        bail!(
            "this share uses format {}; update cemi to accept it",
            bundle.cemi_share
        );
    }
    Ok(bundle)
}

/// What `accept` did.
#[derive(Default)]
pub struct Accepted {
    pub records: usize,
    pub new_values: usize,
    /// Values skipped because this vault has a newer one.
    pub kept_newer: usize,
}

/// Imports a bundle under `target` (an entity path in this vault).
pub fn accept(v: &mut Vault, bundle: &Bundle, target: &[String]) -> Result<Accepted> {
    let mut done = Accepted::default();
    let from_label = format!("share:{}", short_key(&bundle.from));
    for e in &bundle.entities {
        let path = [target, &e.path].concat();
        let id = v.ensure_entity(&path)?;
        let ent = v.entity_mut(&id);
        for env in &e.envs {
            if !ent.envs.contains(env) {
                ent.envs.push(env.clone());
            }
        }
        for (k, val) in &e.memory {
            ent.memory.entry(k.clone()).or_insert_with(|| val.clone());
        }
    }
    for r in &bundle.records {
        let path = [target, &r.entity].concat();
        let entity_id = v.ensure_entity(&path)?;
        let rid = match v.find_record_in(&entity_id, &r.name) {
            Some(existing) => {
                if let Some(rec) = &existing.received
                    && rec.share == bundle.id
                    && rec.at > bundle.created
                {
                    // A newer bundle of this share was already accepted.
                    done.kept_newer += r.fields.iter().map(|f| f.values.len()).sum::<usize>();
                    continue;
                }
                existing.id.clone()
            }
            None => v.add_record(&entity_id, &r.name)?,
        };
        done.records += 1;
        let rec = v.record_mut(&rid);
        rec.received = Some(Received {
            from: bundle.from.clone(),
            share: bundle.id.clone(),
            at: bundle.created,
        });
        for (k, val) in &r.memory {
            rec.memory.insert(k.clone(), val.clone());
        }
        for sf in &r.fields {
            let field = match rec.fields.iter().position(|f| f.name == sf.name) {
                Some(i) => &mut rec.fields[i],
                None => {
                    rec.fields
                        .push(crate::model::Field::new(&sf.name, sf.kind, sf.secret));
                    rec.fields.last_mut().expect("just pushed")
                }
            };
            field.secret = field.secret || sf.secret;
            for (env, sv) in &sf.values {
                let slot = field.values.entry(env.clone()).or_default();
                if let Some(cur) = slot.current_version() {
                    if crypto::ct_eq(&cur.value.bytes(), &sv.value.bytes()) {
                        continue;
                    }
                    if cur.at >= sv.at {
                        done.kept_newer += 1;
                        continue;
                    }
                }
                for old in slot.versions.iter_mut() {
                    if old.state == VersionState::Active {
                        old.state = VersionState::Archived;
                    }
                }
                slot.external = None;
                slot.versions.push(Version {
                    value: sv.value.clone(),
                    state: VersionState::Active,
                    at: sv.at,
                    actor: from_label.clone(),
                    note: Some(format!(
                        "received {}",
                        crate::ui::when(bundle.created, "%Y-%m-%d %H:%M")
                    )),
                    provider_id: None,
                });
                done.new_values += 1;
            }
        }
    }
    Ok(done)
}

/// `age1abc…xyz`, enough to tell keys apart in a list.
pub fn short_key(key: &str) -> String {
    if key.len() <= 16 {
        return key.to_string();
    }
    format!("{}…{}", &key[..10], &key[key.len() - 6..])
}

/// Who a share went to, for people.
pub fn receiver(sh: &SentShare) -> String {
    match &sh.name {
        Some(n) => format!("{n} ({})", short_key(&sh.to)),
        None => short_key(&sh.to),
    }
}

/// Shared values that changed since they were sent (field labels).
pub fn changed_since(v: &Vault, sh: &SentShare) -> Vec<String> {
    let mut out = Vec::new();
    for (key, digest) in &sh.sent {
        let mut parts = key.splitn(3, '#');
        let (Some(rid), Some(field), Some(env)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let now = v
            .records
            .get(rid)
            .and_then(|r| r.field(field))
            .and_then(|f| value_for(f, env))
            .map(|ver| crypto::sha256_hex(&ver.value.bytes()));
        if now.as_deref() != Some(digest.as_str()) {
            let label = match v.records.get(rid) {
                Some(r) => format!("{}#{field} ({env})", v.record_path(r)),
                None => format!("a removed record ({env})"),
            };
            out.push(label);
        }
    }
    out
}

/// `cemi status` lines for shares whose values changed after sending.
pub fn attention(v: &Vault, only: Option<&[String]>) -> Vec<Attention> {
    let mut out = Vec::new();
    let mut shares: Vec<&SentShare> = v.shares.values().collect();
    shares.sort_by_key(|s| s.at);
    for sh in shares {
        if only.is_some_and(|ids| !ids.contains(&sh.entity)) {
            continue;
        }
        let changed = changed_since(v, sh);
        if changed.is_empty() {
            continue;
        }
        let entity = v.entity_path_string(&sh.entity);
        out.push(Attention {
            what: format!("{entity}/ shared with {}", receiver(sh)),
            detail: format!(
                "{} changed since {}; send it again: cemi share {entity} --with {}",
                changed.join(", "),
                crate::ui::when(sh.at, "%Y-%m-%d"),
                sh.to
            ),
            urgent: false,
        });
    }
    out
}
