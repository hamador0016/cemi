//! Logic shared by the command line and the MCP server.

use anyhow::{Result, bail};
use jiff::Zoned;
use jiff::civil::Date;

use crate::cli::Charset;
use crate::crypto;
use crate::model::{Field, FieldKind, Record, SHARED, Value, memory_keys as mk, validate_name};
use crate::refs::Ref;
use crate::vault::Vault;

fn today() -> Date {
    Zoned::now().date()
}

/// A problem shown by `cemi status`.
pub struct Attention {
    pub what: String,
    pub detail: String,
    /// Needs doing soon: expired or expiring this week, a task due, an
    /// unfinished rotation, an approval waiting, a destination out of date.
    /// Missing notes and values are not urgent; `cemi status` lists them.
    pub urgent: bool,
}

/// Everything in one vault that needs attention.
pub fn attention(v: &Vault, only: Option<&[String]>) -> Vec<Attention> {
    let mut out = Vec::new();
    let today = today();
    let mut recs: Vec<&Record> = v
        .records
        .values()
        .filter(|r| !r.archived)
        .filter(|r| only.is_none_or(|ids| ids.contains(&r.entity)))
        .collect();
    recs.sort_by_key(|r| v.record_path(r));
    for r in recs {
        let path = v.record_path(r);
        let envs = v.effective_envs(&r.entity);
        for f in &r.fields {
            if f.kind == FieldKind::Template && f.values.is_empty() {
                out.push(Attention {
                    what: format!("{path}#{}", f.name),
                    detail: "template has no text".into(),
                    urgent: false,
                });
                continue;
            }
            let has_shared = f
                .values
                .get(SHARED)
                .is_some_and(|s| s.current().is_some() || s.external.is_some());
            if f.values.is_empty() {
                out.push(Attention {
                    what: format!("{path}#{}", f.name),
                    detail: "no value".into(),
                    urgent: false,
                });
            } else if !has_shared {
                let missing: Vec<&String> = envs
                    .iter()
                    .filter(|e| {
                        !f.values
                            .get(*e)
                            .is_some_and(|s| s.current().is_some() || s.external.is_some())
                    })
                    .collect();
                if !missing.is_empty() && missing.len() < envs.len() {
                    out.push(Attention {
                        what: format!("{path}#{}", f.name),
                        detail: format!(
                            "no value for {}",
                            missing
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        urgent: false,
                    });
                }
            }
            if f.secret {
                let per_env: Vec<(&String, Vec<u8>)> = f
                    .values
                    .iter()
                    .filter(|(k, _)| k.as_str() != SHARED)
                    .filter_map(|(k, s)| s.current().map(|val| (k, val.bytes().to_vec())))
                    .collect();
                for i in 0..per_env.len() {
                    for j in i + 1..per_env.len() {
                        if crypto::ct_eq(&per_env[i].1, &per_env[j].1) {
                            out.push(Attention {
                                what: format!("{path}#{}", f.name),
                                detail: format!(
                                    "same secret in {} and {}",
                                    per_env[i].0, per_env[j].0
                                ),
                                urgent: false,
                            });
                        }
                    }
                }
            }
        }
        if let Some(exp) = r.memory.get(mk::EXPIRES) {
            expiry(&mut out, &path, exp, today);
        }
        if r.has_secrets() {
            if !r.memory.contains_key(mk::PURPOSE) {
                out.push(Attention {
                    what: path.clone(),
                    detail: "no purpose noted (cemi note --purpose)".into(),
                    urgent: false,
                });
            }
            if !r.memory.contains_key(mk::BACKUP) {
                out.push(Attention {
                    what: path.clone(),
                    detail: "no backup noted (cemi note --backup)".into(),
                    urgent: false,
                });
            }
        }
    }
    for e in v.entities.values() {
        if only.is_some_and(|ids| !ids.contains(&e.id)) {
            continue;
        }
        let epath = format!("{}/", v.entity_path_string(&e.id));
        if let Some(exp) = e.memory.get(mk::EXPIRES) {
            expiry(&mut out, &epath, exp, today);
        }
        for t in &e.tasks {
            if t.due() <= today {
                out.push(Attention {
                    what: epath.clone(),
                    detail: format!("task \"{}\" was due {}", t.name, t.due()),
                    urgent: true,
                });
            }
        }
    }
    if !v.unreadable.is_empty() {
        out.push(Attention {
            what: "vault".into(),
            detail: format!(
                "{} object(s) cannot be opened — run `cemi doctor`",
                v.unreadable.len()
            ),
            urgent: true,
        });
    }
    out
}

fn expiry(out: &mut Vec<Attention>, what: &str, text: &str, today: Date) {
    match text.trim().parse::<Date>() {
        Ok(d) => {
            let days = (d - today).get_days();
            if d < today {
                out.push(Attention {
                    what: what.to_string(),
                    detail: format!("expired on {d}"),
                    urgent: true,
                });
            } else if days <= 30 {
                out.push(Attention {
                    what: what.to_string(),
                    detail: format!("expires on {d} (in {days} days)"),
                    urgent: days <= 7,
                });
            }
        }
        Err(_) => out.push(Attention {
            what: what.to_string(),
            detail: format!("expires: {text:?} is not a YYYY-MM-DD date"),
            urgent: false,
        }),
    }
}

/// The field `r` points at, creating it as a secret text field if allowed.
pub fn ensure_field<'a>(rec: &'a mut Record, r: &Ref, create: bool) -> Result<&'a mut Field> {
    let fname = r.require_field()?.to_string();
    if rec.field(&fname).is_none() {
        if !create {
            bail!(
                "{} has no field {fname:?}. Create it: cemi field add {} {fname:?} [--secret]",
                r.record_path(),
                r.record_path()
            );
        }
        validate_name(&fname, "field")?;
        rec.fields
            .push(Field::new(fname.clone(), FieldKind::Text, true));
    }
    Ok(rec.field_mut(&fname).expect("just ensured"))
}

pub fn random_string(length: usize, charset: Charset) -> String {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const HEX: &[u8] = b"0123456789abcdef";
    const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const SYMBOLS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-.:;=?@^_~";
    let set = match charset {
        Charset::Alnum => ALNUM,
        Charset::Hex => HEX,
        Charset::Base64url => B64URL,
        Charset::Symbols => SYMBOLS,
    };
    // Rejection sampling keeps every character equally likely.
    let limit = 256 - (256 % set.len());
    let mut out = String::with_capacity(length);
    while out.len() < length {
        for b in crypto::random_bytes::<64>() {
            if (b as usize) < limit && out.len() < length {
                out.push(set[b as usize % set.len()] as char);
            }
        }
    }
    out
}

/// Stores a new random value in `record_id`, creating the field if needed.
pub fn generate_value(
    v: &mut Vault,
    record_id: &str,
    r: &Ref,
    env: Option<&str>,
    length: usize,
    actor: &str,
) -> Result<()> {
    if !(8..=4096).contains(&length) {
        bail!("length must be between 8 and 4096");
    }
    let value = zeroize::Zeroizing::new(random_string(length, Charset::Alnum));
    let rec = v.record_mut(record_id);
    let field = ensure_field(rec, r, true)?;
    if !field.secret {
        bail!("{r} is not a secret field; generated values go in secret fields");
    }
    field
        .values
        .entry(env.unwrap_or(SHARED).to_string())
        .or_default()
        .push(Value::text(value.as_str()), actor, Some("generated".into()));
    Ok(())
}

/// A record described without any secret value (for `show` in the MCP server).
pub fn record_summary(v: &Vault, rec: &Record) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "{}", v.record_path(rec));
    for (k, val) in &rec.memory {
        let _ = writeln!(out, "{k}: {val}");
    }
    out.push_str("fields:\n");
    for f in &rec.fields {
        let secret = if f.secret { ", secret" } else { "" };
        let _ = writeln!(out, "- {} ({}{secret})", f.name, f.kind);
        for (env, slot) in &f.values {
            let state = if let Some(ext) = &slot.external {
                format!("not stored in Cemí, lives in: {ext}")
            } else {
                match slot.current() {
                    None => "no value".to_string(),
                    Some(_) if f.secret || f.kind == FieldKind::Template => {
                        "set (hidden)".to_string()
                    }
                    Some(Value::Text { text }) => text.expose().to_string(),
                    Some(Value::File { name, .. }) => format!("file {name}"),
                }
            };
            let _ = writeln!(out, "    {}: {state}", env_name(env));
        }
        for (env, o) in &f.origins {
            let _ = writeln!(
                out,
                "    new values ({}): {}",
                env_name(env),
                o.spec.describe()
            );
        }
        for d in &f.destinations {
            let sent = match &d.last {
                Some(l) => format!("last sent {}", crate::ui::when(l.at, "%Y-%m-%d %H:%M")),
                None => "never sent".to_string(),
            };
            let _ = writeln!(
                out,
                "    copied to ({}): {} [{}, {sent}]",
                env_name(&d.env),
                d.spec.describe(),
                d.id
            );
        }
        for (env, cmd) in &f.verify {
            let _ = writeln!(out, "    checked by ({}): {}", env_name(env), cmd.join(" "));
        }
        for a in &f.apis {
            let _ = writeln!(
                out,
                "    API ({}): {}, allowed: {} [{}]",
                env_name(&a.env),
                a.base,
                a.allow.join(", "),
                a.id
            );
        }
    }
    let envs = v.effective_envs(&rec.entity);
    if !envs.is_empty() {
        let _ = writeln!(out, "environments: {}", envs.join(", "));
    }
    out
}

fn env_name(env: &str) -> &str {
    if env == SHARED {
        "all environments"
    } else {
        env
    }
}
