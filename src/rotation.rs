//! Pushing values to their destinations, checking them, and rotating keys.
//! Used by the command line and by the MCP server; callers decide about
//! approval (see `needs_approval`).
//!
//! A rotation never loses a key: the new value is saved as `pending` before
//! anything else happens. If a destination or the verification fails, the old
//! value goes back to every destination already changed.

use anyhow::{Result, anyhow, bail};
use jiff::Timestamp;
use zeroize::Zeroizing;

use crate::audit;
use crate::cli::Charset;
use crate::cmd_shared::random_string;
use crate::connectors::{self, Observed, OriginSpec, OriginState, Revoked};
use crate::crypto;
use crate::model::{
    Delivery, Destination, Field, FieldKind, SHARED, Value, Version, VersionState, memory_keys,
};
use crate::refs::{Ref, VaultSel};
use crate::resolve;
use crate::runner::Redactor;
use crate::vault::Scope;
use crate::workspace::Workspace;

/// A field of a record in one of the vaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRef {
    pub scope: Scope,
    pub record_id: String,
    pub field: String,
}

/// One destination of a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestRef {
    pub field: FieldRef,
    pub id: String,
}

impl FieldRef {
    /// Finds a field from a reference.
    pub fn find(ws: &mut Workspace, r: &Ref) -> Result<FieldRef> {
        let field = r.require_field()?.to_string();
        let scope = ws.scope_for(r.vault)?;
        let v = ws.open(scope)?;
        let rec = v.find_record(&r.entities, &r.record)?;
        if rec.field(&field).is_none() {
            bail!("{} has no field {field:?}", r.record_path());
        }
        Ok(FieldRef {
            scope,
            record_id: rec.id.clone(),
            field,
        })
    }

    /// A reference to this field, with its vault prefix.
    pub fn to_ref(&self, ws: &mut Workspace) -> Result<Ref> {
        let v = ws.open(self.scope)?;
        let rec = v
            .records
            .get(&self.record_id)
            .ok_or_else(|| anyhow!("the record no longer exists"))?;
        Ok(Ref {
            vault: resolve::sel_for(self.scope),
            entities: v.entity_path(&rec.entity),
            record: rec.name.clone(),
            field: Some(self.field.clone()),
        })
    }

    pub fn text(&self, ws: &mut Workspace) -> String {
        self.to_ref(ws)
            .map(|r| r.to_string())
            .unwrap_or_else(|_| format!("{}#{}", self.record_id, self.field))
    }

    pub fn field<'a>(&self, ws: &'a mut Workspace) -> Result<&'a Field> {
        let v = ws.open(self.scope)?;
        v.records
            .get(&self.record_id)
            .and_then(|r| r.field(&self.field))
            .ok_or_else(|| anyhow!("the field {} no longer exists", self.field))
    }

    pub fn field_mut<'a>(&self, ws: &'a mut Workspace) -> Result<&'a mut Field> {
        let v = ws.open(self.scope)?;
        if !v.records.contains_key(&self.record_id) {
            bail!("the record no longer exists");
        }
        v.record_mut(&self.record_id)
            .field_mut(&self.field)
            .ok_or_else(|| anyhow!("the field {} no longer exists", self.field))
    }

    /// A note of the record's memory.
    fn memory(&self, ws: &mut Workspace, key: &str) -> Option<String> {
        let v = ws.open(self.scope).ok()?;
        v.records.get(&self.record_id)?.memory.get(key).cloned()
    }
}

pub fn audit(
    ws: &mut Workspace,
    scope: Scope,
    actor: &str,
    action: &str,
    target: Option<String>,
    env: Option<&str>,
    detail: Option<String>,
) {
    let Ok(v) = ws.open(scope) else { return };
    if let Err(e) = audit::append(
        &v.dir,
        &v.header,
        audit::Event {
            actor,
            action,
            target,
            env: env.map(str::to_string),
            detail,
        },
    ) {
        crate::ui::warn(format!("could not write the audit log: {e}"));
    }
}

fn save(ws: &mut Workspace, scope: Scope) -> Result<()> {
    ws.open(scope)?.save()
}

/// Hides `value` (and its encodings) in an error message.
fn redact_error(e: anyhow::Error, value: &[u8]) -> anyhow::Error {
    if value.is_empty() {
        return e;
    }
    let r = Redactor::new(&[("VALUE".into(), Zeroizing::new(value.to_vec()))]);
    anyhow!(
        "{}",
        String::from_utf8_lossy(&r.redact(format!("{e:#}").as_bytes()))
    )
}

pub fn env_label(env: &str) -> &str {
    if env == SHARED {
        "all environments"
    } else {
        env
    }
}

fn slot_env(slot: &str) -> Option<&str> {
    (slot != SHARED).then_some(slot)
}

fn destination(ws: &mut Workspace, d: &DestRef) -> Result<Destination> {
    d.field
        .field(ws)?
        .destinations
        .iter()
        .find(|x| x.id == d.id)
        .cloned()
        .ok_or_else(|| anyhow!("destination {} no longer exists", d.id))
}

/// The value a destination should hold now.
fn value_for(ws: &mut Workspace, d: &DestRef) -> Result<Zeroizing<Vec<u8>>> {
    let r = d.field.to_ref(ws)?;
    let dest = destination(ws, d)?;
    Ok(resolve::resolve(ws, &r, dest.env_opt())?.bytes)
}

/// The vaults that exist here, opened. A locked extra vault is skipped: it
/// cannot hold what the caller asked about.
fn open_scopes(ws: &mut Workspace) -> Vec<Scope> {
    let mut out = Vec::new();
    for scope in [Scope::Global, Scope::Local] {
        let exists = match scope {
            Scope::Global => ws.global_exists(),
            Scope::Local => ws.local_dir.is_some(),
        };
        if exists && (ws.get(scope).is_some() || ws.open(scope).is_ok()) {
            out.push(scope);
        }
    }
    out
}

/// Destinations of the fields in the open vaults, optionally limited to one
/// field and/or to the ones that receive one environment's value.
pub fn all_destinations(
    ws: &mut Workspace,
    only_field: Option<&FieldRef>,
    env: Option<&str>,
) -> Result<Vec<DestRef>> {
    let mut out = Vec::new();
    let scopes = match only_field {
        Some(f) => vec![f.scope],
        None => open_scopes(ws),
    };
    for scope in scopes {
        let v = ws.open(scope)?;
        for rec in v.records.values().filter(|r| !r.archived) {
            for f in &rec.fields {
                let fr = FieldRef {
                    scope,
                    record_id: rec.id.clone(),
                    field: f.name.clone(),
                };
                if only_field.is_some_and(|o| *o != fr) {
                    continue;
                }
                for d in &f.destinations {
                    if env.is_some_and(|e| d.env != e) {
                        continue;
                    }
                    out.push(DestRef {
                        field: fr.clone(),
                        id: d.id.clone(),
                    });
                }
            }
        }
    }
    Ok(out)
}

/// Template fields that include `target` (directly or through other templates).
pub fn dependents(ws: &mut Workspace, target: &FieldRef) -> Result<Vec<FieldRef>> {
    let mut found: Vec<FieldRef> = Vec::new();
    let mut frontier = vec![target.clone()];
    while let Some(t) = frontier.pop() {
        let t_ref = t.to_ref(ws)?;
        for scope in open_scopes(ws) {
            let v = ws.open(scope)?;
            let mut hits = Vec::new();
            for rec in v.records.values().filter(|r| !r.archived) {
                let base = v.entity_path(&rec.entity);
                for f in rec.fields.iter().filter(|f| f.kind == FieldKind::Template) {
                    let refers = f.values.values().any(|slot| {
                        slot.current().is_some_and(|val| {
                            let text = String::from_utf8_lossy(&val.bytes()).into_owned();
                            resolve::template_refs(&text).iter().any(|part| {
                                resolve::template_ref(part, scope, &base).is_ok_and(|p| {
                                    same_vault(p.vault, scope, t.scope)
                                        && p.entities == t_ref.entities
                                        && p.record == t_ref.record
                                        && p.field == t_ref.field
                                })
                            })
                        })
                    });
                    if refers {
                        hits.push(FieldRef {
                            scope,
                            record_id: rec.id.clone(),
                            field: f.name.clone(),
                        });
                    }
                }
            }
            for h in hits {
                if !found.contains(&h) && h != *target {
                    found.push(h.clone());
                    frontier.push(h);
                }
            }
        }
    }
    Ok(found)
}

fn same_vault(sel: VaultSel, template_scope: Scope, target_scope: Scope) -> bool {
    match sel {
        VaultSel::Global => target_scope == Scope::Global,
        VaultSel::Local => target_scope == Scope::Local,
        VaultSel::Default => template_scope == target_scope,
    }
}

/// The destinations that receive the value of `slot` of `target`: its own,
/// and those of templates built from it, for environments that use that slot.
pub fn affected(ws: &mut Workspace, target: &FieldRef, slot: &str) -> Result<Vec<DestRef>> {
    let field = target.field(ws)?.clone();
    let uses_slot = |env: &str| -> bool {
        match field.slot_for(slot_env(env)) {
            Some((k, _)) => k == slot,
            None => env == slot,
        }
    };
    let mut out = Vec::new();
    let mut fields = vec![target.clone()];
    fields.extend(dependents(ws, target)?);
    for fr in fields {
        let f = fr.field(ws)?.clone();
        for d in &f.destinations {
            if uses_slot(&d.env) {
                out.push(DestRef {
                    field: fr.clone(),
                    id: d.id.clone(),
                });
            }
        }
    }
    Ok(out)
}

/// Protected environments that an action for `env` on these destinations
/// touches. Empty means no approval is needed.
pub fn needs_approval(ws: &mut Workspace, env: Option<&str>, dests: &[DestRef]) -> Vec<String> {
    let mut envs: Vec<(Scope, String)> = Vec::new();
    if let Some(e) = env {
        for scope in open_scopes(ws) {
            envs.push((scope, e.to_string()));
        }
    }
    for d in dests {
        if let Ok(dest) = destination(ws, d) {
            envs.push((d.field.scope, dest.env));
        }
    }
    let mut out: Vec<String> = Vec::new();
    for (scope, e) in envs {
        let Ok(v) = ws.open(scope) else { continue };
        let hits: Vec<String> = if e == SHARED {
            v.protected_envs()
        } else if v.is_protected(&e) {
            vec![e]
        } else {
            vec![]
        };
        for p in hits {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

// ----- push -----

/// Sends the current value to one destination. Callers decide first with
/// [`check_one`] and [`DestStatus::needs_push`].
pub fn push_one(ws: &mut Workspace, d: &DestRef, actor: &str) -> Result<()> {
    let dest = destination(ws, d)?;
    let value = value_for(ws, d)?;
    deliver(ws, d, &value)?;
    save(ws, d.field.scope)?;
    let target = d.field.text(ws);
    audit(
        ws,
        d.field.scope,
        actor,
        "push",
        Some(target),
        Some(&dest.env),
        Some(dest.spec.describe()),
    );
    Ok(())
}

/// Writes `value` to a destination and records the delivery (not saved).
fn deliver(ws: &mut Workspace, d: &DestRef, value: &[u8]) -> Result<()> {
    let dest = destination(ws, d)?;
    connectors::write(&dest.spec, ws, dest.env_opt(), value).map_err(|e| redact_error(e, value))?;
    let remote = match connectors::observe(&dest.spec, ws, dest.env_opt()) {
        Ok(Observed::Remote(r)) => Some(r),
        _ => None,
    };
    let fingerprint = crypto::sha256_hex(value);
    let field = d.field.field_mut(ws)?;
    if let Some(x) = field.destinations.iter_mut().find(|x| x.id == d.id) {
        x.last = Some(Delivery {
            fingerprint,
            remote,
            at: Timestamp::now(),
        });
    }
    Ok(())
}

// ----- check -----

pub enum DestStatus {
    UpToDate,
    /// The vault changed since the last push.
    Outdated,
    NeverSent,
    /// The destination changed outside Cemí.
    ChangedOutside(String),
    /// The destination does not have it.
    Missing,
    /// The destination cannot be observed; the vault side is up to date.
    Unverifiable,
    Error(String),
}

impl DestStatus {
    pub fn label(&self) -> String {
        match self {
            DestStatus::UpToDate => "up to date".into(),
            DestStatus::Outdated => "out of date: run `cemi push`".into(),
            DestStatus::NeverSent => "never sent: run `cemi push`".into(),
            DestStatus::ChangedOutside(m) => format!("changed outside Cemí ({m})"),
            DestStatus::Missing => "missing at the destination: run `cemi push`".into(),
            DestStatus::Unverifiable => "sent (this kind of destination cannot be checked)".into(),
            DestStatus::Error(e) => format!("error: {e}"),
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, DestStatus::UpToDate | DestStatus::Unverifiable)
    }

    /// A stable name for scripts (`--json`).
    pub fn key(&self) -> &'static str {
        match self {
            DestStatus::UpToDate => "up_to_date",
            DestStatus::Outdated => "outdated",
            DestStatus::NeverSent => "never_sent",
            DestStatus::ChangedOutside(_) => "changed_outside",
            DestStatus::Missing => "missing",
            DestStatus::Unverifiable => "unverifiable",
            DestStatus::Error(_) => "error",
        }
    }

    /// Whether `push` sends the value without being forced. A value changed
    /// outside Cemí is not overwritten: it may be a newer key set by hand.
    pub fn needs_push(&self) -> bool {
        matches!(
            self,
            DestStatus::Outdated | DestStatus::NeverSent | DestStatus::Missing
        )
    }
}

pub struct CheckLine {
    pub field: String,
    /// The environment for people ("all environments" for a shared value).
    pub env: String,
    /// The environment as stored (SHARED for a shared value).
    pub slot: String,
    pub id: String,
    pub describe: String,
    pub status: DestStatus,
}

impl CheckLine {
    /// The command that overwrites this destination with the vault's value.
    pub fn force_command(&self) -> String {
        match slot_env(&self.slot) {
            Some(e) => format!("cemi push --force {} -e {e}", self.field),
            None => format!("cemi push --force {}", self.field),
        }
    }

    /// What a person reads when this destination changed outside Cemí.
    pub fn changed_outside_hint(&self) -> String {
        format!(
            "`{}` puts the vault's value back; if the new value is the right one, save it with `cemi set`",
            self.force_command()
        )
    }
}

/// Compares the vault with what was sent. With `remote`, also asks the
/// destination (network); without it, only the vault side is compared.
pub fn check_one(ws: &mut Workspace, d: &DestRef, remote: bool) -> CheckLine {
    let field = d.field.text(ws);
    let mut line = CheckLine {
        field,
        env: String::new(),
        slot: String::new(),
        id: d.id.clone(),
        describe: String::new(),
        status: DestStatus::UpToDate,
    };
    let dest = match destination(ws, d) {
        Ok(x) => x,
        Err(e) => {
            line.status = DestStatus::Error(format!("{e:#}"));
            return line;
        }
    };
    line.env = env_label(&dest.env).to_string();
    line.slot = dest.env.clone();
    line.describe = dest.spec.describe();
    let current = match value_for(ws, d) {
        Ok(v) => crypto::sha256_hex(&v),
        Err(e) => {
            line.status = DestStatus::Error(format!("{e:#}"));
            return line;
        }
    };
    let Some(last) = &dest.last else {
        line.status = DestStatus::NeverSent;
        return line;
    };
    if remote {
        match connectors::observe(&dest.spec, ws, dest.env_opt()) {
            Ok(Observed::Missing) => {
                line.status = DestStatus::Missing;
                return line;
            }
            Ok(Observed::Remote(now)) => {
                if last.remote.as_ref().is_some_and(|before| *before != now) {
                    line.status =
                        DestStatus::ChangedOutside(connectors::describe_change(&dest.spec, &now));
                    return line;
                }
            }
            Ok(Observed::Unknown) => {
                if last.fingerprint == current {
                    line.status = DestStatus::Unverifiable;
                    return line;
                }
            }
            Err(e) => {
                line.status = DestStatus::Error(format!("{e:#}"));
                return line;
            }
        }
    }
    if last.fingerprint != current {
        line.status = DestStatus::Outdated;
    }
    line
}

/// A problem with the origin of a slot: the provider no longer has the
/// active key (network).
pub fn origin_problem(ws: &mut Workspace, fr: &FieldRef, slot: &str) -> Result<Option<String>> {
    let f = fr.field(ws)?.clone();
    let Some(origin) = f.origins.get(slot) else {
        return Ok(None);
    };
    let Some(ver) = f.values.get(slot).and_then(|s| s.current_version()) else {
        return Ok(None);
    };
    let state =
        connectors::origin_state(&origin.spec, ws, slot_env(slot), ver.provider_id.as_deref())?;
    Ok(match state {
        OriginState::Gone => Some(format!(
            "the active key no longer exists at {}: rotate it (cemi rotate {}{})",
            origin.spec.describe(),
            fr.text(ws),
            slot_env(slot)
                .map(|e| format!(" -e {e}"))
                .unwrap_or_default()
        )),
        OriginState::Alive | OriginState::Unknown => None,
    })
}

// ----- rotate -----

pub enum NewValue {
    /// Ask the origin.
    Origin,
    Generate {
        length: usize,
        charset: Charset,
    },
    Given(Zeroizing<String>),
}

pub struct RotateOptions {
    pub new_value: NewValue,
    /// The old key leaked: revoke it as soon as the new one works.
    pub leaked: bool,
    /// Do not revoke the old key (for a grace period).
    pub keep_old: bool,
}

/// The slot a rotation of `fr` for `env` changes.
pub fn slot_key(ws: &mut Workspace, fr: &FieldRef, env: Option<&str>) -> Result<String> {
    let f = fr.field(ws)?;
    Ok(match f.slot_for(env) {
        Some((k, _)) => k.to_string(),
        None => env.unwrap_or(SHARED).to_string(),
    })
}

fn env_flag(slot: &str) -> String {
    slot_env(slot)
        .map(|e| format!(" -e {e}"))
        .unwrap_or_default()
}

/// What a rotation will do, one line per step, for the person who approves it.
pub fn describe_plan(
    ws: &mut Workspace,
    fr: &FieldRef,
    env: Option<&str>,
    opts: &RotateOptions,
) -> Result<Vec<String>> {
    let slot = slot_key(ws, fr, env)?;
    let f = fr.field(ws)?.clone();
    let name = fr.text(ws);
    let mut out = vec![format!("Rotate {name} ({})", env_label(&slot))];
    let has_pending = f
        .values
        .get(&slot)
        .and_then(|s| s.pending_index())
        .is_some();
    out.push(if has_pending {
        "1. New value: the pending one of an unfinished rotation".into()
    } else {
        match (&opts.new_value, f.origins.get(&slot)) {
            (NewValue::Origin, Some(o)) => {
                format!("1. New value: created at {}", o.spec.describe())
            }
            (NewValue::Origin, None) => {
                "1. New value: none (no origin; use --generate or --paste)".into()
            }
            (NewValue::Generate { length, .. }, _) => {
                format!("1. New value: {length} random characters made by Cemí")
            }
            (NewValue::Given(_), _) => "1. New value: the one you typed".into(),
        }
    });
    let dests = affected(ws, fr, &slot)?;
    if dests.is_empty() {
        out.push("2. Destinations: none yet (`cemi dest add` adds them)".into());
    } else {
        out.push("2. Send it to:".into());
        for d in &dests {
            if let Ok(x) = destination(ws, d) {
                let via = if d.field == *fr {
                    String::new()
                } else {
                    format!(" (inside {})", d.field.text(ws))
                };
                out.push(format!("   - {}{via}", x.spec.describe()));
            }
        }
    }
    out.push(match f.verify.get(&slot) {
        Some(cmd) => format!("3. Verify with `{}`", cmd.join(" ")),
        None => "3. Verify: no check set (`cemi verify` adds one)".into(),
    });
    out.push(match (opts.keep_old, f.origins.get(&slot)) {
        (true, _) => "4. Keep the old key valid (revoke it later with `cemi revoke`)".into(),
        (false, Some(o)) => format!(
            "4. Revoke the old key at {}{}",
            o.spec.describe(),
            if opts.leaked {
                " (reported as leaked)"
            } else {
                ""
            }
        ),
        (false, None) => "4. Revoke the old key: by hand (it was not created by Cemí)".into(),
    });
    Ok(out)
}

/// How a step of a rotation went, so people see it marked as done or as
/// something that needs them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    Done,
    Attention,
}

/// Rotates `fr` for `env`, telling `progress` each step as it happens. The
/// caller has already checked approval.
pub fn rotate(
    ws: &mut Workspace,
    fr: &FieldRef,
    env: Option<&str>,
    opts: RotateOptions,
    actor: &str,
    progress: &mut dyn FnMut(Step, &str),
) -> Result<()> {
    let name = fr.text(ws);
    let f = fr.field(ws)?.clone();
    match f.kind {
        FieldKind::Template => {
            bail!("{name} is a template: it is rebuilt from its parts. Rotate the parts instead")
        }
        FieldKind::File => {
            bail!("{name} is a file; replace it with `cemi set --from-file`, then `cemi push`")
        }
        _ => {}
    }
    let slot = slot_key(ws, fr, env)?;
    let origin = f.origins.get(&slot).cloned();
    // 1. The new value, saved as pending before anything else.
    let existing = f.values.get(&slot).and_then(|s| s.pending_index());
    let pending = match existing {
        Some(i) => {
            progress(
                Step::Done,
                "Continuing an unfinished rotation with its pending value",
            );
            i
        }
        None => {
            let (value, provider_id, how) = match opts.new_value {
                NewValue::Origin => {
                    let Some(o) = &origin else {
                        let hint = fr
                            .memory(ws, memory_keys::ROTATE)
                            .map(|n| format!("\nYour note on how to rotate it: {n}"))
                            .unwrap_or_default();
                        bail!(
                            "{name} has no origin for {}, so Cemí cannot create the new key. Either \
                             set one (`cemi origin set`), let Cemí generate the value (--generate) \
                             when the service accepts any value, or type the new key (--paste).{hint}",
                            env_label(&slot)
                        );
                    };
                    let k = connectors::create(&o.spec, ws, slot_env(&slot))?;
                    (
                        k.value,
                        k.provider_id,
                        format!("created at {}", o.spec.describe()),
                    )
                }
                NewValue::Generate { length, charset } => {
                    if !(8..=4096).contains(&length) {
                        bail!("length must be between 8 and 4096");
                    }
                    (
                        Zeroizing::new(random_string(length, charset)),
                        None,
                        "generated by Cemí".to_string(),
                    )
                }
                NewValue::Given(v) => (v, None, "typed by a person".to_string()),
            };
            let fm = fr.field_mut(ws)?;
            let s = fm.values.entry(slot.clone()).or_default();
            s.versions.push(Version {
                value: Value::text(value.as_str()),
                state: VersionState::Pending,
                at: Timestamp::now(),
                actor: actor.to_string(),
                note: Some(format!(
                    "rotation{}: {how}",
                    if opts.leaked { " after a leak" } else { "" }
                )),
                provider_id,
            });
            let i = s.versions.len() - 1;
            save(ws, fr.scope)?;
            audit(
                ws,
                fr.scope,
                actor,
                "rotate.create",
                Some(name.clone()),
                Some(&slot),
                Some(how.clone()),
            );
            progress(Step::Done, &format!("New value {how} (saved as pending)"));
            i
        }
    };

    // 2. Make it current in memory and send it everywhere.
    let previous = {
        let s = fr
            .field_mut(ws)?
            .values
            .get_mut(&slot)
            .expect("has the pending value");
        let prev = s.active_index();
        s.activate(pending);
        prev
    };
    let dests = affected(ws, fr, &slot)?;
    let mut sent: Vec<DestRef> = Vec::new();
    let mut failure: Option<anyhow::Error> = None;
    for d in &dests {
        let label = destination(ws, d)
            .map(|x| x.spec.describe())
            .unwrap_or_default();
        match value_for(ws, d).and_then(|v| deliver(ws, d, &v)) {
            Ok(()) => {
                progress(Step::Done, &format!("Updated {label}"));
                sent.push(d.clone());
            }
            Err(e) => {
                failure = Some(anyhow!("updating {label}: {e:#}"));
                break;
            }
        }
    }

    // 3. Verify.
    if failure.is_none()
        && let Some(cmd) = f.verify.get(&slot)
    {
        let value = fr.field(ws)?.values[&slot].versions[pending].value.bytes();
        match connectors::verify(cmd, &value) {
            Ok(()) => progress(Step::Done, &format!("Verified with `{}`", cmd.join(" "))),
            Err(e) => failure = Some(anyhow!("verification failed: {e:#}")),
        }
    }

    if let Some(err) = failure {
        progress(Step::Attention, &format!("Problem: {err:#}"));
        let undo = Undo {
            fr,
            slot: &slot,
            pending,
            previous,
            sent: &sent,
            origin: origin.as_ref().map(|o| &o.spec),
        };
        let complete = undo.run(ws, progress);
        audit(
            ws,
            fr.scope,
            actor,
            "rotate.failed",
            Some(name.clone()),
            Some(&slot),
            Some(format!("{err:#}")),
        );
        if complete {
            bail!("the rotation of {name} failed and was undone: {err:#}");
        }
        bail!(
            "the rotation of {name} failed and could not be fully undone: {err:#}. The steps marked with ! say what is left"
        );
    }

    // 4. Confirm.
    fr.field_mut(ws)?
        .values
        .get_mut(&slot)
        .expect("exists")
        .external = None;
    save(ws, fr.scope)?;
    audit(
        ws,
        fr.scope,
        actor,
        "rotate",
        Some(name.clone()),
        Some(&slot),
        Some(format!("{} destination(s)", sent.len())),
    );
    progress(Step::Done, "The new value is now the active one");

    // 5. Revoke the old one.
    let Some(prev) = previous else {
        return Ok(());
    };
    let retry = format!("cemi revoke {name} {}{}", prev + 1, env_flag(&slot));
    if opts.keep_old {
        progress(
            Step::Attention,
            &format!("The old key is still valid. Revoke it later: {retry}"),
        );
        return Ok(());
    }
    match &origin {
        Some(o) => match revoke_version(ws, fr, &slot, prev, &o.spec, opts.leaked, actor) {
            Ok(Revoked::Done) => progress(
                Step::Done,
                &format!("Revoked the old key at {}", o.spec.describe()),
            ),
            Ok(Revoked::Manual(m)) => progress(Step::Attention, &format!("The old key: {m}")),
            Err(e) => progress(
                Step::Attention,
                &format!("Could not revoke the old key ({e:#}). Retry with: {retry}"),
            ),
        },
        None => {
            let key = if opts.leaked {
                memory_keys::IF_LEAKED
            } else {
                memory_keys::ROTATE
            };
            let hint = fr
                .memory(ws, key)
                .map(|n| format!(". Your note: {n}"))
                .unwrap_or_default();
            progress(
                Step::Attention,
                &format!(
                    "Revoke the old key at its provider by hand{}{hint}",
                    if opts.leaked { ", now: it leaked" } else { "" }
                ),
            );
        }
    }
    Ok(())
}

/// What to undo after a failed rotation.
struct Undo<'a> {
    fr: &'a FieldRef,
    slot: &'a str,
    pending: usize,
    previous: Option<usize>,
    sent: &'a [DestRef],
    origin: Option<&'a OriginSpec>,
}

impl Undo<'_> {
    /// Puts things back as they were. Returns false when something is left
    /// for a person to finish (each such step is reported as Attention).
    fn run(&self, ws: &mut Workspace, progress: &mut dyn FnMut(Step, &str)) -> bool {
        let mut complete = true;
        let mut say = |step: Step, s: &str| {
            if step == Step::Attention {
                complete = false;
            }
            progress(step, s);
        };
        let set_states = |ws: &mut Workspace| -> Result<()> {
            let s = self
                .fr
                .field_mut(ws)?
                .values
                .get_mut(self.slot)
                .expect("exists");
            if let Some(prev) = self.previous {
                s.activate(prev);
            }
            s.versions[self.pending].state = VersionState::Pending;
            Ok(())
        };
        if let Err(e) = set_states(ws) {
            say(
                Step::Attention,
                &format!("Could not restore the vault state: {e:#}"),
            );
            return false;
        }
        if self.previous.is_none() {
            let _ = save(ws, self.fr.scope);
            say(
                Step::Attention,
                "There was no previous value to restore; the new one stays pending",
            );
            return false;
        }
        for d in self.sent {
            let label = destination(ws, d)
                .map(|x| x.spec.describe())
                .unwrap_or_default();
            match value_for(ws, d).and_then(|v| deliver(ws, d, &v)) {
                Ok(()) => say(Step::Done, &format!("Put the old value back in {label}")),
                Err(e) => say(
                    Step::Attention,
                    &format!(
                        "Could NOT put the old value back in {label}: {e:#}. Run `cemi push` once it is fixed"
                    ),
                ),
            }
        }
        // The new key was never used: remove it at the provider.
        if let Some(origin) = self.origin {
            let (value, provider_id) = match self.fr.field(ws) {
                Ok(f) => {
                    let v = &f.values[self.slot].versions[self.pending];
                    (v.value.bytes(), v.provider_id.clone())
                }
                Err(e) => {
                    say(
                        Step::Attention,
                        &format!("Could not read the unused new key: {e:#}"),
                    );
                    return false;
                }
            };
            match connectors::revoke(
                origin,
                ws,
                slot_env(self.slot),
                provider_id.as_deref(),
                &value,
                false,
            ) {
                Ok(Revoked::Done) => {
                    if let Ok(f) = self.fr.field_mut(ws) {
                        f.values.get_mut(self.slot).expect("exists").versions[self.pending].state =
                            VersionState::Retired;
                    }
                    say(Step::Done, "Deleted the unused new key at the provider");
                }
                Ok(Revoked::Manual(m)) => say(Step::Attention, &format!("The unused new key: {m}")),
                Err(e) => say(
                    Step::Attention,
                    &format!(
                        "Could not delete the unused new key ({}); it stays pending. `cemi revoke --pending` removes it",
                        redact_error(e, &value)
                    ),
                ),
            }
        }
        if let Err(e) = save(ws, self.fr.scope) {
            say(Step::Attention, &format!("Could not save the vault: {e:#}"));
        }
        complete
    }
}

/// Revokes version `index` of a slot at its origin and marks it retired.
pub fn revoke_version(
    ws: &mut Workspace,
    fr: &FieldRef,
    slot: &str,
    index: usize,
    origin: &OriginSpec,
    compromised: bool,
    actor: &str,
) -> Result<Revoked> {
    let (value, provider_id, state) = {
        let f = fr.field(ws)?;
        let v = f
            .values
            .get(slot)
            .and_then(|s| s.versions.get(index))
            .ok_or_else(|| anyhow!("there is no version {}", index + 1))?;
        (v.value.bytes(), v.provider_id.clone(), v.state)
    };
    match state {
        VersionState::Active => bail!("version {} is the active one; rotate first", index + 1),
        VersionState::Retired => bail!("version {} is already revoked", index + 1),
        VersionState::Pending | VersionState::Archived => {}
    }
    let out = connectors::revoke(
        origin,
        ws,
        slot_env(slot),
        provider_id.as_deref(),
        &value,
        compromised,
    )
    .map_err(|e| redact_error(e, &value))?;
    if matches!(out, Revoked::Done) {
        fr.field_mut(ws)?
            .values
            .get_mut(slot)
            .expect("exists")
            .versions[index]
            .state = VersionState::Retired;
        save(ws, fr.scope)?;
        let name = fr.text(ws);
        audit(
            ws,
            fr.scope,
            actor,
            "revoke",
            Some(name),
            Some(slot),
            Some(format!(
                "version {}{}",
                index + 1,
                if compromised { " (leaked)" } else { "" }
            )),
        );
    }
    Ok(out)
}

// ----- attention -----

/// What needs doing about destinations, rotations and approvals in one vault
/// (no network). `only` limits it to some entity ids.
pub fn attention(
    ws: &mut Workspace,
    scope: Scope,
    only: Option<&[String]>,
) -> Vec<crate::cmd_shared::Attention> {
    use crate::cmd_shared::Attention;
    let mut out = Vec::new();
    let Ok(v) = ws.open(scope) else {
        return out;
    };
    let mut fields: Vec<FieldRef> = Vec::new();
    for rec in v.records.values().filter(|r| !r.archived) {
        if only.is_some_and(|o| !o.contains(&rec.entity)) {
            continue;
        }
        for f in &rec.fields {
            let interesting = !f.destinations.is_empty()
                || !f.origins.is_empty()
                || f.values.values().any(|s| s.pending_index().is_some());
            if interesting {
                fields.push(FieldRef {
                    scope,
                    record_id: rec.id.clone(),
                    field: f.name.clone(),
                });
            }
        }
    }
    if only.is_none() {
        let now = Timestamp::now();
        for a in v.approvals.values().filter(|a| a.expires > now) {
            out.push(Attention {
                what: format!("approval {}", a.id),
                detail: format!(
                    "{} asks to {}: `cemi approve {}`",
                    a.requested_by, a.action, a.id
                ),
            });
        }
    }
    for fr in fields {
        let name = fr.text(ws);
        let Ok(f) = fr.field(ws).cloned() else {
            continue;
        };
        for (slot, s) in &f.values {
            if s.pending_index().is_some() {
                out.push(Attention {
                    what: format!("{name} ({})", env_label(slot)),
                    detail: format!(
                        "a rotation did not finish: `cemi rotate {name}{}` continues it, `cemi revoke {name}{} --pending` discards the new value",
                        env_flag(slot),
                        env_flag(slot)
                    ),
                });
            }
            if let Some(o) = f.origins.get(slot) {
                for (i, ver) in s.versions.iter().enumerate() {
                    if ver.state == VersionState::Archived && ver.provider_id.is_some() {
                        out.push(Attention {
                            what: format!("{name} ({})", env_label(slot)),
                            detail: format!(
                                "the old key v{} is still valid at {}: `cemi revoke {name} {}{}`",
                                i + 1,
                                o.spec.describe(),
                                i + 1,
                                env_flag(slot)
                            ),
                        });
                    }
                }
            }
        }
        for d in &f.destinations {
            let line = check_one(
                ws,
                &DestRef {
                    field: fr.clone(),
                    id: d.id.clone(),
                },
                false,
            );
            if !line.status.is_ok() {
                out.push(Attention {
                    what: format!("{name} ({})", line.env),
                    detail: format!("{}: {}", line.describe, line.status.label()),
                });
            }
        }
    }
    out
}
