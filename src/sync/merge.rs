//! Merging two copies of one vault object that two computers changed.
//!
//! Nothing a person typed is lost: every version of every value is kept
//! (each slot ends with one active version, the newest), fields, notes,
//! destinations and APIs are merged one by one, and where both sides changed
//! the same setting the copy changed last wins. Something deleted on one side
//! and edited on the other is kept.

use std::collections::BTreeMap;

use serde::Serialize;
use zeroize::Zeroizing;

use crate::crypto;
use crate::model::{Entity, Field, Object, Record, Slot, Version, VersionState};

/// True when both serialize to the same bytes (compared in constant time,
/// since they may hold secrets).
pub fn same<T: Serialize>(a: &T, b: &T) -> bool {
    let x = Zeroizing::new(serde_json::to_vec(a).unwrap_or_default());
    let y = Zeroizing::new(serde_json::to_vec(b).unwrap_or_default());
    crypto::ct_eq(&x, &y)
}

/// Three-way merge of keyed items: added on either side is kept, deleted on
/// one side is dropped only if the other side did not change it, and items
/// on both sides go through `both`.
fn merge_keyed<V: Serialize + Clone>(
    base: Option<&BTreeMap<String, V>>,
    ours: &BTreeMap<String, V>,
    theirs: &BTreeMap<String, V>,
    both: impl Fn(Option<&V>, &V, &V) -> V,
) -> BTreeMap<String, V> {
    let mut out = BTreeMap::new();
    let keys: std::collections::BTreeSet<&String> = ours.keys().chain(theirs.keys()).collect();
    for k in keys {
        let b = base.and_then(|m| m.get(k));
        match (ours.get(k), theirs.get(k)) {
            (Some(o), Some(t)) => {
                out.insert(k.clone(), both(b, o, t));
            }
            (Some(only), None) | (None, Some(only)) => match b {
                // The other side deleted it; keep it only if this side changed it.
                Some(b) if same(b, only) => {}
                _ => {
                    out.insert(k.clone(), only.clone());
                }
            },
            (None, None) => {}
        }
    }
    out
}

fn pick<V: Clone>(prefer_theirs: bool, o: &V, t: &V) -> V {
    if prefer_theirs { t.clone() } else { o.clone() }
}

fn rank(s: VersionState) -> u8 {
    match s {
        VersionState::Pending => 0,
        VersionState::Active => 1,
        VersionState::Archived => 2,
        VersionState::Retired => 3,
    }
}

/// Every version of both sides, once each, with one active version: the newest.
pub fn merge_slot(o: &Slot, t: &Slot) -> Slot {
    let mut versions: Vec<Version> = Vec::new();
    for v in o.versions.iter().chain(t.versions.iter()) {
        match versions
            .iter_mut()
            .find(|x| x.at == v.at && same(&x.value, &v.value))
        {
            Some(x) => {
                if rank(v.state) > rank(x.state) {
                    x.state = v.state;
                }
                if x.provider_id.is_none() {
                    x.provider_id = v.provider_id.clone();
                }
            }
            None => versions.push(v.clone()),
        }
    }
    versions.sort_by_key(|v| v.at);
    if let Some(newest) = versions
        .iter()
        .rposition(|v| v.state == VersionState::Active)
    {
        for (i, v) in versions.iter_mut().enumerate() {
            if i != newest && v.state == VersionState::Active {
                v.state = VersionState::Archived;
            }
        }
    }
    let has_active = versions.iter().any(|v| v.state == VersionState::Active);
    Slot {
        versions,
        external: if has_active {
            None
        } else {
            o.external.clone().or_else(|| t.external.clone())
        },
    }
}

fn by_id<V: Clone>(items: &[V], id: impl Fn(&V) -> &str) -> BTreeMap<String, V> {
    items
        .iter()
        .map(|x| (id(x).to_string(), x.clone()))
        .collect()
}

/// A yes/no setting both sides may have changed: a side that changed it
/// from the base wins; if both did, `prefer_theirs` decides.
fn merge_flag(base: Option<bool>, o: bool, t: bool, prefer_theirs: bool) -> bool {
    match base {
        Some(b) if o == b => t,
        Some(b) if t == b => o,
        Some(_) => pick(prefer_theirs, &o, &t),
        // No common copy: the safer choice.
        None => o || t,
    }
}

fn merge_field(base: Option<&Field>, o: &Field, t: &Field, prefer_theirs: bool) -> Field {
    let mut f = pick(prefer_theirs, o, t);
    f.secret = merge_flag(base.map(|b| b.secret), o.secret, t.secret, prefer_theirs);
    f.values = merge_keyed(base.map(|b| &b.values), &o.values, &t.values, |_, a, b| {
        merge_slot(a, b)
    });
    f.origins = merge_keyed(
        base.map(|b| &b.origins),
        &o.origins,
        &t.origins,
        |_, a, b| pick(prefer_theirs, a, b),
    );
    f.verify = merge_keyed(base.map(|b| &b.verify), &o.verify, &t.verify, |_, a, b| {
        pick(prefer_theirs, a, b)
    });
    let dest_base = base.map(|b| by_id(&b.destinations, |d| &d.id));
    let mut dests: Vec<_> = merge_keyed(
        dest_base.as_ref(),
        &by_id(&o.destinations, |d| &d.id),
        &by_id(&t.destinations, |d| &d.id),
        |_, a, b| {
            // The copy that delivered last knows the destination's state.
            let at = |d: &crate::model::Destination| d.last.as_ref().map(|l| l.at);
            if at(b) > at(a) { b.clone() } else { a.clone() }
        },
    )
    .into_values()
    .collect();
    dests.sort_by_key(|d| d.created);
    f.destinations = dests;
    let api_base = base.map(|b| by_id(&b.apis, |a| &a.id));
    let mut apis: Vec<_> = merge_keyed(
        api_base.as_ref(),
        &by_id(&o.apis, |a| &a.id),
        &by_id(&t.apis, |a| &a.id),
        |_, a, b| pick(prefer_theirs, a, b),
    )
    .into_values()
    .collect();
    apis.sort_by_key(|a| a.created);
    f.apis = apis;
    f
}

pub fn merge_record(base: Option<&Record>, o: &Record, t: &Record) -> Record {
    let prefer_theirs = t.updated > o.updated;
    let mut r = pick(prefer_theirs, o, t);
    r.updated = o.updated.max(t.updated);
    r.memory = merge_keyed(base.map(|b| &b.memory), &o.memory, &t.memory, |_, a, b| {
        pick(prefer_theirs, a, b)
    });
    let to_map = |fields: &[Field]| -> BTreeMap<String, Field> {
        fields.iter().map(|f| (f.name.clone(), f.clone())).collect()
    };
    let base_fields = base.map(|b| to_map(&b.fields));
    let merged = merge_keyed(
        base_fields.as_ref(),
        &to_map(&o.fields),
        &to_map(&t.fields),
        |b, a, c| merge_field(b, a, c, prefer_theirs),
    );
    // Keep the order of the preferred side, then anything new from the other.
    let order: Vec<String> = r
        .fields
        .iter()
        .map(|f| f.name.clone())
        .chain(
            o.fields
                .iter()
                .chain(t.fields.iter())
                .map(|f| f.name.clone()),
        )
        .collect();
    let mut fields = Vec::new();
    for name in order {
        if !fields.iter().any(|f: &Field| f.name == name)
            && let Some(f) = merged.get(&name)
        {
            fields.push(f.clone());
        }
    }
    r.fields = fields;
    r
}

fn merge_entity(base: Option<&Entity>, o: &Entity, t: &Entity) -> Entity {
    let prefer_theirs = t.updated > o.updated;
    let mut e = pick(prefer_theirs, o, t);
    // The key never changes; if it did, the copy that opens existing records wins.
    e.identity = o.identity.clone();
    e.parent = o.parent.clone();
    e.updated = o.updated.max(t.updated);
    for env in o.envs.iter().chain(t.envs.iter()) {
        if !e.envs.contains(env) {
            e.envs.push(env.clone());
        }
    }
    e.memory = merge_keyed(base.map(|b| &b.memory), &o.memory, &t.memory, |_, a, b| {
        pick(prefer_theirs, a, b)
    });
    e.protected = merge_protected(base, o, t);
    e.approve_with = match base.map(|b| b.approve_with) {
        Some(b) if o.approve_with == b => t.approve_with,
        Some(b) if t.approve_with == b => o.approve_with,
        _ => pick(prefer_theirs, &o.approve_with, &t.approve_with),
    };
    e
}

/// Protected environments: one protected on either side stays protected;
/// one stops being protected only if a side removed it from the base list
/// (with the password, on that computer) and the other did not add it back.
fn merge_protected(base: Option<&Entity>, o: &Entity, t: &Entity) -> Option<Vec<String>> {
    if o.protected.is_none() && t.protected.is_none() {
        return None;
    }
    let list = |e: &Entity| -> Vec<String> {
        match &e.protected {
            Some(l) => l.clone(),
            None => crate::model::DEFAULT_PROTECTED
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    };
    let (lo, lt) = (list(o), list(t));
    let lb = base.map(list);
    let mut out: Vec<String> = Vec::new();
    for env in lo.iter().chain(lt.iter()) {
        if out.contains(env) {
            continue;
        }
        let removed_by = |side: &Vec<String>| {
            lb.as_ref().is_some_and(|b| b.contains(env)) && !side.contains(env)
        };
        if removed_by(&lo) || removed_by(&lt) {
            continue;
        }
        out.push(env.clone());
    }
    Some(out)
}

/// Two entities that are the same one created on two computers (same parent
/// and name, different ids): `keep`'s id and key stay; envs, notes and
/// protection are joined.
pub fn merge_entity_copies(keep: &Entity, other: &Entity) -> Entity {
    let mut e = keep.clone();
    for env in &other.envs {
        if !e.envs.contains(env) {
            e.envs.push(env.clone());
        }
    }
    for (k, v) in &other.memory {
        e.memory.entry(k.clone()).or_insert_with(|| v.clone());
    }
    if let Some(p) = &other.protected {
        let mut list = e.protected.clone().unwrap_or_default();
        for env in p {
            if !list.contains(env) {
                list.push(env.clone());
            }
        }
        e.protected = Some(list);
    }
    e.updated = keep.updated.max(other.updated);
    e
}

/// Merges two changed copies of one object (`base` is the copy both started from).
pub fn merge_object(base: Option<&Object>, ours: &Object, theirs: &Object) -> Object {
    match (ours, theirs) {
        (Object::Record(o), Object::Record(t)) => {
            let b = match base {
                Some(Object::Record(b)) => Some(b),
                _ => None,
            };
            Object::Record(merge_record(b, o, t))
        }
        (Object::Entity(o), Object::Entity(t)) => {
            let b = match base {
                Some(Object::Entity(b)) => Some(b),
                _ => None,
            };
            Object::Entity(merge_entity(b, o, t))
        }
        (Object::Token(o), Object::Token(t)) => {
            // A revocation on either computer stands.
            let mut tok = o.clone();
            tok.revoked = match (o.revoked, t.revoked) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            Object::Token(tok)
        }
        (Object::Share(o), Object::Share(t)) => {
            Object::Share(if t.at > o.at { t.clone() } else { o.clone() })
        }
        // Launchers and requests: whichever side changed it from the base.
        _ => match base {
            Some(b) if same(b, ours) => theirs.clone(),
            _ => ours.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldKind, SHARED, Value};
    use jiff::Timestamp;

    fn version(text: &str, at: i64, state: VersionState) -> Version {
        Version {
            value: Value::text(text),
            state,
            at: Timestamp::from_second(at).unwrap(),
            actor: "t".into(),
            note: None,
            provider_id: None,
        }
    }

    fn text(v: &Version) -> String {
        match &v.value {
            Value::Text { text } => text.expose().to_string(),
            _ => panic!(),
        }
    }

    #[test]
    fn both_new_versions_are_kept_and_the_newest_is_active() {
        let base = version("one", 10, VersionState::Active);
        let mut archived = base.clone();
        archived.state = VersionState::Archived;
        let o = Slot {
            versions: vec![archived.clone(), version("two", 20, VersionState::Active)],
            external: None,
        };
        let t = Slot {
            versions: vec![archived, version("three", 30, VersionState::Active)],
            external: None,
        };
        let m = merge_slot(&o, &t);
        let texts: Vec<String> = m.versions.iter().map(text).collect();
        assert_eq!(texts, vec!["one", "two", "three"]);
        assert_eq!(text(m.current_version().unwrap()), "three");
        assert_eq!(
            m.versions
                .iter()
                .filter(|v| v.state == VersionState::Active)
                .count(),
            1
        );
    }

    #[test]
    fn a_retirement_on_either_side_stands() {
        let o = Slot {
            versions: vec![version("one", 10, VersionState::Active)],
            external: None,
        };
        let t = Slot {
            versions: vec![
                version("one", 10, VersionState::Retired),
                version("two", 20, VersionState::Active),
            ],
            external: None,
        };
        let m = merge_slot(&o, &t);
        assert_eq!(m.versions[0].state, VersionState::Retired);
        assert_eq!(text(m.current_version().unwrap()), "two");
    }

    fn record(updated: i64, fields: Vec<Field>) -> Record {
        Record {
            id: "r".into(),
            entity: "e".into(),
            name: "db".into(),
            fields,
            memory: BTreeMap::new(),
            archived: false,
            received: None,
            created: Timestamp::from_second(1).unwrap(),
            updated: Timestamp::from_second(updated).unwrap(),
        }
    }

    #[test]
    fn fields_added_on_each_side_and_deletions_are_merged() {
        let a = Field::new("a", FieldKind::Text, true);
        let gone = Field::new("gone", FieldKind::Text, false);
        let base = record(5, vec![a.clone(), gone.clone()]);
        // Ours deleted `gone` and added `b`; theirs added `c` and set `a`.
        let ours = record(6, vec![a.clone(), Field::new("b", FieldKind::Text, true)]);
        let mut a2 = a.clone();
        a2.values
            .entry(SHARED.into())
            .or_default()
            .push(Value::text("x"), "t", None);
        let theirs = record(7, vec![a2, gone, Field::new("c", FieldKind::Url, false)]);
        let m = merge_record(Some(&base), &ours, &theirs);
        let names: Vec<&str> = m.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["a", "c", "b"]);
        assert!(m.field("a").unwrap().current(None).is_some());
    }

    #[test]
    fn an_edit_wins_over_a_deletion() {
        let base = record(5, vec![Field::new("k", FieldKind::Text, false)]);
        let ours = record(6, vec![]);
        let mut k = Field::new("k", FieldKind::Text, false);
        k.secret = true;
        let theirs = record(7, vec![k]);
        let m = merge_record(Some(&base), &ours, &theirs);
        assert!(m.field("k").unwrap().secret);
    }
}
