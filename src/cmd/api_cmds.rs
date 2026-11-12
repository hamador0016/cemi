//! `cemi api`: the HTTP APIs a key signs in to, for Cemí's proxy.

use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use serde_json::{Value as Json, json};

use super::Ctx;
use crate::cli::ApiCmd;
use crate::crypto;
use crate::model::{Api, ApiAuth, SHARED};
use crate::proxy::{self, Rule};
use crate::refs::Ref;
use crate::rotation::{self, FieldRef, env_label};
use crate::ui;

fn field_ref(ctx: &mut Ctx, reference: &str) -> Result<(Ref, FieldRef)> {
    let r = ctx.parse_ref(reference)?;
    let fr = FieldRef::find(&mut ctx.ws, &r)?;
    let full = fr.to_ref(&mut ctx.ws)?;
    Ok((full, fr))
}

pub fn api(ctx: &mut Ctx, cmd: ApiCmd) -> Result<i32> {
    match cmd {
        ApiCmd::Add {
            reference,
            env,
            base,
            auth,
            allow,
        } => add(ctx, &reference, env.as_deref(), &base, &auth, &allow),
        ApiCmd::Ls { reference } => ls(ctx, reference.as_deref()),
        ApiCmd::Rm { reference, id } => rm(ctx, &reference, &id),
        ApiCmd::Call {
            reference,
            env,
            method,
            path,
            data,
            header,
        } => call(
            ctx,
            &reference,
            env.as_deref(),
            &method,
            &path,
            data,
            &header,
        ),
    }
}

fn add(
    ctx: &mut Ctx,
    reference: &str,
    env: Option<&str>,
    base: &str,
    auth: &[String],
    allow: &[String],
) -> Result<i32> {
    let (r, fr) = field_ref(ctx, reference)?;
    super::values::check_env(ctx, fr.scope, &fr.record_id, env)?;
    let base = proxy::check_base(base)?;
    let auth = auth
        .iter()
        .map(|a| a.parse::<ApiAuth>())
        .collect::<Result<Vec<_>>>()?;
    for rule in allow {
        Rule::parse(rule)?;
    }
    let field = fr.field(&mut ctx.ws)?;
    if !field.secret {
        ui::warn(format!(
            "{r} is not marked secret; the proxy is for keys (cemi field edit {r} --secret true)"
        ));
    }
    let env_key = env.unwrap_or(SHARED).to_string();
    // The address decides where the key goes, so protected environments
    // need the password, like any change there.
    let protected = rotation::needs_approval(&mut ctx.ws, Some(&env_key), &[]);
    if !protected.is_empty() {
        super::reauthenticate(
            ctx,
            fr.scope,
            &format!("This sends the {} key to {base}", protected.join(", ")),
        )?;
    }
    let field = fr.field_mut(&mut ctx.ws)?;
    if field.apis.iter().any(|a| a.env == env_key) {
        bail!(
            "{r} already has an API for {}: remove it first with `cemi api rm` (see `cemi api ls {r}`)",
            env_label(&env_key)
        );
    }
    let id = loop {
        let id = crypto::new_id()[..6].to_string();
        if !field.apis.iter().any(|a| a.id == id) {
            break id;
        }
    };
    field.apis.push(Api {
        id: id.clone(),
        env: env_key.clone(),
        base: base.clone(),
        auth: auth.clone(),
        allow: allow.to_vec(),
        created: Timestamp::now(),
    });
    ctx.ws.open(fr.scope)?.save()?;
    ctx.audit_detail(
        fr.scope,
        "api.add",
        Some(r.to_string()),
        env,
        Some(format!("{base} allow {}", allow.join(", "))),
    );
    ui::ok(format!(
        "{r} ({}) signs in to {base} through the proxy  [id {id}]. Allowed: {}",
        env_label(&env_key),
        allow.join(", ")
    ));
    Ok(0)
}

fn api_json(field: &str, a: &Api) -> Json {
    json!({
        "field": field,
        "id": a.id,
        "env": a.env_opt(),
        "base": a.base,
        "auth": a.auth.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
        "allow": a.allow,
        "created": a.created.to_string(),
    })
}

fn ls(ctx: &mut Ctx, reference: Option<&str>) -> Result<i32> {
    let mut rows: Vec<(String, Api)> = Vec::new();
    match reference {
        Some(t) => {
            let (r, fr) = field_ref(ctx, t)?;
            for a in &fr.field(&mut ctx.ws)?.apis {
                rows.push((r.to_string(), a.clone()));
            }
        }
        None => {
            let scope = ctx.scope()?;
            let v = ctx.ws.open(scope)?;
            let mut recs: Vec<_> = v.records.values().filter(|r| !r.archived).collect();
            recs.sort_by_key(|r| (v.entity_path(&r.entity), r.name.clone()));
            for rec in recs {
                for f in &rec.fields {
                    for a in &f.apis {
                        let mut path = v.entity_path(&rec.entity);
                        path.push(rec.name.clone());
                        rows.push((format!("{}#{}", path.join("/"), f.name), a.clone()));
                    }
                }
            }
        }
    }
    ui::data(json!({
        "apis": rows.iter().map(|(f, a)| api_json(f, a)).collect::<Vec<_>>()
    }));
    if rows.is_empty() {
        crate::outln!(
            "No APIs. Add one with `cemi api add <record#field> --base https://… --allow \"GET /…\"`."
        );
        return Ok(0);
    }
    for (f, a) in &rows {
        crate::outln!(
            "{f} ({})  [{}]\n  {}  auth: {}\n  allow: {}",
            env_label(&a.env),
            a.id,
            a.base,
            a.auth
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            a.allow.join(", ")
        );
    }
    Ok(0)
}

fn rm(ctx: &mut Ctx, reference: &str, id: &str) -> Result<i32> {
    let (r, fr) = field_ref(ctx, reference)?;
    let field = fr.field_mut(&mut ctx.ws)?;
    let Some(i) = field.apis.iter().position(|a| a.id == id) else {
        return Err(crate::errors::not_found(format!(
            "{r} has no API {id}; see `cemi api ls {r}`"
        )));
    };
    let gone = field.apis.remove(i);
    ctx.ws.open(fr.scope)?.save()?;
    ctx.audit_detail(
        fr.scope,
        "api.rm",
        Some(r.to_string()),
        gone.env_opt(),
        Some(gone.base.clone()),
    );
    ui::ok(format!(
        "{r} no longer signs in to {} through the proxy",
        gone.base
    ));
    Ok(0)
}

fn call(
    ctx: &mut Ctx,
    reference: &str,
    env: Option<&str>,
    method: &str,
    path: &str,
    data: Option<String>,
    headers: &[String],
) -> Result<i32> {
    let (r, fr) = field_ref(ctx, reference)?;
    let up = proxy::upstream_for(&mut ctx.ws, &fr, env)?;
    let mut hs = Vec::new();
    for h in headers {
        let (k, v) = h
            .split_once(':')
            .with_context(|| format!("--header must look like NAME:VALUE, got {h:?}"))?;
        hs.push((k.trim().to_string(), v.trim().to_string()));
    }
    let body = match data {
        Some(d) => match d.strip_prefix('@') {
            Some(file) => std::fs::read(file).with_context(|| format!("cannot read {file}"))?,
            None => d.into_bytes(),
        },
        None => Vec::new(),
    };
    if !body.is_empty()
        && !hs
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        hs.push(("content-type".into(), "application/json".into()));
    }
    let result = up.forward(method, path, &hs, body);
    let detail = |s: &str| {
        format!(
            "{} {} → {s}",
            method.to_ascii_uppercase(),
            path.split('?').next().unwrap_or("")
        )
    };
    match &result {
        Ok(reply) => ctx.audit_detail(
            fr.scope,
            "api.call",
            Some(r.to_string()),
            env,
            Some(detail(&reply.status.to_string())),
        ),
        Err(_) => ctx.audit_detail(
            fr.scope,
            "api.call",
            Some(r.to_string()),
            env,
            Some(detail("failed")),
        ),
    }
    let reply = result?;
    ui::data(json!({
        "status": reply.status,
        "headers": reply.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "body": String::from_utf8_lossy(&reply.body),
    }));
    eprintln!("HTTP {}", reply.status);
    crate::out!("{}", String::from_utf8_lossy(&reply.body));
    Ok(if (200..400).contains(&reply.status) {
        0
    } else {
        1
    })
}
