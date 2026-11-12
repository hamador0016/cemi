//! Credential proxy. A caller (an AI client, or a program started by
//! `cemi run --proxy`) asks for an API call; Cemí adds the key and forwards
//! the request to the API's own address, only for the methods and paths the
//! person allowed. The caller never holds the key, so it cannot leak it.
//!
//! An API is set up from the terminal (`cemi api add`), never by an AI: its
//! address decides where the key goes. Requests are not redirected, and
//! answers have the key hidden in case the API echoes it.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::BASE64;
use zeroize::Zeroizing;

use crate::model::{Api, ApiAuth, Field, SHARED};
use crate::project::Project;
use crate::resolve;
use crate::rotation::{FieldRef, env_label};
use crate::runner::{Plan, Redactor};
use crate::workspace::Workspace;

/// Largest request or answer body the proxy carries.
pub const MAX_BODY: u64 = 10 * 1024 * 1024;

const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// One allowed method and path pattern, like `GET /v1/charges/*`.
/// `*` matches within one path segment; `**` matches any number of segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    method: String,
    segments: Vec<String>,
}

impl Rule {
    pub fn parse(text: &str) -> Result<Rule> {
        let (method, path) = text
            .trim()
            .split_once(' ')
            .ok_or_else(|| anyhow!("a rule looks like \"GET /v1/*\", got {text:?}"))?;
        let method = method.trim().to_ascii_uppercase();
        if method != "*" && !METHODS.contains(&method.as_str()) {
            bail!(
                "unknown method {method:?} in {text:?} (use one of {} or *)",
                METHODS.join(", ")
            );
        }
        let path = path.trim();
        let (segments, _) = split_path(path).with_context(|| format!("in the rule {text:?}"))?;
        Ok(Rule { method, segments })
    }

    pub fn matches(&self, method: &str, segments: &[String]) -> bool {
        (self.method == "*" || self.method == method) && match_segments(&self.segments, segments)
    }
}

fn match_segments(pattern: &[String], path: &[String]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((p, rest)) if p == "**" => {
            (0..=path.len()).any(|skip| match_segments(rest, &path[skip..]))
        }
        Some((p, rest)) => match path.split_first() {
            Some((s, path_rest)) => glob(p, s) && match_segments(rest, path_rest),
            None => false,
        },
    }
}

/// `*` matches any run of characters (within one segment).
fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut rest = text;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            match rest.strip_prefix(part) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(at) => rest = &rest[at + part.len()..],
                None => return false,
            }
        }
    }
    true
}

/// Splits `/a/b?q=1` into checked segments and the query. Anything that could
/// make the API's server read another path (dot segments, encoded slashes,
/// backslashes) is refused rather than cleaned up.
pub fn split_path(path_and_query: &str) -> Result<(Vec<String>, Option<String>)> {
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q.to_string())),
        None => (path_and_query, None),
    };
    if !path.starts_with('/') {
        bail!("the path must start with /, got {path:?}");
    }
    if path_and_query
        .chars()
        .any(|c| c.is_control() || c == ' ' || c == '\\' || c == '#')
    {
        bail!("the path has spaces, backslashes, # or control characters: {path_and_query:?}");
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00") {
        bail!("the path has an encoded slash, backslash or NUL: {path:?}");
    }
    let raw: Vec<&str> = path[1..].split('/').collect();
    let mut segments = Vec::new();
    for (i, s) in raw.iter().enumerate() {
        let decoded_dots = s.to_ascii_lowercase().replace("%2e", ".");
        if decoded_dots == "." || decoded_dots == ".." {
            bail!("the path has . or .. segments: {path:?}");
        }
        if s.is_empty() && i + 1 != raw.len() {
            bail!("the path has an empty segment (//): {path:?}");
        }
        segments.push(s.to_string());
    }
    if segments.last().is_some_and(String::is_empty) && segments.len() == 1 {
        segments.clear();
    }
    Ok((segments, query))
}

/// Checks the address of an API before it is saved.
pub fn check_base(base: &str) -> Result<String> {
    crate::connectors::check_url(base)?;
    let after_scheme = base.split_once("://").map(|x| x.1).unwrap_or("");
    let authority = after_scheme.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        bail!("{base} needs a host and no user name in it");
    }
    if base.contains(['?', '#', ' ', '\\']) {
        bail!("{base} cannot have a query (?), a fragment (#), spaces or backslashes");
    }
    Ok(base.trim_end_matches('/').to_string())
}

/// The API of a field for an environment: its own, or the shared one.
pub fn api_for<'a>(field: &'a Field, env: Option<&str>) -> Option<&'a Api> {
    if let Some(e) = env
        && let Some(a) = field.apis.iter().find(|a| a.env == e)
    {
        return Some(a);
    }
    field.apis.iter().find(|a| a.env == SHARED)
}

/// An API with its key, ready to forward requests.
pub struct Upstream {
    /// For messages and the audit log, like `acme/shop/stripe#secret (prod)`.
    pub label: String,
    pub base: String,
    pub auth: Vec<ApiAuth>,
    pub rules: Vec<Rule>,
    pub allow: Vec<String>,
    value: Zeroizing<String>,
    redactor: Redactor,
}

impl Upstream {
    pub fn new(label: String, api: &Api, value: Zeroizing<String>) -> Result<Upstream> {
        let rules = api
            .allow
            .iter()
            .map(|r| Rule::parse(r))
            .collect::<Result<Vec<_>>>()?;
        let redactor =
            Redactor::new(&[("key".to_string(), Zeroizing::new(value.as_bytes().to_vec()))]);
        Ok(Upstream {
            label,
            base: api.base.clone(),
            auth: api.auth.clone(),
            rules,
            allow: api.allow.clone(),
            value,
            redactor,
        })
    }

    /// Whether the rules allow this call; the error says what is allowed.
    pub fn check(&self, method: &str, path_and_query: &str) -> Result<()> {
        let method = method.to_ascii_uppercase();
        if !METHODS.contains(&method.as_str()) {
            bail!("unknown method {method:?}");
        }
        let (segments, _) = split_path(path_and_query)?;
        if self.rules.iter().any(|r| r.matches(&method, &segments)) {
            return Ok(());
        }
        Err(anyhow!(
            "{method} {} is not allowed for {}. Allowed: {}. The human changes this with `cemi api add` in a terminal",
            path_and_query.split('?').next().unwrap_or(""),
            self.label,
            if self.allow.is_empty() {
                "nothing".to_string()
            } else {
                self.allow.join(", ")
            }
        ))
    }

    /// Hides the key in text that goes back to the caller.
    pub fn redact(&self, bytes: &[u8]) -> Vec<u8> {
        self.redactor.redact(bytes)
    }

    /// Sends one request to the API with the key added.
    pub fn forward(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<Reply> {
        let method = method.to_ascii_uppercase();
        self.check(&method, path_and_query)?;
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path_and_query, None),
        };
        let managed: Vec<String> = self
            .auth
            .iter()
            .filter_map(|a| match a {
                ApiAuth::Header { name } => Some(name.to_ascii_lowercase()),
                ApiAuth::Bearer | ApiAuth::Basic => Some("authorization".into()),
                ApiAuth::Query { .. } => None,
            })
            .collect();
        // The caller's own copy of a query key (a placeholder) is replaced.
        let mut params: Vec<String> = query
            .unwrap_or("")
            .split('&')
            .filter(|p| !p.is_empty())
            .filter(|p| {
                let name = p.split('=').next().unwrap_or("");
                !self
                    .auth
                    .iter()
                    .any(|a| matches!(a, ApiAuth::Query { name: n } if n == name))
            })
            .map(str::to_string)
            .collect();
        for a in &self.auth {
            if let ApiAuth::Query { name } = a {
                params.push(format!(
                    "{name}={}",
                    crate::connectors::query_escape(&self.value)
                ));
            }
        }
        let mut url = Zeroizing::new(format!("{}{path}", self.base));
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        let mut builder = ureq::http::Request::builder()
            .method(method.as_str())
            .uri(url.as_str());
        for (k, v) in headers {
            let lower = k.to_ascii_lowercase();
            if HOP_BY_HOP.contains(&lower.as_str())
                || lower == "host"
                || lower == "content-length"
                || lower == "accept-encoding"
                || lower == "cookie"
                || lower == "authorization"
                || managed.contains(&lower)
            {
                continue;
            }
            builder = builder.header(k.as_str(), v.as_str());
        }
        for a in &self.auth {
            builder = match a {
                ApiAuth::Bearer => {
                    builder.header("authorization", format!("Bearer {}", self.value.as_str()))
                }
                ApiAuth::Header { name } => builder.header(name.as_str(), self.value.as_str()),
                ApiAuth::Basic => builder.header(
                    "authorization",
                    format!(
                        "Basic {}",
                        BASE64.encode(format!("{}:", self.value.as_str()).as_bytes())
                    ),
                ),
                ApiAuth::Query { .. } => builder,
            };
        }
        let req = builder.body(body).context("bad request")?;
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(concat!("cemi-proxy/", env!("CARGO_PKG_VERSION")))
            .build();
        let agent = ureq::Agent::new_with_config(config);
        let host = self
            .base
            .split('/')
            .nth(2)
            .unwrap_or(&self.base)
            .to_string();
        let mut resp = agent.run(req).map_err(|e| {
            let msg = String::from_utf8_lossy(&self.redact(e.to_string().as_bytes())).into_owned();
            crate::errors::external(format!("cannot reach {host}: {msg}"))
        })?;
        let status = resp.status().as_u16();
        let mut out_headers = Vec::new();
        for (k, v) in resp.headers() {
            let name = k.as_str().to_ascii_lowercase();
            if HOP_BY_HOP.contains(&name.as_str()) || name == "content-length" {
                continue;
            }
            let value = String::from_utf8_lossy(&self.redact(v.as_bytes())).into_owned();
            out_headers.push((name, value));
        }
        let body = if method == "HEAD" {
            Vec::new()
        } else {
            resp.body_mut()
                .with_config()
                .limit(MAX_BODY)
                .read_to_vec()
                .with_context(|| format!("cannot read the answer from {host}"))?
        };
        Ok(Reply {
            status,
            headers: out_headers,
            body: self.redact(&body),
        })
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// With the key hidden.
    pub body: Vec<u8>,
}

impl Reply {
    /// A short text for an AI client: status, the useful headers and the body.
    pub fn summary(&self, max: usize) -> String {
        let mut s = format!("HTTP {}\n", self.status);
        for (k, v) in &self.headers {
            if matches!(
                k.as_str(),
                "content-type" | "location" | "retry-after" | "x-request-id" | "request-id"
            ) {
                s.push_str(&format!("{k}: {v}\n"));
            }
        }
        s.push('\n');
        let text = String::from_utf8_lossy(&self.body);
        if text.len() > max {
            let mut cut = max;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            s.push_str(&text[..cut]);
            s.push_str(&format!("\n(answer cut: {} of {} bytes)", cut, text.len()));
        } else {
            s.push_str(&text);
        }
        s
    }
}

/// Called after each request the local proxy forwards: (label, method, path, status).
pub type Logger = Box<dyn Fn(&str, &str, &str, Option<u16>) + Send + Sync>;

/// A proxy on 127.0.0.1 for one `cemi run`. Each API gets an address like
/// `http://127.0.0.1:PORT/<session>/<api>`; the session part is random, so
/// other programs on this computer cannot use the proxy.
pub struct Local {
    server: Arc<tiny_http::Server>,
    thread: Option<std::thread::JoinHandle<()>>,
    prefix: String,
}

struct State {
    session: String,
    upstreams: BTreeMap<String, Upstream>,
    log: Logger,
}

impl Local {
    /// Starts the proxy. `upstreams` maps a short name (the address part) to an API.
    pub fn start(upstreams: BTreeMap<String, Upstream>, log: Logger) -> Result<Local> {
        let server = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|e| anyhow!("cannot start the local proxy: {e}"))?;
        let port = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| anyhow!("the local proxy has no TCP address"))?
            .port();
        let session = crate::crypto::new_id();
        let prefix = format!("http://127.0.0.1:{port}/{session}");
        let server = Arc::new(server);
        let state = Arc::new(State {
            session,
            upstreams,
            log,
        });
        let srv = server.clone();
        let thread = std::thread::spawn(move || {
            for request in srv.incoming_requests() {
                let state = state.clone();
                std::thread::spawn(move || handle(&state, request));
            }
        });
        Ok(Local {
            server,
            thread: Some(thread),
            prefix,
        })
    }

    /// The address a program uses for the API named `name`.
    pub fn url(&self, name: &str) -> String {
        format!("{}/{name}", self.prefix)
    }
}

impl Drop for Local {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn respond_text(request: tiny_http::Request, status: u16, text: &str) {
    let resp =
        tiny_http::Response::from_string(format!("Cemí proxy: {text}\n")).with_status_code(status);
    let _ = request.respond(resp);
}

fn handle(state: &State, mut request: tiny_http::Request) {
    let url = request.url().to_string();
    let method = request.method().as_str().to_ascii_uppercase();
    let rest = url.strip_prefix('/').unwrap_or(&url);
    let (session, rest) = rest.split_once('/').unwrap_or((rest, ""));
    if !crate::crypto::ct_eq(session.as_bytes(), state.session.as_bytes()) {
        respond_text(request, 404, "unknown address");
        return;
    }
    let (name, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, String::from("/")),
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path
    };
    let Some(up) = state.upstreams.get(name) else {
        respond_text(request, 404, &format!("no API named {name:?} in this run"));
        return;
    };
    if let Err(e) = up.check(&method, &path) {
        (state.log)(&up.label, &method, &path, None);
        respond_text(request, 403, &format!("{e:#}"));
        return;
    }
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|h| (h.field.as_str().to_string(), h.value.as_str().to_string()))
        .collect();
    let mut body = Vec::new();
    if let Err(e) = request
        .as_reader()
        .take(MAX_BODY + 1)
        .read_to_end(&mut body)
    {
        respond_text(request, 400, &format!("cannot read the request: {e}"));
        return;
    }
    if body.len() as u64 > MAX_BODY {
        respond_text(request, 413, "the request body is larger than 10 MB");
        return;
    }
    match up.forward(&method, &path, &headers, body) {
        Ok(reply) => {
            (state.log)(&up.label, &method, &path, Some(reply.status));
            let mut resp =
                tiny_http::Response::from_data(reply.body).with_status_code(reply.status);
            for (k, v) in &reply.headers {
                if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                    resp.add_header(h);
                }
            }
            let _ = request.respond(resp);
        }
        Err(e) => {
            (state.log)(&up.label, &method, &path, None);
            respond_text(request, 502, &format!("{e:#}"));
        }
    }
}

/// The API of a field with its key, for one environment.
pub fn upstream_for(ws: &mut Workspace, fr: &FieldRef, env: Option<&str>) -> Result<Upstream> {
    let full = fr.to_ref(ws)?;
    let field = fr.field(ws)?;
    let Some(api) = api_for(field, env).cloned() else {
        return Err(crate::errors::not_found(format!(
            "{full} has no API for {}. The human adds one in a terminal: cemi api add {full}{} --base https://… --allow \"GET /…\"",
            env.unwrap_or("the shared value"),
            env.map(|e| format!(" -e {e}")).unwrap_or_default()
        )));
    };
    let value = resolve::resolve(ws, &full, env)?.text()?;
    Upstream::new(format!("{full} ({})", env_label(&api.env)), &api, value)
}

/// What `cemi run --proxy` changes in a run.
pub struct RunProxy {
    pub local: Local,
    /// Variables that got the proxy's address, and secrets replaced by a placeholder.
    pub notes: Vec<String>,
}

/// Puts the proxy between a run and the APIs: every secret `[env]` variable
/// whose field has an API gets a placeholder, and each `[proxy]` variable
/// gets the proxy's address for its API. With `required`, any other secret
/// is an error (an AI run in a protected environment).
pub fn for_run(
    ws: &mut Workspace,
    project: &Project,
    env: Option<&str>,
    plan: &mut Plan,
    required: bool,
    actor: &str,
) -> Result<RunProxy> {
    let mut upstreams: BTreeMap<String, Upstream> = BTreeMap::new();
    // Canonical field reference → address name.
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    let mut logs: BTreeMap<String, (std::path::PathBuf, crate::vault::Header)> = BTreeMap::new();
    let mut notes = Vec::new();
    let mut add = |ws: &mut Workspace, fr: &FieldRef| -> Result<String> {
        let key = fr.text(ws);
        if let Some(n) = names.get(&key) {
            return Ok(n.clone());
        }
        let up = upstream_for(ws, fr, env)?;
        let name = format!("api{}", names.len() + 1);
        let v = ws.open(fr.scope)?;
        logs.insert(up.label.clone(), (v.dir.clone(), v.header.clone()));
        upstreams.insert(name.clone(), up);
        names.insert(key, name.clone());
        Ok(name)
    };
    let mut proxied: Vec<String> = Vec::new();
    for (var, spec) in &project.file.env {
        let r = project.resolve_ref(spec.text())?;
        let Ok(fr) = FieldRef::find(ws, &r) else {
            continue;
        };
        let field = fr.field(ws)?;
        if !field.secret || api_for(field, env).is_none() {
            continue;
        }
        add(ws, &fr)?;
        let placeholder = Zeroizing::new(format!("cemi-proxy-{var}"));
        for (k, v) in plan.env.iter_mut() {
            if k == var {
                *v = placeholder.clone();
            }
        }
        proxied.push(var.clone());
        notes.push(format!("{var}: a placeholder; the proxy adds the key"));
    }
    let mut addresses: Vec<(String, String)> = Vec::new();
    for (var, spec) in &project.file.proxy {
        let r = project.resolve_ref(spec.text())?;
        let fr = FieldRef::find(ws, &r).with_context(|| format!("[proxy] {var}"))?;
        let name = add(ws, &fr).with_context(|| format!("[proxy] {var}"))?;
        addresses.push((var.clone(), name));
    }
    if required {
        let mut left: Vec<String> = plan
            .secrets
            .iter()
            .map(|(k, _)| k.clone())
            .filter(|k| !proxied.contains(k))
            .collect();
        left.dedup();
        if !left.is_empty() {
            return Err(crate::errors::needs_person(format!(
                "in a protected environment an AI may only run commands whose secrets go through Cemí's proxy, and these do not: {}. The human can give each one an API (`cemi api add`), or run the command in a terminal",
                left.join(", ")
            )));
        }
    }
    let actor = actor.to_string();
    let log: Logger = Box::new(move |label, method, path, status| {
        let Some((dir, header)) = logs.get(label) else {
            return;
        };
        let _ = crate::audit::append(
            dir,
            header,
            crate::audit::Event {
                actor: &actor,
                action: "api.call",
                target: Some(label.to_string()),
                env: None,
                detail: Some(match status {
                    Some(s) => format!("{method} {} → {s}", path.split('?').next().unwrap_or("")),
                    None => format!(
                        "{method} {} → refused",
                        path.split('?').next().unwrap_or("")
                    ),
                }),
            },
        );
    });
    let local = Local::start(upstreams, log)?;
    for (var, name) in addresses {
        let url = local.url(&name);
        notes.push(format!("{var}: the proxy's address ({url})"));
        plan.env.retain(|(k, _)| k != &var);
        plan.env.push((var, Zeroizing::new(url)));
    }
    Ok(RunProxy { local, notes })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segs(p: &str) -> Vec<String> {
        split_path(p).unwrap().0
    }

    #[test]
    fn rules_match_methods_and_paths() {
        let r = Rule::parse("GET /v1/charges/*").unwrap();
        assert!(r.matches("GET", &segs("/v1/charges/ch_1")));
        assert!(!r.matches("POST", &segs("/v1/charges/ch_1")));
        assert!(!r.matches("GET", &segs("/v1/charges/ch_1/refunds")));
        assert!(!r.matches("GET", &segs("/v1/charges")));
        let all = Rule::parse("* /v1/**").unwrap();
        assert!(all.matches("DELETE", &segs("/v1/a/b/c")));
        assert!(all.matches("GET", &segs("/v1")));
        assert!(!all.matches("GET", &segs("/v2/a")));
        let mid = Rule::parse("get /rest/v1/*/rpc").unwrap();
        assert!(mid.matches("GET", &segs("/rest/v1/x/rpc")));
        let star = Rule::parse("GET /v1/cus_*").unwrap();
        assert!(star.matches("GET", &segs("/v1/cus_123")));
        assert!(!star.matches("GET", &segs("/v1/ch_123")));
        assert!(Rule::parse("FETCH /x").is_err());
        assert!(Rule::parse("/x").is_err());
    }

    #[test]
    fn tricky_paths_are_refused() {
        assert!(split_path("/v1/../admin").is_err());
        assert!(split_path("/v1/%2e%2E/admin").is_err());
        assert!(split_path("/v1/a%2Fb").is_err());
        assert!(split_path("/v1\\admin").is_err());
        assert!(split_path("//evil.com/x").is_err());
        assert!(split_path("v1/x").is_err());
        assert!(split_path("/v1/x y").is_err());
        let (s, q) = split_path("/v1/x?limit=3&a=b").unwrap();
        assert_eq!(s, vec!["v1", "x"]);
        assert_eq!(q.as_deref(), Some("limit=3&a=b"));
        assert!(split_path("/").unwrap().0.is_empty());
    }

    #[test]
    fn bases_are_checked() {
        assert_eq!(
            check_base("https://api.stripe.com/").unwrap(),
            "https://api.stripe.com"
        );
        assert!(check_base("http://api.stripe.com").is_err());
        assert!(check_base("https://user@api.stripe.com").is_err());
        assert!(check_base("https://api.stripe.com/v1?x=1").is_err());
        assert!(check_base("http://127.0.0.1:9/x").is_ok());
    }
}
