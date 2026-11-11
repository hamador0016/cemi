//! `cemi scan`: finds the exact secret values of your vaults in files, staged
//! changes or git history, so they never reach a repository. Unlike pattern
//! scanners, it catches any of your secrets, whatever their format.

use std::path::{Path, PathBuf};
use std::process::Command;

use aho_corasick::{AhoCorasick, MatchKind};
use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use super::Ctx;
use crate::cli::HookCmd;
use crate::model::Value;
use crate::ui;
use crate::vault::{Scope, Vault};

struct Needles {
    matcher: AhoCorasick,
    labels: Vec<String>,
}

/// Every current and past secret value (8+ characters) of a vault.
fn collect(v: &Vault, scope: Scope, out: &mut Vec<(String, Zeroizing<Vec<u8>>)>) {
    for r in v.records.values() {
        for f in r.fields.iter().filter(|f| f.secret) {
            for (env, slot) in &f.values {
                for ver in &slot.versions {
                    let bytes = match &ver.value {
                        Value::Text { .. } => ver.value.bytes(),
                        Value::File { .. } => {
                            // Scan files line by line: a key file often appears partially.
                            let b = ver.value.bytes();
                            for line in b.split(|c| *c == b'\n') {
                                let line = line.strip_suffix(b"\r").unwrap_or(line);
                                if line.len() >= 24 && !line.starts_with(b"-----") {
                                    out.push((
                                        label(v, r, &f.name, env, scope),
                                        Zeroizing::new(line.to_vec()),
                                    ));
                                }
                            }
                            continue;
                        }
                    };
                    if bytes.len() >= 8 {
                        out.push((label(v, r, &f.name, env, scope), bytes));
                    }
                }
            }
        }
    }
}

fn label(v: &Vault, r: &crate::model::Record, field: &str, env: &str, scope: Scope) -> String {
    let env = if env == crate::model::SHARED {
        String::new()
    } else {
        format!(" [{env}]")
    };
    format!("{scope}:{}#{field}{env}", v.record_path(r))
}

fn needles(ctx: &mut Ctx) -> Result<Needles> {
    let mut values = Vec::new();
    let mut scopes = Vec::new();
    if ctx.ws.local_dir.is_some() {
        scopes.push(Scope::Local);
    }
    if ctx.ws.global_exists() {
        scopes.push(Scope::Global);
    }
    if scopes.is_empty() {
        bail!("no vault to compare with");
    }
    for s in scopes {
        let v = ctx.ws.open(s)?;
        collect(v, s, &mut values);
    }
    if values.is_empty() {
        bail!("your vaults have no secret values yet, so there is nothing to look for");
    }
    let matcher = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(values.iter().map(|(_, v)| v.as_slice()))
        .expect("valid patterns");
    Ok(Needles {
        matcher,
        labels: values.into_iter().map(|(l, _)| l).collect(),
    })
}

struct Finding {
    place: String,
    line: usize,
    secret: String,
}

fn scan_bytes(n: &Needles, place: &str, data: &[u8], out: &mut Vec<Finding>) {
    for m in n.matcher.find_iter(data) {
        let line = data[..m.start()].iter().filter(|b| **b == b'\n').count() + 1;
        out.push(Finding {
            place: place.to_string(),
            line,
            secret: n.labels[m.pattern().as_usize()].clone(),
        });
    }
}

fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .context("cannot run git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

pub fn scan(ctx: &mut Ctx, path: Option<PathBuf>, staged: bool, history: bool) -> Result<i32> {
    let root = path.unwrap_or_else(|| ctx.ws.cwd.clone());
    let n = needles(ctx)?;
    let mut findings = Vec::new();
    let mut vault_files = Vec::new();
    if staged {
        let names = git(
            &root,
            &[
                "diff",
                "--cached",
                "--name-only",
                "-z",
                "--diff-filter=ACMR",
            ],
        )?;
        for name in names.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            let name = String::from_utf8_lossy(name).into_owned();
            if name.split('/').any(|part| part == ".cemi") {
                vault_files.push(name.clone());
            }
            let content = git(&root, &["show", &format!(":{name}")])?;
            scan_bytes(&n, &name, &content, &mut findings);
        }
    } else if history {
        let log = git(
            &root,
            &["log", "-p", "--all", "--no-color", "--format=commit %H"],
        )?;
        let mut commit = String::new();
        let mut file = String::new();
        for (i, line) in log.split(|b| *b == b'\n').enumerate() {
            if let Some(c) = line.strip_prefix(b"commit ") {
                commit = String::from_utf8_lossy(&c[..c.len().min(12)]).into_owned();
            } else if let Some(f) = line.strip_prefix(b"+++ b/") {
                file = String::from_utf8_lossy(f).into_owned();
            }
            if line.starts_with(b"+") || line.starts_with(b"-") {
                let before = findings.len();
                scan_bytes(&n, &format!("{commit} {file}"), line, &mut findings);
                for f in &mut findings[before..] {
                    f.line = i + 1;
                }
            }
        }
    } else {
        let walker = ignore::WalkBuilder::new(&root).hidden(false).build();
        for entry in walker.flatten() {
            let p = entry.path();
            if !p.is_file()
                || p.components()
                    .any(|c| c.as_os_str() == ".git" || c.as_os_str() == ".cemi")
            {
                continue;
            }
            let Ok(meta) = p.metadata() else { continue };
            if meta.len() > 20 * 1024 * 1024 {
                continue;
            }
            let Ok(data) = std::fs::read(p) else { continue };
            let shown = p.strip_prefix(&root).unwrap_or(p).display().to_string();
            scan_bytes(&n, &shown, &data, &mut findings);
        }
    }
    for f in &vault_files {
        println!("! {f}: this is a vault file; never commit .cemi/");
    }
    for f in &findings {
        if history {
            println!("! {}: value of {}", f.place, f.secret);
        } else {
            println!("! {}:{}: value of {}", f.place, f.line, f.secret);
        }
    }
    if findings.is_empty() && vault_files.is_empty() {
        ui::ok(if staged {
            "No secrets in the staged changes"
        } else if history {
            "No secrets in the git history"
        } else {
            "No secrets found"
        });
        return Ok(0);
    }
    eprintln!();
    if history {
        eprintln!(
            "These secrets are in the history. Removing them from git is not enough: rotate them."
        );
    } else if staged {
        eprintln!(
            "Commit blocked. Remove the values (use `cemi run` or cemi.toml references instead) and try again."
        );
    }
    Ok(1)
}

pub fn hook(ctx: &mut Ctx, cmd: HookCmd) -> Result<i32> {
    let HookCmd::Install { force } = cmd;
    let top = git(&ctx.ws.cwd, &["rev-parse", "--git-path", "hooks"])?;
    let hooks = ctx.ws.cwd.join(String::from_utf8_lossy(&top).trim());
    std::fs::create_dir_all(&hooks)?;
    let path = hooks.join("pre-commit");
    if path.exists() && !force {
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current.contains("cemi scan --staged") {
            ui::ok("The pre-commit hook already runs cemi scan");
            return Ok(0);
        }
        bail!(
            "{} already exists. Add the line `cemi scan --staged || exit 1` to it, or use --force to replace it",
            path.display()
        );
    }
    std::fs::write(
        &path,
        "#!/bin/sh\n# Installed by `cemi hook install`: blocks commits that contain values from your Cemí vaults.\ncemi scan --staged || exit 1\n",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    }
    ui::ok(format!("Installed {}", path.display()));
    eprintln!(
        "  Commits now stop if they contain a value from your vaults (the vault must be unlocked)."
    );
    Ok(0)
}
