//! `cemi sync`: the same vault on several computers, through a private git
//! repository. The vault folder becomes a git working copy of it.
//!
//! What goes to git: `vault.json` (the header: id, public key, the vault key
//! wrapped by the password and the recovery code) and `objects/*.age`. Every
//! object is already encrypted with age, so the repository never holds a
//! value, a name or a note in clear. What stays on each computer: the lock,
//! the audit log (each computer keeps its own chain of what happened there),
//! the folders of known projects (they are paths of this computer) and any
//! other machine-local file.
//!
//! When both computers changed the vault, git finds the objects that changed
//! on each side. An object changed on one side is taken as it is. An object
//! changed on both is opened and merged here (see `merge`), not by git:
//! merging needs the vault's keys, which only this process has. The result
//! is a normal merge commit, pushed back.

pub mod merge;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use anyhow::{Context, Result, anyhow, bail};

use crate::crypto::{self, AgeKey};
use crate::model::{Envelope, OBJECT_FORMAT, Object};
use crate::vault::{HEADER_FILE, Header, OBJECTS_DIR, Vault};

const BRANCH: &str = "main";
const REMOTE_REF: &str = "refs/remotes/origin/main";

fn git_command(dir: &Path) -> Command {
    let mut c = Command::new(crate::runner::resolve_program("git"));
    c.current_dir(dir)
        .arg("-c")
        .arg("core.autocrlf=false")
        .stdin(Stdio::null());
    c
}

fn run(dir: &Path, args: &[&str]) -> Result<Output> {
    let out = git_command(dir)
        .args(args)
        .output()
        .map_err(|_| anyhow!("cannot run git: install git and try again"))?;
    Ok(out)
}

/// Runs git and fails with its message.
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = run(dir, args)?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(crate::errors::external(format!(
            "git {} failed: {msg}",
            args.first().copied().unwrap_or("")
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A blob's bytes at a revision (`None` if the path is not there).
fn blob(dir: &Path, rev: &str, path: &str) -> Result<Option<Vec<u8>>> {
    let out = run(dir, &["cat-file", "blob", &format!("{rev}:{path}")])?;
    Ok(out.status.success().then_some(out.stdout))
}

/// Commits with the person's git identity, or a neutral one if git has none.
fn commit(dir: &Path, message: &str) -> Result<()> {
    let has_identity = run(dir, &["config", "user.email"])
        .map(|o| o.status.success() && !o.stdout.trim_ascii().is_empty())
        .unwrap_or(false);
    let mut c = git_command(dir);
    c.args(["commit", "-q", "--no-verify", "-m", message]);
    if !has_identity {
        c.env("GIT_AUTHOR_NAME", "cemi")
            .env("GIT_AUTHOR_EMAIL", "cemi@localhost")
            .env("GIT_COMMITTER_NAME", "cemi")
            .env("GIT_COMMITTER_EMAIL", "cemi@localhost");
    }
    let out = c
        .output()
        .map_err(|_| anyhow!("cannot run git: install git and try again"))?;
    if !out.status.success() {
        bail!(
            "git commit failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

pub fn is_synced(dir: &Path) -> bool {
    dir.join(".git").exists()
}

/// The files of the vault that belong in git: the header and every object
/// except machine-local ones (known project folders).
fn wanted(v: &Vault) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    out.insert(HEADER_FILE.to_string());
    for entry in std::fs::read_dir(v.dir.join(OBJECTS_DIR))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("age") {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if v.projects.contains_key(id) {
            continue;
        }
        out.insert(format!("{OBJECTS_DIR}/{id}.age"));
    }
    Ok(out)
}

/// Stages the vault's files (the folder's own .gitignore ignores everything,
/// so files are added by name) and commits if anything changed.
fn commit_local(v: &Vault, message: &str) -> Result<bool> {
    let dir = &v.dir;
    let want = wanted(v)?;
    let tracked: BTreeSet<String> = git(dir, &["ls-files"])?
        .lines()
        .map(str::to_string)
        .collect();
    let gone: Vec<&String> = tracked.difference(&want).collect();
    for chunk in gone.chunks(100) {
        let mut args = vec!["rm", "-q", "--cached", "--ignore-unmatch", "--"];
        args.extend(chunk.iter().map(|s| s.as_str()));
        git(dir, &args)?;
    }
    let want: Vec<&String> = want.iter().collect();
    for chunk in want.chunks(100) {
        let mut args = vec!["add", "-f", "--"];
        args.extend(chunk.iter().map(|s| s.as_str()));
        git(dir, &args)?;
    }
    let staged = run(dir, &["diff", "--cached", "--quiet"])?;
    if staged.status.success() {
        return Ok(false);
    }
    commit(dir, message)?;
    Ok(true)
}

fn remote_has_branch(dir: &Path) -> Result<bool> {
    Ok(!git(dir, &["ls-remote", "--heads", "origin", BRANCH])?
        .trim()
        .is_empty())
}

/// `cemi sync init`: makes the vault folder a git working copy and pushes it.
pub fn init(v: &Vault, remote: &str) -> Result<()> {
    let dir = &v.dir;
    if is_synced(dir) {
        bail!(
            "this vault already syncs (see `git -C {} remote -v`)",
            dir.display()
        );
    }
    git(dir, &["init", "-q"])?;
    git(
        dir,
        &["symbolic-ref", "HEAD", &format!("refs/heads/{BRANCH}")],
    )?;
    git(dir, &["config", "core.autocrlf", "false"])?;
    git(dir, &["remote", "add", "origin", remote])?;
    if remote_has_branch(dir)? {
        let _ = std::fs::remove_dir_all(dir.join(".git"));
        bail!(
            "{remote} already holds a vault. To use it on this computer, move this vault away and run `cemi sync clone {remote}`"
        );
    }
    commit_local(v, "cemi: first sync")?;
    git(dir, &["push", "-q", "-u", "origin", BRANCH])?;
    Ok(())
}

/// `cemi sync clone`: makes `dir` a copy of the vault in `remote`.
pub fn clone(remote: &str, dir: &Path) -> Result<()> {
    if dir.join(HEADER_FILE).exists() {
        bail!(
            "there is already a vault in {}. Move it away first, or sync it with `cemi sync`",
            dir.display()
        );
    }
    if dir.exists() && std::fs::read_dir(dir)?.next().is_some() {
        bail!("{} is not empty", dir.display());
    }
    let parent = dir
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent folder", dir.display()))?;
    std::fs::create_dir_all(parent)?;
    let target = dir.to_string_lossy().into_owned();
    git(
        parent,
        &[
            "clone",
            "-q",
            "-c",
            "core.autocrlf=false",
            "--branch",
            BRANCH,
            remote,
            &target,
        ],
    )?;
    if !dir.join(HEADER_FILE).is_file() {
        let _ = std::fs::remove_dir_all(dir);
        bail!("{remote} does not hold a Cemí vault");
    }
    Header::read(dir)?;
    std::fs::create_dir_all(dir.join(OBJECTS_DIR))?;
    std::fs::write(dir.join(".gitignore"), "*\n")?;
    Ok(())
}

#[derive(Default)]
pub struct Report {
    pub sent: bool,
    /// Objects that came from the other computers.
    pub received: usize,
    /// Objects both sides changed, merged here.
    pub merged: usize,
    /// The password or recovery code changed on another computer.
    pub header_changed: bool,
}

/// Paths changed between two revisions, with git's status letter.
fn changes(dir: &Path, from: &str, to: &str) -> Result<BTreeMap<String, char>> {
    let text = git(
        dir,
        &[
            "diff",
            "--name-status",
            "--no-renames",
            from,
            to,
            "--",
            HEADER_FILE,
            OBJECTS_DIR,
        ],
    )?;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.split('\t');
        if let (Some(status), Some(path)) = (parts.next(), parts.next()) {
            out.insert(path.to_string(), status.chars().next().unwrap_or('M'));
        }
    }
    Ok(out)
}

fn decrypt(keys: &[&AgeKey], bytes: &[u8]) -> Option<Object> {
    let plain = crypto::age_decrypt_any(keys, bytes).ok()??;
    let env: Envelope = serde_json::from_slice(&plain).ok()?;
    (env.format == OBJECT_FORMAT).then_some(env.object)
}

/// `cemi sync`: commits local changes, brings in the other computers' and
/// pushes. The vault is open for writing (its lock is held) the whole time.
pub fn sync(v: &mut Vault) -> Result<Report> {
    let dir = v.dir.clone();
    if !is_synced(&dir) {
        return Err(crate::errors::not_found(
            "this vault does not sync yet. Start with `cemi sync init <git remote>`, or copy one with `cemi sync clone <git remote>`",
        ));
    }
    v.save()?;
    let mut report = Report::default();
    commit_local(v, "cemi sync")?;
    for _attempt in 0..3 {
        if !remote_has_branch(&dir)? {
            git(&dir, &["push", "-q", "-u", "origin", BRANCH])?;
            report.sent = true;
            return Ok(report);
        }
        git(&dir, &["fetch", "-q", "origin", BRANCH])?;
        let counts = git(
            &dir,
            &[
                "rev-list",
                "--left-right",
                "--count",
                &format!("HEAD...{REMOTE_REF}"),
            ],
        )?;
        let mut nums = counts
            .split_whitespace()
            .map(|n| n.parse::<usize>().unwrap_or(0));
        let (ahead, behind) = (nums.next().unwrap_or(0), nums.next().unwrap_or(0));
        if behind > 0 {
            let theirs = changes(&dir, "HEAD", REMOTE_REF)?;
            if ahead == 0 {
                report.header_changed |= theirs.contains_key(HEADER_FILE);
                report.received += theirs.keys().filter(|p| *p != HEADER_FILE).count();
                git(&dir, &["merge", "-q", "--ff-only", REMOTE_REF])?;
                return Ok(report);
            }
            merge_diverged(v, &mut report)?;
        } else if ahead == 0 {
            return Ok(report);
        }
        let pushed = run(&dir, &["push", "-q", "origin", BRANCH])?;
        if pushed.status.success() {
            report.sent = true;
            return Ok(report);
        }
        // Another computer pushed in between: fetch and merge again.
    }
    bail!("the remote keeps changing; run `cemi sync` again in a moment")
}

/// Both sides have commits: take each side's changes, merge objects both
/// changed, and commit the result with both parents.
fn merge_diverged(v: &mut Vault, report: &mut Report) -> Result<()> {
    let dir = v.dir.clone();
    let base = git(&dir, &["merge-base", "HEAD", REMOTE_REF])?
        .trim()
        .to_string();
    let ours = changes(&dir, &base, "HEAD")?;
    let theirs = changes(&dir, &base, REMOTE_REF)?;
    // Records our tree with both parents; files are then set one by one.
    git(
        &dir,
        &[
            "merge",
            "-q",
            "--no-ff",
            "--no-commit",
            "-s",
            "ours",
            REMOTE_REF,
        ],
    )?;

    // Keys: this vault's, plus entity keys that only exist on the other side.
    let mut keys: Vec<AgeKey> = vec![v.master().clone()];
    for e in v.entities.values() {
        keys.push(AgeKey::parse(e.identity.expose())?);
    }
    let mut incoming: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (path, status) in &theirs {
        if *status != 'D'
            && let Some(bytes) = blob(&dir, REMOTE_REF, path)?
        {
            incoming.insert(path.clone(), bytes);
        }
    }
    loop {
        let refs: Vec<&AgeKey> = keys.iter().collect();
        let mut found = Vec::new();
        for bytes in incoming.values() {
            if let Some(Object::Entity(e)) = decrypt(&refs, bytes)
                && !keys
                    .iter()
                    .any(|k| k.secret_text().as_str() == e.identity.expose())
            {
                found.push(AgeKey::parse(e.identity.expose())?);
            }
        }
        if found.is_empty() {
            break;
        }
        keys.extend(found);
    }
    let refs: Vec<&AgeKey> = keys.iter().collect();

    let mut merged: Vec<Object> = Vec::new();
    for (path, their_status) in &theirs {
        let file = dir.join(path);
        let our_status = ours.get(path);
        if path == HEADER_FILE {
            if our_status.is_some() {
                report.header_changed |= merge_header(&dir)?;
            } else {
                let bytes = incoming
                    .get(path)
                    .ok_or_else(|| anyhow!("the other side deleted vault.json"))?;
                crate::vault::atomic_write(&file, bytes)?;
                report.header_changed = true;
            }
            continue;
        }
        match (our_status, their_status) {
            // Only they changed it: take their copy.
            (None, 'D') => {
                if file.exists() {
                    std::fs::remove_file(&file)?;
                }
                report.received += 1;
            }
            (None, _) => {
                crate::vault::atomic_write(&file, &incoming[path])?;
                if let Some(o) = decrypt(&refs, &incoming[path]) {
                    v.adopt(o);
                }
                report.received += 1;
            }
            // Both deleted it.
            (Some('D'), 'D') => {}
            // Deleted here, edited there: keep the edit.
            (Some('D'), _) => {
                crate::vault::atomic_write(&file, &incoming[path])?;
                if let Some(o) = decrypt(&refs, &incoming[path]) {
                    v.adopt(o);
                }
                report.received += 1;
            }
            // Edited here, deleted there: keep ours.
            (Some(_), 'D') => {}
            (Some(_), _) => {
                let ours_bytes = std::fs::read(&file)
                    .with_context(|| format!("cannot read {}", file.display()))?;
                if ours_bytes == incoming[path] {
                    continue;
                }
                let base_obj = blob(&dir, &base, path)?.and_then(|b| decrypt(&refs, &b));
                match (decrypt(&refs, &ours_bytes), decrypt(&refs, &incoming[path])) {
                    (Some(o), Some(t)) => {
                        merged.push(merge::merge_object(base_obj.as_ref(), &o, &t));
                    }
                    _ => crate::ui::warn(format!(
                        "{path} changed on both computers and cannot be opened here; kept this computer's copy"
                    )),
                }
            }
        }
    }
    report.merged = merged.len();
    for o in merged {
        v.replace_object(o);
    }
    v.save()?;
    commit_local(v, "cemi sync: merge")?;
    Ok(())
}

/// Both computers changed the header: it must be the same vault, and the
/// one whose password or recovery code changed last wins (the vault key is
/// the same in both, so both open the same objects).
fn merge_header(dir: &Path) -> Result<bool> {
    let ours = Header::read(dir)?;
    let theirs_bytes = blob(dir, REMOTE_REF, HEADER_FILE)?
        .ok_or_else(|| anyhow!("the other side deleted vault.json"))?;
    let theirs: Header =
        serde_json::from_slice(&theirs_bytes).context("the other side's vault.json is damaged")?;
    if theirs.id != ours.id || theirs.recipient != ours.recipient {
        bail!("the remote holds a different vault; nothing was merged");
    }
    if theirs.changed > ours.changed {
        crate::vault::atomic_write(&dir.join(HEADER_FILE), &theirs_bytes)?;
        return Ok(true);
    }
    Ok(false)
}
