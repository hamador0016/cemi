//! `cemi sync`: the same vault on several computers, through a private git
//! repository. The vault folder becomes a git working copy of it.
//!
//! What goes to git: `vault.json` (the header: id, public key, the vault key
//! wrapped by the password and the recovery code) and `objects/*.age`. Every
//! object is encrypted with age, so the repository never holds a value, a
//! name or a note in clear. What stays on each computer: the lock, the audit
//! log (each computer keeps its own chain of what happened there), the
//! folders of known projects (paths of this computer) and the `requests` file.
//!
//! Nothing from the repository is trusted as it comes. Every object and the
//! header carry a tag made with the vault key, which the repository never
//! sees: an object or header without a valid tag stops the sync before
//! anything changes. An authentic but old copy (put back by someone who can
//! push) cannot undo newer changes either: every incoming object is merged
//! with this computer's copy (see `merge`), which keeps the newest of each
//! thing, every version of every value and every revocation, and the
//! password and recovery code each keep their newest wrap.

pub mod merge;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::{Result, anyhow, bail};

use crate::crypto::{self, AgeKey};
use crate::model::Object;
use crate::vault::{HEADER_FILE, Header, OBJECTS_DIR, Opened, Vault, open_object};

const BRANCH: &str = "main";
const REMOTE_REF: &str = "refs/remotes/origin/main";

fn git_command(dir: &Path) -> Command {
    let mut c = Command::new(crate::runner::resolve_program("git"));
    c.current_dir(dir)
        .args(["-c", "core.autocrlf=false", "-c", "core.symlinks=false"])
        .stdin(Stdio::null());
    // Commits and merges need a name; without the person's own git
    // identity, a neutral one.
    if !has_identity(dir) {
        c.env("GIT_AUTHOR_NAME", "cemi")
            .env("GIT_AUTHOR_EMAIL", "cemi@localhost")
            .env("GIT_COMMITTER_NAME", "cemi")
            .env("GIT_COMMITTER_EMAIL", "cemi@localhost");
    }
    c
}

/// Whether git has a user name and email to sign commits with.
fn has_identity(dir: &Path) -> bool {
    static KNOWN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *KNOWN.get_or_init(|| {
        let set = |key: &str| {
            Command::new(crate::runner::resolve_program("git"))
                .current_dir(dir)
                .args(["config", key])
                .stdin(Stdio::null())
                .output()
                .map(|o| o.status.success() && !o.stdout.trim_ascii().is_empty())
                .unwrap_or(false)
        };
        set("user.email") && set("user.name")
    })
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
    let mut c = git_command(dir);
    c.args([
        "commit",
        "-q",
        "--no-verify",
        "--allow-empty",
        "-m",
        message,
    ]);
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

/// A remote is passed to git as a value; one that starts with `-` would be
/// read as an option.
fn check_remote(remote: &str) -> Result<()> {
    if remote.trim().is_empty() || remote.starts_with('-') {
        bail!("{remote:?} is not a git remote");
    }
    Ok(())
}

/// Files are bytes to git: no line-ending changes, filters or merge drivers,
/// whatever a `.gitattributes` in the repository says.
fn protect_checkout(dir: &Path) -> Result<()> {
    let info = dir.join(".git").join("info");
    std::fs::create_dir_all(&info)?;
    std::fs::write(info.join("attributes"), "* -text -filter -diff -merge\n")?;
    Ok(())
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
/// so files are added by name) and commits if anything changed, or always
/// while a merge is open.
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
    let merging = merge_open(dir);
    let staged = run(dir, &["diff", "--cached", "--quiet"])?;
    if staged.status.success() && !merging {
        return Ok(false);
    }
    commit(dir, message)?;
    Ok(true)
}

fn merge_open(dir: &Path) -> bool {
    dir.join(".git").join("MERGE_HEAD").exists()
}

fn remote_has_branch(dir: &Path) -> Result<bool> {
    Ok(!git(dir, &["ls-remote", "--heads", "origin", BRANCH])?
        .trim()
        .is_empty())
}

/// `cemi sync init`: makes the vault folder a git working copy and pushes it.
pub fn init(v: &mut Vault, remote: &str) -> Result<()> {
    check_remote(remote)?;
    let dir = v.dir.clone();
    if is_synced(&dir) {
        bail!(
            "this vault already syncs (see `git -C {} remote -v`)",
            dir.display()
        );
    }
    // Every object and the header get their tags before anything is pushed.
    v.save()?;
    let result = (|| -> Result<()> {
        git(&dir, &["init", "-q"])?;
        git(
            &dir,
            &["symbolic-ref", "HEAD", &format!("refs/heads/{BRANCH}")],
        )?;
        git(&dir, &["config", "core.autocrlf", "false"])?;
        git(&dir, &["config", "core.symlinks", "false"])?;
        protect_checkout(&dir)?;
        git(&dir, &["remote", "add", "origin", "--", remote])?;
        if remote_has_branch(&dir)? {
            bail!(
                "{remote} already holds a vault. To use it on this computer, move this vault away and run `cemi sync clone {remote}`"
            );
        }
        commit_local(v, "cemi: first sync")?;
        git(&dir, &["push", "-q", "-u", "origin", BRANCH])?;
        Ok(())
    })();
    if result.is_err() {
        // Leave the folder as it was, so `cemi sync init` can be tried again.
        let _ = std::fs::remove_dir_all(dir.join(".git"));
    }
    result
}

/// `cemi sync clone`: makes `dir` a copy of the vault in `remote`. The copy
/// is checked when it is first opened: its header must carry a tag, and
/// every object must too.
pub fn clone(remote: &str, dir: &Path) -> Result<()> {
    check_remote(remote)?;
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
    let cleanup = |dir: &Path| {
        let _ = std::fs::remove_dir_all(dir);
    };
    let cloned = git(
        parent,
        &[
            "clone",
            "-q",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.symlinks=false",
            "--no-checkout",
            "--branch",
            BRANCH,
            "--",
            remote,
            &target,
        ],
    );
    if let Err(e) = cloned {
        cleanup(dir);
        return Err(e);
    }
    let checked_out = protect_checkout(dir).and_then(|_| git(dir, &["checkout", "-q", BRANCH]));
    if let Err(e) = checked_out {
        cleanup(dir);
        return Err(e);
    }
    let header = match Header::read(dir) {
        Ok(h) => h,
        Err(_) => {
            cleanup(dir);
            bail!("{remote} does not hold a Cemí vault");
        }
    };
    if header.mac.is_none() {
        cleanup(dir);
        bail!(
            "the vault in {remote} has no tag from its key, so this computer cannot tell it was not changed. Run `cemi sync` once on a computer that has the vault (with this version of cemi), then clone again"
        );
    }
    std::fs::create_dir_all(dir.join(OBJECTS_DIR))?;
    std::fs::write(dir.join(".gitignore"), "*\n")?;
    crate::vault::restrict_permissions(dir);
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
    /// Entities or records created with the same name on two computers,
    /// now one.
    pub folded: usize,
    /// Files the remote put back to a copy this computer already had in its
    /// history: ignored, so newer changes are not undone.
    pub old_copies: Vec<String>,
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

/// The id of a file's contents at a revision.
fn blob_id(dir: &Path, rev: &str, path: &str) -> Result<Option<String>> {
    let out = run(
        dir,
        &["rev-parse", "--verify", "-q", &format!("{rev}:{path}")],
    )?;
    Ok(out
        .status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string()))
}

/// Every content a file has had in this computer's history. Encryption is
/// randomized, so new content never matches an old one: a match means an
/// old copy was put back.
fn history_blobs(dir: &Path, path: &str) -> Result<BTreeSet<String>> {
    let text = git(
        dir,
        &[
            "log",
            "--format=",
            "--raw",
            "--no-abbrev",
            "--no-renames",
            "HEAD",
            "--",
            path,
        ],
    )?;
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 {
            for sha in &fields[2..4] {
                if sha.chars().any(|c| c != '0') {
                    out.insert(sha.to_string());
                }
            }
        }
    }
    Ok(out)
}

/// The object id of `objects/<id>.age`, if the path is one.
fn object_id(path: &str) -> Option<&str> {
    let id = path
        .strip_prefix(OBJECTS_DIR)?
        .strip_prefix('/')?
        .strip_suffix(".age")?;
    (!id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    .then_some(id)
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
    if merge_open(&dir) {
        // A sync that stopped halfway: start over from this computer's copy.
        git(&dir, &["merge", "--abort"])?;
    }
    protect_checkout(&dir)?;
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
        if behind == 0 && ahead == 0 {
            return Ok(report);
        }
        if behind > 0 {
            let written = merge_remote(v, &mut report);
            if let Err(e) = written {
                abort(&dir, &e.new_files);
                return Err(e.error);
            }
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

struct MergeError {
    error: anyhow::Error,
    /// Object files written that this computer did not have before.
    new_files: Vec<PathBuf>,
}

impl<E: Into<anyhow::Error>> From<E> for MergeError {
    fn from(e: E) -> MergeError {
        MergeError {
            error: e.into(),
            new_files: Vec::new(),
        }
    }
}

/// Puts the folder back as it was before a merge that failed.
fn abort(dir: &Path, new_files: &[PathBuf]) {
    if merge_open(dir) {
        let _ = run(dir, &["merge", "--abort"]);
    }
    let _ = run(
        dir,
        &[
            "checkout",
            "-q",
            "-f",
            "HEAD",
            "--",
            HEADER_FILE,
            OBJECTS_DIR,
        ],
    );
    for f in new_files {
        let _ = std::fs::remove_file(f);
    }
}

/// What to do with one object that came from the other computers.
enum Action {
    /// Their file as it is (it is what the merge would produce).
    Take {
        path: String,
        bytes: Vec<u8>,
        object: Object,
    },
    /// A merged copy, written anew.
    Write(Object),
    Delete(String),
}

fn not_from_this_vault(path: &str) -> anyhow::Error {
    anyhow!(
        "{path} in the remote was not written with this vault's key (changed by someone else, or damaged). Nothing was merged. Check the repository's history (`git log -- {path}` in the vault folder)"
    )
}

/// Brings in the remote's changes. Everything that comes in is checked
/// first; only then is anything written.
fn merge_remote(v: &mut Vault, report: &mut Report) -> std::result::Result<(), MergeError> {
    let dir = v.dir.clone();
    let base = git(&dir, &["merge-base", "HEAD", REMOTE_REF])?
        .trim()
        .to_string();
    let ours = changes(&dir, &base, "HEAD")?;
    let theirs = changes(&dir, &base, REMOTE_REF)?;
    let mac = crypto::MacKey::for_vault(v.master());

    // Keys: this vault's, plus entity keys that only exist on the other side.
    let mut keys: Vec<AgeKey> = vec![v.master().clone()];
    for e in v.entities.values() {
        keys.push(AgeKey::parse(e.identity.expose())?);
    }
    let mut incoming: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (path, status) in &theirs {
        if path != HEADER_FILE && object_id(path).is_none() {
            return Err(
                anyhow!("the remote has an unexpected file {path}; nothing was merged").into(),
            );
        }
        if *status != 'D'
            && let Some(bytes) = blob(&dir, REMOTE_REF, path)?
        {
            incoming.insert(path.clone(), bytes);
        }
    }
    let open = |keys: &[AgeKey], path: &str, bytes: &[u8]| -> Option<Opened> {
        let refs: Vec<&AgeKey> = keys.iter().collect();
        let plain = crypto::age_decrypt_any(&refs, bytes).ok()??;
        Some(open_object(&mac, object_id(path)?, &plain))
    };
    // New entities bring the keys of what is below them; only signed ones count.
    loop {
        let mut found = Vec::new();
        for (path, bytes) in &incoming {
            if path == HEADER_FILE {
                continue;
            }
            if let Some(Opened::Signed(Object::Entity(e))) = open(&keys, path, bytes)
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

    // 1. Check everything that comes in.
    let mut their_objects: BTreeMap<String, Object> = BTreeMap::new();
    let mut their_header: Option<Header> = None;
    for (path, bytes) in &incoming {
        if path == HEADER_FILE {
            let h: Header = serde_json::from_slice(bytes).map_err(|_| not_from_this_vault(path))?;
            if !h.signed_by(&mac) {
                return Err(not_from_this_vault(path).into());
            }
            their_header = Some(h);
            continue;
        }
        match open(&keys, path, bytes) {
            Some(Opened::Signed(o)) => {
                their_objects.insert(path.clone(), o);
            }
            Some(Opened::Format(f)) => {
                return Err(anyhow!(
                    "{path} uses format {f}, newer than this cemi understands: update cemi, then sync"
                )
                .into());
            }
            _ => return Err(not_from_this_vault(path).into()),
        }
    }

    // 2. Decide, object by object.
    let mut actions: Vec<Action> = Vec::new();
    let mut header = v.header.clone();
    for (path, their_status) in &theirs {
        if *their_status != 'D'
            && let Some(sha) = blob_id(&dir, REMOTE_REF, path)?
            && blob_id(&dir, "HEAD", path)?.as_deref() != Some(sha.as_str())
            && history_blobs(&dir, path)?.contains(&sha)
        {
            report.old_copies.push(path.clone());
            continue;
        }
        if path == HEADER_FILE {
            if let Some(h) = &their_header {
                let (merged, changed) = merge_header(&v.header, h)?;
                header = merged;
                report.header_changed |= changed;
            }
            continue;
        }
        let id = object_id(path).expect("checked above").to_string();
        let local = v.object(&id);
        let ours_changed = ours.contains_key(path);
        match (their_status, local) {
            // They deleted it.
            ('D', Some(local)) => {
                // Kept if this computer changed it, and entities are never
                // deleted (records below them would be lost).
                if !ours_changed && !matches!(local, Object::Entity(_)) {
                    actions.push(Action::Delete(id));
                    report.received += 1;
                }
            }
            ('D', None) => {}
            (_, None) => {
                // New there, or deleted here and edited there: the edit wins.
                actions.push(Action::Take {
                    path: path.clone(),
                    bytes: incoming[path].clone(),
                    object: their_objects[path].clone(),
                });
                report.received += 1;
            }
            (_, Some(local)) => {
                let theirs_obj = &their_objects[path];
                // The copy both started from (from this computer's own history).
                let base_obj = blob(&dir, &base, path)?.and_then(|b| match open(&keys, path, &b) {
                    Some(Opened::Signed(o)) | Some(Opened::Unsigned(o)) => Some(o),
                    _ => None,
                });
                let merged = merge::merge_object(base_obj.as_ref(), &local, theirs_obj);
                if merge::same(&merged, theirs_obj) {
                    actions.push(Action::Take {
                        path: path.clone(),
                        bytes: incoming[path].clone(),
                        object: merged,
                    });
                    report.received += 1;
                } else if !merge::same(&merged, &local) {
                    actions.push(Action::Write(merged));
                    report.merged += 1;
                }
            }
        }
    }

    // 3. Write. From here on a failure puts the folder back.
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
    let mut new_files: Vec<PathBuf> = Vec::new();
    let written = (|| -> Result<()> {
        for action in actions {
            match action {
                Action::Take {
                    path,
                    bytes,
                    object,
                } => {
                    let file = dir.join(&path);
                    if !file.exists() {
                        new_files.push(file.clone());
                    }
                    crate::vault::atomic_write(&file, &bytes)?;
                    v.adopt(object);
                }
                Action::Write(o) => v.replace_object(o),
                Action::Delete(id) => v.remove_object(&id),
            }
        }
        report.folded = fold_duplicates(v);
        if report.header_changed {
            let master = v.master().clone();
            header.write(&dir, &master)?;
            v.header = header;
        }
        v.save()?;
        commit_local(v, "cemi sync: merge")?;
        Ok(())
    })();
    written.map_err(|error| MergeError { error, new_files })
}

/// Both computers have a header for the vault: it must be the same vault,
/// and the password and the recovery code each keep their newest wrap.
fn merge_header(ours: &Header, theirs: &Header) -> Result<(Header, bool)> {
    if theirs.id != ours.id
        || theirs.recipient != ours.recipient
        || theirs.salt != ours.salt
        || theirs.kdf != ours.kdf
    {
        bail!("the remote holds a different vault; nothing was merged");
    }
    let mut out = ours.clone();
    let mut changed = false;
    if theirs.password_changed > ours.password_changed {
        out.password = theirs.password.clone();
        out.password_changed = theirs.password_changed;
        changed = true;
    }
    if theirs.recovery_changed > ours.recovery_changed {
        out.recovery = theirs.recovery.clone();
        out.recovery_changed = theirs.recovery_changed;
        changed = true;
    }
    Ok((out, changed))
}

/// When an object was created, and its id.
type Dated = (jiff::Timestamp, String);

/// Entities or records created with the same name on two computers (each
/// with its own random id) become one: the oldest keeps its id, and what
/// was in the others moves into it. Returns how many were folded.
fn fold_duplicates(v: &mut Vault) -> usize {
    let mut folded = 0;
    loop {
        let mut changed = false;
        // Entities with the same parent and name.
        let mut groups: BTreeMap<(Option<String>, String), Vec<Dated>> = BTreeMap::new();
        for e in v.entities.values() {
            groups
                .entry((e.parent.clone(), e.name.clone()))
                .or_default()
                .push((e.created, e.id.clone()));
        }
        for (_, mut ids) in groups.into_iter().filter(|(_, ids)| ids.len() > 1) {
            ids.sort();
            let keep = ids[0].1.clone();
            for (_, dup) in &ids[1..] {
                let (Some(Object::Entity(k)), Some(Object::Entity(d))) =
                    (v.object(&keep), v.object(dup))
                else {
                    continue;
                };
                let merged = merge::merge_entity_copies(&k, &d);
                v.replace_object(Object::Entity(merged));
                let children: Vec<String> = v
                    .entities
                    .values()
                    .filter(|e| e.parent.as_deref() == Some(dup.as_str()))
                    .map(|e| e.id.clone())
                    .collect();
                for c in children {
                    if let Some(Object::Entity(mut e)) = v.object(&c) {
                        e.parent = Some(keep.clone());
                        v.replace_object(Object::Entity(e));
                    }
                }
                let records: Vec<String> = v
                    .records
                    .values()
                    .filter(|r| r.entity == *dup)
                    .map(|r| r.id.clone())
                    .collect();
                for r in records {
                    if let Some(Object::Record(mut rec)) = v.object(&r) {
                        rec.entity = keep.clone();
                        v.replace_object(Object::Record(rec));
                    }
                }
                v.remove_object(dup);
                folded += 1;
                changed = true;
            }
        }
        // Records with the same entity and name.
        let mut groups: BTreeMap<(String, String), Vec<Dated>> = BTreeMap::new();
        for r in v.records.values() {
            groups
                .entry((r.entity.clone(), r.name.clone()))
                .or_default()
                .push((r.created, r.id.clone()));
        }
        for (_, mut ids) in groups.into_iter().filter(|(_, ids)| ids.len() > 1) {
            ids.sort();
            let keep = ids[0].1.clone();
            for (_, dup) in &ids[1..] {
                let (Some(Object::Record(k)), Some(Object::Record(d))) =
                    (v.object(&keep), v.object(dup))
                else {
                    continue;
                };
                let mut merged = merge::merge_record(None, &k, &d);
                merged.id = keep.clone();
                v.replace_object(Object::Record(merged));
                v.remove_object(dup);
                folded += 1;
                changed = true;
            }
        }
        if !changed {
            return folded;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_object_paths_are_accepted() {
        assert_eq!(object_id("objects/abc123.age"), Some("abc123"));
        assert_eq!(object_id("objects/../x.age"), None);
        assert_eq!(object_id("objects/a/b.age"), None);
        assert_eq!(object_id("lock"), None);
        assert!(check_remote("--upload-pack=x").is_err());
        assert!(check_remote("git@host:me/vault.git").is_ok());
    }
}
