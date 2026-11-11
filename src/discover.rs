//! Finding the `.env` files of your projects, for `cemi import --discover`.
//! Nothing here changes a file or a vault: it only reads and reports.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Result;
use jiff::Timestamp;
use zeroize::Zeroizing;

use crate::crypto;
use crate::dotenv;
use crate::model::{SHARED, validate_name};

/// Folders that never hold a project's own `.env`: dependencies, build
/// output, caches and tool folders.
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".cemi",
    "node_modules",
    "bower_components",
    "vendor",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".vercel",
    ".netlify",
    ".cache",
    "coverage",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".gradle",
    ".idea",
    ".vscode",
    "AppData",
    "Library",
];

/// Values shorter than this are not compared between projects: they are
/// ports, flags and words, not keys.
const MIN_COMPARED_LEN: usize = 8;

/// A file that has not changed for this many days is reported as old.
pub const OLD_AFTER_DAYS: i64 = 365;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitState {
    /// Not inside a git repository.
    NoRepo,
    /// Committed: anyone with the repository has the values.
    Tracked,
    /// Covered by .gitignore.
    Ignored,
    /// In a repository, not committed and not ignored: one `git add .` away.
    Unprotected,
}

pub struct EnvFile {
    pub path: PathBuf,
    /// The environment guessed from the file name ([`SHARED`] for `.env`).
    pub env: String,
    /// Later files override earlier ones in the same environment, the way
    /// most loaders read them (.env, then .env.<env>, then .env.local…).
    pub precedence: u8,
    pub vars: Vec<(String, Zeroizing<String>)>,
    pub modified: Option<Timestamp>,
    pub git: GitState,
    /// Why the file could not be read, if it could not.
    pub error: Option<String>,
}

impl EnvFile {
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    pub fn is_old(&self, now: Timestamp) -> bool {
        self.modified
            .is_some_and(|m| now.duration_since(m).as_secs() > OLD_AFTER_DAYS * 86_400)
    }
}

pub struct FoundProject {
    pub dir: PathBuf,
    /// Entity name for it in the vault (the folder name, made unique).
    pub name: String,
    pub files: Vec<EnvFile>,
}

impl FoundProject {
    /// Variables per environment, with later files overriding earlier ones.
    pub fn merged(&self) -> BTreeMap<String, BTreeMap<String, Zeroizing<String>>> {
        let mut files: Vec<&EnvFile> = self.files.iter().filter(|f| f.error.is_none()).collect();
        files.sort_by_key(|f| f.precedence);
        let mut out: BTreeMap<String, BTreeMap<String, Zeroizing<String>>> = BTreeMap::new();
        for f in files {
            let env = out.entry(f.env.clone()).or_default();
            for (k, v) in &f.vars {
                env.insert(k.clone(), v.clone());
            }
        }
        out
    }
}

/// The environment and precedence of a `.env` file from its name, or `None`
/// when it is not a file of values (examples, templates, dotenvx files…).
pub fn classify(file_name: &str) -> Option<(String, u8)> {
    let rest = file_name.strip_prefix(".env")?;
    if rest.is_empty() {
        // Loaders read .env in every environment; .env.<env> overrides it.
        return Some((SHARED.into(), 0));
    }
    let rest = rest.strip_prefix('.')?;
    let lower = rest.to_ascii_lowercase();
    const NOT_VALUES: &[&str] = &[
        "example", "sample", "template", "dist", "defaults", "schema", "vault", "keys", "bak",
        "old", "orig", "swp",
    ];
    if lower
        .split(['.', '-', '_'])
        .any(|part| NOT_VALUES.contains(&part))
    {
        return None;
    }
    let parts: Vec<&str> = lower.split('.').collect();
    let (name, local) = match parts.as_slice() {
        ["local"] => return Some(("dev".into(), 2)),
        [name] => (*name, false),
        [name, "local"] => (*name, true),
        _ => return None,
    };
    let env = match name {
        "development" | "dev" | "develop" => "dev",
        "production" | "prod" => "prod",
        "staging" | "stage" => "staging",
        "test" | "testing" => "test",
        other => other,
    };
    validate_name(env, "environment").ok()?;
    Some((env.to_string(), if local { 3 } else { 1 }))
}

/// Walks `root` (up to `max_depth` folders down) and groups the `.env`
/// files it finds by folder.
pub fn find(root: &Path, max_depth: usize) -> Result<Vec<FoundProject>> {
    let walker = ignore::WalkBuilder::new(root)
        // .env files are usually git-ignored, so ignore files cannot be used.
        .standard_filters(false)
        .hidden(false)
        .follow_links(false)
        .max_depth(Some(max_depth))
        .filter_entry(|e| {
            !(e.file_type().is_some_and(|t| t.is_dir())
                && e.depth() > 0
                && SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref()))
        })
        .build();
    let mut by_dir: BTreeMap<PathBuf, Vec<EnvFile>> = BTreeMap::new();
    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some((env, precedence)) = classify(&name) else {
            continue;
        };
        let path = entry.path().to_path_buf();
        let dir = path.parent().unwrap_or(root).to_path_buf();
        by_dir
            .entry(dir)
            .or_default()
            .push(read_file(path, env, precedence));
    }
    let mut projects: Vec<FoundProject> = by_dir
        .into_iter()
        .map(|(dir, mut files)| {
            files.sort_by_key(|f| (f.precedence, f.name()));
            FoundProject {
                name: String::new(),
                dir,
                files,
            }
        })
        .collect();
    name_projects(&mut projects, root);
    Ok(projects)
}

fn read_file(path: PathBuf, env: String, precedence: u8) -> EnvFile {
    let modified = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| Timestamp::try_from(t).ok());
    let git = git_state(&path);
    let (vars, error) = match std::fs::read_to_string(&path) {
        Ok(text) => {
            let text = Zeroizing::new(text);
            match dotenv::parse(&text) {
                Ok(pairs) => (
                    pairs
                        .into_iter()
                        .map(|(k, v)| (k, Zeroizing::new(v)))
                        .collect(),
                    None,
                ),
                Err(e) => (Vec::new(), Some(format!("{e:#}"))),
            }
        }
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    EnvFile {
        path,
        env,
        precedence,
        vars,
        modified,
        git,
        error,
    }
}

/// Entity names: the folder name, or more of the path when two projects
/// share a folder name ("web" and "web" become "shop-web" and "blog-web").
fn name_projects(projects: &mut [FoundProject], root: &Path) {
    let parts = |dir: &Path| -> Vec<String> {
        let rel = dir.strip_prefix(root).unwrap_or(dir);
        let mut v: Vec<String> = rel
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => Some(clean_name(&s.to_string_lossy())),
                _ => None,
            })
            .filter(|s| !s.is_empty())
            .collect();
        if v.is_empty() {
            let own = dir
                .file_name()
                .map(|n| clean_name(&n.to_string_lossy()))
                .unwrap_or_default();
            v.push(if own.is_empty() {
                "project".into()
            } else {
                own
            });
        }
        v
    };
    let all: Vec<Vec<String>> = projects.iter().map(|p| parts(&p.dir)).collect();
    for (i, p) in projects.iter_mut().enumerate() {
        let mine = &all[i];
        let mut take = 1;
        loop {
            let name = mine[mine.len() - take..].join("-");
            let clash = all.iter().enumerate().any(|(j, other)| {
                j != i && other[other.len().saturating_sub(take)..].join("-") == name
            });
            if !clash || take == mine.len() {
                p.name = name;
                break;
            }
            take += 1;
        }
    }
}

fn clean_name(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c == '/' || c == '#' || c.is_control() {
                '-'
            } else {
                c
            }
        })
        .collect();
    cleaned.trim().trim_matches('.').to_string()
}

pub fn git_state(file: &Path) -> GitState {
    let (Some(dir), Some(name)) = (file.parent(), file.file_name()) else {
        return GitState::NoRepo;
    };
    let git = |args: &[&std::ffi::OsStr]| -> Option<i32> {
        Command::new(crate::runner::resolve_program("git"))
            .args(args)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?
            .code()
    };
    let tracked = git(&[
        "ls-files".as_ref(),
        "--error-unmatch".as_ref(),
        "--".as_ref(),
        name,
    ]);
    match tracked {
        Some(0) => return GitState::Tracked,
        Some(1) => {}
        // 128: not a repository (or git is missing).
        _ => return GitState::NoRepo,
    }
    match git(&["check-ignore".as_ref(), "-q".as_ref(), "--".as_ref(), name]) {
        Some(0) => GitState::Ignored,
        Some(1) => GitState::Unprotected,
        _ => GitState::NoRepo,
    }
}

/// One value found in more than one project.
pub struct Repeated {
    /// (project name, file name, variable)
    pub places: Vec<(String, String, String)>,
}

/// Values that appear in two or more projects. Within one project, equal
/// values between environments are left to `cemi env diff`.
pub fn repeated(projects: &[FoundProject]) -> Vec<Repeated> {
    let mut seen: BTreeMap<String, Vec<(usize, String, String)>> = BTreeMap::new();
    for (i, p) in projects.iter().enumerate() {
        for f in &p.files {
            for (k, v) in &f.vars {
                if v.len() < MIN_COMPARED_LEN {
                    continue;
                }
                let places = seen.entry(crypto::sha256_hex(v.as_bytes())).or_default();
                if !places.iter().any(|(j, _, key)| *j == i && key == k) {
                    places.push((i, f.name(), k.clone()));
                }
            }
        }
    }
    let mut out: Vec<Repeated> = seen
        .into_values()
        .filter(|places| {
            let first = places[0].0;
            places.iter().any(|(j, _, _)| *j != first)
        })
        .map(|places| Repeated {
            places: places
                .into_iter()
                .map(|(i, file, key)| (projects[i].name.clone(), file, key))
                .collect(),
        })
        .collect();
    out.sort_by(|a, b| a.places.cmp(&b.places));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_give_environments() {
        assert_eq!(classify(".env"), Some((SHARED.into(), 0)));
        assert_eq!(classify(".env.local"), Some(("dev".into(), 2)));
        assert_eq!(classify(".env.development"), Some(("dev".into(), 1)));
        assert_eq!(classify(".env.development.local"), Some(("dev".into(), 3)));
        assert_eq!(classify(".env.production"), Some(("prod".into(), 1)));
        assert_eq!(classify(".env.staging"), Some(("staging".into(), 1)));
        assert_eq!(classify(".env.preview"), Some(("preview".into(), 1)));
        for not in [
            ".env.example",
            ".env.local.example",
            ".env.sample",
            ".env.vault",
            ".env.keys",
            ".envrc",
            ".environment",
            ".env.a.b.c",
            "env",
        ] {
            assert_eq!(classify(not), None, "{not}");
        }
    }

    #[test]
    fn clashing_folder_names_get_more_of_the_path() {
        let root = Path::new("/code");
        let mk = |d: &str| FoundProject {
            dir: root.join(d),
            name: String::new(),
            files: Vec::new(),
        };
        let mut ps = vec![mk("shop/web"), mk("blog/web"), mk("api")];
        name_projects(&mut ps, root);
        let names: Vec<&str> = ps.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["shop-web", "blog-web", "api"]);
    }

    #[test]
    fn repeated_values_are_found_across_projects_only() {
        let file = |name: &str, vars: &[(&str, &str)]| EnvFile {
            path: PathBuf::from(name),
            env: "dev".into(),
            precedence: 0,
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
                .collect(),
            modified: None,
            git: GitState::NoRepo,
            error: None,
        };
        let ps = vec![
            FoundProject {
                dir: "a".into(),
                name: "a".into(),
                files: vec![file(
                    ".env",
                    &[("KEY", "same-long-value"), ("PORT", "3000")],
                )],
            },
            FoundProject {
                dir: "b".into(),
                name: "b".into(),
                files: vec![
                    file(".env", &[("OTHER", "same-long-value"), ("PORT", "3000")]),
                    file(".env.local", &[("OTHER", "same-long-value")]),
                ],
            },
        ];
        let r = repeated(&ps);
        assert_eq!(r.len(), 1);
        assert_eq!(
            r[0].places,
            [
                ("a".into(), ".env".into(), "KEY".into()),
                ("b".into(), ".env".into(), "OTHER".into()),
            ]
        );
    }
}
