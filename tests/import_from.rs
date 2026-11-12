//! `cemi import --from doppler|1password`, with stand-ins for the `doppler`
//! and `op` programs that print fixed JSON and log their arguments.

mod common;

use std::path::{Path, PathBuf};
use std::process::Stdio;

use common::*;

const DOPPLER_JSON: &str = r#"{
  "API_KEY": "doppler-value-1111",
  "DATABASE_URL": "postgres://app:fake-db-value-222@localhost/app",
  "PUBLIC_URL": "https://shop.example.com",
  "DOPPLER_CONFIG": "dev",
  "DOPPLER_ENVIRONMENT": "dev",
  "DOPPLER_PROJECT": "shop"
}"#;

const OP_LIST: &str = r#"[
  {"id": "item1", "title": "GitHub", "category": "LOGIN", "vault": {"id": "v1", "name": "Work"}},
  {"id": "item2", "title": "Payments API", "category": "API_CREDENTIAL", "vault": {"id": "v1", "name": "Work"}},
  {"id": "item3", "title": "Contract scan", "category": "DOCUMENT", "vault": {"id": "v1", "name": "Work"}}
]"#;

const OP_ITEM1: &str = r#"{
  "id": "item1", "title": "GitHub", "category": "LOGIN",
  "vault": {"id": "v1", "name": "Work"},
  "fields": [
    {"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": "octo-tester"},
    {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "fake-op-password-333"},
    {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": "recovery codes are in the safe"}
  ],
  "files": [{"id": "f1", "name": "backup-codes.txt", "size": 12}],
  "urls": [{"label": "website", "primary": true, "href": "https://github.com/login"}]
}"#;

const OP_ITEM2: &str = r#"{
  "id": "item2", "title": "Payments API", "category": "API_CREDENTIAL",
  "fields": [
    {"id": "credential", "type": "CONCEALED", "label": "credential", "value": "op-credential-4444"},
    {"id": "expires", "type": "DATE", "label": "expires", "value": 1893456000},
    {"id": "s1f1", "type": "CONCEALED", "label": "webhook secret", "section": {"id": "s1", "label": "Webhooks"}, "value": "fake-op-webhook-555"}
  ]
}"#;

const OP_ITEM3: &str = r#"{
  "id": "item3", "title": "Contract scan", "category": "DOCUMENT",
  "files": [{"id": "f2", "name": "contract.pdf", "size": 1000}]
}"#;

const VALUES: [&str; 6] = [
    "doppler-value-1111",
    "fake-db-value-222",
    "fake-op-password-333",
    "op-credential-4444",
    "fake-op-webhook-555",
    "recovery codes",
];

/// A folder with fake `doppler` and `op` programs and their fixtures.
struct Fakes {
    bin: PathBuf,
    log: PathBuf,
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn fakes(env: &Env) -> Fakes {
    let bin = env.project.parent().unwrap().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = bin.join("args.log");
    for (name, text) in [
        ("doppler.json", DOPPLER_JSON),
        ("op-list.json", OP_LIST),
        ("op-item-item1.json", OP_ITEM1),
        ("op-item-item2.json", OP_ITEM2),
        ("op-item-item3.json", OP_ITEM3),
    ] {
        std::fs::write(bin.join(name), text).unwrap();
    }
    if cfg!(windows) {
        let dir = bin.display().to_string();
        let log = log.display().to_string();
        std::fs::write(
            bin.join("doppler.cmd"),
            format!(
                "@echo off\r\n\
                 echo doppler %*>> \"{log}\"\r\n\
                 if exist \"{dir}\\signed-out\" (echo Doppler Error: you must log in 1>&2 & exit /b 1)\r\n\
                 type \"{dir}\\doppler.json\"\r\n"
            ),
        )
        .unwrap();
        std::fs::write(
            bin.join("op.cmd"),
            format!(
                "@echo off\r\n\
                 echo op %*>> \"{log}\"\r\n\
                 if exist \"{dir}\\signed-out\" (echo [ERROR] account is not signed in 1>&2 & exit /b 1)\r\n\
                 if \"%1 %2\"==\"item list\" (type \"{dir}\\op-list.json\" & exit /b 0)\r\n\
                 if \"%1 %2\"==\"item get\" (type \"{dir}\\op-item-%3.json\" & exit /b 0)\r\n\
                 exit /b 2\r\n"
            ),
        )
        .unwrap();
    } else {
        let dir = slash(&bin);
        let log_s = slash(&log);
        let doppler = format!(
            "#!/bin/sh\n\
             printf 'doppler %s\\n' \"$*\" >> '{log_s}'\n\
             if [ -f '{dir}/signed-out' ]; then echo 'Doppler Error: you must log in' >&2; exit 1; fi\n\
             cat '{dir}/doppler.json'\n"
        );
        let op = format!(
            "#!/bin/sh\n\
             printf 'op %s\\n' \"$*\" >> '{log_s}'\n\
             if [ -f '{dir}/signed-out' ]; then echo '[ERROR] account is not signed in' >&2; exit 1; fi\n\
             case \"$1 $2\" in\n\
               'item list') cat '{dir}/op-list.json' ;;\n\
               'item get') cat \"{dir}/op-item-$3.json\" ;;\n\
               *) exit 2 ;;\n\
             esac\n"
        );
        for (name, text) in [("doppler", doppler), ("op", op)] {
            let p = bin.join(name);
            std::fs::write(&p, text).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
    }
    Fakes { bin, log }
}

/// Runs cemi with `path_first` before the usual PATH (or as the only folder).
fn run_with_path(
    env: &Env,
    path_first: &Path,
    only: bool,
    args: &[&str],
    stdin: &str,
) -> (i32, String, String) {
    let mut dirs = vec![path_first.to_path_buf()];
    if !only {
        dirs.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
    }
    let mut c = env.cmd(args);
    c.env("PATH", std::env::join_paths(dirs).unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn reveal(env: &Env, reference: &str, e: Option<&str>) -> String {
    let mut args = vec!["--password-stdin", "reveal", reference];
    if let Some(e) = e {
        args.extend(["-e", e]);
    }
    env.ok(&args, &format!("{PASSWORD}\n")).trim().to_string()
}

fn assert_no_values(text: &str) {
    for v in VALUES {
        assert!(!text.contains(v), "a value leaked: {v} in\n{text}");
    }
}

#[test]
fn doppler_previews_then_imports() {
    let env = Env::new();
    env.setup();
    let f = fakes(&env);
    let args = [
        "import",
        "--from",
        "doppler",
        "--project",
        "shop",
        "--config",
        "dev",
        "-e",
        "dev",
        "--plain",
        "PUBLIC_URL",
    ];

    // Without --yes and without a terminal: the names, and nothing changes.
    let (code, out, err) = run_with_path(&env, &f.bin, false, &args, "");
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("API_KEY"), "{out}");
    assert!(out.contains("PUBLIC_URL  (plain)"), "{out}");
    assert!(!out.contains("DOPPLER_PROJECT"), "{out}");
    assert!(out.contains("Nothing imported"), "{out}");
    assert_no_values(&out);
    assert_no_values(&err);
    let toml = std::fs::read_to_string(env.project.join("cemi.toml")).unwrap();
    assert!(!toml.contains("API_KEY"), "{toml}");

    let mut yes = args.to_vec();
    yes.push("--yes");
    let (code, out, err) = run_with_path(&env, &f.bin, false, &yes, "");
    assert_eq!(code, 0, "{out}\n{err}");
    assert_no_values(&out);
    assert_no_values(&err);
    assert_eq!(
        reveal(&env, "API_KEY#value", Some("dev")),
        "doppler-value-1111"
    );
    assert!(reveal(&env, "DATABASE_URL#value", Some("dev")).contains("fake-db-value-222"));
    let toml = std::fs::read_to_string(env.project.join("cemi.toml")).unwrap();
    assert!(toml.contains("API_KEY = \"API_KEY#value\""), "{toml}");
    let show = env.ok(&["show", "PUBLIC_URL"], "");
    assert!(show.contains("https://shop.example.com"), "{show}");
    let (code, _, _) = env.run(&["show", "DOPPLER_PROJECT"], "");
    assert_ne!(code, 0, "Doppler's own variables are not imported");

    // The program got the documented arguments, and no value.
    let log = std::fs::read_to_string(&f.log).unwrap();
    assert!(
        log.contains(
            "doppler secrets download --no-file --format json --project shop --config dev"
        ),
        "{log}"
    );
    assert_no_values(&log);
}

#[test]
fn onepassword_maps_items_to_records() {
    let env = Env::new();
    env.setup();
    let f = fakes(&env);
    let args = ["import", "--from", "1password", "--vault", "Work"];

    let (code, out, err) = run_with_path(&env, &f.bin, false, &args, "");
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(
        out.contains("GitHub: username, password (secret), notes (secret), website"),
        "{out}"
    );
    assert!(
        out.contains("Payments API: credential (secret), expires, webhook secret (secret)"),
        "{out}"
    );
    assert!(out.contains("Skipped 2 file attachments"), "{out}");
    assert!(out.contains("Skipped 1 item with no value"), "{out}");
    assert!(out.contains("Nothing imported"), "{out}");
    assert_no_values(&out);
    assert_no_values(&err);

    let mut yes = args.to_vec();
    yes.push("--yes");
    let (code, out, err) = run_with_path(&env, &f.bin, false, &yes, "");
    assert_eq!(code, 0, "{out}\n{err}");
    assert_no_values(&out);
    assert_no_values(&err);

    assert_eq!(
        reveal(&env, "Work/GitHub#password", None),
        "fake-op-password-333"
    );
    assert_eq!(
        reveal(&env, "Work/GitHub#notes", None),
        "recovery codes are in the safe"
    );
    assert_eq!(
        reveal(&env, "Work/Payments API#webhook secret", None),
        "fake-op-webhook-555"
    );
    let show = env.ok(&["show", "Work/GitHub"], "");
    assert!(
        show.contains("octo-tester"),
        "plain fields are shown: {show}"
    );
    assert!(show.contains("https://github.com/login"), "{show}");
    assert_no_values(&show);
    let (code, _, _) = env.run(&["show", "Work/Contract scan"], "");
    assert_ne!(code, 0, "documents are not imported");

    // Importing again changes nothing.
    let (code, _, err) = run_with_path(&env, &f.bin, false, &yes, "");
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("2 already there"), "{err}");

    let log = std::fs::read_to_string(&f.log).unwrap();
    assert!(
        log.contains("op item list --vault Work --format json"),
        "{log}"
    );
    assert!(
        log.contains("op item get item1 --vault Work --format json --reveal"),
        "{log}"
    );
    assert_no_values(&log);
}

#[test]
fn missing_or_signed_out_programs() {
    let env = Env::new();
    env.setup();
    let f = fakes(&env);

    let empty = env.project.parent().unwrap().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let (code, _, err) = run_with_path(
        &env,
        &empty,
        true,
        &["import", "--from", "doppler", "--yes"],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("not installed"), "{err}");
    assert!(err.contains("doppler login"), "{err}");
    let (code, _, err) = run_with_path(
        &env,
        &empty,
        true,
        &["import", "--from", "1password", "--vault", "Work"],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("op signin"), "{err}");

    std::fs::write(f.bin.join("signed-out"), "").unwrap();
    let (code, _, err) = run_with_path(
        &env,
        &f.bin,
        false,
        &["import", "--from", "1password", "--vault", "Work", "--yes"],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("op signin"), "{err}");
    let (code, _, err) = run_with_path(
        &env,
        &f.bin,
        false,
        &["import", "--from", "doppler", "--yes"],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("doppler login"), "{err}");

    // Options of the other source are refused.
    let (code, _, err) = env.run(&["import", "--from", "1password", "--project", "x"], "");
    assert_ne!(code, 0);
    assert!(err.contains("--vault"), "{err}");
    let (code, _, err) = env.run(&["import", "--from", "1password"], "");
    assert_ne!(code, 0);
    assert!(err.contains("--vault"), "{err}");
}
