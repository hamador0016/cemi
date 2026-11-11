//! `cemi ci`: secrets for CI, encrypted into the repository.

mod common;

use common::*;

fn ci_key(env: &Env) -> String {
    // Reading a secret asks for the password again.
    env.ok(
        &["--password-stdin", "reveal", "cemi-ci#key"],
        &format!("{PASSWORD}\n"),
    )
    .trim()
    .to_string()
}

#[test]
fn export_and_load() {
    let env = Env::new();
    env.setup();
    env.ok(&["ci", "setup"], "");
    let toml = std::fs::read_to_string(env.project.join("cemi.toml")).unwrap();
    assert!(
        toml.contains("[ci]") && toml.contains("recipient = \"age1"),
        "{toml}"
    );
    // A second setup needs --new-key.
    let (code, _, err) = env.run(&["ci", "setup"], "");
    assert_ne!(code, 0);
    assert!(err.contains("--new-key"), "{err}");

    env.ok(&["ci", "export", "-e", "dev"], "");
    let file = env.project.join("cemi.ci.age");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("# Variables: DATABASE_URL"), "{text}");
    assert!(!text.contains(SECRET), "a value is in the clear");

    let key = ci_key(&env);
    assert!(key.starts_with("AGE-SECRET-KEY-"), "{key}");

    // GitHub Actions: masked in the log, written to $GITHUB_ENV.
    let gh_env = env.project.join("github_env");
    let out = env
        .cmd(&["ci", "load", "--github-env"])
        .env("CEMI_CI_KEY", &key)
        .env("GITHUB_ENV", &gh_env)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let url = format!("postgres://app:{SECRET}@localhost/app");
    assert!(stdout.contains(&format!("::add-mask::{url}")), "{stdout}");
    let written = std::fs::read_to_string(&gh_env).unwrap();
    assert!(written.starts_with("DATABASE_URL<<CEMI_EOF_"), "{written}");
    assert!(written.contains(&url), "{written}");

    // Any CI: one command, with the values hidden in its output.
    let mut args = vec!["ci", "load", "--"];
    let print = print_var_command("DATABASE_URL");
    args.extend(print.iter().map(String::as_str));
    let out = env.cmd(&args).env("CEMI_CI_KEY", &key).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[hidden:DATABASE_URL]"), "{stdout}");
    assert!(!stdout.contains(SECRET));

    // Another key cannot open it.
    let out = env
        .cmd(&["ci", "load", "--github-env"])
        .env(
            "CEMI_CI_KEY",
            cemi::crypto::AgeKey::generate().secret_text().as_str(),
        )
        .env("GITHUB_ENV", &gh_env)
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn export_picks_variables_and_protects_prod() {
    let env = Env::new();
    env.setup();
    env.ok(
        &["set", "db#password", "-e", "prod", "--stdin"],
        "prod-value-123",
    );
    env.ok(&["var", "add", "DB_PASSWORD", "db#password"], "");
    env.ok(&["ci", "setup"], "");

    // Only what CI needs.
    let (code, _, _) = env.run(&["ci", "export", "-e", "dev", "--only", "NOPE"], "");
    assert_eq!(code, 4);
    env.ok(&["ci", "export", "-e", "dev", "--only", "DB_PASSWORD"], "");
    let text = std::fs::read_to_string(env.project.join("cemi.ci.age")).unwrap();
    assert!(text.contains("# Variables: DB_PASSWORD\n"), "{text}");

    // prod is protected: exporting it asks for the password.
    env.ok(
        &["--password-stdin", "ci", "export", "-e", "prod"],
        &format!("{PASSWORD}\n"),
    );
    let (code, _, err) = env.run(
        &["--password-stdin", "ci", "export", "-e", "prod"],
        "not the password\n",
    );
    assert_eq!(code, 3, "{err}");
}
