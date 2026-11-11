//! `cemi import --discover`: finding the .env files of several projects.

mod common;

use std::path::Path;
use std::process::Command;

use common::*;

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(["-c", "user.email=test@example.com", "-c", "user.name=test"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?}");
}

/// Runs `cemi run -e <env>` in `dir` and returns what the program printed.
fn run_in(env: &Env, dir: &Path, cemi_env: &str, var: &str) -> String {
    let mut args = vec!["run", "-e", cemi_env, "--"];
    let print = print_var_command(var);
    args.extend(print.iter().map(String::as_str));
    let out = env.cmd(&args).current_dir(dir).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn discover_finds_warns_and_imports() {
    let env = Env::new();
    env.setup();
    let code = env.project.join("code");

    // shop: a committed .env.production, an ignored .env.local, and a .env for all.
    let shop = code.join("shop");
    write(
        &shop.join(".env"),
        "PORT=3000\nSTRIPE_KEY=sk_base_value_000\n",
    );
    write(
        &shop.join(".env.local"),
        "STRIPE_KEY=sk_test_shared_value_1\n",
    );
    write(
        &shop.join(".env.production"),
        "STRIPE_KEY=sk_live_value_222\n",
    );
    write(&shop.join(".env.example"), "STRIPE_KEY=\n");
    write(&shop.join(".gitignore"), ".env\n.env.local\n");
    git(&shop, &["init", "-q"]);
    git(&shop, &["add", ".gitignore", ".env.production"]);
    git(&shop, &["commit", "-qm", "init"]);

    // blog/web: in a repository without a .gitignore, and it repeats a value of shop.
    let web = code.join("blog").join("web");
    write(&web.join(".env"), "PAYMENTS=sk_test_shared_value_1\n");
    git(&web, &["init", "-q"]);

    // Dependencies are not projects.
    write(
        &code.join("shop/node_modules/lib/.env"),
        "LIB_SECRET=nothing\n",
    );

    // Without --yes and without a terminal: a report, and nothing changes.
    let (code_, out, _) = env.run(&["import", "--discover", "code"], "");
    assert_eq!(code_, 0, "{out}");
    assert!(out.contains("Found 4 .env files in 2 folders"), "{out}");
    assert!(out.contains("shop  →  global:shop"), "{out}");
    assert!(!out.contains("node_modules"), "{out}");
    assert!(!out.contains(".env.example"), "{out}");
    assert!(
        out.contains("shop/.env.production is committed to git"),
        "{out}"
    );
    assert!(out.contains("web/.env is not in .gitignore"), "{out}");
    assert!(
        out.contains("The same value is in PAYMENTS in web/.env, STRIPE_KEY in shop/.env.local"),
        "{out}"
    );
    assert!(out.contains("Nothing imported"), "{out}");
    assert!(!shop.join("cemi.toml").exists());

    // Import.
    env.ok(&["import", "--discover", "code", "--yes"], "");
    let toml = std::fs::read_to_string(shop.join("cemi.toml")).unwrap();
    assert!(toml.contains("vault = \"global\""), "{toml}");
    assert!(toml.contains("entity = \"shop\""), "{toml}");
    assert!(toml.contains("STRIPE_KEY = \"STRIPE_KEY#value\""), "{toml}");
    // .env is for every environment; .env.<env> and .env.local override it.
    assert_eq!(
        run_in(&env, &shop, "prod", "STRIPE_KEY"),
        "sk_live_value_222"
    );
    assert_eq!(run_in(&env, &shop, "prod", "PORT"), "3000");
    assert_eq!(
        run_in(&env, &shop, "dev", "STRIPE_KEY"),
        "sk_test_shared_value_1"
    );
    assert_eq!(
        run_in(&env, &web, "dev", "PAYMENTS"),
        "sk_test_shared_value_1"
    );
    // Secrets stay secret: AI clients and `show` do not see them.
    let show = env.ok(&["show", "global:shop/STRIPE_KEY"], "");
    assert!(!show.contains("sk_"), "{show}");

    // Importing again changes nothing.
    let (_, _, err) = env.run(&["import", "--discover", "code", "--yes"], "");
    assert!(
        err.contains("shop → global:shop (all, dev, prod; 0 new, 0 updated, 4 already there)"),
        "{err}"
    );
    let hist = env.ok(
        &["history", "global:shop/STRIPE_KEY#value", "-e", "dev"],
        "",
    );
    assert_eq!(hist.matches("  v").count(), 1, "{hist}");
}

#[test]
fn discover_without_a_vault_only_reports() {
    let env = Env::new();
    write(&env.project.join("app/.env"), "TOKEN=abcdefghijk\n");
    let out = env.ok(&["import", "--discover", "--yes"], "");
    assert!(out.contains("app  →  global:app"), "{out}");
    assert!(out.contains("create the global vault first"), "{out}");
}
