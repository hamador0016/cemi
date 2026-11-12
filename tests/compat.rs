//! Vaults made by older versions of Cemí must keep opening. The vaults in
//! tests/fixtures were made with those versions' own binaries (test values
//! and the test password only); every new version runs this.

mod common;

use std::path::Path;

use common::*;

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn reveal(env: &Env, reference: &str, e: Option<&str>) -> String {
    let mut args = vec!["--password-stdin", "reveal", reference];
    if let Some(e) = e {
        args.extend(["-e", e]);
    }
    env.ok(&args, &format!("{PASSWORD}\n")).trim().to_string()
}

#[test]
fn a_vault_from_v0_1_still_opens() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v0.1");
    let env = Env::new();
    copy_dir(&fixture.join("global"), &env.home);
    copy_dir(&fixture.join("local"), &env.project.join(".cemi"));
    std::fs::copy(fixture.join("cemi.toml"), env.project.join("cemi.toml")).unwrap();

    // A wrong password is still refused; the right one opens both vaults.
    let (code, _, _) = env.run(&["--password-stdin", "unlock"], "not the password\n");
    assert_ne!(code, 0);
    env.ok(&["--password-stdin", "unlock"], &format!("{PASSWORD}\n"));

    let ls = env.ok(&["-g", "ls", "--all"], "");
    assert!(ls.contains("stripe  [secret*, publishable, url]"), "{ls}");
    let show = env.ok(&["-g", "show", "acme/shop/stripe"], "");
    assert!(show.contains("payments for the shop"), "{show}");
    assert_eq!(
        reveal(&env, "global:acme/shop/stripe#secret", Some("dev")),
        "sk_test_compat_dev_111"
    );
    assert_eq!(
        reveal(&env, "global:acme/shop/stripe#secret", Some("prod")),
        "sk_test_compat_prod_444"
    );
    assert_eq!(
        reveal(&env, "global:acme/shop/stripe#url", None),
        "https://x/pk_test_compat_222"
    );
    assert_eq!(reveal(&env, "db#password", None), "local_db_pass_333");
    let out = env.ok(
        &[
            &["run", "--"][..],
            &print_var_command("DB_PASSWORD")
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()[..],
        ]
        .concat(),
        "",
    );
    assert!(out.contains("local_db_pass_333"), "{out}");
    let tokens = env.ok(&["token", "ls"], "");
    assert!(tokens.contains("bot"), "{tokens}");
    env.ok(&["-g", "log", "--verify"], "");
    env.ok(&["log", "--verify"], "");

    // The first change signs the old vault; it keeps opening afterwards.
    env.ok(
        &[
            "-g",
            "set",
            "acme/shop/stripe#secret",
            "-e",
            "dev",
            "--stdin",
        ],
        "sk_test_compat_dev_555",
    );
    env.ok(&["set", "db#password", "--stdin"], "local_db_pass_666");
    let header = std::fs::read_to_string(env.home.join("vault.json")).unwrap();
    assert!(header.contains("\"mac\""), "{header}");
    env.ok(&["lock"], "");
    env.ok(&["--password-stdin", "unlock"], &format!("{PASSWORD}\n"));
    assert_eq!(
        reveal(&env, "global:acme/shop/stripe#secret", Some("dev")),
        "sk_test_compat_dev_555"
    );
    assert_eq!(
        reveal(&env, "global:acme/shop/stripe#secret", Some("prod")),
        "sk_test_compat_prod_444"
    );
    assert_eq!(reveal(&env, "db#password", None), "local_db_pass_666");
    let history = env.ok(
        &["-g", "history", "acme/shop/stripe#secret", "-e", "dev"],
        "",
    );
    assert!(
        history.contains("archived") && history.contains("active"),
        "{history}"
    );
}
