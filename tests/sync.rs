//! `cemi sync`: one vault on two computers through a bare git repository.

mod common;

use std::path::Path;
use std::process::Command;

use common::*;

const A1: &str = "sync_secret_AAA111";
const B2: &str = "sync_secret_BBB222";
const C3: &str = "sync_secret_CCC333";
const NEW_PASSWORD: &str = "a brand new long password";

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn reveal(env: &Env, reference: &str) -> String {
    env.ok(
        &["--password-stdin", "reveal", reference, "-e", "dev"],
        &format!("{PASSWORD}\n"),
    )
    .trim()
    .to_string()
}

#[test]
fn two_computers_share_one_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let bare = tmp.path().join("vault.git");
    git(
        tmp.path(),
        &["init", "-q", "--bare", bare.to_str().unwrap()],
    );
    let remote = bare.to_str().unwrap();

    let a = Env::new();
    a.ok(
        &["--password-stdin", "init", "--global"],
        &format!("{PASSWORD}\n"),
    );
    a.ok(&["add", "acme/shop/stripe"], "");
    a.ok(
        &["field", "add", "acme/shop/stripe", "secret", "--secret"],
        "",
    );
    a.ok(
        &["set", "acme/shop/stripe#secret", "-e", "dev", "--stdin"],
        A1,
    );
    let (code, _, err) = a.run(&["sync"], "");
    assert_eq!(code, 4, "{err}");
    a.ok(&["sync", "init", remote], "");
    let (code, _, err) = a.run(&["sync", "init", remote], "");
    assert_ne!(code, 0, "{err}");

    // The second computer copies it and opens it with the same password.
    let b = Env::new();
    b.ok(&["-g", "sync", "clone", remote], "");
    b.ok(&["--password-stdin", "unlock"], &format!("{PASSWORD}\n"));
    assert_eq!(reveal(&b, "acme/shop/stripe#secret"), A1);

    // Both change the same value, and each adds a record.
    a.ok(
        &["set", "acme/shop/stripe#secret", "-e", "dev", "--stdin"],
        B2,
    );
    a.ok(&["add", "acme/shop/from-a"], "");
    std::thread::sleep(std::time::Duration::from_millis(30));
    b.ok(
        &["set", "acme/shop/stripe#secret", "-e", "dev", "--stdin"],
        C3,
    );
    b.ok(&["add", "acme/shop/from-b"], "");
    // The same new entity and record, created on both before syncing.
    a.ok(&["add", "acme/billing/card"], "");
    b.ok(&["add", "acme/billing/card"], "");
    a.ok(&["sync"], "");
    let (_, _, err) = b.run(&["sync"], "");
    assert!(err.contains("merged 1"), "{err}");
    a.ok(&["sync"], "");

    for env in [&a, &b] {
        let ls = env.ok(&["ls", "--all"], "");
        assert!(ls.contains("from-a") && ls.contains("from-b"), "{ls}");
        assert_eq!(ls.matches("billing").count(), 1, "{ls}");
        assert_eq!(ls.matches("card").count(), 1, "{ls}");
        // The newest value is current; the other one is kept in the history.
        assert_eq!(reveal(env, "acme/shop/stripe#secret"), C3);
        let history = env.ok(&["history", "acme/shop/stripe#secret", "-e", "dev"], "");
        assert_eq!(history.matches("archived").count(), 2, "{history}");
        assert_eq!(history.matches("active").count(), 1, "{history}");
    }

    // A password changed on one computer works on the other.
    a.ok(
        &["--password-stdin", "passwd"],
        &format!("{NEW_PASSWORD}\n"),
    );
    a.ok(&["sync"], "");
    let (_, _, err) = b.run(&["sync"], "");
    assert!(err.contains("password or recovery code changed"), "{err}");
    b.ok(&["lock"], "");
    let (code, _, _) = b.run(&["--password-stdin", "unlock"], &format!("{PASSWORD}\n"));
    assert_ne!(code, 0);
    b.ok(
        &["--password-stdin", "unlock"],
        &format!("{NEW_PASSWORD}\n"),
    );

    // Only encrypted vault files are in the repository, and no value or name
    // appears in any git object.
    let files = git(&bare, &["ls-tree", "-r", "--name-only", "main"]);
    for f in files.lines() {
        assert!(
            f == "vault.json" || (f.starts_with("objects/") && f.ends_with(".age")),
            "{f} is in the repository"
        );
    }
    let all = Command::new("git")
        .current_dir(&bare)
        .args(["cat-file", "--batch-all-objects", "--batch"])
        .output()
        .unwrap();
    let all = String::from_utf8_lossy(&all.stdout);
    assert!(all.contains("vault.json"), "the objects were read");
    for clear in [A1, B2, C3, "stripe", "acme", "from-a"] {
        assert!(
            !all.contains(clear),
            "{clear} is readable in the repository"
        );
    }
}

/// Someone who can push to the repository (or the git host) tries to put
/// back old files and to add a file of their own.
#[test]
fn the_repository_cannot_roll_back_or_forge() {
    let tmp = tempfile::tempdir().unwrap();
    let bare = tmp.path().join("vault.git");
    git(
        tmp.path(),
        &["init", "-q", "--bare", bare.to_str().unwrap()],
    );
    let remote = bare.to_str().unwrap();
    let a = Env::new();
    a.ok(
        &["--password-stdin", "init", "--global"],
        &format!("{PASSWORD}\n"),
    );
    a.ok(&["add", "acme/shop/stripe"], "");
    a.ok(
        &["field", "add", "acme/shop/stripe", "secret", "--secret"],
        "",
    );
    a.ok(
        &["set", "acme/shop/stripe#secret", "-e", "dev", "--stdin"],
        A1,
    );
    a.ok(&["sync", "init", remote], "");
    a.ok(
        &["set", "acme/shop/stripe#secret", "-e", "dev", "--stdin"],
        B2,
    );
    a.ok(&["sync"], "");

    let attacker = tmp.path().join("attacker");
    git(
        tmp.path(),
        &[
            "clone",
            "-q",
            "--branch",
            "main",
            remote,
            attacker.to_str().unwrap(),
        ],
    );
    let push = |message: &str| {
        git(&attacker, &["add", "-A"]);
        git(
            &attacker,
            &[
                "-c",
                "user.name=x",
                "-c",
                "user.email=x@x",
                "commit",
                "-q",
                "-m",
                message,
            ],
        );
        git(&attacker, &["push", "-q", "origin", "main"]);
    };

    // 1. The record's file before the last change is put back.
    let changed = git(
        &attacker,
        &["diff", "--name-only", "HEAD~1", "HEAD", "--", "objects"],
    );
    for f in changed.lines() {
        git(&attacker, &["checkout", "HEAD~1", "--", f]);
    }
    push("put back the old key");
    a.ok(&["sync"], "");
    assert_eq!(reveal(&a, "acme/shop/stripe#secret"), B2);

    // 2. The old password is put back after a change.
    a.ok(
        &["--password-stdin", "passwd"],
        &format!("{NEW_PASSWORD}\n"),
    );
    a.ok(&["sync"], "");
    git(&attacker, &["pull", "-q", "origin", "main"]);
    let first = git(&attacker, &["rev-list", "--max-parents=0", "HEAD"]);
    git(&attacker, &["checkout", first.trim(), "--", "vault.json"]);
    push("put back the old password");
    a.ok(&["sync"], "");
    a.ok(&["lock"], "");
    let (code, _, _) = a.run(&["--password-stdin", "unlock"], &format!("{PASSWORD}\n"));
    assert_ne!(code, 0, "the old password opens the vault again");
    a.ok(
        &["--password-stdin", "unlock"],
        &format!("{NEW_PASSWORD}\n"),
    );

    // 3. A token of their own, encrypted to the vault's public key.
    git(&attacker, &["pull", "-q", "origin", "main"]);
    let key = a.ok(&["share", "key"], "").trim().to_string();
    let forged = serde_json::json!({
        "format": 1,
        "object": {
            "type": "token", "id": "f0f0f0f0f0f0f0f0", "name": "eve",
            "hash": "00", "entities": [], "envs": [], "allow": ["read"],
            "expires": null, "created": "2026-11-11T00:00:00Z"
        }
    });
    let ct = cemi::crypto::age_encrypt(
        &cemi::crypto::parse_recipient(&key).unwrap(),
        forged.to_string().as_bytes(),
    )
    .unwrap();
    std::fs::write(attacker.join("objects").join("f0f0f0f0f0f0f0f0.age"), ct).unwrap();
    push("add a token");
    let (code, _, err) = a.run(&["sync"], "");
    assert_ne!(code, 0);
    assert!(err.contains("not written with this vault's key"), "{err}");
    let tokens = a.ok(&["token", "ls"], "");
    assert!(!tokens.contains("eve"), "{tokens}");
    // Nothing was left half done.
    assert!(!a.home.join(".git").join("MERGE_HEAD").exists());
    assert!(!a.home.join("objects").join("f0f0f0f0f0f0f0f0.age").exists());
}
