//! `cemi share`: one entity, chosen environments only, to another vault.

mod common;

use common::*;

const DEV: &str = "sk_dev_value_111aaa";
const DEV2: &str = "sk_dev_value_222bbb";
const PROD: &str = "sk_prod_value_999zzz";
const OTHER: &str = "other_secret_555yyy";

fn vault() -> Env {
    let env = Env::new();
    env.ok(
        &["--password-stdin", "init", "--global"],
        &format!("{PASSWORD}\n"),
    );
    env
}

fn reveal(env: &Env, reference: &str, e: &str) -> (i32, String) {
    let (code, out, _) = env.run(
        &["--password-stdin", "reveal", reference, "-e", e],
        &format!("{PASSWORD}\n"),
    );
    (code, out.trim().to_string())
}

#[test]
fn a_second_developer_gets_only_the_shared_entity_and_environment() {
    let alice = vault();
    let bob = vault();
    alice.ok(&["add", "acme/shop/stripe"], "");
    alice.ok(
        &["field", "add", "acme/shop/stripe", "secret", "--secret"],
        "",
    );
    alice.ok(
        &["set", "acme/shop/stripe#secret", "-e", "dev", "--stdin"],
        DEV,
    );
    alice.ok(
        &["set", "acme/shop/stripe#secret", "-e", "prod", "--stdin"],
        PROD,
    );
    alice.ok(&["note", "acme/shop/stripe", "--purpose", "payments"], "");
    alice.ok(&["add", "acme/other/x"], "");
    alice.ok(&["field", "add", "acme/other/x", "k", "--secret"], "");
    alice.ok(&["set", "acme/other/x#k", "-e", "dev", "--stdin"], OTHER);
    alice.ok(
        &[
            "dest",
            "add",
            "acme/shop/stripe#secret",
            "-e",
            "dev",
            "dotenv",
            "--key",
            "STRIPE",
        ],
        "",
    );

    let key = bob.ok(&["share", "key"], "").trim().to_string();
    assert!(key.starts_with("age1"), "{key}");

    let (_, _, err) = alice.run(
        &[
            "share",
            "acme/shop",
            "--with",
            &key,
            "-e",
            "dev",
            "--name",
            "bob",
            "-o",
            "shop.share.age",
        ],
        "",
    );
    assert!(err.contains("1 records, 1 values (dev)"), "{err}");
    assert!(
        err.contains("Left out:") && err.contains("destinations"),
        "{err}"
    );
    let bundle = alice.project.join("shop.share.age");
    let text = std::fs::read_to_string(&bundle).unwrap();
    assert!(
        text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
        "{text}"
    );
    for clear in [DEV, PROD, OTHER, "stripe", "acme"] {
        assert!(!text.contains(clear), "{clear} in the bundle");
    }

    // Alice cannot open what she sent to Bob.
    let (code, _, err) = alice.run(&["share", "accept", bundle.to_str().unwrap()], "");
    assert_eq!(code, 4, "{err}");

    let out = bob.ok(&["share", "accept", bundle.to_str().unwrap()], "");
    let _ = out;
    let ls = bob.ok(&["ls", "--all"], "");
    assert!(ls.contains("stripe"), "{ls}");
    assert!(!ls.contains("other"), "{ls}");
    assert_eq!(
        reveal(&bob, "acme/shop/stripe#secret", "dev"),
        (0, DEV.into())
    );
    let (code, out) = reveal(&bob, "acme/shop/stripe#secret", "prod");
    assert_ne!(code, 0);
    assert!(!out.contains(PROD));
    let show = bob.ok(&["show", "acme/shop/stripe"], "");
    assert!(
        show.contains("received from age1") && show.contains("payments"),
        "{show}"
    );
    assert!(!show.contains("copied to"), "{show}");

    // Alice changes the value: status says to send it again.
    std::thread::sleep(std::time::Duration::from_millis(20));
    alice.ok(
        &["set", "acme/shop/stripe#secret", "-e", "dev", "--stdin"],
        DEV2,
    );
    let status = alice.ok(&["status"], "");
    assert!(
        status.contains("shared with bob") && status.contains("acme/shop/stripe#secret (dev)"),
        "{status}"
    );
    let ls = alice.ok(&["share", "ls"], "");
    assert!(
        ls.contains("acme/shop") && ls.contains("changed since"),
        "{ls}"
    );
    alice.ok(
        &[
            "share",
            "acme/shop",
            "--with",
            &key,
            "-e",
            "dev",
            "--name",
            "bob",
            "-o",
            "shop2.share.age",
        ],
        "",
    );
    let status = alice.ok(&["status"], "");
    assert!(!status.contains("shared with bob"), "{status}");
    let bundle2 = alice.project.join("shop2.share.age");
    bob.ok(&["share", "accept", bundle2.to_str().unwrap()], "");
    assert_eq!(
        reveal(&bob, "acme/shop/stripe#secret", "dev"),
        (0, DEV2.into())
    );
    // The older bundle again: nothing goes back.
    bob.ok(&["share", "accept", bundle.to_str().unwrap()], "");
    assert_eq!(
        reveal(&bob, "acme/shop/stripe#secret", "dev"),
        (0, DEV2.into())
    );

    // Somewhere else in Bob's vault.
    bob.ok(
        &[
            "share",
            "accept",
            bundle2.to_str().unwrap(),
            "--as",
            "clients/acme",
        ],
        "",
    );
    assert_eq!(
        reveal(&bob, "clients/acme/stripe#secret", "dev"),
        (0, DEV2.into())
    );
}

#[test]
fn sharing_production_values_needs_the_password() {
    let alice = vault();
    let bob = vault();
    alice.ok(&["add", "acme/shop/stripe"], "");
    alice.ok(
        &["field", "add", "acme/shop/stripe", "secret", "--secret"],
        "",
    );
    alice.ok(
        &["set", "acme/shop/stripe#secret", "-e", "prod", "--stdin"],
        PROD,
    );
    let key = bob.ok(&["share", "key"], "").trim().to_string();
    let (code, _, err) = alice.run(
        &[
            "--password-stdin",
            "share",
            "acme/shop",
            "--with",
            &key,
            "-e",
            "prod",
        ],
        "wrong password here\n",
    );
    assert_ne!(code, 0, "{err}");
    alice.ok(
        &[
            "--password-stdin",
            "share",
            "acme/shop",
            "--with",
            &key,
            "-e",
            "prod",
        ],
        &format!("{PASSWORD}\n"),
    );
    assert!(alice.project.join("acme-shop.share.age").is_file());
    let (code, _, err) = alice.run(
        &["share", "acme/shop", "--with", "age1nope", "-e", "dev"],
        "",
    );
    assert_ne!(code, 0, "{err}");
}
