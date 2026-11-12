//! `--json` and exit codes: what scripts rely on.

mod common;

use common::*;

/// Runs with --json and returns (exit code, the JSON object on stdout).
fn json(env: &Env, args: &[&str]) -> (i32, serde_json::Value) {
    let mut all = vec!["--json"];
    all.extend_from_slice(args);
    let (code, out, err) = env.run(&all, "");
    let v: serde_json::Value = serde_json::from_str(out.trim())
        .unwrap_or_else(|e| panic!("not one JSON object ({e}):\n{out}\n{err}"));
    assert_eq!(v["exit_code"], code, "{v}");
    (code, v)
}

#[test]
fn read_commands_give_data_and_never_secrets() {
    let env = Env::new();
    env.setup();

    let (code, v) = json(&env, &["ls"]);
    assert_eq!(code, 0);
    assert_eq!(v["ok"], true);
    let rec = &v["data"]["records"][0];
    assert_eq!(rec["path"], "db");
    assert_eq!(rec["fields"][0]["name"], "password");
    assert_eq!(rec["fields"][0]["secret"], true);

    let (_, v) = json(&env, &["show", "db"]);
    let fields = v["data"]["fields"].as_array().unwrap();
    let password = fields.iter().find(|f| f["name"] == "password").unwrap();
    assert_eq!(password["values"][0]["set"], true);
    assert!(password["values"][0].get("value").is_none(), "{v}");
    let url = fields.iter().find(|f| f["name"] == "url").unwrap();
    assert_eq!(
        url["values"][0]["value"],
        "postgres://app:{{db#password}}@localhost/app"
    );
    assert!(!v.to_string().contains(SECRET));

    let (_, v) = json(&env, &["history", "db#password", "-e", "dev"]);
    assert_eq!(v["data"]["versions"][0]["state"], "active");

    let (_, v) = json(&env, &["var", "ls"]);
    assert_eq!(v["data"]["variables"][0]["name"], "DATABASE_URL");
    assert_eq!(v["data"]["variables"][0]["resolved"], "local:db#url");

    let (_, v) = json(&env, &["status"]);
    assert!(v["data"]["vaults"].is_array(), "{v}");

    let (_, v) = json(&env, &["env", "ls"]);
    assert_eq!(v["data"]["environments"][1]["name"], "prod");
    assert_eq!(v["data"]["environments"][1]["protected"], true);

    // Commands without data still give their text.
    let (code, v) = json(&env, &["preset", "ls"]);
    assert_eq!(code, 0);
    assert!(v["text"].as_str().unwrap().contains("next-supabase"));
}

#[test]
fn exit_codes_are_stable() {
    let env = Env::new();
    env.setup();

    // 4: not found.
    let (code, v) = json(&env, &["show", "nope"]);
    assert_eq!(code, 4);
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["kind"], "not_found");
    let (code, _, _) = env.run(&["history", "db#nope"], "");
    assert_eq!(code, 4);

    // 1: the command worked and found problems.
    env.ok(
        &[
            "dest",
            "add",
            "db#password",
            "-e",
            "dev",
            "dotenv",
            "--key",
            "DB",
        ],
        "",
    );
    let (code, v) = json(&env, &["check"]);
    assert_eq!(code, 1);
    assert_eq!(v["data"]["destinations"][0]["status"], "never_sent");

    // 5: a person has to say yes.
    let (code, v) = json(&env, &["rotate", "db#password", "-e", "dev", "--generate"]);
    assert_eq!(code, 5, "{v}");
    assert_eq!(v["error"]["kind"], "needs_person");

    // 3: locked, and the password given is wrong.
    env.ok(&["lock"], "");
    let (code, out, _) = env.run(
        &["--json", "--password-stdin", "ls"],
        "wrong one\nwrong two\nwrong three\n",
    );
    assert_eq!(code, 3, "{out}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["error"]["kind"], "locked");
    // --no-input: editors get "locked" at once instead of a password prompt.
    let (code, v) = json(&env, &["--no-input", "show", "db"]);
    assert_eq!(code, 3, "{v}");
    assert_eq!(v["error"]["kind"], "locked");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("cemi unlock"),
        "{v}"
    );

    // 2: wrong usage (from the argument parser, before any JSON).
    let (code, _, _) = env.run(&["ls", "--no-such-flag"], "");
    assert_eq!(code, 2);

    // --json does not apply where the output belongs to another program.
    let (code, v) = json(&env, &["run", "--", "x"]);
    assert_eq!(code, 9);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not apply")
    );
}
