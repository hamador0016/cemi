//! Presets: `cemi init --preset` and `cemi preset add`.

mod common;

use common::*;

#[test]
fn init_with_presets_builds_the_structure() {
    let env = Env::new();
    env.ok(
        &["--password-stdin", "init", "--global"],
        &format!("{PASSWORD}\n"),
    );
    // A wrong name stops before anything is created.
    let (code, _, err) = env.run(&["init", "--preset", "nope"], "");
    assert_ne!(code, 0);
    assert!(err.contains("next-supabase"), "{err}");
    assert!(!env.project.join(".cemi").exists());

    let (_, _, err) = env.run(
        &["init", "--preset", "next-supabase", "--preset", "postgres"],
        "",
    );
    assert!(err.contains("2 records, 5 fields"), "{err}");
    assert!(err.contains("cemi set supabase#secret-key -e dev"), "{err}");
    let toml = std::fs::read_to_string(env.project.join("cemi.toml")).unwrap();
    for line in [
        "NEXT_PUBLIC_SUPABASE_URL = \"supabase#url\"",
        "SUPABASE_SECRET_KEY = \"supabase#secret-key\"",
        "DATABASE_URL = \"db#url\"",
    ] {
        assert!(toml.contains(line), "{toml}");
    }
    // Memory notes come with the records; secrets are marked secret.
    let show = env.ok(&["show", "supabase"], "");
    assert!(show.contains("bypasses Row Level Security"), "{show}");
    assert!(show.contains("secret-key  [text, secret]"), "{show}");

    // The template is ready: only the password is missing.
    env.ok(&["set", "db#password", "-e", "dev", "--stdin"], SECRET);
    let mut args = vec!["run", "-e", "dev", "--"];
    let print = print_var_command("DATABASE_URL");
    args.extend(print.iter().map(String::as_str));
    // The Supabase values are still missing, so run refuses.
    let (code, _, err) = env.run(&args, "");
    assert_ne!(code, 0);
    assert!(err.contains("supabase#url"), "{err}");

    // Applying again changes nothing and does not warn.
    let (code, _, err) = env.run(&["preset", "add", "postgres"], "");
    assert_eq!(code, 0);
    assert!(err.contains("0 records, 0 fields, 0 notes"), "{err}");
    assert!(!err.contains("left as it was"), "{err}");
    assert!(!err.contains("cemi set db#password"), "{err}");
}

#[test]
fn preset_into_an_entity_points_the_project_at_it() {
    let env = Env::new();
    env.setup();
    env.ok(&["preset", "add", "resend", "--into", "acme"], "");
    let toml = std::fs::read_to_string(env.project.join("cemi.toml")).unwrap();
    assert!(
        toml.contains("RESEND_API_KEY = \"acme/resend#api-key\""),
        "{toml}"
    );
    env.ok(
        &["set", "acme/resend#api-key", "-e", "dev", "--stdin"],
        SECRET,
    );
    let mut args = vec!["run", "-e", "dev", "--"];
    let print = print_var_command("RESEND_API_KEY");
    args.extend(print.iter().map(String::as_str));
    assert_eq!(env.ok(&args, "").trim(), SECRET);
}
