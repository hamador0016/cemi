use std::sync::Once;

use cemi::connectors::DestSpec;
use cemi::crypto::KdfParams;
use cemi::model::{Destination, Field, Value};
use cemi::vault::Scope;

use super::*;

const PASSWORD: &str = "a test password";
const SECRET: &str = "fake-secret-for-tests-1";

/// Sessions go to a folder of files, never to the real credential store
/// (debug builds only, which is what tests use).
fn sessions_in_a_folder() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let dir = std::env::temp_dir().join(format!("cemi-desktop-tests-{}", std::process::id()));
        // SAFETY: every test calls this first, and `Once` makes the others
        // wait until it is done, so nothing reads the environment meanwhile.
        unsafe {
            std::env::set_var("CEMI_TEST_SESSION_DIR", dir);
            std::env::remove_var("CEMI_NO_SESSION");
            std::env::remove_var("CEMI_SESSION_MINUTES");
        }
    });
}

struct TestVault {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
}

fn add_value(v: &mut Vault, record: &str, field: Field, env: &str, text: &str) {
    let mut field = field;
    field
        .values
        .entry(env.to_string())
        .or_default()
        .push(Value::text(text), "test", None);
    v.record_mut(record).fields.push(field);
}

/// A global vault:
/// - acme/shop/stripe: secret `key` (dev and prod), `publishable` (not
///   secret), a template `url`, a purpose and an expiry in 3 days, and a
///   `.env` destination;
/// - acme/shop/mail: purpose, a secret, nothing to look at;
/// - acme/blog/ghost: no notes;
/// - note at the root.
fn test_vault() -> TestVault {
    sessions_in_a_folder();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".cemi");
    let mut v = Vault::create(
        &dir,
        Scope::Global,
        Some(PASSWORD),
        None,
        &["dev", "prod"],
        KdfParams::INSECURE_FAST,
    )
    .unwrap()
    .vault;
    let shop = v.ensure_entity(&["acme".into(), "shop".into()]).unwrap();
    let blog = v.ensure_entity(&["acme".into(), "blog".into()]).unwrap();
    let root = v.root_id();

    let stripe = v.add_record(&shop, "stripe").unwrap();
    add_value(
        &mut v,
        &stripe,
        Field::new("key", FieldKind::Text, true),
        "dev",
        SECRET,
    );
    v.record_mut(&stripe).fields[0]
        .values
        .entry("prod".into())
        .or_default()
        .push(Value::text("fake-secret-for-tests-prod"), "test", None);
    add_value(
        &mut v,
        &stripe,
        Field::new("publishable", FieldKind::Text, false),
        SHARED,
        "public-part-for-tests",
    );
    add_value(
        &mut v,
        &stripe,
        Field::new("url", FieldKind::Template, false),
        SHARED,
        "https://user:{{stripe#key}}@example.test",
    );
    let soon = jiff::Zoned::now()
        .date()
        .checked_add(jiff::Span::new().days(3))
        .unwrap();
    {
        let r = v.record_mut(&stripe);
        r.memory
            .insert(memory_keys::PURPOSE.into(), "Card payments".into());
        r.memory
            .insert(memory_keys::EXPIRES.into(), soon.to_string());
        r.memory.insert("owner".into(), "the shop team".into());
        r.memory
            .insert(memory_keys::ROTATE.into(), "Roll it in the panel".into());
        r.fields[0].destinations.push(Destination {
            id: "d1".into(),
            env: "dev".into(),
            spec: DestSpec::Dotenv {
                file: PathBuf::from("app/.env"),
                key: "STRIPE_KEY".into(),
            },
            last: None,
            created: Timestamp::now(),
        });
    }

    let mail = v.add_record(&shop, "mail").unwrap();
    add_value(
        &mut v,
        &mail,
        Field::new("token", FieldKind::Text, true),
        SHARED,
        "fake-mail-token",
    );
    for (k, t) in [
        (memory_keys::PURPOSE, "Sends the receipts"),
        (memory_keys::BACKUP, "none needed"),
    ] {
        v.record_mut(&mail).memory.insert(k.into(), t.into());
    }

    v.add_record(&blog, "ghost").unwrap();
    v.add_record(&root, "note").unwrap();
    v.save().unwrap();
    TestVault { _tmp: tmp, dir }
}

fn open(t: &TestVault) -> Opened {
    unlock(
        &t.dir,
        PASSWORD,
        true,
        &mut Limiter::default(),
        Instant::now(),
    )
    .unwrap()
}

fn record_id(v: &Vault, name: &str) -> String {
    v.records
        .values()
        .find(|r| r.name == name)
        .unwrap()
        .id
        .clone()
}

// ----- unlocking and the session -----

#[test]
fn unlock_checks_the_password() {
    let t = test_vault();
    let mut limiter = Limiter::default();
    let now = Instant::now();
    let wrong = unlock(&t.dir, "not it", true, &mut limiter, now);
    assert!(matches!(wrong, Err(UnlockError::WrongPassword)));
    let opened = unlock(&t.dir, PASSWORD, true, &mut limiter, now).unwrap();
    assert!(opened.shared);
    assert!(opened.remaining_secs() > 60);
}

#[test]
fn three_wrong_passwords_block_for_a_while() {
    let t = test_vault();
    let mut limiter = Limiter::default();
    let now = Instant::now();
    for _ in 0..MAX_TRIES {
        assert_eq!(
            unlock(&t.dir, "nope", true, &mut limiter, now).err(),
            Some(UnlockError::WrongPassword)
        );
    }
    // Even the right password waits.
    assert_eq!(
        unlock(&t.dir, PASSWORD, true, &mut limiter, now).err(),
        Some(UnlockError::Wait(LOCKOUT.as_secs()))
    );
    let later = now + LOCKOUT + Duration::from_secs(1);
    assert!(unlock(&t.dir, PASSWORD, true, &mut limiter, later).is_ok());
}

#[test]
fn no_vault_is_reported() {
    sessions_in_a_folder();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("nothing-here");
    assert!(!vault_info(&dir).exists);
    assert_eq!(
        unlock(
            &dir,
            PASSWORD,
            true,
            &mut Limiter::default(),
            Instant::now()
        )
        .err(),
        Some(UnlockError::NoVault)
    );
}

#[test]
fn the_session_is_shared_with_the_command_line() {
    let t = test_vault();
    assert!(resume(&t.dir).is_none());
    let opened = open(&t);
    // What the command line does: `Workspace::master_key` finds the session.
    let header = Header::read(&t.dir).unwrap();
    assert!(session::load(&header.id).is_some());
    // And a new run of the app resumes it.
    let again = resume(&t.dir).expect("session found");
    assert_eq!(again.vault_id, opened.vault_id);
    // "Close the vault" ends it everywhere, like `cemi lock`.
    opened.close(true);
    assert!(session::load(&header.id).is_none());
    assert!(resume(&t.dir).is_none());
}

#[test]
fn without_keep_the_session_stays_in_the_app() {
    let t = test_vault();
    let mut opened = unlock(
        &t.dir,
        PASSWORD,
        false,
        &mut Limiter::default(),
        Instant::now(),
    )
    .unwrap();
    assert!(!opened.shared);
    assert!(resume(&t.dir).is_none());
    assert!(opened.load().is_ok());
}

#[test]
fn cemi_lock_closes_the_app_too() {
    let t = test_vault();
    let mut opened = open(&t);
    assert!(opened.load().is_ok());
    session::clear(&opened.vault_id);
    assert!(opened.expires().is_none());
    let err = opened.load().err().expect("closed");
    assert_eq!(err.to_string(), LOCKED);
}

// ----- the views -----

#[test]
fn the_tree_lists_entities_in_order() {
    let t = test_vault();
    let v = open(&t).load().unwrap();
    let view = vault_view(&v);
    let names: Vec<(&str, usize)> = view
        .entities
        .iter()
        .map(|e| (e.name.as_str(), e.depth))
        .collect();
    assert_eq!(names, vec![("", 0), ("acme", 1), ("blog", 2), ("shop", 2)]);
    assert_eq!(view.root, v.root_id());
    let shop = view.entities.iter().find(|e| e.name == "shop").unwrap();
    assert_eq!(shop.records, 2);
    assert_eq!(shop.path, "acme/shop");
    assert!(!shop.has_children);
    assert!(view.entities[1].has_children);
    assert_eq!(view.records.len(), 4);
}

#[test]
fn records_carry_a_status() {
    let t = test_vault();
    let v = open(&t).load().unwrap();
    let view = vault_view(&v);
    let status = |name: &str| {
        view.records
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.status)
            .unwrap()
    };
    // Expires in 3 days: urgent.
    assert_eq!(status("stripe"), Status::Bad);
    assert_eq!(status("mail"), Status::Ok);
    assert_eq!(status("ghost"), Status::Bare);
    let stripe = view.records.iter().find(|r| r.name == "stripe").unwrap();
    assert_eq!(stripe.purpose.as_deref(), Some("Card payments"));
    assert_eq!(stripe.path, "acme/shop/stripe");
    assert!(stripe.notes.contains("the shop team"));
    assert!(stripe.attention.iter().any(|a| a.contains("expires")));
}

#[test]
fn the_record_view_never_holds_a_secret() {
    let t = test_vault();
    let v = open(&t).load().unwrap();
    let id = record_id(&v, "stripe");
    for env in [None, Some("dev"), Some("prod")] {
        let view = record_view(&v, &id, env).unwrap();
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("fake-secret-for-tests"), "{json}");
        assert!(json.contains("public-part-for-tests"));
        // The template shows nothing either: it may hold secrets.
        assert!(!json.contains("example.test"));
    }
}

#[test]
fn the_record_view_describes_fields_notes_and_destinations() {
    let t = test_vault();
    let v = open(&t).load().unwrap();
    let id = record_id(&v, "stripe");
    let view = record_view(&v, &id, Some("prod")).unwrap();
    assert_eq!(view.envs, vec!["dev", "prod"]);
    assert_eq!(view.env.as_deref(), Some("prod"));
    assert!(view.protected);
    assert_eq!(view.path, "acme/shop/stripe");

    let key = &view.fields[0];
    assert_eq!(key.name, "key");
    assert!(key.secret && key.confirm);
    assert_eq!(key.state, "value");
    assert_eq!(key.value, None);
    assert_eq!(key.version, Some(1));
    assert!(!key.shared);
    let publishable = &view.fields[1];
    assert!(!publishable.confirm && publishable.shared);
    assert_eq!(publishable.value.as_deref(), Some("public-part-for-tests"));
    let url = &view.fields[2];
    assert!(!url.secret && url.confirm);
    assert_eq!(url.kind, "template");

    // Known notes in their usual order, then the others.
    let keys: Vec<&str> = view.memory.iter().map(|m| m.key.as_str()).collect();
    assert_eq!(keys, vec!["purpose", "rotate", "expires", "owner"]);

    assert_eq!(view.destinations.len(), 1);
    let d = &view.destinations[0];
    assert_eq!(d.kind, ".env");
    assert_eq!(d.field, "key");
    assert_eq!(d.env.as_deref(), Some("dev"));
    assert!(d.description.contains("STRIPE_KEY"));
    assert!(d.last_sent.is_none());

    // An unknown environment falls back to the first one.
    let view = record_view(&v, &id, Some("staging")).unwrap();
    assert_eq!(view.env.as_deref(), Some("dev"));
    assert!(!view.protected);
}

#[test]
fn an_empty_field_is_reported_as_empty() {
    let t = test_vault();
    let v = open(&t).load().unwrap();
    let id = record_id(&v, "stripe");
    let view = record_view(&v, &id, Some("prod")).unwrap();
    assert_eq!(view.fields[0].state, "value");
    let ghost = record_id(&v, "ghost");
    assert!(record_view(&v, &ghost, None).unwrap().fields.is_empty());
    assert!(record_view(&v, "no-such-id", None).is_err());
}

// ----- showing and copying -----

#[test]
fn the_method_follows_the_field_and_the_vault_setting() {
    let t = test_vault();
    let mut opened = open(&t);
    let v = opened.load().unwrap();
    let id = record_id(&v, "stripe");
    assert_eq!(method_for(&v, &id, "publishable").unwrap(), Method::None);
    assert_eq!(method_for(&v, &id, "key").unwrap(), Method::Password);
    assert_eq!(method_for(&v, &id, "url").unwrap(), Method::Password);
    assert!(method_for(&v, &id, "missing").is_err());
    drop(v);

    // `cemi approve-with device`
    let mut w = Vault::load(&t.dir, opened.key().unwrap(), true).unwrap();
    let root = w.root_id();
    w.entity_mut(&root).approve_with = Some(ApproveWith::Device);
    w.save().unwrap();
    drop(w);
    let v = opened.load().unwrap();
    assert_eq!(method_for(&v, &id, "key").unwrap(), Method::Device);
    assert_eq!(method_for(&v, &id, "publishable").unwrap(), Method::None);
}

fn no_presence() -> Check {
    panic!("the device check must not run here")
}

fn no_password(_: &str) -> Result<bool> {
    panic!("the password must not be checked here")
}

#[test]
fn values_that_are_not_secret_need_nothing() {
    let auth = authorize(
        Method::None,
        None,
        &mut Limiter::default(),
        Instant::now(),
        no_presence,
        no_password,
    )
    .unwrap();
    assert_eq!(auth, Auth::Granted { by: Method::None });
}

#[test]
fn the_device_check_decides() {
    let mut limiter = Limiter::default();
    let now = Instant::now();
    let ask = |answer: Check| {
        authorize(
            Method::Device,
            None,
            &mut Limiter::default(),
            now,
            move || answer,
            no_password,
        )
        .unwrap()
    };
    assert_eq!(ask(Check::Verified), Auth::Granted { by: Method::Device });
    assert_eq!(ask(Check::Refused), Auth::Refused);
    assert_eq!(
        ask(Check::Unavailable("no camera".into())),
        Auth::NeedPassword {
            reason: Some("no camera".into())
        }
    );
    // The password still works when the device cannot.
    let auth = authorize(
        Method::Device,
        Some(PASSWORD),
        &mut limiter,
        now,
        no_presence,
        |pw| Ok(pw == PASSWORD),
    )
    .unwrap();
    assert_eq!(
        auth,
        Auth::Granted {
            by: Method::Password
        }
    );
}

#[test]
fn the_password_method_asks_and_counts_mistakes() {
    let mut limiter = Limiter::default();
    let now = Instant::now();
    let auth = authorize(
        Method::Password,
        None,
        &mut limiter,
        now,
        no_presence,
        no_password,
    );
    assert_eq!(auth.unwrap(), Auth::NeedPassword { reason: None });
    for _ in 0..MAX_TRIES {
        let auth = authorize(
            Method::Password,
            Some("wrong"),
            &mut limiter,
            now,
            no_presence,
            |pw| Ok(pw == PASSWORD),
        );
        assert_eq!(auth.unwrap(), Auth::WrongPassword);
    }
    let auth = authorize(
        Method::Password,
        Some(PASSWORD),
        &mut limiter,
        now,
        no_presence,
        no_password,
    );
    assert_eq!(auth.unwrap(), Auth::Wait(LOCKOUT.as_secs()));
}

#[test]
fn the_vault_password_is_checked_again() {
    let t = test_vault();
    assert!(password_matches(&t.dir, PASSWORD).unwrap());
    assert!(!password_matches(&t.dir, "other").unwrap());
}

#[test]
fn release_resolves_and_writes_the_audit_log() {
    let t = test_vault();
    let mut opened = open(&t);
    let v = opened.load().unwrap();
    let id = record_id(&v, "stripe");
    let req = ValueRequest {
        record_id: id.clone(),
        field: "url".into(),
        env: Some("dev".into()),
    };
    let mut delivered = String::new();
    let out = release(v, &req, "value.copy", |text| {
        delivered.push_str(text);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        out.text.as_str(),
        format!("https://user:{SECRET}@example.test")
    );
    assert_eq!(delivered, out.text.as_str());
    assert_eq!(out.reference, "global:acme/shop/stripe#url");
    assert_eq!(out.env.as_deref(), Some("dev"));

    let req = ValueRequest {
        record_id: id.clone(),
        field: "key".into(),
        env: Some("prod".into()),
    };
    let v = opened.load().unwrap();
    let out = release(v, &req, "value.reveal", |_| Ok(())).unwrap();
    assert_eq!(out.text.as_str(), "fake-secret-for-tests-prod");
    assert_eq!(out.version, Some(1));

    let log = cemi::audit::read(&t.dir, &opened.key().unwrap()).unwrap();
    let ours: Vec<(&str, &str, Option<&str>)> = log
        .entries
        .iter()
        .filter(|e| e.actor == ACTOR)
        .map(|e| {
            (
                e.action.as_str(),
                e.target.as_deref().unwrap_or_default(),
                e.env.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        ours,
        vec![
            ("value.copy", "global:acme/shop/stripe#url", Some("dev")),
            ("value.reveal", "global:acme/shop/stripe#key", Some("prod")),
        ]
    );
    assert!(log.broken.is_empty());
}

#[test]
fn release_refuses_an_unknown_environment() {
    let t = test_vault();
    let mut opened = open(&t);
    let v = opened.load().unwrap();
    let req = ValueRequest {
        record_id: record_id(&v, "stripe"),
        field: "key".into(),
        env: Some("staging".into()),
    };
    assert!(release(v, &req, "value.reveal", |_| Ok(())).is_err());
}

#[test]
fn a_failed_delivery_is_not_logged() {
    let t = test_vault();
    let mut opened = open(&t);
    let v = opened.load().unwrap();
    let req = ValueRequest {
        record_id: record_id(&v, "mail"),
        field: "token".into(),
        env: None,
    };
    let result = release(v, &req, "value.copy", |_| Err(anyhow!("no clipboard")));
    assert!(result.is_err());
    let log = cemi::audit::read(&t.dir, &opened.key().unwrap()).unwrap();
    assert!(log.entries.iter().all(|e| e.actor != ACTOR));
}

#[test]
fn copying_after_a_reveal_is_covered_only_briefly() {
    let now = Instant::now();
    let req = ValueRequest {
        record_id: "r".into(),
        field: "key".into(),
        env: Some("dev".into()),
    };
    let grace = Grace::new(&req, Method::Device, now);
    assert_eq!(grace.covers(&req, now), Some(Method::Device));
    let other_env = ValueRequest {
        env: Some("prod".into()),
        ..req.clone()
    };
    assert_eq!(grace.covers(&other_env, now), None);
    let other_field = ValueRequest {
        field: "other".into(),
        ..req.clone()
    };
    assert_eq!(grace.covers(&other_field, now), None);
    assert_eq!(grace.covers(&req, now + REVEAL_TIME), None);
}
