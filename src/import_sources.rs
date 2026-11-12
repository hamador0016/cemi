//! Reading secrets from other secret managers through their own command-line
//! programs (`doppler`, `op`). Cemí never handles their API tokens: the
//! programs use the person's own session. Values only come through the
//! child's standard output and are kept in zeroized buffers.

use std::collections::BTreeMap;
use std::fmt;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, Visitor};
use zeroize::Zeroizing;

use crate::model::FieldKind;
use crate::runner;

/// A secret manager's command-line program.
struct Cli {
    program: &'static str,
    name: &'static str,
    install: &'static str,
    login: &'static str,
}

const DOPPLER: Cli = Cli {
    program: "doppler",
    name: "the Doppler CLI",
    install: "https://docs.doppler.com/docs/install-cli",
    login: "doppler login",
};

const OP: Cli = Cli {
    program: "op",
    name: "the 1Password CLI (op)",
    install: "https://developer.1password.com/docs/cli/get-started/",
    login: "op signin",
};

/// Runs the program and returns what it printed on standard output. Its
/// messages and prompts go to the terminal as they are.
fn run(cli: &Cli, args: &[&str]) -> Result<Zeroizing<Vec<u8>>> {
    let stdin = if crate::ui::password_from_stdin() {
        Stdio::null()
    } else {
        Stdio::inherit()
    };
    let out = Command::new(runner::resolve_program(cli.program))
        .args(args)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(crate::errors::not_found(format!(
                "{} is not installed or not on your PATH. Install it ({}), run `{}`, and try again",
                cli.name, cli.install, cli.login
            )));
        }
        Err(e) => return Err(e).with_context(|| format!("cannot run {}", cli.program)),
    };
    let stdout = Zeroizing::new(out.stdout);
    if !out.status.success() {
        bail!(
            "`{} {}` failed. If you are not signed in, run `{}` and try again",
            cli.program,
            args.join(" "),
            cli.login
        );
    }
    Ok(stdout)
}

/// Variables that Doppler adds to every download; they describe the config.
const DOPPLER_META: [&str; 3] = ["DOPPLER_PROJECT", "DOPPLER_CONFIG", "DOPPLER_ENVIRONMENT"];

/// Every variable of a Doppler config:
/// `doppler secrets download --no-file --format json [--project P] [--config C]`.
pub fn doppler(
    project: Option<&str>,
    config: Option<&str>,
) -> Result<Vec<(String, Zeroizing<String>)>> {
    let mut args = vec!["secrets", "download", "--no-file", "--format", "json"];
    if let Some(p) = project {
        args.extend(["--project", p]);
    }
    if let Some(c) = config {
        args.extend(["--config", c]);
    }
    let out = run(&DOPPLER, &args)?;
    let vars: BTreeMap<String, Zeroizing<String>> = serde_json::from_slice(&out)
        .map_err(|_| anyhow!("doppler did not print the JSON object Cemí expected"))?;
    Ok(vars
        .into_iter()
        .filter(|(k, _)| !DOPPLER_META.contains(&k.as_str()))
        .collect())
}

/// A field to import.
pub struct ImportedField {
    pub name: String,
    pub kind: FieldKind,
    pub secret: bool,
    pub value: Zeroizing<String>,
}

/// A 1Password item, as a record.
pub struct ImportedItem {
    pub name: String,
    pub fields: Vec<ImportedField>,
}

pub struct OnePassword {
    pub items: Vec<ImportedItem>,
    /// File attachments and documents, which are not imported.
    pub files_skipped: usize,
    /// Items with no value to import.
    pub empty_skipped: usize,
}

#[derive(Deserialize)]
struct ListedItem {
    id: String,
}

#[derive(Deserialize)]
struct OpItem {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    fields: Vec<OpField>,
    #[serde(default)]
    files: Vec<IgnoredAny>,
    #[serde(default)]
    urls: Vec<OpUrl>,
}

#[derive(Deserialize)]
struct OpField {
    #[serde(default)]
    id: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    purpose: String,
    #[serde(default)]
    label: String,
    #[serde(default, deserialize_with = "lenient_text")]
    value: Option<Zeroizing<String>>,
    #[serde(default)]
    section: Option<OpSection>,
}

#[derive(Deserialize)]
struct OpSection {
    #[serde(default)]
    label: String,
}

#[derive(Deserialize)]
struct OpUrl {
    #[serde(default)]
    href: String,
    #[serde(default)]
    primary: bool,
}

/// A field value as text: strings, numbers and booleans; anything else
/// (an address, for example) is left out.
fn lenient_text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Zeroizing<String>>, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Option<Zeroizing<String>>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a field value")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(Zeroizing::new(v.to_string())))
        }
        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(Some(Zeroizing::new(v)))
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(Some(Zeroizing::new(v.to_string())))
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(Zeroizing::new(v.to_string())))
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
            Ok(Some(Zeroizing::new(v.to_string())))
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
            Ok(Some(Zeroizing::new(v.to_string())))
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Self::Value, D2::Error> {
            d.deserialize_any(V)
        }
        fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok(None)
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(None)
        }
    }
    d.deserialize_any(V)
}

/// Field types whose values are not secret (unless the field is a password).
const PLAIN_TYPES: [&str; 7] = [
    "STRING",
    "EMAIL",
    "PHONE",
    "MENU",
    "MONTH_YEAR",
    "DATE",
    "URL",
];

/// Names in Cemí cannot contain '/' or '#' (they separate references) nor
/// control characters.
fn clean_name(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '/' || c == '#' { '-' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// `base`, or `base 2`, `base 3`… so names are unique in `taken`.
fn unique(base: String, taken: &[String]) -> String {
    if !taken.contains(&base) {
        return base;
    }
    (2..)
        .map(|n| format!("{base} {n}"))
        .find(|n| !taken.contains(n))
        .expect("an unused name")
}

fn map_item(item: OpItem) -> (Option<ImportedItem>, usize) {
    let files =
        item.files.len() + usize::from(item.category == "DOCUMENT" && item.files.is_empty());
    let mut fields: Vec<ImportedField> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for f in item.fields {
        let Some(value) = f.value.filter(|v| !v.trim().is_empty()) else {
            continue;
        };
        let notes = f.purpose == "NOTES";
        let mut name = if notes {
            "notes".to_string()
        } else {
            clean_name(if f.label.trim().is_empty() {
                &f.id
            } else {
                &f.label
            })
        };
        if name.is_empty() {
            name = "field".into();
        }
        if names.contains(&name)
            && let Some(section) = f.section.as_ref().map(|s| clean_name(&s.label))
            && !section.is_empty()
        {
            name = format!("{section} {name}");
        }
        let name = unique(name, &names);
        let secret = notes || f.purpose == "PASSWORD" || !PLAIN_TYPES.contains(&f.kind.as_str());
        let kind = if value.contains('\n') {
            FieldKind::Multiline
        } else if f.kind == "URL" {
            FieldKind::Url
        } else {
            FieldKind::Text
        };
        names.push(name.clone());
        fields.push(ImportedField {
            name,
            kind,
            secret,
            value,
        });
    }
    let url = item
        .urls
        .iter()
        .find(|u| u.primary)
        .or(item.urls.first())
        .map(|u| u.href.trim())
        .filter(|h| !h.is_empty());
    if let Some(href) = url
        && !fields.iter().any(|f| f.kind == FieldKind::Url)
    {
        fields.push(ImportedField {
            name: unique("website".into(), &names),
            kind: FieldKind::Url,
            secret: false,
            value: Zeroizing::new(href.to_string()),
        });
    }
    if fields.is_empty() {
        return (None, files);
    }
    let mut name = clean_name(&item.title);
    if name.is_empty() {
        name = format!("item {}", clean_name(&item.id));
    }
    (Some(ImportedItem { name, fields }), files)
}

/// Every item of a 1Password vault: `op item list --vault V --format json`,
/// then `op item get <id> --vault V --format json --reveal` for each.
pub fn onepassword(vault: &str) -> Result<OnePassword> {
    let list = run(&OP, &["item", "list", "--vault", vault, "--format", "json"])?;
    let listed: Vec<ListedItem> = serde_json::from_slice(&list)
        .map_err(|_| anyhow!("op did not print the list of items Cemí expected"))?;
    let mut out = OnePassword {
        items: Vec::new(),
        files_skipped: 0,
        empty_skipped: 0,
    };
    for l in listed {
        let raw = run(
            &OP,
            &[
                "item", "get", &l.id, "--vault", vault, "--format", "json", "--reveal",
            ],
        )?;
        let item: OpItem = serde_json::from_slice(&raw)
            .map_err(|_| anyhow!("op did not print the item {} as Cemí expected", l.id))?;
        let (mapped, files) = map_item(item);
        out.files_skipped += files;
        match mapped {
            Some(mut m) => {
                let taken: Vec<String> = out.items.iter().map(|i| i.name.clone()).collect();
                m.name = unique(m.name, &taken);
                out.items.push(m);
            }
            None => out.empty_skipped += 1,
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_fields() {
        let item: OpItem = serde_json::from_str(
            r#"{
              "id": "abc", "title": "Git/Hub", "category": "LOGIN",
              "fields": [
                {"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": "octo"},
                {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "pw-value"},
                {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": "line one\nline two"},
                {"id": "x1", "type": "CONCEALED", "label": "token", "section": {"id": "s1", "label": "API"}, "value": "tok-1"},
                {"id": "x2", "type": "CONCEALED", "label": "token", "section": {"id": "s2", "label": "Old"}, "value": "tok-2"},
                {"id": "x3", "type": "STRING", "label": "empty", "value": ""},
                {"id": "x4", "type": "ADDRESS", "label": "home", "value": {"city": "x"}},
                {"id": "x5", "type": "OTP", "label": "one-time password", "value": "otpauth://totp/x?secret=ABC"}
              ],
              "files": [{"id": "f1", "name": "a.pdf"}],
              "urls": [{"href": "https://github.com", "primary": true}]
            }"#,
        )
        .unwrap();
        let (m, files) = map_item(item);
        let m = m.unwrap();
        assert_eq!(files, 1);
        assert_eq!(m.name, "Git-Hub");
        let got: Vec<(&str, bool)> = m
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.secret))
            .collect();
        assert_eq!(
            got,
            vec![
                ("username", false),
                ("password", true),
                ("notes", true),
                ("token", true),
                ("Old token", true),
                ("one-time password", true),
                ("website", false),
            ]
        );
        assert_eq!(m.fields[2].kind, FieldKind::Multiline);
        assert_eq!(m.fields[6].kind, FieldKind::Url);
    }

    #[test]
    fn documents_are_skipped() {
        let item: OpItem = serde_json::from_str(
            r#"{"id": "d", "title": "passport scan", "category": "DOCUMENT"}"#,
        )
        .unwrap();
        let (m, files) = map_item(item);
        assert!(m.is_none());
        assert_eq!(files, 1);
    }
}
