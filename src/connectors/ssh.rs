//! One variable of a `.env` file on a server, through the system `ssh`
//! program, so `~/.ssh/config`, the agent and `known_hosts` apply as usual.
//!
//! Cemí reads the file over SSH, changes the variable with the same `.env`
//! rules as for local files, and sends the whole file back on stdin. The
//! server replaces the file only if it still has the content Cemí read
//! (compared by SHA-256), so a change made in between is never lost. Values
//! travel only on stdin, never in the command line. The server needs a POSIX
//! `sh` and one of `sha256sum`, `shasum` or `openssl`.

use anyhow::{Result, anyhow, bail};
use zeroize::Zeroizing;

use super::Observed;
use super::command::{Ran, run, show};

/// Exit codes of the scripts below.
const NO_FILE: i32 = 3;
const CHANGED: i32 = 4;
const RESTART_FAILED: i32 = 5;
const NO_HASH: i32 = 6;
/// What `ssh` itself returns when it cannot connect.
const SSH_FAILED: i32 = 255;

const READ: &str = r#"if [ -e "$1" ]; then exec cat -- "$1"; else exit 3; fi"#;

const WRITE: &str = r#"set -eu
f=$1; want=$2; restart=$3
h() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 | sed 's/.* //'
  fi
}
if [ -e "$f" ]; then now=$(h < "$f"); else now=none; fi
if [ -z "$now" ]; then echo "the server needs sha256sum, shasum or openssl" >&2; exit 6; fi
if [ "$now" != "$want" ]; then exit 4; fi
d=$(dirname -- "$f")
mkdir -p -- "$d"
umask 077
t=$(mktemp "$d/.cemi.XXXXXX")
trap 'rm -f -- "$t"' EXIT
if [ -e "$f" ]; then cp -p -- "$f" "$t"; fi
cat > "$t"
mv -f -- "$t" "$f"
trap - EXIT
if [ -n "$restart" ]; then sh -c "$restart" || exit 5; fi
"#;

pub struct Server<'a> {
    pub host: &'a str,
    pub port: Option<u16>,
    /// The ssh program and leading arguments (default: `ssh`).
    pub program: Option<&'a [String]>,
}

pub fn validate(host: &str, file: &str, restart: Option<&str>) -> Result<()> {
    let ok = !host.is_empty()
        && !host.starts_with('-')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._-:[]".contains(c));
    if !ok {
        bail!("{host:?} is not an ssh host (user@server, or a Host from ~/.ssh/config)");
    }
    if file.is_empty() || file.contains(['\n', '\r', '\0']) {
        bail!("--file must be the path of the .env file on the server");
    }
    if let Some(r) = restart
        && (r.trim().is_empty() || r.contains('\0'))
    {
        bail!("--restart must be a command");
    }
    Ok(())
}

/// Quotes one word for the remote POSIX shell.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn ssh(server: &Server, script: &str, args: &[&str], input: &[u8]) -> Result<Ran> {
    let default = ["ssh".to_string()];
    let program = server.program.unwrap_or(&default);
    let mut remote = format!("sh -c {} cemi", quote(script));
    for a in args {
        remote.push(' ');
        remote.push_str(&quote(a));
    }
    let port = server.port.map(|p| p.to_string());
    let mut extra: Vec<&str> = vec!["-o", "BatchMode=yes"];
    if let Some(p) = &port {
        extra.extend(["-p", p.as_str()]);
    }
    extra.extend(["--", server.host, remote.as_str()]);
    run(program, &extra, input, &[])
}

fn ssh_error(server: &Server, ran: &Ran, what: &str) -> anyhow::Error {
    if ran.code == Some(SSH_FAILED) {
        return crate::errors::external(format!(
            "cannot connect to {} with ssh. Cemí runs ssh without asking for passwords: \
             use a key or the ssh agent, and connect once by hand to accept the host key",
            server.host
        ));
    }
    crate::errors::external(format!(
        "{what} on {} failed{}",
        server.host,
        ran.code
            .map(|c| format!(" with exit code {c}"))
            .unwrap_or_default()
    ))
}

/// The file's text, or None when it does not exist.
fn read(server: &Server, file: &str) -> Result<Option<Zeroizing<String>>> {
    let ran = ssh(server, READ, &[file], b"")?;
    if ran.code == Some(NO_FILE) {
        return Ok(None);
    }
    if !ran.ok {
        show("ssh", &ran.stderr, &[]);
        return Err(ssh_error(server, &ran, &format!("reading {file}")));
    }
    let text = String::from_utf8(ran.stdout.to_vec())
        .map_err(|_| anyhow!("{file} on {} is not text", server.host))?;
    Ok(Some(Zeroizing::new(text)))
}

pub fn write(
    server: &Server,
    file: &str,
    key: &str,
    value: &str,
    restart: Option<&str>,
) -> Result<()> {
    let old = read(server, file)?;
    let want = match &old {
        Some(t) => crate::crypto::sha256_hex(t.as_bytes()),
        None => "none".to_string(),
    };
    let base = old.as_ref().map(|t| t.as_str()).unwrap_or("");
    let new = Zeroizing::new(crate::dotenv::set(base, key, value)?);
    let ran = ssh(
        server,
        WRITE,
        &[file, &want, restart.unwrap_or("")],
        new.as_bytes(),
    )?;
    show("ssh", &ran.stdout, &[value.as_bytes()]);
    show("ssh", &ran.stderr, &[value.as_bytes()]);
    match ran.code {
        _ if ran.ok => Ok(()),
        Some(CHANGED) => Err(crate::errors::external(format!(
            "{file} on {} changed while Cemí was updating it; nothing was written. Run the command again",
            server.host
        ))),
        Some(RESTART_FAILED) => Err(crate::errors::external(format!(
            "the value was written to {file} on {}, but the restart command failed",
            server.host
        ))),
        Some(NO_HASH) => Err(crate::errors::external(format!(
            "{} needs sha256sum, shasum or openssl so Cemí can update files safely",
            server.host
        ))),
        _ => Err(ssh_error(server, &ran, &format!("writing {file}"))),
    }
}

/// The SHA-256 of the variable's value (the file is read over SSH and only
/// the digest is kept).
pub fn observe(server: &Server, file: &str, key: &str) -> Result<Observed> {
    let Some(text) = read(server, file)? else {
        return Ok(Observed::Missing);
    };
    Ok(match crate::dotenv::get(&text, key)? {
        Some(v) => {
            let v = Zeroizing::new(v);
            Observed::Remote(crate::crypto::sha256_hex(v.as_bytes()))
        }
        None => Observed::Missing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_and_quoting() {
        assert!(validate("deploy@app.example.com", "/srv/app/.env", None).is_ok());
        assert!(validate("prod-web", "/srv/app/.env", Some("systemctl restart app")).is_ok());
        assert!(validate("-oProxyCommand=x", "/srv/.env", None).is_err());
        assert!(validate("a b", "/srv/.env", None).is_err());
        assert!(validate("web", "", None).is_err());
        assert!(validate("web", "/srv/.env", Some("  ")).is_err());
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote("/srv/app/.env"), "'/srv/app/.env'");
    }
}
