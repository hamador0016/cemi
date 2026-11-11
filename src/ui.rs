//! Talking to the human: passwords, confirmations and secret input.
//! Values are never accepted as command-line arguments, because arguments end
//! up in shell history and process listings.

use std::io::{BufRead, IsTerminal, Read};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

static PASSWORD_STDIN: Mutex<bool> = Mutex::new(false);
static NON_INTERACTIVE: Mutex<bool> = Mutex::new(false);

/// For processes started by AI clients: never ask for a password.
pub fn set_non_interactive() {
    *NON_INTERACTIVE.lock().expect("not poisoned") = true;
}

/// `--password-stdin`: read passwords from standard input, one per line.
pub fn use_password_stdin() {
    *PASSWORD_STDIN.lock().expect("not poisoned") = true;
}

fn password_from_stdin() -> bool {
    *PASSWORD_STDIN.lock().expect("not poisoned")
}

fn read_stdin_line() -> Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("cannot read from standard input")?;
    let trimmed = Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string());
    Ok(trimmed)
}

/// Asks for a password without echoing it.
pub fn password(prompt: &str) -> Result<Zeroizing<String>> {
    if *NON_INTERACTIVE.lock().expect("not poisoned") {
        bail!("the vault is locked. Ask the human to run `cemi unlock` in a terminal");
    }
    if password_from_stdin() {
        let pw = read_stdin_line()?;
        if pw.is_empty() {
            bail!("no password on standard input");
        }
        return Ok(pw);
    }
    match rpassword::prompt_password(prompt) {
        Ok(p) => Ok(Zeroizing::new(p)),
        Err(_) => bail!(
            "there is no terminal to ask for the password. Run `cemi unlock` in a terminal first, or pass --password-stdin"
        ),
    }
}

/// Asks for a new password twice.
pub fn new_password(what: &str) -> Result<Zeroizing<String>> {
    if password_from_stdin() {
        let pw = password("")?;
        check_password_strength(&pw)?;
        return Ok(pw);
    }
    loop {
        let a = password(&format!("New password for {what}: "))?;
        if let Err(e) = check_password_strength(&a) {
            eprintln!("{e}");
            continue;
        }
        let b = password("Repeat it: ")?;
        if a.as_str() == b.as_str() {
            return Ok(a);
        }
        eprintln!("They do not match. Try again.");
    }
}

fn check_password_strength(pw: &str) -> Result<()> {
    if pw.chars().count() < 10 {
        bail!("Use at least 10 characters. A few random words work well.");
    }
    Ok(())
}

/// Reads a secret value typed by the human (hidden) or piped on stdin.
pub fn secret_value(prompt: &str, from_stdin: bool) -> Result<Zeroizing<String>> {
    if from_stdin || !std::io::stdin().is_terminal() {
        let mut buf = Zeroizing::new(String::new());
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("cannot read the value from standard input")?;
        // A single trailing newline comes from `echo`; anything else is kept as is.
        let value = buf
            .strip_suffix("\r\n")
            .or_else(|| buf.strip_suffix('\n'))
            .unwrap_or(&buf)
            .to_string();
        return Ok(Zeroizing::new(value));
    }
    match rpassword::prompt_password(prompt) {
        Ok(p) => Ok(Zeroizing::new(p)),
        Err(_) => bail!("cannot read the value: no terminal. Pipe it with --stdin instead."),
    }
}

/// Yes/no question on the terminal. Without a terminal the answer is no.
pub fn confirm(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprint!("{question} [y/N] ");
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(
        line.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí"
    )
}

pub fn ok(msg: impl AsRef<str>) {
    eprintln!("✓ {}", msg.as_ref());
}

pub fn warn(msg: impl AsRef<str>) {
    eprintln!("! {}", msg.as_ref());
}
