//! Exit codes that scripts can rely on, and the kinds of errors behind them.
//! An error gets a kind where it happens (`errors::not_found(…)`); the kind
//! survives any context added later, and `main` turns it into the exit code.

use std::fmt;

/// Exit codes. They do not change between versions.
pub mod code {
    /// The command did what was asked.
    pub const OK: i32 = 0;
    /// The command worked and found problems: `check`, `scan`, `types --check`,
    /// a `push` that could not reach every destination…
    pub const PROBLEMS: i32 = 1;
    /// Wrong arguments (from the argument parser).
    pub const USAGE: i32 = 2;
    /// The vault is locked or the password was wrong: a person has to unlock it.
    pub const LOCKED: i32 = 3;
    /// A record, field, entity, environment, preset or file does not exist.
    pub const NOT_FOUND: i32 = 4;
    /// A person has to approve or confirm it (protected environments).
    pub const NEEDS_PERSON: i32 = 5;
    /// A provider, the network or an external command failed.
    pub const EXTERNAL: i32 = 6;
    /// Any other error.
    pub const ERROR: i32 = 9;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Locked,
    NotFound,
    NeedsPerson,
    External,
}

impl Kind {
    pub fn code(self) -> i32 {
        match self {
            Kind::Locked => code::LOCKED,
            Kind::NotFound => code::NOT_FOUND,
            Kind::NeedsPerson => code::NEEDS_PERSON,
            Kind::External => code::EXTERNAL,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Locked => "locked",
            Kind::NotFound => "not_found",
            Kind::NeedsPerson => "needs_person",
            Kind::External => "external",
        }
    }
}

/// An error with a kind. Its message is the whole message.
#[derive(Debug)]
pub struct Classified {
    pub kind: Kind,
    message: String,
}

impl fmt::Display for Classified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Classified {}

fn new(kind: Kind, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Classified {
        kind,
        message: message.into(),
    })
}

pub fn locked(message: impl Into<String>) -> anyhow::Error {
    new(Kind::Locked, message)
}

pub fn not_found(message: impl Into<String>) -> anyhow::Error {
    new(Kind::NotFound, message)
}

pub fn needs_person(message: impl Into<String>) -> anyhow::Error {
    new(Kind::NeedsPerson, message)
}

pub fn external(message: impl Into<String>) -> anyhow::Error {
    new(Kind::External, message)
}

/// The kind of an error, looking through any context added on top.
pub fn kind_of(e: &anyhow::Error) -> Option<Kind> {
    e.chain()
        .find_map(|c| c.downcast_ref::<Classified>())
        .map(|c| c.kind)
}

pub fn exit_code(e: &anyhow::Error) -> i32 {
    kind_of(e).map(Kind::code).unwrap_or(code::ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn kind_survives_context() {
        let e = Err::<(), _>(not_found("record not found: x"))
            .context("opening x")
            .unwrap_err();
        assert_eq!(kind_of(&e), Some(Kind::NotFound));
        assert_eq!(exit_code(&e), code::NOT_FOUND);
        assert_eq!(format!("{e:#}"), "opening x: record not found: x");
        assert_eq!(exit_code(&anyhow::anyhow!("other")), code::ERROR);
    }
}
