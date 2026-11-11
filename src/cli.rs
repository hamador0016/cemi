//! Command-line interface. Commands are short and predictable, like git's.

use clap::{Parser, Subcommand};
use clap_complete::ArgValueCompleter;

use crate::model::{Every, FieldKind, Permission};

#[derive(Parser)]
#[command(
    name = "cemi",
    version,
    about = "Secrets with memory that your AI can use without seeing",
    long_about = "Cemí keeps your API keys, tokens and passwords encrypted on your computer, \
together with what they are for, where they are used and how to replace them. \
Run your projects with them injected, and let AI assistants use them without ever seeing the values.\n\n\
Start with `cemi init --global` once per computer, then `cemi init` inside a project.",
    propagate_version = true
)]
pub struct Cli {
    /// Use the global vault of this computer instead of the project's local vault
    #[arg(short = 'g', long, global = true)]
    pub global: bool,

    /// Read passwords from standard input, one per line (for scripts)
    #[arg(long, global = true)]
    pub password_stdin: bool,

    /// Print one JSON object on standard output: {ok, exit_code, data, text, error}
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Create a vault in this project (or for this computer with --global)
    Init {
        /// Environments to start with, comma separated
        #[arg(long, default_value = "dev,prod")]
        envs: String,
        /// Start with the usual records of a stack (repeat for several; see `cemi preset ls`)
        #[arg(long, value_name = "NAME", conflicts_with = "global")]
        preset: Vec<String>,
        /// Give a local vault its own password instead of linking it to the global vault
        #[arg(long)]
        own_password: bool,
    },
    /// Type the password once; the vault stays open for a few minutes
    Unlock,
    /// Close the vault now
    Lock,
    /// What needs attention: missing values, expirations, tasks, project problems
    Status,
    /// Check or use the recovery code
    #[command(subcommand)]
    Recovery(RecoveryCmd),
    /// Change the master password
    Passwd,
    /// Check the installation and the vault
    Doctor,

    /// List entities and records (never values)
    Ls {
        /// Entity path to start from
        #[arg(add = ArgValueCompleter::new(crate::complete::entities))]
        path: Option<String>,
        /// Include archived records
        #[arg(long)]
        all: bool,
    },
    /// Create a record (and any entity on its path): cemi add acme/shop/stripe
    Add {
        #[arg(add = ArgValueCompleter::new(crate::complete::entities))]
        path: String,
    },
    /// Rename or move a record
    Mv {
        #[arg(add = ArgValueCompleter::new(crate::complete::records))]
        from: String,
        #[arg(add = ArgValueCompleter::new(crate::complete::entities))]
        to: String,
    },
    /// Archive a record (or delete it for good with --purge)
    Rm {
        #[arg(add = ArgValueCompleter::new(crate::complete::records))]
        path: String,
        #[arg(long)]
        purge: bool,
    },
    /// Define the fields of a record
    #[command(subcommand)]
    Field(FieldCmd),
    /// Search names and memory
    Find { text: String },
    /// A record's fields (secret values hidden), memory and history summary
    Show {
        #[arg(add = ArgValueCompleter::new(crate::complete::records))]
        reference: String,
    },

    /// Store a value (typed hidden, or piped with --stdin). Never as an argument.
    Set {
        /// record#field
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Environment; without it the value is shared by all environments
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        /// Read the value from standard input
        #[arg(long)]
        stdin: bool,
        /// Read the value from a file (for keys, certificates, JSON credentials)
        #[arg(long, value_name = "PATH", conflicts_with = "stdin")]
        from_file: Option<std::path::PathBuf>,
        /// Do not store the value: note where it lives instead
        #[arg(long, value_name = "WHERE", conflicts_with_all = ["stdin", "from_file"])]
        external: Option<String>,
        /// Note for the history (why it changed)
        #[arg(long)]
        note: Option<String>,
    },
    /// Generate a random value and store it without showing it
    Generate {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        #[arg(long, default_value_t = 40)]
        length: usize,
        #[arg(long, value_enum, default_value_t = Charset::Alnum)]
        charset: Charset,
        #[arg(long)]
        note: Option<String>,
    },
    /// Copy a value to the clipboard for 30 seconds (kept out of clipboard history). Without a reference, pick one
    Copy {
        /// record#field (without it: search and pick)
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: Option<String>,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
    },
    /// Print a value. Asks for the master password again.
    Reveal {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
    },
    /// Versions of a value (dates and notes, never the values)
    History {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
    },
    /// Make an older version current again
    Revert {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Version number from `cemi history` (1, 2, …)
        #[arg(value_name = "VERSION")]
        number: usize,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
    },

    /// Read or edit the memory of a record or entity: what it is for, how to rotate it…
    Note(NoteArgs),
    /// Recurring chores, like "monthly restore test"
    #[command(subcommand)]
    Task(TaskCmd),
    /// What uses this value (templates and this project's cemi.toml)
    Deps {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
    },
    /// Write a Markdown inventory without values
    Doc {
        /// Entity path (default: everything)
        #[arg(add = ArgValueCompleter::new(crate::complete::entities))]
        entity: Option<String>,
        /// Output file (default: standard output)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// Environments: list, add, remove, compare
    #[command(subcommand)]
    Env(EnvCmd),

    /// Ready-made records for common stacks: Next.js + Supabase, Stripe, Resend, Postgres
    #[command(subcommand)]
    Preset(PresetCmd),

    /// Point this project at an entity of a vault (creates or updates cemi.toml)
    Link { entity: Option<String> },
    /// Variables of this project's cemi.toml
    #[command(subcommand)]
    Var(VarCmd),
    /// Run a command with this project's secrets injected
    Run {
        #[arg(short, long, env = "CEMI_ENV", add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        /// Hide secret values in the output (the command loses its terminal)
        #[arg(long)]
        redact: bool,
        #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// TypeScript types or a zod schema for this project's variables (from cemi.toml)
    #[command(after_help = "Examples:\n  \
        cemi types -o env.d.ts\n  \
        cemi types --format zod -o src/env.ts\n  \
        cemi types -o env.d.ts --check      # in CI: fails if cemi.toml changed and the file did not")]
    Types {
        #[arg(long, value_enum, default_value_t = crate::types_gen::Format::Ts)]
        format: crate::types_gen::Format,
        /// File to write (default: standard output)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        /// Do not write: fail if the file is not up to date
        #[arg(long, requires = "output")]
        check: bool,
    },
    /// Write a .env.example with this project's variable names
    Export {
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// Import a .env file (one record per variable), or find the .env files of all your projects
    #[command(after_help = "Examples:\n  \
        cemi import .env -e dev\n  \
        cemi import --discover ~/code          # show what it finds, then ask\n  \
        cemi import --discover ~/code --yes    # import without asking")]
    Import {
        /// The .env file; with --discover, the folder to search (default: this one)
        #[arg(value_name = "PATH", required_unless_present = "discover")]
        path: Option<std::path::PathBuf>,
        /// Find .env files in every project under PATH, warn about the risky ones and import them
        #[arg(long)]
        discover: bool,
        /// Entity to put the records in (with --discover: one entity per project inside it)
        #[arg(long, add = ArgValueCompleter::new(crate::complete::entities))]
        into: Option<String>,
        /// Environment, like dev or prod (default: the value shared by all; with --discover, guessed from each file name)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        /// Variables that are not secret, comma separated
        #[arg(long, default_value = "")]
        plain: String,
        /// Do not add the variables to cemi.toml
        #[arg(long)]
        no_link: bool,
        /// With --discover: how many folders deep to look
        #[arg(long, default_value_t = 5, requires = "discover")]
        depth: usize,
        /// With --discover: import without asking
        #[arg(short, long, requires = "discover")]
        yes: bool,
    },

    /// Where a key is created, per environment (used by `cemi rotate`)
    #[command(subcommand)]
    Origin(OriginCmd),
    /// Places a value is copied to: GitHub, Supabase, .env files, commands…
    #[command(subcommand)]
    Dest(DestCmd),
    /// Set a command that checks a value works (it gets the value on stdin)
    Verify {
        /// record#field
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        /// Remove the check
        #[arg(long, conflicts_with = "command")]
        clear: bool,
        #[arg(
            trailing_var_arg = true,
            value_name = "COMMAND",
            required_unless_present = "clear"
        )]
        command: Vec<String>,
    },
    /// Send current values to the destinations that are missing them or are out of date
    Push {
        /// record#field (default: every field with destinations)
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: Option<String>,
        /// Only the destinations of this environment
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        /// Send without checking first: also overwrites values changed outside Cemí
        #[arg(long)]
        force: bool,
    },
    /// Compare destinations with the vault: out of date, changed outside Cemí, missing
    Check {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: Option<String>,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        /// Do not contact providers; compare with what Cemí last sent
        #[arg(long)]
        offline: bool,
    },
    /// Replace a key everywhere: create it, send it, verify it, revoke the old one
    Rotate {
        /// record#field
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        /// The old key leaked: revoke it as soon as the new one works
        #[arg(long)]
        leaked: bool,
        /// Let Cemí make the new value (for services that accept any value)
        #[arg(long, conflicts_with = "paste")]
        generate: bool,
        /// Type the new value (when the provider has no API)
        #[arg(long)]
        paste: bool,
        #[arg(long, default_value_t = 40, requires = "generate")]
        length: usize,
        #[arg(long, value_enum, default_value_t = Charset::Alnum, requires = "generate")]
        charset: Charset,
        /// Keep the old key valid (revoke it later with `cemi revoke`)
        #[arg(long, conflicts_with = "leaked")]
        keep_old: bool,
        /// Do not ask "go ahead?" (protected environments still ask for the password)
        #[arg(short, long)]
        yes: bool,
    },
    /// Revoke an old version of a key at its origin
    Revoke {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        /// Version number from `cemi history`
        #[arg(
            value_name = "VERSION",
            conflicts_with = "pending",
            required_unless_present = "pending"
        )]
        number: Option<usize>,
        /// The value left pending by a rotation that did not finish
        #[arg(long)]
        pending: bool,
        /// Report the key as leaked to the provider
        #[arg(long)]
        leaked: bool,
    },
    /// A key leaked: what it reaches, who used it, and how to replace it
    Incident {
        /// record#field (one or more)
        #[arg(required = true, add = ArgValueCompleter::new(crate::complete::references))]
        references: Vec<String>,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        /// Rotate them now (as leaked)
        #[arg(long)]
        rotate: bool,
        #[arg(short, long)]
        yes: bool,
    },
    /// Changes that an AI client asked for in protected environments
    Approve {
        /// Request id (without it: list the requests)
        id: Option<String>,
        /// Refuse the request
        #[arg(long, requires = "id")]
        deny: bool,
    },

    /// Access tokens for AI clients
    #[command(subcommand)]
    Token(TokenCmd),
    /// MCP: serve Cemí to AI clients, and launch other MCP servers with their keys
    #[command(subcommand)]
    Mcp(McpCmd),
    /// The audit log
    Log {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Check the chain of entries
        #[arg(long)]
        verify: bool,
    },
    /// Look for this vault's secret values in files, staged changes or git history
    Scan {
        path: Option<std::path::PathBuf>,
        /// Only what is staged for the next commit
        #[arg(long, conflicts_with = "history")]
        staged: bool,
        /// The whole git history
        #[arg(long)]
        history: bool,
    },
    /// Git hooks
    #[command(subcommand)]
    Hook(HookCmd),

    /// Tab completion for your shell, including record and environment names
    #[command(
        after_help = "Names come from vaults that are already unlocked; completing never asks for a password."
    )]
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Internal: keeps a copied value on the clipboard, then clears it
    #[command(hide = true, name = "__clipboard")]
    ClipboardHelper { seconds: u64 },
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Charset {
    /// Letters and digits
    Alnum,
    /// 0-9 a-f
    Hex,
    /// Letters, digits, - and _
    Base64url,
    /// Letters, digits and punctuation
    Symbols,
}

#[derive(Subcommand)]
pub enum RecoveryCmd {
    /// Check that a recovery code opens the vault
    Verify,
    /// Forgot the password: use the recovery code to set a new one
    Reset,
    /// Replace the recovery code (the old one stops working)
    New,
}

#[derive(Subcommand)]
pub enum FieldCmd {
    /// Add a field: cemi field add acme/shop/stripe secret --secret
    Add {
        /// Record path
        #[arg(add = ArgValueCompleter::new(crate::complete::records))]
        record: String,
        name: String,
        #[arg(long = "type", value_enum, default_value_t = FieldKind::Text)]
        kind: FieldKind,
        /// The value is secret: hidden, never shown to AI clients
        #[arg(long)]
        secret: bool,
    },
    /// Remove a field and its values
    Rm { reference: String },
    /// Change a field's type or secrecy
    Edit {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        #[arg(long = "type", value_enum)]
        kind: Option<FieldKind>,
        #[arg(long)]
        secret: Option<bool>,
        #[arg(long)]
        rename: Option<String>,
    },
}

#[derive(clap::Args)]
pub struct NoteArgs {
    /// Record or entity path
    #[arg(add = ArgValueCompleter::new(crate::complete::records))]
    pub path: String,
    #[arg(long)]
    pub purpose: Option<String>,
    #[arg(long)]
    pub used_in: Option<String>,
    #[arg(long)]
    pub rotate: Option<String>,
    #[arg(long)]
    pub if_lost: Option<String>,
    #[arg(long)]
    pub if_leaked: Option<String>,
    /// YYYY-MM-DD
    #[arg(long)]
    pub expires: Option<String>,
    #[arg(long)]
    pub backup: Option<String>,
    #[arg(long)]
    pub links: Option<String>,
    /// e.g. "rotating it requires migrating data"
    #[arg(long)]
    pub delicate: Option<String>,
    /// Any other note: --set key=value
    #[arg(long, value_name = "KEY=VALUE")]
    pub set: Vec<String>,
    #[arg(long, value_name = "KEY")]
    pub unset: Vec<String>,
}

#[derive(Subcommand)]
pub enum TaskCmd {
    /// cemi task add acme "restore test" --every month
    Add {
        #[arg(add = ArgValueCompleter::new(crate::complete::entities))]
        entity: String,
        name: String,
        #[arg(long, value_enum)]
        every: Every,
    },
    /// Mark a task as done today
    Done {
        #[arg(add = ArgValueCompleter::new(crate::complete::entities))]
        entity: String,
        name: String,
    },
    Rm {
        #[arg(add = ArgValueCompleter::new(crate::complete::entities))]
        entity: String,
        name: String,
    },
    Ls,
}

#[derive(Subcommand)]
pub enum EnvCmd {
    Ls {
        #[arg(long, add = ArgValueCompleter::new(crate::complete::entities))]
        at: Option<String>,
    },
    Add {
        name: String,
        /// Entity that gets the environment (inherited below it)
        #[arg(long, add = ArgValueCompleter::new(crate::complete::entities))]
        at: Option<String>,
    },
    Rm {
        name: String,
        #[arg(long, add = ArgValueCompleter::new(crate::complete::entities))]
        at: Option<String>,
    },
    /// What is missing in one environment, and secrets that are equal in both
    Diff {
        a: String,
        b: String,
        #[arg(long, add = ArgValueCompleter::new(crate::complete::entities))]
        at: Option<String>,
    },
    /// Changes in this environment need the password (AI clients need `cemi approve`)
    Protect { name: String },
    /// Stop protecting an environment (asks for the password)
    Unprotect { name: String },
}

#[derive(Subcommand)]
pub enum OriginCmd {
    /// cemi origin set acme/shop/supabase#key -e prod supabase-key --project abcd --token global:accounts/supabase#token
    Set {
        /// record#field
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        #[command(subcommand)]
        kind: OriginKind,
    },
    /// Forget the origin
    Rm {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Environment, like dev or prod (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum OriginKind {
    /// A Supabase secret API key (sb_secret_…), created and deleted through the Management API
    SupabaseKey {
        /// Project ref (the id in your project URL)
        #[arg(long)]
        project: String,
        /// record#field with a Supabase access token
        #[arg(long)]
        token: String,
        /// Base name for the keys; Cemí adds the date
        #[arg(long, default_value = "cemi")]
        name: String,
        #[arg(long, hide = true)]
        api_url: Option<String>,
    },
    /// Your program: `COMMAND create` prints a new value, `COMMAND revoke` gets the old one on stdin
    Command {
        #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// A program called cemi-connector-NAME (see docs/connectors.md)
    External {
        name: String,
        /// Option for the connector
        #[arg(long = "set", value_name = "KEY=VALUE")]
        set: Vec<String>,
        /// Secret option, given as a reference: --secret token=global:accounts/x#token
        #[arg(long = "secret", value_name = "KEY=REF")]
        secret: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum DestCmd {
    /// cemi dest add acme/shop/stripe#key -e prod github --repo acme/shop --name STRIPE_KEY
    Add {
        /// record#field
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Environment whose value goes there (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        #[command(subcommand)]
        kind: DestKind,
    },
    /// Destinations of one field, or of all
    Ls { reference: Option<String> },
    /// Forget a destination (nothing is deleted there)
    Rm {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Id from `cemi dest ls`
        id: String,
    },
}

#[derive(Subcommand)]
pub enum DestKind {
    /// A GitHub Actions secret (of the repository, or of one of its environments)
    Github {
        /// owner/name
        #[arg(long)]
        repo: String,
        /// Secret name
        #[arg(long)]
        name: String,
        /// GitHub environment (default: a repository secret)
        #[arg(long)]
        environment: Option<String>,
        /// record#field with a GitHub token (default: the GitHub CLI's login)
        #[arg(long)]
        token: Option<String>,
        /// For GitHub Enterprise Server: https://HOST/api/v3
        #[arg(long)]
        api_url: Option<String>,
    },
    /// A Supabase Edge Function secret
    SupabaseSecret {
        #[arg(long)]
        project: String,
        #[arg(long)]
        name: String,
        /// record#field with a Supabase access token
        #[arg(long)]
        token: String,
        #[arg(long, hide = true)]
        api_url: Option<String>,
    },
    /// A variable in a .env file on this computer
    Dotenv {
        #[arg(long, default_value = ".env")]
        file: std::path::PathBuf,
        /// Variable name
        #[arg(long)]
        key: String,
    },
    /// A program that receives the value on stdin: -- gh secret set NAME
    Command {
        #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// A program called cemi-connector-NAME (see docs/connectors.md)
    External {
        name: String,
        #[arg(long = "set", value_name = "KEY=VALUE")]
        set: Vec<String>,
        #[arg(long = "secret", value_name = "KEY=REF")]
        secret: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum PresetCmd {
    /// The presets that come with Cemí
    Ls,
    /// Add a preset's records, notes and variables: cemi preset add stripe
    Add {
        #[arg(required = true, value_name = "NAME")]
        names: Vec<String>,
        /// Entity to put the records in (default: the vault's top)
        #[arg(long, add = ArgValueCompleter::new(crate::complete::entities))]
        into: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum VarCmd {
    /// cemi var add DATABASE_URL db#url
    Add {
        name: String,
        reference: String,
        /// Give the program a file path instead of the value
        #[arg(long)]
        file: bool,
    },
    Rm {
        name: String,
    },
    Ls,
}

#[derive(Subcommand)]
pub enum TokenCmd {
    /// Create a token for an AI client
    Create {
        name: String,
        /// Entity paths it can see (repeat; default: all)
        #[arg(long = "entity")]
        entities: Vec<String>,
        /// Environments it can use (repeat; default: all)
        #[arg(long = "env")]
        envs: Vec<String>,
        /// What it can do (repeat)
        #[arg(long = "allow", value_enum, default_values_t = vec![Permission::Read])]
        allow: Vec<Permission>,
        /// 7d, 24h, 90d or never
        #[arg(long, default_value = "30d")]
        expires: String,
        /// Also print the token (for clients that need it in a variable)
        #[arg(long)]
        print: bool,
    },
    Ls,
    Revoke {
        name: String,
    },
}

#[derive(Subcommand)]
pub enum McpCmd {
    /// Run the Cemí MCP server on standard input/output
    Serve {
        /// Token stored on this computer by `cemi token create` (or set CEMI_TOKEN)
        #[arg(long)]
        token_name: Option<String>,
    },
    /// Connect an AI client to Cemí
    Setup {
        /// claude-code, claude-desktop, cursor or other
        client: String,
        #[arg(long)]
        token_name: String,
    },
    /// Register another MCP server with keys injected: cemi mcp add supabase --env TOKEN=cuentas/supabase#token -- npx -y @supabase/mcp-server-supabase
    Add {
        name: String,
        #[arg(long = "env", value_name = "VAR=REF")]
        env: Vec<String>,
        #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Start a registered MCP server (use this as the command in your AI client)
    Launch {
        name: String,
    },
    Ls,
    Rm {
        name: String,
    },
}

#[derive(Subcommand)]
pub enum HookCmd {
    /// Run `cemi scan --staged` before every commit in this repository
    Install {
        #[arg(long)]
        force: bool,
    },
}

#[cfg(test)]
mod tests {
    #[test]
    fn command_definitions_are_valid() {
        use clap::CommandFactory;
        super::Cli::command().debug_assert();
    }
}
