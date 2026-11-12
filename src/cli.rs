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

    /// Never ask for a password or a confirmation; fail instead (exit code 3 or 5). For editors and other tools
    #[arg(long, global = true)]
    pub no_input: bool,

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
    /// One short line for your shell prompt: what needs doing soon, or "locked"
    #[command(
        after_help = "Prints nothing when all is well. It never asks for a password and never uses the network.\n\n\
        Starship (~/.config/starship.toml):\n  \
        [custom.cemi]\n  \
        command = \"cemi prompt\"\n  \
        when = true\n  \
        style = \"bold yellow\""
    )]
    Prompt,
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
    /// What uses a value or record: every project Cemí knows, templates, connectors, CI files
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

    /// Secrets for CI: encrypt what CI needs into the repository, open it there with one key
    #[command(subcommand)]
    Ci(CiCmd),

    /// Point this project at an entity of a vault (creates or updates cemi.toml)
    Link { entity: Option<String> },
    /// Variables of this project's cemi.toml
    #[command(subcommand)]
    Var(VarCmd),
    /// The projects each vault knows, so `cemi deps` searches all of them
    #[command(subcommand)]
    Project(ProjectCmd),
    /// Run a command with this project's secrets injected
    Run {
        #[arg(short, long, env = "CEMI_ENV", add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        /// Hide secret values in the output (the command loses its terminal)
        #[arg(long)]
        redact: bool,
        /// Secrets that have an API (`cemi api add`) go through Cemí's proxy: the
        /// command gets a placeholder, and [proxy] variables get the proxy's address
        #[arg(long)]
        proxy: bool,
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
    /// HTTP APIs a key signs in to, called through Cemí's proxy without handing out the key
    #[command(subcommand)]
    Api(ApiCmd),
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
        /// Request id (without it: list the requests, and in a terminal pick one)
        id: Option<String>,
        /// Refuse the request
        #[arg(long, requires = "id")]
        deny: bool,
    },
    /// How a person confirms approvals and protected changes: device (Windows Hello or Touch ID) or password
    ApproveWith {
        #[arg(value_enum)]
        method: crate::model::ApproveWith,
    },
    /// An icon in the notification area that tells you when an AI asks for approval (Windows)
    Tray {
        /// Also watch the local vault of these project folders (the current one is always watched)
        #[arg(long = "project", value_name = "FOLDER")]
        projects: Vec<std::path::PathBuf>,
        /// Stay attached to this terminal (used when the icon starts itself)
        #[arg(long, hide = true)]
        foreground: bool,
    },

    /// Give an entity to another developer, encrypted to their key (no server)
    #[command(after_help = "Examples:
          cemi share key                                      # your public key, for others to share with you
          cemi share acme/shop --with age1… -e dev --name ana # writes acme-shop.share.age
          cemi share accept acme-shop.share.age               # on the receiver's computer
          cemi share ls")]
    Share(ShareArgs),
    /// Keep this vault the same on several computers through a private git repository
    #[command(after_help = "Examples:
          cemi sync init git@github.com:me/vault.git -g   # once, on the first computer
          cemi sync clone git@github.com:me/vault.git -g  # on another computer
          cemi sync -g                                    # send and receive changes")]
    Sync(SyncArgs),

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

    /// Update cemi itself (when it was installed with the install script)
    #[command(name = "self", subcommand)]
    SelfCmd(SelfCmd),

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
    /// A Cloudflare API token: each new one copies the permissions of the current one
    CloudflareToken {
        /// record#field with a token allowed to create and delete tokens (API Tokens Write)
        #[arg(long)]
        token: String,
        /// For account-owned tokens: the account id (default: tokens of your user)
        #[arg(long)]
        account: Option<String>,
        /// Base name for the tokens; Cemí adds the date
        #[arg(long, default_value = "cemi")]
        name: String,
        #[arg(long, hide = true)]
        api_url: Option<String>,
    },
    /// A Resend API key, created and deleted through the Resend API
    ResendKey {
        /// record#field with a full-access Resend key
        #[arg(long)]
        token: String,
        /// Base name for the keys; Cemí adds the date
        #[arg(long, default_value = "cemi")]
        name: String,
        /// full_access or sending_access
        #[arg(long, default_value = "sending_access")]
        permission: String,
        /// With sending_access: the id of the only domain it may send from
        #[arg(long)]
        domain: Option<String>,
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
    /// A Cloudflare Workers secret
    CloudflareWorker {
        /// Account id (32 characters, in the dashboard)
        #[arg(long)]
        account: String,
        /// Worker name
        #[arg(long)]
        script: String,
        /// Secret name
        #[arg(long)]
        name: String,
        /// record#field with a token allowed to edit Workers (Workers Scripts Write)
        #[arg(long)]
        token: String,
        #[arg(long, hide = true)]
        api_url: Option<String>,
    },
    /// A Netlify environment variable of a site (or of the whole team), for one deploy context
    Netlify {
        /// Team slug (app.netlify.com/teams/SLUG)
        #[arg(long)]
        account: String,
        /// Site id (default: a variable of the whole team)
        #[arg(long)]
        site: Option<String>,
        /// Variable name
        #[arg(long)]
        key: String,
        /// production, deploy-preview, branch-deploy, dev or all
        #[arg(long, default_value = "production")]
        context: String,
        /// Create it as a normal variable, readable in the dashboard (default: secret)
        #[arg(long)]
        plain: bool,
        /// record#field with a Netlify personal access token
        #[arg(long)]
        token: String,
        #[arg(long, hide = true)]
        api_url: Option<String>,
    },
    /// A Vercel project environment variable for one target
    Vercel {
        /// Project name or id
        #[arg(long)]
        project: String,
        /// Variable name
        #[arg(long)]
        key: String,
        /// production, preview or development
        #[arg(long, default_value = "production")]
        target: String,
        /// Team id, for projects of a team
        #[arg(long)]
        team: Option<String>,
        /// record#field with a Vercel access token
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
    /// A variable in a .env file on a server, through your ssh (keys or agent, no passwords)
    Ssh {
        /// user@server, or a Host from ~/.ssh/config
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: Option<u16>,
        /// Path of the .env file on the server
        #[arg(long)]
        file: String,
        /// Variable name
        #[arg(long)]
        key: String,
        /// Command run on the server after the file changes, like 'systemctl restart app'
        #[arg(long)]
        restart: Option<String>,
        /// Another ssh program; repeat for its first arguments
        #[arg(long = "ssh-program", hide = true)]
        ssh_program: Vec<String>,
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
pub enum ApiCmd {
    /// cemi api add acme/shop/stripe#secret -e prod --base https://api.stripe.com --auth bearer --allow "GET /v1/**"
    #[command(
        after_help = "Rules: METHOD PATH, where * matches inside one path segment and ** any number of segments.
          --allow \"GET /v1/**\"            every GET under /v1
          --allow \"POST /v1/refunds\"      one path
          --allow \"* /rest/v1/orders*\"    any method
        Auth: bearer (Authorization: Bearer KEY), basic (KEY as the user name), header:NAME, query:NAME"
    )]
    Add {
        /// record#field with the key
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Environment whose value is used (default: the value shared by all)
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        /// The API's address, like https://api.stripe.com. Requests never go anywhere else
        #[arg(long)]
        base: String,
        /// Where the key goes in each request (repeat for more than one place)
        #[arg(long, default_value = "bearer")]
        auth: Vec<String>,
        /// Allowed calls, like "GET /v1/**" (repeat it; nothing else is allowed)
        #[arg(long, required = true)]
        allow: Vec<String>,
    },
    /// APIs of one field, or of all
    Ls { reference: Option<String> },
    /// Forget an API
    Rm {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        /// Id from `cemi api ls`
        id: String,
    },
    /// Call an API through the proxy, as an AI client would: cemi api call stripe#secret -e prod GET /v1/balance
    Call {
        #[arg(add = ArgValueCompleter::new(crate::complete::references))]
        reference: String,
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: Option<String>,
        method: String,
        /// Path and query, like /v1/charges?limit=3
        path: String,
        /// Request body (@FILE reads a file)
        #[arg(long)]
        data: Option<String>,
        /// Extra header, NAME:VALUE
        #[arg(short = 'H', long = "header", value_name = "NAME:VALUE")]
        header: Vec<String>,
    },
}

#[derive(clap::Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ShareArgs {
    #[command(subcommand)]
    pub cmd: Option<ShareCmd>,
    /// Entity to share, like acme/shop (with everything below it)
    #[arg(requires_all = ["with", "envs"])]
    pub entity: Option<String>,
    /// The receiver's public key (they get it with `cemi share key`)
    #[arg(long, value_name = "PUBLIC_KEY")]
    pub with: Option<String>,
    /// Environments whose values go (repeat it); no other value is included
    #[arg(short = 'e', long = "env", add = ArgValueCompleter::new(crate::complete::envs))]
    pub envs: Vec<String>,
    /// A name for the receiver, for `cemi share ls` and `cemi status`
    #[arg(long)]
    pub name: Option<String>,
    /// File to write (default: <entity>.share.age in this folder)
    #[arg(short, long)]
    pub output: Option<std::path::PathBuf>,
}

#[derive(Subcommand)]
pub enum ShareCmd {
    /// This vault's public key, to give to whoever shares with you
    Key,
    /// Import a share file into this vault
    Accept {
        file: std::path::PathBuf,
        /// Put it under another entity path (default: the sender's path)
        #[arg(long = "as", value_name = "ENTITY")]
        as_path: Option<String>,
        /// Do not ask (it still shows who sent it and what it holds)
        #[arg(long)]
        yes: bool,
    },
    /// What this vault shared, with whom, and whether it changed since
    Ls,
}

#[derive(clap::Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct SyncArgs {
    #[command(subcommand)]
    pub cmd: Option<SyncCmd>,
}

#[derive(Subcommand)]
pub enum SyncCmd {
    /// Start syncing this vault to an empty private git repository
    Init { remote: String },
    /// Copy a synced vault to this computer (-g: as the global vault; otherwise .cemi here)
    Clone { remote: String },
}

#[derive(Subcommand)]
pub enum SelfCmd {
    /// Download and install the newest release, checked with its SHA-256
    Update,
}

#[derive(Subcommand)]
pub enum CiCmd {
    /// Make this project's CI key; with --repo, also store it as a GitHub secret
    Setup {
        /// GitHub repository (owner/name) that gets the secret CEMI_CI_KEY
        #[arg(long)]
        repo: Option<String>,
        /// GitHub environment for the secret (default: a repository secret)
        #[arg(long, requires = "repo")]
        environment: Option<String>,
        /// Replace the key (export again afterwards)
        #[arg(long)]
        new_key: bool,
    },
    /// Encrypt this project's variables for one environment into cemi.ci.age (safe to commit)
    Export {
        #[arg(short, long, add = ArgValueCompleter::new(crate::complete::envs))]
        env: String,
        /// Only these variables (comma separated; default: [ci] vars, or all)
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// File to write (default: [ci] file, or cemi.ci.age next to cemi.toml)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// In CI: open the file with CEMI_CI_KEY and pass the values on (no vault needed)
    #[command(after_help = "Examples:\n  \
        cemi ci load --github-env          # GitHub Actions: masked, and set for the next steps\n  \
        cemi ci load -- npm run deploy     # any CI: run one command with the values, hidden in its output")]
    Load {
        /// The encrypted file (default: [ci] file of cemi.toml here, or cemi.ci.age)
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Write the values to $GITHUB_ENV, masked in the log
        #[arg(long, conflicts_with = "command")]
        github_env: bool,
        #[arg(trailing_var_arg = true, value_name = "COMMAND")]
        command: Vec<String>,
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
pub enum ProjectCmd {
    /// Projects that use this vault (-g: the global vault)
    Ls,
    /// Note a project folder now, without running anything there
    Add {
        /// Folder with a cemi.toml (default: this one)
        path: Option<std::path::PathBuf>,
    },
    /// Forget a project folder (its files are not touched)
    Rm {
        /// The folder, or its name as `cemi project ls` shows it
        project: String,
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
    /// Connect an AI client to Cemí: adds the server "cemi" to the client's configuration
    #[command(
        after_help = "With a project vault, the client's project file is written in the project folder         (.cursor/mcp.json, .mcp.json for VS Code, .zed/settings.json, .codex/config.toml, .gemini/settings.json,         .devin/mcp_config.json); with --global, the client's file for every project.         Claude Desktop and Windsurf only have the second. Other servers and settings in the file are kept.         `other` prints a generic snippet.

        Examples:
          cemi mcp setup cursor --token-name claude
          cemi --global mcp setup claude-desktop --token-name claude
          cemi mcp setup zed --token-name claude --print    # only show what to add"
    )]
    Setup {
        #[arg(value_parser = clap::builder::PossibleValuesParser::new(crate::mcp_clients::CLIENT_NAMES))]
        client: String,
        #[arg(long)]
        token_name: String,
        /// Only print what to add to the client's configuration; change nothing
        #[arg(long)]
        print: bool,
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
