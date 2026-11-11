//! Command-line interface. Commands are short and predictable, like git's.

use clap::{Parser, Subcommand};

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
        path: Option<String>,
        /// Include archived records
        #[arg(long)]
        all: bool,
    },
    /// Create a record (and any entity on its path): cemi add acme/shop/stripe
    Add { path: String },
    /// Rename or move a record
    Mv { from: String, to: String },
    /// Archive a record (or delete it for good with --purge)
    Rm {
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
    Show { reference: String },

    /// Store a value (typed hidden, or piped with --stdin). Never as an argument.
    Set {
        /// record#field
        reference: String,
        /// Environment; without it the value is shared by all environments
        #[arg(short, long)]
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
        reference: String,
        #[arg(short, long)]
        env: Option<String>,
        #[arg(long, default_value_t = 40)]
        length: usize,
        #[arg(long, value_enum, default_value_t = Charset::Alnum)]
        charset: Charset,
        #[arg(long)]
        note: Option<String>,
    },
    /// Copy a value to the clipboard for 30 seconds (kept out of clipboard history)
    Copy {
        reference: String,
        #[arg(short, long)]
        env: Option<String>,
    },
    /// Print a value. Asks for the master password again.
    Reveal {
        reference: String,
        #[arg(short, long)]
        env: Option<String>,
    },
    /// Versions of a value (dates and notes, never the values)
    History {
        reference: String,
        #[arg(short, long)]
        env: Option<String>,
    },
    /// Make an older version current again
    Revert {
        reference: String,
        /// Version number from `cemi history` (1, 2, …)
        #[arg(value_name = "VERSION")]
        number: usize,
        #[arg(short, long)]
        env: Option<String>,
    },

    /// Read or edit the memory of a record or entity: what it is for, how to rotate it…
    Note(NoteArgs),
    /// Recurring chores, like "monthly restore test"
    #[command(subcommand)]
    Task(TaskCmd),
    /// What uses this value (templates and this project's cemi.toml)
    Deps { reference: String },
    /// Write a Markdown inventory without values
    Doc {
        /// Entity path (default: everything)
        entity: Option<String>,
        /// Output file (default: standard output)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// Environments: list, add, remove, compare
    #[command(subcommand)]
    Env(EnvCmd),

    /// Point this project at an entity of a vault (creates or updates cemi.toml)
    Link { entity: Option<String> },
    /// Variables of this project's cemi.toml
    #[command(subcommand)]
    Var(VarCmd),
    /// Run a command with this project's secrets injected
    Run {
        #[arg(short, long, env = "CEMI_ENV")]
        env: Option<String>,
        /// Hide secret values in the output (the command loses its terminal)
        #[arg(long)]
        redact: bool,
        #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Write a .env.example with this project's variable names
    Export {
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// Import a .env file: one record per variable
    Import {
        file: std::path::PathBuf,
        /// Entity to put the records in
        #[arg(long)]
        into: Option<String>,
        #[arg(short, long)]
        env: Option<String>,
        /// Variables that are not secret, comma separated
        #[arg(long, default_value = "")]
        plain: String,
        /// Do not add the variables to cemi.toml
        #[arg(long)]
        no_link: bool,
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

    /// Internal: keeps a copied value on the clipboard, then clears it
    #[command(hide = true, name = "__clipboard")]
    ClipboardHelper { seconds: u64 },
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
        entity: String,
        name: String,
        #[arg(long, value_enum)]
        every: Every,
    },
    /// Mark a task as done today
    Done {
        entity: String,
        name: String,
    },
    Rm {
        entity: String,
        name: String,
    },
    Ls,
}

#[derive(Subcommand)]
pub enum EnvCmd {
    Ls {
        #[arg(long)]
        at: Option<String>,
    },
    Add {
        name: String,
        /// Entity that gets the environment (inherited below it)
        #[arg(long)]
        at: Option<String>,
    },
    Rm {
        name: String,
        #[arg(long)]
        at: Option<String>,
    },
    /// What is missing in one environment, and secrets that are equal in both
    Diff {
        a: String,
        b: String,
        #[arg(long)]
        at: Option<String>,
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
