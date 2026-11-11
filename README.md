# Cemí

**Secrets with memory that your AI can use without seeing.**

[Español](README.es.md)

Cemí keeps your API keys, tokens and passwords encrypted on your computer, together with
what each one is for, where it is used and how to replace it. Your projects run with them
injected, and AI assistants (Claude, ChatGPT, Cursor… through MCP) can use them without
ever receiving the values.

*The name comes from the Taíno cemí, a carved figure that guarded what its owners valued.*

> **Status: v0.1, early.** The format and commands may still change. Read
> [docs/threat-model.md](docs/threat-model.md) before trusting it with production secrets.

## Why

- **Secrets are scattered**: CI secrets, `.env` files, servers, function secrets, a password
  manager. Some are never stored anywhere ("if it is lost, regenerate it"). You still need to
  know they exist.
- **The important part is not the value**: what it is for, where it is copied, how to rotate
  it, when it expires, whether it has a backup. Every team ends up writing this down by hand.
- **AI assistants need keys** to run tests or deploy, and the usual way of giving them
  (pasting into the chat, or a `.env` the AI reads) leaks them.

## What makes it different

- **Your structure, not a fixed schema.** Entities inside entities (`acme/shop`), records
  inside them, and fields you name yourself. No "AWS key" templates.
- **Memory next to each secret**: purpose, where it is used, how to rotate it, what to do if it
  is lost or leaked, expiry, backup. `cemi status` tells you what needs attention.
- **Environments** (`dev`, `prod`…) inherited down the tree.
- **The AI uses, never sees.** No MCP tool returns a secret value. The AI can list, read notes,
  generate new secrets and run allowlisted commands with secrets injected and hidden from the
  output. A person unlocks the vault; tokens are scoped, expire and can be revoked.
- **Open format.** Every record is an [age](https://age-encryption.org) file. If Cemí
  disappears, your data still opens with standard tools.
- **Local first.** No account, no server, no network.

## Install

Cemí is a single executable.

```bash
cargo install --git https://github.com/hamador0016/cemi --locked
```

Coming with the first release: `cargo install cemi`, `npm install -g cemi`, Homebrew and
an install script, plus `npm install --save-dev cemi` or `mise use cemi` to pin it per project.

## Quick start

```bash
# Once per computer: the global vault (shared keys live here)
cemi init --global

# In a project, like `git init`
cd my-project
cemi init                         # creates .cemi/ (git-ignored) and cemi.toml
cemi add db
cemi field add db password --secret
cemi set db#password -e dev       # typed hidden; never as an argument
cemi field add db url --type template
cemi set db#url --stdin <<< 'postgres://app:{{db#password}}@localhost/app'
cemi var add DATABASE_URL db#url  # cemi.toml gets a reference, not the value
cemi run -e dev -- npm run dev    # DATABASE_URL is injected
cemi note db --purpose "app database" --rotate "ALTER ROLE app PASSWORD …" --backup "password manager"
cemi status
```

The local vault opens with your global password. Shared keys can live in the global vault and
be referenced from any project: `cemi var add CF_TOKEN global:accounts/cloudflare#token`.

## With an AI assistant

```bash
cemi token create claude --allow read --allow run --env dev --expires 7d
cemi mcp setup claude-code --token-name claude
```

Then in `cemi.toml`, list what the AI may run:

```toml
[ai.commands]
test = { cmd = ["npm", "test"], envs = ["dev"] }
```

The AI can now see your records and notes, ask what needs attention, generate secrets and run
`test` with the keys injected. Values in the output come back as `[hidden:DATABASE_URL]`.

Other MCP servers usually want a token in their configuration file. Keep it in Cemí instead:

```bash
cemi mcp add supabase --env SUPABASE_ACCESS_TOKEN=global:accounts/supabase#token -- npx -y @supabase/mcp-server-supabase
# In the AI client, the command becomes: cemi mcp launch supabase
```

**What redaction does not cover.** A command that receives a secret in its environment can
still send it elsewhere or print it in an encoding Cemí does not recognize. Cemí narrows this
down: AI clients can only run the commands you list, in the environments you list. The
credential proxy planned for v0.4 closes it for HTTP APIs, because the command never receives
the key. Until then, do not let an AI run commands with production secrets. Details in
[docs/threat-model.md](docs/threat-model.md).

## Never commit a secret

```bash
cemi hook install        # pre-commit: blocks commits that contain any value from your vaults
cemi scan --history      # looks for your values in the whole git history
```

Unlike pattern scanners, `cemi scan` looks for *your* values, whatever their format.

## Commands

| Area | Commands |
|---|---|
| Vault | `init [-g]`, `unlock`, `lock`, `status`, `recovery verify/reset/new`, `passwd`, `doctor`, `log` |
| Structure | `ls`, `add`, `mv`, `rm`, `field add/rm/edit`, `find`, `show` |
| Values | `set`, `generate`, `copy`, `reveal`, `history`, `revert` |
| Memory | `note`, `task`, `deps`, `doc` |
| Environments | `env ls/add/rm/diff` |
| Project | `link`, `var add/rm/ls`, `run`, `export`, `import` |
| AI | `token create/ls/revoke`, `mcp serve/setup/add/launch/ls/rm` |
| Git | `scan`, `hook install` |

`cemi help <command>` explains each one. References look like `[global:|local:]entity/record#field`.

## How it is built

- Password → Argon2id (256 MiB) → unwraps the vault key (X25519). A recovery code is created
  with every vault.
- Each entity has its own key; records are age files encrypted to their entity. Names are
  encrypted too: on disk there are only random ids.
- After `cemi unlock`, the vault key stays in the operating system's credential store for 15
  minutes of inactivity. `cemi lock` removes it.
- Audit log of every use, without values, chained with SHA-256.

Design notes (Spanish): [docs/design.es.md](docs/design.es.md).

## Roadmap

- **v0.2**: rotation. Cemí knows where each key is born and where it is copied (GitHub secrets,
  Supabase, `.env` files…), so `cemi rotate` creates a new key, updates every destination,
  verifies and revokes the old one, with your approval.
- **v0.3**: daily use: discover existing `.env` files, shell completions, types for your code,
  secrets in CI.
- **v0.4**: desktop app and credential proxy (the AI calls APIs without receiving the key).
- **v0.5**: sync between your machines and sharing one entity with someone else.

Full plan: [docs/roadmap.md](docs/roadmap.md).

## License

Apache-2.0. Cemí comes with no warranty: you are responsible for your keys and your recovery code.
