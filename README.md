# Cemí

**Secrets with memory that your AI can use without seeing.**

[Español](README.es.md)

Cemí keeps your API keys, tokens and passwords encrypted on your computer, together with
what each one is for, where it is used and how to replace it. Your projects run with them
injected, and AI assistants (Claude, ChatGPT, Cursor… through MCP) can use them without
ever receiving the values.

*The name comes from the Taíno cemí, a carved figure that guarded what its owners valued.*

> **Status: v0.2, early.** The format and commands may still change. Read
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

Tab completion, including your record and environment names while the vault is unlocked:
`cemi completion powershell` (or `bash`, `zsh`, `fish`, `elvish`) prints the line for your
shell's profile.

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

For a common stack, start from a preset instead of a blank vault:

```bash
cemi init --preset next-supabase --preset stripe
```

It creates the records with their fields, notes on how to rotate each key and what to do if
it leaks, and the variables in `cemi.toml`; then it lists the `cemi set` commands for the
values. `cemi preset ls` shows them all (Supabase, Next.js + Supabase, Stripe, Resend,
Postgres); `cemi preset add` adds one to a project that already exists.

## Already have .env files?

```bash
cemi import --discover ~/code
```

Cemí finds the `.env` files of every project under that folder (skipping `node_modules`,
build output and `.env.example`) and shows what it found before changing anything:

```text
  shop  →  global:shop
    .env                       all        2 variables
    .env.local                 dev        1 variable
    .env.production            prod       1 variable

! shop/.env.production is committed to git: anyone with the repository has these keys. …
! web/.env is not in .gitignore: one `git add .` away from being committed
! The same value is in PAYMENTS in web/.env, STRIPE_KEY in shop/.env.local: …
! api/.env.staging has not changed since 2024-01-01: its keys may be due for rotation
```

After a yes, each project gets an entity in the global vault and a `cemi.toml` that points at
it. The environment comes from the file name: `.env` is for every environment, and
`.env.<env>` and `.env.local` override it, the way most loaders read them. Then
`cemi run -e dev -- <your command>` in each folder, and the `.env` files can go.

## Types for your variables

```bash
cemi types -o env.d.ts                       # process.env.DATABASE_URL is a string, not string | undefined
cemi types --format zod -o src/env.ts        # a zod schema that names every missing variable at startup
cemi types -o env.d.ts --check               # in CI: fails when cemi.toml changed and the file did not
```

They come from `cemi.toml` alone, so they are the same on every computer and in CI.

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
With `--allow push --allow rotate` it can also check destinations and replace a leaked key
without seeing it; in protected environments it only asks, and you approve.

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

## Rotate a key everywhere

Tell Cemí where each key is created and where it is copied, once:

```bash
cemi origin set shop/supabase#key -e prod supabase-key --project abcdefghijklmnopqrst --token global:accounts/supabase#token
cemi dest add shop/supabase#key -e prod github --repo acme/shop --name SUPABASE_KEY --environment production
cemi dest add shop/supabase#key -e prod dotenv --file .env.production --key SUPABASE_KEY
cemi verify shop/supabase#key -e prod -- npm run check:supabase
```

From then on:

```bash
cemi check                                   # out of date, changed outside Cemí, missing
cemi push                                    # send current values where they are missing
cemi rotate shop/supabase#key -e prod        # new key → every destination → check → revoke the old one
cemi incident shop/supabase#key -e prod      # it leaked: where it is, who used it; --rotate replaces it
```

If a destination or the check fails, the old key goes back everywhere. Built in: GitHub
Actions secrets, Supabase API keys and function secrets, `.env` files and any command; anyone
can add a provider as a small program. See [docs/connectors.md](docs/connectors.md).

`prod` is protected: changes there ask for your password, and an AI that asks for them through
MCP only creates a request that you approve with `cemi approve`.

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
| Values | `set`, `generate`, `copy` (no argument: search and pick), `reveal`, `history`, `revert` |
| Memory | `note`, `task`, `deps`, `doc` |
| Environments | `env ls/add/rm/diff/protect/unprotect` |
| Rotation | `origin set/rm`, `dest add/ls/rm`, `verify`, `push`, `check`, `rotate`, `revoke`, `incident`, `approve` |
| Project | `preset ls/add`, `link`, `var add/rm/ls`, `run`, `types`, `export`, `import` (`--discover` for every project) |
| AI | `token create/ls/revoke`, `mcp serve/setup/add/launch/ls/rm` |
| Git | `scan`, `hook install` |

`cemi help <command>` explains each one. References look like `[global:|local:]entity/record#field`.

For scripts and CI, every command takes `--json`, and exit codes do not change between versions:
see [docs/scripting.md](docs/scripting.md).

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

- **v0.2** (this version): rotation, with origins, destinations and approvals.
- **v0.3**: daily use: discover existing `.env` files, shell completions, types for your code,
  secrets in CI.
- **v0.4**: desktop app and credential proxy (the AI calls APIs without receiving the key).
- **v0.5**: sync between your machines and sharing one entity with someone else.

Full plan: [docs/roadmap.md](docs/roadmap.md).

## License

Apache-2.0. Cemí comes with no warranty: you are responsible for your keys and your recovery code.
