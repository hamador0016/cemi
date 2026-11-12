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

In your prompt, `cemi prompt` prints `cemi !2` when two things need doing soon (a key that
expires this week, a rotation that did not finish, an approval waiting, a destination out of
date), `cemi locked` in a project whose vault is locked, and nothing otherwise. With
[Starship](https://starship.rs):

```toml
[custom.cemi]
command = "cemi prompt"
when = true
style = "bold yellow"
```

In VS Code, the extension in [editors/vscode](editors/vscode/README.md) shows what a variable is
for, when it expires and how it is rotated when you hover it, and warns when a value of your
vaults is written in a file.

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
down: AI clients can only run the commands you list, in the environments you list. In protected
environments (`prod` by default) an AI may only run a command when every secret goes through the
credential proxy, so the command never receives a key. Details in
[docs/threat-model.md](docs/threat-model.md).

## Production APIs without the key

Give a key the API it signs in to and the calls an AI may make with it:

```bash
cemi api add acme/shop/stripe#secret -e prod --base https://api.stripe.com \
  --auth basic --allow "GET /v1/**" --allow "POST /v1/refunds"
cemi token create claude --allow read --allow api --env prod --expires 1d
```

The AI calls the MCP tool `call_api` (`GET /v1/balance` on `acme/shop/stripe#secret`, `prod`).
Cemí adds the key, sends the request only to `https://api.stripe.com`, refuses any method or path
outside the rules, does not follow redirects, and hides the key if the answer contains it. You
can try the same call yourself with `cemi api call stripe#secret -e prod GET /v1/balance`.

Programs work the same way. List in `cemi.toml` the variable that holds the API's address:

```toml
[env]
STRIPE_SECRET_KEY = "stripe#secret"

[proxy]
STRIPE_API_BASE = "stripe#secret"
```

`cemi run --proxy -e prod -- npm test` starts a proxy on `127.0.0.1` for that run.
`STRIPE_SECRET_KEY` gets a placeholder and `STRIPE_API_BASE` the proxy's address. The proxy
swaps the placeholder for the key. An AI's `run` in a protected environment always works this
way, and fails if some secret of the command has no API. The program has to read the API's
address from a variable; most SDKs accept a base URL.

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

## Secrets in CI

CI gets one key; the values travel encrypted inside the repository.

```bash
cemi ci setup --repo acme/shop        # a key only for CI; GitHub gets it as the secret CEMI_CI_KEY
cemi ci export -e prod                # cemi.ci.age: this project's variables for prod, encrypted
git add cemi.ci.age cemi.toml && git commit -m "CI secrets"
```

```yaml
# .github/workflows/deploy.yml
- uses: hamador0016/cemi@main
  with:
    key: ${{ secrets.CEMI_CI_KEY }}
- run: npm run deploy                 # the variables are set, and masked in the log
```

In other CIs, set `CEMI_CI_KEY` and run `cemi ci load -- <command>`. `--only` (or `vars` in
`cemi.toml [ci]`) limits what goes to CI. After changing a value, export again (`cemi status`
reminds you). If the CI key
leaks, replace it (`cemi ci setup --new-key`) and the values in the file too: old copies of the
file stay in the git history.

## What uses a key

Each vault remembers the projects whose `cemi.toml` uses it (encrypted, like everything else in
the vault). A project is noted the first time `cemi` opens the vault from its folder, or with
`cemi project add <folder>`. One question then covers every project:

```bash
cemi deps global:accounts/cloudflare#token
```

```text
global:accounts/cloudflare#token is used by:
Projects:
  blog: CF_TOKEN (/home/me/code/blog)
  shop: CLOUDFLARE_API_TOKEN (/home/me/code/shop)
    copied to cemi.ci.age (prod): out of date; run `cemi ci export -e prod` in that folder and commit it
Connectors that sign in with it:
  connector cloudflare-dns (destination of acme/shop/api#token)
Copied to:
  GitHub acme/shop: secret CLOUDFLARE_API_TOKEN (prod)
```

It also lists templates built from the value and MCP servers started with it. Projects that
Cemí has not noted are not searched; `cemi project ls` shows the ones it knows. `cemi status`
warns when a `cemi.ci.age` holds an old value, and `cemi rotate` lists the ones to export again.
AI assistants get the same list from the MCP `show` tool, without values.

## Never commit a secret

```bash
cemi hook install        # pre-commit: blocks commits that contain any value from your vaults
cemi scan --history      # looks for your values in the whole git history
```

Unlike pattern scanners, `cemi scan` looks for *your* values, whatever their format.

## Commands

| Area | Commands |
|---|---|
| Vault | `init [-g]`, `unlock`, `lock`, `status`, `prompt`, `recovery verify/reset/new`, `passwd`, `doctor`, `log` |
| Structure | `ls`, `add`, `mv`, `rm`, `field add/rm/edit`, `find`, `show` |
| Values | `set`, `generate`, `copy` (no argument: search and pick), `reveal`, `history`, `revert` |
| Memory | `note`, `task`, `deps` (every project that uses a value), `doc` |
| Environments | `env ls/add/rm/diff/protect/unprotect` |
| Rotation | `origin set/rm`, `dest add/ls/rm`, `verify`, `push`, `check`, `rotate`, `revoke`, `incident`, `approve` |
| Project | `preset ls/add`, `link`, `var add/rm/ls`, `project ls/add/rm`, `run`, `types`, `ci setup/export/load`, `export`, `import` (`--discover` for every project) |
| AI | `token create/ls/revoke`, `mcp serve/setup/add/launch/ls/rm`, `api add/ls/rm/call`, `run --proxy` |
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

- **v0.2**: rotation, with origins, destinations and approvals.
- **v0.3** (in progress, mostly done): daily use: discover existing `.env` files, shell
  completions, presets, types for your code, `--json`, secrets in CI, a prompt module. Left:
  the VS Code extension.
- **v0.4**: desktop app and credential proxy (the AI calls APIs without receiving the key).
- **v0.5**: sync between your machines and sharing one entity with someone else.

Full plan: [docs/roadmap.md](docs/roadmap.md).

## License

Apache-2.0. Cemí comes with no warranty: you are responsible for your keys and your recovery code.
