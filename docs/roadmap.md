# Roadmap

[Español](roadmap.es.md)

Each version is ready when the sentence in *Done when* is true. Every version builds and passes
its tests on Windows, macOS and Linux.

## v0.1 — Vault, memory and AI without values (done)

Vaults, free structure, environments, memory, `status`, `run`, `cemi.toml`, `import`/`export`,
MCP server with scoped tokens, `mcp launch`, audit log, `scan` and the pre-commit hook.

## v0.2 — Rotation (done)

- **Origins and destinations.** Cemí knows where each key is born and every place it is copied
  to, per environment.
- **Connectors**: GitHub Actions secrets, Supabase (Edge Function secrets and API keys), local
  `.env` files, and any command you write. External connectors (`cemi-connector-<name>`) speak
  JSON over stdin, so anyone can add a provider.
- **Fingerprints**: each destination remembers a hash of the last value sent, so `cemi check`
  sees what is out of date or was changed outside Cemí.
- `cemi push`, `cemi check`, `cemi rotate` (plan → approve → create → propagate → verify →
  confirm → revoke, with automatic rollback) and `cemi incident` for leaked keys.
- **Approval** that an AI cannot give: production changes need the vault password typed by a
  person; requests from AI clients wait for `cemi approve`.
- MCP tools `check`, `push` and `rotate`; the AI receives plans and results, never values.

*Done when:* a leaked key is replaced everywhere it is used with one command.

## v0.3 — Daily use (done)

- `cemi import --discover`: finds the `.env` files in your projects, brings them into the vault
  and reports `.env` files committed to git or missing from `.gitignore`, values repeated
  across projects, and files unchanged for a year.
- Shell completions (PowerShell, bash, zsh, fish, elvish) that also complete record, entity and
  environment names while the vault is unlocked.
- Interactive picker: `cemi copy` with no arguments.
- `cemi types`: TypeScript declarations or a zod schema generated from `cemi.toml`, with
  `--check` for CI.
- Presets: `cemi init --preset next-supabase` (also `supabase`, `stripe`, `resend`, `postgres`)
  creates the usual structure with its memory notes; `cemi preset add` for existing projects.
- `--json` output and stable exit codes for every command ([docs/scripting.md](scripting.md)).
- Secrets in CI without copying them by hand: `cemi ci export` encrypts only what CI needs to
  a key made for CI, and the `cemi` GitHub Action (or `cemi ci load` in any CI) opens it during
  the run.
- `cemi prompt` for the shell prompt (Starship) with what needs doing soon, such as keys that
  expire this week.
- `cemi deps` across projects: each vault remembers the projects that use it, so one command
  lists every project, template, connector, MCP server, destination and CI file that uses a
  value. `cemi status` warns about CI files with old values; `cemi rotate` lists them.
- VS Code extension ([editors/vscode](../editors/vscode)): hover a variable to see its purpose,
  expiry and rotation steps (never the value); warnings for secrets written in code.

*Done when:* someone who installs Cemí moves their `.env` files into it on day one and keeps
using it.

## v0.4 — Production (done)

- Approvals with Windows Hello or Touch ID (`cemi approve-with device`), and a tray icon on
  Windows (`cemi tray`) that tells you when an AI asks for approval.
- Credential proxy: the AI calls HTTP APIs (`call_api`) and Cemí adds the key, only for the
  methods and paths you allow (`cemi api add`), so the AI never receives it. AI `run` in a
  protected environment works only when every secret goes through the proxy (`[proxy]` in
  `cemi.toml`).
- More connectors: Cloudflare (tokens and Worker secrets), Netlify, Vercel, Resend, servers over
  SSH.

*Done when:* an AI can test production APIs without ever holding a production key.

## v0.5 — Teams and several machines (done)

- `cemi share acme/shop --with <public key> -e dev`: give one entity to another developer, with
  only the environments you choose, in a file encrypted to their vault's key. No server.
- `cemi sync`: the vault is one encrypted file per object, so it syncs through a private git
  repository, with conflicts resolved object by object.

*Done when:* a second developer receives only `acme/shop` for `dev`.

## Before the first public release

Trust matters more than features in a secrets tool. These are free and come before announcing
Cemí.

Done:

- **Compatibility tests**: vaults made with the v0.1 binary live in `tests/fixtures`, and every
  version must open them, read every value and sign them on the first change.
- **Fuzzing** (`cargo-fuzz`, in `fuzz/`) of everything that reads outside data: references,
  templates, `.env`, `cemi.toml`, CI file headers, vault and share files, and proxy paths. One
  minute per target on every push, ten every week.
- **Verifiable releases** with cargo-dist: archives for Windows, macOS and Linux with SHA-256
  checksums, install scripts, build provenance attestations, and `cemi self update`.
- **Supply chain**: actions pinned by commit hash, Dependabot, OpenSSF Scorecard.
- **Repository**: CHANGELOG, semantic versioning, issue and pull request templates.
- The VS Code extension builds as a `.vsix` in CI.
- **Protected `main`**, secret scanning with push protection, and Dependabot security updates.
- **First release**: v0.5.0 on GitHub, with installers, and on crates.io.

Left:

- **Reserve the name** on npm.
- **minisign signatures** checked by `cemi self update`: they need a signing key that only the
  maintainer holds.
- **External audit** once there are users (OSTIF supports open source security projects).

## Adoption

- ~~A recording in the README~~: done with VHS (`demo/demo.tape`, recorded by the Demo
  workflow): `import` → `cemi.toml` → `run --redact` → `status`.
- Documentation site with mdBook on GitHub Pages.
- A fair comparison with dotenvx, SOPS, Infisical and the 1Password CLI.
- Installers: Scoop and winget (Windows), Homebrew (macOS), `cargo binstall`.
- Announce on Show HN and r/rust when v0.2 ships.
