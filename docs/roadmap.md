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

## v0.3 — Daily use

- `cemi import --discover`: finds the `.env` files in your projects, brings them into the vault
  and reports keys repeated across projects, old keys and `.env` files tracked by git.
- Shell completions (PowerShell, bash, zsh, fish) that also complete record names.
- Interactive picker: `cemi copy` with no arguments.
- `cemi types`: TypeScript declarations or a zod schema generated from `cemi.toml`.
- Presets: `cemi init --preset next-supabase` creates the usual structure with its memory notes.
- `--json` output and stable exit codes for every command.
- Secrets in CI without copying them by hand: `cemi export --to ci` encrypts only what CI needs
  to a CI key, and a `cemi` GitHub Action decrypts it during the run.
- VS Code extension: hover a variable to see its purpose, expiry and rotation steps (never the
  value); warnings for secrets written in code.
- Prompt module (starship) with pending items, such as keys that expire this week.

*Done when:* someone who installs Cemí moves their `.env` files into it on day one and keeps
using it.

## v0.4 — Production

- Desktop app (tray) with approvals through Windows Hello or Touch ID.
- Credential proxy: the AI calls HTTP APIs and the proxy adds the key, so the command never
  receives it. This enables AI `run` in production.
- More connectors: Cloudflare, Netlify, Vercel, Resend, servers over SSH.

*Done when:* an AI can test production APIs without ever holding a production key.

## v0.5 — Teams and several machines

- `cemi share acme/shop --with <public key>`: give one entity to another developer. Every object
  is already encrypted to a list of recipients, so no server is needed.
- `cemi sync`: the vault is one encrypted file per object, so it syncs through a private git
  repository, with conflicts resolved object by object.

*Done when:* a second developer receives only `acme/shop` for `dev`.

## Before the first public release

Trust matters more than features in a secrets tool. These are free and come before announcing
Cemí:

- **Compatibility tests**: a vault created with v0.1 lives in the repository, and every new
  version must open it.
- **Fuzzing** (`cargo-fuzz`) of everything that reads outside data: references, `.env`,
  `cemi.toml` and vault files.
- **Verifiable releases** with cargo-dist: SHA-256 checksums, build provenance attestations
  (`actions/attest-build-provenance`) and minisign signatures checked by `cemi self update`.
- **Supply chain**: actions pinned by commit hash, Dependabot, OpenSSF Scorecard.
- **Repository**: protected `main`, CHANGELOG (git-cliff), semantic versioning, issue templates.
- **Publish the name** on crates.io (and npm for the installer).
- **External audit** once there are users (OSTIF supports open source security projects).

## Adoption

- A 20-second recording in the README (asciinema): `import` → `run` → an AI using a key it never
  sees.
- Documentation site with mdBook on GitHub Pages.
- A fair comparison with dotenvx, SOPS, Infisical and the 1Password CLI.
- Installers: Scoop and winget (Windows), Homebrew (macOS), `cargo binstall`.
- Announce on Show HN and r/rust when v0.2 ships.
