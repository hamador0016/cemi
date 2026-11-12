# Changelog

Every version builds and passes its tests on Windows, macOS and Linux. Versions follow
[semantic versioning](https://semver.org); while Cemí is below 1.0, a new minor version may
change commands. Vaults made by any earlier version keep opening (`tests/compat.rs`).

## Unreleased

### Added
- `cemi mcp setup` writes the configuration of `claude-desktop`, `cursor`, `vscode` (GitHub
  Copilot), `windsurf`, `devin`, `zed`, `codex` and `gemini`: the project's file with a project
  vault, the user's file with `--global`. Other servers and settings in the file are kept; a
  file with comments is left as it was and the snippet is printed. `--print` only prints it.
- `cemi import --from doppler` (`--project`, `--config`) and `cemi import --from 1password`
  (`--vault`), through the `doppler` and `op` programs: a preview with names only, then a
  question (`--yes` skips it). 1Password items become records and their fields become fields;
  attachments are skipped and counted.

## 0.5.0

### Added
- `cemi share`: give one entity to another developer, with only the environments you choose,
  in a file encrypted to their vault's key and signed by yours. `share key`, `share accept`,
  `share ls`; `cemi status` says when a shared value changed.
- `cemi sync`: the same vault on several computers through a private git repository, merged
  object by object. `sync init`, `sync clone`.
- Every object and the vault header carry a tag made with the vault key. Vaults made by older
  versions are signed on their first change.
- Credential proxy: `cemi api add/ls/rm/call`, the MCP tool `call_api` and `cemi run --proxy`
  with `[proxy]` in `cemi.toml`. An AI's `run` in a protected environment works only when every
  secret goes through the proxy.
- Approvals with Windows Hello or Touch ID (`cemi approve-with device`), a tray icon on Windows
  (`cemi tray`), and `cemi approve` without an id lets you pick a request.
- Connectors: `cloudflare-token`, `cloudflare-worker`, `netlify`, `vercel`, `resend-key`, `ssh`.
- VS Code extension (`editors/vscode`): hover a variable for its purpose, expiry and rotation
  steps; warnings for your secret values written in files.
- `--no-input` for programs that start `cemi` without a terminal.

## 0.3.0

### Added
- `cemi import --discover`, shell completions with names from the vault, the `cemi copy`
  picker, `cemi types` (TypeScript and zod), presets, `--json` and stable exit codes on every
  command, `cemi ci setup/export/load` and the GitHub action, `cemi prompt`, and `cemi deps`
  across every project that uses a vault (`cemi project ls/add/rm`).

## 0.2.0

### Added
- Origins and destinations per environment; connectors for GitHub Actions, Supabase, `.env`
  files, commands and external `cemi-connector-<name>` programs.
- `cemi push`, `cemi check`, `cemi rotate` (with automatic rollback), `cemi revoke`,
  `cemi incident`, protected environments and `cemi approve`; MCP tools `check`, `push` and
  `rotate`.

## 0.1.0

### Added
- Global and local vaults (age, Argon2id, recovery code), free structure, environments,
  memory, tasks, `status`, `run` with redaction, `cemi.toml`, `import`/`export`, the MCP server
  with scoped tokens, `mcp launch`, the audit log, `scan` and the pre-commit hook.
