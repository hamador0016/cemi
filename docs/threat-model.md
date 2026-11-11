# Threat model

What Cemí protects against, and what it does not. Read this before trusting it with
production secrets.

## Assets

- Secret values and their history.
- Names and notes (they reveal what you use and where).
- The vault key, AI tokens and the recovery code.

## What Cemí protects against

| Threat | Protection |
|---|---|
| Someone copies the vault folder (stolen laptop, backup, sync service) | Everything is encrypted with age; the vault key is wrapped with Argon2id (256 MiB, 3 passes). Names are encrypted too: only random ids are on disk. |
| A secret is committed to git | `.cemi/` carries its own `.gitignore` (`*`) and is added to the project's `.gitignore`. `cemi scan --staged` and the pre-commit hook block commits containing any secret value of your vaults (8 characters or more, current or past). |
| A secret is pasted into an AI chat | Values are never accepted as arguments or returned by MCP tools. `cemi set` reads hidden input. |
| An AI assistant reads your project | `cemi.toml` holds references only. The vault is encrypted. |
| A prompt-injected AI tries to get a value through MCP | No tool returns a value. Tokens are scoped (entities, environments, actions), expire and can be revoked. `run` only executes commands you allowlist in `cemi.toml`, only in the environments you list. |
| An object file is swapped or edited | age authenticates every file; the id inside must match the file name. Damaged files are reported, never trusted. |
| A secret shows up in command output | `run --redact` and MCP `run` replace values and their base64, base64url, hex and URL-encoded forms. |
| Forgotten password | Recovery code (256 bits) created with every vault. `cemi recovery verify` checks it. |

## What Cemí does NOT protect against

1. **A command that runs with a secret in its environment can leak it.** It can print it in a
   form the redactor does not know, write it to a file, or send it over the network. This is
   true for every tool that injects secrets. Cemí limits it (allowlisted commands, chosen
   environments), but if an AI can edit the script that an allowed command runs, it can make
   that script leak the secret. Do not allow AI `run` in production until the credential proxy
   (v0.3) exists, and treat any secret an AI could have reached as exposed: rotate it.
2. **Malware running as your user while the vault is unlocked.** It can read the session from
   the operating system's credential store, or simply run `cemi`. Lock the vault (`cemi lock`)
   when you do not need it; sessions expire after 15 minutes of inactivity.
3. **A weak master password.** Argon2id slows guessing down; it cannot save `123456`.
4. **Losing both the password and the recovery code.** Nobody can open the vault, by design.
5. **An AI with control of your desktop** can type in your terminal like you.
6. **The audit log against someone with write access to the folder.** The chain detects removed
   or reordered lines, not a full rewrite.

## Design rules

- No invented cryptography: age (X25519, ChaCha20-Poly1305), Argon2id, XChaCha20-Poly1305,
  SHA-256, all from audited RustCrypto/age crates.
- Secret material is wiped from memory when dropped (`zeroize`) where the libraries allow it.
- Debug-only switches (`CEMI_INSECURE_FAST_KDF`, `CEMI_TEST_SESSION_DIR`) do nothing in release
  builds.
- Only dependencies with permissive licenses (checked with `cargo deny`).
- Known advisories fail the build. The only exceptions are listed in `deny.toml` with the reason:
  today, `crypto-bigint` 0.5 (timing issues) and `basic-toml` (unmaintained), both pulled in by
  age for features Cemí does not use (P-256 recipients, localization). Cemí only uses X25519.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
