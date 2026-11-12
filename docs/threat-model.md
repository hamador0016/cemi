# Threat model

What Cemí protects against, and what it does not. Read this before trusting it with
production secrets.

## Assets

- Secret values and their history.
- Names, notes and the folders of the projects that use each vault (they reveal what you use
  and where). They are encrypted like the values.
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
| A leaked key keeps working | `cemi rotate` / `cemi incident --rotate` replace it at its origin and in every destination, then revoke the old one (telling the provider it leaked when the API allows it). |
| A prompt-injected AI changes production | Pushes, rotations and revocations in protected environments (`prod`, `production` by default) need the vault password typed by a person. Through MCP they only create a request for `cemi approve`, which expires in one hour and works once. A token limited to some environments cannot rotate a value shared by all of them. |
| An AI sends a secret somewhere new | Destinations, origins and API addresses are set only from the command line, never through MCP. Giving a key of a protected environment an API address needs the password. Values travel only over HTTPS (plain http is refused except for localhost), or over SSH with your own `ssh`, which checks the server's host key. |
| An AI needs a production key to test an API | The credential proxy (MCP `call_api`, `cemi run --proxy`) adds the key itself and sends the request only to the API's address, only for the methods and paths allowed with `cemi api add`. Paths with `..`, encoded slashes or backslashes are refused, redirects are not followed, and the key is hidden in answers. The local proxy listens on 127.0.0.1 under a random path that only the command it serves knows. |
| Someone intercepts a shared entity | `cemi share` encrypts the file with age to the receiver's vault key; only that vault opens it. It holds only the chosen environments' values; origins, destinations, APIs and verify commands are left out. Sharing a protected environment needs the password. |
| The git host of a synced vault reads it | Only `vault.json` and `objects/*.age` are pushed. Objects are age-encrypted (values, names, notes); the header holds the public key, the Argon2id parameters and salt, and the vault key wrapped by the password and the recovery code. The host sees how many objects there are, their sizes and when they change. The audit log and the folders of known projects are not pushed. |
| A failed rotation breaks a service | The new value is saved as pending before anything changes. If a destination or the `verify` check fails, the old value is written back to every destination already changed, and the unused new key is deleted at the provider. |
| Someone with the repository reads the CI secrets | `cemi.ci.age` is encrypted with age to a key made only for CI, kept in the CI's secret store (`CEMI_CI_KEY`). It holds only the variables of one environment, and only those chosen with `--only` or `[ci] vars`. Exporting a protected environment asks for the password. In GitHub Actions every value is masked in the log. If the CI key leaks, the values in every copy of the file in git history are exposed: replace the key and those values. |

## What Cemí does NOT protect against

1. **A command that runs with a secret in its environment can leak it.** It can print it in a
   form the redactor does not know, write it to a file, or send it over the network. This is
   true for every tool that injects secrets. Cemí limits it (allowlisted commands, chosen
   environments), but if an AI can edit the script that an allowed command runs, it can make
   that script leak the secret. In protected environments an AI's `run` only works when every
   secret goes through the credential proxy. Treat any secret an AI could have reached as
   exposed: rotate it.
2. **Malware running as your user while the vault is unlocked.** It can read the session from
   the operating system's credential store, or simply run `cemi`. Lock the vault (`cemi lock`)
   when you do not need it; sessions expire after 15 minutes of inactivity.
3. **A weak master password.** Argon2id slows guessing down; it cannot save `123456`.
4. **Losing both the password and the recovery code.** Nobody can open the vault, by design.
5. **An AI with control of your desktop** can type in your terminal like you.
6. **The audit log against someone with write access to the folder.** The chain detects removed
   or reordered lines, not a full rewrite.
7. **Connectors you install.** A `command` origin or destination and an external
   `cemi-connector-<name>` program receive values (that is their job). Use only programs you
   trust, as you would with a git credential helper.
8. **Calls the rules allow.** The proxy keeps the key away from the caller, not the damage a
   call can do: with `POST /v1/refunds` allowed, an AI can make refunds. Allow only what the
   task needs, and prefer keys with limited permissions at the provider.
9. **The places values are copied to.** A value sent to a provider or written to a server is as
   safe as that account and that machine. Provider tokens that can create other tokens (such as
   the one `cloudflare-token` uses) are powerful: give them the narrowest permission listed in
   [docs/connectors.md](connectors.md).
10. **What was shared.** A shared value cannot be taken back; whoever received it keeps it, and
    so does any copy of the share file. To cut someone off, rotate the keys they received.
11. **A synced vault's repository.** Its copy of `vault.json` is as hard to open as your
    password is to guess, offline and without limit, so a synced vault needs a strong password.
    An old password keeps opening the copies of `vault.json` in the git history: after
    `cemi passwd` because a password leaked, also replace the vault key (a new vault) or the
    repository.
12. **Providers that cannot revoke.** Without an origin that supports it, the old key is revoked by
   hand; Cemí says so and keeps it as an archived version.

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
