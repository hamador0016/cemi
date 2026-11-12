<p align="center"><img src="icon.png" alt="Cemí" width="96"></p>

# Cemí for VS Code

*[Leer en español](README.es.md)*

Hover an environment variable to see what the key is for, when it expires and how it is
rotated. The value is never shown. When you save a file, the extension warns you if a value from
your vaults is written in it.

```text
STRIPE_SECRET_KEY → local:stripe#secret

Kind: secret text
For: Charges cards
Expires: 2027-01-15 (in 65 days)
Rotate: Roll it in the Stripe dashboard
Set for: dev (2026-11-11)
No value for: prod
Copied to: GitHub acme/shop: secret STRIPE_KEY (prod)
```

## What it recognizes

Only variables declared in the project's `cemi.toml` get a hover. It reads them in:

| Language | Forms |
|---|---|
| JavaScript, TypeScript (also Vue, Svelte, Astro) | `process.env.X`, `process.env["X"]`, `import.meta.env.X`, `Deno.env.get("X")`, `Bun.env.X` |
| Python | `os.environ["X"]`, `os.environ.get("X")`, `os.getenv("X")` |
| Rust | `env::var("X")`, `env::var_os("X")`, `env!("X")`, `option_env!("X")` |
| Go | `os.Getenv("X")`, `os.LookupEnv("X")` |
| Shell, Dockerfile, Makefile, YAML | `$X`, `${X}` |
| PowerShell | `$env:X` |
| `.env` files and `cemi.toml` | `X=…`, `export X=…`, `X = "…"` |

## Secrets written in files

On save, the extension runs `cemi scan` on the file. Cemí compares it with the exact values of
your vaults (current and past versions), so it finds any of your secrets whatever their format.
The warning names the record and underlines where the value starts and ends. `.env` files and
`.cemi/` are skipped (setting `cemi.scan.exclude`). **Cemí: Look for vault values in this file**
runs it on demand.

## Locked vault

The extension never asks for your password. When the vault is locked, the hover and the status
bar say so; **Cemí: Unlock the vault** opens a terminal running `cemi unlock`, and you type the
password there.

## How it talks to Cemí

It runs the `cemi` program with `--json --no-input` and only these commands: `var ls`, which
reads `cemi.toml`; `show`, which gives each secret's memory and whether it is set, never its
value; and `scan`, which gives the record and position of a value it finds, never the value.

`cemi` is looked up in `PATH` only, never in the open folder, so a repository cannot ship its
own program for the extension to run. The `cemi.path` setting can only be set in your user
settings, not in a workspace.

## Install

Install `cemi` first (see the [main README](../../README.md)). The extension is not on the
Marketplace yet; it comes as a `.vsix` file. Build it from this folder (it uses Microsoft's
`vsce`, run once through `npx`):

```bash
npx --yes @vscode/vsce@4.1.0 package -o cemi-vscode.vsix
code --install-extension cemi-vscode.vsix
```

The CI builds the same file on every push to `main` (artifact `cemi-vscode`). To try changes
without installing:

```bash
code --extensionDevelopmentPath=/path/to/cemi/editors/vscode /path/to/your/project
```

It has no dependencies. It activates in folders that have a `cemi.toml` or a `.cemi/` vault.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `cemi.path` | `cemi` | The program: a name in `PATH`, or a full path (`cemi.exe` on Windows) |
| `cemi.hover.enabled` | `true` | Show the hover |
| `cemi.scan.onSave` | `true` | Look for vault values when a file is saved |
| `cemi.scan.exclude` | `.env`, `.env.*`, `.cemi/` | Files not checked on save |
| `cemi.timeoutMs` | `5000` | How long to wait for `cemi` |

## Tests

```bash
node --test editors/vscode/test/*.test.js
```
