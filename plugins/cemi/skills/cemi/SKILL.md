---
name: cemi
description: Use Cemí to work with API keys, tokens, passwords and environment variables without ever seeing their values. Use it whenever a task needs a secret (running tests or a dev server that read env vars, calling an API that needs a key, deploying, setting up a new service, rotating or checking a leaked key), when the user mentions .env files, or when a project has a cemi.toml.
---

# Cemí: secrets you use without seeing

Cemí keeps the user's secrets in an encrypted vault on their computer, with notes on what each
one is for, where it is copied and how to rotate it. Through its MCP server you can list and
read everything about a secret except its value, run the project's allowed commands with the
secrets injected, call APIs with keys you never receive, and rotate keys.

## Rules

1. **Never ask the user to paste a secret into the chat**, and never write one into a file,
   command line or code. To store a value, tell the user to run this in their own terminal (it
   asks for the value hidden):
   ```
   cemi set <record>#<field> -e <env>
   ```
2. **Never read `.env` files or print environment variables** to find a key. If the project has
   `.env` files, suggest moving them into Cemí: `cemi import --discover .`
3. **Run commands through Cemí**, not directly, when they need secrets: the MCP `run` tool, or
   in a shell `cemi run -e <env> --redact -- <command>`. Output values come back as
   `[hidden:NAME]`; that is expected, not an error.
4. **Production needs a human.** In protected environments (like `prod`), `push`, `rotate` and
   some runs create a request. Tell the user to approve it with `cemi approve`, then continue.
5. If a value is missing, say which `record#field` and environment, and give the user the
   `cemi set` line. Do not invent placeholder values.

## MCP tools

| Tool | Use it to |
|---|---|
| `project` | See this project's `cemi.toml`: the variables it injects and the commands you may run. Start here. |
| `list`, `search`, `show` | Find records and read their notes (purpose, where used, how to rotate). Never values. |
| `status` | See what needs attention: missing values, expirations, unfinished rotations. |
| `run` | Run an allowed command with the secrets injected and hidden in the output. |
| `call_api` | Call an HTTP API with a key Cemí adds, for the methods and paths the user allowed. |
| `generate` | Create a random secret (password, webhook secret) and store it. You do not get it back. |
| `check` | See whether the places a secret is copied to (GitHub, Vercel, `.env`…) are up to date. |
| `push` | Send the current value to destinations that do not have it. |
| `rotate` | Replace a key everywhere; `leaked=true` when it leaked. You never see the new value. |

## Common tasks

**Run tests or the dev server.** Call `project` to see the allowed commands, then `run` one. If
the command you need is not allowed, ask the user to add it to `cemi.toml`:
```toml
[ai.commands]
test = { cmd = ["npm", "test"], envs = ["dev"] }
```

**A new variable for the project.** Ask the user to create it and store the value themselves:
```
cemi add <record>
cemi field add <record> <field> --secret
cemi set <record>#<field> -e dev
cemi var add <ENV_NAME> <record>#<field>
```
For random values (passwords, signing secrets), use `generate` instead of asking.

**A key leaked** (committed, pasted, printed in a log). Call `show` to read its rotation notes,
then `rotate` with `leaked=true`. If the record has no origin, tell the user how to rotate it
from its notes and to run `cemi rotate <record>#<field> -e <env> --leaked --paste` to type the
new value; Cemí sends it to every destination.

**Test a production API.** Use `call_api`; Cemí adds the key and enforces the allowed paths. If
the API is not set up, the user adds it with `cemi api add`.

## If the Cemí tools are not available

The MCP server is not connected yet. Tell the user to run, in the project folder:
```
cemi token create agent --allow read --allow run --env dev --expires 7d
cemi mcp setup <client> --token-name agent
```
where `<client>` is their AI client (for example `claude-code`). Until then, use
`cemi run -e dev --redact -- <command>` in the shell; it hides any secret that the command
prints. Cemí is at https://github.com/hamador0016/cemi.
