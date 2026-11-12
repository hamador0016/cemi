# Scripting Cemí

Every command can be used from scripts and CI: exit codes do not change between versions, and
`--json` gives one JSON object instead of text.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done |
| 1 | The command worked and found problems: `check`, `scan`, `types --check`, `env diff`, a `push` that could not reach every destination, `find` with no matches |
| 2 | Wrong arguments |
| 3 | The vault is locked or the password was wrong: a person has to unlock it (`cemi unlock`) |
| 4 | Not found: a record, field, entity, environment, preset, request or `cemi.toml` |
| 5 | A person has to approve or confirm it: a protected environment, or a "go ahead?" with no terminal (pass `--yes` where the command has it) |
| 6 | A provider, the network or an external command failed |
| 9 | Any other error |

`--no-input` makes Cemí fail instead of asking: a locked vault gives exit code 3 at once, and a
"go ahead?" gives 5. Editors and other tools that have no terminal should always pass it.

`cemi status` always exits 0 when it runs: it reports, it does not judge. Use `cemi check` in
CI to fail on destinations that are out of date.

## --json

With `--json`, standard output is exactly one JSON object:

```json
{
  "ok": true,
  "exit_code": 0,
  "data": { "...": "the command's result" },
  "text": "what the command would have printed",
  "error": { "kind": "not_found", "message": "record not found: shop/stripe" }
}
```

- `ok` is true only when the exit code is 0.
- `data` is the structured result of commands that read: `ls`, `show`, `find`, `status`,
  `history`, `check`, `dest ls`, `env ls`, `env diff`, `var ls`, `task ls`, `deps`,
  `project ls`, `log`, `scan`, `token ls`, `mcp ls`, `approve` (the list), `preset ls` and
  `import --discover`.
  Other commands give `null` and their output in `text`.
- `error` is there only when the command failed. `kind` is one of `locked`, `not_found`,
  `needs_person`, `external` or `error`.
- Messages for people (✓ and !) still go to standard error.
- Dates are RFC 3339 in UTC.
- Secret values never appear: `show` says whether each secret is set, when, and how many
  versions it has.

`--json` does not apply to `run`, `ci load`, `mcp serve`, `mcp launch` and `completion`,
whose output belongs to another program, nor to `reveal`, which prints the value alone.

### Examples

Fail a deploy when a destination is out of date, and list them:

```bash
cemi check --json | jq -r '.data.destinations[] | select(.ok | not) | "\(.field) → \(.destination): \(.status)"'
```

The records of an entity that have a secret with no value:

```bash
cemi show acme/shop/stripe --json | jq '.data.fields[] | select(.secret) | {name, set: [.values[].set]}'
```

Each `scan` finding has `place`, `line`, `column` (1-based, in characters), `length` (in
characters) and `secret`, the reference of the value found. `line`, `column` and `length` are
null with `--history`.

Each `var ls` variable has `reference` as written in `cemi.toml` and `resolved`, the full
reference with its vault (`local:db#url`), or null when the reference is not valid.

Status values of `check`: `up_to_date`, `outdated`, `never_sent`, `changed_outside`, `missing`,
`unverifiable` (the destination cannot be read back) and `error`.
