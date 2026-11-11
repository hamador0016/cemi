# Connectors

A key has one **origin** per environment (where new values are created) and any number of
**destinations** (where the value is copied). `cemi rotate` uses both: it creates a new value
at the origin, sends it to every destination, runs the check you set with `cemi verify`, and
revokes the old value. If a destination or the check fails, the old value goes back to every
destination already changed.

Credentials for providers are references to other records of your vaults, never values:
`--token global:accounts/github#token`. Without a `global:` or `local:` prefix, Cemí looks in
the key's own vault, then in the global one.

## Built in

### Origins

| Connector | Creates | Revokes | Notices a deleted key |
|---|---|---|---|
| `supabase-key` | A Supabase secret API key (`sb_secret_…`) through the Management API | Deletes it, telling Supabase whether it leaked | Yes |
| `command` | Your program prints the new value | Your program gets the old value on stdin | No |
| `external` | See [External connectors](#external-connectors) | | |

```bash
cemi origin set acme/shop/supabase#key -e prod supabase-key \
  --project abcdefghijklmnopqrst --token global:accounts/supabase#token

cemi origin set acme/shop/webhook#secret -e prod command -- ./scripts/webhook-key
```

A `command` origin is called as `<command> create` (print the new value on stdout) and
`<command> revoke` (the old value arrives on stdin; the variable `CEMI_COMPROMISED` is `1` when
it leaked). Exit with a non-zero code on failure.

Without an origin, `cemi rotate` needs `--generate` (Cemí makes a random value: for passwords
and webhook secrets that you define) or `--paste` (you type the new key, for providers without
an API).

### Destinations

| Connector | Writes | Notices changes made outside Cemí |
|---|---|---|
| `github` | A GitHub Actions secret, of the repository or of one of its environments, sealed to the repository's public key | Yes, by its update time |
| `supabase-secret` | A Supabase Edge Function secret | Yes, by the digest Supabase reports |
| `dotenv` | One variable of a `.env` file on this computer (the rest of the file is kept) | Yes |
| `command` | Your program gets the value on stdin | No |
| `external` | See below | If the connector supports it |

```bash
cemi dest add acme/shop/stripe#key -e prod github --repo acme/shop --name STRIPE_KEY --environment production
cemi dest add acme/shop/stripe#key -e prod supabase-secret --project abcdefghijklmnopqrst --name STRIPE_KEY --token global:accounts/supabase#token
cemi dest add acme/shop/stripe#key -e dev dotenv --file .env.local --key STRIPE_KEY
cemi dest add acme/shop/stripe#key -e prod command -- npx wrangler secret put STRIPE_KEY
```

- `github` uses the GitHub CLI's login (`gh auth login`) unless you give `--token`. For GitHub
  Enterprise Server, add `--api-url https://HOST/api/v3`.
- Many command line tools read a secret from stdin, so `command` covers them: `gh secret set`,
  `wrangler secret put`, `vercel env add`. For anything else, a small script of yours can read
  stdin and do the rest. A destination can also be an action, such as a redeploy, that ignores
  its input.
- Templates are destinations too: if `db#url` is `postgres://app:{{db#password}}@…` and has a
  destination, rotating `db#password` updates it.

Destinations remember a fingerprint (SHA-256) of the last value sent and what the destination
reported afterwards, so `cemi check` can tell:

- **out of date**: the vault changed since the last `cemi push`;
- **changed outside Cemí**: someone edited the destination directly;
- **missing**: the destination no longer has it.

`cemi push` asks each destination the same questions before sending, and sends to the ones
that are out of date, never sent or missing. A value changed outside Cemí is not overwritten,
because it may be a newer key someone set by hand: `cemi push --force <ref> -e <env>` puts the
vault's value back, and `cemi set` keeps the new one. Through MCP, an AI client only reports
these; a person decides.

Values only travel over HTTPS. Plain `http://` is refused, except for `localhost`.

## Protected environments

`prod` and `production` are protected by default (`cemi env protect` / `cemi env unprotect`
change the list). Pushing, rotating or revoking there asks for the vault password, typed by a
person. When an AI client asks for it through MCP, Cemí stores a request and the person runs
`cemi approve <id>`; requests expire after one hour and work once.

## External connectors

Anyone can add a provider without changing Cemí: write a program called
`cemi-connector-<name>`, put it in your `PATH`, and use it with `external <name>`.

```bash
cemi origin set acme/mail#key -e prod external resend --set domain=acme.com --secret token=global:accounts/resend#token
cemi dest add acme/mail#key -e prod external vault --set path=secret/mail
```

Cemí runs the program with no arguments, writes **one JSON request** to its stdin and reads
**one JSON answer** from its stdout. Use stderr for messages to the person; Cemí shows them
with the value hidden.

Request:

```json
{
  "protocol": 1,
  "action": "create | revoke | write | observe",
  "config": { "domain": "acme.com" },
  "secrets": { "token": "…resolved from the vault…" },
  "value": "…for write and revoke…",
  "provider_id": "…for revoke, when create returned one…",
  "compromised": false
}
```

Answer:

```json
{ "ok": true }
```

| Action | Answer fields |
|---|---|
| `create` | `value` (required), `provider_id` (optional: an id to revoke it later) |
| `revoke` | nothing, or `manual`: text telling the person what to do by hand |
| `write` | nothing |
| `observe` | `remote`: any text that changes when the value changes (a digest, an update time), or `missing: true` |

On failure, answer `{ "ok": false, "error": "what went wrong" }`.

Rules for connector authors:

- Never print the value or the secrets to stdout or stderr.
- Never take secrets as arguments; they arrive only on stdin.
- `observe` must not return the value itself, nor anything from which it can be recovered.
