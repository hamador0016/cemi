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
| `cloudflare-token` | A Cloudflare API token with the same permissions (and IP limits) as the current one | Deletes the old token | Yes, and disabled or expired tokens |
| `resend-key` | A Resend API key, full access or sending only (optionally for one domain) | Deletes it, when Cemí created it | Yes |
| `command` | Your program prints the new value | Your program gets the old value on stdin | No |
| `external` | See [External connectors](#external-connectors) | | |

```bash
cemi origin set acme/shop/supabase#key -e prod supabase-key \
  --project abcdefghijklmnopqrst --token global:accounts/supabase#token

cemi origin set acme/shop/webhook#secret -e prod command -- ./scripts/webhook-key

cemi origin set acme/shop/cloudflare#token -e prod cloudflare-token \
  --token global:accounts/cloudflare#admin --name "shop deploy"

cemi origin set acme/shop/resend#key -e prod resend-key \
  --token global:accounts/resend#admin --permission sending_access --domain <domain id>
```

`cloudflare-token` needs a current token to copy: Cemí asks Cloudflare which token the current
value is (`/user/tokens/verify`, signed in with that same value), reads its permissions with the
admin token and creates a new token with them. The old one keeps working until the rotation
deletes it, so a failed destination can still go back to it. Rolling a token in place is not
used, because it stops the old value at once. For tokens owned by an account instead of your
user, add `--account <account id>`. A key that Cemí did not create through `resend-key` has an
id Cemí does not know, so the first rotation tells you to delete the old one in the Resend
dashboard; later rotations delete it themselves.

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
| `cloudflare-worker` | A Cloudflare Workers secret | Only whether it exists (Cloudflare reports nothing that changes with the value) |
| `netlify` | A Netlify environment variable of a site, or of the whole team, for one deploy context | Yes, by the variable's update time (any context of the variable counts) |
| `vercel` | A Vercel project environment variable for one target (sensitive for production and preview) | Yes, by its update time |
| `dotenv` | One variable of a `.env` file on this computer (the rest of the file is kept) | Yes |
| `ssh` | One variable of a `.env` file on a server, through your `ssh`; optionally restarts a service | Yes |
| `command` | Your program gets the value on stdin | No |
| `external` | See below | If the connector supports it |

```bash
cemi dest add acme/shop/stripe#key -e prod github --repo acme/shop --name STRIPE_KEY --environment production
cemi dest add acme/shop/stripe#key -e prod supabase-secret --project abcdefghijklmnopqrst --name STRIPE_KEY --token global:accounts/supabase#token
cemi dest add acme/shop/stripe#key -e dev dotenv --file .env.local --key STRIPE_KEY
cemi dest add acme/shop/stripe#key -e prod command -- npx wrangler secret put STRIPE_KEY
cemi dest add acme/shop/stripe#key -e prod cloudflare-worker --account <account id> --script shop-api --name STRIPE_KEY --token global:accounts/cloudflare#workers
cemi dest add acme/shop/stripe#key -e prod netlify --account acme --site <site id> --key STRIPE_KEY --context production --token global:accounts/netlify#token
cemi dest add acme/shop/stripe#key -e prod vercel --project shop --key STRIPE_KEY --target production --token global:accounts/vercel#token
cemi dest add acme/shop/stripe#key -e prod ssh --host deploy@shop.example.com --file /srv/shop/.env --key STRIPE_KEY --restart "sudo systemctl restart shop"
```

- `github` uses the GitHub CLI's login (`gh auth login`) unless you give `--token`. For GitHub
  Enterprise Server, add `--api-url https://HOST/api/v3`.
- Many command line tools read a secret from stdin, so `command` covers them: `gh secret set`,
  `wrangler secret put`, `vercel env add`. For anything else, a small script of yours can read
  stdin and do the rest. A destination can also be an action, such as a redeploy, that ignores
  its input.
- `netlify` creates the variable as secret ("contains secret values": readable only by code
  running on Netlify, for builds, functions and runtime) unless you add `--plain`. Netlify does
  not let you unmark a secret. Without `--site`, the variable belongs to the whole team.
- `vercel` stores production and preview values as sensitive (not readable back, not even in
  the dashboard); Vercel does not allow sensitive variables for development, so those are
  encrypted. Add `--team <team id>` for projects of a team.
- `ssh` runs your own `ssh` program, so `~/.ssh/config`, the agent and `known_hosts` apply. It
  runs without asking for passwords (`BatchMode`): use a key or the agent, and connect once by
  hand so ssh knows the host key. Cemí reads the file over SSH, changes the variable with the
  same rules as local `.env` files, and sends the whole file back on stdin; the server replaces
  it only if it still has the content Cemí read, so a change made in between is never lost.
  Values travel only on stdin, never in the command line. The server needs a POSIX `sh`, and
  `sha256sum`, `shasum` or `openssl`. `--restart` runs on the server after the file changes.
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

### Permissions for provider tokens

Give each credential the least it needs. A token that can create tokens is powerful: keep it in
a record of its own, and protect the environment it belongs to.

| Connector | Credential | Permission |
|---|---|---|
| `github` | Fine-grained token for the repository | Secrets: read and write (Environments: read and write, for environment secrets) |
| `supabase-key`, `supabase-secret` | Supabase personal access token | Access to the project |
| `cloudflare-token` | Cloudflare API token | User → API Tokens: Edit (account-owned tokens: Account API Tokens: Edit) |
| `cloudflare-worker` | Cloudflare API token | Account → Workers Scripts: Edit |
| `resend-key` | Resend API key | Full access (sending-only keys cannot manage keys) |
| `netlify` | Netlify personal access token | Personal access tokens act as your whole user: prefer a user that belongs only to the team |
| `vercel` | Vercel access token | Scoped to the team that owns the project |
| `ssh` | Your ssh keys | A server account that can write the `.env` file (and run `--restart`) |

Endpoints used (checked in November 2026): Cloudflare
[user tokens](https://developers.cloudflare.com/api/resources/user/subresources/tokens/),
[account tokens](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/) and
[Workers secrets](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/);
Resend [API keys](https://resend.com/docs/api-reference/api-keys/create-api-key);
Netlify [environment variables](https://open-api.netlify.com/);
Vercel [project environment variables](https://vercel.com/docs/rest-api/reference/endpoints/projects/create-one-or-more-environment-variables).

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
