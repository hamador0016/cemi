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

Connectors marked **(beta)** were built from the providers' API documentation and tested
against mock servers of those APIs, not yet against real accounts.

### Origins

| Connector | Creates | Revokes | Notices a deleted key |
|---|---|---|---|
| `supabase-key` | A Supabase secret API key (`sb_secret_…`) through the Management API | Deletes it, telling Supabase whether it leaked | Yes |
| `cloudflare-token` | A Cloudflare API token with the same permissions (and IP limits) as the current one | Deletes the old token | Yes, and disabled or expired tokens |
| `resend-key` | A Resend API key, full access or sending only (optionally for one domain) | Deletes it, when Cemí created it | Yes |
| `aws-access-key` (beta) | An AWS IAM access key of an IAM user: the value is the secret access key; the access key id can go to another field | Deletes the old key | Yes, and inactive keys |
| `openai-key` (beta) | An OpenAI API key of a project service account, through the Admin API | Deletes it, when Cemí created it | Yes |
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

cemi origin set acme/aws/deploy#secret_access_key -e prod aws-access-key --user deploy-bot \
  --access-key-id global:accounts/aws#access_key_id \
  --secret-access-key global:accounts/aws#secret_access_key --id-field access_key_id

cemi origin set acme/shop/openai#key -e prod openai-key --project proj_abc123 \
  --service-account svc_acct_abc123 --token global:accounts/openai#admin --name shop
```

`cloudflare-token` needs a current token to copy: Cemí asks Cloudflare which token the current
value is (`/user/tokens/verify`, signed in with that same value), reads its permissions with the
admin token and creates a new token with them. The old one keeps working until the rotation
deletes it, so a failed destination can still go back to it. Rolling a token in place is not
used, because it stops the old value at once. For tokens owned by an account instead of your
user, add `--account <account id>`. A key that Cemí did not create through `resend-key` has an
id Cemí does not know, so the first rotation tells you to delete the old one in the Resend
dashboard; later rotations delete it themselves.

An AWS access key has two parts: the access key id, which names it, and the secret access key.
`aws-access-key` stores the secret access key in the field you rotate and keeps the access key
id as the key's provider id, to delete it later. Applications need both: with `--id-field
access_key_id`, each rotation also writes the new access key id to that field of the same
record (created when missing) and sends it to that field's destinations in the same step, so
both change together, and both go back if a destination or the check fails. Before the first
rotation, store the id of the key in use in that field (`cemi set
acme/aws/deploy#access_key_id -e prod`): Cemí deletes that key once the new one works. Without
`--id-field`, a key Cemí did not create has an id Cemí does not know, so the first rotation
tells you to delete it in the IAM console. An IAM user has at most two access keys, so a
rotation needs one of them free. AWS has no way to mark a key as leaked: revoking deletes it
either way. Without `--user`, the keys belong to the user of the signing key; with temporary
credentials (`--session-token`), give `--user`. IAM is called at its global endpoint
(`iam.amazonaws.com`, signed for us-east-1); the China and GovCloud partitions are not
supported.

`openai-key` creates keys for an existing service account of a project (in the OpenAI
dashboard: Project settings → Service accounts). Each rotation adds a key to the same service
account and deletes the old one through the project API key endpoints. OpenAI only returns a
key's value when it is created. A key that Cemí did not create through `openai-key` has an id
Cemí does not know, so the first rotation tells you to delete the old one in the dashboard.

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
| `gitlab` (beta) | A GitLab CI/CD variable of a project, for one environment scope; masked by default | Yes, by a digest of the value GitLab returns (hidden variables: only whether they exist) |
| `fly` (beta) | A Fly.io app secret, through the Machines API | Yes, by the digest Fly reports |
| `aws-secret` (beta) | An AWS Secrets Manager secret (created when it does not exist); each write is a new version | Yes, by the id of the version labelled `AWSCURRENT` |
| `aws-parameter` (beta) | An AWS Systems Manager Parameter Store parameter, as a `SecureString` | Yes, by its version |
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
cemi dest add acme/shop/stripe#key -e prod gitlab --project acme/shop --key STRIPE_KEY --environment-scope production --protected --token global:accounts/gitlab#token
cemi dest add acme/shop/stripe#key -e prod fly --app shop-api --name STRIPE_KEY --token global:accounts/fly#token
cemi dest add acme/shop/stripe#key -e prod aws-secret --secret-id prod/shop/stripe --region us-east-1 --access-key-id global:accounts/aws#access_key_id --secret-access-key global:accounts/aws#secret_access_key
cemi dest add acme/shop/stripe#key -e prod aws-parameter --name /shop/prod/stripe-key --region us-east-1 --access-key-id global:accounts/aws#access_key_id --secret-access-key global:accounts/aws#secret_access_key
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
- `gitlab` creates the variable masked and raw (no `$` expansion). GitLab masks only values of 8
  or more characters on one line without spaces; for other values add `--no-mask`.
  `--protected` limits the variable to protected branches and tags, and `--environment-scope`
  picks the scope (default `*`, every environment). `--hidden` creates it masked and hidden
  (GitLab 17.4 and later): it is never shown again, and GitLab only lets you choose this when the
  variable is created. GitLab's API returns a variable's value when it is read; Cemí hashes it
  in memory and keeps only its SHA-256 digest, the same kind of fingerprint it keeps of every
  value it sends. The value is not stored or shown. For a hidden variable, or whenever GitLab
  returns no value, Cemí can only tell whether the variable exists. For a self-managed GitLab,
  add `--api-url https://HOST/api/v4`.
- `fly` sets the secret through the Machines API. Running Machines get new secret values when
  they are updated: run `fly secrets deploy -a APP` or deploy afterwards. A `command` destination
  added after the `fly` one does it in the same push or rotation: `cemi dest add … command -- fly
  secrets deploy -a shop-api`. Tokens from `fly tokens create` work as they are (with their
  `FlyV1` prefix).
- `aws-secret` and `aws-parameter` sign their requests with Signature Version 4, implemented in
  Cemí (no AWS SDK or CLI needed). The credentials are references: `--access-key-id`,
  `--secret-access-key` and, for temporary credentials, `--session-token`. `aws-secret` stores
  the value as the secret's text (`SecretString`); AWS advises against storing new versions more
  than once every 10 minutes for long periods. `--kms-key` applies when Cemí creates the secret.
  A secret scheduled for deletion counts as missing, and AWS refuses new values for it until it
  is restored. `aws-parameter` writes a `SecureString` and replaces the current value (a new
  version); `--kms-key` picks the KMS key (default: the account's `aws/ssm` key). Neither one
  reads the value back: `DescribeSecret` and `DescribeParameters` return only metadata. For the
  China regions, Cemí uses the `amazonaws.com.cn` endpoints.
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
| `gitlab` | GitLab project, group or personal access token | `api` scope, with at least the Maintainer role in the project (needed to manage CI/CD variables) |
| `fly` | Fly.io token | A deploy token for the app: `fly tokens create deploy -a APP` |
| `openai-key` | OpenAI Admin API key | Organization owners create them (Organization settings → Admin keys); it must be able to manage the project's service accounts and API keys |
| `aws-access-key`, `aws-secret`, `aws-parameter` | AWS access key | The IAM policies below |

For `aws-access-key`, a policy for the user or role whose keys sign the requests (replace the
account id and user name):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:ListAccessKeys"],
    "Resource": "arn:aws:iam::123456789012:user/deploy-bot"
  }]
}
```

To let users rotate their own keys (with `--access-key-id` and `--secret-access-key` pointing
at the key being rotated: the old key signs the creation, the new one the deletion), use
`"Resource": "arn:aws:iam::123456789012:user/${aws:username}"` and leave out `--user`.

For `aws-secret` (add `kms:GenerateDataKey` and `kms:Decrypt` on the key when the secret uses a
customer managed KMS key):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "secretsmanager:PutSecretValue",
      "secretsmanager:CreateSecret",
      "secretsmanager:DescribeSecret"
    ],
    "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/shop/*"
  }]
}
```

For `aws-parameter` (`ssm:DescribeParameters` cannot be limited to some parameters; add
`kms:Encrypt` on the key when you give `--kms-key`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ssm:PutParameter",
      "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/shop/prod/*"
    },
    {
      "Effect": "Allow",
      "Action": "ssm:DescribeParameters",
      "Resource": "*"
    }
  ]
}
```

Endpoints used (checked in November 2026): Cloudflare
[user tokens](https://developers.cloudflare.com/api/resources/user/subresources/tokens/),
[account tokens](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/) and
[Workers secrets](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/);
Resend [API keys](https://resend.com/docs/api-reference/api-keys/create-api-key);
Netlify [environment variables](https://open-api.netlify.com/);
Vercel [project environment variables](https://vercel.com/docs/rest-api/reference/endpoints/projects/create-one-or-more-environment-variables);
GitLab [project CI/CD variables](https://docs.gitlab.com/api/project_level_variables/);
Fly.io [Machines API secrets](https://docs.fly.io/api/machines/openapi.json);
OpenAI [service account API keys](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/service_accounts/subresources/api_keys/methods/create)
and [project API keys](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/api_keys);
AWS [Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html),
IAM [CreateAccessKey](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html),
[DeleteAccessKey](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteAccessKey.html) and
[ListAccessKeys](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html),
Secrets Manager [PutSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html),
[CreateSecret](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html) and
[DescribeSecret](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html),
Systems Manager [PutParameter](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html) and
[DescribeParameters](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeParameters.html).

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
