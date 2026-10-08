# Deployment

Target platform is **Render**, defined declaratively in
[`render.yaml`](../render.yaml). No secret is committed: every credential is
either `sync: false` (supplied from the Render dashboard or GitHub environment
secrets) or derived from a Render-managed service.

## Services

| Service | Type | Purpose |
| --- | --- | --- |
| `fundipulse-api` | web (Docker) | The API |
| `fundipulse-db` | postgres 18 | Primary database, private network only |
| `fundipulse-cache` | redis | Shared rate-limit counters |

`maxmemoryPolicy: noeviction` on Redis is deliberate. Redis with an eviction policy
will silently discard a counter, which **raises** the effective rate limit for that
identity rather than lowering it. Running out of memory should fail the limit, not
lift it.

## Where migrations run

`alembic upgrade head` runs **during container startup**, from
[`docker/entrypoint.sh`](../docker/entrypoint.sh), before Uvicorn binds. This is a
deliberate change from a Pre-Deploy Command, and it is forced by the plan.

### Why not a Pre-Deploy Command

Render **Free** provides no shell and no Pre-Deploy Command. Both are paid-plan
features. On Free the only code that runs is the container's `CMD`, so a
`preDeployCommand` in `render.yaml` is silently ignored — which is exactly how this
service came to be deployed with a working database connection and no schema at
all.

The symptom is distinctive and worth recognising:

| Check | Result on a schema-less database |
| --- | --- |
| `/health/ready` | **200**, `database: ok` |
| `/jobs`, `/trades`, `/counties` | **500** |
| `/auth/register`, `/auth/login` | **500** |

Readiness only proves a connection opened. It does not check that the tables
exist, so a health check cannot be trusted to catch a missing schema.

### Why startup is safe here

The concern with migrating on boot is a rolling deploy: container B applying a
migration while container A still serves new code against the old schema. That
does not apply on this deployment:

* Render Free runs **one instance per web service**. There is no second container
  to straddle.
* The entrypoint applies migrations *before* the port is bound, so the container
  never serves a request against a half-migrated schema. If a migration fails the
  container **exits non-zero and does not start**.
* `alembic upgrade head` tracks applied revisions in `alembic_version`, so
  **restarting the service re-runs the command and is a no-op** once the schema
  is current. Restarting costs one query, not a re-migration.

If this service is ever scaled to multiple instances on a paid plan, move the
migration back to `preDeployCommand` and drop it from the entrypoint. The
entrypoint's job is to make Free work, not to make rolling deploys safe.

### Migrating as a non-root user

The runtime image runs as `fundipulse` (uid 1001), and the migration runs as that
same user. This is safe because the migration needs **no filesystem writes**:

* no migration reads or writes a file;
* `PYTHONDONTWRITEBYTECODE=1` means Python writes no `.pyc` files;
* `alembic/`, `alembic.ini`, `app/` and `docker/entrypoint.sh` are `COPY
  --chown=fundipulse:fundipulse`, and the script is `--chmod=0755`;
* the only writes go to the database, over the network.

Run against a scratch database, the migration created all 31 tables without
modifying a single file in the image tree.

### Retries

A free-tier managed database suspends when idle and takes a few seconds to resume,
so the first connection after a cold start can fail even when nothing is wrong.
The entrypoint retries `alembic upgrade head` up to `MIGRATION_ATTEMPTS` times
(default 3) with `MIGRATION_RETRY_DELAY` seconds between (default 5). After the
last attempt it exits non-zero rather than starting the API against no schema.

Both are environment variables, so they can be tuned without a rebuild:

| Variable | Default |
| --- | --- |
| `MIGRATION_ATTEMPTS` | `3` |
| `MIGRATION_RETRY_DELAY` | `5` |

### The database URL

`alembic` never reads a connection string from `alembic.ini` — that field is
deliberately empty. [`alembic/env.py`](../alembic/env.py) resolves
`settings.database_url` from the same `Settings` object the application uses, so
the migration and the API read the identical `DATABASE_URL` and pass the identical
production-posture validation. No credential appears in the script, the
Dockerfile, or the process table.

## Environment variables

Required, with no default:

| Variable | Note |
| --- | --- |
| `DATABASE_URL` | Supplied by `fromDatabase`. Must not be the local placeholder. |
| `SECRET_KEY` | `sync: false`. ≥32 chars, distinct from `JWT_SECRET`. |
| `JWT_SECRET` | `sync: false`. ≥32 chars, distinct from `SECRET_KEY`. |

Production posture — the app **refuses to boot** without these:

| Variable | Value |
| --- | --- |
| `APP_ENV` | `production` |
| `CORS_ALLOWED_ORIGINS` | Comma-separated, **not** JSON |
| `ENABLE_DOCS` | `false` (forced off in production regardless) |

Correctness-critical:

| Variable | Default | Note |
| --- | --- | --- |
| `EMAIL_SMTP_HOST` | — | **Required for registration to work.** Empty keeps the safe-failure channel |
| `EMAIL_SMTP_PORT` | `587` | Submission. Use `465` for implicit TLS |
| `EMAIL_SMTP_USERNAME` | — | Leave empty only for an unauthenticated relay |
| `EMAIL_SMTP_PASSWORD` | — | `sync: false`. Required whenever the username is set |
| `EMAIL_SMTP_FROM` | — | Falls back to the username |
| `EMAIL_SMTP_USE_TLS` | `true` | STARTTLS. `false` + port 465 means implicit TLS |
| `EMAIL_SMTP_FROM_NAME` | `FundiPulse` | Display name in the worker's inbox |
| `EMAIL_SMTP_TIMEOUT_SECONDS` | `10` | Bounds a wedged relay from holding a request open |
| `RATE_LIMIT_BACKEND` | `memory` | Set `redis`. The memory store does not share counters, so N containers give N× the limit. |
| `REDIS_URL` | — | Required when the backend is `redis`. |
| `STORAGE_BACKEND` | `memory` | `s3` in production; `InMemoryStorage` is refused there. |
| `STORAGE_BUCKET` | — | Required for `s3`. |
| `STORAGE_ACCESS_KEY` / `STORAGE_SECRET_KEY` | — | `sync: false`. |
| `STORAGE_ENDPOINT` | — | For MinIO or an S3-compatible provider. |
| `MALWARE_SCANNING_ENABLED` | `false` | Off means uploads land `PENDING` and are therefore **not downloadable**. |

**No secret is committed.** `scripts/scan_secrets.py` runs in CI and compares
against `.secrets.baseline`.

## Email delivery

Verification and password-reset mail is sent over SMTP using the standard
library. There is no vendor SDK, so no dependency and no transitive
vulnerability surface is added.

### How the channel is chosen

`app/services/delivery_service.py` installs exactly one channel:

| Environment | `EMAIL_SMTP_HOST` | Channel |
| --- | --- | --- |
| development / test | anything | `ConsoleTokenDeliveryChannel` — logs the token |
| production | set | `SMTPTokenDeliveryChannel` — real delivery |
| production | empty | `NullTokenDeliveryChannel` — raises 503 |

There is **no fallback from production to the console channel.** It would look
like a healthy deployment while sending nothing, and the only symptom would be
workers reporting they never received a verification email.

`EMAIL_SMTP_USERNAME` set without `EMAIL_SMTP_PASSWORD` is refused at boot: half
a credential pair otherwise fails much later as an opaque authentication error at
send time.

### Configure it on Render

Set these in the dashboard. `EMAIL_SMTP_PASSWORD` is `sync: false`, so it must
be entered by hand and never committed.

```
EMAIL_SMTP_HOST=smtp.your-provider.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=postmaster@yourdomain.co.ke
EMAIL_SMTP_PASSWORD=<the provider's app password>
EMAIL_SMTP_FROM=postmaster@yourdomain.co.ke
EMAIL_SMTP_USE_TLS=true
```

Use the provider's **app password**, not the mailbox password: Gmail, Outlook and
most hosted providers require one, and several refuse basic auth on a real
password. `EMAIL_SMTP_FROM` must be on the domain the credentials authenticate
against, or the relay rejects it.

### What happens if it is misconfigured or unreachable

| Situation | Behaviour |
| --- | --- |
| Registration, delivery fails | **503**, transaction rolled back, **no account created** |
| Password reset, delivery fails | **202**, byte-identical to success |
| Resend verification, delivery fails | **202**, for the same reason |
| Delivery succeeds | the token reaches the worker; nothing else changes |

Reset and resend must not disclose delivery state: reporting "delivery failed"
would confirm whether an account exists. That is an enumeration oracle, so those
two routes swallow the error and answer exactly as they would on success.

Registration is the opposite case. The account cannot be used without
verification, so a registration whose email did not send must not persist. `get_db`
commits only after the route returns cleanly, so the rollback happens naturally.
This is asserted directly against `get_db` in
`tests/unit/test_email_delivery.py` rather than against the test harness's
override, which deliberately has no rollback branch.

### TLS

STARTTLS, with certificate and hostname verification against the system trust
store. A plain connection without TLS is **refused in production** rather than
merely discouraged, because a verification link is a single-use bearer token and
putting one on the wire in cleartext would hand it to anyone on the path. The
refusal does not apply outside production, so a developer's local relay still
works.

### Secrets

`EMAIL_SMTP_PASSWORD` is a `SecretStr`, so it is absent from `repr()` and from
the settings object. The delivery channel does not hold it either: it reads the
password from the process settings at send time, so neither a stack trace nor a
debugger can expose it. No log record, exception message or response body carries
the password or the token, and tests assert both.

### The verification link

Links are built from the **first** `CORS_ALLOWED_ORIGINS` entry:

- `POST /auth/verify-email` → `{origin}/verify-email?token=…`
- password reset → `{origin}/reset-password?token=…`

Two consequences worth knowing before this works end to end:

1. That first origin must be the **PWA**, not the API. As configured today it is
   the API's own origin, so the delivered links point at a service with no such
   page.
2. The worker PWA has **no `/verify-email` route**. A worker who clicks the link
   gets a 404 and cannot activate their account. Adding that screen is front-end
   work and was deliberately not part of this change.

Both are reported rather than silently worked around.
## Container

* Multi-stage build, so the runtime image carries no compiler and no `pip`.
* Runs as uid 1001 (`fundipulse`). CI fails the build if `id -u` returns 0.
* `CMD` is `/app/docker/entrypoint.sh`, which migrates and then `exec`s Uvicorn so
  it becomes PID 1 and receives `SIGTERM` directly.
* Binds `$PORT` (Render always sets it), defaulting to 8080.
* `HEALTHCHECK` polls `/health/ready`, not `/health/live`. Readiness checks the
  database; liveness does not, so a database blip must not restart the container.
  It does **not** verify that the schema exists — see the symptom table above.
* Files go to object storage. The container filesystem is ephemeral, so anything
  written to local disk is lost on redeploy.

## Reference data: a one-time seed, not a startup step

The catalogue tables — **47 counties, 20 trades, 64 skills** — are reference
data, not schema. They are not created by a migration.

```bash
python -m app.db.seed --catalogues-only
```

Run it **once**, after the first successful migration. Until it has run, the
trade, county and skill filters on `GET /jobs` match nothing, and a worker cannot
record a trade on their profile.

**This is deliberately not part of the entrypoint.** The seed is idempotent —
repeated runs insert nothing and converge on the same state — but it is not a
no-op: every run **rewrites all 131 rows**. Running it on each boot would
silently revert any correction made to a county, trade or skill directly in the
database. Idempotent is not the same as harmless, and an automatic, unrequested
write to production reference data on every restart is not a risk worth taking for
convenience.

There is an explicit opt-in if a one-off run is easier than a shell:

| Variable | Default | Effect |
| --- | --- | --- |
| `RUN_CATALOGUE_SEED` | `false` | When `true`, the entrypoint runs `--catalogues-only` after migrating, before Uvicorn. |

Set it to `true` in the Render dashboard, restart once, then set it back to
`false`. A seed failure is logged and **does not** stop the container: the
catalogues are data, not schema, and taking the API down over a data-loading
problem would be worse than having empty filter dropdowns.

The seed never creates the sample accounts in production — that path is guarded
and refuses to run with `APP_ENV=production`, because every sample account shares
one published password.

## Pre-deployment checklist

1. `SECRET_KEY` and `JWT_SECRET` are distinct, ≥32 chars, and not in any log.
2. `CORS_ALLOWED_ORIGINS` lists the exact app origins.
3. `ALLOWED_HOSTS` lists the served hostname, or Host-header checks are skipped.
4. `RATE_LIMIT_BACKEND=redis` and Redis reachable — otherwise the effective limit
   is multiplied by the container count.
5. `STORAGE_BACKEND=s3` with a private bucket.
6. `MALWARE_SCANNING_ENABLED` decided deliberately. Off is safe but means evidence
   is not downloadable until a scanner exists.
7. `EMAIL_SMTP_HOST` and credentials are set. Without them `/auth/register`
   returns **503** by design — see Email delivery above.
8. `CORS_ALLOWED_ORIGINS[0]` is the PWA origin, so verification links resolve.
9. After the first deploy: `python -m app.db.seed --catalogues-only` has been run,
   so the reference catalogues are populated.
10. Health probes return 200 on `/health/ready`.

`POST /auth/register` returning 200 is the single check that covers items 7 and 8
together: it only succeeds if the mail was actually accepted by the relay.

Steps 1–6 are unchanged. Step 7 replaces the old "`alembic upgrade head` applied"
item: on Free the entrypoint applies migrations during startup, so there is no
manual step to perform before the first request — but there **is** a manual seed
afterwards.

### Verifying the schema landed

`/health/ready` returning 200 proves nothing about the schema. Check a route that
actually reads a table:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://fundipulse-api.onrender.com/trades
# 200 once the schema exists; 500 means the migration did not run.
```

## Smoke tests after deploy

```bash
BASE=https://fundipulse-api.onrender.com

curl -sS "$BASE/health/ready" | jq .          # 200, database reachable

# The schema exists. This is the check that actually proves the startup
# migration ran; readiness alone does not.
curl -sS -o /dev/null -w '%{http_code}\n' "$BASE/trades"   # 200, not 500

# The reference catalogues are populated. total_items > 0 proves the one-time
# seed has been run; an empty list means filters will match nothing.
curl -sS "$BASE/trades" | jq '.meta.total_items'           # 20

# Unauthenticated search returns 200; a private worker is absent.
curl -sS "$BASE/workers" | jq '.meta.total_items'

# Registration works end to end, which proves SMTP and the schema.
# 200 = the verification mail was accepted by the relay.
# 503 = EMAIL_SMTP_* is not configured.
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$BASE/auth/register" \
  -H 'content-type: application/json' \
  -d '{"email":"smoke@example.com","password":"BuildSite12345","role":"WORKER","accepted_terms":true}'

# Authentication is enforced.
curl -sS -o /dev/null -w '%{http_code}\n' "$BASE/workers/me/profile"   # 401

# No path carries a version prefix.
curl -sS "$BASE/openapi.json" | jq -r '.paths | keys[]' | grep -c '^/api/' || echo 0
```

That last one should print `0`. A non-zero result means a prefix has been
reintroduced; `tests/integration/test_infrastructure.py` asserts the same thing so
CI catches it first.

## Rollback

Application code rolls back by redeploying the previous commit. **Migrations do
not roll back with it.** A migration that drops or renames a column is not
reverse-compatible with the previous image; take a `pg_dump` before any such
migration:

```bash
pg_dump "$DATABASE_URL" --format=custom --file=pre-downgrade.dump
```
