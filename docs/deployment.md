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

## Why migrations are a pre-deploy command

```yaml
preDeployCommand: alembic upgrade head
```

Not at application start-up. If migrations ran on boot, a failed migration would
leave one container running new code against an old schema while another runs old
code against the same database — two versions serving traffic against one schema.
A pre-deploy command either succeeds for every new container or starts none.

The image therefore contains `alembic/` and `alembic.ini`.

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
| `RATE_LIMIT_BACKEND` | `memory` | Set `redis`. The memory store does not share counters, so N containers give N× the limit. |
| `REDIS_URL` | — | Required when the backend is `redis`. |
| `STORAGE_BACKEND` | `memory` | `s3` in production; `InMemoryStorage` is refused there. |
| `STORAGE_BUCKET` | — | Required for `s3`. |
| `STORAGE_ACCESS_KEY` / `STORAGE_SECRET_KEY` | — | `sync: false`. |
| `STORAGE_ENDPOINT` | — | For MinIO or an S3-compatible provider. |
| `MALWARE_SCANNING_ENABLED` | `false` | Off means uploads land `PENDING` and are therefore **not downloadable**. |

**No secret is committed.** `scripts/scan_secrets.py` runs in CI and compares
against `.secrets.baseline`.

## Container

* Multi-stage build, so the runtime image carries no compiler and no `pip`.
* Runs as uid 1001 (`fundipulse`). CI fails the build if `id -u` returns 0.
* `HEALTHCHECK` polls `/health/ready`, not `/health/live`. Readiness checks the
  database; liveness does not, so a database blip must not restart the container.
* Files go to object storage. The container filesystem is ephemeral, so anything
  written to local disk is lost on redeploy.

## Pre-deployment checklist

1. `alembic upgrade head` applied and `alembic check` reports no drift.
2. `SECRET_KEY` and `JWT_SECRET` are distinct, ≥32 chars, and not in any log.
3. `CORS_ALLOWED_ORIGINS` lists the exact app origins.
4. `ALLOWED_HOSTS` lists the served hostname, or Host-header checks are skipped.
5. `RATE_LIMIT_BACKEND=redis` and Redis reachable — otherwise the effective limit
   is multiplied by the container count.
6. `STORAGE_BACKEND=s3` with a private bucket.
7. `MALWARE_SCANNING_ENABLED` decided deliberately. Off is safe but means evidence
   is not downloadable until a scanner exists.
8. Health probes return 200 on `/health/ready`.

## Smoke tests after deploy

```bash
BASE=https://fundipulse-api.onrender.com

curl -sS "$BASE/health/ready" | jq .          # 200, database reachable

# Unauthenticated search returns 200; a private worker is absent.
curl -sS "$BASE/workers" | jq '.meta.total_items'

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
