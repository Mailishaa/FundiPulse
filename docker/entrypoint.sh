#!/bin/sh
# FundiPulse container entrypoint.
#
# Render Free provides no shell and no Pre-Deploy Command, so there is nowhere
# outside the container to run `alembic upgrade head`. Doing it here is the only
# way the schema gets created, and it has to happen before the first request,
# because every database-backed endpoint fails against a schema-less database
# while `/health/ready` still reports 200: the readiness probe only proves the
# connection opened, not that the tables are there.
#
# Order matters. Migrations first, Uvicorn second, and never the reverse — a
# container that serves traffic against an unmigrated schema fails every request
# in a way that looks like an application bug rather than a missing deployment
# step.
#
# POSIX sh, not bash: the runtime image is python:3.12-slim-bookworm, which has no
# bash. Shebang is `/bin/sh` so this does not depend on the caller's shell.

set -e

# `alembic.ini` and the `alembic/` package are resolved relative to the working
# directory. Deriving it from this script's own location means the container
# still starts if something overrides the working directory.
APP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$APP_ROOT"

# A managed free-tier database suspends when idle and takes a few seconds to
# resume. The first connection after a cold start can therefore fail even though
# nothing is wrong. A short bounded retry rides that out; it does not mask a
# genuine failure, because after the last attempt the exit status still wins and
# the container refuses to start.
MIGRATION_ATTEMPTS="${MIGRATION_ATTEMPTS:-3}"
MIGRATION_RETRY_DELAY="${MIGRATION_RETRY_DELAY:-5}"

log() {
    printf '%s entrypoint: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

# Run the migrations. `alembic` reads DATABASE_URL from app.core.config via
# alembic/env.py, so this uses the same environment variable and the same
# Settings validation as the application. No URL is passed on the command line,
# which keeps credentials out of the process table and out of this file.
run_migrations() {
    attempt=1
    while [ "$attempt" -le "$MIGRATION_ATTEMPTS" ]; do
        if alembic upgrade head; then
            return 0
        fi

        if [ "$attempt" -eq "$MIGRATION_ATTEMPTS" ]; then
            log "alembic upgrade head failed after ${MIGRATION_ATTEMPTS} attempts."
            log "Refusing to start: the API cannot serve requests against an unmigrated schema."
            return 1
        fi

        log "alembic upgrade head failed (attempt ${attempt}/${MIGRATION_ATTEMPTS})."
        log "A suspended free-tier database is the usual cause. Retrying in ${MIGRATION_RETRY_DELAY}s."
        sleep "$MIGRATION_RETRY_DELAY"
        attempt=$((attempt + 1))
    done

    return 1
}

log "app_env=${APP_ENV:-unset} running database migrations"
run_migrations
log "migrations complete, starting uvicorn on port ${PORT:-8080}"

# The catalogue reference data (counties, trades, skills) is deliberately NOT
# seeded here. `--catalogues-only` is idempotent, but it rewrites all 131
# reference rows on every execution, so running it on each boot would silently
# revert any correction made in the database. It is a one-time command; see
# docs/deployment.md.
if [ "${RUN_CATALOGUE_SEED:-false}" = "true" ]; then
    log "RUN_CATALOGUE_SEED=true, loading reference data"
    if ! python -m app.db.seed --catalogues-only; then
        # Not fatal. The catalogues are reference data, not schema: the API runs
        # without them and the affected filters simply match nothing. Failing the
        # boot here would take the whole API down for a data-loading problem.
        log "catalogue seed failed; continuing. Trade, county and skill filters will match nothing."
    fi
fi

# `exec` replaces this shell, so Uvicorn becomes PID 1 and receives SIGTERM
# directly. Without it, PID 1 is a shell that does not forward signals, and a
# rolling deploy or a platform stop would wait out the timeout and then SIGKILL
# an in-flight request.
#
# ${PORT:-8080} is unquoted so the shell expands it; Render always sets PORT.
# The arguments below are otherwise identical to the previous inline CMD.
exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1 --proxy-headers --forwarded-allow-ips='*'