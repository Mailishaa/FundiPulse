# FundiPulse API
#
# Multi-stage so the runtime image carries no build toolchain and no source.
# The wheels are resolved on the builder's platform and installed with
# `--no-compiler`, so no `.c` toolchain is needed in the final image.

# --------------------------------------------------------------------------- #
# Stage 1: build a virtualenv with the runtime dependencies                    #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

RUN apt-get update \
    && apt-get install --no-install-recommends -y build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/ ./requirements/

# Build the dependency tree into a self-contained prefix rather than installing
# into the system site-packages, so it can be copied out without pip or headers.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install -r requirements/base.txt


# --------------------------------------------------------------------------- #
# Stage 2: runtime                                                            #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_ENV=production

# libpq5 is the only shared library the app needs at run time; curl is for the
# container HEALTHCHECK below.
RUN apt-get update \
    && apt-get install --no-install-recommends -y libpq5 curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1001 fundipulse \
    && useradd --system --uid 1001 --gid fundipulse --home-dir /app --shell /usr/sbin/nologin fundipulse

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Copy the application and the migration history. Alembic runs as a pre-deploy
# command, so its versions must be in the image.
COPY --chown=fundipulse:fundipulse alembic/ ./alembic/
COPY --chown=fundipulse:fundipulse alembic.ini ./
COPY --chown=fundipulse:fundipulse app/ ./app/
COPY --chown=fundipulse:fundipulse pyproject.toml ./

USER fundipulse

EXPOSE 8080

# Readiness, not liveness: a container that is up but cannot reach the database is
# not ready, and this is the probe Render's health check uses.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:"${PORT:-8080}"/health/ready || exit 1

# Bind to 0.0.0.0 so the platform's router can reach it, and honour $PORT which
# Render sets. One worker per container: the rate-limit counters are in-process,
# and the docs say so; scale with more containers and RATE_LIMIT_BACKEND=redis.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1 --proxy-headers --forwarded-allow-ips='*'"]
