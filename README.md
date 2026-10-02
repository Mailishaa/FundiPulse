# FundiPulse API

Backend API for FundiPulse, a mobile-first construction workforce platform for
Kenya. Workers build a verifiable digital **Work Passport**; employers find and
contact suitable tradespeople; administrators moderate the platform.

> **Milestone status:** this repository is being built in phases. The current
> state is described honestly in [Project status](#project-status) below. Where a
> document describes behaviour that is not implemented yet, it says so.

---

## Table of contents

- [What this API does](#what-this-api-does)
- [Project status](#project-status)
- [Architecture](#architecture)
- [Local setup](#local-setup)
- [Environment variables](#environment-variables)
- [Database setup and migrations](#database-setup-and-migrations)
- [Seed data](#seed-data)
- [Running the API](#running-the-api)
- [Running tests](#running-tests)
- [Linting, typing and security checks](#linting-typing-and-security-checks)
- [API documentation](#api-documentation)
- [CI/CD](#cicd)
- [Deployment](#deployment)
- [Security assumptions](#security-assumptions)
- [Known limitations](#known-limitations)
- [Further documentation](#further-documentation)

---

## What this API does

FundiPulse connects construction workers to employers in Kenya.

**Workers** create an account and a *Work Passport*: trades, skills, dated work
experience, documented construction projects with the role they played,
evidence files, referees, credentials, availability and location. A worker
requests verification of specific claims; an authorised third party responds;
the platform records that fact.

**Employers** are organizations. Several users can belong to one company with
different powers. Employers post jobs and search for workers by trade, skills,
county, experience and availability, then review the factual parts of a Work
Passport and manage applications.

**Administrators** moderate content, manage the trade and skill catalogues,
review reports, and record sensitive account actions. Every administrator action
is written to an append-only audit log.

Deliberately out of scope for this milestone: tender ingestion, SMS/WhatsApp
delivery, star ratings, and a general-purpose web scraper. See
[docs/architecture.md](docs/architecture.md#explicitly-out-of-scope) for why.

---

## Project status

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Repository inspection, architecture, data model, migrations | **Complete** (PR #1) |
| 2 | Authentication, authorisation, users | **Complete** (PR #2) |
| 3 | Worker profiles, trades, skills, projects, experiences | Not started |
| 4 | References, verification, credentials, audit logs | Not started |
| 5 | Organizations, employer search, jobs, applications | Not started |
| 6 | File security, rate limiting, hardening | Not started |
| 7 | Full test suite, coverage, static analysis | Not started |
| 8 | Docker, CI/CD, Render readiness | Not started |

**What exists today:**

* **20 endpoints** under `/api/v1` plus three health probes, with full OpenAPI.
* **Full authentication**: registration, login, refresh rotation with reuse
  detection, logout, password change/reset, email verification.
* **Authorisation**: deny-by-default role gates, mass-assignment protection,
  resource-ownership helpers, administrator safety rails.
* **28-table schema** with 48 CHECK constraints, partial unique indexes, and a
  trigger making `audit_logs` append-only. `alembic check` reports zero drift.
* **Structured logging** with request correlation and key-name redaction.
* **Security headers**, an exact-origin CORS allowlist, body-size limits.
* **380 tests** passing at **90.75%** application coverage.
* Ruff, MyPy (strict), Bandit, `pip-audit` and a secret scanner all clean.

**What does not exist yet:** rate limiting, file uploads and object storage, the
worker/employer/job domain endpoints, seed data, the CI pipeline and the Docker
image. Phases 3-8. Nothing in this README describes them as working.

**Not implemented, and not faked:** no email is actually sent. No mail provider is
configured, so `NullTokenDeliveryChannel` raises in production rather than silently
dropping password-reset mail — a silent no-op would leave users locked out while
reporting success.

---

## Architecture

Layered, with a strict dependency direction: `api → services → repositories →
db`. HTTP concerns, validation, business rules, data access, authentication and
security are separate concerns and never mixed in a route handler.

```
app/
├── main.py                 # ASGI application factory and middleware wiring
├── api/
│   ├── dependencies.py     # Shared FastAPI dependencies (auth, rate limits, DB)
│   ├── errors.py           # Exception handlers → the standard error envelope
│   └── routes/             # One module per domain; thin, no business logic
├── core/
│   ├── config.py           # Pydantic Settings, production safety validation
│   ├── constants.py        # Controlled vocabularies (roles, statuses, enums)
│   ├── security.py         # Argon2id hashing, JWT issue/verify (Phase 2)
│   ├── logging.py          # Structured JSON logging (Phase 6)
│   ├── exceptions.py       # Application exception hierarchy
│   ├── rate_limit.py       # Pluggable rate limiting (Phase 6)
│   └── storage.py          # Object-storage abstraction (Phase 6)
├── db/
│   ├── base.py             # Declarative base, mixins, enum CHECK installer
│   ├── guards.py           # DB-level guarantees (append-only audit, checks)
│   ├── session.py          # Engine, session factory, request-scoped session
│   ├── types.py            # Column type and constraint helpers
│   └── models/             # SQLAlchemy ORM models by domain
├── schemas/                # Pydantic request/response schemas (Phase 2+)
├── services/               # Business logic; the only place rules live (Phase 2+)
└── repositories/           # Query construction and persistence (Phase 2+)
```

Full reasoning, including the dependency-direction rules and how later features
slot in, is in [docs/architecture.md](docs/architecture.md).

### Why these technology choices

| Choice | Reason |
| --- | --- |
| PostgreSQL | Partial unique indexes, CHECK constraints and row triggers are load-bearing for the race-safety and audit guarantees. SQLite cannot provide them. |
| SQLAlchemy 2.0 (sync) | The transaction patterns the domain needs map directly onto one session. Sync avoids running blocking I/O across an async/sync boundary. See the ADR. |
| UUIDv4 primary keys | Non-sequential, so IDs in URLs cannot be walked. 122 bits of entropy means enumeration is infeasible. |
| `VARCHAR` + `CHECK` enums | Adding a status becomes a reversible migration instead of `ALTER TYPE` surgery. |
| Alembic only | `create_all()` is never used for schema management, in any environment. |

---

## Local setup

**Requirements:** Python 3.12, PostgreSQL 14+ (developed against 18), `uv` or
`pip`.

```bash
git clone https://github.com/Mailishaa/FundiPulse.git
cd FundiPulse

# 1. Create a virtual environment
uv venv --python 3.12 .venv          # or: python3.12 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
uv pip install -r requirements/dev.txt     # or: pip install -r requirements/dev.txt
#    For runtime only:  pip install -r requirements/base.txt
```

### PostgreSQL

Using Docker:

```bash
docker compose up -d db
```

Or an existing local server:

```bash
sudo -u postgres psql -c "CREATE USER fundipulse WITH PASSWORD 'fundipulse';"
sudo -u postgres psql -c "CREATE DATABASE fundipulse OWNER fundipulse;"
sudo -u postgres psql -c "CREATE DATABASE fundipulse_test OWNER fundipulse;"
```

### Environment

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(48))"   # JWT_SECRET
```

Then edit `.env` and set `DATABASE_URL` for your local server. `.env` is
git-ignored; `.env.example` contains placeholders only.

### Database setup and migrations

```bash
alembic upgrade head          # create/upgrade the schema
alembic current               # show applied revision
alembic history --verbose     # revision history
alembic downgrade -1          # roll back one migration
alembic check                 # detect model/migration drift (CI runs this)
```

**There is no `create_all()`.** The schema comes from migrations only, in every
environment, so that a fresh database is byte-for-byte reproducible from the
repository history.

Rolling back: `downgrade` is implemented for every migration, but downgrades
destroy data. Before running one in production, take a snapshot:

```bash
pg_dump "$DATABASE_URL" --format=custom --file=pre-downgrade.dump
```

### Seed data

Not implemented yet — Phase 3. It will be **development-only** and will refuse to
run when `APP_ENV=production`. Until then the trade, skill and county catalogues
are empty, so the worker endpoints that depend on them land with seeding.

### Running the API

```bash
# Development (auto-reload)
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Production-style: no reload, bound to $PORT (Render supplies this)
uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers 1
```

`app.main:app` is the application factory result.

---

## Running tests

```bash
pytest                                  # 380 tests
pytest -m unit                          # fast, no database
pytest -m integration                   # service + database
pytest -m api                           # HTTP surface
pytest -m security                      # adversarial / regression tests
pytest --cov=app --cov-report=term-missing
```

The test database (`fundipulse_test`) is created and **migrated by Alembic** at
session start — the suite therefore proves the migrations work, using the same
code path production uses. `create_all()` is never used. The suite refuses to run
against a database whose name does not contain `test`.

Each test gets a fresh app instance and a session whose work is rolled back, so
tests cannot leak state into one another.

**Coverage gate:** ≥ 90% of application code, enforced by `pytest` and by CI
(`pyproject.toml → [tool.coverage.report] fail_under = 90`). Currently **90.75%**.

---

## Linting, typing and security checks

```bash
ruff check app tests alembic scripts     # lint
ruff format --check app tests alembic    # formatting
ruff format app                          # apply formatting
mypy app                                 # strict type checking
bandit -r app -c pyproject.toml           # security lint (OWASP/CWE)
pip-audit --local --strict             # dependency vulnerabilities (audits the venv)
detect-secrets scan --all-files           # secret scanning
```

All of these run in CI and **fail the build** on a new finding.

---

## API documentation

Interactive docs (development only by default):

* Swagger UI: `http://localhost:8000/docs`
* ReDoc: `http://localhost:8000/redoc`
* OpenAPI JSON: `http://localhost:8000/openapi.json`

In production the OpenAPI schema is still served (needed for client generation)
but the interactive UIs are **disabled by default**. Enable them deliberately
with `ENABLE_DOCS=true`.

Endpoints are versioned under `/api/v1`. Unversioned production contracts are
not exposed.

---

## CI/CD

`.github/workflows/security.yml` exists now: secret scanning, Bandit and
`pip-audit`. The full `ci.yml` (lint, type check, tests, coverage gate, build) is
Phase 8.

Branch strategy: **feature branches → PR → `dev`**. `main` is the stable trunk and
is only promoted deliberately. PRs are never auto-merged.

Deployment is never triggered by an arbitrary branch.

---

## Deployment

Target platform is **Render**. `render.yaml` and the full procedure are Phase 8.
The design assumptions already enforced in code:

* Managed PostgreSQL, reachable only over Render's private network.
* Migrations run as a **pre-deploy command**, not at application start-up, so a
  failed migration never leaves two versions serving traffic.
* The container runs as a non-root user and exposes `GET /health/ready` for the
  Render health check.
* All secrets are set in Render's dashboard or via GitHub environment secrets.
  No secret is committed.

Full procedure, including the pre-deployment checklist and smoke tests, is in
[docs/deployment.md](docs/deployment.md).

---

## Security assumptions

Implemented controls are listed in [docs/security.md](docs/security.md) and
tracked in [docs/security-checklist.md](docs/security-checklist.md).

What the design assumes and does **not** claim:

* **Not "OWASP compliant".** OWASP Top 10 categories are used as an engineering
  checklist. There is no such thing as OWASP certification, and none is claimed.
* **Verification is not a guarantee.** A FundiPulse verification records that a
  named third party confirmed a claim on a stated date. It is not a background
  check, not a guarantee of competence, and not professional certification.
* **A credential is not a verification.** Uploading a certificate records a
  claim. It never makes the platform assert the document is genuine.
* **No legal or regulatory compliance is asserted.** Data-protection, labour and
  professional-licensing questions need review by a qualified Kenyan lawyer
  before launch. See [docs/privacy.md](docs/privacy.md).
* **TLS termination is the platform's job.** The app enforces HSTS and
  secure-cookie behaviour, but assumes TLS is terminated upstream and that
  Render's private database link is trusted.

---

## Known limitations

Current, honest limitations:

* **No HTTP endpoints yet.** `app/main.py` and the `api/` layer are not
  implemented; this milestone delivers the data layer.
* **No authentication yet.** `app/core/security.py` is not implemented, so there
  are no tokens, no password hashing and no sessions.
* **No test suite yet.** The 90% coverage gate is configured but nothing is
  measured.
* **No CI/CD or Docker yet.**
* **Storage is not wired.** `files` is metadata-only; there is no object-storage
  client, no upload endpoint and no signed URLs.
* **No notification delivery.** `notification_events` is an outbox table with
  no dispatcher.
* **Trade, skill and county catalogues are empty** until seeding lands.

---

## Further documentation

| Document | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Layering, dependency rules, request lifecycle, extension points |
| [docs/data-model.md](docs/data-model.md) | Entities, ERD, integrity rules, concurrency guarantees |
| [docs/api-design.md](docs/api-design.md) | Response conventions, versioning, pagination, errors, idempotency |
| [docs/security.md](docs/security.md) | Threat model and controls per OWASP category |
| [docs/security-checklist.md](docs/security-checklist.md) | Pre-deployment review checklist, itemised |
| [docs/privacy.md](docs/privacy.md) | Data inventory, retention, deletion, legal open questions |
| [docs/privacy.md](docs/privacy.md) | Data minimisation, retention, what is collected and why |
| [docs/testing-strategy.md](docs/testing-strategy.md) | Test layers, fixtures, property testing, coverage policy |
| [docs/deployment.md](docs/deployment.md) | Render deployment, migrations, smoke tests, rollback |
| [docs/decisions/](docs/decisions/) | Architecture decision records with rationale |