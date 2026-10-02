# Architecture

How the FundiPulse API is put together, and why. This document describes the
structure that is **currently in the repository**. Features scheduled for later
phases are labelled as such rather than described as if they exist.

---

## 1. Design goals, in priority order

The product brief sets the priorities explicitly, and they drive every trade-off
in this document:

1. **Correctness** — business rules are enforced server-side, once, in one place.
2. **Security** — authorisation is deny-by-default and resource-scoped.
3. **Testability** — rules are reachable without HTTP or a database where possible.
4. **Maintainability** — a new contributor can find the right layer quickly.
5. **Stable contracts** — the PWA can be built without the backend changing.
6. **Privacy** — collect the minimum, expose the minimum.

A seventh, implied: **honesty**. No document describes behaviour that does not
exist, and no test asserts a control that is not implemented.

---

## 2. Layering and dependency direction

```text
             ┌───────────────────────────────────────────────┐
   HTTP ───▶ │ api/           routes, dependencies, errors   │
             └──────────────────────┬────────────────────────┘
                                    │  (schemas: request/response DTOs)
             ┌──────────────────────▼────────────────────────┐
             │ services/       business rules, transactions   │
             └──────────────────────┬────────────────────────┘
                                    │
             ┌──────────────────────▼────────────────────────┐
             │ repositories/   query construction, persistence│
             └──────────────────────┬────────────────────────┘
                                    │
             ┌──────────────────────▼────────────────────────┐
             │ db/             engine, session, ORM models    │
             └───────────────────────────────────────────────┘

   core/  ── configuration, security primitives, logging, exceptions.
            Imported by every layer; depends on nothing above it.
```

**The rule:** an arrow may only point downward. A route may call a service. A
service may call a repository. A repository may use a model. Nothing may call
back up.

### Why a repository layer at all

It is tempting to write queries directly in services. FundiPulse separates them
because the search and filtering endpoints (worker discovery, job listing) are
where query construction goes wrong: an unvalidated sort key, a missing
pagination bound, an N+1. Isolating query construction means those decisions are
made in reviewable, unit-testable files instead of being interleaved with
business rules.

### Why schemas are separate from ORM models

`schemas/` holds Pydantic models; `db/models/` holds SQLAlchemy models. They are
never the same class. This is what prevents three classes of defect:

* **Accidental secret exposure.** `User.password_hash` cannot leak because the
  response schema simply has no such field.
* **Mass assignment.** Update schemas are explicit lists of writable fields; a
  new column is not writable until someone adds it deliberately.
* **Contract drift.** Column renames do not silently become breaking API
  changes, because the two vocabularies are separate.

### Layer responsibilities

| Layer | May do | May **not** do |
| --- | --- | --- |
| `api/routes/` | Parse request, call a service, map result to a schema, map errors | Contain business rules, build queries, or make authorisation decisions from request data alone |
| `api/dependencies.py` | Resolve the current user, enforce rate limits, provide a session | Decide ownership of a specific resource |
| `schemas/` | Validate shape, types, ranges, enums | Touch the database or perform I/O |
| `services/` | Enforce business rules, manage transactions, authorise actions, write audit entries | Import from `api/` |
| `repositories/` | Build and execute queries, return ORM or domain objects | Decide *whether* a caller may see a result |
| `db/models/` | Declare schema and integrity constraints | Know about HTTP or users |

---

## 3. Request lifecycle

Planned (Phase 2 and later):

```text
Request
  │
  ├─▶ SecurityHeadersMiddleware      HSTS, nosniff, frame-deny, referrer policy
  ├─▶ RequestIdMiddleware            accept or mint X-Request-ID, store in context
  ├─▶ CORSMiddleware                 exact allowlist, never wildcard + credentials
  ├─▶ LoggingMiddleware              structured access log with request_id
  │
  ├─▶ Route handler
  │     ├─ Depends(get_current_user)      Bearer token → User, or 401
  │     ├─ Depends(rate_limit("login"))    fixed-window counter, or 429
  │     ├─ Depends(get_db)                 request-scoped session
  │     └─ service call ──▶ authorisation ──▶ repository ──▶ PostgreSQL
  │
  ├─▶ Response envelope               {"data": ..., "meta": {...}}
  └─▶ Exception handler                {"error": {"code", "message", "request_id"}}
```

Any unhandled exception is logged with its `request_id` and replaced with a
generic `INTERNAL_ERROR` body. Stack traces are never returned in production.

---

## 4. Identity and authorisation model

### Identity is separate from profile

`users` holds only credentials and the platform role. A worker's professional
data lives in `worker_profiles`; an employer's company data lives in
`organizations`, reached through `organization_memberships`. Consequence: an
employer account is never "a company", so it cannot accidentally leak one
company's data to another.

### Two role vocabularies

| Scope | Where | Values |
| --- | --- | --- |
| Platform | `users.role` | `WORKER`, `EMPLOYER`, `ADMIN` |
| Organization | `organization_memberships.role` | `OWNER`, `ADMIN`, `RECRUITER`, `MEMBER` |

A user's power over an organization is the **intersection** of "has an active
membership" and "the membership role is in the required set". There is no
shortcut from platform role to organization access, so a user who is an
`EMPLOYER` has no authority over any organization until an `OWNER` adds them.

### Deny by default

Authorisation lives in service methods, not in route signatures. A route says
*who* is acting; the service decides *what they may do to this resource*.
Because the service holds the loaded row, ownership is checked against the
actual record rather than a client-supplied id.

Platform roles are read from the database session only. A request body, header
or query parameter can never influence an authorisation decision — the client is
not a trusted source of authority by construction.

---

## 5. Data layer decisions

* **UUIDv4 primary keys** on every table. Non-sequential, so an ID in a URL
  cannot be walked, and 122 bits of entropy makes enumeration infeasible even
  though IDs are public. Authorisation is enforced regardless, because
  unpredictable IDs are a defence-in-depth measure, not a substitute for an
  ownership check.
* **`TIMESTAMP WITH TIME ZONE` everywhere.** Timestamps are stored and returned in
  UTC. CI enforces this with ruff's `DTZ` rules, so a naive datetime cannot be
  introduced.
* **Enums are `VARCHAR` + `CHECK`.** Not native PostgreSQL enums, because adding
  a status must be a reversible migration.
* **Enum CHECK constraints are generated, not hand-written.** `install_enum_checks`
  derives them from the column types in `app/db/base.py`, so a new enum column
  cannot be created unconstrained.
* **Soft deletion only where retention has a rationale** — passports,
  credentials, references, evidence, organizations, jobs. Never for audit logs,
  verification records or applications, which transition instead.

---

## 6. Concurrency and race safety

The rule is: **never rely on `if not exists(): create()`**. Concurrent requests
can both pass the check. Every rule that must hold under concurrency is a
database constraint.

| Rule | Mechanism |
| --- | --- |
| One application per worker per job | `UNIQUE (job_id, worker_profile_id)` |
| Safe retry of an application | `UNIQUE (worker_profile_id, idempotency_key) WHERE idempotency_key IS NOT NULL` |
| One pending verification request per claim | `UNIQUE (target_type, target_id) WHERE status = 'PENDING'` |
| One primary trade per passport | `UNIQUE (worker_profile_id) WHERE is_primary` |
| No duplicate aggregated listing | `UNIQUE (source_id, source_job_id) WHERE source_job_id IS NOT NULL` |
| One report per reporter per subject | `UNIQUE (reporter_user_id, subject_type, subject_id)` |
| Unique registration for an email | `UNIQUE (email)` on the lower-cased value |

The service layer still performs a friendly pre-check so it can return a clean
`409 CONFLICT` instead of a driver error, but the **constraint** is what
guarantees correctness. Tests cover both the sequential and the concurrent path.

---

## 7. Transaction boundaries

A service method owns one transaction. It may read, validate, write several rows,
write an audit entry, and append a notification event — all committed together,
or none of it. Reads that must not observe a partially written unit of work are
performed inside the same transaction.

Application creation, verification responses and job status transitions all
follow this shape, so an audit entry cannot exist for an action whose effect was
rolled back, and vice versa.

---

## 8. Extension points

How later requirements attach without rework:

| Future need | Extension point |
| --- | --- |
| Job ingestion | `jobs` already carries full provenance and `job_source_events` records change detection. A pipeline writes `Job` rows; there is deliberately no HTTP endpoint that fetches an arbitrary URL. |
| Tender domain | A separate aggregate. A tender is a procurement opportunity, not a vacancy, so it never enters `job_applications`. Its absence from V1 is a decision, not an oversight. |
| Notifications | `notification_events` is an append-only outbox. A worker process can deliver SMS/push later without a schema change to the domain tables. |
| Email delivery | `security_tokens`, reference invitations and verification invitations all store **hashed** tokens already, so a mailer only needs the plaintext at issue time. |
| Redis rate limiting | `core/rate_limit.py` defines a store interface; the in-memory implementation is for single-process and test use. |
| Object storage | `core/storage.py` defines a `Storage` protocol; S3 and in-memory implementations satisfy it. |
| Additional platform roles | `users.role` is a `VARCHAR` + `CHECK`. Adding a value is a migration, and every role check is an explicit set membership test rather than an equality test. |

---

## 9. Explicitly out of scope for V1

Deliberately excluded, with reasoning:

* **Star ratings and reputation scores.** Unverifiable and gameable. The platform
  exposes factual signals instead: documented projects, verified projects,
  skills, credentials, availability.
* **Overall "passport completion" percentage.** A single number implies quality.
  The API returns per-section factual state instead.
* **Tender ingestion.** The core workforce system must be stable first, and a
  tender is a different domain.
* **SMS/WhatsApp/push delivery.** The outbox exists; the channels do not.
* **A generic `POST /fetch-url`.** Server-side fetching of user-supplied URLs is
  the SSRF problem in one line. There is no such endpoint, and any future
  fetcher must use an allowlist with private-range blocking.
* **Automatically verified uploaded certificates.** A credential is a claim.
* **Collecting a national ID number.** Nothing in V1 needs it, and not collecting
  it is the strongest available data-minimisation control.

---

## 10. Where to look for something

| Question | File |
| --- | --- |
| What roles and statuses exist? | `app/core/constants.py` |
| Why is the schema shaped this way? | `docs/data-model.md`, `docs/decisions/` |
| What makes production config safe? | `app/core/config.py` (`_validate_production_posture`) |
| What does the database guarantee? | `app/db/guards.py`, `docs/data-model.md` |
| Which table enforces a rule? | The `__table_args__` of that model |