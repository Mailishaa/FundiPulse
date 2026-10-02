# Security

Controls implemented in this milestone, mapped to the OWASP Top 10 (2021).

> **This is not a certification claim.** There is no such thing as "OWASP
> compliant". The categories are used as an engineering checklist. Verification
> against an actual standard, penetration test or legal review is outstanding work
> — see [Remaining risk](#remaining-risk).

---

## Summary of what exists

| OWASP | Status | Where |
| --- | --- | --- |
| A01 Broken Access Control | Substantial | `app/api/dependencies.py`, `app/services/*`, tests |
| A02 Cryptographic Failures | Substantial | `app/core/security.py`, `app/db/guards.py` |
| A03 Injection | Substantial | ORM throughout, bounds, allowlists |
| A04 Insecure Design | Documented | `docs/decisions/`, this document |
| A05 Security Misconfiguration | Substantial | `app/core/config.py`, `app/api/middleware.py` |
| A06 Vulnerable Components | Enforced in CI | `.github/workflows/security.yml` |
| A07 Authentication Failures | Substantial | `app/services/auth_service.py` |
| A08 Software/Data Integrity | Partial | Pinned locks, audit guard; CI/CD still to come |
| A09 Logging/Monitoring Failures | Partial | `app/core/logging.py`, `audit_logs`; alerting outstanding |
| A10 SSRF | N/A this milestone | No server-side fetching exists |

---

## A01 — Broken access control

### Implemented

* **The current user comes from the database, never the request.** `get_current_user`
  resolves a bearer token to a `User` row. A `role` in a body or header has no
  effect on anything.
* **Deny-by-default role gates.** `require_roles(*allowed)` admits only listed
  roles; an empty allowlist admits nobody. Adding a new `UserRole` member grants
  nothing until it is explicitly listed.
* **Two independent checks per admin endpoint.** The route dependency enforces the
  role, and the service re-asserts it. A refactor that loosens one does not open
  a hole.
* **Mass assignment is impossible.** Every request schema sets
  `extra="forbid"`, so `{"role": "ADMIN"}` on `PATCH /users/me` returns `422`,
  not a silent privilege change.
* **Self-registration cannot mint an administrator.** Rejected by a schema
  validator; the service independently normalises the role.
* **Account state is re-checked per request.** A valid JWT for a suspended or
  deactivated account is refused, so a stateless token check cannot outlive the
  state that justified it.

### Not yet implemented

Ownership checks for worker passports, organisations, jobs and applications
arrive with phases 3-5. The pattern — service holds the row, compares against
`actor.id`, deny — is already fixed by `require_self_or_admin`.

### Tests

`tests/security/test_authorization_and_security.py` — `TestRoleBasedAccessControl`,
`TestPrivilegeEscalation`, `TestIdorResistance`, `TestAdminSafetyRails`.

---

## A02 — Cryptographic failures

| Concern | Control |
| --- | --- |
| Passwords | Argon2id via `argon2-cffi` directly. `passlib` deliberately not used — unmaintained, lagging Argon2 backend. |
| Hash upgrades | `needs_rehash` upgrades a stored hash transparently on next successful login. |
| Access tokens | HS256 JWT with `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `typ`. Algorithm pinned from config. |
| Refresh tokens | Opaque 256-bit random values; only SHA-256 hashes stored, domain-separated. |
| Reset / verification tokens | Opaque, hashed, single-use, purpose-separated. |
| Storage | Not wired yet (Phase 6). Encryption at rest is the provider's responsibility — [ADR 0012](decisions/0012-sensitive-data-at-rest.md). |

### `alg: none` and algorithm confusion

The verifier passes `algorithms=[configured]`, so a token re-signed with `none` or
with an asymmetric algorithm is rejected. Tested in
`tests/unit/test_security.py::TestAccessTokens::test_rejects_an_unsigned_alg_none_token`.

### Why contact details are not application-encrypted

Rationale, alternatives and the trigger for revisiting are in
[ADR 0012](decisions/0012-sensitive-data-at-rest.md). The short version: a key
held by the same process that reads the data protects against nothing that
matters, and the real control is that no employer-facing schema contains those
fields at all.

---

## A03 — Injection

### SQL

All queries go through SQLAlchemy's parameterised layer. No string is ever
interpolated into SQL from user input. The only `text()` calls with interpolation
are in `app/db/guards.py`, using fixed literals from module constants.

Belt and braces: `statement_timeout = 15s`, `lock_timeout = 5s` and
`idle_in_transaction_session_timeout = 30s` are set on every connection, so a
pathological query fails fast instead of pinning a worker.

### Filter and sort allowlists

Sort keys and filters are typed parameters validated against
`app/core/constants.py` allowlists. There is no generic `?filter=` expression,
which is the usual route from user input to a WHERE clause.

### Path traversal

Structurally impossible: `files.object_key` is generated server-side from a UUID
and a validated content type. A user-supplied filename never influences a storage
path. There is no `open(user_supplied_filename)` anywhere.

### Header and log injection

`X-Request-ID` is accepted only when it matches `^[A-Za-z0-9_-]{8,64}$`;
anything else is replaced rather than reflected. Credential-bearing path segments
are replaced with a placeholder in the access log.

### Deserialisation

Only JSON. No pickle, no YAML `load`, no `eval`.

### Tests

`TestInjection` — 8 SQL payloads × login, registration, query parameters, plus a
proof the `users` table still exists afterwards.

---

## A04 — Insecure design

Threat modelling is embedded in the design rather than documented after the fact:

| Flow | Threat | Control |
| --- | --- | --- |
| Registration | Enumeration | Same error whether or not the address exists |
| Login | Enumeration, brute force | Identical error + equalised timing + lockout + audit |
| Password reset | Enumeration, replay | Uniform 202, single-use, newest-only, reuse invalidates the rest |
| Email verification | Token crossover | Separate `purpose` namespace; a reset token cannot verify an email |
| Token refresh | Theft | Rotation + family reuse detection revokes everything |
| Verification | Self-attestation | `CHECK (verified_by <> requested_by)` at row level |
| Files | Path traversal, malware, type confusion | Server keys, quarantine, magic-number checks |
| Job ingestion | SSRF, terms breach | No fetching code exists; source gates are in the schema |
| Admin actions | Privilege abuse | Self-change blocked, reason mandatory, append-only audit |

Decisions with rejected alternatives are in [`docs/decisions/`](decisions/).

---

## A05 — Security misconfiguration

`Settings._validate_production_posture` **refuses to start** on:

* `DEBUG=true`
* missing, short, placeholder, or shared `SECRET_KEY`/`JWT_SECRET`
* `PASSWORD_POLICY_ENFORCED=false`
* empty `CORS_ALLOWED_ORIGINS`
* `RATE_LIMIT_ENABLED=false`
* `DATABASE_ECHO=true`
* placeholder database credentials (`postgres:postgres`)
* `SENTRY_DSN` set without an integration

Additionally:

* SQLite is rejected in **every** environment, so the constraints and triggers
  the design relies on cannot be silently skipped.
* Interactive docs are off by default in production; enabling requires an
  explicit `ENABLE_DOCS=true`.
* `INTERNAL_SERVER` errors return a fixed message and a `request_id` in
  production. Verified by a test that builds an app with production settings.
* Security headers on every response: `nosniff`, `DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`, a restrictive
  `Permissions-Policy`, and `Content-Security-Policy: default-src 'none'`.
* HSTS is sent only in production — adding it to localhost would pin developers
  to plain HTTP.
* CORS uses an exact origin allowlist; a wildcard is rejected by configuration
  validation, and credentialed CORS is off by default.
* `sqlalchemy.engine` logging is pinned at WARNING because query text can contain
  values.

---

## A06 — Vulnerable components

* Dependencies pinned in `requirements/base.txt` and `dev.txt`, generated by
  `scripts/lock_requirements.py` with PEP 508 marker evaluation.
* `pip-audit --local --strict` runs in CI and fails on any finding.
* Verified locally: **no known vulnerabilities**.

Nothing is ignored. If a finding must be accepted, it is documented in this
document with a reason and a re-check date — not silenced in configuration.

---

## A07 — Authentication failures

* Argon2id; minimum 12 characters; length-dominant policy so a passphrase passes.
* Failures are uniform: "no such user" and "wrong password" produce the same code,
  the same message, and comparable latency (a dummy hash is verified when the
  address is unknown).
* Lockout after `MAX_FAILED_LOGIN_ATTEMPTS`, cleared on success.
* Access tokens live 15 minutes by default.
* Refresh tokens rotate on every use; **replay of a rotated token revokes the
  entire family** and records `TOKEN_REUSE_DETECTED`.
* Absolute family ceiling, so rotation cannot extend a session indefinitely.
* Password change and reset revoke **every** session, including the caller's —
  otherwise a stolen refresh token would survive the event meant to evict it.
* Logout revokes the current session; `{"all_sessions": true}` revokes all.

---

## A08 — Software and data integrity failures

* Dependencies pinned; lock files regenerated deliberately.
* Migrations are the only schema mechanism; `create_all()` is never used.
* Migration rollback ordering was verified: `upgrade → downgrade → upgrade`
  produces an identical schema, and `alembic check` reports zero drift.
* **Guard DDL is idempotent** — a re-applied or retried migration does not fail on
  `DuplicateObject`. Found by testing, fixed in `app/db/guards.py`.
* `audit_logs` is append-only via a database trigger, so it resists a compromised
  service account or a manual `psql` session, not merely a missing API endpoint.
* **Secret scanning** in CI: `detect-secrets` against a reviewed baseline, plus
  `scripts/scan_secrets.py` for concrete key shapes, plus an assertion that no
  `.env` exists anywhere in git history.
* Uploaded files are never executed or served from the application filesystem.

### Outstanding

CI/CD pipeline hardening (signed commits, protected branches, environment
secrets) arrives in Phase 8. Render deployment runs migrations as a pre-deploy
command rather than at application start-up, so a failed migration never leaves
two versions serving traffic.

---

## A09 — Logging and monitoring failures

* Newline-delimited JSON to stdout; readable locally.
* `X-Request-ID` on every request and response; carried in a `contextvar` so any
  log call can reach it.
* Fixed access-log vocabulary: method, **route template**, status, duration, user,
  `error_category`. The route template is logged rather than the raw path so a
  per-UUID path cannot fragment the logs, and so identifiers are not needlessly
  written.
* **Redaction by key name**, applied before serialisation: a caller that logs
  `extra={"refresh_token": ...}` produces `[REDACTED]`. Matched
  case-insensitively and separator-insensitively, so `Api-Key`, `api.key` and
  `ACCESS_TOKEN` are all caught.
* **Audit rows are the durable record**, and failures survive rollback. See below.

### The audit-rollback problem

An audit trail that discards failures is worse than none, because it looks
complete while recording only successes — precisely the gap an attacker exploits.
So `AuditService` has two write paths:

| Method | Transaction | Use for |
| --- | --- | --- |
| `record` | The caller's | Successful actions — commits atomically with the effect |
| `record_durable` | Commits on the caller's session | Failed/denied actions that accompany a raised exception |

`record_durable` commits rather than opening a second connection: a second
connection cannot see this transaction's uncommitted rows, so the audit insert
would fail its own foreign key on exactly the interesting cases.

### Outstanding

Alerting rules, log retention, and dashboards are **not** implemented. Logs alone
do not satisfy A09; they must be monitored. Tracked in
`docs/security-checklist.md`.

---

## A10 — SSRF

Not applicable in this milestone: **no code fetches a user-supplied URL**, and
there is no `POST /fetch-url` endpoint.

Future ingestion must, per `docs/architecture.md` and `job_sources` in the schema:

* allowlist registered sources only (no arbitrary hostname),
* block loopback, link-local, private ranges and cloud metadata endpoints,
* restrict to HTTPS, follow a bounded number of redirects and re-validate each hop,
* apply connect/read timeouts and response-size limits,
* require `terms_status = APPROVED` before any fetch,
* honour `robots_status` unless an operator recorded an explicit decision.

---

## Privacy and legal posture

* **No national ID is collected** — [ADR 0005](decisions/0005-no-national-id.md).
* No star ratings or trust scores — [ADR 0010](decisions/0010-no-ratings-or-completion-score.md).
* Verification is an attributed fact, never a guarantee —
  [ADR 0006](decisions/0006-verification-is-not-certification.md).
* Deletion is deactivation plus anonymisation, never a blind `DELETE`.

**No legal or regulatory compliance is claimed.** Kenya's Data Protection Act
2019 and OPSC guidance require review by a qualified lawyer before launch. See
`docs/privacy.md`.

---

## Remaining risk

| Risk | Severity | Mitigation / next step |
| --- | --- | --- |
| Rate limiting not bound to any endpoint | High | The limiter, its rules and its Redis backend are built and tested, but no route declares a limit yet, so requests are still unthrottled. Phase 6 binds it per endpoint.
| Redis rate-limit backend unverified against a real server | Medium | Exercised only through an injected fake client, so the Lua script has never executed. Smoke-test before relying on it.
| No email provider | Medium | Phase 2 gap by design. `NullTokenDeliveryChannel` fails loudly rather than silently dropping reset mail. |
| No file-upload endpoint | Medium | The storage layer and byte-level inspection are built and tested, but no route is mounted, so `files` stays metadata-only. Phase 6. |
| No alerting on security events | High | Needs log shipping plus rules before production. |
| Audit rows survive indefinitely | Low | Retention policy needs legal input. |
| No dependency-update automation | Medium | `dependabot.yml` in Phase 8. |
| Single-process deployment | Low | Documented in [ADR 0003](decisions/0003-sync-sqlalchemy.md). |
| Password policy cannot be disabled in production | — | Enforced; the flag exists for documented break-glass only. |