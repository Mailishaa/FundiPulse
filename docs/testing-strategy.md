# Testing strategy

How this project is tested, and why it is tested that way.

**Current state: 380 tests, 90.75% application coverage, gate enforced at 90%.**

---

## Layers

| Layer | Marker | Database | Speed | Purpose |
| --- | --- | --- | --- | --- |
| Unit | `unit` | No | < 1s | Pure logic: policy, tokens, redaction, validation, helpers |
| Integration | `integration` | Yes | ~1s | Service + database + constraints + triggers |
| API | `api` | Yes | ~3s | Full HTTP through ASGI, real auth |
| Security | `security` | Yes | ~3s | Adversarial regression tests |

Run one layer with `pytest -m unit`, etc.

---

## Test database

* **Dedicated** `fundipulse_test`, never production.
* The suite **refuses to run** unless the database name contains `test`. A typo in
  `DATABASE_URL` would otherwise let the suite operate on real tables.
* The schema is built by **running Alembic** at session start, not by
  `create_all()`. That makes the suite prove the migrations work, using the same
  code path production uses.
* Each test gets a **fresh app instance** and a **rolled-back session**, so tests
  cannot leak state into one another.

The one deliberate exception is `AuditService.record_durable`, which commits its
own audit row — by design, because a failure audit that is rolled back with the
request would not be an audit trail. Those rows persist between tests, so
assertions on the audit table are scoped by `actor_user_id` or `request_id`
rather than counting globally.

---

## What is tested against the real thing

Nothing security-relevant is mocked:

* **Real Argon2id hashing.** A mock would not catch a change to the hash
  algorithm, the cost parameters, or the encode format.
* **Real signed JWTs.** A mock cannot catch a missing claim validation or an
  `alg: none` acceptance.
* **Real PostgreSQL.** CHECK constraints, partial unique indexes, triggers and
  `INET` columns only exist in the real database.
* **Real HTTP** through ASGI, including middleware and exception handlers.

Argon2 parameters are lowered in the test environment purely for speed.
`test_test_suite_never_uses_weaker_hashing_than_production` asserts the *declared
production defaults* are still 64 MiB / 3 iterations / 4 parallelism, so the
speed-up cannot leak into production.

---

## Coverage policy

**Gate: ≥ 90% application code**, enforced by `pytest` and by CI
(`pyproject.toml → [tool.coverage.report] fail_under = 90`).

The gate genuinely fails the build — it did during development, first at 83.7%
and then at 89.7%, and the gap was closed with real tests rather than by lowering
the threshold.

What is **not** done to reach the number:

* no `# pragma: no cover` on anything that is merely untested,
* no test that asserts a tautology,
* no exclusion of security-critical modules. `pyproject.toml` omits only
  `app/main.py` (the factory) and `app/db/models/*` (declarative schema, covered
  by the integration tests that exercise the constraints).

Coverage is a floor, not a goal. The security and authorisation paths carry
explicit adversarial tests regardless of what the percentage says.

---

## Fixtures

`tests/conftest.py` provides:

| Fixture | Purpose |
| --- | --- |
| `client` | `TestClient` whose requests share the test's session (`get_db` overridden) |
| `db_session` | Session whose uncommitted work is rolled back at teardown |
| `make_user` | Create a user with a valid password; optionally any role |
| `make_admin` | Same, defaulting to `ADMIN` |
| `auth_headers` | Log in through the **real** login endpoint, return bearer headers |
| `audit_rows` | Read audit rows written by the service under test |
| `error_code` | Extract the stable error code from a response, asserting the envelope shape |

`auth_headers` deliberately goes through the login endpoint rather than minting a
token directly, so a test using it exercises the actual authentication path.

---

## Property and edge-case testing

Property-based testing with Hypothesis is **planned for phase 3-5** rather than
applied everywhere, because most of the value is in validation-heavy logic that
does not exist yet: dates, geographic filters, availability, file inspection.

Already covered by ordinary tests, where they are clearer:

* **Empty / very long / Unicode / whitespace** strings in email validation,
  password policy and metadata redaction.
* **Invalid, future and inverted dates** in experience, project and credential
  records (CHECK constraints, plus Pydantic).
* **Huge pagination values** — `page_size` over the cap and `page` over
  `MAX_PAGE_NUMBER` both return `422`.
* **Negative and out-of-range values** — validated by Pydantic field constraints.
* **Duplicate records** — 409 from unique constraints, not 500.
* **Concurrent requests** — the unique-constraint race is asserted against the
  database (`uq_job_applications_job_worker` and friends arrive in phase 5);
  token consumption uses a conditional `UPDATE` and is tested for replay.

---

## Security regression tests

`tests/security/test_authorization_and_security.py`, grouped by OWASP category so
a reviewer can map a test to a threat:

* **A01** — every admin endpoint × {anonymous, worker, employer, admin}; mass
  assignment on every privileged field; IDOR by swapping identifiers; admin
  self-demotion blocked.
* **A02** — Argon2id prefix, hashing that never contains the password, salted
  hashes.
* **A03** — 8 SQL-injection payloads across login, registration and query
  parameters, plus a check that `users` still exists afterwards.
* **A05** — every security header; `default-src 'none'`; hostile `X-Request-ID`
  not reflected; wildcard CORS refused by configuration validation.
* **A07** — unknown address and wrong password indistinguishable; suspended
  account loses access immediately; token in a query string refused.
* **A09** — audit rows cannot be updated or deleted (the trigger); a failed login
  leaves a durable row despite the rollback; health endpoints leak nothing.

These are the tests that must keep passing. A failure there is an incident.

---

## What the tests found

The suite earned its keep during phases 1-2. Real defects it caught, each fixed:

| Defect | Severity |
| --- | --- |
| Nothing committed a request transaction — registrations were never persisted | **Critical** |
| Audit rows for failed logins were rolled back with the request, defeating the audit trail | **High** |
| `UserService.list_users` called `_require_admin()` with no actor, so it always denied | **High** |
| Request context read the global settings, not the app's, so a production-mode app could return a traceback | **High** |
| An invalid `X-Forwarded-For` reached the `INET` column and would 500 on any spoofed header | **Medium** |
| Secrets nested inside lists were not redacted in audit metadata | **Medium** |
| `JsonFormatter` redacted values but not key names, so `extra={"refresh_token": …}` leaked | **Medium** |
| A second password-reset request in one transaction did not invalidate the first token | **Medium** |
| `use_enum_values=True` stripped `.value` before the service layer could use it | **Medium** |
| Guard DDL was not idempotent, so a retried migration failed on `DuplicateObject` | **Medium** |
| `ContextVar` writes inside a threadpool-run dependency never reached the route | **Medium** |
| Router-level 404/405 returned FastAPI's `{"detail": …}` instead of the standard envelope | **Low** |
| Suspending an account recorded `ADMIN_ACTION` instead of `ACCOUNT_DISABLED` | **Low** |
| `+` in an email local part was rejected | **Low** |
| `lock_requirements.py` skipped `-r base.in`, producing a lock with no app dependencies | **Build** |

---

## Running

```bash
pytest                                        # everything
pytest -m "not slow"                          # skip the DDL-exercising tests
pytest -m security -x                         # security only, stop at first failure
pytest --cov=app --cov-report=html            # browsable report
pytest -k "reuse or idor"                     # by name
```

Useful during development:

```bash
pytest -x -q                                  # fail fast
pytest --lf                                   # rerun last failures only
pytest -vv --durations=10                     # find slow tests
```

---

## Adding tests

1. **Security-relevant?** Add it under `tests/security/`, grouped by OWASP
   category, and assert the *invariant* rather than the status code alone.
2. **Touches the database?** Use the `db_session` fixture so the work rolls back.
3. **Ends up in a response?** Assert the negative too — that a forbidden field is
   absent. A test that only checks the happy path misses the interesting bug.
4. **Document a control that relies on the database?** Assert the constraint
   directly, so the guarantee survives a refactor of the service layer.