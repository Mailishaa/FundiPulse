# Conventions — read before writing code

House rules for FundiPulse. Existing code is the reference; follow it rather than
inventing a second style. **Concise code: one-line docstrings, no multi-paragraph
essays in code.** Depth belongs in `docs/`.

## Stack

Sync SQLAlchemy 2.0 (ADR 0003). Python 3.12. Use `.venv/bin/python`, `.venv/bin/ruff`,
`.venv/bin/mypy`. Never `pip3` (it is Python 3.9).

## Layers

```
app/schemas/<domain>.py      Pydantic request/response contracts
app/services/<domain>_service.py   business logic, the only place rules live
app/api/routes/<domain>.py   HTTP surface: parse, delegate, serialise
app/api/serializers.py       model -> schema (already exists; extend if needed)
```

A route must not contain business rules and a service must not know about HTTP.

## Database

- UUIDv4 primary keys, `UUIDPrimaryKeyMixin` + `TimestampMixin`.
- Enums are `VARCHAR` + a derived CHECK, never a native PG enum:
  `enum_column_type(SomeStrEnum, name="some_status")` (ADR 0002). Add the member to
  `app/core/constants.py`; the CHECK is generated automatically.
- Soft delete only where retention has an audit or legal rationale.
- **Never** `Base.metadata.create_all()`. Schema changes go through Alembic only.
- Migrations are hand-written when autogenerate cannot express the change (it cannot
  diff CHECK expressions). Name constraints explicitly, mind the
  `ck_%(table_name)s_%(constraint_name)s` convention which may double-apply.
- Use `selectinload` for collections; avoid N+1.
- Soft-deleted rows must be filtered with `deleted_at.is_(None)`.

## Schemas

- Inherit `RequestSchema` / `ResponseSchema` from `app/schemas/common.py`.
  `RequestSchema` sets `extra="forbid"`, which is the mass-assignment guard — do not
  disable it.
- **No `user_id` in a request schema.** A resource belongs to the authenticated
  caller. Accepting it would be an IDOR.
- Response models: `ResponseEnvelope[T]` for one resource,
  `PaginatedResponseEnvelope[T]` for a page, `Meta(request_id=...)`.
- Use the existing enums from `app.core.constants` rather than new string literals.

## Authorisation — the rules that matter

- `CurrentUser`, `DbSession`, `OptionalUser`, `RequireAdmin` from
  `app/api/dependencies.py`. `require_roles(*roles)` is deny-by-default.
- **Ownership is decided against a loaded row**, not against a client-supplied id, so
  substituting another user's id simply matches nothing.
- Scope sub-resource queries by parent: `where(Child.parent_id == profile.id,
  Child.id == child_id)`. If it does not match, nothing is left to authorise.
- Return **404, not 403**, where 403 would confirm the resource exists.
- Never trust a role, ownership flag or status from a request body.
- Cross-tenant: `Organization A` must never read or mutate `Organization B`'s rows.
  Scope every query by the caller's membership and role.

## Privacy tiers

Worker data has three tiers, and the middle one is a *structural* control:

- `WorkerProfilePrivateResponse` — owner only, includes contact details.
- `WorkerProfilePublicResponse` — anyone, subject to visibility. **Has no phone,
  contact-email or contact-name field at all.** That is the guarantee: no service bug
  can leak one because the type cannot represent one.
- `WorkerProfileSummaryResponse` — search rows, factual counts, no score.

Do not add contact fields to a public or summary schema. Do not build ratings, star
scores or trust scores (ADR 0010) — ever.

## Audit

`AuditService(session).record(action=AuditAction.X, actor_user_id=..., actor_role=...,
resource_type=..., resource_id=..., outcome="SUCCESS", metadata={...})`.

- `record()` commits with the effect.
- `record_durable()` commits on the caller's session so a **failure** event survives
  the rollback of the effect. Use it for refusals and errors, not for successes.
- Adding an `AuditAction` member needs a migration (`audit_logs.action` is CHECK-constrained).
- Never log passwords, tokens, private documents or contact details.

## Errors

Raise from `app/core.exceptions` (`NotFoundError`, `ForbiddenError`, `ConflictError`,
`ValidationError`, `InvalidStateTransitionError`, `CatalogueEntryNotFoundError`).
`app/api/errors.py` maps them to the envelope; the driver message is never returned.

## Conventions worth keeping

- Dates: `app/utils/dates.py` `utc_today()`, never `date.today()` (ruff `DTZ`).
  Never accept a future start/end date.
- Kenyan phone: 10 digits from `0`, `+254` rewritten to `0`, spaces/hyphens stripped.
- File uploads: `inspect_upload` (byte-level sniffing, not the declared MIME) and
  `get_storage()`. Generated object keys only, private by default. Path traversal is
  rejected before any socket opens. **Uploading a certificate does not verify it.**
- Verification is a third-party attestation of a **specific claim**. It is not a trust
  score, a certification, or a guarantee, and it must not rewrite the worker's claim
  into an absolute fact.

## Tests

`tests/api/test_<domain>.py` for HTTP, `tests/services/` for branches the HTTP suite
cannot reach.

Conftest gives you: `client`, `db_session`, `make_user`, `make_admin`, `make_user(...)`
with `role=`, and `auth_headers`. Password for fixtures: `Correct-Horse-9-Battery`.

- `db_session` joins a connection-level transaction in `create_savepoint` mode, so
  **every** write including a `commit()` is undone at teardown. Do not add your own
  truncate or commit.
- The suite refuses to run against a database whose URL does not look like a test
  database. If you need env vars for an Alembic command, pass them inline.
- Assert on the *security* property, not just the status code: `"0712345678" not in
  response.text` beats `response.status_code == 200`.

## Gate — all four must pass before you report done

```
.venv/bin/ruff check <files> && .venv/bin/ruff format <files>
.venv/bin/mypy app          # strict; must be clean
.venv/bin/python -m bandit -r app -c pyproject.toml
.venv/bin/python -m pytest tests/ -q
```

Coverage gate is 90% and genuinely fails below it. Do not add `pragma: no cover`
and do not weaken the gate. Write real tests for the branches you add.

## Ownership

You own **only** the files listed in your task. Other agents are editing the rest of
the tree concurrently. If you need a change in a file you do not own, describe it in
your final report instead of making it. Never edit `app/api/router.py`.
