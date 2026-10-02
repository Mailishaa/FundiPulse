# ADR 0009 — Database constraints, not check-then-insert, for concurrency rules

**Status:** Accepted · **Date:** 2026-10-02

## Context

Several business rules must hold even when two identical requests arrive
simultaneously — which is realistic on a mobile-first platform with intermittent
connectivity and client retries:

* a worker may have at most one application per job,
* at most one verification request may be pending per claim,
* an aggregated listing must not be stored twice,
* a passport may have only one primary trade,
* a user may report a subject once.

## Decision

Every such rule is a **database constraint**. The service layer still performs a
friendly pre-check so it can return a clean `409 CONFLICT` instead of a driver
exception, but the constraint is what guarantees correctness.

| Rule | Mechanism |
| --- | --- |
| One application per worker per job | `UNIQUE (job_id, worker_profile_id)` |
| Safe retry of an application | `UNIQUE (worker_profile_id, idempotency_key) WHERE idempotency_key IS NOT NULL` |
| One pending verification per claim | `UNIQUE (target_type, target_id) WHERE status = 'PENDING'` |
| One primary trade | `UNIQUE (worker_profile_id) WHERE is_primary` |
| No duplicate aggregated listing | `UNIQUE (source_id, source_job_id) WHERE source_job_id IS NOT NULL AND deleted_at IS NULL` |
| One report per reporter per subject | `UNIQUE (reporter_user_id, subject_type, subject_id)` |
| One membership per user per organization | `UNIQUE (organization_id, user_id)` |
| Unique registration | `UNIQUE (email)` on the lower-cased value |

Integrity errors are caught and translated into the standard `409 CONFLICT`
response envelope. The driver error is never surfaced to the client.

## The anti-pattern this replaces

```python
# WRONG - two concurrent requests both pass the check
existing = repo.find_one_by(job_id=job_id, worker=worker)
if existing is None:
    return repo.create(...)   # both succeed
```

## Alternatives considered

| Option | Why rejected |
| --- | --- |
| `SELECT ... FOR UPDATE` on the parent row | Correct but serialises unrelated work and needs the right row to lock, which varies per rule. The unique index is simpler and always applies. |
| Application-level advisory locks | Requires a session-scoped lock discipline that is easy to leak, and is invisible in the schema. |
| Optimistic concurrency with a version column | Useful for lost-update prevention (see `VersionMixin` on `jobs`), but it does not express "this row must not exist twice". |

## Consequences

**Accepted costs**

* The pre-check plus constraint is slightly more code than either alone.
* Constraint violations must be translated carefully, or a legitimate race turns
  into a `500`.
* Partial unique indexes are PostgreSQL-specific. That is acceptable: the project
  already requires PostgreSQL for CHECK constraints, `INET` and triggers, and
  `Settings` rejects SQLite outright.

**Accepted benefits**

* The invariant holds regardless of which code path writes the row.
* The rule is visible in the schema, so a reviewer sees it without reading a
  service.
* Tests can assert the constraint directly against the database.

**Note on `VersionMixin`**

`jobs` additionally carries a `version` column for optimistic concurrency, which
addresses a *different* problem: two users editing the same job concurrently and
silently losing one edit. The two mechanisms are complementary and both are used.