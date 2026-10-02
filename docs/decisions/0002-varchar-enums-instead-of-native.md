# ADR 0002 — `VARCHAR` + `CHECK` instead of native PostgreSQL enums

**Status:** Accepted · **Date:** 2026-10-02

## Context

Almost every domain table stores a controlled vocabulary: user role, job status,
application status, verification status, availability, evidence visibility.
Job and verification statuses will definitely gain values as the product grows,
and that has to be a routine, reversible migration.

## Decision

Model enums as `VARCHAR(64)` with an explicit `CHECK` constraint listing the
permitted values. Python `StrEnum` classes are the single source of truth, and
`app.db.base.install_enum_checks` derives the SQL constraint from the column type
so a new enum column cannot be created unconstrained.

## Alternatives considered

| Option | Why rejected |
| --- | --- |
| Native PostgreSQL `ENUM` | Adding a value needs `ALTER TYPE ... ADD VALUE`, which cannot run inside a transaction block on older PostgreSQL versions and cannot run at all in one. Removing a value is impossible. Neither is reversible. |
| `CHECK` on a lookup table with FK | More joins on hot paths, and a `DELETE` on a lookup row would break history. Our own catalogue tables use soft deactivation for that reason; applying the same pattern to every status would be heavy. |
| Free text, validated only in the application | One bug in one code path writes `OPENNING` to the database and the damage is permanent. |

## Consequences

**Accepted costs**

* No storage-level enum typing. A typo is caught by the `CHECK`, not by the type
  system — which is the same failure mode as the application check, but at the
  point of insertion, inside the transaction.
* Slightly wider storage than a 1-byte native enum.

**Accepted benefits**

* Adding or removing a status is an ordinary Alembic migration, fully reversible.
* Constraints are named per **column**, so two columns of the same enum in one
  table cannot collide. (This was a real bug during development: PostgreSQL
  rejected two identically named `CHECK` constraints on `verifications`.)
* The OpenAPI schema, the Python enum and the database constraint are generated
  from the same definition, so they cannot disagree.

## Note on why constraints are generated

Repeating `enum_check(...)` in twenty `__table_args__` tuples is one omission away
from an unconstrained status column. Deriving the constraint from the column type
removes that possibility: adding an enum-typed column adds its `CHECK`
automatically.