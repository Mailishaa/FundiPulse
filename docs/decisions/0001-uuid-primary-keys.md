# ADR 0001 — UUIDv4 primary keys

**Status:** Accepted · **Date:** 2026-10-02

## Context

Every table needs a primary key that is safe to expose in a URL. The brief
requires non-sequential public identifiers and forbids exposing database primary
keys unnecessarily.

## Decision

Use UUIDv4 as the primary key type for every table, generated application-side
via `app.db.base.new_uuid` with `gen_random_uuid()` as the server default.

## Alternatives considered

| Option | Why rejected |
| --- | --- |
| `BIGSERIAL` integer | Sequential. `GET /workers/1`, `/workers/2` is a trivially enumerable directory of every worker on the platform, and reveals business volume. |
| UUIDv7 / UUIDv1 | Both embed a timestamp (v7 explicitly, v1 through the version/variant bits plus the node identifier). v1 additionally leaks the host MAC address. |
| Public integer + internal UUID | Two identifiers per table doubles the surface area and creates a mapping to get wrong. Authorization would have to use whichever the client sees. |

## Consequences

**Accepted costs**

* 16 bytes per key instead of 4/8, and index entries are larger — irrelevant at
  this scale.
* Poor locality for range scans. Mitigated by the composite indexes that matter
  (`ix_jobs_status_published`, `ix_worker_profiles_visibility`).
* Slightly larger JSON payloads. Acceptable against the mobile-first constraint,
  and short stable IDs matter more than a few hundred bytes.

**Accepted benefits**

* Identifiers cannot be walked, so a leaked URL does not enumerate the platform.
* IDs can be generated client- or server-side without a round trip, which suits
  future offline-tolerant mobile flows.
* No coordination between services issuing IDs.

**Important caveat.** Unpredictable IDs are *defence in depth*, not
authorisation. Every endpoint still performs an ownership check, because an
attacker who obtains a valid UUID by any means — a shared link, a screenshot, a
support agent — must still be refused. Tests assert that swapping one worker's
ID for another's returns `403`/`404`, not data.