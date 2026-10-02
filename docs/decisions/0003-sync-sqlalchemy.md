# ADR 0003 — Synchronous SQLAlchemy sessions

**Status:** Accepted · **Date:** 2026-10-02

## Context

FastAPI supports both synchronous and asynchronous handlers. The domain needs
explicit transaction control: read-then-write patterns guarded by unique indexes
for application submission, verification requests, and job status transitions.

## Decision

Use synchronous SQLAlchemy 2.0 sessions. FastAPI dispatches `def` (non-`async
def`) path operations to a threadpool, so blocking database I/O does not stall
the event loop. One session per request, one transaction per service method.

## Alternatives considered

| Option | Why rejected |
| --- | --- |
| Async SQLAlchemy (`AsyncSession`) | Cleaner concurrency for high I/O-bound fan-out, but the transaction semantics the domain needs become noticeably harder to reason about, and the same application cannot then share code with synchronous scripts (seeding, maintenance jobs, smoke tests). |
| Both sync and async, chosen per route | Two code paths for every service, and services are where the transaction boundaries live. Guarantees they diverge. |
| An ORM-free query layer | Loses the declarative schema, the type mapping and the migration tooling that this project's correctness depends on. |

## Consequences

**Accepted costs**

* Throughput is bounded by threadpool size and database connection count, not by
  the event loop. Fine for a single Render instance; it would need revisiting
  well before thousands of concurrent workers.
* Long-running scripts must not be run inside the request threadpool.

**Accepted benefits**

* One transaction model, used identically by HTTP handlers, CLI scripts, seed
  tooling and smoke tests.
* Connection pooling is straightforward to reason about and to observe.
* Operations are easier to debug: the same `get_db` pattern everywhere.

## Consequences for deployment

This is a **single-process-per-service** design. It pairs with one Render web
service and a managed PostgreSQL on Render's private network. If horizontal
scaling is ever needed, the rate limiter moves to the Redis backend (already
supported by configuration) and the session model is revisited under its own ADR
— it is not a decision to revisit opportunistically.