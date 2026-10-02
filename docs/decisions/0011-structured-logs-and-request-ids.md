# ADR 0011 — Structured JSON logging with request correlation

**Status:** Accepted · **Date:** 2026-10-02

## Context

The platform handles authentication, verification and private worker documents.
Investigating a security event requires answering: which request, which user,
which endpoint, what outcome, how long, and which error category. Plain-text
logs and a wall of `print()` do not answer those questions reliably.

## Decision

1. **Newline-delimited JSON logs** to stdout. Render's log collector ingests
   them; local development keeps a human-readable formatter.
2. **Every request carries a correlation ID.** `RequestIdMiddleware` accepts an
   inbound `X-Request-ID` if it is well-formed, otherwise mints a UUID. It is
   placed in a `contextvar` so any log call in the request can reach it, returned
   in the response header, and included in every `meta` block and error body.
3. **A fixed field vocabulary** on every access log:

   `timestamp` `level` `event` `request_id` `method` `path` `route_template`
   `status_code` `duration_ms` `user_id` `user_role` `error_category` `ip`

4. **Security events are additionally written to `audit_logs`**, which is the
   durable, tamper-evident record. Logs are for operations; audit rows are for
   accountability. The two are deliberately not interchangeable.

## Fields that must never be logged

Passwords, password hashes, access tokens, refresh tokens, reset tokens,
invitation tokens, object-storage credentials, signed URLs, and private document
content. This is enforced by an explicit redaction layer, not by convention alone.

Also excluded from logs: a worker's phone number or alternate email. Request
bodies and response bodies are never logged.

## Alternatives considered

| Option | Why rejected |
| --- | --- |
| Plain-text logs | Requires fragile regular expressions to query, and mixing an unescaped user-controlled value into a line invites log injection. |
| A third-party logging framework | Additional dependency and supply-chain surface for a solved problem; `logging` plus a `JSONFormatter` is ~40 lines. |
| Logging everything at DEBUG in production | Leaks sensitive data into log storage, which usually has weaker access control than the database. `DEBUG` is refused in production. |
| Audit rows only, no operational logs | Cannot answer "is the service healthy, is latency up, are we being scanned". The two needs differ. |

## Consequences

**Accepted costs**

* Log output is machine-oriented, so local debugging is slightly less pleasant.
  Mitigated by keeping a readable formatter for non-production.
* JSON logs are larger than plain text. Acceptable; these are not high-volume.
* The contextvar pattern requires care in worker threads. Handlers read the
  contextvar defensively and tolerate it being unset.

**Accepted benefits**

* "Show me every request from this IP in the last hour" is a single indexed
  query against the log store.
* A user can quote a `request_id` from an error response and support can find the
  exact request.
* Structured `error_category` enables alerting on a class of failure (auth
  failure spike, rate-limit spike) rather than on a string match.

## A09 note

Logs alone do not satisfy OWASP A09. They must be *monitored*. Alerting rules
and a retention policy are part of operating this in production and are listed as
open items in `docs/security-checklist.md`; they are not claimed as implemented.