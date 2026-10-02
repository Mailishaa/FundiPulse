# ADR 0008 — File bytes live in object storage, never in PostgreSQL

**Status:** Accepted · **Date:** 2026-10-02

## Context

Workers upload photographs of completed work, scanned certificates and project
documents. These need to be stored, authorised per-request, and eventually
scanned for malware.

## Decision

`files` stores **metadata only**. The bytes go to private object storage (S3 or
S3-compatible), reached only through short-lived, single-purpose signed URLs that
the API issues **after** an authorisation check.

## Rules

| Rule | Reason |
| --- | --- |
| `object_key` is server-generated from a UUID plus an extension derived from the **validated** content type | A user-supplied filename never influences a storage path, which removes path traversal as a whole class of bug. |
| `original_filename` is sanitised and display-only | Never used to build a path, and never echoed verbatim into `Content-Disposition`. |
| `content_type` is agreed by server-side sniffing | The `Content-Type` header is a client claim. |
| Magic-number signature is checked, not just the extension | `evil.pdf` with an image extension, or a file whose real type is HTML, must be rejected. |
| Private bucket, no public ACL, no direct serving | The application is the only authorisation path. |
| `is_quarantined` defaults to `true`; only a `CLEAN` scan is downloadable | Enabling malware scanning later cannot retroactively expose previously unscanned content. |
| Hard size ceiling in the schema | `CHECK (size_bytes > 0 AND size_bytes <= 26214400)`, so an oversized object cannot be recorded even if application validation is bypassed. |
| Authorisation on every access | Owner, an assigned verifier, or an employer for evidence the worker explicitly exposed — evaluated per request. |

## Alternatives considered

| Option | Why rejected |
| --- | --- |
| Store bytes in PostgreSQL | Bloats backups and WAL, makes the database a high-value target for a payload it has no business holding, and complicates range requests. Large files degrade everything around them. |
| Store bytes on the application filesystem | Reintroduces the path-traversal class of bug, does not scale horizontally, and makes backups and disaster recovery the operator's problem. |
| Public bucket with unguessable keys | "Unguessable" is not authorisation. The key leaks through logs, referrers, screenshots and support conversations. |

## Consequences

**Accepted costs**

* Two systems to operate: the database and object storage.
* Signed URL issuance needs a storage client with credentials, so
  `core/storage.py` defines a `Storage` protocol with an in-memory implementation
  for development and tests.
* Large uploads should eventually use pre-signed multipart POST so bytes bypass
  the API entirely. The schema supports it; the endpoint arrives in Phase 6.

**Accepted benefits**

* Path traversal is structurally impossible, not merely filtered.
* The database never holds an executable or attacker-controlled payload.
* Horizontal scaling works, and backup/restore concerns are separated by concern.

## Explicitly not done

There is **no** `POST /fetch-url` endpoint, and no code path that writes to a
location derived from user input. When job ingestion is built, it must use an
allowlist of registered sources, block private IP ranges and metadata endpoints,
restrict protocols, apply timeouts and size limits, and validate redirects.