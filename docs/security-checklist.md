# Security review checklist

Every line must be **actually done and verified** before a production deploy.
Status reflects this repository at the end of Phase 2.

Legend: `[x]` done · `[~]` partial · `[ ]` not done

---

## Authentication

- [x] Argon2id password hashing with parameters from configuration
- [x] `passlib` deliberately not used (unmaintained, lagging Argon2 backend)
- [x] Transparent hash upgrade via `needs_rehash` on successful login
- [x] Minimum password length enforced at the schema boundary
- [x] Long-passphrase-friendly policy (length-dominant, not symbol classes)
- [x] Login failure is uniform for unknown address and wrong password
- [x] Login latency equalised with a dummy hash (no enumeration by timing)
- [x] Account lockout after repeated failures; cleared on success
- [x] Account state re-checked per request (JWT cannot outlive suspension)
- [x] Email verification workflow with single-use hashed tokens
- [x] Password reset workflow with single-use hashed tokens
- [x] Password change revokes every session, including the caller's
- [x] Password reset revokes every session
- [x] Refresh tokens rotated on every use
- [x] Refresh-token reuse revokes the whole family and audits it
- [x] Absolute refresh-family lifetime ceiling
- [x] Logout revokes the current session; `all_sessions` revokes everything
- [x] Admin self-registration refused at the schema boundary
- [~] Rate limiting on login — **Phase 6**
- [x] MFA — deliberately deferred; not claimed

## Tokens

- [x] `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti` all set and validated
- [x] Algorithm pinned from configuration (`alg: none` and confusion refused)
- [x] Required-claim enforcement (an incomplete token is rejected)
- [x] Token purpose (`typ`) checked
- [x] Short access-token lifetime (15 minutes default)
- [x] Opaque tokens for refresh/reset/verification; only hashes stored
- [x] Domain-separated token hashing
- [x] Tokens never placed in a URL
- [x] Tokens never logged (key-name redaction)
- [x] Reset and verification tokens cannot be exchanged

## Authorisation

- [x] Identity resolved from the database, never from request data
- [x] Deny-by-default role gates; empty allowlist denies everyone
- [x] Two independent checks per admin endpoint (route + service)
- [x] `extra="forbid"` on every request schema (mass assignment refused)
- [x] Role changes audited with previous and new value
- [x] Account status changes require a reason, stored in the audit trail
- [x] Admin cannot change their own role or status
- [x] Organisation membership checks — **Phase 5**
- [x] Resource ownership checks for passports/jobs/applications — **Phases 3-5**
- [x] Employer cannot read a private worker profile — **Phase 3**

## Input validation

- [x] Pydantic validation on every body, query and path parameter
- [x] Pagination bounded (`page_size` capped, `page` capped)
- [x] Sort keys allowlisted, unknown values rejected
- [x] No generic filter expression that could reach a WHERE clause
- [x] Email validated and normalised (lower-cased) at every entry point
- [x] Request body size limited before the body is read
- [x] Enum values constrained in the database, not only in Python

## Injection

- [x] SQL via the ORM only; no string interpolation of user input
- [x] 8 SQL-injection payloads tested against login, registration and filters
- [x] `users` table verified intact after injection attempts
- [x] `statement_timeout` / `lock_timeout` / idle timeout per connection
- [x] Path traversal structurally impossible (server-generated object keys)
- [x] Header injection blocked (request id allowlist, not reflected)
- [x] Log injection prevented (route templates, redacted values)
- [x] No unsafe deserialisation

## File security

- [x] `files` holds metadata only; no bytes in PostgreSQL
- [x] Server-generated object keys
- [x] `is_quarantined` defaults to true
- [x] Single `is_downloadable` property centralises the check
- [x] Size ceiling enforced in the schema (`CHECK`)
- [x] Sanitised display filename, never used for a path or header
- [~] MIME sniffing and magic-number validation — **Phase 6**
- [~] Signed URL issuance after authorisation — **Phase 6**
- [~] Malware scanning integration point — interface exists, scanner Phase 6
- [x] No file served from the application filesystem
- [x] No user-controlled storage path

## Crypto

- [x] Argon2id
- [x] SHA-256 for high-entropy token hashes (correct: no brute-force surface)
- [x] Constant-time comparison available for secret equality
- [x] Encryption-at-rest decision documented — [ADR 0012](decisions/0012-sensitive-data-at-rest.md)
- [~] Object storage encryption — provider-side, Phase 6

## Secrets management

- [x] No secret in source control
- [x] `.env.example` with placeholders only, committed deliberately
- [x] `.env` git-ignored
- [x] Production refuses placeholder secrets, and refuses shared secrets
- [x] Production refuses placeholder database credentials
- [x] `detect-secrets` baseline committed and reviewed
- [x] `scripts/scan_secrets.py` in CI
- [x] CI asserts no `.env` anywhere in git history
- [x] Secrets are `SecretStr`, so they cannot leak via accidental `str()`
- [x] CI/CD secret management (Render/GitHub environment secrets) — **Phase 8**

## CORS

- [x] Exact origin allowlist from configuration
- [x] Wildcard rejected by configuration validation
- [x] Credentialed CORS off by default
- [x] Default is *no origins at all*
- [x] Custom headers allowlisted
- [x] `X-Request-ID` and `Retry-After` exposed

## Security headers

- [x] `X-Content-Type-Options: nosniff`
- [x] `X-Frame-Options: DENY`
- [x] `Referrer-Policy: no-referrer`
- [x] `Cross-Origin-Opener-Policy: same-origin`
- [x] `Cross-Origin-Resource-Policy: same-origin`
- [x] `Permissions-Policy` denying ambient device APIs
- [x] `Content-Security-Policy: default-src 'none'` on API responses
- [x] Separate, narrower CSP for the docs pages
- [x] HSTS in production only (not on localhost)
- [x] Headers present on 404s and errors too

## Error handling

- [x] Single error envelope for every failure, including router-level 404/405
- [x] Stable machine-readable `code` alongside `message`
- [x] `request_id` in every error body
- [x] No stack trace in production (tested with production settings)
- [x] Database errors never echoed to the client
- [x] Constraint violations translated to `409`, not `500`
- [x] Database unavailability translated to `503` so retries are safe
- [x] No internal identifiers in health responses

## Logging and monitoring

- [x] Structured JSON logs
- [x] Request correlation id on every request and response
- [x] Redaction by key name, applied before serialisation
- [x] Separator- and case-insensitive secret matching
- [x] No passwords, tokens or secrets logged
- [x] SQL statement logging suppressed
- [x] Access log uses route templates, not raw paths
- [x] Audit trail for security events
- [x] Audit trail survives rollback for failed actions
- [x] `audit_logs` append-only, enforced by a database trigger
- [x] Audit action vocabulary constrained in the database
- [ ] **Alerting rules** for auth-failure spikes, rate-limit spikes, 5xx — before production
- [ ] **Log shipping / retention policy** — before production
- [ ] **Dashboard** for verification and admin actions

## Verification

- [x] Request → verifier response → record
- [x] Worker cannot mark their own claim verified
- [x] Row-level `CHECK` makes self-verification impossible
- [x] At most one pending request per claim (partial unique index)
- [x] Records transition; revocation keeps history
- [x] Verification exposes factual fields only, never a "certified" flag
- [x] Credentials kept separate from verification

## Data privacy

- [x] No national ID collected — [ADR 0005](decisions/0005-no-national-id.md)
- [x] Worker visibility defaults to `PRIVATE`
- [x] Contact details exist only in owner-only schemas
- [x] `contact_preference` is a routing hint, never an address
- [x] No star ratings or trust scores — [ADR 0010](decisions/0010-no-ratings-or-completion-score.md)
- [x] Deactivation and anonymisation rather than blind deletion
- [x] Audit metadata redacted before persistence
- [x] Data inventory and retention documented — `docs/privacy.md`
- [ ] Legal review of Kenya DPA 2019 applicability — **before production**

## Audit trail

- [x] Actor, action, resource, timestamp, IP, user agent, request id, metadata
- [x] Actor role snapshotted at event time
- [x] Login success/failure/blocked/logout/refresh/reuse
- [x] Password change/reset, email verification, account lifecycle
- [x] Role change, membership changes, admin actions
- [x] File upload/access/denial events (constants defined)
- [x] Verification lifecycle events
- [x] Append-only enforced in the database
- [x] No update or delete path on the service
- [x] Batch size capped

## Production configuration

- [x] Refuses to boot on unsafe configuration
- [x] `DEBUG=false` required
- [x] Distinct, long, non-placeholder secrets required
- [x] Documentation off by default
- [x] Rate limiting cannot be disabled
- [x] Database echo off
- [x] HSTS enabled
- [x] PostgreSQL required; SQLite rejected everywhere
- [x] Migrations run as a pre-deploy command, not at start-up

## Dependency and supply chain

- [x] Pinned dependency locks generated from the installed closure
- [x] PEP 508 marker evaluation in the lock script
- [x] Lock verified to install and import standalone
- [x] `pip-audit --local --strict` — no known vulnerabilities
- [x] Bandit clean
- [x] Secret scanning in CI
- [ ] `dependabot.yml` / automated update PRs — **Phase 8**

## Remaining before production

These are the gaps that matter. None is a surprise; all are tracked.

1. **Rate limiting** (Phase 6) — login, register, reset, uploads, search.
2. **Email delivery** — a real provider; the null channel currently fails loudly.
3. **File upload endpoint** and signed URLs (Phase 6).
4. **Monitoring and alerting** on security events.
5. **CI/CD hardening and Render deployment** (Phase 8).
6. **Legal review** of data protection and any labour/verification regulation.
7. **Independent penetration test** before handling real worker data.
8. **TLS verification at the edge** — the app trusts Render's private database link
   and assumes TLS terminates upstream.