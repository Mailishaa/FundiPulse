# ADR 0012 — Encrypting sensitive data at rest

**Status:** Accepted · **Date:** 2026-10-02

## Context

OWASP A02 (Cryptographic Failures) covers both passwords and other sensitive
data at rest. Passwords are handled with Argon2id (see ADR to be written with
Phase 2). This record addresses the *other* data: private contact details,
document references, and evidence metadata.

## Decision

| Data class | At rest | Rationale |
| --- | --- | --- |
| Passwords | Argon2id, one-way, never decryptable | Standard; slow and memory-hard. |
| Refresh / reset / invitation tokens | SHA-256 hash only | The plaintext is shown once, at issue. A database disclosure yields no usable credential. |
| `users.email`, `phone_number`, `contact_email` | **Plaintext**, protected by access control | See below. |
| Evidence bytes | Private object storage, server-side encryption (AES-256 / SSE) | Standard practice, off the critical path. |
| Signed URLs | Never logged, TTL ≤ 300s | Reduces the value of a leaked URL. |

## Why contact details are not application-encrypted

Application-level encryption of `phone_number` and `contact_email` was
considered and rejected for V1.

**In favour:** a stolen database dump yields no contactable data. This is a real
benefit for a platform operating in a context where bulk identity data is
valuable.

**Against:**

1. **Key management becomes the whole problem.** The application must hold a key.
   If it does, the key sits in the same process as the code that reads the data,
   and the encryption provides marginal protection against exactly the threat it
   targets — a dump of the live system's reachable data.
2. **It is defeated by the legitimate read path.** An employer contacting a
   worker is a *normal* operation. Any key that permits that permits bulk
   decryption by the same credential that permits one lookup.
3. **Deterministic search breaks.** Deterministic encryption permits equality
   lookups; randomised encryption does not. Blinded indexes are a significant
   additional subsystem.
4. **No encryption at rest can substitute for access control.** The real control
   is that no employer-facing schema contains these fields at all, enforced by
   separate Pydantic schemas that have no such attribute.

**The effective control is structural:** these columns exist only on
`worker_profiles` and appear only in the owner-only schema. A query bug in an
employer endpoint cannot leak them because the response schema cannot represent
them. That is a stronger guarantee than ciphertext.

## Consequences

**Accepted costs**

* A database compromise exposes contact details. Accepted with the reasoning
  above, mitigated by encryption-at-rest from the infrastructure provider,
  network isolation on Render, and the fact that this is the *lowest*-sensitivity
  class of data held (no national ID — see ADR 0005).

**Accepted benefits**

* No key to leak, rotate, back up or accidentally log.
* Search, uniqueness and support workflows stay simple and correct.
* The security model rests on authorisation, which is where it belongs.

## Revisit if

* The data set changes — for example, if national ID collection is ever approved
  (ADR 0005), field-level encryption becomes mandatory and gets its own ADR.
* An envelope-encryption service (KMS/HSM) with per-tenant keys becomes
  available. At that point application-level encryption stops being key management
  theatre and becomes worth doing.
* A regulatory determination requires it. **This is the most likely trigger**, and
  it requires legal review rather than engineering preference.