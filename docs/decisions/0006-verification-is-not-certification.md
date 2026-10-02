# ADR 0006 — Verification records facts, never guarantees

**Status:** Accepted · **Date:** 2026-10-02

## Context

Verification is the feature employers will trust most, and therefore the feature
most likely to be misrepresented. The failure modes are familiar from
gig-economy platforms: a "verified worker" badge that is really just "uploaded a
photo", a star rating that cannot be audited, and a "certified" label implying a
regulatory standard nobody checked.

## Decision

Verification is modelled as **a recorded third-party attestation about a specific
claim, by a specific person, on a specific date.**

The API returns only factual fields:

```
verification_type   what was checked (PROJECT | EXPERIENCE | SKILL | CREDENTIAL | REFERENCE)
verification_status VERIFIED | REJECTED | REVOKED
verified_by         the named person or organization
verified_at         timestamp
verifier_relationship  how they know the worker (e.g. "Foreman, ABC Builders")
evidence_summary    what they relied on
```

The API never returns a `trusted`, `certified`, `guaranteed`, `background_checked`
or equivalent field, and no endpoint computes an overall legitimacy score.

## Enforced invariants

1. **A worker cannot verify themselves.** `verifications` carries
   `CHECK (verified_by_user_id IS NULL OR verified_by_user_id <> requested_by_user_id)`.
   The worker is also forbidden from responding to their own request in the service
   layer, and the refusal is audited.
2. **A credential is not a verification.** Uploading a certificate records a
   claim. Genuineness is established only through the verification workflow.
3. **Records transition, they are not deleted.** A completed verification is
   revoked by setting `REVOKED` with `revoked_at`, `revoked_by_user_id` and a
   reason. What was once asserted stays inspectable.
4. **One in-flight request per claim.**
   `UNIQUE (target_type, target_id) WHERE status = 'PENDING'`.
5. **Presentation is separable from fact.** `is_visible_to_employers` lets a
   worker hide a verification from employers without altering what the record
   says.

## Alternatives considered

| Option | Why rejected |
| --- | --- |
| A single `is_verified` boolean on the worker | Conflates many independent claims into one flag, gives the worker or a buggy code path a way to assert it wholesale, and tells an employer nothing actionable. |
| An overall `trust_score` | Not reproducible, not auditable, and creates a perverse incentive to game the inputs. |
| Trust uploaded document metadata | Any worker can upload a plausible-looking certificate. It is evidence of nothing. |

## Consequences

**Accepted costs**

* Employers must read several factual fields rather than glance at one badge.
  This is the intended outcome: the information is actionable instead of
  decorative.
* UI work for the future PWA is more nuanced than a badge. The API gives it the
  right primitives; the presentation is a frontend concern.
* Verification adds latency — it depends on a third party responding. Mitigated
  by expiry and re-request, not by relaxing the rule.

**Accepted benefits**

* The claim is defensible. Every statement traces to a person, a relationship and
  a date.
* Revocation is possible without destroying history.
* Legal and reputational exposure is bounded: the platform states what it knows,
  and nothing more.

**Not claimed**

A FundiPulse verification is **not** a background check, **not** a professional
certification, and **not** a guarantee that a worker is competent or legitimate.
The onboarding and documentation copy must say so in plain language.