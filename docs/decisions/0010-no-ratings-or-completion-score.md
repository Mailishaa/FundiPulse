# ADR 0010 — No star ratings or overall completion score

**Status:** Accepted · **Date:** 2026-10-02

## Context

Most marketplaces display a star rating, a "trust score" or a "profile
completeness" percentage. All three are common because they are cheap to compute
and easy to render as a badge.

## Decision

FundiPulse exposes **factual signals only**. Specifically, the API does not
provide:

* a star rating for workers or employers,
* a reputation or trust score,
* an overall "passport completion" percentage,
* an overall profile quality indicator.

What it provides instead:

| Signal | Why it is honest |
| --- | --- |
| Count of documented projects | A fact about the record. |
| Count of **verified** projects | A fact about what third parties confirmed. |
| Trades and skills with self-declared proficiency | Labelled as self-declared, never verified implicitly. |
| Credentials with issuer, issue date, expiry | A claim with full provenance; never asserted genuine. |
| Availability status and available-from date | A current, explicit statement from the worker. |
| Dated experience records | Claims with a time span. |
| Verification records with verifier and date | An attributed attestation. |

## Rationale

1. **Ratings are unauditable.** A 4.7 average cannot be explained to a worker who
   disputes it, cannot be traced to a source, and decays into popularity rather
   than quality.
2. **Scores create perverse incentives.** A single number rewards optimising the
   number. In an informal-sector construction market, that incentive pushes
   towards inflating claimed experience — precisely the behaviour the verification
   system exists to counteract.
3. **A completion percentage implies quality.** "Passport 85% complete" reads as
   "85% employable", which the platform cannot know. A worker with three
   thoroughly documented projects is more employable than one with a long
   half-filled form.
4. **Employers need to act on the information.** "Verified by a foreman at ABC
   Builders on 12 March" is actionable. "4.7 stars" is not.

## Consequences

**Accepted costs**

* More work for the future PWA to render usefully: no single badge, more
  structured detail to present well.
* Loses a cheap ranking signal for search. Mitigated by deterministic,
  explainable matching (trade, skills, county, experience, availability) whose
  factors are returned to the client so a result can be justified.
* No reputation feedback loop between employers and workers in V1. This is a
  deliberate gap, not an oversight.

**Accepted benefits**

* Every number the platform shows can be traced to a record and, where relevant,
  to a named person who confirmed it.
* No metric can be gamed independently of the underlying facts.
* The API cannot mislead, because it has no opinionated scalar to mislead with.

## If ratings are ever added

They would be a separate, additive feature requiring their own ADR, and would
have to address: who can rate, whether a rating is tied to a real engagement,
how brigading is prevented, whether ratings are visible to the rated party, and
whether they are ever used in ranking. A rating must never be presented as a
verification.