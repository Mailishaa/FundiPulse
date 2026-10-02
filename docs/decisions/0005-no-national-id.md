# ADR 0005 — Do not collect a national ID number

**Status:** Accepted · **Date:** 2026-10-02

## Context

Kenyan construction recruitment frequently involves national ID numbers.
Identity documents are highly sensitive personal data, are frequently
photocopied and forwarded insecurely, and carry a material breach cost. The
question is whether the V1 platform needs to collect one.

## Decision

**The schema has no column for a national ID number, and no field requests one.**
Verification is achieved through third-party attestation: a foreman, supervisor
or client confirms that they worked with the person.

## Rationale

1. **No V1 requirement needs it.** The worker flows are: create a passport,
   document experience, attach evidence, request verification, apply for jobs.
   None of these requires a government identifier.
2. **Data minimisation is the strongest control.** Protecting a field with
   encryption, access control and redaction is strictly more work and strictly
   more risk than never collecting it.
3. **Verification does not depend on it.** The product's verification model is
   third-party attestation by a named person with a stated relationship — not
   identity-document matching. Collecting an ID would not improve it.
4. **Breach cost is disproportionate.** An ID number is a permanent identifier
   that cannot be rotated, unlike a phone number or an email address.

## Consequences

**Accepted costs**

* Cannot implement government-ID-based identity proofing in V1.
* Some legitimate employers may ask for it during the off-platform conversation
  that follows a match. The API cannot prevent that, and the product should not
  pretend otherwise.

**Accepted benefits**

* A database disclosure does not yield a set of usable national identities.
* One fewer high-value field in breach assessments and in
  `docs/privacy.md` data inventories.
* Avoids a category of Kenyan legal analysis (DPA 2019 and OPSC guidance on
  sensitive personal data) that is genuinely non-trivial.

## If it is ever needed

This decision can be reversed, but it should be treated as a **schema change plus
a legal review**, not a field addition. Any such proposal must document:

1. the specific product requirement that cannot be met without it,
2. the lawful basis and any registration with the Office of the Data Protection
   Commissioner,
3. encryption at rest, a separate access-control policy, and audit logging of
   every read,
4. retention limits and verified deletion on account closure,
5. that the field is excluded from every employer-facing schema by default.

Until that document exists, the field does not exist.