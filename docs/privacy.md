# Privacy and data protection

What FundiPulse collects, why, who can see it, and how long it is kept.

> **No legal or regulatory compliance is claimed.** Kenya's Data Protection Act
> 2019, the OPSC guidance on sensitive personal data, and any sector-specific
> labour or professional-licensing rules require review by a qualified Kenyan
> lawyer before launch. This document is an engineering record, not legal advice.

---

## Principles applied

1. **Data minimisation** — do not collect what the product does not need.
2. **Privacy by default** — nothing is public until the user opts in.
3. **Separation of concerns** — public, authenticated, private and administrative
   data have different schemas, not different field lists inside one schema.
4. **Access control over encryption** — the primary control is who may read a
   field, enforced by the absence of that field from their response type.
5. **Retention, not accumulation** — deactivation and anonymisation, never an
   unexamined hard delete.

---

## What is collected

### Account (all users)

| Field | Why | Notes |
| --- | --- | --- |
| Email address | Login identity, password recovery | Unique, lower-cased, never exposed to other users |
| Password hash | Authentication | Argon2id. Irreversible by design |
| Role | Authorisation | Server-side only |
| Account status | Suspension, deactivation | Server-side only |
| Email verified | Trust signal for abuse-prone actions | |
| Failed login count, lockout | Brute-force protection | |
| Last login, timestamps | Security monitoring | |

**Not collected:** name, national ID, date of birth, photograph, signature.

### Worker profile

| Field | Why | Visibility |
| --- | --- | --- |
| Display name | Identity to employers | Per the profile's visibility setting |
| Headline, bio | Professional summary | Per the profile's visibility setting |
| Trades, skills | Matching and discovery | Per the profile's visibility setting |
| Experience, projects, credentials | Professional history | Per the profile's visibility setting |
| Availability status, available-from | Matching | Per the profile's visibility setting |
| County, location | Matching | Per the profile's visibility setting |
| Preferred counties | Matching | Per the profile's visibility setting |
| **Phone number** | Contact, at the worker's choice | **Owner only** |
| **Alternate contact email** | Contact, at the worker's choice | **Owner only** |
| **Contact name / phone** | A relative, where a worker asks for it | **Owner only** |

The private block exists because a worker must be *reachable*. It is never
serialised into an employer-facing schema — not as "anonymised", not as masked,
not at all. `contact_preference` tells an employer whether contact is permitted and
by what route; it is not an address.

### Organization (employers)

Company name, description, industry, website, business contact details, location,
county, verification flag. Organization members are listed with their role.

### Verification

Who requested it, who was asked to verify, what claim, the response, dates, and any
evidence summary. Verification is a factual third-party attestation.

### Operational

IP address, user agent, request id on requests. Used for security monitoring,
rate limiting and incident response. Stored on refresh sessions and audit rows.

---

## What is deliberately **not** collected

| Not collected | Why |
| --- | --- |
| **National ID number** | Nothing in V1 needs it. Not collecting it is the strongest available control — see [ADR 0005](decisions/0005-no-national-id.md). |
| Date of birth | No V1 requirement. Adds identity-theft surface for no benefit. |
| Biometric data | Proportionate-dispute risk is not justified by this product. |
| Precise GPS location | County-level matching is sufficient. |
| Payment or bank details | Not a payments product; no legal or security reason to hold this. |
| Social media logins | Password reuse across sites is a known credential-stuffing vector. |
| Star ratings | See [ADR 0010](decisions/0010-no-ratings-or-completion-score.md). |

If any of these is ever proposed, it requires an ADR **and** a legal review before
implementation, not after.

---

## Who can see what

| Audience | Can see |
| --- | --- |
| Anonymous | Public-profile workers: display name, headline, trades, skills, documented projects, credentials, availability, county, and the factual verification fields |
| Authenticated worker | Their own account **and** their own private contact block |
| Authenticated employer | Whatever the worker's visibility setting permits. Never private contact details, never documents marked private |
| Assigned verifier | The specific claim under verification, and only the evidence attached to that claim |
| Administrator | Account state; audit trail; moderation queue. Every administrative action is itself audited |

### Visibility levels

```
PRIVATE       default. Nothing is discoverable. Only the owner sees the passport.
DISCOVERABLE  appears in employer search and can be viewed in full.
PUBLIC        full visibility, including for signed-out users.
```

Per-evidence and per-reference visibility can be **narrower** than the passport
default, never broader. A worker can hide a project with client confidentiality
obligations, or a confirmed referee, without changing the passport setting.

### Verification is factual, not an endorsement

The API returns `verified_by`, `verified_at`, `verification_type`,
`verifier_relationship` and `verification_status`. It never returns a "trusted",
"certified" or "guaranteed" flag. A verification means *this person confirmed this
claim on this date* — not that the worker is legitimate or competent.

---

## Retention

| Data | Retained | Basis |
| --- | --- | --- |
| Active account data | Until deactivation | Account creation |
| Deactivated account row | Indefinitely, anonymised after `INACTIVE_ACCOUNT_PURGE_DAYS` (30) | Audit and moderation integrity |
| Anonymised passport | Aggregate statistics only | Legitimate interest |
| Private contact details | Until anonymisation | Purpose limitation |
| Password hashes | Until anonymisation, then retained but unusable | Security integrity |
| Refresh sessions | Until revoked, then revoked rows retained | Session integrity |
| Reset / verification tokens | Until consumed or expired | Purpose limitation |
| Verification records | Indefinitely | Dispute resolution |
| **Audit logs** | **Indefinitely** | Accountability; append-only by design |
| Uploaded evidence | Until the worker deletes it or is anonymised | Purpose limitation |
| IP address, user agent | With the audit row | Security monitoring |

**Exact periods require legal sign-off before production.** The numbers above are
engineering defaults chosen to be defensible, not legally determined.

---

## Deletion

Account closure is **deactivation followed by anonymisation**, not deletion:

1. **Deactivate** — authentication stops, every session and outstanding token is
   revoked, the profile is tombstoned. The row is retained.
2. **Anonymise** (after 30 days) — the private contact block, bio and headline are
   cleared; the display name becomes a stable non-identifying placeholder derived
   from the user id, so historical aggregates stay consistent.

What is **not** deleted: audit logs, verification records, moderation outcomes and
the anonymised account row.

The reasoning: an audit trail that a user can erase by closing their account is not
an audit trail. Trade-off: deletion is not total, which must be disclosed. A user
who wants the record removed entirely needs a legal process, not a button — and
that is a deliberate design decision, not an oversight.

A verified working example, tested in
`tests/integration/test_user_service.py::TestAnonymisation`.

---

## Data-inventory notes for a future DPIA

| Processing | Purpose | Lawful basis (to be confirmed legally) |
| --- | --- | --- |
| Account creation | Provide the service | Contract |
| Employer search | Match workers to vacancies | Legitimate interest (worker's opt-in) |
| Verification | Third-party attestation of a claim | Legitimate interest |
| Security logging | Prevent and detect abuse | Legitimate interest |
| Content moderation | Platform integrity | Legal obligation / legitimate interest |
| Evidence storage | Support verification requests | Consent of the worker |

Data subjects: workers, referees, verifiers, employer staff.

Cross-border transfer: none planned. All storage is expected to be in-region;
this must be confirmed before launch, because a US or EU region would introduce a
transfer question.

---

## Open questions for legal review

1. Does the DPA 2019 classify construction employment records as sensitive
   personal data? Likely yes for some fields.
2. Is a registration requirement (data controller registration with OPSC) needed?
3. Must a data-subject request process (access, correction, deletion) be published
   before launch? Almost certainly yes.
4. What worker consent is required for employer search — explicit opt-in, and can it
   be withdrawn at any time? Currently: visibility is private by default, so search
   requires opt-in, and withdrawing it is a single PATCH.
5. Are verification records admissible or sensitive under Kenyan employment law?
6. What are the required retention periods, particularly for audit logs?
7. Does aggregating externally sourced jobs create a licensing or database-right
   obligation that the worker-facing terms must disclose?
8. Must the platform provide a way to correct or erase a referee's data — whose data
   is it, legally?

---

## Security controls that protect this data

Detailed in [security.md](security.md). In summary: Argon2id, short-lived tokens
with revocable refresh sessions, deny-by-default authorisation, append-only audit
trail, encryption in transit assumed at the platform edge, and no application-level
encryption of contact details — with the reasoning and the trigger for revisiting
that in [ADR 0012](decisions/0012-sensitive-data-at-rest.md).