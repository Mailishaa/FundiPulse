# ADR 0007 — Tenders are a separate domain from jobs

**Status:** Accepted · **Date:** 2026-10-02

## Context

Both construction jobs and construction tenders describe construction demand.
It is tempting to model them as one "opportunity" table with a `type` column.
Kenyan construction workers searching for work would then be shown procurement
notices they are not eligible for.

## Decision

A tender is a **procurement opportunity**, not an employment vacancy. It is a
separate domain and does not appear in the V1 schema at all.

Tenders never:

* appear in `GET /jobs`,
* appear in worker job search or job-match results,
* accept a `job_application`,
* appear on a Work Passport as an opportunity a worker can pursue.

## Rationale

* **Eligibility differs.** A tender is won by a company that can bid; an
  individual tradesperson cannot. A worker cannot "apply" for one.
* **The lifecycle differs.** Tender status tracks publication, bid opening,
  evaluation, award and contract. Job status tracks open/closed applications.
* **The audience differs.** Tender readers are procurement professionals.
  Job readers are workers and recruiters.
* **Flattening them would corrupt both.** A `type` column means every job query
  needs `WHERE type = 'JOB'`, every worker-facing surface needs a filter, and a
  future bug that forgets the filter shows tradespeople a procurement notice.

## Future shape, when tenders are added

A separate `tenders` aggregate with its own schemas, services and endpoints.
The connection to the workforce domain is **demand signalling**, not
application flow:

```text
tender (awarded)
      │
      ▼
awarded project ──▶ implies future staffing demand
      │
      ▼
job requisitions derived from the awarded scope
      │
      ▼
ordinary jobs ──▶ workers apply normally
```

A future system *may* derive job requisitions from awarded tenders, because an
awarded road contract implies a crew. It may **never** tell an individual worker
to apply for a tender unless eligibility for that specific procurement has been
explicitly established.

## Consequences

**Accepted costs**

* No tender functionality in V1, and the brief explicitly accepts this.
* A future migration must create the tables and, if desired, a derived-requisition
  service. Neither requires changing `jobs`.

**Accepted benefits**

* Worker-facing surfaces stay honest: everything a worker sees is something they
  can actually do.
* Job and tender lifecycles evolve independently.