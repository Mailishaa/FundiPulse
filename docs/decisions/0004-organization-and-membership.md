# ADR 0004 — Employers are organizations with memberships

**Status:** Accepted · **Date:** 2026-10-02

## Context

The brief is explicit: "If employer organizations have multiple users, model
`organization`, `organization_members`, `roles` instead of assuming one account
equals one company." In practice a Kenyan contractor or developer may have a
director, a recruiter and a site manager all using the same employer account.

## Decision

Model `organizations` and `organization_memberships` separately. A user's powers
over a company come from an **active membership** whose **organization role** is
in the set required for the action.

| Organization role | May manage | May post/managing jobs | May administer the org |
| --- | --- | --- | --- |
| `OWNER` | Yes | Yes | Yes |
| `ADMIN` | Yes | Yes | Yes |
| `RECRUITER` | Yes | Yes | No |
| `MEMBER` | Yes | No | No |

## Alternatives considered

| Option | Why rejected |
| --- | --- |
| `employer_profiles` one-to-one with `users` | Cannot express "four people work for this company". Either they all share one login (unattributable audit trail) or each gets a duplicate company record. |
| `organization_id` column on `users` | Assumes one user, one company. Breaks the moment a recruiter works for two, and has no room for per-company roles. |
| Platform-wide `EMPLOYER` role implying full access | The platform role says "this is an employer"; it says nothing about *which* company, or with what authority. |

## Consequences

**Accepted costs**

* Every organization-scoped endpoint needs a membership lookup. This is cached on
  the request in the planned `dependencies.py`, so it costs one indexed query.
* Cross-organization confusion is a real bug class; it is covered by explicit
  tests ("a user in Company A cannot modify Company B").

**Accepted benefits**

* Audit attribution: every job and application action names the specific user who
  performed it.
* A user can belong to several organizations with different powers in each.
* Ownership questions are answerable from data rather than inferred from naming
  conventions.

**Security rule that follows from this**

A platform role of `EMPLOYER` grants **no** organization access whatsoever. There
is no implicit path from `users.role` to `organization_memberships`. A user with
no membership has zero authority over every organization, including one whose
name they know.