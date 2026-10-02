# Data model

Reference for the PostgreSQL schema implemented in this milestone.

The ERD below is **generated from the live SQLAlchemy metadata** by
`scripts/generate_erd.py`, so it cannot drift from the code. Regenerate it after
any schema change:

```bash
python scripts/generate_erd.py --write
```

Schema changes are made **only** through Alembic. `Base.metadata.create_all()` is
never used, in any environment.

---

## Entity relationship diagram

<!-- ERD:BEGIN -->
```mermaid
erDiagram
    %% Identity & access
    users {
        string email
        string password_hash
        string role
        bool is_active
        bool is_email_verified
        string status
        datetime last_login_at
        datetime email_verified_at
        int failed_login_count
        datetime locked_until
        datetime deactivated_at
        string id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at
    }
    refresh_sessions {
        string user_id FK
        string family_id
        string token_hash
        datetime issued_at
        datetime expires_at
        datetime last_used_at
        datetime revoked_at
        string revoked_reason
        string replaced_by_id FK
        datetime absolute_expires_at
        string user_agent
        inet ip_address
        string id PK
        datetime created_at
        datetime updated_at
    }
    security_tokens {
        string user_id FK
        string purpose
        string token_hash
        datetime expires_at
        datetime consumed_at
        inet request_ip
        string id PK
        datetime created_at
        datetime updated_at
    }
    %% Organizations
    organizations {
        string name
        string slug
        string description
        string industry
        string website_url
        string contact_email
        string contact_phone
        string location
        string county
        string county_id FK
        bool is_active
        bool is_verified
        string id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at
    }
    organization_memberships {
        string organization_id FK
        string user_id FK
        string role
        string status
        string title
        string invited_by_user_id FK
        datetime joined_at
        string id PK
        datetime created_at
        datetime updated_at
    }
    %% Controlled catalogues
    trades {
        string code
        string name
        string description
        bool is_active
        int display_order
        string id PK
        datetime created_at
        datetime updated_at
    }
    skills {
        string code
        string name
        string description
        string trade_id FK
        bool is_active
        int display_order
        string id PK
        datetime created_at
        datetime updated_at
    }
    counties {
        string code
        string name
        string region
        string capital
        bool is_active
        string id PK
        datetime created_at
        datetime updated_at
    }
    %% Work passport
    worker_profiles {
        string user_id FK
        string display_name
        string bio
        string headline
        string primary_trade_id FK
        string county_id FK
        string location
        numeric self_declared_experience_years
        string availability_status
        date available_from
        string visibility
        string contact_preference
        bool is_open_to_opportunities
        string phone_number
        string contact_email
        string contact_name
        string contact_phone
        string id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at
    }
    worker_trades {
        string worker_profile_id FK
        string trade_id FK
        bool is_primary
        numeric years_experience
        string id PK
        datetime created_at
        datetime updated_at
    }
    worker_skills {
        string worker_profile_id FK
        string skill_id FK
        string proficiency
        numeric years_experience
        string id PK
        datetime created_at
        datetime updated_at
    }
    worker_preferred_counties {
        string worker_profile_id FK
        string county_id FK
        string id PK
        datetime created_at
        datetime updated_at
    }
    work_experiences {
        string worker_profile_id FK
        string employer_name
        string project_name
        string role_title
        string trade_id FK
        string description
        date start_date
        date end_date
        bool is_current
        string location
        string county_id FK
        string id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at
    }
    projects {
        string worker_profile_id FK
        string name
        string project_type
        string role_title
        string description
        string work_performed
        string location
        string county_id FK
        string trade_id FK
        date start_date
        date end_date
        bool is_confidential
        string id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at
    }
    credentials {
        string worker_profile_id FK
        string title
        string credential_type
        string issuer
        string issuing_country_code
        string credential_number
        date issue_date
        date expiry_date
        string description
        string file_id FK
        string id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at
    }
    worker_references {
        string worker_profile_id FK
        string full_name
        string relationship
        string organization_name
        string job_title
        string phone_number
        string email
        string status
        string invitation_token_hash
        datetime invitation_expires_at
        datetime invitation_consumed_at
        datetime invited_at
        datetime responded_at
        string response_statement
        string responded_by_user_id FK
        bool is_visible_to_employers
        string id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at
    }
    %% Files & evidence
    files {
        string owner_user_id FK
        string purpose
        string object_key
        string bucket
        string original_filename
        string content_type
        bigint size_bytes
        string sha256
        int width
        int height
        int page_count
        string scan_status
        datetime scanned_at
        string scan_engine
        bool is_quarantined
        int access_count
        datetime last_accessed_at
        datetime verified_at
        string id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at
    }
    evidence_items {
        string worker_profile_id FK
        string file_id FK
        string project_id FK
        string work_experience_id FK
        string credential_id FK
        string title
        string description
        string visibility
        date captured_at
        string id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at
    }
    %% Verification
    verification_requests {
        string worker_profile_id FK
        string requested_by_user_id FK
        string target_type
        string target_id
        string target_label
        jsonb target_snapshot
        string verifier_email
        string verifier_full_name
        string verifier_organization_id FK
        string verifier_relationship
        string message
        string status
        datetime requested_at
        datetime expires_at
        datetime responded_at
        string responded_by_user_id FK
        string response_notes
        string invitation_token_hash
        datetime invitation_expires_at
        datetime invitation_consumed_at
        inet request_ip
        string id PK
        datetime created_at
        datetime updated_at
    }
    verifications {
        string verification_request_id FK
        string worker_profile_id FK
        string requested_by_user_id FK
        string target_type
        string target_id
        string status
        string verified_by_user_id FK
        string verifier_display_name
        string verifier_organization_id FK
        string verifier_relationship
        datetime verified_at
        datetime expires_at
        string evidence_summary
        string response_statement
        bool is_visible_to_employers
        datetime revoked_at
        string revoked_by_user_id FK
        string revoked_reason
        string id PK
        datetime created_at
        datetime updated_at
    }
    %% Jobs & applications
    job_sources {
        string code
        string name
        string source_type
        string base_url
        string terms_status
        string robots_status
        bool respect_robots
        string licensing_notes
        int rate_limit_per_minute
        bool is_active
        datetime last_checked_at
        string last_error
        string id PK
        datetime created_at
        datetime updated_at
    }
    jobs {
        string title
        string description
        string trade_id FK
        string organization_id FK
        string county_id FK
        string location
        string employment_type
        string experience_level
        int experience_required_years
        string status
        datetime published_at
        datetime closing_at
        datetime closed_at
        int application_count
        string source_id FK
        string source_type
        string source_name
        string source_url
        string source_job_id
        string external_apply_url
        datetime first_seen_at
        datetime last_seen_at
        datetime last_verified_at
        bool is_aggregated
        string created_by_user_id FK
        int salary_min
        int salary_max
        string salary_currency
        string salary_period
        string id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at
        int version
    }
    job_skills {
        string job_id FK
        string skill_id FK
        bool is_required
        string id PK
        datetime created_at
        datetime updated_at
    }
    job_source_events {
        string job_id FK
        string source_id FK
        string change_type
        string detail
        datetime detected_at
        string payload_hash
        string id PK
        datetime created_at
        datetime updated_at
    }
    job_applications {
        string job_id FK
        string worker_profile_id FK
        string cover_note
        string status
        datetime submitted_at
        datetime updated_status_at
        datetime withdrawn_at
        datetime decided_at
        string decided_by_user_id FK
        string decision_note
        string idempotency_key
        inet source_ip
        string id PK
        datetime created_at
        datetime updated_at
    }
    %% Trust & safety
    audit_logs {
        string actor_user_id FK
        string actor_role
        string action
        string resource_type
        string resource_id
        string request_id
        inet ip_address
        string user_agent
        jsonb metadata
        string outcome
        datetime created_at
        string id PK
    }
    reports {
        string reporter_user_id FK
        string subject_type
        string subject_id
        string reason
        string details
        string status
        string resolved_by_user_id FK
        string resolution_note
        datetime resolved_at
        string id PK
        datetime created_at
        datetime updated_at
    }
    notification_events {
        string event_type
        string user_id FK
        string recipient_email
        string worker_profile_id FK
        string organization_id FK
        string job_id FK
        jsonb payload
        datetime created_at
        datetime processed_at
        int attempts
        string last_error
        string id PK
    }

    counties "1" ||--|.. jobs "county_id"
    counties "1" ||--|.. organizations "county_id"
    counties "1" ||--|.. projects "county_id"
    counties "1" ||--|.. work_experiences "county_id"
    counties "1" ||--|.. worker_preferred_counties "county_id"
    counties "1" ||--|.. worker_profiles "county_id"
    credentials "1" ||--|.. evidence_items "credential_id"
    files "1" ||--|.. credentials "file_id"
    files "1" ||--|.. evidence_items "file_id"
    job_sources "1" ||--|.. job_source_events "source_id"
    job_sources "1" ||--|.. jobs "source_id"
    jobs "1" ||--|.. job_applications "job_id"
    jobs "1" ||--|.. job_skills "job_id"
    jobs "1" ||--|.. job_source_events "job_id"
    jobs "1" ||--|.. notification_events "job_id"
    organizations "1" ||--|.. jobs "organization_id"
    organizations "1" ||--|.. notification_events "organization_id"
    organizations "1" ||--|.. organization_memberships "organization_id"
    organizations "1" ||--|.. verification_requests "verifier_organization_id"
    organizations "1" ||--|.. verifications "verifier_organization_id"
    projects "1" ||--|.. evidence_items "project_id"
    refresh_sessions "1" ||--|.. refresh_sessions "replaced_by_id"
    skills "1" ||--|.. job_skills "skill_id"
    skills "1" ||--|.. worker_skills "skill_id"
    trades "1" ||--|.. jobs "trade_id"
    trades "1" ||--|.. projects "trade_id"
    trades "1" ||--|.. skills "trade_id"
    trades "1" ||--|.. work_experiences "trade_id"
    trades "1" ||--|.. worker_profiles "primary_trade_id"
    trades "1" ||--|.. worker_trades "trade_id"
    users "1" ||--|.. audit_logs "actor_user_id"
    users "1" ||--|.. files "owner_user_id"
    users "1" ||--|.. job_applications "decided_by_user_id"
    users "1" ||--|.. jobs "created_by_user_id"
    users "1" ||--|.. notification_events "user_id"
    users "1" ||--|.. organization_memberships "invited_by_user_id"
    users "1" ||--|.. organization_memberships "user_id"
    users "1" ||--|.. refresh_sessions "user_id"
    users "1" ||--|.. reports "reporter_user_id"
    users "1" ||--|.. reports "resolved_by_user_id"
    users "1" ||--|.. security_tokens "user_id"
    users "1" ||--|.. verification_requests "requested_by_user_id"
    users "1" ||--|.. verification_requests "responded_by_user_id"
    users "1" ||--|.. verifications "requested_by_user_id"
    users "1" ||--|.. verifications "revoked_by_user_id"
    users "1" ||--|.. verifications "verified_by_user_id"
    users "1" ||--|.. worker_profiles "user_id"
    users "1" ||--|.. worker_references "responded_by_user_id"
    verification_requests "1" ||--|.. verifications "verification_request_id"
    work_experiences "1" ||--|.. evidence_items "work_experience_id"
    worker_profiles "1" ||--|.. credentials "worker_profile_id"
    worker_profiles "1" ||--|.. evidence_items "worker_profile_id"
    worker_profiles "1" ||--|.. job_applications "worker_profile_id"
    worker_profiles "1" ||--|.. notification_events "worker_profile_id"
    worker_profiles "1" ||--|.. projects "worker_profile_id"
    worker_profiles "1" ||--|.. verification_requests "worker_profile_id"
    worker_profiles "1" ||--|.. verifications "worker_profile_id"
    worker_profiles "1" ||--|.. work_experiences "worker_profile_id"
    worker_profiles "1" ||--|.. worker_preferred_counties "worker_profile_id"
    worker_profiles "1" ||--|.. worker_references "worker_profile_id"
    worker_profiles "1" ||--|.. worker_skills "worker_profile_id"
    worker_profiles "1" ||--|.. worker_trades "worker_profile_id"
```
<!-- ERD:END -->

---

## Table index

| Group | Tables |
| --- | --- |
| Identity & access | `users`, `refresh_sessions`, `security_tokens` |
| Organizations | `organizations`, `organization_memberships` |
| Controlled catalogues | `trades`, `skills`, `counties` |
| Work passport | `worker_profiles`, `worker_trades`, `worker_skills`, `worker_preferred_counties`, `work_experiences`, `projects`, `credentials`, `worker_references` |
| Files & evidence | `files`, `evidence_items` |
| Verification | `verification_requests`, `verifications` |
| Jobs & applications | `job_sources`, `jobs`, `job_skills`, `job_source_events`, `job_applications` |
| Trust & safety | `audit_logs`, `reports`, `notification_events` |

---

## 1. Identity and access

### `users`

Authentication identity only. No professional or company data.

| Column | Notes |
| --- | --- |
| `id` | UUIDv4 PK |
| `email` | `UNIQUE`, `CHECK (email = lower(email))` |
| `password_hash` | Argon2id. Never serialised by any schema. |
| `role` | `WORKER` \| `EMPLOYER` \| `ADMIN` |
| `status` | `ACTIVE` \| `SUSPENDED` \| `DEACTIVATED` |
| `is_active`, `is_email_verified` | Boolean flags |
| `failed_login_count`, `locked_until` | Brute-force throttling state |
| `deleted_at` | Soft-delete tombstone (anonymisation target) |

The unique index is on the **normalised** value, so
`Worker@Example.com` cannot be registered alongside `worker@example.com`, and two
simultaneous registrations for the same address cannot both succeed.

### `refresh_sessions`

One row per issued refresh token, storing **only** its SHA-256 hash.

* `family_id` links every token descended from one login.
* Rotation replaces the token and sets `replaced_by_id`.
* Presenting an already-rotated token means it was captured, so the entire
  family is revoked and `TOKEN_REUSE_DETECTED` is audited.
* `absolute_expires_at` caps the family regardless of rotation, so an
  indefinitely refreshed session still ends.

### `security_tokens`

Single-use, hashed, expiring tokens for `PASSWORD_RESET` and
`EMAIL_VERIFICATION`. The `purpose` column keeps the two namespaces separate so a
reset token can never be replayed against the email-verification endpoint.

---

## 2. Organizations

An Employer is an organization, never a single account.

### `organizations`
`slug` is a stable, URL-safe public identifier and is never reused, so historic
audit references keep resolving. `is_verified` is administrator-set and cannot be
self-asserted.

### `organization_memberships`
`UNIQUE (organization_id, user_id)` plus a per-organization role
(`OWNER`, `ADMIN`, `RECRUITER`, `MEMBER`) and status. Authority over a company is
the intersection of *has an active membership* and *role is in the required
set* — never the platform role.

---

## 3. Controlled catalogues

`trades`, `skills` and `counties` replace free-text strings with admin-managed
reference data, which makes filters deterministic and index-backed.

* Every catalogue has a stable `code` (e.g. `MASONRY`, `NAKURU`) and an
  `is_active` flag.
* **Deactivation, not deletion**, so historic passports and jobs keep a
  resolvable reference.
* `skills.trade_id` is optional because skills such as *Site Supervision* span
  trades.
* `counties` covers Kenya's 47 counties; `worker_profiles.county_id` and
  `organizations.county_id` reference it so location filters never rely on
  user-entered spelling.

---

## 4. The Work Passport

### `worker_profiles`

One per user (`UNIQUE (user_id)`).

**Privacy-relevant columns.** `phone_number`, `contact_email`, `contact_name` and
`contact_phone` exist so a worker can be reached through a channel they chose.
No employer-facing schema will include them; `contact_preference` is what an
employer sees, and it is a routing hint, not an address. `visibility` defaults to
`PRIVATE`, so nothing is discoverable until the worker opts in.

**No national ID column.** Nothing in V1 needs one, and not collecting it is the
strongest available data-minimisation control.

**Experience.** `self_declared_experience_years` is explicitly secondary and
labelled as self-declared. Authoritative experience is derived from dated records
in `work_experiences` and `projects`.

### `worker_trades` and `worker_skills`

`UNIQUE (worker_profile_id, trade_id)` and `UNIQUE (worker_profile_id, skill_id)`
prevent duplicates. A partial unique index (`UNIQUE (worker_profile_id) WHERE
is_primary`) guarantees at most one primary trade even under concurrent updates.
`worker_profiles.primary_trade_id` denormalises it for indexed filtering.

### `work_experiences`

A **claim**, never a certification. Two CHECK constraints encode the date
invariants:

* `end_date IS NULL OR end_date >= start_date`
* `(end_date IS NULL) != is_current` — exactly one of "current" or "end date" is
  set.

`employer_name` is free text because the employer may not be a FundiPulse
organization.

### `projects`

Documents a construction project and the **role the worker played** on it, with
optional `start_date`/`end_date`. `is_confidential` lets a worker withhold a
project with client confidentiality obligations.

### `credentials`

A certificate, licence or qualification the worker claims to hold. Uploading a
document records the claim; it never asserts the document is genuine. Issuers'
confirmation is handled by the verification workflow.

### `worker_references`

A nominated referee. **The worker cannot set `status`** — only the referee
responding, or an administrator, can move it to `CONFIRMED`. `invitation_token_hash`
stores the hash of the single-use token sent to the referee.

### `evidence_items`

Binds an uploaded object to what it evidences (project, experience, credential)
and carries a **per-evidence visibility** (`PRIVATE`, `EMPLOYERS`, `PUBLIC`) that
is always at most as permissive as the passport.

---

## 5. Files and evidence

`files` stores **metadata only**. No file bytes are stored in PostgreSQL.

| Column | Purpose |
| --- | --- |
| `object_key` | **Server-generated** storage key. Never derived from user input — this removes path traversal as a class of bug. |
| `original_filename` | Sanitised, display-only. Never used to build a path or a `Content-Disposition` header. |
| `content_type` | Agreed by server-side sniffing, not the client's claim. |
| `sha256` | Integrity hash; supports dedupe and tamper evidence. |
| `size_bytes` | `CHECK (size_bytes > 0 AND size_bytes <= 26214400)` |
| `scan_status` | `PENDING`/`CLEAN`/`INFECTED`/`ERROR` |
| `is_quarantined` | Defaults to `true`. |

`is_downloadable` is a single property requiring *not quarantined*, *not deleted*
and *scanned clean*. Centralising it stops an individual endpoint from forgetting
the check. Enabling malware scanning later cannot retroactively expose unscanned
content, because `PENDING` is not downloadable.

---

## 6. Verification

This is the security-critical part of the domain.

### `verification_requests`

A worker's request that a third party confirm one specific claim. Records who
asked, who was asked, what is being verified, when, and the response.

* Partial unique index `UNIQUE (target_type, target_id) WHERE status = 'PENDING'`
  — one in-flight request per claim, race-safe.
* `requested_by_user_id` is always the worker.
* `invitation_token_hash` allows a verifier without an account to respond once.

### `verifications`

The factual record of a completed verification. Two invariants are enforced on
the row itself:

```sql
CHECK (verified_by_user_id IS NULL OR verified_by_user_id <> requested_by_user_id)
CHECK ((status = 'REVOKED') OR revoked_at IS NULL)
```

The first is the **no self-verification** guarantee: a worker physically cannot be
recorded as verifying their own claim, even if a service bug tried. The second
keeps revocation consistent.

`UNIQUE (verification_request_id)` means one outcome per request.

Records **transition, they are not deleted**. A completed verification is revoked
by setting `status = 'REVOKED'` with `revoked_at`, `revoked_by_user_id` and a
reason, so what was once asserted remains inspectable.

---

## 7. Jobs, sources and applications

### `job_sources`

A permitted origin. `terms_status` must be `APPROVED` before ingestion, and
`robots_status` must be `PERMITTED` unless an operator has explicitly recorded
`respect_robots = false`. This encodes "respect source terms" as a
machine-checkable gate rather than a comment in a scraper.

### `jobs`

Provenance is mandatory:

* `source_type`, `source_id`, `source_name`, `source_url`, `source_job_id`
* `first_seen_at`, `last_seen_at`, `last_verified_at`
* `is_aggregated` — drives mandatory "apply on the original site" routing

Integrity rules:

```sql
CHECK (status = 'DRAFT' OR organization_id IS NOT NULL)  -- ownership is answerable
CHECK (source_type <> 'PLATFORM' OR source_job_id IS NULL)
CHECK (closing_at IS NULL OR published_at IS NULL OR closing_at >= published_at)
```

A listing cannot be published without an owning organization, so "who may manage
this job" is always answerable without inference. Aggregated listings keep their
origin forever.

Partial unique index `UNIQUE (source_id, source_job_id) WHERE source_job_id IS NOT
NULL AND deleted_at IS NULL` makes re-ingestion idempotent.

### `job_source_events`

Append-only change-detection ledger: `NEW_JOB`, `JOB_UPDATED`,
`DEADLINE_CHANGED`, `JOB_CLOSED`, `JOB_REMOVED`. Determined by deterministic
comparison, never by a model.

### `job_applications`

```sql
UNIQUE (job_id, worker_profile_id)
UNIQUE (worker_profile_id, idempotency_key) WHERE idempotency_key IS NOT NULL
```

At most one application per worker per job, enforced at the database level.
Withdrawal is a **status transition**, not a deletion, so an employer's decision
history survives a candidate changing their mind. `application_count` on `jobs`
is maintained transactionally for cheap list rendering.

---

## 8. Trust and safety

### `audit_logs`

Append-only, enforced by a PostgreSQL trigger:

```sql
CREATE TRIGGER audit_logs_append_only
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();
```

The application offers no update or delete path, but the absence of an endpoint
is not a control. This makes the log tamper-evident against any session that can
reach the table — including a compromised service account or a manual `psql`
login.

`action` is a `CHECK`-constrained vocabulary, so adding an event type requires a
migration. That friction is intentional: the audit trail is a security control,
not free text. `metadata` is redacted before it is written.

### `reports`

Any authenticated user may report a `USER`, `WORKER_PROFILE`, `ORGANIZATION`,
`JOB` or `VERIFICATION` for fraud, misleading information, scams or inappropriate
content. Only an administrator transitions `status`. One report per reporter per
subject.

### `notification_events`

An **outbox**, not a delivery system. Domain services append an event; a future
worker would deliver it over SMS, WhatsApp or push. There is no dispatcher in
this milestone and no endpoint that sends a message.

---

## 9. Integrity summary

| Guarantee | Mechanism |
| --- | --- |
| Valid statuses and enums | 47 generated `CHECK` constraints (`install_enum_checks`) |
| Referential integrity | Foreign keys with explicit `ON DELETE` behaviour |
| `RESTRICT` on catalogue references | Deleting a trade/skill cannot orphan history |
| Lower-case emails | `CHECK (email = lower(email))` on three tables |
| Date consistency | `CHECK` on experiences, projects, credentials |
| Availability consistency | `AVAILABLE_SOON` requires `available_from` |
| One primary trade | Partial unique index |
| One pending verification per claim | Partial unique index |
| One application per worker per job | Unique constraint |
| Idempotent ingestion | Partial unique index on `(source_id, source_job_id)` |
| Audit immutability | `BEFORE UPDATE OR DELETE` trigger |
| Bounded statements | `statement_timeout`, `lock_timeout` per connection |

---

## 10. Deletion and retention

Account deletion is **deactivation and anonymisation**, never a blind `DELETE`:
audit records may be required for auditability and legitimate business purposes.

* `deleted_at` marks soft-deleted passport records.
* Deactivation sets `users.deactivated_at`, clears `is_active`, and revokes every
  refresh session and outstanding token.
* Anonymisation scrubs the private contact block on the passport while leaving
  aggregate statistics and audit rows intact.
* Audit logs are never deleted by any application path, and the database refuses.

Retention periods and the legal basis for each class of data require review
before production — see [privacy.md](privacy.md).