# Architecture decision records

Each record captures a decision that was actually made, the alternatives that
were considered, and the consequences we accept. Records are immutable once
accepted; a changed decision gets a new record that supersedes the old one.

| # | Decision | Status |
| --- | --- | --- |
| [0001](0001-uuid-primary-keys.md) | UUIDv4 primary keys | Accepted |
| [0002](0002-varchar-enums-instead-of-native.md) | `VARCHAR` + `CHECK` instead of native PostgreSQL enums | Accepted |
| [0003](0003-sync-sqlalchemy.md) | Synchronous SQLAlchemy sessions | Accepted |
| [0004](0004-organization-and-membership.md) | Employers are organizations with memberships | Accepted |
| [0005](0005-no-national-id.md) | Do not collect a national ID number | Accepted |
| [0006](0006-verification-is-not-certification.md) | Verification records facts, never guarantees | Accepted |
| [0007](0007-tenders-are-a-separate-domain.md) | Tenders are not worker jobs | Accepted |
| [0008](0008-object-storage-not-database-blobs.md) | File bytes live in object storage, never in PostgreSQL | Accepted |
| [0009](0009-database-constraints-for-race-safety.md) | Constraints, not check-then-insert, for concurrency rules | Accepted |
| [0010](0010-no-ratings-or-completion-score.md) | No star ratings or overall completion percentage | Accepted |
| [0011](0011-structured-logs-and-request-ids.md) | Structured JSON logging with request correlation | Accepted |
| [0012](0012-sensitive-data-at-rest.md) | Encryption strategy for sensitive data at rest | Accepted |