"""Application-wide constants and controlled vocabularies.

Every value that a client may store or filter by is declared here as a
:class:`str` enum so that:

* the database can enforce validity with CHECK constraints,
* Pydantic can reject unknown values at the API boundary,
* the OpenAPI schema documents the exact allowed values, and
* the domain logic never compares bare strings.

Enums deliberately use ``str`` mixin so they serialise transparently and
compare correctly against database values.
"""

from __future__ import annotations

from enum import StrEnum

APP_NAME = "FundiPulse API"
APP_SLUG = "fundipulse"
APP_VERSION = "0.1.0"

API_DESCRIPTION = """
REST API for FundiPulse, a mobile-first construction workforce platform for
Kenya.

**Core concepts**

* A **Work Passport** is a worker's professional profile: trades, skills, dated
  work experience, documented construction projects, evidence, references and
  credentials.
* An **Employer** is an *organization*. Users join organizations with an
  organization role (`OWNER`, `ADMIN`, `RECRUITER`, `MEMBER`); one account is
  never assumed to equal one company.
* **Verification** is a request/response workflow performed by an authorised
  third party. A worker can never mark their own experience as verified, and a
  verification is a factual record - it is not a guarantee or a professional
  certification.

**Conventions**

* All endpoints are versioned under `/api/v1`.
* Successful single-resource responses are `{"data": ..., "meta": {...}}`.
* List responses are `{"data": [...], "meta": {"pagination": {...}}}`.
* Errors are `{"error": {"code", "message", "request_id", "details"}}`.
* Every list endpoint is paginated; `page_size` is capped.
* Authentication uses `Authorization: Bearer <access token>`.
""".strip()


# --------------------------------------------------------------------------- #
# Identity & access                                                          #
# --------------------------------------------------------------------------- #
class UserRole(StrEnum):
    """Platform-wide role. Authorisation is always server-side enforced."""

    WORKER = "WORKER"
    EMPLOYER = "EMPLOYER"
    ADMIN = "ADMIN"


class AccountStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DEACTIVATED = "DEACTIVATED"


class TokenPurpose(StrEnum):
    """Single-use, hashed tokens that are never access credentials."""

    # Audit/token event identifier, not a credential.
    PASSWORD_RESET = "PASSWORD_RESET"  # nosec B105
    EMAIL_VERIFICATION = "EMAIL_VERIFICATION"


class OrganizationRole(StrEnum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    RECRUITER = "RECRUITER"
    MEMBER = "MEMBER"


class MembershipStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INVITED = "INVITED"
    SUSPENDED = "SUSPENDED"


#: Organization roles permitted to manage jobs and applications.
JOB_MANAGING_ORG_ROLES: frozenset[OrganizationRole] = frozenset(
    {OrganizationRole.OWNER, OrganizationRole.ADMIN, OrganizationRole.RECRUITER}
)

#: Organization roles permitted to administer the organization itself.
ORG_ADMIN_ROLES: frozenset[OrganizationRole] = frozenset(
    {OrganizationRole.OWNER, OrganizationRole.ADMIN}
)


# --------------------------------------------------------------------------- #
# Controlled catalogues                                                       #
# --------------------------------------------------------------------------- #
class ProfileVisibility(StrEnum):
    """Who may see a worker's passport.

    ``PRIVATE`` is the default. Nothing about a worker is exposed to other
    users until they opt in.
    """

    PRIVATE = "PRIVATE"
    DISCOVERABLE = "DISCOVERABLE"
    PUBLIC = "PUBLIC"


#: Visibilities at which a worker appears in employer search results.
SEARCHABLE_VISIBILITIES: tuple[ProfileVisibility, ...] = (
    ProfileVisibility.DISCOVERABLE,
    ProfileVisibility.PUBLIC,
)


class AvailabilityStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    AVAILABLE_SOON = "AVAILABLE_SOON"
    CURRENTLY_WORKING = "CURRENTLY_WORKING"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class ContactPreference(StrEnum):
    """How (and whether) an employer may reach a worker.

    Contact details are never surfaced by search regardless of this value; the
    API returns a routing hint only.
    """

    NONE = "NONE"
    IN_APP = "IN_APP"
    EMAIL = "EMAIL"
    PHONE = "PHONE"


class SkillProficiency(StrEnum):
    BEGINNER = "BEGINNER"
    INTERMEDIATE = "INTERMEDIATE"
    ADVANCED = "ADVANCED"
    EXPERT = "EXPERT"


# --------------------------------------------------------------------------- #
# Work passport content                                                      #
# --------------------------------------------------------------------------- #
class VerificationTargetType(StrEnum):
    PROJECT = "PROJECT"
    EXPERIENCE = "EXPERIENCE"
    SKILL = "SKILL"
    CREDENTIAL = "CREDENTIAL"
    REFERENCE = "REFERENCE"


class VerificationRequestStatus(StrEnum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class VerificationStatus(StrEnum):
    """Terminal outcomes recorded on a verification."""

    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"


class ReferenceRelationship(StrEnum):
    FOREMAN = "FOREMAN"
    SUPERVISOR = "SUPERVISOR"
    COLLEAGUE = "COLLEAGUE"
    CLIENT = "CLIENT"
    CONTRACTOR = "CONTRACTOR"
    PERSONAL = "PERSONAL"


class ReferenceStatus(StrEnum):
    PENDING_INVITATION = "PENDING_INVITATION"
    CONFIRMED = "CONFIRMED"
    DECLINED = "DECLINED"
    REVOKED = "REVOKED"


class CredentialType(StrEnum):
    CERTIFICATE = "CERTIFICATE"
    LICENCE = "LICENCE"
    ACADEMIC_QUALIFICATION = "ACADEMIC_QUALIFICATION"
    TRADE_TEST_CERTIFICATE = "TRADE_TEST_CERTIFICATE"
    SAFETY_TRAINING = "SAFETY_TRAINING"
    FIRST_AID = "FIRST_AID"
    OTHER = "OTHER"


#: Credential types whose validity implies a licence to practise in Kenya.
#: Recorded as a factual attribute only - presence of a credential never makes
#: a verification automatically, and never implies regulatory compliance.
PROFESSIONAL_LICENCE_TYPES: frozenset[CredentialType] = frozenset(
    {CredentialType.LICENCE, CredentialType.TRADE_TEST_CERTIFICATE}
)


# --------------------------------------------------------------------------- #
# Files & evidence                                                           #
# --------------------------------------------------------------------------- #
class FilePurpose(StrEnum):
    WORK_EVIDENCE = "WORK_EVIDENCE"
    CREDENTIAL_DOCUMENT = "CREDENTIAL_DOCUMENT"
    REFERENCE_DOCUMENT = "REFERENCE_DOCUMENT"
    ORGANIZATION_LOGO = "ORGANIZATION_LOGO"
    REPORT_ATTACHMENT = "REPORT_ATTACHMENT"


class ScanStatus(StrEnum):
    """Malware-scanning integration point.

    ``PENDING`` means the object is quarantined from consumers until a scanner
    reports otherwise, so enabling scanning later cannot retroactively expose
    unscanned content.
    """

    PENDING = "PENDING"
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    ERROR = "ERROR"

    @property
    def is_downloadable(self) -> bool:
        return self is ScanStatus.CLEAN


class EvidenceVisibility(StrEnum):
    """Per-evidence override, narrower than the passport default."""

    PRIVATE = "PRIVATE"
    EMPLOYERS = "EMPLOYERS"
    PUBLIC = "PUBLIC"


# --------------------------------------------------------------------------- #
# Jobs                                                                       #
# --------------------------------------------------------------------------- #
class JobStatus(StrEnum):
    DRAFT = "DRAFT"
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


#: Job statuses a worker is allowed to see and apply to.
APPLICABLE_JOB_STATUSES: tuple[JobStatus, ...] = (JobStatus.OPEN,)

#: Statuses that can no longer accept applications.
TERMINAL_JOB_STATUSES: frozenset[JobStatus] = frozenset(
    {JobStatus.CLOSED, JobStatus.CANCELLED, JobStatus.EXPIRED}
)


class EmploymentType(StrEnum):
    FULL_TIME = "FULL_TIME"
    PART_TIME = "PART_TIME"
    CONTRACT = "CONTRACT"
    TEMPORARY = "TEMPORARY"
    CASUAL = "CASUAL"
    APPRENTICESHIP = "APPRENTICEHIP"
    INTERNSHIP = "INTERNSHIP"


class ExperienceLevel(StrEnum):
    NOT_SPECIFIED = "NOT_SPECIFIED"
    ENTRY = "ENTRY"
    INTERMEDIATE = "INTERMEDIATE"
    EXPERIENCED = "EXPERIENCED"


class JobSourceType(StrEnum):
    """Provenance of a job listing.

    ``PLATFORM`` means the platform itself published it. Every other value is
    externally sourced and must always be rendered with its origin attached.
    """

    PLATFORM = "PLATFORM"
    EMPLOYER_SUBMITTED = "EMPLOYER_SUBMITTED"
    AGGREGATED_PUBLIC = "AGGREGATED_PUBLIC"
    PARTNER_FEED = "PARTNER_FEED"


#: Source types that are not platform-owned. Listings from these sources may
#: never be presented as created by FundiPulse.
EXTERNAL_JOB_SOURCE_TYPES: frozenset[JobSourceType] = frozenset(
    {JobSourceType.AGGREGATED_PUBLIC, JobSourceType.PARTNER_FEED}
)

#: Source types that MUST name an owning organization.
ORGANIZATION_BACKED_SOURCE_TYPES: frozenset[JobSourceType] = frozenset(
    {JobSourceType.PLATFORM, JobSourceType.EMPLOYER_SUBMITTED}
)


class JobSourceTermsStatus(StrEnum):
    """Whether the operator has reviewed the source's terms of service.

    Ingestion must be blocked for anything other than ``APPROVED``; this is the
    machine-readable form of the platform's "respect source terms" rule.
    """

    UNKNOWN = "UNKNOWN"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    PROHIBITED = "PROHIBITED"


class JobSourceRobotsStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    PERMITTED = "PERMITTED"
    RESTRICTED = "RESTRICTED"
    DISALLOWED = "DISALLOWED"


#: Terms statuses for which ingestion is permitted.
INGESTION_ALLOWED_TERMS_STATUSES: frozenset[JobSourceTermsStatus] = frozenset(
    {JobSourceTermsStatus.APPROVED}
)

#: Robots statuses for which automated fetching is permitted.
INGESTION_ALLOWED_ROBOTS_STATUSES: frozenset[JobSourceRobotsStatus] = frozenset(
    {JobSourceRobotsStatus.PERMITTED}
)


class JobChangeType(StrEnum):
    """Change-detection outcomes recorded by future ingestion pipelines."""

    NEW_JOB = "NEW_JOB"
    JOB_UPDATED = "JOB_UPDATED"
    DEADLINE_CHANGED = "DEADLINE_CHANGED"
    JOB_CLOSED = "JOB_CLOSED"
    JOB_REMOVED = "JOB_REMOVED"


class ApplicationStatus(StrEnum):
    SUBMITTED = "SUBMITTED"
    VIEWED = "VIEWED"
    SHORTLISTED = "SHORTLISTED"
    REJECTED = "REJECTED"
    WITHDRAWN = "WITHDRAWN"
    HIRED = "HIRED"


#: Statuses a worker may move their own application to.
WORKER_DRIVEN_APPLICATION_STATUSES: frozenset[ApplicationStatus] = frozenset(
    {ApplicationStatus.WITHDRAWN}
)

#: Statuses an employer (for their own organization's jobs) may set.
EMPLOYER_DRIVEN_APPLICATION_STATUSES: frozenset[ApplicationStatus] = frozenset(
    {
        ApplicationStatus.VIEWED,
        ApplicationStatus.SHORTLISTED,
        ApplicationStatus.REJECTED,
        ApplicationStatus.HIRED,
    }
)


# --------------------------------------------------------------------------- #
# Moderation & reporting                                                     #
# --------------------------------------------------------------------------- #
class ReportReason(StrEnum):
    FRAUD = "FRAUD"
    MISLEADING_INFORMATION = "MISLEADING_INFORMATION"
    SCAM = "SCAM"
    INAPPROPRIATE_CONTENT = "INAPPROPRIATE_CONTENT"
    HARASSMENT = "HARASSMENT"
    ILLEGAL_ACTIVITY = "ILLEGAL_ACTIVITY"
    OTHER = "OTHER"


class ReportSubjectType(StrEnum):
    USER = "USER"
    WORKER_PROFILE = "WORKER_PROFILE"
    ORGANIZATION = "ORGANIZATION"
    JOB = "JOB"
    VERIFICATION = "VERIFICATION"


class ReportStatus(StrEnum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"
    ACTIONED = "ACTIONED"


# --------------------------------------------------------------------------- #
# Notification foundation (outbox only - no delivery channels in V1)          #
# --------------------------------------------------------------------------- #
class NotificationEventType(StrEnum):
    VERIFICATION_REQUESTED = "VERIFICATION_REQUESTED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    REFERENCE_INVITATION_SENT = "REFERENCE_INVITATION_SENT"
    JOB_MATCH_FOUND = "JOB_MATCH_FOUND"
    APPLICATION_STATUS_CHANGED = "APPLICATION_STATUS_CHANGED"
    APPLICATION_WITHDRAWN = "APPLICATION_WITHDRAWN"
    EMPLOYER_CONTACT_REQUEST = "EMPLOYER_CONTACT_REQUEST"
    CONTENT_REPORTED = "CONTENT_REPORTED"


# --------------------------------------------------------------------------- #
# Audit log                                                                  #
# --------------------------------------------------------------------------- #
class AuditAction(StrEnum):
    """Canonical, database-enforced audit actions.

    Adding an action requires a migration because ``audit_logs.action`` has a
    CHECK constraint. That friction is intentional: the audit trail is a
    security control, not a free-text log.
    """

    # --- authentication -------------------------------------------------- #
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGIN_BLOCKED_LOCKED = "LOGIN_BLOCKED_LOCKED"
    LOGOUT = "LOGOUT"
    # Audit event identifier, not a credential.
    TOKEN_REFRESHED = "TOKEN_REFRESHED"  # nosec B105
    # Audit event identifier, not a credential.
    TOKEN_REUSE_DETECTED = "TOKEN_REUSE_DETECTED"  # nosec B105
    # Audit event identifier, not a credential.
    PASSWORD_CHANGED = "PASSWORD_CHANGED"  # nosec B105
    # Audit event identifier, not a credential.
    PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED"  # nosec B105
    # Audit event identifier, not a credential.
    PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED"  # nosec B105
    ACCOUNT_REGISTERED = "ACCOUNT_REGISTERED"
    EMAIL_VERIFICATION_REQUESTED = "EMAIL_VERIFICATION_REQUESTED"
    EMAIL_VERIFIED = "EMAIL_VERIFIED"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED"
    ACCOUNT_DEACTIVATED = "ACCOUNT_DEACTIVATED"
    ACCOUNT_ANONYMISED = "ACCOUNT_ANONYMISED"

    # --- authorisation / administration ---------------------------------- #
    ROLE_CHANGED = "ROLE_CHANGED"
    ADMIN_ACTION = "ADMIN_ACTION"
    MEMBERSHIP_ADDED = "MEMBERSHIP_ADDED"
    MEMBERSHIP_REMOVED = "MEMBERSHIP_REMOVED"
    MEMBERSHIP_ROLE_CHANGED = "MEMBERSHIP_ROLE_CHANGED"

    # --- verification ---------------------------------------------------- #
    VERIFICATION_REQUESTED = "VERIFICATION_REQUESTED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    VERIFICATION_REJECTED = "VERIFICATION_REJECTED"
    VERIFICATION_CANCELLED = "VERIFICATION_CANCELLED"
    VERIFICATION_REVOKED = "VERIFICATION_REVOKED"

    # --- files ----------------------------------------------------------- #
    FILE_UPLOADED = "FILE_UPLOADED"
    FILE_ACCESSED = "FILE_ACCESSED"
    FILE_DOWNLOAD_URL_ISSUED = "FILE_DOWNLOAD_URL_ISSUED"
    FILE_DELETED = "FILE_DELETED"
    FILE_ACCESS_DENIED = "FILE_ACCESS_DENIED"

    # --- domain ---------------------------------------------------------- #
    JOB_CREATED = "JOB_CREATED"
    JOB_UPDATED = "JOB_UPDATED"
    JOB_STATUS_CHANGED = "JOB_STATUS_CHANGED"
    JOB_SOURCE_REGISTERED = "JOB_SOURCE_REGISTERED"
    JOB_INGESTED = "JOB_INGESTED"
    APPLICATION_SUBMITTED = "APPLICATION_SUBMITTED"
    APPLICATION_STATUS_CHANGED = "APPLICATION_STATUS_CHANGED"
    APPLICATION_WITHDRAWN = "APPLICATION_WITHDRAWN"
    CATALOGUE_ITEM_CREATED = "CATALOGUE_ITEM_CREATED"
    CATALOGUE_ITEM_UPDATED = "CATALOGUE_ITEM_UPDATED"
    CONTENT_REPORTED = "CONTENT_REPORTED"
    REPORT_RESOLVED = "REPORT_RESOLVED"
    CONTACT_REQUESTED = "CONTACT_REQUESTED"


# --------------------------------------------------------------------------- #
# API / pagination                                                           #
# --------------------------------------------------------------------------- #
DEFAULT_PAGE_SIZE = 20
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 100

#: Fields a client may sort worker search results by. Anything else is rejected
#: rather than ignored, so a client never silently gets the wrong ordering.
WORKER_SORT_FIELDS: frozenset[str] = frozenset(
    {"match_score", "recently_updated", "experience_desc", "created_desc"}
)

JOB_SORT_FIELDS: frozenset[str] = frozenset(
    {"published_at_desc", "closing_at_asc", "created_at_desc"}
)

DEFAULT_WORKER_SORT = "match_score"
DEFAULT_JOB_SORT = "published_at_desc"

MAX_SEARCH_QUERY_LENGTH = 120
MAX_PAGE_NUMBER = 10_000

#: Job/invitation lifetimes. Expiry is enforced server-side, never by the client.
VERIFICATION_REQUEST_EXPIRE_DAYS = 30
REFERENCE_INVITATION_EXPIRE_DAYS = 30
DEFAULT_JOB_CLOSING_DAYS = 30
MAX_JOB_CLOSING_DAYS = 180

#: Maximum characters accepted for free-text fields. Enforced by Pydantic so a
#: single oversized field cannot be used to bloat the database.
MAX_SHORT_TEXT = 255
MAX_BIO_LENGTH = 2000
MAX_DESCRIPTION_LENGTH = 5000
MAX_NOTES_LENGTH = 4000
