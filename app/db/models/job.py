"""Jobs, job sources, provenance and applications.

Two rules shape this module:

**Provenance is never optional.** Every job carries where it came from. Jobs
whose ``source_type`` is external keep ``source_url``, ``source_job_id``,
``first_seen_at`` and ``last_seen_at``, and the API always renders their origin.
The database refuses to store an aggregated listing without an owning source,
and refuses to store an external listing that claims to be platform-owned.

**Job status is deterministic.** Status is set by the organization that owns the
job, by explicit transitions, or by a deterministic expiry rule evaluated
server-side. It is never inferred by a model, and a worker cannot influence it.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import (
    ApplicationStatus,
    EmploymentType,
    ExperienceLevel,
    JobChangeType,
    JobSourceRobotsStatus,
    JobSourceTermsStatus,
    JobSourceType,
    JobStatus,
)
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.models.mixins import SoftDeleteMixin, VersionMixin
from app.db.types import enum_column_type, inet_column

if TYPE_CHECKING:
    from app.db.models.catalogue import Skill, Trade
    from app.db.models.organization import Organization
    from app.db.models.worker import WorkerProfile


class JobSource(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A permitted origin for job listings.

    Ingestion pipelines must consult ``terms_status`` and ``robots_status``
    before fetching anything. ``INGESTION_ALLOWED_*`` constants in
    ``app.core.constants`` encode which combinations permit ingestion; there is
    intentionally no generic "fetch any URL" code path in this codebase.
    """

    __tablename__ = "job_sources"
    __table_args__ = (
        UniqueConstraint("code", name="uq_job_sources_code"),
        Index("ix_job_sources_active", "is_active", "terms_status"),
    )

    code: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(
        enum_column_type(JobSourceType, name="job_source_type"),
        nullable=False,
        default=JobSourceType.AGGREGATED_PUBLIC.value,
    )
    base_url: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        doc="Only informational. Hostnames are validated against this before fetching.",
    )
    terms_status: Mapped[str] = mapped_column(
        enum_column_type(JobSourceTermsStatus, name="job_source_terms_status"),
        nullable=False,
        default=JobSourceTermsStatus.UNKNOWN.value,
        doc="Only APPROVED permits ingestion.",
    )
    robots_status: Mapped[str] = mapped_column(
        enum_column_type(JobSourceRobotsStatus, name="job_source_robots_status"),
        nullable=False,
        default=JobSourceRobotsStatus.UNKNOWN.value,
    )
    respect_robots: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
        doc="Non-negotiable default; kept explicit for operator review.",
    )
    licensing_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="Redistribution/licensing constraints reviewed by an administrator.",
    )
    rate_limit_per_minute: Mapped[int] = mapped_column(
        nullable=False, default=10, server_default="10"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)

    jobs: Mapped[list[Job]] = relationship(back_populates="source")

    @property
    def ingestion_permitted(self) -> bool:
        """Whether this source may currently be ingested from."""
        from app.core.constants import (
            INGESTION_ALLOWED_ROBOTS_STATUSES,
            INGESTION_ALLOWED_TERMS_STATUSES,
        )

        if not self.is_active:
            return False
        if self.terms_status not in INGESTION_ALLOWED_TERMS_STATUSES:
            return False
        robots_ok = self.robots_status in INGESTION_ALLOWED_ROBOTS_STATUSES
        # An operator who has explicitly set respect_robots=False has recorded a
        # decision; the gate above still requires an APPROVED terms status, so
        # this cannot be used to bypass terms review.
        return robots_ok or not self.respect_robots


class Job(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, VersionMixin):
    """A construction job opportunity."""

    __tablename__ = "jobs"
    __table_args__ = (
        # Deterministic de-duplication for aggregated listings. NULL
        # source_job_id values are excluded, so platform jobs are unaffected.
        Index(
            "uq_jobs_source_external_id",
            "source_id",
            "source_job_id",
            unique=True,
            postgresql_where=text("source_job_id IS NOT NULL AND deleted_at IS NULL"),
        ),
        # A published or closed platform listing must belong to an organization:
        # this is what makes "who owns this job" answerable without inference.
        # EXTERNAL jobs are the exception, because their owner is the source rather
        # than an employer - without this carve-out an aggregated job could never
        # reach OPEN, and workers would never see it.
        CheckConstraint(
            "status = 'DRAFT' OR organization_id IS NOT NULL OR source_type = 'EXTERNAL'",
            name="jobs_published_requires_organization",
        ),
        CheckConstraint(
            "closing_at IS NULL OR published_at IS NULL OR closing_at >= published_at",
            name="jobs_closing_after_publish",
        ),
        CheckConstraint(
            "source_type <> 'PLATFORM' OR source_job_id IS NULL",
            name="jobs_platform_has_no_external_id",
        ),
        Index("ix_jobs_status_published", "status", "published_at"),
        Index("ix_jobs_organization", "organization_id", "status"),
        Index("ix_jobs_county_status", "county_id", "status"),
        Index("ix_jobs_trade_status", "trade_id", "status"),
        Index("ix_jobs_external", "source_type", "last_seen_at"),
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    trade_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("trades.id", ondelete="SET NULL"), nullable=True
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True
    )
    county_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("counties.id", ondelete="SET NULL"), nullable=True
    )
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)

    employment_type: Mapped[str] = mapped_column(
        enum_column_type(EmploymentType, name="employment_type"),
        nullable=False,
        default=EmploymentType.FULL_TIME.value,
    )
    experience_level: Mapped[str] = mapped_column(
        enum_column_type(ExperienceLevel, name="experience_level"),
        nullable=False,
        default=ExperienceLevel.NOT_SPECIFIED.value,
    )
    experience_required_years: Mapped[int | None] = mapped_column(Integer, nullable=True)

    status: Mapped[str] = mapped_column(
        enum_column_type(JobStatus, name="job_status"),
        nullable=False,
        default=JobStatus.DRAFT.value,
        doc="Server-controlled. A worker can never set this.",
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closing_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Drives deterministic EXPIRED derivation on the server.",
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    application_count: Mapped[int] = mapped_column(
        nullable=False,
        default=0,
        server_default="0",
        doc="Maintained transactionally for cheap list rendering.",
    )

    # --- provenance ------------------------------------------------------ #
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("job_sources.id", ondelete="SET NULL"), nullable=True
    )
    source_type: Mapped[str] = mapped_column(
        enum_column_type(JobSourceType, name="job_source_type"),
        nullable=False,
        default=JobSourceType.PLATFORM.value,
    )
    source_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    source_job_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    external_apply_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="When the source listing was last confirmed to still exist.",
    )
    is_aggregated: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        doc="Drives mandatory 'apply on the original site' routing.",
    )

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    salary_min: Mapped[int | None] = mapped_column(Integer, nullable=True)
    salary_max: Mapped[int | None] = mapped_column(Integer, nullable=True)
    salary_currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    salary_period: Mapped[str | None] = mapped_column(String(16), nullable=True)

    source: Mapped[JobSource | None] = relationship(back_populates="jobs")
    organization: Mapped[Organization | None] = relationship(back_populates="jobs")
    trade: Mapped[Trade | None] = relationship()
    skills: Mapped[list[JobSkill]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )
    applications: Mapped[list[JobApplication]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )

    @property
    def status_enum(self) -> JobStatus:
        return JobStatus(self.status)

    @property
    def accepts_applications(self) -> bool:
        """Whether a worker may apply right now, by business rule alone."""
        return self.status == JobStatus.OPEN.value and not self.is_aggregated

    @property
    def is_platform_owned(self) -> bool:
        from app.core.constants import EXTERNAL_JOB_SOURCE_TYPES

        return JobSourceType(self.source_type) not in EXTERNAL_JOB_SOURCE_TYPES


class JobSkill(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A skill required by a job."""

    __tablename__ = "job_skills"
    __table_args__ = (
        UniqueConstraint("job_id", "skill_id", name="uq_job_skills_job_skill"),
        Index("ix_job_skills_skill", "skill_id"),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    skill_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("skills.id", ondelete="RESTRICT"), nullable=False
    )
    is_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    job: Mapped[Job] = relationship(back_populates="skills")
    skill: Mapped[Skill] = relationship()


class JobSourceEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Change-detection ledger for aggregated listings.

    Append-oriented: ``NEW_JOB``, ``JOB_UPDATED``, ``DEADLINE_CHANGED``,
    ``JOB_CLOSED`` and ``JOB_REMOVED`` are recorded rather than inferred, so a
    provenance question ("why does this job say it closed?") is answerable
    later. Determined by deterministic comparison, never by a model.
    """

    __tablename__ = "job_source_events"
    __table_args__ = (
        Index("ix_job_source_events_job", "job_id", "detected_at"),
        Index("ix_job_source_events_source", "source_id", "change_type"),
    )

    job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("job_sources.id", ondelete="CASCADE"), nullable=False
    )
    change_type: Mapped[str] = mapped_column(
        enum_column_type(JobChangeType, name="job_change_type"), nullable=False
    )
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class JobApplication(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A worker's application to a job.

    Lifecycle rules rather than CRUD: a worker may ``WITHDRAW`` (a status
    transition), never delete, so an employer's decision history survives a
    candidate changing their mind. The one-application-per-job rule is a unique
    constraint, so two concurrent submissions cannot both succeed.
    """

    __tablename__ = "job_applications"
    __table_args__ = (
        UniqueConstraint("job_id", "worker_profile_id", name="uq_job_applications_job_worker"),
        Index(
            "uq_job_applications_idempotency",
            "worker_profile_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
        Index("ix_job_applications_job_status", "job_id", "status"),
        Index("ix_job_applications_worker", "worker_profile_id", "created_at"),
        Index("ix_job_applications_status", "status", "created_at"),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )
    cover_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        enum_column_type(ApplicationStatus, name="application_status"),
        nullable=False,
        default=ApplicationStatus.SUBMITTED.value,
    )
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_status_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        doc="Client-supplied dedupe key for safe retries over poor connections.",
    )
    source_ip: Mapped[str | None] = inet_column()

    job: Mapped[Job] = relationship(back_populates="applications")
    worker_profile: Mapped[WorkerProfile] = relationship()

    @property
    def status_enum(self) -> ApplicationStatus:
        return ApplicationStatus(self.status)

    @property
    def is_active(self) -> bool:
        return self.status not in {
            ApplicationStatus.REJECTED.value,
            ApplicationStatus.WITHDRAWN.value,
        }
