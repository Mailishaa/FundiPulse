"""The Worker's Work Passport and its constituent records.

Design notes that matter for security:

* **No national ID.** The schema deliberately does not store an identity number.
  Nothing in the V1 product needs it, and not collecting it is the strongest
  available data-minimisation control (see ``docs/privacy.md``). Adding it later
  is a schema change with its own legal review.
* **Contact details are private by construction.** ``phone_number``,
  ``contact_email`` and ``contact_name`` exist so the worker can be reached
  through a deliberate channel, but no employer-facing schema ever includes
  them. ``contact_preference`` is what employers see: a routing hint only.
* **Experience is never self-certified.** A worker's total experience is derived
  from dated experience records; ``self_declared_experience_years`` is retained
  only as an explicitly labelled secondary signal and is never treated as
  authoritative.
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import TYPE_CHECKING
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import (
    AvailabilityStatus,
    ContactPreference,
    CredentialType,
    EvidenceVisibility,
    ProfileVisibility,
    ReferenceRelationship,
    ReferenceStatus,
    SkillProficiency,
)
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.models.mixins import SoftDeleteMixin
from app.db.types import enum_column_type

if TYPE_CHECKING:
    from app.db.models.catalogue import Skill, Trade
    from app.db.models.file import FileObject
    from app.db.models.user import User
    from app.db.models.verification import VerificationRequest


class WorkerProfile(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A worker's professional identity and professional profile."""

    __tablename__ = "worker_profiles"
    __table_args__ = (
        UniqueConstraint("user_id", name="uq_worker_profiles_user_id"),
        Index("ix_worker_profiles_visibility", "visibility", "deleted_at"),
        Index("ix_worker_profiles_county", "county_id"),
        Index("ix_worker_profiles_availability", "availability_status"),
        Index("ix_worker_profiles_primary_trade", "primary_trade_id"),
        {"comment": "One Work Passport per user account."},
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    display_name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
        doc="Chosen name shown to employers. Legal name is not collected in V1.",
    )
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)
    headline: Mapped[str | None] = mapped_column(
        String(160),
        nullable=True,
        doc="Short professional summary shown in search results.",
    )

    primary_trade_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("trades.id", ondelete="SET NULL"),
        nullable=True,
        doc="Denormalised from worker_trades for indexed filtering.",
    )
    county_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("counties.id", ondelete="SET NULL"), nullable=True
    )
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)

    self_declared_experience_years: Mapped[Decimal | None] = mapped_column(
        Numeric(4, 1),
        nullable=True,
        doc="Worker-entered figure. Never authoritative; derived years are exposed separately.",
    )

    availability_status: Mapped[str] = mapped_column(
        enum_column_type(AvailabilityStatus, name="availability_status"),
        nullable=False,
        default=AvailabilityStatus.NOT_AVAILABLE.value,
    )
    available_from: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
        doc="Required when availability_status is AVAILABLE_SOON.",
    )

    visibility: Mapped[str] = mapped_column(
        enum_column_type(ProfileVisibility, name="profile_visibility"),
        nullable=False,
        default=ProfileVisibility.PRIVATE.value,
        doc="PRIVATE by default. Employers only see PRIVATE profiles via direct link.",
    )
    contact_preference: Mapped[str] = mapped_column(
        enum_column_type(ContactPreference, name="contact_preference"),
        nullable=False,
        default=ContactPreference.NONE.value,
        doc="How employers may reach this worker. NONE means nobody may.",
    )
    is_open_to_opportunities: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
        doc="Opt-in flag for job alerts. Separate from availability.",
    )

    # --- Private contact block. Never serialised to another user. --------- #
    phone_number: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        doc="E.164-ish Kenyan number. Owner-only field.",
    )
    contact_email: Mapped[str | None] = mapped_column(
        String(320),
        nullable=True,
        doc="Optional alternate contact address. Owner-only field.",
    )
    contact_name: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
        doc="Optional third-party contact (e.g. a relative on informal sites).",
    )
    contact_phone: Mapped[str | None] = mapped_column(String(32), nullable=True)

    user: Mapped[User] = relationship(back_populates="worker_profile")
    trades: Mapped[list[WorkerTrade]] = relationship(
        back_populates="worker_profile",
        cascade="all, delete-orphan",
        order_by="WorkerTrade.is_primary.desc()",
    )
    skills: Mapped[list[WorkerSkill]] = relationship(
        back_populates="worker_profile",
        cascade="all, delete-orphan",
    )
    preferred_counties: Mapped[list[WorkerPreferredCounty]] = relationship(
        back_populates="worker_profile",
        cascade="all, delete-orphan",
    )
    experiences: Mapped[list[WorkExperience]] = relationship(
        back_populates="worker_profile",
        cascade="all, delete-orphan",
    )
    projects: Mapped[list[Project]] = relationship(
        back_populates="worker_profile",
        cascade="all, delete-orphan",
    )
    credentials: Mapped[list[Credential]] = relationship(
        back_populates="worker_profile",
        cascade="all, delete-orphan",
    )
    references: Mapped[list[WorkerReference]] = relationship(
        back_populates="worker_profile",
        cascade="all, delete-orphan",
    )
    evidence: Mapped[list[EvidenceItem]] = relationship(
        back_populates="worker_profile",
        cascade="all, delete-orphan",
    )
    verification_requests: Mapped[list[VerificationRequest]] = relationship(
        back_populates="worker_profile",
        cascade="all, delete-orphan",
    )

    @property
    def visibility_enum(self) -> ProfileVisibility:
        return ProfileVisibility(self.visibility)

    @property
    def availability_enum(self) -> AvailabilityStatus:
        return AvailabilityStatus(self.availability_status)

    @property
    def contact_preference_enum(self) -> ContactPreference:
        return ContactPreference(self.contact_preference)

    @property
    def is_searchable(self) -> bool:
        """Whether this profile may appear in employer discovery at all."""
        return self.deleted_at is None and self.visibility != ProfileVisibility.PRIVATE.value

    @property
    def accepts_contact(self) -> bool:
        return (
            self.visibility != ProfileVisibility.PRIVATE.value
            and self.contact_preference != ContactPreference.NONE.value
        )


class WorkerTrade(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A worker's association with a trade, flagging the primary one.

    Workers may hold several trades. Exactly one may be ``is_primary``; the
    partial unique index below enforces that at the database level so two
    concurrent updates cannot both claim primacy.
    """

    __tablename__ = "worker_trades"
    __table_args__ = (
        UniqueConstraint("worker_profile_id", "trade_id", name="uq_worker_trades_profile_trade"),
        Index(
            "uq_worker_trades_single_primary",
            "worker_profile_id",
            unique=True,
            postgresql_where=text("is_primary"),
        ),
        Index("ix_worker_trades_trade", "trade_id"),
    )

    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )
    trade_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("trades.id", ondelete="RESTRICT"), nullable=False
    )
    is_primary: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        doc="At most one primary trade per passport.",
    )
    years_experience: Mapped[Decimal | None] = mapped_column(Numeric(4, 1), nullable=True)

    worker_profile: Mapped[WorkerProfile] = relationship(back_populates="trades")
    trade: Mapped[Trade] = relationship()


class WorkerSkill(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A skill held by a worker, with a self-declared proficiency level."""

    __tablename__ = "worker_skills"
    __table_args__ = (
        UniqueConstraint("worker_profile_id", "skill_id", name="uq_worker_skills_profile_skill"),
        Index("ix_worker_skills_skill", "skill_id"),
        Index("ix_worker_skills_profile", "worker_profile_id"),
    )

    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )
    skill_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("skills.id", ondelete="RESTRICT"), nullable=False
    )
    proficiency: Mapped[str] = mapped_column(
        enum_column_type(SkillProficiency, name="skill_proficiency"),
        nullable=False,
        default=SkillProficiency.INTERMEDIATE.value,
        doc="Self-declared. Never counts as verification.",
    )
    years_experience: Mapped[Decimal | None] = mapped_column(Numeric(4, 1), nullable=True)

    worker_profile: Mapped[WorkerProfile] = relationship(back_populates="skills")
    skill: Mapped[Skill] = relationship()


class WorkerPreferredCounty(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A county a worker is willing to work in."""

    __tablename__ = "worker_preferred_counties"
    __table_args__ = (
        UniqueConstraint(
            "worker_profile_id",
            "county_id",
            name="uq_worker_preferred_counties_profile_county",
        ),
        Index("ix_worker_preferred_counties_county", "county_id"),
    )

    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )
    county_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("counties.id", ondelete="CASCADE"), nullable=False
    )

    worker_profile: Mapped[WorkerProfile] = relationship(back_populates="preferred_counties")


class WorkExperience(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A dated claim of previous employment.

    A claim, never a certification. Verification lives in
    :mod:`app.db.models.verification` and is applied independently.
    """

    __tablename__ = "work_experiences"
    __table_args__ = (
        CheckConstraint(
            "end_date IS NULL OR end_date >= start_date",
            name="work_experiences_end_after_start",
        ),
        CheckConstraint(
            "(end_date IS NULL) != is_current",
            name="work_experiences_current_matches_end_date",
        ),
        Index("ix_work_experiences_profile", "worker_profile_id", "deleted_at"),
        Index("ix_work_experiences_dates", "start_date", "end_date"),
        Index("ix_work_experiences_trade", "trade_id"),
    )

    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )
    employer_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Free text: the employer may not be a FundiPulse organization.",
    )
    project_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role_title: Mapped[str] = mapped_column(String(160), nullable=False)
    trade_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("trades.id", ondelete="SET NULL"), nullable=True
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    start_date: Mapped[date] = mapped_column(Date, nullable=False)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    is_current: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        doc="Exactly one of is_current / end_date must be set.",
    )
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    county_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("counties.id", ondelete="SET NULL"), nullable=True
    )

    worker_profile: Mapped[WorkerProfile] = relationship(back_populates="experiences")
    trade: Mapped[Trade | None] = relationship()


class Project(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A construction project a worker documents, with the role they played."""

    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint(
            "end_date IS NULL OR end_date >= start_date",
            name="projects_end_after_start",
        ),
        Index("ix_projects_profile", "worker_profile_id", "deleted_at"),
        Index("ix_projects_county", "county_id"),
        Index("ix_projects_trade", "trade_id"),
    )

    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    project_type: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
        doc="e.g. RESIDENTIAL, COMMERCIAL, ROADWORKS, RENOVATION.",
    )
    role_title: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
        doc="The worker's role on this specific project.",
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    work_performed: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="Detailed scope the worker carried out.",
    )
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    county_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("counties.id", ondelete="SET NULL"), nullable=True
    )
    trade_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("trades.id", ondelete="SET NULL"), nullable=True
    )
    start_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    is_confidential: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        doc="Client or site confidentiality requested by the worker.",
    )

    worker_profile: Mapped[WorkerProfile] = relationship(back_populates="projects")
    trade: Mapped[Trade | None] = relationship()
    evidence: Mapped[list[EvidenceItem]] = relationship(back_populates="project")


class Credential(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A professional credential, certificate or licence the worker holds.

    **A credential is not a verification.** Uploading a certificate records that
    the worker claims to hold it; it never makes the platform assert the
    credential is genuine. Issuing-body confirmation is handled by the
    verification workflow.
    """

    __tablename__ = "credentials"
    __table_args__ = (
        CheckConstraint(
            "expiry_date IS NULL OR issue_date IS NULL OR expiry_date >= issue_date",
            name="credentials_expiry_after_issue",
        ),
        Index("ix_credentials_profile", "worker_profile_id", "deleted_at"),
        Index("ix_credentials_type", "credential_type"),
    )

    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    credential_type: Mapped[str] = mapped_column(
        enum_column_type(CredentialType, name="credential_type"),
        nullable=False,
        default=CredentialType.CERTIFICATE.value,
    )
    issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    issuing_country_code: Mapped[str | None] = mapped_column(
        String(2),
        nullable=True,
        doc="ISO 3166-1 alpha-2. Defaults to KE for the worker's declared origin.",
    )
    credential_number: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
        doc="Reference printed on the document. Never treated as proof.",
    )
    issue_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    expiry_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("files.id", ondelete="SET NULL"),
        nullable=True,
        doc="Optional scanned copy. Authorised access is checked before any URL is issued.",
    )

    worker_profile: Mapped[WorkerProfile] = relationship(back_populates="credentials")
    file: Mapped[FileObject | None] = relationship()


class WorkerReference(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A referee a worker nominates.

    The worker may create and delete a nomination, but **cannot** set
    ``status``. Only the referee responding, or an administrator, can move it.
    That asymmetry is enforced in the service layer and covered by tests.
    """

    __tablename__ = "worker_references"
    __table_args__ = (
        UniqueConstraint("worker_profile_id", "email", name="uq_worker_references_profile_email"),
        Index("ix_worker_references_profile", "worker_profile_id", "deleted_at"),
        Index("ix_worker_references_status", "status"),
        Index("ix_worker_references_invitation", "invitation_token_hash"),
    )

    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )
    full_name: Mapped[str] = mapped_column(String(160), nullable=False)
    relationship_type: Mapped[str] = mapped_column(
        "relationship",
        enum_column_type(ReferenceRelationship, name="reference_relationship"),
        nullable=False,
        default=ReferenceRelationship.SUPERVISOR.value,
        doc=(
            "Named relationship_type rather than relationship because the latter "
            "would shadow sqlalchemy.orm.relationship inside this class body."
        ),
    )
    organization_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    job_title: Mapped[str | None] = mapped_column(String(160), nullable=True)
    phone_number: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        doc="Used only to build the invitation message; never exposed in search.",
    )
    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        doc="Where the confirmation invitation is addressed.",
    )
    status: Mapped[str] = mapped_column(
        enum_column_type(ReferenceStatus, name="reference_status"),
        nullable=False,
        default=ReferenceStatus.PENDING_INVITATION.value,
        doc="Server-controlled. A worker may not set this to CONFIRMED.",
    )
    invitation_token_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        doc="Hash of the single-use confirmation token issued to the referee.",
    )
    invitation_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    invitation_consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    invited_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    response_statement: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="The referee's own words. Editable only by the referee or an admin.",
    )
    responded_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        doc="Set when the referee responded through an authenticated account.",
    )
    is_visible_to_employers: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
        doc="Worker-controlled. A confirmed referee can be hidden from employers.",
    )

    worker_profile: Mapped[WorkerProfile] = relationship(back_populates="references")


class EvidenceItem(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """Binds an uploaded object to what it evidences.

    Visibility is per-evidence and always at most as permissive as the owning
    passport: a PUBLIC passport item can still be PRIVATE evidence.
    """

    __tablename__ = "evidence_items"
    __table_args__ = (
        Index("ix_evidence_items_profile", "worker_profile_id", "deleted_at"),
        Index("ix_evidence_items_project", "project_id"),
        Index("ix_evidence_items_file", "file_id"),
    )

    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )
    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("files.id", ondelete="RESTRICT"),
        nullable=False,
        doc="RESTRICT: the object must be orphaned deliberately, never silently.",
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=True
    )
    work_experience_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("work_experiences.id", ondelete="CASCADE"), nullable=True
    )
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("credentials.id", ondelete="CASCADE"), nullable=True
    )
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    visibility: Mapped[str] = mapped_column(
        enum_column_type(EvidenceVisibility, name="evidence_visibility"),
        nullable=False,
        default=EvidenceVisibility.PRIVATE.value,
    )
    captured_at: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
        doc="When the photo/document was taken, if known. Not the upload time.",
    )

    worker_profile: Mapped[WorkerProfile] = relationship(back_populates="evidence")
    project: Mapped[Project | None] = relationship(back_populates="evidence")
    file: Mapped[FileObject] = relationship()
