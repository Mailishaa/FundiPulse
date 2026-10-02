"""Organizations and their memberships.

An Employer in FundiPulse is a *company*, not a person. Modelling organizations
and memberships separately (rather than one employer profile per account) means
a company can have several users with different powers, and that a user can
belong to more than one company.

Authorisation rule enforced throughout the services: an organization resource
may only be touched by an **active membership** whose role is in the required
set. There is no implicit access from merely holding a ``user_id``.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import MembershipStatus, OrganizationRole
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.models.mixins import SoftDeleteMixin
from app.db.types import enum_column_type

if TYPE_CHECKING:
    from app.db.models.job import Job
    from app.db.models.user import User


class Organization(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A company or contracting entity.

    ``slug`` is the stable, URL-safe public identifier used in links and
    employer-facing references; it is never reused after deletion so historic
    audit records keep resolving.
    """

    __tablename__ = "organizations"
    __table_args__ = (
        UniqueConstraint("slug", name="uq_organizations_slug"),
        Index("ix_organizations_county", "county"),
        Index("ix_organizations_active", "is_active"),
        {"comment": "Employers are organizations; users join via memberships."},
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    industry: Mapped[str | None] = mapped_column(String(120), nullable=True)
    website_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    contact_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    contact_phone: Mapped[str | None] = mapped_column(String(32), nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    county: Mapped[str | None] = mapped_column(String(120), nullable=True)
    county_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("counties.id", ondelete="SET NULL"), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False, server_default="true")
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        doc="Set only by an administrator; never self-asserted.",
    )

    memberships: Mapped[list[OrganizationMembership]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    jobs: Mapped[list[Job]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Organization {self.name!r}>"


class OrganizationMembership(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Links a user to an organization with an organization-scoped role."""

    __tablename__ = "organization_memberships"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_organization_memberships_org_user"),
        Index("ix_org_memberships_user_status", "user_id", "status"),
        {"comment": "Per-organization role; platform role is stored on users.role."},
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(
        enum_column_type(OrganizationRole, name="organization_role"),
        nullable=False,
        default=OrganizationRole.MEMBER.value,
    )
    status: Mapped[str] = mapped_column(
        enum_column_type(MembershipStatus, name="membership_status"),
        nullable=False,
        default=MembershipStatus.ACTIVE.value,
    )
    title: Mapped[str | None] = mapped_column(String(120), nullable=True)
    invited_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    joined_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Set when the membership becomes ACTIVE.",
    )

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships", foreign_keys=[user_id])

    @property
    def organization_role_enum(self) -> OrganizationRole:
        return OrganizationRole(self.role)

    @property
    def membership_status_enum(self) -> MembershipStatus:
        return MembershipStatus(self.status)
