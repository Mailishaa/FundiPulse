"""User accounts, refresh-token sessions and single-use security tokens.

Authentication identity is deliberately separated from domain profiles: a
``User`` holds only credentials and platform-level role. A worker's professional
data lives in :class:`~app.db.models.worker.WorkerProfile`; an employer's
company data lives in an organization the user merely belongs to.
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
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import AccountStatus, TokenPurpose, UserRole
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.models.mixins import SoftDeleteMixin
from app.db.types import enum_column_type, inet_column

if TYPE_CHECKING:
    from app.db.models.organization import OrganizationMembership
    from app.db.models.worker import WorkerProfile


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A platform account.

    ``email`` is stored lower-cased and uniquely indexed so that
    ``Worker@Example.com`` and ``worker@example.com`` cannot both register.
    The unique index on the normalised value is what makes registration
    race-safe under concurrent requests.
    """

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
        Index("ix_users_role_active", "role", "is_active"),
        {"comment": "Authentication identity for workers, employers and admins."},
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        doc="Lower-cased, unique login identifier.",
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Argon2id hash. Never serialised by any API schema.",
    )
    role: Mapped[str] = mapped_column(
        enum_column_type(UserRole, name="user_role"),
        nullable=False,
        default=UserRole.WORKER.value,
        doc="Platform-wide role. Authorisation is enforced server-side only.",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    is_email_verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    status: Mapped[str] = mapped_column(
        enum_column_type(AccountStatus, name="account_status"),
        nullable=False,
        default=AccountStatus.ACTIVE.value,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    worker_profile: Mapped[WorkerProfile | None] = relationship(
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    memberships: Mapped[list[OrganizationMembership]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="OrganizationMembership.user_id",
    )

    @property
    def is_locked(self) -> bool:
        from app.db.base import utcnow

        return self.locked_until is not None and self.locked_until > utcnow()


class RefreshSession(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A rotating refresh-token session.

    Only the SHA-256 hash of the refresh token is stored, so a database
    disclosure does not yield usable credentials.

    Rotation and reuse detection work through ``family_id``: every token
    descended from one login shares a family. Presenting an already-rotated
    token means the token was stolen, so the entire family is revoked
    immediately and the event is audited.
    """

    __tablename__ = "refresh_sessions"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_refresh_sessions_token_hash"),
        Index("ix_refresh_sessions_user_active", "user_id", "revoked_at"),
        Index("ix_refresh_sessions_family", "family_id"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    family_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("refresh_sessions.id", ondelete="SET NULL"), nullable=True
    )
    absolute_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        doc="Hard ceiling for the family; rotation cannot extend past this.",
    )
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[str | None] = inet_column()

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


class SecurityToken(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A single-use, hashed, expiring token for password reset / email verify.

    Storing only the hash means a leaked database row cannot be replayed. The
    ``purpose`` column keeps reset and verification tokens in separate
    namespaces so one can never be replayed against the other's endpoint.
    """

    __tablename__ = "security_tokens"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_security_tokens_token_hash"),
        Index("ix_security_tokens_user_purpose", "user_id", "purpose"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    purpose: Mapped[str] = mapped_column(
        enum_column_type(TokenPurpose, name="token_purpose"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    request_ip: Mapped[str | None] = inet_column()

    @property
    def is_consumed(self) -> bool:
        return self.consumed_at is not None
