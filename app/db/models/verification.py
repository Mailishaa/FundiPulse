"""Verification requests and the immutable verification record.

This is the security-critical part of the product, so the invariants are stated
explicitly and each one is backed by both a service-layer check and a test:

1. **A worker cannot verify themselves.** ``VerificationRequest`` records who
   asked; ``Verification`` records who answered. The service layer refuses any
   response whose verifier is the requesting worker, and that refusal is itself
   audited.
2. **Verification is a third-party assertion, not a guarantee.** The API returns
   ``verified_by``, ``verified_at``, ``verification_type`` and
   ``verification_status`` - factual metadata only. No endpoint ever returns a
   "trusted", "certified" or "guaranteed" flag.
3. **Requests do not duplicate.** A partial unique index permits at most one
   ``PENDING`` request per target, which closes the check-then-insert race that
   a naive ``if not exists()`` would leave open.
4. **Records transition, they do not vanish.** Verification rows are updated
   through explicit state transitions (including ``REVOKED``) and are never
   deleted; deletions are refused at the service layer.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import (
    VerificationRequestStatus,
    VerificationStatus,
    VerificationTargetType,
)
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import enum_column_type, inet_column

if TYPE_CHECKING:
    from app.db.models.worker import WorkerProfile


class VerificationRequest(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A worker's request that a third party confirm a specific claim."""

    __tablename__ = "verification_requests"
    __table_args__ = (
        # At most one in-flight request per target. This is the race-safe
        # substitute for "SELECT then INSERT" in the service layer.
        Index(
            "uq_verification_requests_one_pending_per_target",
            "target_type",
            "target_id",
            unique=True,
            postgresql_where=text("status = 'PENDING'"),
        ),
        Index("ix_verification_requests_worker", "worker_profile_id", "status"),
        Index("ix_verification_requests_invitee", "verifier_email"),
        Index("ix_verification_requests_invitation_token", "invitation_token_hash"),
    )

    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        doc="Always the worker. Retained separately from the profile for audit.",
    )
    target_type: Mapped[str] = mapped_column(
        enum_column_type(VerificationTargetType, name="verification_target_type"),
        nullable=False,
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        nullable=False,
        doc="UUID of the project/experience/skill/credential/reference being verified.",
    )
    target_label: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        doc="Snapshot of the claim's label at request time, for verifier context.",
    )
    target_snapshot: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="Immutable JSON snapshot of the claim as the verifier will see it.",
    )

    verifier_email: Mapped[str] = mapped_column(String(320), nullable=False)
    verifier_full_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    verifier_organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        doc="Set when the verifier belongs to a FundiPulse organization.",
    )
    verifier_relationship: Mapped[str | None] = mapped_column(
        String(160),
        nullable=True,
        doc="How the verifier knows the worker, e.g. 'Foreman at ABC Builders'.",
    )
    message: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(
        enum_column_type(VerificationRequestStatus, name="verification_request_status"),
        nullable=False,
        default=VerificationRequestStatus.PENDING.value,
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, doc="When the request was created."
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        doc="Server-enforced deadline; expiry is decided by the server, not the client.",
    )
    responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    responded_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        doc="NULL when the verifier responded via a single-use invitation token.",
    )
    response_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    invitation_token_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        doc="SHA-256 of the single-use token mailed to the verifier.",
    )
    invitation_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    invitation_consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    request_ip: Mapped[str | None] = inet_column()

    worker_profile: Mapped[WorkerProfile] = relationship(back_populates="verification_requests")
    verification: Mapped[Verification | None] = relationship(
        back_populates="request",
        uselist=False,
        cascade="all, delete-orphan",
    )

    @property
    def status_enum(self) -> VerificationRequestStatus:
        return VerificationRequestStatus(self.status)


class Verification(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The factual record of one completed verification.

    Append-oriented: a completed verification is revoked by transitioning to
    ``REVOKED`` (which records who and when), never by deleting the row, so the
    history of what was once asserted remains inspectable.
    """

    __tablename__ = "verifications"
    __table_args__ = (
        UniqueConstraint("verification_request_id", name="uq_verifications_request_id"),
        CheckConstraint(
            "(status = 'REVOKED') OR revoked_at IS NULL",
            name="verifications_revoked_at_consistent",
        ),
        CheckConstraint(
            "verified_by_user_id IS NULL OR verified_by_user_id <> requested_by_user_id",
            name="verifications_no_self_verification",
        ),
        Index("ix_verifications_worker", "worker_profile_id", "status"),
        Index("ix_verifications_target", "target_type", "target_id"),
    )

    verification_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("verification_requests.id", ondelete="CASCADE"), nullable=False
    )
    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        doc="Copied from the request so the no-self-verification rule is enforced in the row itself.",
    )
    target_type: Mapped[str] = mapped_column(
        enum_column_type(VerificationTargetType, name="verification_target_type"),
        nullable=False,
        doc=(
            "What kind of claim this covers: PROJECT, EXPERIENCE, SKILL, "
            "CREDENTIAL or REFERENCE. This single column is both the verification "
            "type and the record type - they were previously duplicated."
        ),
    )
    target_id: Mapped[uuid.UUID] = mapped_column(nullable=False)

    status: Mapped[str] = mapped_column(
        enum_column_type(VerificationStatus, name="verification_status"),
        nullable=False,
    )
    verified_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        doc="Account of the verifier; NULL when they responded via invitation token.",
    )
    verifier_display_name: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
        doc="How the verifier is named to the worker and to employers.",
    )
    verifier_organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    verifier_relationship: Mapped[str | None] = mapped_column(String(160), nullable=True)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Optional re-confirmation horizon. NULL means it does not expire.",
    )
    evidence_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="What the verifier relied on. No document bodies are stored here.",
    )
    response_statement: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_visible_to_employers: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
        doc="Worker-controlled presentation choice; the record itself is factual.",
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoked_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)

    request: Mapped[VerificationRequest] = relationship(back_populates="verification")

    @property
    def is_current(self) -> bool:
        """Whether this verification is currently being asserted."""
        return self.status == VerificationStatus.VERIFIED.value
