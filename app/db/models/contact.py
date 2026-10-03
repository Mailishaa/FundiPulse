"""Employer-to-worker contact requests.

The worker controls whether their phone number or email is ever handed over, so
a contact request is a **request**, not a disclosure. An employer states who they
are and which job the interest relates to; the worker accepts, rejects or lets it
lapse. Only on acceptance are the contact details revealed, and only to the
requesting employer's authorised members.

Kept in its own module rather than beside the worker profile because the ownership
is inverted: the worker profile owns this row, but the *requester* is an
organisation member, and the interesting rule (a requester from another
organisation can never see or answer it) is about the organisation.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import ContactRequestStatus
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.models.mixins import SoftDeleteMixin
from app.db.types import enum_column_type

if TYPE_CHECKING:
    from app.db.models.organization import Organization
    from app.db.models.user import User
    from app.db.models.worker import WorkerProfile


class ContactRequest(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """One employer's interest in contacting one worker."""

    __tablename__ = "contact_requests"
    __table_args__ = (
        UniqueConstraint(
            "requester_user_id",
            "worker_profile_id",
            "job_id",
            name="uq_contact_requests_requester_worker_job",
        ),
        # A requester may have one *live* request per worker. The partial index
        # makes "one pending request" a database invariant rather than something
        # a service has to check for races: a second concurrent insert loses.
        Index(
            "uq_contact_requests_one_pending_per_worker",
            "worker_profile_id",
            "requester_user_id",
            unique=True,
            postgresql_where="status = 'PENDING' AND deleted_at IS NULL",
        ),
        Index("ix_contact_requests_worker_status", "worker_profile_id", "status"),
        Index("ix_contact_requests_requester", "requester_user_id", "created_at"),
        CheckConstraint(
            "status <> 'ACCEPTED' OR responded_at IS NOT NULL",
            name="contact_requests_accepted_needs_response",
        ),
        CheckConstraint(
            "status <> 'REJECTED' OR responded_at IS NOT NULL",
            name="contact_requests_rejected_needs_response",
        ),
        CheckConstraint(
            "status <> 'CANCELLED' OR responded_at IS NOT NULL",
            name="contact_requests_cancelled_needs_response",
        ),
        CheckConstraint(
            "length(trim(message)) BETWEEN 1 AND 1000",
            name="contact_requests_message_length",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    worker_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=False
    )

    #: The employer-side user who asked. Not the organisation: the row records
    #: who to answer to, while ``organization_id`` records who is accountable.
    requester_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    #: Optional: contact requests need not relate to a specific vacancy.
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[str] = mapped_column(
        enum_column_type(ContactRequestStatus, name="contact_request_status"),
        nullable=False,
    )
    message: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: The worker's reply. Written once, on accept or reject.
    response_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: Set when the worker accepts, and false otherwise. Kept as a stored fact
    #: rather than derived from ``status`` so a query can filter on disclosure
    #: without a join, and so an audit of "was this ever disclosed" survives a
    #: later status correction.
    contact_details_shared: Mapped[bool] = mapped_column(nullable=False)

    worker: Mapped[WorkerProfile] = relationship(
        "WorkerProfile", foreign_keys=[worker_profile_id], lazy="joined"
    )
    requester: Mapped[User] = relationship("User", foreign_keys=[requester_user_id])
    organization: Mapped[Organization] = relationship(
        "Organization", foreign_keys=[organization_id]
    )

    @property
    def is_pending(self) -> bool:
        return self.status == ContactRequestStatus.PENDING
