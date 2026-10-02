"""User reports and the notification outbox.

Both tables are deliberately narrow:

* :class:`Report` exists so workers, employers and jobs can be reported for
  fraud or misleading information, with administrator review as the only path to
  a resolution. Workers cannot report their own content, and a reporter cannot
  file the same report twice (unique constraint).
* :class:`NotificationEvent` is an **outbox**, not a delivery system. Domain
  services append an event; a future worker would read and deliver it over SMS,
  WhatsApp or push. No delivery channel exists in this milestone, and no
  endpoint dispenses with SMS or WhatsApp.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import (
    NotificationEventType,
    ReportReason,
    ReportStatus,
    ReportSubjectType,
)
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import enum_column_type

if TYPE_CHECKING:
    from app.db.models.user import User


class Report(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A report raised against platform content or an account."""

    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint(
            "reporter_user_id",
            "subject_type",
            "subject_id",
            name="uq_reports_reporter_subject",
        ),
        Index("ix_reports_status", "status", "created_at"),
        Index("ix_reports_subject", "subject_type", "subject_id"),
    )

    reporter_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    subject_type: Mapped[str] = mapped_column(
        enum_column_type(ReportSubjectType, name="report_subject_type"), nullable=False
    )
    subject_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    reason: Mapped[str] = mapped_column(
        enum_column_type(ReportReason, name="report_reason"), nullable=False
    )
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        enum_column_type(ReportStatus, name="report_status"),
        nullable=False,
        default=ReportStatus.OPEN.value,
        doc="Only an administrator may transition this.",
    )
    resolved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    reporter: Mapped[User] = relationship(foreign_keys=[reporter_user_id])
    resolver: Mapped[User | None] = relationship(foreign_keys=[resolved_by_user_id])


class NotificationEvent(Base, UUIDPrimaryKeyMixin):
    """An append-only record of something the user should eventually be told.

    Writing to this table must not fail the business transaction that produced
    it, so it is intentionally separate from domain tables and is flushed in the
    same transaction without any external side effect.
    """

    __tablename__ = "notification_events"
    __table_args__ = (
        CheckConstraint(
            "user_id IS NOT NULL OR recipient_email IS NOT NULL",
            name="notification_events_has_recipient",
        ),
        Index("ix_notification_events_recipient", "user_id", "created_at"),
        Index("ix_notification_events_unprocessed", "processed_at", "event_type"),
    )

    event_type: Mapped[str] = mapped_column(
        enum_column_type(NotificationEventType, name="notification_event_type"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    recipient_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    worker_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("worker_profiles.id", ondelete="CASCADE"), nullable=True
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), nullable=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
        doc="Template variables only. Must contain no secrets or document data.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
