"""The user-facing notification inbox.

Deliberately separate from :class:`~app.db.models.moderation.NotificationEvent`.
That table is an **outbox**: rows a future dispatcher claims, attempts and marks
``processed``. This table is an **inbox**: something the user has not read yet.

Conflating them would make ``read_at`` ambiguous — read by the recipient, or
processed by the dispatcher? — and would force every read receipt to write into the
queue a background worker polls, so a user opening the app would look like
delivery traffic. Two tables, one transaction each, no shared columns beyond the
recipient.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import NotificationEventType
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import enum_column_type


class Notification(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One unread-or-read notice for one recipient."""

    __tablename__ = "notifications"
    __table_args__ = (
        # A badge query is "unread for this user, newest first"; this index serves
        # it without touching the read rows.
        Index(
            "ix_notifications_recipient_unread",
            "recipient_user_id",
            "created_at",
            postgresql_where="read_at IS NULL",
        ),
        Index("ix_notifications_related", "related_resource_type", "related_resource_id"),
    )

    recipient_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(
        enum_column_type(NotificationEventType, name="notification_event_type"),
        nullable=False,
    )

    #: Factual wording. A notification states what happened; it does not rate,
    #: rank or characterise a worker.
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)

    #: Set by the recipient. Null means unread.
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: A UUID plus a type label rather than a path. The client resolves it through
    #: its own domain endpoint, which re-checks authorisation — following a link
    #: embedded in a notification would move the authorisation decision to whatever
    #: the notifier wrote.
    related_resource_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    related_resource_type: Mapped[str | None] = mapped_column(String(40), nullable=True)

    #: Template variables for future channels. No secrets, no document bytes.
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    recipient = relationship("User", foreign_keys=[recipient_user_id])

    @property
    def is_read(self) -> bool:
        return self.read_at is not None
