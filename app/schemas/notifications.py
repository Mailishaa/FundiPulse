"""Notification schemas.

``notification_events`` is an **outbox**, not a delivery system. Domain services
append an event; a future worker reads and delivers it over push, SMS or
WhatsApp. No delivery adapter exists yet and none is faked here — a request that
returns "sent" while nothing was sent is worse than one that says "queued".

``read_at`` is the one piece of state a user owns: it records that *this* user saw
the notification. It is deliberately per-recipient rather than per-event, because
an application status change has several recipients and each reads it separately.
"""

from __future__ import annotations

from datetime import datetime
import uuid

from pydantic import Field

from app.core.constants import NotificationEventType
from app.schemas.common import PaginatedResponseEnvelope, ResponseSchema, TimestampMixinSchema


class NotificationResponse(TimestampMixinSchema):
    """One notification for the authenticated recipient."""

    id: uuid.UUID
    #: Named ``type`` on the wire; the column is ``event_type`` because ``type`` is
    #: a SQL keyword-ish name to carry through the model layer. Aliased rather than
    #: duplicated so there is one source of truth for the column name.
    type: NotificationEventType = Field(validation_alias="event_type")
    title: str = Field(description="Short headline, safe to show in a list.")
    body: str = Field(description="Full text. Factual; never a judgement about a worker.")
    read_at: datetime | None = Field(
        default=None, description="When this recipient read it. Null until then."
    )
    is_read: bool
    #: The resource this concerns (an application, a verification, a contact
    #: request). Null for an event with no single related row. A UUID rather than
    #: a path, so a client resolves it through its own domain endpoint and is
    #: authorised there rather than by following a link from a notification.
    related_resource_id: uuid.UUID | None = None
    related_resource_type: str | None = None


class NotificationListResponse(PaginatedResponseEnvelope[NotificationResponse]):
    """Paginated notifications."""


class UnreadCountResponse(ResponseSchema):
    """A single integer, for a badge."""

    unread_count: int = Field(ge=0)
