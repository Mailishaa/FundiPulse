"""Notification inbox: listing, unread counts, read receipts.

Read state is per-recipient and enforced in SQL, not by filtering in Python. A
recipient can only ever see their own rows, and marking someone else's as read
matches nothing rather than succeeding.

``enqueue`` is the write side used by domain services (verification requested,
application shortlisted, contact request received). It appends only — delivery is
a future dispatcher's problem, and nothing here claims a message was sent.
"""

from __future__ import annotations

from typing import Any
import uuid

from sqlalchemy import Select, func, select, update
from sqlalchemy.orm import Session

from app.core.constants import NotificationEventType
from app.core.exceptions import NotFoundError
from app.db.base import utcnow
from app.db.models.notification import Notification


class NotificationNotFoundError(NotFoundError):
    public_message = "The requested notification was not found."


class NotificationService:
    def __init__(self, session: Session) -> None:
        self._session = session

    # -- write side -------------------------------------------------------- #

    def enqueue(
        self,
        *,
        recipient_user_id: uuid.UUID,
        event_type: NotificationEventType,
        title: str,
        body: str,
        related_resource_id: uuid.UUID | None = None,
        related_resource_type: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> Notification:
        """Record that a user has something to be told.

        Factual wording only. A notification says what happened; it must not
        rank, rate or characterise a worker, because a push notification is the
        one surface a user reads without opening anything to check the context.
        """
        notification = Notification(
            recipient_user_id=recipient_user_id,
            event_type=event_type.value,
            title=title[:200],
            body=body,
            related_resource_id=related_resource_id,
            related_resource_type=related_resource_type,
            payload=payload or {},
        )
        self._session.add(notification)
        self._session.flush()
        return notification

    # -- read side --------------------------------------------------------- #

    def list_for(
        self, *, recipient_user_id: uuid.UUID, unread_only: bool, limit: int, offset: int
    ) -> tuple[list[Notification], int]:
        base = self._base(recipient_user_id, unread_only=unread_only)
        total = int(
            self._session.execute(select(func.count()).select_from(base.subquery())).scalar_one()
        )
        rows = (
            self._session.execute(
                base.order_by(Notification.created_at.desc(), Notification.id)
                .limit(limit)
                .offset(offset)
            )
            .scalars()
            .all()
        )
        return list(rows), total

    def unread_count(self, *, recipient_user_id: uuid.UUID) -> int:
        return int(
            self._session.execute(
                select(func.count())
                .select_from(Notification)
                .where(
                    Notification.recipient_user_id == recipient_user_id,
                    Notification.read_at.is_(None),
                )
            ).scalar_one()
        )

    def get(self, *, recipient_user_id: uuid.UUID, notification_id: uuid.UUID) -> Notification:
        """Fetch one, scoped to the recipient. Raises if it is not theirs."""
        row = self._session.execute(
            self._base(recipient_user_id, unread_only=False)
            .where(Notification.id == notification_id)
            .limit(1)
        ).scalar_one_or_none()
        if row is None:
            raise NotificationNotFoundError()
        return row

    def mark_read(self, *, recipient_user_id: uuid.UUID, notification_id: uuid.UUID) -> bool:
        """Mark one as read. ``False`` means no such row for this recipient.

        Scoped in the UPDATE's WHERE rather than read-then-write: a read-then-write
        would report success for a notification that does not exist, and would open
        a window for a concurrent mark to overwrite the timestamp.

        Idempotent, and the timestamp is only set if it was unset, so a client
        retrying after a dropped response keeps the original read time.
        """
        result = self._session.execute(
            update(Notification)
            .where(
                Notification.id == notification_id,
                Notification.recipient_user_id == recipient_user_id,
            )
            .values(read_at=func.coalesce(Notification.read_at, utcnow()))
            .returning(Notification.id)
        )
        self._session.flush()
        return result.scalar_one_or_none() is not None

    def mark_all_read(self, *, recipient_user_id: uuid.UUID) -> int:
        result = self._session.execute(
            update(Notification)
            .where(
                Notification.recipient_user_id == recipient_user_id,
                Notification.read_at.is_(None),
            )
            .values(read_at=utcnow())
            .returning(Notification.id)
        )
        self._session.flush()
        return len(result.all())

    def _base(
        self, recipient_user_id: uuid.UUID, *, unread_only: bool
    ) -> Select[tuple[Notification]]:
        conditions = [Notification.recipient_user_id == recipient_user_id]
        if unread_only:
            conditions.append(Notification.read_at.is_(None))
        return select(Notification).where(*conditions)
