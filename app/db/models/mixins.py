"""Shared model mixins: soft deletion and row-version locking."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, text
from sqlalchemy.orm import Mapped, mapped_column


class SoftDeleteMixin:
    """Adds a ``deleted_at`` tombstone column.

    Soft deletion is used only where retention has an audit or legal rationale
    (worker passports, references, credentials, evidence, organizations).
    It is deliberately *not* used for audit logs, verification records or job
    applications, which are append-oriented.
    """

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        index=True,
        doc="UTC timestamp at which the record was soft deleted; NULL means live.",
    )

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


class VersionMixin:
    """Adds a monotonically increasing ``version`` for optimistic concurrency.

    Used where a lost update would be materially harmful, such as an employer
    editing the same job concurrently.
    """

    version: Mapped[int] = mapped_column(
        default=1,
        server_default=text("1"),
        nullable=False,
    )
