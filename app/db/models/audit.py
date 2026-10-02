"""Append-only audit trail.

``audit_logs`` is insert-only. That is enforced in two independent places:

* the application exposes no update or delete path, and
* the initial migration installs a PostgreSQL trigger that raises on ``UPDATE``
  or ``DELETE``, so even a direct ``psql`` session cannot rewrite history.

Metadata is stored as JSONB but is written through
:func:`app.services.audit_service.build_metadata`, which redacts known-sensitive
keys. Nothing here stores passwords, tokens, object URLs or private documents.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
import uuid

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import AuditAction
from app.db.base import Base, UUIDPrimaryKeyMixin
from app.db.types import enum_column_type, inet_column

if TYPE_CHECKING:
    from app.db.models.user import User


class AuditLog(Base, UUIDPrimaryKeyMixin):
    """One recorded security-relevant event."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_actor_created", "actor_user_id", "created_at"),
        Index("ix_audit_logs_action_created", "action", "created_at"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_request_id", "request_id"),
    )

    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        doc="NULL for anonymous or system-originated events.",
    )
    actor_role: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        doc="Role captured at event time, so a later role change cannot rewrite it.",
    )
    action: Mapped[str] = mapped_column(
        enum_column_type(AuditAction, name="audit_action"),
        nullable=False,
        doc="Database-constrained vocabulary; adding one requires a migration.",
    )
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = inet_column()
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
        doc="Redacted structured context. Never secrets, tokens or document bodies.",
    )
    outcome: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        doc="SUCCESS | FAILURE | DENIED - distinguishes an attempt from an effect.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        doc="Event time. Written explicitly so it cannot be tampered with later.",
    )

    actor: Mapped[User | None] = relationship()

    @property
    def action_enum(self) -> AuditAction:
        return AuditAction(self.action)
