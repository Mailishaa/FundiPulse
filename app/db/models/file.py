"""File metadata.

**No file bytes are stored in PostgreSQL.** This table records metadata only;
the object itself lives in private object storage and is reached exclusively
through short-lived, single-purpose signed URLs that the API issues *after* an
authorisation check.

Key properties:

* ``object_key`` is generated server-side from a UUID and extension derived from
  the *validated* content type. A user-supplied filename never influences a
  storage path, which is what removes path traversal as a class of bug.
* ``original_filename`` is retained only for display, sanitised, and never used
  to build a path or set a response ``Content-Disposition`` verbatim.
* ``scan_status`` defaults to ``PENDING``. When malware scanning is disabled the
  upload path writes ``CLEAN`` explicitly; when it is enabled, objects stay
  quarantined until a scanner clears them.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import FilePurpose, ScanStatus
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.models.mixins import SoftDeleteMixin
from app.db.types import enum_column_type

if TYPE_CHECKING:
    from app.db.models.user import User


class FileObject(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """Metadata for one stored object."""

    __tablename__ = "files"
    __table_args__ = (
        UniqueConstraint("object_key", name="uq_files_object_key"),
        CheckConstraint(
            "size_bytes > 0 AND size_bytes <= 26214400",
            name="files_size_within_hard_cap",
        ),
        Index("ix_files_owner", "owner_user_id", "deleted_at"),
        Index("ix_files_purpose", "purpose"),
    )

    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    purpose: Mapped[str] = mapped_column(
        enum_column_type(FilePurpose, name="file_purpose"),
        nullable=False,
        default=FilePurpose.WORK_EVIDENCE.value,
    )
    object_key: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        doc="Server-generated storage key. Never derived from user input.",
    )
    bucket: Mapped[str] = mapped_column(String(255), nullable=False)
    original_filename: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        doc="Sanitised display name only. Never used for paths or headers verbatim.",
    )
    content_type: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
        doc="Content type agreed by server-side sniffing, not the client's claim.",
    )
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Integrity hash for deduplication and tamper evidence.",
    )
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    page_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    scan_status: Mapped[str] = mapped_column(
        enum_column_type(ScanStatus, name="scan_status"),
        nullable=False,
        default=ScanStatus.PENDING.value,
    )
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scan_engine: Mapped[str | None] = mapped_column(String(64), nullable=True)

    is_quarantined: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
        doc="Quarantined objects are never downloadable, even to their owner.",
    )
    access_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    last_accessed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="When the byte content was successfully sniffed and validated.",
    )

    owner: Mapped[User] = relationship()

    @property
    def is_downloadable(self) -> bool:
        """Whether the object may be handed out at all.

        An infected or unscanned object is never downloadable. Checking this in
        one place stops an individual endpoint from forgetting it.
        """
        return (
            not self.is_quarantined
            and self.deleted_at is None
            and self.scan_status == ScanStatus.CLEAN.value
        )

    @property
    def extension(self) -> str:
        _, _, suffix = self.object_key.rpartition(".")
        return f".{suffix.lower()}" if suffix else ""
