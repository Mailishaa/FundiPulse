"""Controlled reference data: trades, skills and Kenyan counties.

These are admin-managed catalogues rather than free text. Referential
constraints guarantee that a worker profile, work experience or job can only
ever reference a real trade, skill or county, which in turn makes filtering and
matching deterministic and index-friendly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
import uuid

from sqlalchemy import Boolean, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.db.models.worker import WorkerSkill


class Trade(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A construction trade such as Masonry, Carpentry or Electrical work."""

    __tablename__ = "trades"
    __table_args__ = (
        UniqueConstraint("code", name="uq_trades_code"),
        Index("ix_trades_active", "is_active"),
    )

    code: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        doc="Stable machine key, e.g. MASONRY. Never reused after deactivation.",
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    display_order: Mapped[int] = mapped_column(default=100, nullable=False, server_default="100")

    skills: Mapped[list[Skill]] = relationship(back_populates="trade")

    @property
    def is_usable(self) -> bool:
        """Only active trades may be attached to new or updated records.

        Deactivation is preferred over deletion so historical passports and job
        listings keep a resolvable reference to the trade they were recorded
        against.
        """
        return self.is_active


class Skill(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A specific capability, optionally grouped under a trade."""

    __tablename__ = "skills"
    __table_args__ = (
        UniqueConstraint("code", name="uq_skills_code"),
        Index("ix_skills_trade_active", "trade_id", "is_active"),
    )

    code: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    trade_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("trades.id", ondelete="SET NULL"),
        nullable=True,
        doc="Optional grouping. Skills such as 'Site Supervision' span trades.",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    display_order: Mapped[int] = mapped_column(default=100, nullable=False, server_default="100")

    trade: Mapped[Trade | None] = relationship(back_populates="skills")
    worker_skills: Mapped[list[WorkerSkill]] = relationship(back_populates="skill")


class County(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A Kenyan county.

    Modelled as a table rather than a free-text string so that location filters
    (``GET /workers?county=NAKURU``) use an index and never match on
    user-entered spelling variations such as "Nakuru" vs "nakuru county".
    """

    __tablename__ = "counties"
    __table_args__ = (UniqueConstraint("code", name="uq_counties_code"),)

    code: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="Upper-case short code, e.g. NA KURU -> NAKURU, 047 for Nairobi.",
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    region: Mapped[str | None] = mapped_column(String(80), nullable=True)
    capital: Mapped[str | None] = mapped_column(String(120), nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
