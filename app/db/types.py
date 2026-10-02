"""Reusable SQLAlchemy column types and constraint builders.

Centralising these keeps the database-level integrity rules identical across
every table: enums are always ``VARCHAR + CHECK``, and soft deletion is always
the same ``deleted_at`` shape.

Why ``VARCHAR + CHECK`` instead of a native PostgreSQL ``ENUM`` type
-------------------------------------------------------------
Adding a value to a native enum requires ``ALTER TYPE ... ADD VALUE`` inside a
transaction that may not be able to commit (older PostgreSQL), and removing a
value is not possible at all. Since job and verification statuses will
definitely evolve, enums are modelled as bounded ``VARCHAR`` columns with an
explicit CHECK constraint. The trade-off (no storage-level enum typing) is paid
back in migration simplicity and a reversible schema history.

Constraint names are generated per **column**, not per enum type. That matters:
two columns of the same enum in one table (``verifications.target_type`` and
``verifications.verification_type``) would otherwise produce two identically
named CHECK constraints, which PostgreSQL rejects.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import CheckConstraint, Enum as SAEnum, String
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.constants import MAX_SHORT_TEXT
from app.db.base import enum_values

_ENUM_TYPE_CACHE: dict[type[Any], SAEnum] = {}


def enum_column_type(python_enum: type[Any], *, name: str) -> SAEnum:
    """Return a memoised, non-native enum SQL type.

    ``create_constraint`` is deliberately ``False``: the CHECK constraint is
    added separately by :func:`enum_check` so that it can be named after the
    specific column and never collide with a sibling column of the same enum.
    """
    cached = _ENUM_TYPE_CACHE.get(python_enum)
    if cached is not None:
        return cached
    created = SAEnum(
        *enum_values(python_enum),
        name=name,
        native_enum=False,
        create_constraint=False,
        length=64,
        validate_strings=True,
    )
    _ENUM_TYPE_CACHE[python_enum] = created
    return created


def enum_check(table: str, column: str, python_enum: type[Any]) -> CheckConstraint:
    """Build the CHECK constraint restricting ``column`` to enum values.

    Put the result in the table's ``__table_args__``. The name follows the
    project's ``ck_%(table_name)s_%(constraint_name)s`` naming convention so
    Alembic can reference it deterministically.
    """
    allowed = ", ".join(f"'{value}'" for value in enum_values(python_enum))
    return CheckConstraint(
        f"{column} IN ({allowed})",
        name=f"{table}_{column}_valid",
    )


def string_column(
    *,
    length: int = MAX_SHORT_TEXT,
    nullable: bool = False,
    unique: bool = False,
    index: bool = False,
    doc: str | None = None,
) -> Mapped[str]:
    """A bounded, non-nullable-by-default ``VARCHAR`` column."""
    return mapped_column(
        String(length),
        nullable=nullable,
        unique=unique,
        index=index,
        doc=doc,
    )


def text_column(
    *,
    nullable: bool = False,
    doc: str | None = None,
) -> Mapped[str]:
    """A long-form text column."""
    return mapped_column(doc=doc, nullable=nullable)


def jsonb_column(
    *,
    nullable: bool = False,
    doc: str | None = None,
) -> Mapped[dict[str, Any]]:
    """A JSONB column for structured, schema-flexible payloads."""
    return mapped_column(JSONB, nullable=nullable, doc=doc)


def inet_column(
    *,
    nullable: bool = True,
    doc: str | None = None,
) -> Mapped[str | None]:
    """An ``INET`` column. Chosen over text so PostgreSQL validates addresses."""
    return mapped_column(INET, nullable=nullable, doc=doc)


__all__ = [
    "enum_check",
    "enum_column_type",
    "inet_column",
    "jsonb_column",
    "string_column",
    "text_column",
]
