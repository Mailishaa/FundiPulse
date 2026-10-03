"""Restore the server default on ``contact_requests.id``.

``ContactRequest`` originally redeclared ``id``, which silently dropped the
``default`` and ``server_default`` that :class:`UUIDPrimaryKeyMixin` supplies. The
redeclaration was removed because a bare ``mapped_column(primary_key=True)`` has no
default at all, so every insert failed on a NOT NULL violation.

With the override gone the model correctly inherits the mixin's
``server_default=gen_random_uuid()``, which the existing table does not have. That is
exactly the drift ``alembic check`` is for.

Adding the default is strictly safer: an insert that omits ``id`` now succeeds at the
database rather than depending on the application to supply one.

Revision ID: c93e7b2d41af
Revises: 5a1d9f4c2b80
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c93e7b2d41af"
down_revision: str | None = "5a1d9f4c2b80"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "contact_requests",
        "id",
        server_default=sa.text("gen_random_uuid()"),
        existing_type=sa.dialects.postgresql.UUID(as_uuid=True),
        existing_nullable=False,
    )


def downgrade() -> None:
    # Only safe because every existing row already has an id. Do not extend this to
    # a column that is not a primary key: dropping a default on a populated table
    # is how a migration starts failing halfway.
    op.alter_column(
        "contact_requests",
        "id",
        server_default=None,
        existing_type=sa.dialects.postgresql.UUID(as_uuid=True),
        existing_nullable=False,
    )
