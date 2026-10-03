"""Make the EXTERNAL carve-out on jobs reachable.

Migration ``5a1d9f4c2b80`` changed ``jobs_published_requires_organization`` to allow a
published listing with no ``organization_id`` by testing ``source_type = 'EXTERNAL'``.

There is no ``EXTERNAL`` member of ``JobSourceType``. The externally sourced values
are ``EMPLOYER_SUBMITTED``, ``AGGREGATED_PUBLIC`` and ``PARTNER_FEED``, and the
enum's own docstring states that every value other than ``PLATFORM`` is externally
sourced. So the predicate matched no row: the constraint stayed exactly as strict
as before, and an aggregated listing could never reach ``OPEN`` without an employer
falsely attached to it.

Tested against the enum rather than a literal, so a future member cannot silently
fall back into the strict branch.

Revision ID: d41f8b6c0e37
Revises: c93e7b2d41af
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "d41f8b6c0e37"
down_revision: str | None = "c93e7b2d41af"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CONSTRAINT = "ck_jobs_jobs_published_requires_organization"


def upgrade() -> None:
    op.drop_constraint(op.f(CONSTRAINT), "jobs", type_="check")
    op.create_check_constraint(
        op.f(CONSTRAINT),
        "jobs",
        # `<> 'PLATFORM'` rather than `= 'EXTERNAL'`: PLATFORM is the one value that
        # means "an employer on this platform published this", and every other
        # member of JobSourceType is externally sourced.
        "status = 'DRAFT' OR organization_id IS NOT NULL OR source_type <> 'PLATFORM'",
    )


def downgrade() -> None:
    op.drop_constraint(op.f(CONSTRAINT), "jobs", type_="check")
    op.create_check_constraint(
        op.f(CONSTRAINT),
        "jobs",
        "status = 'DRAFT' OR organization_id IS NOT NULL",
    )
