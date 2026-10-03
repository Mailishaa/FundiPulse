"""Let an EXTERNAL job reach OPEN without an organization.

The original constraint was ``status = 'DRAFT' OR organization_id IS NOT NULL``,
which enforces that a published job has an identifiable owner. That is right for
a platform listing and wrong for an aggregated one: an external job's owner is its
source, not an employer, so the constraint made it impossible to ever publish one.
Externally sourced vacancies are exactly the ones a worker most needs to see.

The intent is preserved and made explicit - a ``PLATFORM`` job still cannot reach
OPEN, OPEN, CLOSED, CANCELLED or EXPIRED without an ``organization_id``.

Revision ID: 5a1d9f4c2b80
Revises: 36eb48c08ad4
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "5a1d9f4c2b80"
down_revision: str | None = "36eb48c08ad4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Fully qualified: the project's naming convention
#: ``ck_%(table_name)s_%(constraint_name)s`` is applied to the model attribute, so
#: the stored name carries the prefix twice. ``op.f()`` stops a third application.
CONSTRAINT = "ck_jobs_jobs_published_requires_organization"

PLATFORM_WITHOUT_OWNER = "SELECT count(*) FROM jobs WHERE organization_id IS NULL AND source_type <> 'EXTERNAL' AND status <> 'DRAFT'"


def upgrade() -> None:
    # Refuse rather than silently drop: if any row exists, a platform listing is
    # published with no owner, and the tightened rule below would reject it.
    orphan = bind_scalar(PLATFORM_WITHOUT_OWNER)
    if orphan:
        raise RuntimeError(
            f"cannot tighten jobs_published_requires_organization: {orphan} non-DRAFT "
            "job(s) have no organization and are not EXTERNAL. Fix them first."
        )

    op.drop_constraint(op.f(CONSTRAINT), "jobs", type_="check")
    op.create_check_constraint(
        op.f(CONSTRAINT),
        "jobs",
        "status = 'DRAFT' OR organization_id IS NOT NULL OR source_type = 'EXTERNAL'",
    )


def downgrade() -> None:
    # Rows that only became valid because of the carve-out would break here, so
    # check rather than let the ALTER fail with a constraint violation.
    external_open = bind_scalar(
        "SELECT count(*) FROM jobs WHERE organization_id IS NULL "
        "AND source_type = 'EXTERNAL' AND status <> 'DRAFT'"
    )
    if external_open:
        raise RuntimeError(
            f"cannot restore the previous constraint: {external_open} EXTERNAL job(s) "
            "are published without an organization. Close them or set an owner first."
        )
    op.drop_constraint(op.f(CONSTRAINT), "jobs", type_="check")
    op.create_check_constraint(
        op.f(CONSTRAINT), "jobs", "status = 'DRAFT' OR organization_id IS NOT NULL"
    )


def bind_scalar(sql: str) -> int:
    """Run a scalar query on the migration's connection."""
    result = op.get_bind().execute(text(sql))
    row = result.fetchone()
    return int(row[0]) if row and row[0] is not None else 0
