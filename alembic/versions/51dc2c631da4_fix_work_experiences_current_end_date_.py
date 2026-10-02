"""Fix the work_experiences current/end_date consistency check.

The original constraint was ``(end_date IS NULL) != is_current``, which rejects
the *valid* case: a current role has no end date and ``is_current = true``, so
the expression evaluates to ``true != true`` = false. Every "I currently work
here" record was therefore rejected by the database while passing application
validation - the core worker flow was broken at the schema layer.

Corrected to equality, which expresses "exactly one of is_current / end_date is
set" as an agreement between the two.

Alembic's autogenerate cannot diff CHECK-constraint expressions, so this is
written by hand. Data is repaired first: the broken constraint previously forced
``is_current`` to be the exact inverse of "has an end date", so any row that
survived is already consistent; the repair is defensive and idempotent.

Revision ID: 51dc2c631da4
Revises: 19e2bb154733
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "51dc2c631da4"
down_revision: str | None = "19e2bb154733"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Fully qualified name. The project naming convention
#: ``ck_%(table_name)s_%(constraint_name)s`` is applied to the model attribute,
#: so the stored name carries the prefix twice - hence the literal here plus
#: ``op.f()`` below, which stops Alembic applying it a third time.
CONSTRAINT = "ck_work_experiences_work_experiences_current_matches_end_date"


def upgrade() -> None:
    op.execute(f"ALTER TABLE work_experiences DROP CONSTRAINT IF EXISTS {CONSTRAINT}")

    # Defensive repair: align is_current with the presence of an end date.
    op.execute(
        "UPDATE work_experiences SET is_current = (end_date IS NULL) "
        "WHERE is_current <> (end_date IS NULL)"
    )

    op.create_check_constraint(
        op.f(CONSTRAINT),
        "work_experiences",
        "(end_date IS NULL) = is_current",
    )


def downgrade() -> None:
    op.drop_constraint(op.f(CONSTRAINT), "work_experiences", type_="check")
    op.create_check_constraint(
        op.f(CONSTRAINT),
        "work_experiences",
        "(end_date IS NULL) != is_current",
    )

    # Restore what the broken constraint used to enforce.
    op.execute(
        "UPDATE work_experiences SET is_current = false "
        "WHERE end_date IS NOT NULL AND is_current"
    )