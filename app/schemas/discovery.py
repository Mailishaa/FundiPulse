"""Worker search: query validation and the result row.

The result type is the privacy boundary for this endpoint. It has no phone,
contact-email, contact-name, national-id or authentication field, so discovery
cannot disclose contact details even if a query is wrong. Adding one would remove
the guarantee that a service bug cannot leak it.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated
import uuid

from pydantic import Field, field_validator

from app.core.constants import (
    MAX_PAGE_NUMBER,
    MAX_PAGE_SIZE,
    MIN_PAGE_SIZE,
    WORKER_SORT_FIELDS,
    AvailabilityStatus,
    ProfileVisibility,
    SkillProficiency,
)
from app.schemas.common import RequestSchema, ResponseSchema


class WorkerSearchQuery(RequestSchema):
    """Filters for ``GET /workers``. All conjunctive.

    A filter naming something absent from the catalogue matches nothing rather than
    being ignored: silently dropping a location filter would return workers the
    caller did not ask to see.
    """

    trade: Annotated[str | None, Field(max_length=50, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")] = None
    skill: Annotated[str | None, Field(max_length=50, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")] = None
    county: Annotated[str | None, Field(max_length=32, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")] = None

    primary_trade: Annotated[
        str | None, Field(max_length=50, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    ] = None

    availability: AvailabilityStatus | None = None
    minimum_experience_years: Annotated[Decimal | None, Field(ge=0, le=80)] = None

    has_verified_experience: bool | None = None
    has_verified_project: bool | None = None
    has_credentials: bool | None = None

    sort: str = "recently_updated"
    page: Annotated[int, Field(ge=1, le=MAX_PAGE_NUMBER)] = 1
    page_size: Annotated[int, Field(ge=MIN_PAGE_SIZE, le=MAX_PAGE_SIZE)] = 20

    @field_validator("sort")
    @classmethod
    def _known_sort(cls, value: str) -> str:
        """Rejected rather than ignored, so a typo cannot silently change ordering.

        There is no ranking sort: ordering by a computed score would reintroduce
        the trust ranking ADR 0010 rules out.
        """
        if value not in WORKER_SORT_FIELDS:
            raise ValueError(f"sort must be one of: {', '.join(sorted(WORKER_SORT_FIELDS))}")
        return value

    @property
    def trade_code(self) -> str | None:
        return _upper(self.trade)

    @property
    def skill_code(self) -> str | None:
        return _upper(self.skill)

    @property
    def county_code(self) -> str | None:
        return _upper(self.county)

    @property
    def primary_trade_code(self) -> str | None:
        return _upper(self.primary_trade)


class SkillSummary(ResponseSchema):
    """A skill on a passport. ``proficiency`` is self-declared, never verified."""

    code: str
    name: str
    proficiency: SkillProficiency | None = None


class WorkerSearchResult(ResponseSchema):
    """One employer-facing search row.

    Factual signals about a passport. There is deliberately no score, rank, rating
    or rating count: a number that reads as "how good is this worker" is exactly
    the unsupported judgment the product brief rules out. ``derived_*`` and
    ``self_declared_*`` experience are reported separately and never substituted for
    one another, and ``verified_*`` counts attestations without vouching for them.
    """

    id: uuid.UUID
    display_name: str
    headline: str | None = None
    visibility: ProfileVisibility

    primary_trade: str | None = Field(default=None, description="Trade code, e.g. MASONRY.")
    trades: list[str] = Field(default_factory=list)
    skills: list[SkillSummary] = Field(default_factory=list)

    county: str | None = Field(default=None, description="County code.")
    preferred_counties: list[str] = Field(default_factory=list)

    availability_status: AvailabilityStatus
    is_open_to_opportunities: bool

    derived_experience_years: Decimal = Field(
        description=(
            "Years from dated records, overlapping roles merged. Never a guarantee "
            "of total experience - a documented record is not a life."
        )
    )
    self_declared_experience_years: Decimal | None = None

    verified_experience_count: int = 0
    verified_project_count: int = 0
    credential_count: int = 0


def _upper(value: str | None) -> str | None:
    return value.upper() if value else None
