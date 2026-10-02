"""Schemas for documented construction projects."""

from __future__ import annotations

from datetime import date
from typing import Annotated, Self
import uuid

from pydantic import Field, field_validator, model_validator

from app.core.constants import (
    MAX_BIO_LENGTH,
    MAX_DESCRIPTION_LENGTH,
    MAX_NOTES_LENGTH,
    MAX_SHORT_TEXT,
)
from app.schemas.common import (
    PaginatedResponseEnvelope,
    RequestSchema,
    ResponseSchema,
    TimestampMixinSchema,
)
from app.schemas.experiences import VerificationBadgeResponse
from app.utils.dates import utc_today

TradeCode = Annotated[str, Field(min_length=2, max_length=50, pattern=r"^[A-Z][A-Z0-9_]*$")]
CountyCode = Annotated[str, Field(min_length=2, max_length=32, pattern=r"^[A-Z][A-Z0-9_]*$")]

#: Controlled project-type vocabulary. A free-text field would make the taxonomy
#: unusable for matching, which is the whole point of recording it.
PROJECT_TYPES: tuple[str, ...] = (
    "RESIDENTIAL",
    "COMMERCIAL",
    "INDUSTRIAL",
    "INFRASTRUCTURE",
    "ROADWORKS",
    "BRIDGE",
    "WATER_AND_SANITATION",
    "RENOVATION",
    "EARTHWORKS",
    "LANDSCAPING",
    "PUBLIC_BUILDING",
    "HEALTHCARE",
    "EDUCATIONAL",
    "OTHER",
)

ProjectType = Annotated[
    str,
    Field(description="Controlled project type. One of: " + ", ".join(PROJECT_TYPES)),
]


def _validate_project_type(value: str) -> str:
    upper = value.strip().upper()
    if upper not in PROJECT_TYPES:
        raise ValueError(f"project_type must be one of: {', '.join(PROJECT_TYPES)}")
    return upper


class ProjectBase(RequestSchema):
    name: Annotated[str, Field(min_length=2, max_length=MAX_SHORT_TEXT)]
    role_title: Annotated[
        str,
        Field(
            min_length=2,
            max_length=160,
            description="The worker's own role on this project. Mandatory by design.",
        ),
    ]
    project_type: ProjectType | None = None
    description: Annotated[str, Field(max_length=MAX_DESCRIPTION_LENGTH)] | None = None
    work_performed: (
        Annotated[
            str,
            Field(
                max_length=MAX_BIO_LENGTH,
                description="The scope the worker personally carried out.",
            ),
        ]
        | None
    ) = None
    trade_code: TradeCode | None = None
    county_code: CountyCode | None = None
    location: Annotated[str, Field(max_length=MAX_SHORT_TEXT)] | None = None
    is_confidential: bool = False
    start_date: date | None = None
    end_date: date | None = None

    @field_validator("project_type")
    @classmethod
    def _check_type(cls, value: str | None) -> str | None:
        return _validate_project_type(value) if value is not None else None

    @model_validator(mode="after")
    def _validate_dates(self) -> Self:
        """Reject future dates and an inverted range."""
        if self.start_date is not None and self.start_date > utc_today():
            raise ValueError("start_date cannot be in the future.")
        if self.end_date is not None and self.end_date > utc_today():
            raise ValueError("end_date cannot be in the future.")
        if (
            self.start_date is not None
            and self.end_date is not None
            and self.end_date < self.start_date
        ):
            raise ValueError("end_date cannot be earlier than start_date.")
        return self


class ProjectCreateRequest(ProjectBase):
    @model_validator(mode="after")
    def _validate_range(self) -> Self:
        if self.start_date and self.end_date and self.end_date < self.start_date:
            raise ValueError("end_date cannot be earlier than start_date.")
        return self


class ProjectUpdateRequest(RequestSchema):
    """Partial update. Dates are re-validated against the stored record."""

    name: Annotated[str, Field(min_length=2, max_length=MAX_SHORT_TEXT)] | None = None
    role_title: Annotated[str, Field(min_length=2, max_length=160)] | None = None
    project_type: ProjectType | None = None
    description: Annotated[str, Field(max_length=MAX_DESCRIPTION_LENGTH)] | None = None
    work_performed: Annotated[str, Field(max_length=MAX_BIO_LENGTH)] | None = None
    trade_code: TradeCode | None = None
    county_code: CountyCode | None = None
    location: Annotated[str, Field(max_length=MAX_SHORT_TEXT)] | None = None
    start_date: date | None = None
    end_date: date | None = None
    is_confidential: bool | None = None

    @field_validator("project_type")
    @classmethod
    def _check_type(cls, value: str | None) -> str | None:
        return _validate_project_type(value) if value is not None else None

    @model_validator(mode="after")
    def _validate_dates(self) -> Self:
        for label, value in (("start_date", self.start_date), ("end_date", self.end_date)):
            if value is not None and value > utc_today():
                raise ValueError(f"{label} cannot be in the future.")
        if (
            self.start_date is not None
            and self.end_date is not None
            and self.end_date < self.start_date
        ):
            raise ValueError("end_date cannot be earlier than start_date.")
        return self


class ProjectRefResponse(ResponseSchema):
    """A project reference, for inclusion inside a verification request."""

    id: uuid.UUID
    name: str
    role_title: str
    project_type: str | None = None


class ProjectResponse(TimestampMixinSchema):
    """A documented project."""

    id: uuid.UUID
    name: str
    role_title: str
    project_type: str | None = None
    description: str | None = None
    work_performed: str | None = None
    trade_code: str | None = None
    trade_name: str | None = None
    county_code: str | None = None
    county_name: str | None = None
    location: str | None = None
    start_date: date | None = None
    end_date: date | None = None
    is_confidential: bool
    verification: VerificationBadgeResponse | None = None
    evidence_count: int = 0


class ProjectListResponse(PaginatedResponseEnvelope[ProjectResponse]):
    """Paginated projects."""


class ProjectNotesRequest(RequestSchema):
    """Administrator-only note attached during review."""

    notes: Annotated[str, Field(min_length=1, max_length=MAX_NOTES_LENGTH)]


class ProjectStatsResponse(ResponseSchema):
    """Factual project counts. Not a quality score - see ADR 0010."""

    total_projects: int
    verified_projects: int
    projects_with_evidence: int
    confidential_projects: int
    projects_by_type: dict[str, int] = Field(default_factory=dict)
