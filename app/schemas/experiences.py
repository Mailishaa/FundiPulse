"""Schemas for work experience records."""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Self
import uuid

from pydantic import Field, model_validator

from app.core.constants import MAX_DESCRIPTION_LENGTH, MAX_NOTES_LENGTH, MAX_SHORT_TEXT
from app.schemas.common import (
    PaginatedResponseEnvelope,
    RequestSchema,
    ResponseSchema,
    TimestampMixinSchema,
)
from app.utils.dates import utc_today

TradeCode = Annotated[str, Field(min_length=2, max_length=50, pattern=r"^[A-Z][A-Z0-9_]*$")]
CountyCode = Annotated[str, Field(min_length=2, max_length=32, pattern=r"^[A-Z][A-Z0-9_]*$")]


class WorkExperienceBase(RequestSchema):
    """Fields shared by create and update."""

    employer_name: Annotated[str, Field(min_length=2, max_length=MAX_SHORT_TEXT)]
    role_title: Annotated[str, Field(min_length=2, max_length=160)]
    trade_code: TradeCode | None = None
    description: Annotated[str, Field(max_length=MAX_DESCRIPTION_LENGTH)] | None = None
    start_date: date
    location: Annotated[str, Field(max_length=MAX_SHORT_TEXT)] | None = None
    county_code: CountyCode | None = None

    @model_validator(mode="after")
    def _validate_dates(self) -> Self:
        """Dates must be coherent and not in the future."""
        today = utc_today()
        if self.start_date > today:
            raise ValueError("start_date cannot be in the future.")
        return self

    def _check_range(self, end_date: date | None, is_current: bool) -> None:
        """Shared end-date rules for create and update."""
        today = utc_today()
        if end_date is not None:
            if end_date > today:
                raise ValueError("end_date cannot be in the future.")
            if end_date < self.start_date:
                raise ValueError("end_date cannot be earlier than start_date.")
        if end_date is None and not is_current:
            raise ValueError("Provide end_date, or set is_current=true for a role you still hold.")
        if end_date is not None and is_current:
            raise ValueError("A role with an end_date is not current; set is_current=false.")


class WorkExperienceCreateRequest(WorkExperienceBase):
    """Create an experience record on the caller's own passport."""

    project_name: Annotated[str, Field(max_length=MAX_SHORT_TEXT)] | None = None
    end_date: date | None = None
    is_current: bool = False

    @model_validator(mode="after")
    def _validate_range(self) -> Self:
        self._check_range(self.end_date, self.is_current)
        return self


class WorkExperienceUpdateRequest(RequestSchema):
    """Partial update."""

    employer_name: Annotated[str, Field(min_length=2, max_length=MAX_SHORT_TEXT)] | None = None
    role_title: Annotated[str, Field(min_length=2, max_length=160)] | None = None
    trade_code: TradeCode | None = None
    project_name: Annotated[str, Field(max_length=MAX_SHORT_TEXT)] | None = None
    description: Annotated[str, Field(max_length=MAX_DESCRIPTION_LENGTH)] | None = None
    start_date: date | None = None
    end_date: date | None = None
    is_current: bool | None = None
    location: Annotated[str, Field(max_length=MAX_SHORT_TEXT)] | None = None
    county_code: CountyCode | None = None

    @model_validator(mode="after")
    def _validate_dates(self) -> Self:
        today = utc_today()
        for label, value in (("start_date", self.start_date), ("end_date", self.end_date)):
            if value is not None and value > today:
                raise ValueError(f"{label} cannot be in the future.")
        if (
            self.start_date is not None
            and self.end_date is not None
            and self.end_date < self.start_date
        ):
            raise ValueError("end_date cannot be earlier than start_date.")
        if self.end_date is not None and self.is_current is True:
            raise ValueError("A role with an end_date is not current.")
        return self


class TradeRefInExperience(ResponseSchema):
    """Minimal trade reference; avoids leaking catalogue internals."""

    code: str
    name: str


class CountyRefInExperience(ResponseSchema):
    code: str
    name: str


class VerificationBadgeResponse(ResponseSchema):
    """Factual verification metadata for one claim."""

    verification_type: str
    verification_status: str
    verified_at: datetime | None = None
    verified_by: str | None = Field(
        default=None, description="How the verifier is named to the worker."
    )
    verifier_relationship: str | None = None


class WorkExperienceResponse(TimestampMixinSchema):
    """An experience record."""

    id: uuid.UUID
    employer_name: str
    project_name: str | None = None
    role_title: str
    description: str | None = None
    trade: TradeRefInExperience | None = None
    county: CountyRefInExperience | None = None
    location: str | None = None
    start_date: date
    end_date: date | None = None
    is_current: bool
    verification: VerificationBadgeResponse | None = None
    #: Always false. A record cannot be deleted while verifications reference it;
    #: the service soft-deletes instead so history stays resolvable.
    is_deletable: bool = True


class WorkExperienceListResponse(PaginatedResponseEnvelope[WorkExperienceResponse]):
    """Paginated experience records."""


class WorkExperienceNotesRequest(RequestSchema):
    """Free-text note an administrator attaches during review."""

    notes: Annotated[str, Field(min_length=1, max_length=MAX_NOTES_LENGTH)]


class DerivedExperienceResponse(ResponseSchema):
    """Computed experience, never stored as an authoritative field."""

    total_years: float = Field(description="Years from the union of dated records.")
    completed_years: float
    current_years: float
    record_count: int
    current_record_count: int
    earliest_start: date | None = None
    latest_end: date | None = None
