"""Job listing schemas.

Two kinds of listing exist, and the difference is structural rather than
cosmetic:

* a **platform job** is written by an organization through this API. It always
  names its owning organization and never carries third-party provenance.
* an **external job** was aggregated from somewhere else and is only ever
  *rendered* by this API. Its organization is always ``None`` and its provenance
  block is always populated, so a client has no way to mistake it for something an
  employer posted on FundiPulse.

Only the first kind is writable here, and that is enforced by what the request
schemas are *able* to express:

* there is no ``organization_id`` - it comes from the path and is authorised there;
* there is no ``status``, ``published_at`` or ``created_by_user_id``;
* ``source_type`` is pinned to ``PLATFORM`` and says why. A client that sends
  ``AGGREGATED_PUBLIC`` gets a 422 rather than a listing that would then be
  rendered as if FundiPulse had created it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Self
import uuid

from pydantic import Field, field_validator, model_validator

from app.core.constants import (
    MAX_DESCRIPTION_LENGTH,
    MAX_JOB_CLOSING_DAYS,
    MAX_SHORT_TEXT,
    EmploymentType,
    ExperienceLevel,
    JobSourceType,
    JobStatus,
)
from app.schemas.common import (
    PaginatedResponseEnvelope,
    RequestSchema,
    ResponseEnvelope,
    ResponseSchema,
    TimestampMixinSchema,
)

TradeCode = Annotated[str, Field(min_length=2, max_length=50, pattern=r"^[A-Z][A-Z0-9_]*$")]
CountyCode = Annotated[str, Field(min_length=2, max_length=32, pattern=r"^[A-Z][A-Z0-9_]*$")]

#: Accepted salary periods. ``None`` means "not stated", which is different from
#: zero: an undisclosed salary is normal on a construction site posting.
SALARY_PERIODS: tuple[str, ...] = (
    "HOURLY",
    "DAILY",
    "WEEKLY",
    "MONTHLY",
    "QUARTERLY",
    "YEARLY",
    "PROJECT",
)
SalaryPeriod = Annotated[
    str,
    Field(
        min_length=3,
        max_length=16,
        pattern=r"^[A-Z_]+$",
        description="One of: " + ", ".join(SALARY_PERIODS),
    ),
]
CurrencyCode = Annotated[
    str,
    Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$", description="ISO 4217, e.g. KES."),
]


# --------------------------------------------------------------------------- #
# Requests                                                                    #
# --------------------------------------------------------------------------- #
class JobSkillAssignment(RequestSchema):
    """One skill required by a job."""

    skill_code: Annotated[str, Field(min_length=2, max_length=50, pattern=r"^[A-Z][A-Z0-9_]*$")]
    is_required: bool = True


class JobFieldsBase(RequestSchema):
    """The writable shape of a job, shared by create and update.

    Deliberately absent: ``organization_id`` (it comes from the path and is
    authorised there), ``status``, ``published_at``, ``created_by_user_id`` and
    every provenance field. ``extra="forbid"`` turns an attempt to send one into a
    422, which is the mass-assignment guard.

    Every field here is optional because ``JobUpdateRequest`` is a partial update;
    :class:`JobCreateRequest` re-declares ``title`` and ``description`` as required.
    """

    trade_code: TradeCode | None = None
    county_code: CountyCode | None = None
    location: Annotated[str | None, Field(max_length=MAX_SHORT_TEXT)] = None
    employment_type: EmploymentType = EmploymentType.FULL_TIME
    experience_level: ExperienceLevel = ExperienceLevel.NOT_SPECIFIED
    experience_required_years: Annotated[int | None, Field(ge=0, le=60)] = None
    salary_min: Annotated[int | None, Field(ge=0, le=100_000_000)] = None
    salary_max: Annotated[int | None, Field(ge=0, le=100_000_000)] = None
    salary_currency: CurrencyCode | None = None
    salary_period: SalaryPeriod | None = None
    skills: Annotated[list[JobSkillAssignment], Field(max_length=25)] = Field(default_factory=list)
    source_type: Literal["PLATFORM"] | None = Field(
        default=None,
        description=(
            "Optional, and if sent must be `PLATFORM`. A job created on this route "
            "belongs to the organization in the path; external provenance cannot be "
            "asserted by a client, and asserting it would misattribute the listing."
        ),
    )
    closing_at: datetime | None = Field(
        default=None,
        description=(
            "When applications stop. Must be in the future and within "
            f"{MAX_JOB_CLOSING_DAYS} days, so a listing cannot be written already expired."
        ),
    )

    @field_validator("closing_at")
    @classmethod
    def _normalise_closing_at(cls, value: datetime | None) -> datetime | None:
        """Normalise to UTC and refuse a date that has already passed.

        A naive value is read as UTC rather than rejected: the column is
        ``TIMESTAMPTZ`` and refusing it would only teach clients a quirk.
        """
        if value is None:
            return None
        moment = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        now = datetime.now(UTC)
        if moment <= now:
            raise ValueError("closing_at must be in the future; a job that has already closed.")
        if moment > now + timedelta(days=MAX_JOB_CLOSING_DAYS):
            raise ValueError(f"closing_at cannot be more than {MAX_JOB_CLOSING_DAYS} days away.")
        return moment

    @model_validator(mode="after")
    def _validate_salary_range(self) -> Self:
        if (
            self.salary_min is not None
            and self.salary_max is not None
            and self.salary_min > self.salary_max
        ):
            raise ValueError("salary_min cannot be greater than salary_max.")
        return self

    @model_validator(mode="after")
    def _validate_unique_skills(self) -> Self:
        codes = [s.skill_code for s in self.skills]
        if len(codes) != len(set(codes)):
            raise ValueError("A skill may only be listed once.")
        return self


class JobCreateRequest(JobFieldsBase):
    """Create a draft job for the organization named in the path.

    Omitting ``closing_at`` gives the job a deterministic close date 30 days out,
    so expiry never depends on a client remembering to send one.
    """

    title: Annotated[str, Field(min_length=3, max_length=MAX_SHORT_TEXT)]
    description: Annotated[str, Field(min_length=20, max_length=MAX_DESCRIPTION_LENGTH)]


class JobUpdateRequest(JobFieldsBase):
    """Partial update. Every field is optional; ``skills`` replaces the list.

    The stored record is re-validated after the merge, so a patch cannot produce a
    closing date that has already passed.
    """

    title: Annotated[str, Field(min_length=3, max_length=MAX_SHORT_TEXT)] | None = None
    description: Annotated[str, Field(min_length=20, max_length=MAX_DESCRIPTION_LENGTH)] | None = (
        None
    )


# --------------------------------------------------------------------------- #
# Responses                                                                   #
# --------------------------------------------------------------------------- #
class JobOrganizationRefResponse(ResponseSchema):
    """The owning organization. Null for an externally sourced listing."""

    id: uuid.UUID
    name: str
    slug: str
    is_verified: bool = False


class JobProvenanceResponse(ResponseSchema):
    """Where a listing came from.

    Always populated. For an external listing this block **is** the attribution:
    ``platform_published`` is false, ``organization`` on the enclosing response is
    null, and ``external_apply_url`` points at the site the worker must apply to. A
    client must not render such a listing as one an employer posted here.
    """

    source_type: JobSourceType
    platform_published: bool = Field(
        description="True only for a listing an organization published through FundiPulse."
    )
    source_id: uuid.UUID | None = None
    source_name: str | None = None
    source_url: str | None = None
    source_job_id: str | None = None
    external_apply_url: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    last_verified_at: datetime | None = None
    is_aggregated: bool = Field(
        description="True when the listing came from elsewhere. Applications route to that site."
    )


class JobSkillResponse(ResponseSchema):
    """One required skill on a listing."""

    id: uuid.UUID
    code: str
    name: str
    is_required: bool


class JobResponse(TimestampMixinSchema):
    """A job listing, employer-managed or aggregated.

    One shape for both, so a client needs one parser. Provenance, not wording,
    is what distinguishes them: ``source_type`` plus ``provenance.platform_published``
    and a null ``organization`` for an external listing.
    """

    id: uuid.UUID
    title: str
    description: str
    status: JobStatus = Field(
        description=(
            "The lifecycle state. `EXPIRED` is also derived server-side for a listing "
            "whose closing date has passed, whether or not it has been swept yet."
        )
    )
    trade_code: str | None = None
    trade_name: str | None = None
    county_code: str | None = None
    county_name: str | None = None
    location: str | None = None
    employment_type: EmploymentType
    experience_level: ExperienceLevel
    experience_required_years: int | None = None
    published_at: datetime | None = None
    closing_at: datetime | None = None
    closed_at: datetime | None = None
    application_count: int = 0
    salary_min: int | None = None
    salary_max: int | None = None
    salary_currency: str | None = None
    salary_period: str | None = None
    organization: JobOrganizationRefResponse | None = Field(
        default=None, description="Owning organization. Always null for an external listing."
    )
    provenance: JobProvenanceResponse
    accepts_applications: bool = Field(
        description="False for an aggregated listing, whatever its status: the worker applies elsewhere."
    )
    skills: list[JobSkillResponse] = Field(default_factory=list)


class JobListResponse(PaginatedResponseEnvelope[JobResponse]):
    """A page of job listings."""


class JobTransitionResponse(ResponseEnvelope[JobResponse]):
    """A job after a lifecycle transition."""
