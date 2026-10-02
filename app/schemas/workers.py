"""Work Passport schemas - the privacy boundary for worker data."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Annotated
import uuid

from pydantic import Field, field_validator, model_validator

from app.core.constants import (
    MAX_BIO_LENGTH,
    MAX_SHORT_TEXT,
    AvailabilityStatus,
    ContactPreference,
    ProfileVisibility,
    SkillProficiency,
)
from app.schemas.common import (
    PaginatedResponseEnvelope,
    RequestSchema,
    ResponseSchema,
    TimestampMixinSchema,
)

DisplayName = Annotated[str, Field(min_length=2, max_length=120)]
CountyCode = Annotated[
    str,
    Field(
        min_length=2,
        max_length=32,
        pattern=r"^[A-Z][A-Z0-9_]*$",
        description="County code, e.g. NAKURU. Validated against the catalogue.",
    ),
]
TradeCode = Annotated[
    str,
    Field(min_length=2, max_length=50, pattern=r"^[A-Z][A-Z0-9_]*$"),
]


# --------------------------------------------------------------------------- #
# Nested reference shapes                                                     #
# --------------------------------------------------------------------------- #
class TradeRefResponse(ResponseSchema):
    """A trade attached to a passport."""

    id: uuid.UUID
    code: str
    name: str
    is_primary: bool
    years_experience: Decimal | None = None


class SkillRefResponse(ResponseSchema):
    """A skill on a passport. ``proficiency`` is self-declared, never verified."""

    id: uuid.UUID
    code: str
    name: str
    proficiency: SkillProficiency = Field(
        description="Self-declared by the worker. Never counts as verification."
    )
    years_experience: Decimal | None = None


class CountyRefResponse(ResponseSchema):
    """A county on the passport."""

    id: uuid.UUID
    code: str
    name: str


# --------------------------------------------------------------------------- #
# Requests                                                                    #
# --------------------------------------------------------------------------- #
class WorkerProfileCreateRequest(RequestSchema):
    """Create the caller's passport. No ``user_id``: that would be an IDOR."""

    display_name: DisplayName
    bio: Annotated[str, Field(max_length=MAX_BIO_LENGTH)] | None = None
    headline: Annotated[str, Field(max_length=160)] | None = None
    primary_trade_code: TradeCode | None = None
    county_code: CountyCode | None = None
    location: Annotated[str, Field(max_length=MAX_SHORT_TEXT)] | None = None
    self_declared_experience_years: Annotated[
        Decimal | None,
        Field(ge=0, le=80, max_digits=4, decimal_places=1),
    ] = None
    availability_status: AvailabilityStatus = AvailabilityStatus.NOT_AVAILABLE
    available_from: date | None = None
    visibility: ProfileVisibility = ProfileVisibility.PRIVATE
    contact_preference: ContactPreference = ContactPreference.NONE
    preferred_county_codes: Annotated[list[CountyCode], Field(max_length=47)] = Field(
        default_factory=list
    )
    trade_codes: Annotated[list[TradeCode], Field(max_length=25)] = Field(default_factory=list)

    # --- private contact block ------------------------------------------ #
    phone_number: Annotated[
        str | None,
        Field(max_length=32, description="Owner-only. Never exposed to other users."),
    ] = None
    contact_email: Annotated[
        str | None,
        Field(max_length=320, description="Owner-only alternate contact address."),
    ] = None
    contact_name: Annotated[str | None, Field(max_length=120)] = None
    contact_phone: Annotated[str | None, Field(max_length=32)] = None

    @field_validator("phone_number", "contact_phone")
    @classmethod
    def _validate_kenyan_phone(cls, value: str | None) -> str | None:
        """Kenyan formats only (07XXXXXXXX / 01XXXXXXXX / landline), normalised so."""
        if value is None:
            return None
        digits = value.replace(" ", "").replace("-", "")
        if digits.startswith("+254"):
            digits = "0" + digits[4:]
        if not digits.isdigit():
            raise ValueError("A phone number may contain only digits, spaces, - and +254.")
        if not (len(digits) == 10 and digits.startswith("0")):
            raise ValueError("Enter a Kenyan number as 07XXXXXXXX or 01XXXXXXXX.")
        return digits

    @model_validator(mode="after")
    def _validate_availability(self) -> WorkerProfileCreateRequest:
        """Mirrors the database CHECK constraint: this gives a message, that."""
        if (
            self.availability_status == AvailabilityStatus.AVAILABLE_SOON
            and not self.available_from
        ):
            raise ValueError(
                "available_from is required when availability_status is AVAILABLE_SOON."
            )
        return self

    @model_validator(mode="after")
    def _validate_primary_trade(self) -> WorkerProfileCreateRequest:
        """The primary trade must be one of the worker's trades."""
        if (
            self.primary_trade_code
            and self.trade_codes
            and self.primary_trade_code not in self.trade_codes
        ):
            raise ValueError("primary_trade_code must be one of trade_codes.")
        return self


class WorkerProfileUpdateRequest(RequestSchema):
    """Partial update. No ``user_id`` and no verification field, so a worker cannot."""

    display_name: DisplayName | None = None
    bio: Annotated[str, Field(max_length=MAX_BIO_LENGTH)] | None = None
    headline: Annotated[str, Field(max_length=160)] | None = None
    primary_trade_code: TradeCode | None = None
    county_code: CountyCode | None = None
    location: Annotated[str, Field(max_length=MAX_SHORT_TEXT)] | None = None
    self_declared_experience_years: Annotated[
        Decimal | None, Field(ge=0, le=80, max_digits=4, decimal_places=1)
    ] = None
    availability_status: AvailabilityStatus | None = None
    available_from: date | None = None
    visibility: ProfileVisibility | None = None
    contact_preference: ContactPreference | None = None
    is_open_to_opportunities: bool | None = None
    phone_number: Annotated[str | None, Field(max_length=32)] = None
    contact_email: Annotated[str | None, Field(max_length=320)] = None
    contact_name: Annotated[str | None, Field(max_length=120)] | None = None
    contact_phone: Annotated[str | None, Field(max_length=32)] = None

    _validate_phone = field_validator("phone_number", "contact_phone")(
        WorkerProfileCreateRequest._validate_kenyan_phone.__func__  # type: ignore[attr-defined]
    )


class TradeAssignment(RequestSchema):
    """One trade on a passport."""

    trade_code: TradeCode
    is_primary: bool = False
    years_experience: Annotated[
        Decimal | None, Field(ge=0, le=80, max_digits=4, decimal_places=1)
    ] = None


class SkillAssignment(RequestSchema):
    """One skill on a passport."""

    skill_code: Annotated[str, Field(min_length=2, max_length=50, pattern=r"^[A-Z][A-Z0-9_]*$")]
    proficiency: SkillProficiency = SkillProficiency.INTERMEDIATE
    years_experience: Annotated[
        Decimal | None, Field(ge=0, le=80, max_digits=4, decimal_places=1)
    ] = None


class WorkerTradesUpdateRequest(RequestSchema):
    """Replace the trade list wholesale, so "one primary trade" is atomic."""

    trades: Annotated[list[TradeAssignment], Field(max_length=25)] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_single_primary(self) -> WorkerTradesUpdateRequest:
        """Caught here for a useful message; the partial unique index would."""
        primaries = [t.trade_code for t in self.trades if t.is_primary]
        if len(primaries) > 1:
            raise ValueError(
                "Only one trade can be the primary trade; got: " + ", ".join(primaries)
            )
        codes = [t.trade_code for t in self.trades]
        if len(codes) != len(set(codes)):
            raise ValueError("A trade may only be listed once.")
        return self


class WorkerSkillsUpdateRequest(RequestSchema):
    """Replace the worker's skill list."""

    skills: Annotated[list[SkillAssignment], Field(max_length=100)] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_no_duplicates(self) -> WorkerSkillsUpdateRequest:
        codes = [s.skill_code for s in self.skills]
        if len(codes) != len(set(codes)):
            raise ValueError("A skill may only be listed once.")
        return self


class PreferredCountiesUpdateRequest(RequestSchema):
    """Replace the worker's preferred work counties."""

    county_codes: Annotated[list[CountyCode], Field(max_length=47)] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Responses                                                                   #
# --------------------------------------------------------------------------- #
class WorkerProfilePublicResponse(TimestampMixinSchema):
    """Any user, subject to visibility. Professional information only - no contact."""

    id: uuid.UUID
    display_name: str
    headline: str | None = None
    bio: str | None = None
    visibility: ProfileVisibility
    primary_trade: TradeRefResponse | None = None
    trades: list[TradeRefResponse] = Field(default_factory=list)
    skills: list[SkillRefResponse] = Field(default_factory=list)
    county: CountyRefResponse | None = None
    location: str | None = None
    preferred_counties: list[CountyRefResponse] = Field(default_factory=list)
    availability_status: AvailabilityStatus
    available_from: date | None = None
    is_open_to_opportunities: bool
    self_declared_experience_years: Decimal | None = Field(
        default=None,
        description=(
            "Self-declared and therefore secondary. Authoritative experience is "
            "derived from the worker's dated experience records."
        ),
    )


class WorkerProfilePrivateResponse(WorkerProfilePublicResponse):
    """Owner-only: adds the contact block. ``contact_preference`` is a routing hint."""

    user_id: uuid.UUID
    contact_preference: ContactPreference
    is_contactable: bool = Field(
        description=(
            "Whether an employer may request contact. Never an address: it is "
            "false when the profile is PRIVATE or the preference is NONE."
        ),
    )
    phone_number: str | None = None
    contact_email: str | None = None
    contact_name: str | None = None
    contact_phone: str | None = None


class WorkerProfileSummaryResponse(ResponseSchema):
    """Search-result row: minimal, with factual counts rather than a score (ADR 0010)."""

    id: uuid.UUID
    display_name: str
    headline: str | None = None
    primary_trade: TradeRefResponse | None = None
    trades: list[TradeRefResponse] = Field(default_factory=list)
    skill_count: int = 0
    county: CountyRefResponse | None = None
    availability_status: AvailabilityStatus
    is_open_to_opportunities: bool
    experience_summary: ExperienceSummaryResponse | None = None
    #: Deterministic match score; factors are returned so a result can be justified.
    match_score: int = 0
    match_reasons: list[str] = Field(default_factory=list)


class ExperienceSummaryResponse(ResponseSchema):
    """Factual signals. Not one authoritative figure: derived and self-declared are."""

    derived_years: Decimal = Field(
        description="Years computed from the overlap of dated experience records."
    )
    experience_record_count: int
    self_declared_years: Decimal | None = None
    current_position_count: int


class WorkerProfileListResponse(PaginatedResponseEnvelope[WorkerProfilePublicResponse]):
    """Paginated passports. Exists so the OpenAPI schema names the collection."""


class WorkerSearchResponse(PaginatedResponseEnvelope[WorkerProfileSummaryResponse]):
    """Paginated employer search results."""
