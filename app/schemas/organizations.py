"""Organization schemas: the company record and the memberships that grant access.

An Employer in FundiPulse is a *company*, so nothing here carries an ``employer
person``: an organization is addressed by its own id, and the humans who can act
on it do so through an :class:`OrganizationMembership`. ``User`` stays the
authentication identity and is never a field on an organization payload.

Two privacy decisions live in the types rather than in a view function:

* ``OrganizationPublicResponse`` has **no** contact block, so the company phone
  and email reach only ``OWNER``/``ADMIN`` members. The route that builds it for
  anyone else simply has nothing to pass.
* ``MembershipResponse`` has no email, phone or ``user_id`` field at all, so no
  service bug can leak a member's account details through the members list.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
import uuid

from pydantic import EmailStr, Field, field_validator, model_validator

from app.core.constants import (
    MAX_DESCRIPTION_LENGTH,
    MAX_SHORT_TEXT,
    MembershipStatus,
    OrganizationRole,
)
from app.schemas.common import (
    PaginatedResponseEnvelope,
    RequestSchema,
    ResponseSchema,
    TimestampMixinSchema,
)

OrganizationName = Annotated[str, Field(min_length=2, max_length=255)]
Slug = Annotated[
    str,
    Field(
        min_length=2,
        max_length=120,
        pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
        description="URL-safe identifier: lower-case words joined by hyphens.",
    ),
]
CountyCode = Annotated[
    str,
    Field(
        min_length=2,
        max_length=32,
        pattern=r"^[A-Z][A-Z0-9_]*$",
        description="County code, e.g. NAKURU. Validated against the catalogue.",
    ),
]
JobTitle = Annotated[str, Field(min_length=2, max_length=120)]


def normalise_kenyan_phone(value: str | None) -> str | None:
    """Accept the Kenyan formats only, and store one normalised form.

    ``+254`` is rewritten to a leading ``0`` and separators are stripped, so
    ``+254 712 345 678`` and ``0712345678`` are the same stored value and one
    unique index over it is enough.
    """
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


def _validate_website_url(value: str | None) -> str | None:
    """Only ``http``/``https`` links, because the field is rendered as a link."""
    if value is None:
        return None
    if not value.startswith(("http://", "https://")):
        raise ValueError("A website address must start with http:// or https://.")
    return value


# --------------------------------------------------------------------------- #
# Requests                                                                    #
# --------------------------------------------------------------------------- #
class OrganizationCreateRequest(RequestSchema):
    """Create a company. The caller becomes its first ``OWNER``.

    No ``user_id``: the creator is the authenticated caller, and an organisation
    row that names somebody else's user would be an IDOR. ``is_verified`` is
    absent too - it is set by an administrator, never self-asserted.
    """

    name: OrganizationName
    slug: Slug | None = Field(default=None, description="Derived from the name when omitted.")
    description: Annotated[str | None, Field(max_length=MAX_DESCRIPTION_LENGTH)] = None
    industry: Annotated[str | None, Field(max_length=120)] = None
    website_url: Annotated[str | None, Field(max_length=512)] = None
    location: Annotated[str | None, Field(max_length=MAX_SHORT_TEXT)] = None
    county_code: CountyCode | None = None
    contact_email: EmailStr | None = None
    contact_phone: Annotated[str | None, Field(max_length=32)] = None

    _validate_phone = field_validator("contact_phone")(normalise_kenyan_phone)
    _validate_website = field_validator("website_url")(_validate_website_url)


class OrganizationUpdateRequest(RequestSchema):
    """Partial update by an ``OWNER``/``ADMIN`` member.

    Not a subclass of the create schema: every field is optional here, and
    ``slug`` is absent because it is the stable public identifier that audit
    records and links resolve against - changing it would break them and would
    allow a deleted company to squat a successor's address.
    """

    name: OrganizationName | None = None
    description: Annotated[str | None, Field(max_length=MAX_DESCRIPTION_LENGTH)] = None
    industry: Annotated[str | None, Field(max_length=120)] = None
    website_url: Annotated[str | None, Field(max_length=512)] = None
    location: Annotated[str | None, Field(max_length=MAX_SHORT_TEXT)] = None
    county_code: CountyCode | None = None
    contact_email: EmailStr | None = None
    contact_phone: Annotated[str | None, Field(max_length=32)] = None

    _validate_phone = field_validator("contact_phone")(normalise_kenyan_phone)
    _validate_website = field_validator("website_url")(_validate_website_url)


class OrganizationAdminUpdateRequest(RequestSchema):
    """Administrator-only state. Neither field is reachable from a member route."""

    is_verified: bool | None = Field(
        default=None,
        description="Platform trust mark. Set only by an administrator.",
    )
    is_active: bool | None = Field(
        default=None,
        description="Set false to close the company to its members without deleting it.",
    )


class MembershipCreateRequest(RequestSchema):
    """Add someone to an organization the caller administers.

    Exactly one of ``user_id`` or ``email`` identifies *another* person: a
    request cannot add the caller to their own organization, and the role is
    checked against the caller's own organization role in the service, so an
    ``ADMIN`` can neither grant nor grant themselves ``OWNER``.
    """

    user_id: uuid.UUID | None = Field(
        default=None, description="A registered account. Never the caller's own id."
    )
    email: EmailStr | None = Field(
        default=None,
        description="Login address of a registered account; normalised before lookup.",
    )
    role: OrganizationRole = OrganizationRole.MEMBER
    status: MembershipStatus = MembershipStatus.ACTIVE
    title: JobTitle | None = None

    @model_validator(mode="after")
    def _exactly_one_target(self) -> MembershipCreateRequest:
        """Ambiguity here would let a client believe it invited someone it did not."""
        if (self.user_id is None) == (self.email is None):
            raise ValueError("Provide exactly one of user_id or email.")
        return self


class MembershipUpdateRequest(RequestSchema):
    """Change one membership. No ``user_id``: the membership id identifies it."""

    role: OrganizationRole | None = None
    status: MembershipStatus | None = None
    title: JobTitle | None = None


# --------------------------------------------------------------------------- #
# Responses                                                                   #
# --------------------------------------------------------------------------- #
class OrganizationPublicResponse(TimestampMixinSchema):
    """The company as any active member may see it: no contact block."""

    id: uuid.UUID
    name: str
    slug: str
    description: str | None = None
    industry: str | None = None
    website_url: str | None = None
    location: str | None = None
    county_code: str | None = None
    county_name: str | None = None
    is_active: bool
    is_verified: bool = Field(description="Set only by an administrator. Never a worker or rating.")


class OrganizationResponse(OrganizationPublicResponse):
    """``OWNER``/``ADMIN`` view: adds the company contact block."""

    contact_email: str | None = None
    contact_phone: str | None = None


class OrganizationAdminResponse(OrganizationResponse):
    """Administrator view: includes soft-deleted companies and their tombstone."""

    deleted_at: datetime | None = None


class MembershipResponse(TimestampMixinSchema):
    """One membership row.

    There is deliberately no ``email``, ``phone_number`` or ``user_id`` field:
    the members list is readable by every member of the organization, so the
    type itself refuses to carry a member's account details.
    """

    id: uuid.UUID
    organization_id: uuid.UUID
    role: OrganizationRole
    status: MembershipStatus
    title: str | None = None
    display_name: str | None = Field(
        default=None,
        description="Work Passport display name when the member has one; never an email.",
    )
    joined_at: datetime | None = None


class MyMembershipResponse(ResponseSchema):
    """The caller's own membership, so a client can render its permissions."""

    id: uuid.UUID
    organization_id: uuid.UUID
    role: OrganizationRole
    status: MembershipStatus
    title: str | None = None
    joined_at: datetime | None = None


class OrganizationListResponse(PaginatedResponseEnvelope[OrganizationPublicResponse]):
    """Paginated organizations the caller belongs to."""


class MembershipListResponse(PaginatedResponseEnvelope[MembershipResponse]):
    """Paginated organization members. Public fields only."""
