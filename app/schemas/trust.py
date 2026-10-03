"""Schemas for the worker's trust and evidence layer: referees and credentials.

Two invariants are encoded in the *shapes*, not in prose, because a shape cannot be
forgotten by a later service call:

* **A nomination is not a verification.** :class:`WorkerReferenceResponse` carries
  no verification badge and no ``verified`` flag, and no request field can move
  ``status``, so a worker cannot dress a referee up as a completed attestation.
* **A credential is a claim, not a certification.**
  :attr:`CredentialResponse.verification` is nullable and this layer always leaves
  it null: uploading a certificate records that the worker *says* they hold it.
  There is no ``verified`` field to send and no endpoint that would accept one.

Both request schemas inherit ``extra="forbid"``, so ``user_id``,
``worker_profile_id`` and ``verification_status`` are 422s rather than silently
ignored assignments.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Any, Self
import uuid

from pydantic import EmailStr, Field, field_validator, model_validator

from app.core.constants import (
    MAX_BIO_LENGTH,
    MAX_SHORT_TEXT,
    CredentialType,
    ReferenceRelationship,
    ReferenceStatus,
)
from app.schemas.common import (
    PaginatedResponseEnvelope,
    RequestSchema,
    TimestampMixinSchema,
)
from app.schemas.experiences import VerificationBadgeResponse
from app.utils.dates import utc_today

#: Platform default for the issuing country. Workers are matched to employers in
#: Kenya; a credential issued elsewhere has to say so explicitly.
DEFAULT_ISSUING_COUNTRY = "KE"

EmailAddress = Annotated[EmailStr, Field(max_length=320, description="Lower-cased on write.")]
IssuingCountry = Annotated[
    str,
    Field(min_length=2, max_length=2, pattern=r"^[A-Z]{2}$", description="ISO 3166-1 alpha-2."),
]


def _reject_impossible_dates(issue_date: date | None, expiry_date: date | None) -> None:
    """Reject a credential that cannot have existed yet.

    ``issue_date`` may not be in the future, and an ``expiry_date`` may not be
    before it. A future ``expiry_date`` is refused as well: combined with a missing
    or future ``issue_date`` it describes a document that does not exist yet, and
    a certificate that has not been issued cannot have a validity window.
    """
    if issue_date is not None and issue_date > utc_today():
        raise ValueError("issue_date cannot be in the future.")
    if expiry_date is None:
        return
    if expiry_date > utc_today():
        raise ValueError("expiry_date cannot be in the future.")
    if issue_date is not None and expiry_date < issue_date:
        raise ValueError("expiry_date cannot be earlier than issue_date.")


def _normalise_kenyan_phone(value: str | None) -> str | None:
    """Accept the Kenyan formats a worker would actually type, store one form."""
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


def _normalise_email(value: Any) -> Any:
    """Lower-case an address so one referee cannot be nominated twice by casing."""
    return value.strip().lower() if isinstance(value, str) else value


def _upper_country(value: Any) -> Any:
    """Upper-case before the ``^[A-Z]{2}$`` constraint runs, not after it."""
    return value.strip().upper() if isinstance(value, str) else value


# --------------------------------------------------------------------------- #
# Credentials                                                                  #
# --------------------------------------------------------------------------- #
class CredentialCreateRequest(RequestSchema):
    """Record a credential the worker claims to hold. Not a verification."""

    title: Annotated[str, Field(min_length=2, max_length=MAX_SHORT_TEXT)]
    credential_type: CredentialType = CredentialType.CERTIFICATE
    issuer: Annotated[str, Field(min_length=2, max_length=MAX_SHORT_TEXT)] | None = None
    issuing_country_code: IssuingCountry | None = None
    credential_number: (
        Annotated[
            str,
            Field(
                max_length=120,
                description="The reference printed on the document. Never treated as proof.",
            ),
        ]
        | None
    ) = None
    issue_date: date | None = None
    expiry_date: date | None = None
    description: Annotated[str, Field(max_length=MAX_BIO_LENGTH)] | None = None

    @field_validator("issuing_country_code", mode="before")
    @classmethod
    def _upper_country_code(cls, value: Any) -> Any:
        return _upper_country(value)

    @model_validator(mode="after")
    def _validate_dates(self) -> Self:
        _reject_impossible_dates(self.issue_date, self.expiry_date)
        return self


class CredentialUpdateRequest(RequestSchema):
    """Partial update, revalidated against the stored dates by the service.

    ``credential_type`` is settable. Nothing here can mark the credential as
    issuer-confirmed, and there is no ``verified`` or ``verification_status``
    field to send: ``extra="forbid"`` turns either into a 422.
    """

    title: Annotated[str, Field(min_length=2, max_length=MAX_SHORT_TEXT)] | None = None
    credential_type: CredentialType | None = None
    issuer: Annotated[str, Field(min_length=2, max_length=MAX_SHORT_TEXT)] | None = None
    issuing_country_code: IssuingCountry | None = None
    credential_number: Annotated[str, Field(max_length=120)] | None = None
    issue_date: date | None = None
    expiry_date: date | None = None
    description: Annotated[str, Field(max_length=MAX_BIO_LENGTH)] | None = None

    @field_validator("issuing_country_code", mode="before")
    @classmethod
    def _upper_country_code(cls, value: Any) -> Any:
        return _upper_country(value)

    @model_validator(mode="after")
    def _validate_dates(self) -> Self:
        """Catches the invalid pair inside one patch body."""
        _reject_impossible_dates(self.issue_date, self.expiry_date)
        return self


class CredentialResponse(TimestampMixinSchema):
    """A credential, exactly as the worker described it.

    ``verification`` is always ``null`` from this layer. It exists so a client can
    tell "no verification has been recorded" apart from "this API does not know",
    and it is populated only by the verification workflow, which attests to a
    specific claim from a third party. Nothing here is ever described as certified.
    """

    id: uuid.UUID
    title: str
    credential_type: CredentialType
    issuer: str | None = None
    issuing_country_code: str | None = None
    credential_number: str | None = None
    issue_date: date | None = None
    expiry_date: date | None = None
    description: str | None = None
    is_expired: bool = Field(
        default=False,
        description=(
            "Whether the stated expiry has passed. A fact about the dates the "
            "worker entered, never a judgement about the document."
        ),
    )
    verification: VerificationBadgeResponse | None = None


class CredentialListResponse(PaginatedResponseEnvelope[CredentialResponse]):
    """Paginated credentials."""


# --------------------------------------------------------------------------- #
# References                                                                   #
# --------------------------------------------------------------------------- #
class WorkerReferenceCreateRequest(RequestSchema):
    """Nominate a referee. No ``status`` field: only the referee can move it."""

    full_name: Annotated[str, Field(min_length=2, max_length=160)]
    email: EmailAddress
    relationship_type: ReferenceRelationship = ReferenceRelationship.SUPERVISOR
    organization_name: Annotated[str, Field(max_length=MAX_SHORT_TEXT)] | None = None
    job_title: Annotated[str, Field(max_length=160)] | None = None
    phone_number: (
        Annotated[
            str,
            Field(max_length=32, description="Used to address the invitation. Owner-only."),
        ]
        | None
    ) = None
    is_visible_to_employers: bool = True

    @field_validator("email", mode="before")
    @classmethod
    def _normalise_address(cls, value: Any) -> Any:
        return _normalise_email(value)

    @field_validator("phone_number")
    @classmethod
    def _check_phone(cls, value: str | None) -> str | None:
        return _normalise_kenyan_phone(value)


class WorkerReferenceUpdateRequest(RequestSchema):
    """Partial update of a nomination.

    There is deliberately no ``status``, ``response_statement`` or
    ``responded_by_user_id``: those belong to the referee or an administrator.
    """

    full_name: Annotated[str, Field(min_length=2, max_length=160)] | None = None
    email: EmailAddress | None = None
    relationship_type: ReferenceRelationship | None = None
    organization_name: Annotated[str, Field(max_length=MAX_SHORT_TEXT)] | None = None
    job_title: Annotated[str, Field(max_length=160)] | None = None
    phone_number: Annotated[str, Field(max_length=32)] | None = None
    is_visible_to_employers: bool | None = None

    @field_validator("email", mode="before")
    @classmethod
    def _normalise_address(cls, value: Any) -> Any:
        return _normalise_email(value)

    @field_validator("phone_number")
    @classmethod
    def _check_phone(cls, value: str | None) -> str | None:
        return _normalise_kenyan_phone(value)


class WorkerReferenceResponse(TimestampMixinSchema):
    """A nomination, owner-only.

    **A nominated referee is not a verified reference.** This shape has no
    verification badge and no verified flag, because a person the worker says can
    vouch for them has not vouched. Confirmation is the referee's own act.

    ``email`` and ``phone_number`` are the referee's contact details. They are
    reachable only through these owner-scoped routes, which resolve the caller's
    passport from the session and never accept a worker id.
    """

    id: uuid.UUID
    full_name: str
    relationship_type: ReferenceRelationship
    organization_name: str | None = None
    job_title: str | None = None
    email: str
    phone_number: str | None = None
    status: ReferenceStatus = Field(
        description="The nomination's own state, server-controlled. Never a verification.",
    )
    is_visible_to_employers: bool = Field(
        description=(
            "Worker-controlled presentation choice: whether this nomination may be "
            "shown to employers once the referee confirms."
        ),
    )
    invited_at: datetime | None = None
    responded_at: datetime | None = None
    response_statement: str | None = Field(
        default=None, description="The referee's own words. Not editable here."
    )


class WorkerReferenceListResponse(PaginatedResponseEnvelope[WorkerReferenceResponse]):
    """Paginated nominations."""


__all__ = [
    "DEFAULT_ISSUING_COUNTRY",
    "CredentialCreateRequest",
    "CredentialListResponse",
    "CredentialResponse",
    "CredentialUpdateRequest",
    "WorkerReferenceCreateRequest",
    "WorkerReferenceListResponse",
    "WorkerReferenceResponse",
    "WorkerReferenceUpdateRequest",
]
