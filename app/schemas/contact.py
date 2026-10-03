"""Contact-request schemas.

A contact request is a **request**, not a disclosure. An employer states who they
are and what they are interested in; the worker decides whether their phone number
or email is ever handed over. `contact_preference` on the passport is a routing
hint, not an address, and nothing here returns a contact detail directly — the
worker's response is the only thing that releases one.
"""

from __future__ import annotations

from datetime import datetime
import uuid

from pydantic import Field

from app.core.constants import ContactRequestStatus
from app.schemas.common import (
    PaginatedResponseEnvelope,
    RequestSchema,
    ResponseSchema,
    TimestampMixinSchema,
)


class ContactRequestCreateRequest(RequestSchema):
    """Ask a worker to make contact.

    No `worker_profile_id`: it comes from the path. No `user_id`: the requester is
    the authenticated caller, resolved server-side to their organization
    membership. Accepting either would let a client file a request as somebody
    else.
    """

    organization_id: uuid.UUID = Field(
        description=(
            "The employer organization asking. Must be one the caller belongs to "
            "with a role permitted to recruit."
        )
    )
    job_id: uuid.UUID | None = Field(
        default=None, description="Optional: the vacancy this interest relates to."
    )
    message: str | None = Field(
        default=None,
        max_length=1000,
        description=(
            "Why you are interested. Shown to the worker, who decides whether to "
            "respond. Cannot contain a phone number or email address on the "
            "worker's behalf — those are what the request is for."
        ),
    )


class ContactRequestRespondRequest(RequestSchema):
    """The worker's answer. There is no third option beyond declining."""

    accept: bool = Field(
        description=(
            "True releases the worker's contact details to the requesting "
            "organization's members. False declines."
        )
    )
    response_note: str | None = Field(
        default=None, max_length=1000, description="Optional note to the requester."
    )


class ContactRequestCancelRequest(RequestSchema):
    """Withdraw a request the caller filed."""


class ContactRequestResponse(TimestampMixinSchema):
    """A contact request.

    Never carries a phone number or email address. The employer side of this
    response is the same shape as the worker side, so a request cannot leak a
    contact detail to whichever party happens to read it.
    """

    id: uuid.UUID
    status: ContactRequestStatus
    message: str | None = None
    response_note: str | None = None

    #: The worker the request is about. The worker owns the decision.
    worker_profile_id: uuid.UUID
    #: Who asked. Null once the asking account is deactivated.
    requester_user_id: uuid.UUID | None = None
    organization_id: uuid.UUID
    organization_name: str | None = None
    job_id: uuid.UUID | None = None
    job_title: str | None = None

    #: True only after the worker accepted. A single explicit fact, so "was this
    #: ever disclosed" survives a later status correction.
    contact_details_shared: bool = False

    requested_at: datetime | None = None
    responded_at: datetime | None = None
    expires_at: datetime | None = None

    #: Present only for the worker, once they have accepted. Never present for an
    #: employer: disclosure is to the worker, not from them.
    worker_contact: WorkerContactBlock | None = None


class WorkerContactBlock(ResponseSchema):
    """A worker's own contact details, returned only to the worker themselves."""

    phone_number: str | None = None
    contact_email: str | None = None
    contact_name: str | None = None
    contact_phone: str | None = None


class ContactRequestListResponse(PaginatedResponseEnvelope[ContactRequestResponse]):
    """Paginated contact requests."""
