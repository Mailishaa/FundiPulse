"""Job application schemas.

An application is a lifecycle record, not a row the client edits. Three
properties are enforced by what the request schemas are *able* to express, so no
service bug can undo them:

* **No ``worker_id`` and no ``job_id``.** The worker comes from the authenticated
  caller's Work Passport and the job from the path, so accepting either would be
  an IDOR. ``extra="forbid"`` turns an attempt to send one into a 422.
* **No ``status`` on create, and no derived counter.** An application starts at
  ``SUBMITTED``; a worker cannot mint itself ``SHORTLISTED`` or ``HIRED``. There is
  no ``application_count`` to set either - it is maintained on the job.
* **The status-change body carries a status, never an identity.** Which
  applications an employer may move is decided by a membership check in the
  service, scoped by the job's organization.

The employer-facing worker block is a *summary* shape: it has no phone number,
contact email or contact name field at all, so an employer reading an application
gets professional information and nothing more.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
import uuid

from pydantic import Field

from app.core.constants import MAX_NOTES_LENGTH, ApplicationStatus, JobStatus
from app.schemas.common import (
    PaginatedResponseEnvelope,
    RequestSchema,
    ResponseEnvelope,
    ResponseSchema,
    TimestampMixinSchema,
)


# --------------------------------------------------------------------------- #
# Requests                                                                    #
# --------------------------------------------------------------------------- #
class ApplicationCreateRequest(RequestSchema):
    """Apply to the job in the path.

    Deliberately absent: ``worker_profile_id``, ``job_id``, ``status``,
    ``submitted_at``, ``withdrawn_at``, ``decision_note`` and ``decided_by``.
    """

    cover_note: Annotated[
        str | None,
        Field(
            max_length=MAX_NOTES_LENGTH,
            description="Optional message to the employer. Shown to the employer's staff only.",
        ),
    ] = None
    idempotency_key: Annotated[
        str | None,
        Field(
            min_length=8,
            max_length=100,
            pattern=r"^[A-Za-z0-9_.:-]+$",
            description=(
                "Client-generated dedupe key for a retry over a poor connection. Sending "
                "the same key again returns the application created the first time "
                "instead of a conflict, so a dropped response is never mistaken for a "
                "refusal. Reusing one key for a different job is a 409."
            ),
        ),
    ] = None


class ApplicationStatusChangeRequest(RequestSchema):
    """Move an application to a new status.

    ``status`` is validated against the lifecycle rather than against a fixed list:
    a syntactically valid status that is not legal from the current state is a 409,
    not a 422, because the client's field was well-formed - the *transition* is
    what it got wrong.
    """

    status: ApplicationStatus = Field(
        description=(
            "The requested status. Only `VIEWED`, `SHORTLISTED`, `REJECTED` and "
            "`HIRED` are employer decisions. `WITHDRAWN` is the worker's own move "
            "(`POST /applications/{id}/withdraw`) and is refused here."
        )
    )
    decision_note: Annotated[
        str | None,
        Field(
            max_length=MAX_NOTES_LENGTH,
            description="Optional note recorded with the decision and shown to the worker.",
        ),
    ] = None


# --------------------------------------------------------------------------- #
# Responses                                                                   #
# --------------------------------------------------------------------------- #
class ApplicationWorkerRefResponse(ResponseSchema):
    """The applicant, as an employer may see them.

    Professional information only. There is no phone number, contact email or
    contact name field here, and none may be added: an employer reaches a worker
    through ``POST /workers/{profile_id}/contact-requests``.
    """

    id: uuid.UUID
    display_name: str
    headline: str | None = None
    primary_trade_code: str | None = None
    primary_trade_name: str | None = None
    location: str | None = None


class ApplicationJobRefResponse(ResponseSchema):
    """The job applied to, as the row is stored plus its derived status."""

    id: uuid.UUID
    title: str
    status: JobStatus = Field(description="`EXPIRED` is derived server-side from the closing date.")
    location: str | None = None
    organization_id: uuid.UUID | None = None
    organization_name: str | None = None


class ApplicationResponse(TimestampMixinSchema):
    """One application, in the shape both sides read.

    One shape rather than a worker shape and an employer shape: the difference
    between the two is who is allowed to fetch it, which is decided by the query,
    not by the type. A withdrawn application keeps this shape and stays readable -
    the row records that a worker changed their mind, which is exactly the history
    an employer needs.
    """

    id: uuid.UUID
    status: ApplicationStatus = Field(description="Where the application is in its lifecycle.")
    cover_note: str | None = None
    submitted_at: datetime
    updated_status_at: datetime | None = None
    withdrawn_at: datetime | None = Field(
        default=None, description="Set only by withdrawal. Withdrawn rows are never deleted."
    )
    decided_at: datetime | None = Field(
        default=None, description="Set by a decision (``SHORTLISTED``/``REJECTED``/``HIRED``)."
    )
    decision_note: str | None = None
    is_active: bool = Field(
        description="Whether the employer may still act on it. False once rejected or withdrawn."
    )
    job: ApplicationJobRefResponse
    worker: ApplicationWorkerRefResponse


class ApplicationListResponse(PaginatedResponseEnvelope[ApplicationResponse]):
    """A page of applications."""


class ApplicationTransitionResponse(ResponseEnvelope[ApplicationResponse]):
    """An application after a lifecycle transition."""
