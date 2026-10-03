"""Schemas for the verification request/response workflow.

A verification is a **third-party attestation of one specific claim**: a named
person confirms that one work experience record, one documented project or one
credential is what the worker says it is. The mobile client reads these
descriptions straight out of the OpenAPI document, so the boundaries below are
stated in the field text rather than only in the module docstring.

**What a verification is not.** This is the part that is easy to erode, so it is
repeated wherever a client might render a verification:

* It is **not** a trust score, a star rating, a quality score or a ranking.
  Nothing here measures quality, and no such field may be added.
* It is **not** a certification. Only an issuing body can certify a credential;
  a third party confirming the worker held it on a site is not certification.
* It is **not** a guarantee of quality, safety, conduct or future performance.
  The verifier speaks for what they personally observed, not for the worker's
  future work.
* It does **not** rewrite the worker's claim into an absolute fact. The claim
  stays in the worker's own words; the verification is a separate, attributed
  record that sits beside it.

The single invariant the service enforces is that **a worker can never be the
verifier of their own claim** - not by nominating themselves, and not by
answering a request they raised.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Self
import uuid

from pydantic import EmailStr, Field, field_serializer, model_validator

from app.core.constants import (
    MAX_NOTES_LENGTH,
    VerificationRequestStatus,
    VerificationStatus,
    VerificationTargetType,
)
from app.schemas.common import (
    PaginatedResponseEnvelope,
    RequestSchema,
    ResponseSchema,
    TimestampMixinSchema,
    serialise_datetime,
)

#: Reused verbatim on every verification surface so the caveat cannot drift.
ATTESTATION_CAVEAT = (
    "A third party's factual confirmation of one specific claim. It is not a trust "
    "score, not a professional certification, and not a guarantee of quality, "
    "safety or future performance. The claim itself remains the worker's own words."
)


class VerificationRequestCreate(RequestSchema):
    """Ask one named person to confirm one claim on the caller's passport.

    There is deliberately no ``worker_profile_id``, ``status``, ``verified_by`` or
    ``user_id`` field. The worker is the authenticated caller, the status is
    ``PENDING`` by construction, and the verifier is whoever the server resolves
    from ``verifier_email`` - accepting any of them would be mass assignment, and
    accepting a status would let a client pre-write the outcome.
    """

    target_type: Annotated[
        VerificationTargetType,
        Field(
            description=(
                "Which kind of claim is being put to the verifier: one specific "
                "record of this type, named by `target_id`."
            ),
        ),
    ]
    target_id: Annotated[
        uuid.UUID,
        Field(
            description=(
                "The exact record being verified. It must exist and belong to the "
                "caller; another worker's record is reported as not found rather "
                "than forbidden, so its existence is not disclosed."
            ),
        ),
    ]
    verifier_email: Annotated[
        EmailStr,
        Field(
            description=(
                "The third party being asked. Must not be the caller's own address: "
                "a worker cannot nominate themselves as the verifier of their own "
                "claim, and the refusal is audited."
            ),
        ),
    ]
    verifier_full_name: Annotated[str, Field(max_length=160)] | None = None
    verifier_relationship: (
        Annotated[
            str,
            Field(
                max_length=160,
                description=(
                    "How the verifier knows the worker, e.g. 'Foreman at ABC Builders'. "
                    "Attributed to the verifier when they answer; not a claim made by "
                    "the platform."
                ),
            ),
        ]
        | None
    ) = None
    message: (
        Annotated[
            str,
            Field(
                max_length=MAX_NOTES_LENGTH,
                description="Optional note to the verifier, in the worker's own words.",
            ),
        ]
        | None
    ) = None


class VerificationRespondRequest(RequestSchema):
    """A verifier's single-use answer to one request.

    A boolean rather than a status enum on purpose: the only two outcomes a
    verifier can produce are "I confirm this claim" and "I decline to confirm it".
    Exposing the record-level statuses would put ``REVOKED`` - an administrator's
    later transition, not an answer - onto a public request body.
    """

    confirm: Annotated[
        bool,
        Field(
            description=(
                "`true` confirms the claim as the worker described it. `false` "
                "declines to confirm it; the claim is left exactly as written and "
                "nothing is asserted about the worker either way."
            ),
        ),
    ]
    notes: (
        Annotated[
            str,
            Field(
                max_length=MAX_NOTES_LENGTH,
                description=(
                    "Optional context in the verifier's own words. Required when "
                    "`confirm` is false, because a bare refusal tells the worker "
                    "nothing they can act on."
                ),
            ),
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def _reason_is_required_to_decline(self) -> Self:
        if not self.confirm and not (self.notes or "").strip():
            raise ValueError("notes are required when you decline to confirm a claim.")
        return self


class VerificationRecordResponse(ResponseSchema):
    """The factual record of one answered request.

    Exactly what happened, who said it and when. There is no score, no tier, no
    weighting and no derived judgement: the record reports an assertion, it does
    not evaluate the claim it refers to.
    """

    id: uuid.UUID
    status: Annotated[
        VerificationStatus,
        Field(
            description=(
                "The verifier's answer: `VERIFIED` or `REJECTED`. `REVOKED` appears "
                "here only once an administrator withdraws a standing "
                "attestation, which records who and when rather than erasing it."
            ),
        ),
    ]
    target_type: VerificationTargetType
    target_id: uuid.UUID = Field(description="The claim this answer refers to.")
    verifier_display_name: Annotated[
        str,
        Field(description="How the verifier is named to the worker and to employers."),
    ]
    verifier_relationship: str | None = None
    verified_at: datetime = Field(description="When the verifier answered.")
    evidence_summary: str | None = Field(
        default=None,
        description=(
            "What the verifier relied on, in their words. Free text, never a score "
            "and never a document body."
        ),
    )
    response_statement: (
        Annotated[
            str,
            Field(description="The verifier's own statement, verbatim."),
        ]
        | None
    ) = None
    caveat: Annotated[
        str,
        Field(default=ATTESTATION_CAVEAT, description=ATTESTATION_CAVEAT),
    ]

    @field_serializer("verified_at")
    def _ser_verified_at(self, value: datetime) -> str:
        return serialise_datetime(value) or ""


class VerificationRequestResponse(TimestampMixinSchema):
    """One verification request, as seen by one of its two parties.

    A request identifies the worker, the one claim being verified, the person
    asked, the relationship they are recorded as having to the worker, the status,
    the worker's optional message, the timestamps and - once answered - who
    responded, what they said, and the resulting record.

    The claim is returned as the worker wrote it. Nothing here restates it as an
    established fact, and the accompanying verification is a separate attributed
    record rather than a rewrite of the claim.
    """

    id: uuid.UUID
    worker_profile_id: uuid.UUID
    worker_display_name: str | None = Field(
        default=None,
        description="The worker's chosen display name, so a verifier can tell requests apart.",
    )
    target_type: VerificationTargetType = Field(description="The kind of claim being verified.")
    target_id: uuid.UUID = Field(description="The exact record being verified.")
    target_label: str | None = Field(
        default=None,
        description="Short snapshot of the claim's own wording, for list display.",
    )
    target_snapshot: (
        Annotated[
            dict[str, Any],
            Field(
                description=(
                    "The claim exactly as the worker wrote it when the request was made, "
                    "frozen so a later edit cannot change what the verifier was asked "
                    "about. This is the worker's claim, not a restatement by the platform."
                ),
            ),
        ]
        | None
    ) = None
    verifier_email: Annotated[
        str,
        Field(description="The third party who was asked, as nominated by the worker."),
    ]
    verifier_full_name: str | None = None
    verifier_relationship: str | None = Field(
        default=None,
        description="How the verifier is recorded as knowing the worker.",
    )
    requested_by_user_id: Annotated[
        uuid.UUID,
        Field(
            description=(
                "The worker account that raised the request. Both parties to a "
                "request know who the other is, and this is what lets a client tell "
                "which side of the request it is looking at."
            ),
        ),
    ]
    status: Annotated[
        VerificationRequestStatus,
        Field(
            description=(
                "`PENDING` until a verifier answers, then `VERIFIED` or `REJECTED`; "
                "`CANCELLED` if the worker withdrew it. A request that has passed its "
                "deadline stops being answerable."
            ),
        ),
    ]
    message: str | None = None
    requested_at: datetime = Field(description="When the request was raised.")
    expires_at: datetime = Field(
        description="Server-set deadline. The client neither supplies nor extends it."
    )
    responded_at: datetime | None = Field(default=None, description="When the verifier answered.")
    responded_by_user_id: uuid.UUID | None = Field(
        default=None,
        description="The verifier's account, once they have answered.",
    )
    response_notes: (
        Annotated[
            str,
            Field(description="The verifier's own words, verbatim. Never summarised or scored."),
        ]
        | None
    ) = None
    verification: (
        Annotated[
            VerificationRecordResponse,
            Field(description=ATTESTATION_CAVEAT),
        ]
        | None
    ) = None

    @field_serializer("requested_at", "expires_at", "responded_at")
    def _ser_timestamps(self, value: datetime | None) -> str | None:
        return serialise_datetime(value)


class VerificationRequestListResponse(PaginatedResponseEnvelope[VerificationRequestResponse]):
    """A page of the caller's verification requests, in both directions."""

    model_config = {
        "json_schema_extra": {
            "description": (
                "Every request the caller raised, plus every request addressed to "
                "them as verifier - the two directions in one page, newest first. A "
                "request addressed to a different verifier is neither in this list "
                "nor findable by id."
            )
        }
    }


__all__ = [
    "ATTESTATION_CAVEAT",
    "VerificationRecordResponse",
    "VerificationRequestCreate",
    "VerificationRequestListResponse",
    "VerificationRequestResponse",
    "VerificationRespondRequest",
]
