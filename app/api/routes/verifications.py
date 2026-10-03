"""Verification request endpoints.

Five routes, three parties' worth of rules, and none of the rules here: every
authorisation and state decision belongs to
:class:`~app.services.verification_service.VerificationService`. This module
parses, delegates and serialises, and its ``description`` text is what the mobile
client reads out of the OpenAPI document - which is why the wording about what a
verification is and is not appears here as well as on the schema.
"""

from __future__ import annotations

from typing import Annotated, Any
import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser, DbSession, get_request_context
from app.core.constants import VerificationRequestStatus, VerificationTargetType
from app.db.models.verification import VerificationRequest
from app.schemas.common import ErrorResponse, Meta, PaginationMeta, ResponseEnvelope
from app.schemas.verifications import (
    VerificationRecordResponse,
    VerificationRequestCreate,
    VerificationRequestListResponse,
    VerificationRequestResponse,
    VerificationRespondRequest,
)
from app.services.auth_service import RequestContext
from app.services.verification_service import VerificationService

router = APIRouter(prefix="/verification-requests", tags=["Verification"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]

#: Shared OpenAPI additions. Typed loosely because OpenAPI keys mix ints and strs.
AUTH_ERRORS: dict[int | str, Any] = {
    401: {"model": ErrorResponse, "description": "Authentication required."}
}

_SCOPE_DESCRIPTION = (
    "Only the caller's own requests are returned: the ones they raised as a worker, "
    "plus the ones addressed to them as the named verifier. A request addressed to "
    "a different verifier is not in this list and is not found when read by id."
)

_NOT_A_SCORE = (
    "A verification is a third party's factual confirmation of **one specific "
    "claim**. It is not a trust score, not a certification, and not a guarantee of "
    "quality or of future performance. The claim stays in the worker's own words; "
    "the confirmation is a separate, attributed record."
)

_SELF_BLOCKED = {
    "model": ErrorResponse,
    "description": "A worker may not verify their own claim.",
}


def _service(session: Session) -> VerificationService:
    return VerificationService(session)


def _to_response(request: VerificationRequest) -> VerificationRequestResponse:
    """Model -> schema. Kept here because routes own serialisation, not the model.

    ``worker_profile`` and ``verification`` are eager-loaded by the service, so a
    page of these costs two extra queries rather than two per row.
    """
    return VerificationRequestResponse(
        id=request.id,
        worker_profile_id=request.worker_profile_id,
        worker_display_name=request.worker_profile.display_name,
        target_type=request.target_type,
        target_id=request.target_id,
        target_label=request.target_label,
        target_snapshot=request.target_snapshot,
        verifier_email=request.verifier_email,
        verifier_full_name=request.verifier_full_name,
        verifier_relationship=request.verifier_relationship,
        requested_by_user_id=request.requested_by_user_id,
        status=request.status,
        message=request.message,
        requested_at=request.requested_at,
        expires_at=request.expires_at,
        responded_at=request.responded_at,
        responded_by_user_id=request.responded_by_user_id,
        response_notes=request.response_notes,
        verification=(
            None
            if request.verification is None
            else VerificationRecordResponse.model_validate(request.verification)
        ),
        created_at=request.created_at,
        updated_at=request.updated_at,
    )


@router.post(
    "",
    response_model=ResponseEnvelope[VerificationRequestResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Ask a third party to confirm one claim",
    description=(
        f"{_NOT_A_SCORE}\n\n"
        "The claim must exist and belong to the caller: another worker's record is "
        "reported as not found, so its existence is never disclosed. `verifier_email` "
        "must not be the caller's own address — nominating yourself is refused and "
        "audited, in both the address form and the account form.\n\n"
        "The claim is frozen into `target_snapshot` exactly as the worker wrote it, "
        "so a later edit cannot change what the verifier was asked about. One "
        "request per claim may be awaiting an answer; a second is a `409`."
    ),
    responses={
        201: {"description": "Raised and awaiting a response."},
        403: _SELF_BLOCKED,
        404: {"model": ErrorResponse, "description": "No such claim on this passport."},
        409: {
            "model": ErrorResponse,
            "description": "A request for that claim is already awaiting a response.",
        },
        422: {"model": ErrorResponse, "description": "Unknown field or unsupported claim type."},
        **AUTH_ERRORS,
    },
)
def create_verification_request(
    payload: VerificationRequestCreate,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[VerificationRequestResponse]:
    request = _service(session).create_request(actor=current_user, payload=payload)
    return ResponseEnvelope(data=_to_response(request), meta=Meta(request_id=ctx.request_id))


@router.get(
    "",
    response_model=VerificationRequestListResponse,
    summary="List the caller's verification requests",
    description=f"{_SCOPE_DESCRIPTION}\n\n{_NOT_A_SCORE}",
    responses={200: {"description": "A page of requests."}, **AUTH_ERRORS},
)
def list_verification_requests(
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
    request_status: Annotated[
        VerificationRequestStatus | None,
        Query(alias="status", description="Filter by request status."),
    ] = None,
    target_type: Annotated[
        VerificationTargetType | None, Query(description="Filter by the kind of claim.")
    ] = None,
    page: Annotated[int, Query(ge=1, le=10_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> VerificationRequestListResponse:
    rows, total = _service(session).list_requests(
        actor=current_user,
        status=request_status,
        target_type=target_type,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return VerificationRequestListResponse(
        data=[_to_response(row) for row in rows],
        meta=PaginationMeta.build(
            page=page, page_size=page_size, total_items=total, request_id=ctx.request_id
        ),
    )


@router.get(
    "/{request_id}",
    response_model=ResponseEnvelope[VerificationRequestResponse],
    summary="Read one verification request",
    description=(
        f"{_SCOPE_DESCRIPTION}\n\n"
        "Once answered, `verification` carries the attributed record: who answered, "
        "in what capacity, when, and in their own words. A request that exists but "
        "belongs to another verifier's queue is a `404`, not a `403`."
    ),
    responses={
        200: {"description": "The request."},
        404: {"model": ErrorResponse, "description": "No such request addressed to you."},
        **AUTH_ERRORS,
    },
)
def read_verification_request(
    request_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[VerificationRequestResponse]:
    request = _service(session).get_request(actor=current_user, request_id=request_id)
    return ResponseEnvelope(data=_to_response(request), meta=Meta(request_id=ctx.request_id))


@router.post(
    "/{request_id}/respond",
    response_model=ResponseEnvelope[VerificationRequestResponse],
    summary="Confirm or decline one claim, as the named verifier",
    description=(
        f"{_NOT_A_SCORE}\n\n"
        "Single-use. Only a `PENDING` request that has not passed its deadline may "
        "be answered; anything else is a `409` and the first answer is never "
        "overwritten.\n\n"
        "**A worker cannot answer a request about their own claim.** The refusal is "
        "audited and returns `403`. A `confirm` of `true` records that this person "
        "saw this claim and agrees it is what the worker wrote — nothing more. "
        "Declining requires `notes`, because a bare refusal is not actionable."
    ),
    responses={
        200: {"description": "The request, answered."},
        403: _SELF_BLOCKED,
        404: {"model": ErrorResponse, "description": "No such request addressed to you."},
        409: {"model": ErrorResponse, "description": "Already answered, withdrawn or expired."},
        422: {"model": ErrorResponse, "description": "Missing rejection note."},
        **AUTH_ERRORS,
    },
)
def respond_to_verification_request(
    request_id: uuid.UUID,
    payload: VerificationRespondRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[VerificationRequestResponse]:
    request = _service(session).respond(actor=current_user, request_id=request_id, payload=payload)
    return ResponseEnvelope(data=_to_response(request), meta=Meta(request_id=ctx.request_id))


@router.post(
    "/{request_id}/cancel",
    response_model=ResponseEnvelope[VerificationRequestResponse],
    summary="Withdraw a verification request",
    description=(
        "Only the worker who raised the request may withdraw it; a verifier calling "
        "this receives `404`. Single-use, like answering: once answered or "
        "withdrawn, the request cannot be moved again.\n\n"
        "Withdrawing is not a judgement on the claim or on the verifier. The claim "
        "is unchanged and stays in the worker's own words; the request is retained "
        "for the audit trail."
    ),
    responses={
        200: {"description": "Withdrawn."},
        404: {"model": ErrorResponse, "description": "No such request raised by you."},
        409: {"model": ErrorResponse, "description": "Already answered or withdrawn."},
        **AUTH_ERRORS,
    },
)
def cancel_verification_request(
    request_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[VerificationRequestResponse]:
    request = _service(session).cancel(actor=current_user, request_id=request_id)
    return ResponseEnvelope(data=_to_response(request), meta=Meta(request_id=ctx.request_id))


__all__ = ["router"]
