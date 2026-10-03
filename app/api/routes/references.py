"""Referee nomination endpoints, all scoped to the authenticated caller.

Every route lives under ``/workers/me`` and resolves the passport from the
session, so there is no route parameter that could address another worker. A
reference id belonging to somebody else simply matches nothing.
"""

from __future__ import annotations

from typing import Annotated, Any
import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser, DbSession, get_request_context
from app.db.models.user import User
from app.db.models.worker import WorkerProfile, WorkerReference
from app.schemas.common import (
    ErrorResponse,
    Meta,
    PaginationMeta,
    ResponseEnvelope,
    StatusResponse,
)
from app.schemas.trust import (
    WorkerReferenceCreateRequest,
    WorkerReferenceListResponse,
    WorkerReferenceResponse,
    WorkerReferenceUpdateRequest,
)
from app.services.auth_service import RequestContext
from app.services.trust_service import TrustService
from app.services.worker_service import WorkerProfileService

router = APIRouter(prefix="/workers/me", tags=["Worker references"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]
PageQuery = Annotated[int, Query(ge=1, le=10_000)]
PageSizeQuery = Annotated[int, Query(ge=1, le=100)]

AUTH_ERRORS: dict[int | str, Any] = {
    401: {"model": ErrorResponse, "description": "Authentication required."}
}


def _my_profile(session: Session, user: User) -> WorkerProfile:
    """The caller's passport, from the session. Never from the request."""
    return WorkerProfileService(session).get_for_user(user)


def _service(session: Session, user: User) -> tuple[TrustService, WorkerProfile]:
    return TrustService(session), _my_profile(session, user)


@router.post(
    "/references",
    response_model=ResponseEnvelope[WorkerReferenceResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Nominate a referee",
    description=(
        "Records a person the worker says can vouch for them. **This is not a "
        "verification**: no verification is created, no verification status is set, "
        "and the nomination starts at `PENDING_INVITATION`. Only the referee answering, "
        "or an administrator, can move it to `CONFIRMED`.\n\n"
        "The referee's `email` and `phone_number` are used to address the invitation and "
        "are returned only to the worker who supplied them."
    ),
    responses={
        201: {"description": "Nominated."},
        404: {"model": ErrorResponse, "description": "No Work Passport yet."},
        409: {"model": ErrorResponse, "description": "That referee is already nominated."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
    },
)
def create_my_reference(
    payload: WorkerReferenceCreateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkerReferenceResponse]:
    service, profile = _service(session, current_user)
    reference = service.create_reference(actor=current_user, profile=profile, payload=payload)
    return ResponseEnvelope(
        data=to_reference_response(reference), meta=Meta(request_id=ctx.request_id)
    )


@router.get(
    "/references",
    response_model=WorkerReferenceListResponse,
    summary="List the caller's nominations",
    description="Newest first. Includes nominations the worker has hidden from employers.",
)
def list_my_references(
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> WorkerReferenceListResponse:
    service, profile = _service(session, current_user)
    rows, total = service.list_references(
        profile=profile, limit=page_size, offset=(page - 1) * page_size
    )
    return WorkerReferenceListResponse(
        data=[to_reference_response(row) for row in rows],
        meta=PaginationMeta.build(
            page=page, page_size=page_size, total_items=total, request_id=ctx.request_id
        ),
    )


@router.get(
    "/references/{reference_id}",
    response_model=ResponseEnvelope[WorkerReferenceResponse],
    summary="Read one nomination",
    responses={
        200: {"description": "The nomination."},
        404: {"model": ErrorResponse, "description": "No such nomination on this passport."},
        **AUTH_ERRORS,
    },
)
def read_my_reference(
    reference_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkerReferenceResponse]:
    service, profile = _service(session, current_user)
    reference = service.get_reference(profile=profile, reference_id=reference_id)
    return ResponseEnvelope(
        data=to_reference_response(reference), meta=Meta(request_id=ctx.request_id)
    )


@router.patch(
    "/references/{reference_id}",
    response_model=ResponseEnvelope[WorkerReferenceResponse],
    summary="Update a nomination",
    description=(
        "Edits who the referee is and how they are described. `status` is not an "
        "accepted field: a worker cannot confirm their own referee. Unknown fields are "
        "refused, so a stray `status` or `user_id` is a 422."
    ),
    responses={
        200: {"description": "Updated."},
        404: {"model": ErrorResponse, "description": "No such nomination on this passport."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
    },
)
def update_my_reference(
    reference_id: uuid.UUID,
    payload: WorkerReferenceUpdateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkerReferenceResponse]:
    service, profile = _service(session, current_user)
    reference = service.update_reference(
        profile=profile,
        reference_id=reference_id,
        payload=payload,
    )
    return ResponseEnvelope(
        data=to_reference_response(reference), meta=Meta(request_id=ctx.request_id)
    )


@router.delete(
    "/references/{reference_id}",
    response_model=ResponseEnvelope[StatusResponse],
    summary="Withdraw a nomination",
    description=(
        "Soft delete. A verification may already target this nomination, and history "
        "that becomes unresolvable when a worker edits their passport would undermine "
        "the trust model."
    ),
    responses={
        200: {"description": "Withdrawn."},
        404: {"model": ErrorResponse, "description": "No such nomination on this passport."},
        **AUTH_ERRORS,
    },
)
def delete_my_reference(
    reference_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[StatusResponse]:
    service, profile = _service(session, current_user)
    service.delete_reference(actor=current_user, profile=profile, reference_id=reference_id)
    return ResponseEnvelope(
        data=StatusResponse(status="DELETED"), meta=Meta(request_id=ctx.request_id)
    )


def to_reference_response(reference: WorkerReference) -> WorkerReferenceResponse:
    """Owner-only mapping.

    Fields not carried over on purpose: ``invitation_token_hash``,
    ``invitation_expires_at``, ``invitation_consumed_at`` and
    ``responded_by_user_id`` are the referee's business, not the worker's.
    """
    return WorkerReferenceResponse.model_validate(reference)


__all__ = ["router"]
