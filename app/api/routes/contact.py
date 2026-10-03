"""Contact requests: the only route by which a worker's details are ever released.

Split into two routers because the two sides are different audiences with
different authorisation. The worker side hangs off `/workers/me` and needs nothing
but the passport; the employer side is organization-scoped.
"""

from __future__ import annotations

from typing import Annotated, Any
import uuid

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import CurrentUser, DbSession, get_request_context
from app.core.constants import MAX_PAGE_NUMBER, MAX_PAGE_SIZE, MIN_PAGE_SIZE
from app.db.models.contact import ContactRequest
from app.schemas.common import ErrorResponse, Meta, PaginationMeta, ResponseEnvelope
from app.schemas.contact import (
    ContactRequestCreateRequest,
    ContactRequestListResponse,
    ContactRequestRespondRequest,
    ContactRequestResponse,
    WorkerContactBlock,
)
from app.services.auth_service import RequestContext
from app.services.contact_service import ContactRequestService
from app.services.worker_service import WorkerProfileService

router = APIRouter(tags=["Contact requests"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]
PageQuery = Annotated[int, Query(ge=1, le=MAX_PAGE_NUMBER)]
PageSizeQuery = Annotated[int, Query(ge=MIN_PAGE_SIZE, le=MAX_PAGE_SIZE)]

#: Shared OpenAPI additions. Typed loosely because OpenAPI keys mix ints and strs.
AUTH: dict[int | str, Any] = {
    401: {"model": ErrorResponse, "description": "Authentication required."}
}


def _view(request: ContactRequest, *, for_worker: bool) -> ContactRequestResponse:
    """Serialise a request.

    The worker's own contact block is attached only on the worker side, so an
    employer reading this response cannot obtain a phone number from it — and the
    worker cannot obtain one belonging to anybody else, because this route only
    ever loads their own passport's requests.
    """
    worker = request.worker
    return ContactRequestResponse(
        id=request.id,
        status=request.status,
        message=request.message,
        response_note=request.response_note,
        worker_profile_id=request.worker_profile_id,
        requester_user_id=request.requester_user_id,
        organization_id=request.organization_id,
        organization_name=request.organization.name if request.organization else None,
        job_id=request.job_id,
        job_title=request.job.title if request.job else None,
        contact_details_shared=request.contact_details_shared,
        requested_at=request.created_at,
        responded_at=request.responded_at,
        created_at=request.created_at,
        updated_at=request.updated_at,
        worker_contact=(
            WorkerContactBlock(
                phone_number=worker.phone_number,
                contact_email=worker.contact_email,
                contact_name=worker.contact_name,
                contact_phone=worker.contact_phone,
            )
            if for_worker
            else None
        ),
    )


# --------------------------------------------------------------------------- #
# Employer side                                                               #
# --------------------------------------------------------------------------- #
@router.post(
    "/workers/{profile_id}/contact-requests",
    response_model=ResponseEnvelope[ContactRequestResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Ask a worker to make contact",
    description=(
        "Files a request for an organization's members. It does **not** disclose "
        "anything: the worker sees it and decides.\n\n"
        "Requires a membership in the named organization with a role that may "
        "recruit. Contact details are released only when the worker accepts."
    ),
    responses={
        201: {"description": "Filed."},
        403: {
            "model": ErrorResponse,
            "description": "Not a recruiting role, or the worker is not accepting contact.",
        },
        404: {"model": ErrorResponse, "description": "No such visible worker."},
        409: {"model": ErrorResponse, "description": "A request is already pending."},
        **AUTH,
    },
)
def create_contact_request(
    profile_id: uuid.UUID,
    payload: ContactRequestCreateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[ContactRequestResponse]:
    request = ContactRequestService(session).create(
        actor=current_user, worker_profile_id=profile_id, payload=payload
    )
    return ResponseEnvelope(
        data=_view(request, for_worker=False), meta=Meta(request_id=ctx.request_id)
    )


@router.get(
    "/contact-requests/{request_id}",
    response_model=ResponseEnvelope[ContactRequestResponse],
    summary="Read a contact request you filed",
    description="Requires a recruiting membership in the organization that filed it.",
    responses={
        200: {"description": "The request."},
        404: {"model": ErrorResponse, "description": "No such request."},
        **AUTH,
    },
)
def read_contact_request(
    request_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[ContactRequestResponse]:
    request = ContactRequestService(session).get_for_requester(
        actor=current_user, request_id=request_id
    )
    return ResponseEnvelope(
        data=_view(request, for_worker=False), meta=Meta(request_id=ctx.request_id)
    )


@router.post(
    "/contact-requests/{request_id}/cancel",
    response_model=ResponseEnvelope[ContactRequestResponse],
    summary="Withdraw a request you filed",
    description="Only the account that filed the request may cancel it.",
    responses={
        200: {"description": "Cancelled."},
        404: {"model": ErrorResponse, "description": "No such request."},
        **AUTH,
    },
)
def cancel_contact_request(
    request_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[ContactRequestResponse]:
    request = ContactRequestService(session).cancel(actor=current_user, request_id=request_id)
    return ResponseEnvelope(
        data=_view(request, for_worker=False), meta=Meta(request_id=ctx.request_id)
    )


# --------------------------------------------------------------------------- #
# Worker side                                                                 #
# --------------------------------------------------------------------------- #
@router.get(
    "/workers/me/contact-requests",
    response_model=ContactRequestListResponse,
    summary="Requests received by the caller",
    description="The worker side of the workflow. Only the caller's own requests.",
    responses={200: {"description": "A page of requests."}, **AUTH},
)
def list_my_contact_requests(
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> ContactRequestListResponse:
    worker = WorkerProfileService(session).get_for_user(current_user)
    rows, total = ContactRequestService(session).list_for_worker(
        worker=worker, limit=page_size, offset=(page - 1) * page_size
    )
    return ContactRequestListResponse(
        data=[_view(row, for_worker=True) for row in rows],
        meta=PaginationMeta.build(
            page=page, page_size=page_size, total_items=total, request_id=ctx.request_id
        ),
    )


@router.get(
    "/workers/me/contact-requests/{request_id}",
    response_model=ResponseEnvelope[ContactRequestResponse],
    summary="Read one request received by the caller",
    responses={
        200: {"description": "The request."},
        404: {"model": ErrorResponse, "description": "No such request."},
        **AUTH,
    },
)
def read_my_contact_request(
    request_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[ContactRequestResponse]:
    worker = WorkerProfileService(session).get_for_user(current_user)
    request = ContactRequestService(session).get_for_worker(worker=worker, request_id=request_id)
    return ResponseEnvelope(
        data=_view(request, for_worker=True), meta=Meta(request_id=ctx.request_id)
    )


@router.post(
    "/workers/me/contact-requests/{request_id}/respond",
    response_model=ResponseEnvelope[ContactRequestResponse],
    summary="Accept or decline a received request",
    description=(
        "Accepting releases the caller's contact details to the requesting "
        "organization's members. Declining closes it. Either way it is final: a "
        "request can be answered once."
    ),
    responses={
        200: {"description": "Answered."},
        404: {"model": ErrorResponse, "description": "No such request."},
        409: {"model": ErrorResponse, "description": "Already answered."},
        **AUTH,
    },
)
def respond_to_contact_request(
    request_id: uuid.UUID,
    payload: ContactRequestRespondRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[ContactRequestResponse]:
    worker = WorkerProfileService(session).get_for_user(current_user)
    service = ContactRequestService(session)
    request = (
        service.accept(worker=worker, request_id=request_id, response_note=payload.response_note)
        if payload.accept
        else service.reject(
            worker=worker, request_id=request_id, response_note=payload.response_note
        )
    )
    return ResponseEnvelope(
        data=_view(request, for_worker=True), meta=Meta(request_id=ctx.request_id)
    )


__all__ = ["router"]
