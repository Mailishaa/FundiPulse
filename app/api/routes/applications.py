"""Job application endpoints: the worker's own records, and the employer's view.

The split between the two audiences is the point of this module. Everything under
``/workers/me/applications`` and ``POST /jobs/{job_id}/applications`` is scoped to
the authenticated caller's own Work Passport, and there is no request field that
could name somebody else's. Everything an employer does is gated on an active
job-managing membership of the organization that owns the job, checked in
:class:`~app.services.application_service.ApplicationService` - never here, because
a route must not decide who may see what.

There is no delete route, and there will not be one. A worker who changes their
mind withdraws: the row records it, and an employer who shortlisted somebody can
still see that the candidate withdrew rather than finding the application gone.
"""

from __future__ import annotations

from typing import Annotated, Any
import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from app.api.dependencies import (
    DbSession,
    RequireEmployerOrAdmin,
    RequireWorker,
    get_request_context,
)
from app.core.constants import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_NUMBER,
    MAX_PAGE_SIZE,
    MIN_PAGE_SIZE,
    ApplicationStatus,
)
from app.db.models.job import JobApplication
from app.db.models.worker import WorkerProfile
from app.schemas.applications import (
    ApplicationCreateRequest,
    ApplicationJobRefResponse,
    ApplicationListResponse,
    ApplicationResponse,
    ApplicationStatusChangeRequest,
    ApplicationTransitionResponse,
    ApplicationWorkerRefResponse,
)
from app.schemas.common import (
    ErrorResponse,
    Meta,
    PaginationMeta,
    ResponseEnvelope,
)
from app.services.application_service import ApplicationService
from app.services.auth_service import RequestContext
from app.services.job_service import effective_status

router = APIRouter(tags=["Applications"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]
PageQuery = Annotated[int, Query(ge=1, le=MAX_PAGE_NUMBER)]
PageSizeQuery = Annotated[int, Query(ge=MIN_PAGE_SIZE, le=MAX_PAGE_SIZE)]

#: Shared OpenAPI additions. Typed loosely because OpenAPI keys mix ints and strs.
AUTH_ERRORS: dict[int | str, Any] = {
    401: {"model": ErrorResponse, "description": "Authentication required."}
}
ROLE_ERRORS: dict[int | str, Any] = {
    403: {
        "model": ErrorResponse,
        "description": (
            "Worker role required, plus a job-managing membership of this organization."
        ),
    }
}


def to_application_response(application: JobApplication) -> ApplicationResponse:
    """Model -> response.

    The worker block is built from the *summary* fields only, so no service bug can
    reach an employer a phone number or contact address through an application
    listing: those attributes are never read here.
    """
    job = application.job
    worker = application.worker_profile
    return ApplicationResponse(
        id=application.id,
        status=application.status_enum,
        cover_note=application.cover_note,
        submitted_at=application.submitted_at,
        updated_status_at=application.updated_status_at,
        withdrawn_at=application.withdrawn_at,
        decided_at=application.decided_at,
        decision_note=application.decision_note,
        is_active=application.is_active,
        job=ApplicationJobRefResponse(
            id=job.id,
            title=job.title,
            status=effective_status(job),
            location=job.location,
            organization_id=job.organization_id,
            organization_name=job.organization.name if job.organization is not None else None,
        ),
        worker=to_worker_ref(worker),
        created_at=application.created_at,
        updated_at=application.updated_at,
    )


def to_worker_ref(profile: WorkerProfile) -> ApplicationWorkerRefResponse:
    """The applicant as an employer may see them. Professional facts only."""
    primary = next(
        (entry.trade for entry in profile.trades if entry.trade_id == profile.primary_trade_id),
        None,
    )
    return ApplicationWorkerRefResponse(
        id=profile.id,
        display_name=profile.display_name,
        headline=profile.headline,
        primary_trade_code=primary.code if primary is not None else None,
        primary_trade_name=primary.name if primary is not None else None,
        location=profile.location,
    )


def _service(session: Session) -> ApplicationService:
    return ApplicationService(session)


def _page(page: int, page_size: int, total: int, request_id: str | None) -> PaginationMeta:
    return PaginationMeta.build(
        page=page, page_size=page_size, total_items=total, request_id=request_id
    )


# --------------------------------------------------------------------------- #
# Worker                                                                       #
# --------------------------------------------------------------------------- #
@router.post(
    "/jobs/{job_id}/applications",
    response_model=ResponseEnvelope[ApplicationResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Apply to a job",
    description=(
        "Submits the caller's own application. There is no `worker_id` in the body: "
        "the worker is the authenticated account, so there is nothing to substitute.\n\n"
        "The application starts at `SUBMITTED` and can never arrive already "
        "`SHORTLISTED` or `HIRED` - those are the employer's decisions.\n\n"
        "One application per worker per job is enforced by a database unique "
        "constraint rather than a pre-check, because two taps of the button on a poor "
        "connection both pass a pre-check. The loser gets a 409. Send an "
        "`idempotency_key` to make a retry safe: the same key returns 200 with the "
        "application created the first time, because nothing was created.\n\n"
        "Only an `OPEN` platform listing accepts applications. A `DRAFT` is a 404 - "
        "an unpublished listing is not something a worker may know exists - and a "
        "closed, cancelled or expired one is a 409 that names the reason."
    ),
    responses={
        201: {"description": "Submitted as SUBMITTED."},
        404: {"model": ErrorResponse, "description": "No such visible job, or no Work Passport."},
        409: {
            "model": ErrorResponse,
            "description": "Already applied, or the job is not accepting applications.",
        },
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def apply_to_job(
    job_id: uuid.UUID,
    payload: ApplicationCreateRequest,
    response: Response,
    session: DbSession,
    actor: RequireWorker,
    ctx: Ctx,
) -> ResponseEnvelope[ApplicationResponse]:
    application, replayed = _service(session).apply(
        actor=actor, job_id=job_id, payload=payload, context=ctx
    )
    if replayed:
        # A retry returned the row the first attempt created, so nothing was created
        # and 200 is the honest answer rather than a second 201.
        response.status_code = status.HTTP_200_OK
    return ResponseEnvelope(
        data=to_application_response(application),
        meta=Meta(request_id=ctx.request_id),
    )


@router.get(
    "/workers/me/applications",
    response_model=ApplicationListResponse,
    summary="The caller's own applications",
    description=(
        "Newest first, withdrawn and rejected ones included: an application is a "
        "record of what happened, not a queue of things still to do. `status` filters "
        "the page. No other worker's application is reachable from here, and there is "
        "no parameter that could ask for one."
    ),
    responses={
        200: {"description": "A page of the caller's applications."},
        404: {"model": ErrorResponse, "description": "The account has no Work Passport."},
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def list_my_applications(
    session: DbSession,
    actor: RequireWorker,
    ctx: Ctx,
    status_filter: Annotated[ApplicationStatus | None, Query(alias="status")] = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = DEFAULT_PAGE_SIZE,
) -> ApplicationListResponse:
    rows, total = _service(session).list_own(
        actor=actor,
        status=status_filter,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return ApplicationListResponse(
        data=[to_application_response(row) for row in rows],
        meta=_page(page, page_size, total, ctx.request_id),
    )


@router.get(
    "/workers/me/applications/{application_id}",
    response_model=ResponseEnvelope[ApplicationResponse],
    summary="Read one of the caller's applications",
    description=(
        "The lookup is scoped by the caller's own Work Passport, so another worker's "
        "application id matches nothing and answers with the same 404 as an id that "
        "does not exist. A withdrawn application stays readable here - withdrawal is a "
        "status, not a deletion."
    ),
    responses={
        200: {"description": "The application."},
        404: {"model": ErrorResponse, "description": "No such application of yours."},
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def read_my_application(
    application_id: uuid.UUID,
    session: DbSession,
    actor: RequireWorker,
    ctx: Ctx,
) -> ResponseEnvelope[ApplicationResponse]:
    application = _service(session).get_own(actor=actor, application_id=application_id)
    return ResponseEnvelope(
        data=to_application_response(application),
        meta=Meta(request_id=ctx.request_id),
    )


@router.post(
    "/applications/{application_id}/withdraw",
    response_model=ApplicationTransitionResponse,
    summary="Withdraw an application",
    description=(
        "The worker's only lifecycle move, and the reason it takes no request body: "
        "there is no field here that could carry a status, so `SHORTLISTED` and "
        "`HIRED` are unreachable from this route by construction.\n\n"
        "Legal from `SUBMITTED`, `VIEWED`, `SHORTLISTED` and `REJECTED`. "
        "`WITHDRAWN` is terminal, so withdrawing twice is a 409 rather than a quiet "
        "200, and `HIRED` is terminal too - a worker cannot withdraw from a job they "
        "have been hired for.\n\n"
        "The row is not deleted. It stays readable to both sides, and the job's "
        "`application_count` falls because that counter tracks applications still "
        "awaiting a decision."
    ),
    responses={
        200: {"description": "Now withdrawn."},
        404: {"model": ErrorResponse, "description": "No such application of yours."},
        409: {"model": ErrorResponse, "description": "Illegal transition from the current status."},
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def withdraw_application(
    application_id: uuid.UUID,
    session: DbSession,
    actor: RequireWorker,
    ctx: Ctx,
) -> ApplicationTransitionResponse:
    application = _service(session).withdraw(
        actor=actor, application_id=application_id, context=ctx
    )
    return ApplicationTransitionResponse(
        data=to_application_response(application),
        meta=Meta(request_id=ctx.request_id),
    )


# --------------------------------------------------------------------------- #
# Employer                                                                     #
# --------------------------------------------------------------------------- #
@router.get(
    "/organizations/{organization_id}/jobs/{job_id}/applications",
    response_model=ApplicationListResponse,
    summary="The applicants to one of your jobs",
    description=(
        "Newest first. Restricted to an active OWNER/ADMIN/RECRUITER membership of "
        "the organization in the path, and scoped by that organization's `job_id`, so "
        "Organization A can neither list Organization B's pipeline nor reach it by "
        "substituting another organization's job id.\n\n"
        "Each row carries the applicant's professional information only. There is no "
        "phone number, contact email or contact name field in the response type at all; "
        "use `POST /workers/{profile_id}/contact-requests` to be put in touch.\n\n"
        "The list is ordered by submission time and never by anything else. A ranked "
        "list would tell a worker they were someone's best candidate, which the "
        "platform does not compute and would not stand behind."
    ),
    responses={
        200: {"description": "A page of applications."},
        404: {"model": ErrorResponse, "description": "No such job in this organization."},
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def list_job_applications(
    organization_id: uuid.UUID,
    job_id: uuid.UUID,
    session: DbSession,
    actor: RequireEmployerOrAdmin,
    ctx: Ctx,
    status_filter: Annotated[ApplicationStatus | None, Query(alias="status")] = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = DEFAULT_PAGE_SIZE,
) -> ApplicationListResponse:
    rows, total = _service(session).list_for_job(
        actor=actor,
        organization_id=organization_id,
        job_id=job_id,
        status=status_filter,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return ApplicationListResponse(
        data=[to_application_response(row) for row in rows],
        meta=_page(page, page_size, total, ctx.request_id),
    )


@router.patch(
    "/applications/{application_id}/status",
    response_model=ApplicationTransitionResponse,
    summary="Move an application through the lifecycle",
    description=(
        "The employer's decisions: `VIEWED`, `SHORTLISTED`, `REJECTED` and `HIRED`.\n\n"
        "Legal transitions only - `SUBMITTED -> VIEWED|SHORTLISTED|REJECTED|HIRED`, "
        "`VIEWED -> SHORTLISTED|REJECTED|HIRED`, "
        "`SHORTLISTED -> REJECTED|HIRED`, `REJECTED -> SHORTLISTED|HIRED`. Anything "
        "else, including re-sending the current status, is a 409 that names why: a "
        "double tap must not be answered with a 200 that changed nothing. `HIRED` and "
        "`WITHDRAWN` are terminal.\n\n"
        "`WITHDRAWN` is refused here as well as unreachable from the worker's route. "
        "An employer records a decision about a candidate; only the candidate "
        "withdraws.\n\n"
        "There is no organization in this path, so the lookup is scoped by your "
        "job-managing memberships instead: an application for a job outside your "
        "organization answers with the same 404 as an id that does not exist, which is "
        "what stops one employer confirming another's application ids by probing."
    ),
    responses={
        200: {"description": "Moved."},
        404: {"model": ErrorResponse, "description": "No such application of yours."},
        409: {"model": ErrorResponse, "description": "Illegal transition from the current status."},
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def change_application_status(
    application_id: uuid.UUID,
    payload: ApplicationStatusChangeRequest,
    session: DbSession,
    actor: RequireEmployerOrAdmin,
    ctx: Ctx,
) -> ApplicationTransitionResponse:
    application = _service(session).change_status(
        actor=actor, application_id=application_id, payload=payload, context=ctx
    )
    return ApplicationTransitionResponse(
        data=to_application_response(application),
        meta=Meta(request_id=ctx.request_id),
    )


__all__ = ["router", "to_application_response"]
