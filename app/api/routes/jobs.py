"""Job endpoints: an employer's own listings, and public discovery.

The split is the point of this module. Routes under
``/organizations/{organization_id}/jobs`` are management operations and are gated on
a job-managing membership of that specific organization. Routes under ``/jobs`` are
discovery, and their visibility rules live in
:class:`~app.services.job_service.JobService`, not here: a route must not decide who
may see what.

Provenance is rendered structurally. An external listing arrives here already
attributed, and :func:`to_job_response` is the only place that decides what a
listing is presented as - so an aggregated job can never be shown with an
organization attached, whatever the stored row says.
"""

from __future__ import annotations

from typing import Annotated, Any
import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import (
    DbSession,
    OptionalUser,
    RequireEmployerOrAdmin,
    get_request_context,
)
from app.core.constants import (
    DEFAULT_PAGE_SIZE,
    EXTERNAL_JOB_SOURCE_TYPES,
    MAX_PAGE_NUMBER,
    MAX_PAGE_SIZE,
    MAX_SHORT_TEXT,
    MIN_PAGE_SIZE,
    EmploymentType,
    ExperienceLevel,
    JobSourceType,
    JobStatus,
)
from app.db.models.catalogue import County
from app.db.models.job import Job
from app.schemas.common import (
    ErrorResponse,
    Meta,
    PaginationMeta,
    ResponseEnvelope,
)
from app.schemas.jobs import (
    JobCreateRequest,
    JobListResponse,
    JobOrganizationRefResponse,
    JobProvenanceResponse,
    JobResponse,
    JobSkillResponse,
    JobTransitionResponse,
    JobUpdateRequest,
)
from app.services.auth_service import RequestContext
from app.services.job_service import JobService, effective_status

router = APIRouter(tags=["Jobs"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]
PageQuery = Annotated[int, Query(ge=1, le=MAX_PAGE_NUMBER)]
PageSizeQuery = Annotated[int, Query(ge=MIN_PAGE_SIZE, le=MAX_PAGE_SIZE)]

#: Shared OpenAPI additions. Typed loosely because OpenAPI keys mix ints and strs.
AUTH_ERRORS: dict[int | str, Any] = {
    401: {"model": ErrorResponse, "description": "Authentication required."}
}
#: 403 covers two independent refusals: the platform role gate (a worker may not
#: touch employer jobs at all) and the membership gate (an employer may not touch
#: another employer's jobs). Both answer 403; the error body names which.
ROLE_ERRORS: dict[int | str, Any] = {
    403: {
        "model": ErrorResponse,
        "description": (
            "Employer role required, plus a job-managing membership of this organization."
        ),
    }
}


def to_job_response(job: Job, *, county: County | None = None) -> JobResponse:
    """Model -> response, including the provenance verdict.

    The one place in the API that decides what a listing is presented as. Two rules
    are enforced here rather than left to a client:

    * an external listing never carries an organization, even if the stored row has
      one, because showing an aggregated posting under an employer's name would
      claim they advertised work they did not;
    * an external listing never reports ``accepts_applications``, because a worker
      must apply on the original site.
    """
    status_value = effective_status(job)
    is_external = JobSourceType(job.source_type) in EXTERNAL_JOB_SOURCE_TYPES
    organization = None if is_external else job.organization
    source = job.source
    return JobResponse(
        id=job.id,
        title=job.title,
        description=job.description,
        status=status_value,
        trade_code=job.trade.code if job.trade is not None else None,
        trade_name=job.trade.name if job.trade is not None else None,
        county_code=county.code if county is not None else None,
        county_name=county.name if county is not None else None,
        location=job.location,
        employment_type=EmploymentType(job.employment_type),
        experience_level=ExperienceLevel(job.experience_level),
        experience_required_years=job.experience_required_years,
        published_at=job.published_at,
        closing_at=job.closing_at,
        closed_at=job.closed_at,
        application_count=job.application_count,
        salary_min=job.salary_min,
        salary_max=job.salary_max,
        salary_currency=job.salary_currency,
        salary_period=job.salary_period,
        organization=(
            JobOrganizationRefResponse(
                id=organization.id,
                name=organization.name,
                slug=organization.slug,
                is_verified=organization.is_verified,
            )
            if organization is not None
            else None
        ),
        provenance=JobProvenanceResponse(
            source_type=JobSourceType(job.source_type),
            platform_published=not is_external,
            source_id=job.source_id,
            source_name=job.source_name or (source.name if source is not None else None),
            source_url=job.source_url,
            source_job_id=job.source_job_id,
            external_apply_url=job.external_apply_url,
            first_seen_at=job.first_seen_at,
            last_seen_at=job.last_seen_at,
            last_verified_at=job.last_verified_at,
            is_aggregated=job.is_aggregated,
        ),
        created_at=job.created_at,
        updated_at=job.updated_at,
        accepts_applications=status_value is JobStatus.OPEN
        and not job.is_aggregated
        and not is_external,
        skills=[
            JobSkillResponse(
                id=entry.skill.id,
                code=entry.skill.code,
                name=entry.skill.name,
                is_required=entry.is_required,
            )
            for entry in sorted(job.skills, key=lambda e: (not e.is_required, e.skill.name))
        ],
    )


def _service(session: Session) -> JobService:
    return JobService(session)


def _county_of(service: JobService, job: Job) -> County | None:
    """Resolve one job's county in a single query."""
    if job.county_id is None:
        return None
    return service.load_counties([job]).get(job.county_id)


def _page(page: int, page_size: int, total: int, request_id: str | None) -> PaginationMeta:
    return PaginationMeta.build(
        page=page, page_size=page_size, total_items=total, request_id=request_id
    )


# --------------------------------------------------------------------------- #
# Employer management                                                         #
# --------------------------------------------------------------------------- #
@router.post(
    "/organizations/{organization_id}/jobs",
    response_model=ResponseEnvelope[JobResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a draft job",
    description=(
        "Creates a `DRAFT` owned by the organization in the path. `organization_id` "
        "cannot be supplied in the body: the path decides ownership and is checked "
        "against an active OWNER/ADMIN/RECRUITER membership. The status is never a "
        "request field - a draft must be published deliberately - and `source_type` "
        "may only be `PLATFORM`, because an external listing is ingested from its own "
        "source and must keep that source attached."
    ),
    responses={
        201: {"description": "Created as a draft."},
        422: {"model": ErrorResponse, "description": "Unknown trade, county or skill."},
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def create_job(
    organization_id: uuid.UUID,
    payload: JobCreateRequest,
    session: DbSession,
    actor: RequireEmployerOrAdmin,
    ctx: Ctx,
) -> ResponseEnvelope[JobResponse]:
    service = _service(session)
    job = service.create(actor=actor, organization_id=organization_id, payload=payload, context=ctx)
    return ResponseEnvelope(
        data=to_job_response(job, county=_county_of(service, job)),
        meta=Meta(request_id=ctx.request_id),
    )


@router.get(
    "/organizations/{organization_id}/jobs",
    response_model=JobListResponse,
    summary="List an organization's jobs",
    description=(
        "Employer view, drafts included - so it is restricted to a job-managing "
        "member of that organization. Newest first."
    ),
    responses={
        200: {"description": "The organization's listings."},
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def list_organization_jobs(
    organization_id: uuid.UUID,
    session: DbSession,
    actor: RequireEmployerOrAdmin,
    ctx: Ctx,
    status: JobStatus | None = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = DEFAULT_PAGE_SIZE,
) -> JobListResponse:
    service = _service(session)
    rows, total = service.list_for_organization(
        actor=actor,
        organization_id=organization_id,
        status=status,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    counties = service.load_counties(rows)
    return JobListResponse(
        data=[
            to_job_response(row, county=counties.get(row.county_id) if row.county_id else None)
            for row in rows
        ],
        meta=_page(page, page_size, total, ctx.request_id),
    )


@router.patch(
    "/organizations/{organization_id}/jobs/{job_id}",
    response_model=ResponseEnvelope[JobResponse],
    summary="Update a job",
    description=(
        "Partial update. The job is looked up scoped to the organization in the "
        "path, so a job id belonging to another employer matches nothing and the "
        "answer is a 404 rather than a disclosure. `skills` replaces the whole list."
    ),
    responses={
        200: {"description": "Updated."},
        404: {"model": ErrorResponse, "description": "No such job in this organization."},
        422: {"model": ErrorResponse, "description": "Unknown trade, county or skill."},
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def update_job(
    organization_id: uuid.UUID,
    job_id: uuid.UUID,
    payload: JobUpdateRequest,
    session: DbSession,
    actor: RequireEmployerOrAdmin,
    ctx: Ctx,
) -> ResponseEnvelope[JobResponse]:
    service = _service(session)
    job = service.update(
        actor=actor,
        organization_id=organization_id,
        job_id=job_id,
        payload=payload,
        context=ctx,
    )
    return ResponseEnvelope(
        data=to_job_response(job, county=_county_of(service, job)),
        meta=Meta(request_id=ctx.request_id),
    )


@router.post(
    "/organizations/{organization_id}/jobs/{job_id}/publish",
    response_model=JobTransitionResponse,
    summary="Publish a draft job",
    description=(
        "`DRAFT` -> `OPEN`. Publishing a job that is already open, closed, cancelled "
        "or expired is a 409 with the reason, not a silent success: a client that "
        "believes it published must be right. A draft whose closing date has already "
        "passed is refused with 422 and must have `closing_at` extended first."
    ),
    responses={
        200: {"description": "Now open and visible in discovery."},
        404: {"model": ErrorResponse, "description": "No such job in this organization."},
        409: {"model": ErrorResponse, "description": "Illegal transition from the current status."},
        422: {"model": ErrorResponse, "description": "The closing date has already passed."},
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def publish_job(
    organization_id: uuid.UUID,
    job_id: uuid.UUID,
    session: DbSession,
    actor: RequireEmployerOrAdmin,
    ctx: Ctx,
) -> JobTransitionResponse:
    service = _service(session)
    job = service.publish(actor=actor, organization_id=organization_id, job_id=job_id, context=ctx)
    return JobTransitionResponse(
        data=to_job_response(job, county=_county_of(service, job)),
        meta=Meta(request_id=ctx.request_id),
    )


@router.post(
    "/organizations/{organization_id}/jobs/{job_id}/close",
    response_model=JobTransitionResponse,
    summary="Close an open job",
    description=(
        "`OPEN` -> `CLOSED`, stamping `closed_at`. Closing an already-closed job is a "
        "409 that says so rather than a no-op that returns 200: the employer needs to "
        "know the listing had already ended. A closed job cannot be reopened."
    ),
    responses={
        200: {"description": "Now closed."},
        404: {"model": ErrorResponse, "description": "No such job in this organization."},
        409: {"model": ErrorResponse, "description": "Illegal transition from the current status."},
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def close_job(
    organization_id: uuid.UUID,
    job_id: uuid.UUID,
    session: DbSession,
    actor: RequireEmployerOrAdmin,
    ctx: Ctx,
) -> JobTransitionResponse:
    service = _service(session)
    job = service.close(actor=actor, organization_id=organization_id, job_id=job_id, context=ctx)
    return JobTransitionResponse(
        data=to_job_response(job, county=_county_of(service, job)),
        meta=Meta(request_id=ctx.request_id),
    )


@router.post(
    "/organizations/{organization_id}/jobs/{job_id}/cancel",
    response_model=JobTransitionResponse,
    summary="Cancel a job",
    description=(
        "`DRAFT` or `OPEN` -> `CANCELLED`. Cancelling records that the employer "
        "withdrew the listing. A closed job cannot be cancelled: the closed record is "
        "the evidence of what happened."
    ),
    responses={
        200: {"description": "Now cancelled."},
        404: {"model": ErrorResponse, "description": "No such job in this organization."},
        409: {"model": ErrorResponse, "description": "Illegal transition from the current status."},
        **ROLE_ERRORS,
        **AUTH_ERRORS,
    },
)
def cancel_job(
    organization_id: uuid.UUID,
    job_id: uuid.UUID,
    session: DbSession,
    actor: RequireEmployerOrAdmin,
    ctx: Ctx,
) -> JobTransitionResponse:
    service = _service(session)
    job = service.cancel(actor=actor, organization_id=organization_id, job_id=job_id, context=ctx)
    return JobTransitionResponse(
        data=to_job_response(job, county=_county_of(service, job)),
        meta=Meta(request_id=ctx.request_id),
    )


# --------------------------------------------------------------------------- #
# Public discovery                                                             #
# --------------------------------------------------------------------------- #
@router.get(
    "/jobs",
    response_model=JobListResponse,
    summary="Discover jobs",
    description=(
        "Open roles, newest first. A `DRAFT` is never included, and a listing whose "
        "closing date has passed reads as `EXPIRED` and drops out of results.\n\n"
        "A signed-in caller who manages an organization also sees that "
        "organization's own drafts and closed listings; asking for any other "
        "non-open status is a 403 rather than a quietly empty page. An externally "
        "sourced listing carries its provenance and no organization - apply on the "
        "original site."
    ),
    responses={
        200: {"description": "Matching listings."},
        403: {
            "model": ErrorResponse,
            "description": "A non-open status was requested and the caller manages no employer.",
        },
        422: {"model": ErrorResponse, "description": "Unknown trade, county or skill."},
    },
)
def list_jobs(
    session: DbSession,
    viewer: OptionalUser,
    ctx: Ctx,
    trade: Annotated[str | None, Query(max_length=50)] = None,
    skill: Annotated[list[str] | None, Query(max_length=50)] = None,
    county: Annotated[str | None, Query(max_length=32)] = None,
    location: Annotated[str | None, Query(max_length=MAX_SHORT_TEXT)] = None,
    employment_type: EmploymentType | None = None,
    experience: ExperienceLevel | None = None,
    source_type: JobSourceType | None = None,
    status: JobStatus | None = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = DEFAULT_PAGE_SIZE,
) -> JobListResponse:
    service = _service(session)
    rows, total = service.discover(
        viewer=viewer,
        trade_code=trade,
        skill_codes=list(skill) if skill else None,
        county_code=county,
        location=location,
        employment_type=employment_type,
        experience_level=experience,
        source_type=source_type,
        status=status,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    counties = service.load_counties(rows)
    return JobListResponse(
        data=[
            to_job_response(row, county=counties.get(row.county_id) if row.county_id else None)
            for row in rows
        ],
        meta=_page(page, page_size, total, ctx.request_id),
    )


@router.get(
    "/jobs/{job_id}",
    response_model=ResponseEnvelope[JobResponse],
    summary="Read one job",
    description=(
        "A `DRAFT` returns 404 to anyone who does not manage its organization, the "
        "same as an id that does not exist, so drafts cannot be enumerated. An "
        "externally sourced listing always shows its origin and never an employer."
    ),
    responses={
        200: {"description": "The listing."},
        404: {"model": ErrorResponse, "description": "No such visible listing."},
        **AUTH_ERRORS,
    },
)
def read_job(
    job_id: uuid.UUID,
    session: DbSession,
    viewer: OptionalUser,
    ctx: Ctx,
) -> ResponseEnvelope[JobResponse]:
    service = _service(session)
    job = service.get_visible(job_id=job_id, viewer=viewer)
    return ResponseEnvelope(
        data=to_job_response(job, county=_county_of(service, job)),
        meta=Meta(request_id=ctx.request_id),
    )


__all__ = ["router", "to_job_response"]
