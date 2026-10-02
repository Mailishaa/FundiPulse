"""Work Passport endpoints, all scoped to the authenticated caller."""

from __future__ import annotations

from typing import Annotated, Any
import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser, DbSession, OptionalUser, get_request_context
from app.api.serializers import (
    to_experience_response,
    to_private_profile,
    to_project_response,
    to_public_profile,
)
from app.db.models.catalogue import County
from app.schemas.common import (
    ErrorResponse,
    Meta,
    PaginationMeta,
    ResponseEnvelope,
    StatusResponse,
)
from app.schemas.experiences import (
    DerivedExperienceResponse,
    WorkExperienceCreateRequest,
    WorkExperienceListResponse,
    WorkExperienceResponse,
    WorkExperienceUpdateRequest,
)
from app.schemas.projects import (
    ProjectCreateRequest,
    ProjectListResponse,
    ProjectResponse,
    ProjectUpdateRequest,
)
from app.schemas.workers import (
    PreferredCountiesUpdateRequest,
    WorkerProfileCreateRequest,
    WorkerProfilePrivateResponse,
    WorkerProfilePublicResponse,
    WorkerProfileUpdateRequest,
    WorkerSkillsUpdateRequest,
    WorkerTradesUpdateRequest,
)
from app.services.auth_service import RequestContext
from app.services.worker_service import WorkerProfileService

router = APIRouter(prefix="/workers", tags=["Workers"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]
PageQuery = Annotated[int, Query(ge=1, le=10_000)]
PageSizeQuery = Annotated[int, Query(ge=1, le=100)]

#: Shared OpenAPI additions. Typed loosely because OpenAPI keys mix ints and strs.
AUTH_ERRORS: dict[int | str, Any] = {
    401: {"model": ErrorResponse, "description": "Authentication required."}
}


def _service(session: Session) -> WorkerProfileService:
    return WorkerProfileService(session)


# --------------------------------------------------------------------------- #
# The caller's passport                                                       #
# --------------------------------------------------------------------------- #
@router.post(
    "/me/profile",
    response_model=ResponseEnvelope[WorkerProfilePrivateResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create the caller's Work Passport",
    description=(
        "One passport per account. Defaults to `PRIVATE` visibility and "
        "`contact_preference=NONE`, so nothing is discoverable until the worker opts in."
    ),
    responses={
        201: {"description": "Created."},
        409: {"model": ErrorResponse, "description": "A passport already exists."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
    },
)
def create_my_profile(
    payload: WorkerProfileCreateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkerProfilePrivateResponse]:
    service = _service(session)
    profile = service.create(actor=current_user, payload=payload)
    county, preferred = service.load_counties(profile)
    return ResponseEnvelope(
        data=to_private_profile(profile, county=county, preferred=preferred),
        meta=Meta(request_id=ctx.request_id),
    )


@router.get(
    "/me/profile",
    response_model=ResponseEnvelope[WorkerProfilePrivateResponse],
    summary="The caller's Work Passport",
    description=(
        "Owner-only view. This is the **only** endpoint that returns phone numbers or "
        "an alternate contact email."
    ),
    responses={
        200: {"description": "The passport."},
        404: {"model": ErrorResponse, "description": "No passport yet."},
        **AUTH_ERRORS,
    },
)
def read_my_profile(
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkerProfilePrivateResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    county, preferred = service.load_counties(profile)
    return ResponseEnvelope(
        data=to_private_profile(profile, county=county, preferred=preferred),
        meta=Meta(request_id=ctx.request_id),
    )


@router.patch(
    "/me/profile",
    response_model=ResponseEnvelope[WorkerProfilePrivateResponse],
    summary="Update the caller's Work Passport",
    description="Partial update. Unknown fields are refused, so a stray `role` is a 422.",
    responses={
        200: {"description": "Updated."},
        404: {"model": ErrorResponse, "description": "No passport yet."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
    },
)
def update_my_profile(
    payload: WorkerProfileUpdateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkerProfilePrivateResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    updated = service.update(actor=current_user, profile_id=profile.id, payload=payload)
    county, preferred = service.load_counties(updated)
    return ResponseEnvelope(
        data=to_private_profile(updated, county=county, preferred=preferred),
        meta=Meta(request_id=ctx.request_id),
    )


@router.put(
    "/me/trades",
    response_model=ResponseEnvelope[WorkerProfilePrivateResponse],
    summary="Replace the caller's trades",
    description=(
        "Replaces the list wholesale so exactly one trade can be primary. An unknown "
        "trade code is a 422 naming it."
    ),
    responses={
        200: {"description": "Replaced."},
        422: {"model": ErrorResponse, "description": "Unknown or duplicated trade."},
        **AUTH_ERRORS,
    },
)
def replace_my_trades(
    payload: WorkerTradesUpdateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkerProfilePrivateResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    updated = service.replace_trades(actor=current_user, profile_id=profile.id, payload=payload)
    county, preferred = service.load_counties(updated)
    return ResponseEnvelope(
        data=to_private_profile(updated, county=county, preferred=preferred),
        meta=Meta(request_id=ctx.request_id),
    )


@router.put(
    "/me/skills",
    response_model=ResponseEnvelope[WorkerProfilePrivateResponse],
    summary="Replace the caller's skills",
    description="Proficiency is self-declared and is never treated as verification.",
    responses={
        200: {"description": "Replaced."},
        422: {"model": ErrorResponse, "description": "Unknown or duplicated skill."},
        **AUTH_ERRORS,
    },
)
def replace_my_skills(
    payload: WorkerSkillsUpdateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkerProfilePrivateResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    updated = service.replace_skills(actor=current_user, profile_id=profile.id, payload=payload)
    county, preferred = service.load_counties(updated)
    return ResponseEnvelope(
        data=to_private_profile(updated, county=county, preferred=preferred),
        meta=Meta(request_id=ctx.request_id),
    )


@router.put(
    "/me/preferred-counties",
    response_model=ResponseEnvelope[WorkerProfilePrivateResponse],
    summary="Replace the caller's preferred work counties",
    responses={
        200: {"description": "Replaced."},
        422: {"model": ErrorResponse, "description": "Unknown county code."},
        **AUTH_ERRORS,
    },
)
def replace_my_preferred_counties(
    payload: PreferredCountiesUpdateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkerProfilePrivateResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    updated = service.replace_preferred_counties(
        actor=current_user, profile_id=profile.id, payload=payload
    )
    county, preferred = service.load_counties(updated)
    return ResponseEnvelope(
        data=to_private_profile(updated, county=county, preferred=preferred),
        meta=Meta(request_id=ctx.request_id),
    )


# --------------------------------------------------------------------------- #
# Work experience                                                            #
# --------------------------------------------------------------------------- #
@router.post(
    "/me/experiences",
    response_model=ResponseEnvelope[WorkExperienceResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Record previous work experience",
    description=(
        "Records a claim. It is **not** verified by being entered, and there is no "
        "field that would mark it so."
    ),
    responses={
        201: {"description": "Recorded."},
        422: {"model": ErrorResponse, "description": "Invalid dates or unknown trade."},
        **AUTH_ERRORS,
    },
)
def create_my_experience(
    payload: WorkExperienceCreateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkExperienceResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    record = service.create_experience(actor=current_user, profile_id=profile.id, payload=payload)
    return ResponseEnvelope(
        data=to_experience_response(record, county=_county_of(session, record.county_id)),
        meta=Meta(request_id=ctx.request_id),
    )


@router.get(
    "/me/experiences",
    response_model=WorkExperienceListResponse,
    summary="List the caller's work experience",
    description="Current roles first, then most recent.",
)
def list_my_experiences(
    session: DbSession,
    current_user: CurrentUser,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> WorkExperienceListResponse:
    service = _service(session)
    profile = service.get_for_user(current_user)
    rows, total = service.list_experiences(
        profile=profile, limit=page_size, offset=(page - 1) * page_size
    )
    return WorkExperienceListResponse(
        data=[to_experience_response(row) for row in rows],
        meta=_page(page, page_size, total, None),
    )


@router.get(
    "/me/experiences/{experience_id}",
    response_model=ResponseEnvelope[WorkExperienceResponse],
    summary="Read one work experience record",
    responses={
        200: {"description": "The record."},
        404: {"model": ErrorResponse, "description": "No such record on this passport."},
        **AUTH_ERRORS,
    },
)
def read_my_experience(
    experience_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkExperienceResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    record = service.get_experience(profile=profile, experience_id=experience_id)
    return ResponseEnvelope(
        data=to_experience_response(record, county=_county_of(session, record.county_id)),
        meta=Meta(request_id=ctx.request_id),
    )


@router.patch(
    "/me/experiences/{experience_id}",
    response_model=ResponseEnvelope[WorkExperienceResponse],
    summary="Update a work experience record",
    description="Revalidated against the stored dates, so a partial patch cannot produce an invalid range.",
    responses={
        200: {"description": "Updated."},
        404: {"model": ErrorResponse, "description": "No such record on this passport."},
        422: {"model": ErrorResponse, "description": "The resulting dates are invalid."},
        **AUTH_ERRORS,
    },
)
def update_my_experience(
    experience_id: uuid.UUID,
    payload: WorkExperienceUpdateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkExperienceResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    record = service.update_experience(
        actor=current_user,
        profile_id=profile.id,
        experience_id=experience_id,
        payload=payload,
    )
    return ResponseEnvelope(
        data=to_experience_response(record, county=_county_of(session, record.county_id)),
        meta=Meta(request_id=ctx.request_id),
    )


@router.delete(
    "/me/experiences/{experience_id}",
    response_model=ResponseEnvelope[StatusResponse],
    summary="Remove a work experience record",
    description=(
        "Soft delete. A verification may already reference this record, and a history "
        "that becomes unresolvable when a worker edits their passport would undermine "
        "the trust model."
    ),
    responses={
        200: {"description": "Removed."},
        404: {"model": ErrorResponse, "description": "No such record on this passport."},
        **AUTH_ERRORS,
    },
)
def delete_my_experience(
    experience_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[StatusResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    service.delete_experience(
        actor=current_user, profile_id=profile.id, experience_id=experience_id
    )
    return ResponseEnvelope(
        data=StatusResponse(status="DELETED"), meta=Meta(request_id=ctx.request_id)
    )


@router.get(
    "/me/experience-summary",
    response_model=ResponseEnvelope[DerivedExperienceResponse],
    summary="Derived experience",
    description=(
        "Computed from the dated records, with overlapping roles merged so concurrent "
        "work is not counted twice. The self-declared figure is returned alongside, "
        "never instead."
    ),
    responses={200: {"description": "Derived figures."}, **AUTH_ERRORS},
)
def my_experience_summary(
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[DerivedExperienceResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    return ResponseEnvelope(
        data=DerivedExperienceResponse.model_validate(service.derive_experience_summary(profile)),
        meta=Meta(request_id=ctx.request_id),
    )


# --------------------------------------------------------------------------- #
# Projects                                                                   #
# --------------------------------------------------------------------------- #
@router.post(
    "/me/projects",
    response_model=ResponseEnvelope[ProjectResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Document a construction project",
    description="`role_title` is required: a project name without the worker's role says nothing about them.",
    responses={
        201: {"description": "Documented."},
        422: {"model": ErrorResponse, "description": "Invalid dates or unknown trade."},
        **AUTH_ERRORS,
    },
)
def create_my_project(
    payload: ProjectCreateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[ProjectResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    project = service.create_project(actor=current_user, profile_id=profile.id, payload=payload)
    return ResponseEnvelope(
        data=to_project_response(project, county=_county_of(session, project.county_id)),
        meta=Meta(request_id=ctx.request_id),
    )


@router.get(
    "/me/projects",
    response_model=ProjectListResponse,
    summary="List the caller's projects",
    description="Includes projects marked confidential; the public view never does.",
)
def list_my_projects(
    session: DbSession,
    current_user: CurrentUser,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> ProjectListResponse:
    service = _service(session)
    profile = service.get_for_user(current_user)
    rows, total = service.list_projects(
        profile=profile, limit=page_size, offset=(page - 1) * page_size, include_confidential=True
    )
    return ProjectListResponse(
        data=[to_project_response(row) for row in rows], meta=_page(page, page_size, total, None)
    )


@router.get(
    "/me/projects/{project_id}",
    response_model=ResponseEnvelope[ProjectResponse],
    summary="Read one documented project",
    responses={
        200: {"description": "The project."},
        404: {"model": ErrorResponse, "description": "No such project on this passport."},
        **AUTH_ERRORS,
    },
)
def read_my_project(
    project_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[ProjectResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    project = service.get_project(profile=profile, project_id=project_id)
    return ResponseEnvelope(
        data=to_project_response(project, county=_county_of(session, project.county_id)),
        meta=Meta(request_id=ctx.request_id),
    )


@router.patch(
    "/me/projects/{project_id}",
    response_model=ResponseEnvelope[ProjectResponse],
    summary="Update a documented project",
    responses={
        200: {"description": "Updated."},
        404: {"model": ErrorResponse, "description": "No such project on this passport."},
        422: {"model": ErrorResponse, "description": "The resulting dates are invalid."},
        **AUTH_ERRORS,
    },
)
def update_my_project(
    project_id: uuid.UUID,
    payload: ProjectUpdateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[ProjectResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    project = service.update_project(
        actor=current_user, profile_id=profile.id, project_id=project_id, payload=payload
    )
    return ResponseEnvelope(
        data=to_project_response(project, county=_county_of(session, project.county_id)),
        meta=Meta(request_id=ctx.request_id),
    )


@router.delete(
    "/me/projects/{project_id}",
    response_model=ResponseEnvelope[StatusResponse],
    summary="Remove a documented project",
    description="Soft delete, for the same reason as work experience.",
    responses={
        200: {"description": "Removed."},
        404: {"model": ErrorResponse, "description": "No such project on this passport."},
        **AUTH_ERRORS,
    },
)
def delete_my_project(
    project_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[StatusResponse]:
    service = _service(session)
    profile = service.get_for_user(current_user)
    service.delete_project(actor=current_user, profile_id=profile.id, project_id=project_id)
    return ResponseEnvelope(
        data=StatusResponse(status="DELETED"), meta=Meta(request_id=ctx.request_id)
    )


# --------------------------------------------------------------------------- #
# Other workers                                                              #
# --------------------------------------------------------------------------- #
@router.get(
    "/{profile_id}",
    response_model=ResponseEnvelope[WorkerProfilePublicResponse],
    summary="Read a worker's public passport",
    description=(
        "Professional information only, and only when the worker has set the profile to "
        "`DISCOVERABLE` or `PUBLIC`. A private passport returns 404 rather than 403, so "
        "existence is not disclosed. Confidential projects are never included."
    ),
    responses={
        200: {"description": "The public passport."},
        404: {"model": ErrorResponse, "description": "No such visible passport."},
    },
)
def read_worker_profile(
    profile_id: uuid.UUID,
    session: DbSession,
    viewer: OptionalUser,
    ctx: Ctx,
) -> ResponseEnvelope[WorkerProfilePublicResponse]:
    service = _service(session)
    profile = service.get_by_id(profile_id)
    actor = viewer
    service.assert_visible_to(viewer=actor, profile=profile)

    county, _ = service.load_counties(profile)
    return ResponseEnvelope(
        data=to_public_profile(profile, county=county), meta=Meta(request_id=ctx.request_id)
    )


def _county_of(session: Session, county_id: uuid.UUID | None) -> County | None:
    """Resolve a county in one query rather than relying on a relationship load."""
    if county_id is None:
        return None
    found = session.execute(select(County).where(County.id == county_id)).scalar_one_or_none()
    return found if isinstance(found, County) else None


def _page(page: int, page_size: int, total: int, request_id: str | None) -> PaginationMeta:
    return PaginationMeta.build(
        page=page, page_size=page_size, total_items=total, request_id=request_id
    )


__all__ = ["router"]
