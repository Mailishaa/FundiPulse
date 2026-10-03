"""``GET /workers`` — employer-facing worker discovery.

Public read: a worker appears only if they have set their passport to
``DISCOVERABLE`` or ``PUBLIC``, and the response type has no contact-detail field.
Both halves matter. The SQL predicate is the authorisation; the response schema is
the guarantee that nothing sensitive can reach the client through it.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import ValidationError

from app.api.dependencies import DbSession, OptionalUser, get_request_context
from app.core.constants import MAX_PAGE_NUMBER, MAX_PAGE_SIZE, MIN_PAGE_SIZE, AvailabilityStatus
from app.core.exceptions import ErrorDetail, ValidationError as AppValidationError
from app.schemas.common import ErrorResponse, Meta, PaginatedResponseEnvelope, PaginationMeta
from app.schemas.discovery import WorkerSearchQuery, WorkerSearchResult
from app.services.auth_service import RequestContext
from app.services.discovery_service import WorkerDiscoveryService

router = APIRouter(prefix="/workers", tags=["Workers"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]
Code = Annotated[
    str | None,
    Query(max_length=50, pattern=r"^[A-Za-z][A-Za-z0-9_]*$", description="Catalogue code."),
]


@router.get(
    "",
    response_model=PaginatedResponseEnvelope[WorkerSearchResult],
    summary="Search workers",
    description=(
        "Searches passports that the worker has chosen to expose.\n\n"
        "A passport is `PRIVATE` until its owner opts in, so a worker who has not "
        "made themselves discoverable does not appear here at all - that is a "
        "database-level filter, not a check applied afterwards.\n\n"
        "Results carry professional information only: trades, skills, county, "
        "availability, and counts of independently verified claims. There is no "
        "phone number, email address or national ID, because the response type has "
        "no field for one. Use `POST /workers/{profile_id}/contact-requests` to ask "
        "to be put in touch."
    ),
    responses={
        200: {"description": "A page of matching passports."},
        422: {"model": ErrorResponse, "description": "Invalid filter."},
    },
)
def search_workers(
    session: DbSession,
    _viewer: OptionalUser,
    ctx: Ctx,
    trade: Code = None,
    skill: Code = None,
    county: Annotated[str | None, Query(max_length=32, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")] = None,
    primary_trade: Code = None,
    availability: AvailabilityStatus | None = None,
    minimum_experience_years: Annotated[float | None, Query(ge=0, le=80)] = None,
    has_verified_experience: bool | None = None,
    has_verified_project: bool | None = None,
    has_credentials: bool | None = None,
    sort: str = "recently_updated",
    page: Annotated[int, Query(ge=1, le=MAX_PAGE_NUMBER)] = 1,
    page_size: Annotated[int, Query(ge=MIN_PAGE_SIZE, le=MAX_PAGE_SIZE)] = 20,
) -> PaginatedResponseEnvelope[WorkerSearchResult]:
    query = _build_query(
        trade=trade,
        skill=skill,
        county=county,
        primary_trade=primary_trade,
        availability=availability,
        minimum_experience_years=minimum_experience_years,
        has_verified_experience=has_verified_experience,
        has_verified_project=has_verified_project,
        has_credentials=has_credentials,
        sort=sort,
        page=page,
        page_size=page_size,
    )

    page_result = WorkerDiscoveryService(session).search(query)
    return PaginatedResponseEnvelope(
        data=page_result.results,
        meta=PaginationMeta.build(
            page=page,
            page_size=page_size,
            total_items=page_result.total,
            request_id=ctx.request_id,
        ),
    )


def _build_query(**values: Any) -> WorkerSearchQuery:
    """Reuse the query schema's own validation for query parameters.

    Constructing the model rather than validating field by field keeps one
    definition of "what a legal filter is", so the route and the service cannot
    drift apart.
    """
    try:
        return WorkerSearchQuery.model_validate(values)
    except ValidationError as exc:
        raise AppValidationError(
            "One or more query parameters are invalid.",
            details=[
                ErrorDetail(
                    field=".".join(str(part) for part in error["loc"]),
                    message=error["msg"],
                    code=error["type"],
                )
                for error in exc.errors()
            ],
        ) from exc


__all__ = ["Meta", "router"]
