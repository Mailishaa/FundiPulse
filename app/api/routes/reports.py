"""Report endpoints.

Two routers, because the authorisation boundary should be readable in the URL
tree rather than inferred from a handler:

* ``/reports`` - the caller's own reports. Scoped by ``reporter_user_id`` in the
  service, for **every** role. Reading someone else's report here is a ``404``,
  not a ``403``: a ``403`` would confirm it exists.
* ``/admin/reports`` - the moderation queue. Administrators only, audited.

There is no ``DELETE``. A report is closed by an administrator and then kept; the
record of what was reported and what was decided is the point of the table.
"""

from __future__ import annotations

from typing import Annotated, Any
import uuid

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import CurrentUser, DbSession, RequireAdmin, get_request_context
from app.core.constants import ReportStatus, ReportSubjectType
from app.db.models.moderation import Report
from app.schemas.common import (
    ErrorResponse,
    Meta,
    PaginatedResponseEnvelope,
    PaginationMeta,
    ResponseEnvelope,
)
from app.schemas.reports import (
    AdminReportResponse,
    ReportCreateRequest,
    ReportDecisionRequest,
    ReportResponse,
)
from app.services.auth_service import RequestContext
from app.services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["Reports"])
admin_router = APIRouter(prefix="/admin/reports", tags=["Reports (admin)"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]
PageQuery = Annotated[int, Query(ge=1, le=10_000)]
PageSizeQuery = Annotated[int, Query(ge=1, le=100)]

AUTH_ERRORS: dict[int | str, Any] = {
    401: {"model": ErrorResponse, "description": "Authentication required."}
}
ADMIN_ERRORS: dict[int | str, Any] = {
    403: {"model": ErrorResponse, "description": "Administrator role required."}
}


def _fields(report: Report) -> dict[str, Any]:
    """The fields both audiences share, read straight off the row."""
    return {
        "id": report.id,
        "subject_type": report.subject_type,
        "subject_id": report.subject_id,
        "reason": report.reason,
        "details": report.details,
        "status": report.status,
        "resolved_at": report.resolved_at,
        "created_at": report.created_at,
        "updated_at": report.updated_at,
    }


def _reporter_ref(reporter_user_id: uuid.UUID) -> str:
    """A stable pseudonym for a reporting account.

    Deterministic in the account id so repeated reports from the same account are
    recognisable to a reviewer, and truncated so it is not an account identifier.
    The reporter's email address, name and phone number are not part of this
    response at all - :class:`~app.schemas.reports.AdminReportResponse` has no
    field that could hold them.
    """
    return f"reporter-{str(reporter_user_id)[:8]}"


def _own_response(report: Report) -> ReportResponse:
    return ReportResponse.model_validate(_fields(report))


def _admin_response(report: Report) -> AdminReportResponse:
    return AdminReportResponse(
        **_fields(report),
        reporter_ref=_reporter_ref(report.reporter_user_id),
        resolution_note=report.resolution_note,
        resolved_by_user_id=report.resolved_by_user_id,
    )


def _page(request_id: str | None, page: int, page_size: int, total: int) -> PaginationMeta:
    return PaginationMeta.build(
        page=page, page_size=page_size, total_items=total, request_id=request_id
    )


# --------------------------------------------------------------------------- #
# The reporter's own reports                                                   #
# --------------------------------------------------------------------------- #
@router.post(
    "",
    response_model=ResponseEnvelope[ReportResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Report content for administrator review",
    description=(
        "Any authenticated user may report a work passport, an employer, a job or "
        "a verification.\n\n"
        "The subject is checked before the report is written: it must exist, it must "
        "be something the reporter could already read, and it must not be the "
        "reporter's own. A subject that does not exist and a subject the reporter "
        "is not entitled to see produce the **same** 404, so this endpoint cannot "
        "be used to discover which private passports or drafts exist.\n\n"
        "One report per reporter per subject; a second one is a 409.\n\n"
        "`status`, `resolution_note` and `resolved_by_user_id` are not accepted - "
        "the schema forbids unknown fields, so sending one is a 422 rather than a "
        "self-resolved report."
    ),
    responses={
        201: {"description": "Report filed."},
        403: {"model": ErrorResponse, "description": "Self-reporting is not allowed."},
        404: {"model": ErrorResponse, "description": "No such reportable subject."},
        409: {"model": ErrorResponse, "description": "Already reported."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
    },
)
def file_report(
    payload: ReportCreateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[ReportResponse]:
    report = ReportService(session).file_report(reporter=current_user, payload=payload, context=ctx)
    return ResponseEnvelope(data=_own_response(report), meta=Meta(request_id=ctx.request_id))


@router.get(
    "",
    response_model=PaginatedResponseEnvelope[ReportResponse],
    summary="The caller's own reports",
    description=(
        "Scoped to the caller, for every role including administrators: an "
        "administrator's own list is the reports they filed. The moderation queue "
        "is `/admin/reports`."
    ),
    responses={
        200: {"description": "A page of the caller's reports."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
    },
)
def list_my_reports(
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
    report_status: Annotated[
        ReportStatus | None,
        Query(alias="status", description="Filter by the report's status."),
    ] = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> PaginatedResponseEnvelope[ReportResponse]:
    reports, total = ReportService(session).list_own(
        reporter=current_user,
        status=report_status,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return PaginatedResponseEnvelope(
        data=[_own_response(report) for report in reports],
        meta=_page(ctx.request_id, page, page_size, total),
    )


@router.get(
    "/{report_id}",
    response_model=ResponseEnvelope[ReportResponse],
    summary="One of the caller's own reports",
    description=(
        "Another user's report is a `404`, not a `403`: reporting that it exists "
        "would defeat the point of scoping it to the reporter."
    ),
    responses={
        200: {"description": "The report."},
        404: {"model": ErrorResponse, "description": "No such report of yours."},
        **AUTH_ERRORS,
    },
)
def read_my_report(
    report_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[ReportResponse]:
    report = ReportService(session).get_own(reporter=current_user, report_id=report_id)
    return ResponseEnvelope(data=_own_response(report), meta=Meta(request_id=ctx.request_id))


# --------------------------------------------------------------------------- #
# Administrator surface                                                       #
# --------------------------------------------------------------------------- #
@admin_router.get(
    "",
    response_model=PaginatedResponseEnvelope[AdminReportResponse],
    summary="The moderation queue (administrator only)",
    description=(
        "Every report, newest first, filterable by typed parameters. There is no "
        "generic filter expression, because allowing one would let a caller reach "
        "an arbitrary WHERE clause.\n\n"
        "The response carries the subject and the reason, never the reporter's "
        "contact details: the response schema has no field that could hold an "
        "email address, a phone number or a name. The reporter appears only as "
        "`reporter_ref`, a stable pseudonym, which is enough to notice one account "
        "being reported repeatedly."
    ),
    responses={
        200: {"description": "A page of reports."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
        **ADMIN_ERRORS,
    },
)
def list_reports(
    session: DbSession,
    actor: RequireAdmin,
    ctx: Ctx,
    report_status: Annotated[
        ReportStatus | None,
        Query(alias="status", description="Filter by the report's status."),
    ] = None,
    subject_type: Annotated[
        ReportSubjectType | None, Query(description="Filter by the kind of reported record.")
    ] = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> PaginatedResponseEnvelope[AdminReportResponse]:
    reports, total = ReportService(session).list_all(
        actor=actor,
        status=report_status,
        subject_type=subject_type,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return PaginatedResponseEnvelope(
        data=[_admin_response(report) for report in reports],
        meta=_page(ctx.request_id, page, page_size, total),
    )


@admin_router.patch(
    "/{report_id}",
    response_model=ResponseEnvelope[AdminReportResponse],
    summary="Record a decision on a report (administrator only)",
    description=(
        "The body names an **intent** - `REVIEW`, `RESOLVE`, `DISMISS` or "
        "`ESCALATE` - never a status. The status is derived server-side from a "
        "transition table, so a client cannot reach a state the machine does not "
        "allow. A closed report is immutable: re-opening one is a 409, because the "
        "row is the record of what was decided.\n\n"
        "`RESOLVE`, `DISMISS` and `ESCALATE` each require a note of at least five "
        "characters. 'Why was this dismissed' must be answerable months later.\n\n"
        "Every decision is written to the audit log with the acting administrator "
        "and the previous and new status. The note stays on the report row; it is "
        "not copied into audit metadata."
    ),
    responses={
        200: {"description": "Decision recorded."},
        403: {"model": ErrorResponse, "description": "Administrator role required."},
        404: {"model": ErrorResponse, "description": "No such report."},
        409: {"model": ErrorResponse, "description": "That decision is not allowed now."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
    },
)
def decide_report(
    report_id: uuid.UUID,
    payload: ReportDecisionRequest,
    session: DbSession,
    actor: RequireAdmin,
    ctx: Ctx,
) -> ResponseEnvelope[AdminReportResponse]:
    report = ReportService(session).decide(
        actor=actor, report_id=report_id, payload=payload, context=ctx
    )
    return ResponseEnvelope(data=_admin_response(report), meta=Meta(request_id=ctx.request_id))


__all__ = ["admin_router", "router"]
