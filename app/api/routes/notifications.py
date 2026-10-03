"""``/notifications`` — the caller's own inbox.

Every query is scoped to the authenticated user in SQL. A notification id from
another user is a 404, not an empty list: an empty list would be a correct answer
for "no notifications" and a wrong one for "these are not yours".
"""

from __future__ import annotations

from typing import Annotated
import uuid

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import CurrentUser, DbSession, get_request_context
from app.core.constants import MAX_PAGE_NUMBER, MAX_PAGE_SIZE, MIN_PAGE_SIZE
from app.core.exceptions import NotFoundError
from app.schemas.common import ErrorResponse, Meta, PaginationMeta, ResponseEnvelope
from app.schemas.notifications import (
    NotificationListResponse,
    NotificationResponse,
    UnreadCountResponse,
)
from app.services.auth_service import RequestContext
from app.services.notification_service import NotificationService

router = APIRouter(prefix="/notifications", tags=["Notifications"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]


@router.get(
    "",
    response_model=NotificationListResponse,
    summary="List notifications",
    description="Newest first. Scoped to the authenticated recipient.",
    responses={
        200: {"description": "A page of notifications."},
        401: {"model": ErrorResponse, "description": "Authentication required."},
    },
)
def list_notifications(
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
    unread_only: bool = False,
    page: Annotated[int, Query(ge=1, le=MAX_PAGE_NUMBER)] = 1,
    page_size: Annotated[int, Query(ge=MIN_PAGE_SIZE, le=MAX_PAGE_SIZE)] = 20,
) -> NotificationListResponse:
    rows, total = NotificationService(session).list_for(
        recipient_user_id=current_user.id,
        unread_only=unread_only,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return NotificationListResponse(
        data=[NotificationResponse.model_validate(row) for row in rows],
        meta=PaginationMeta.build(
            page=page, page_size=page_size, total_items=total, request_id=ctx.request_id
        ),
    )


@router.get(
    "/unread-count",
    response_model=ResponseEnvelope[UnreadCountResponse],
    summary="Unread notification count",
    description="A single integer, for a badge. Separate from the list so the app "
    "can render a badge without fetching and discarding a page.",
    responses={200: {"description": "The count."}},
)
def unread_count(
    session: DbSession, current_user: CurrentUser, ctx: Ctx
) -> ResponseEnvelope[UnreadCountResponse]:
    count = NotificationService(session).unread_count(recipient_user_id=current_user.id)
    return ResponseEnvelope(
        data=UnreadCountResponse(unread_count=count), meta=Meta(request_id=ctx.request_id)
    )


@router.patch(
    "/{notification_id}/read",
    response_model=ResponseEnvelope[NotificationResponse],
    summary="Mark a notification read",
    description=(
        "Idempotent: marking an already-read notification succeeds and leaves the "
        "original timestamp, so a client that retries after a dropped response does "
        "not lose the fact that it was read."
    ),
    responses={
        200: {"description": "Marked read."},
        404: {"model": ErrorResponse, "description": "No such notification for this user."},
        401: {"model": ErrorResponse, "description": "Authentication required."},
    },
)
def mark_notification_read(
    notification_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[NotificationResponse]:
    service = NotificationService(session)
    if not service.mark_read(recipient_user_id=current_user.id, notification_id=notification_id):
        raise NotFoundError("The requested notification was not found.")

    found = service.get(recipient_user_id=current_user.id, notification_id=notification_id)
    return ResponseEnvelope(
        data=NotificationResponse.model_validate(found), meta=Meta(request_id=ctx.request_id)
    )


@router.post(
    "/read-all",
    status_code=status.HTTP_200_OK,
    response_model=ResponseEnvelope[UnreadCountResponse],
    summary="Mark every notification read",
    description="Returns the resulting unread count, which is zero.",
    responses={200: {"description": "All marked read."}},
)
def mark_all_read(
    session: DbSession, current_user: CurrentUser, ctx: Ctx
) -> ResponseEnvelope[UnreadCountResponse]:
    NotificationService(session).mark_all_read(recipient_user_id=current_user.id)
    return ResponseEnvelope(
        data=UnreadCountResponse(unread_count=0), meta=Meta(request_id=ctx.request_id)
    )
