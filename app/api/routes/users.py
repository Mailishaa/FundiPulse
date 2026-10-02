"""User account endpoints.

Two audiences, kept in separate routers so the authorisation boundary is visible
in the URL tree:

* ``/users/me`` - the caller's own account.
* ``/users/{id}`` and ``/users/`` - administrator-only, and even then a
  non-administrator caller is refused rather than silently downgraded.
"""

from __future__ import annotations

from typing import Annotated, Any
import uuid

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import (
    CurrentUser,
    DbSession,
    RequireAdmin,
    get_request_context,
)
from app.core.constants import AccountStatus, UserRole
from app.schemas.auth import UpdateUserRequest, UserResponse
from app.schemas.common import (
    ErrorResponse,
    Meta,
    PaginatedResponseEnvelope,
    PaginationMeta,
    ResponseEnvelope,
)
from app.schemas.users import (
    ChangeRoleRequest,
    SetAccountStatusRequest,
    UserDetailResponse,
)
from app.services.auth_service import RequestContext
from app.services.user_service import UserService

me_router = APIRouter(prefix="/users", tags=["Users"])


@me_router.get(
    "/me",
    response_model=ResponseEnvelope[UserDetailResponse],
    summary="The caller's own account",
    description=(
        "Includes account state and a factual summary of the caller's role "
        "context. Professional profile data lives under `/workers` or "
        "`/organizations` with its own visibility rules, so this endpoint never "
        "discloses another subject's data."
    ),
    responses={
        200: {"description": "The current account."},
        401: {"model": ErrorResponse, "description": "Authentication required."},
    },
)
def read_me(
    current_user: CurrentUser,
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ResponseEnvelope[UserDetailResponse]:
    return ResponseEnvelope(
        data=UserDetailResponse.model_validate(current_user),
        meta=Meta(request_id=context.request_id),
    )


@me_router.patch(
    "/me",
    response_model=ResponseEnvelope[UserDetailResponse],
    summary="Update the caller's own account",
    description=(
        "Only the login email address is self-service editable, and changing it "
        "clears verification: the new address is not proven until the user "
        "confirms it.\n\n"
        "The request schema forbids unknown fields, so sending `role` or "
        "`is_active` returns `422` instead of changing anything. That is the "
        "mass-assignment case OWASP A01 describes."
    ),
    responses={
        200: {"description": "Account updated."},
        401: {"model": ErrorResponse, "description": "Authentication required."},
        409: {"model": ErrorResponse, "description": "The address is already registered."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
    },
)
def update_me(
    payload: UpdateUserRequest,
    session: DbSession,
    current_user: CurrentUser,
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ResponseEnvelope[UserDetailResponse]:
    service = UserService(session)
    if payload.email is not None:
        service.update_contact_email(user=current_user, email=payload.email, context=context)
    return ResponseEnvelope(
        data=UserDetailResponse.model_validate(current_user),
        meta=Meta(request_id=context.request_id),
    )


@me_router.delete(
    "/me",
    response_model=ResponseEnvelope[dict[str, Any]],
    summary="Deactivate the caller's own account",
    description=(
        "Deactivation, not deletion. The account stops authenticating and every "
        "session is revoked, but the row is retained so that audit and "
        "moderation history stays explainable.\n\n"
        "The private contact block is scrubbed by a scheduled job "
        "(`INACTIVE_ACCOUNT_PURGE_DAYS`) rather than immediately, which gives "
        "the user a window to reactivate."
    ),
    responses={
        200: {"description": "Account deactivated."},
        401: {"model": ErrorResponse, "description": "Authentication required."},
    },
)
def deactivate_me(
    session: DbSession,
    current_user: CurrentUser,
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ResponseEnvelope[dict[str, Any]]:
    UserService(session).deactivate(user=current_user, reason="user_requested", context=context)
    return ResponseEnvelope(
        data={"status": "DEACTIVATED", "message": "Your account has been deactivated."},
        meta=Meta(request_id=context.request_id),
    )


# --------------------------------------------------------------------------- #
# Administrator surface                                                       #
# --------------------------------------------------------------------------- #
admin_router = APIRouter(prefix="/users", tags=["Users (admin)"])


@admin_router.get(
    "",
    response_model=PaginatedResponseEnvelope[UserResponse],
    summary="List accounts (administrator only)",
    description=(
        "Paginated and filtered by typed parameters - `role`, `status`. There is "
        "no generic filter expression, because allowing one would let a caller "
        "reach an arbitrary WHERE clause.\n\n"
        "Requires the `ADMIN` platform role, re-checked in the service layer and "
        "not merely in the dependency."
    ),
    responses={
        200: {"description": "A page of accounts."},
        403: {"model": ErrorResponse, "description": "Administrator role required."},
    },
)
def list_users(
    session: DbSession,
    actor: RequireAdmin,
    context: Annotated[RequestContext, Depends(get_request_context)],
    role: Annotated[UserRole | None, Query(description="Filter by platform role.")] = None,
    account_status: Annotated[
        AccountStatus | None, Query(alias="status", description="Filter by account status.")
    ] = None,
    page: Annotated[int, Query(ge=1, le=10_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> PaginatedResponseEnvelope[UserResponse]:
    service = UserService(session)
    users, total = service.list_users(
        actor=actor,
        role=role,
        status=account_status,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return PaginatedResponseEnvelope(
        data=[UserResponse.model_validate(user) for user in users],
        meta=PaginationMeta.build(
            page=page, page_size=page_size, total_items=total, request_id=context.request_id
        ),
    )


@admin_router.get(
    "/{user_id}",
    response_model=ResponseEnvelope[UserDetailResponse],
    summary="Read any account (administrator only)",
    description=(
        "Restricted to administrators. A worker or employer calling this for "
        "another account receives `403`, including for accounts that exist - the "
        "permission is checked before any record is read."
    ),
    responses={
        200: {"description": "The account."},
        403: {"model": ErrorResponse, "description": "Administrator role required."},
        404: {"model": ErrorResponse, "description": "No such account."},
    },
)
def read_user(
    user_id: uuid.UUID,
    session: DbSession,
    actor: RequireAdmin,
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ResponseEnvelope[UserDetailResponse]:
    service = UserService(session)
    # Re-assert the role in the service layer. Two independent checks mean a
    # future refactor that loosens one does not open a hole.
    service.assert_is_admin(actor)
    return ResponseEnvelope(
        data=UserDetailResponse.model_validate(service.get_by_id(user_id)),
        meta=Meta(request_id=context.request_id),
    )


@admin_router.patch(
    "/{user_id}/role",
    response_model=ResponseEnvelope[UserDetailResponse],
    summary="Change an account's platform role (administrator only)",
    description=(
        "Every change is written to the audit log with both the previous and the "
        "new role.\n\n"
        "An administrator cannot change their own role, which is how a platform "
        "ends up with no administrator and nobody able to restore one."
    ),
    responses={
        200: {"description": "Role changed."},
        403: {
            "model": ErrorResponse,
            "description": "Administrator role required, or self-change.",
        },
        404: {"model": ErrorResponse, "description": "No such account."},
    },
)
def change_user_role(
    user_id: uuid.UUID,
    payload: ChangeRoleRequest,
    session: DbSession,
    actor: RequireAdmin,
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ResponseEnvelope[UserDetailResponse]:
    service = UserService(session)
    target = service.get_by_id(user_id)
    service.change_role(actor=actor, target=target, new_role=payload.role, context=context)
    return ResponseEnvelope(
        data=UserDetailResponse.model_validate(target),
        meta=Meta(request_id=context.request_id),
    )


@admin_router.patch(
    "/{user_id}/status",
    response_model=ResponseEnvelope[UserDetailResponse],
    summary="Suspend or restore an account (administrator only)",
    description=(
        "A reason of at least five characters is mandatory and is stored in the "
        'audit trail. "Why was this account suspended" must be answerable '
        "months later.\n\n"
        "Suspending revokes every session for that account immediately."
    ),
    responses={
        200: {"description": "Status changed."},
        403: {
            "model": ErrorResponse,
            "description": "Administrator role required, or self-change.",
        },
        404: {"model": ErrorResponse, "description": "No such account."},
        422: {"model": ErrorResponse, "description": "The reason is missing or too short."},
    },
)
def set_user_status(
    user_id: uuid.UUID,
    payload: SetAccountStatusRequest,
    session: DbSession,
    actor: RequireAdmin,
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ResponseEnvelope[UserDetailResponse]:
    service = UserService(session)
    target = service.get_by_id(user_id)
    service.set_account_status(
        actor=actor,
        target=target,
        status=payload.status,
        reason=payload.reason,
        context=context,
    )
    return ResponseEnvelope(
        data=UserDetailResponse.model_validate(target),
        meta=Meta(request_id=context.request_id),
    )


__all__ = ["admin_router", "me_router"]
