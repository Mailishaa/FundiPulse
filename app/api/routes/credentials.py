"""Credential endpoints, all scoped to the authenticated caller.

Every route lives under ``/workers/me`` and resolves the passport from the session,
so there is no route parameter that could address another worker. A credential id
belonging to somebody else matches nothing.

**Nothing here verifies a credential.** There is no field to set and no endpoint
that would accept one: a stored certificate records that the worker claims to hold
it, and ``verification`` is returned as ``null`` until the verification workflow
attests to the claim.
"""

from __future__ import annotations

from typing import Annotated, Any
import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser, DbSession, get_request_context
from app.db.models.user import User
from app.db.models.worker import Credential, WorkerProfile
from app.schemas.common import (
    ErrorResponse,
    Meta,
    PaginationMeta,
    ResponseEnvelope,
    StatusResponse,
)
from app.schemas.trust import (
    CredentialCreateRequest,
    CredentialListResponse,
    CredentialResponse,
    CredentialUpdateRequest,
)
from app.services.auth_service import RequestContext
from app.services.trust_service import TrustService
from app.services.worker_service import WorkerProfileService
from app.utils.dates import utc_today

router = APIRouter(prefix="/workers/me", tags=["Worker credentials"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]
PageQuery = Annotated[int, Query(ge=1, le=10_000)]
PageSizeQuery = Annotated[int, Query(ge=1, le=100)]

AUTH_ERRORS: dict[int | str, Any] = {
    401: {"model": ErrorResponse, "description": "Authentication required."}
}


def _service(session: Session, user: User) -> tuple[TrustService, WorkerProfile]:
    """The trust service plus the caller's own passport."""
    return TrustService(session), WorkerProfileService(session).get_for_user(user)


@router.post(
    "/credentials",
    response_model=ResponseEnvelope[CredentialResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Record a credential the worker holds",
    description=(
        "Records the claim only. **Uploading a certificate does not verify it**: the "
        "credential has no verification state, and `verification` comes back `null`. "
        "Issuer confirmation belongs to the verification workflow.\n\n"
        "`issue_date` and `expiry_date` may not be in the future, and an expiry may not "
        "precede its issue."
    ),
    responses={
        201: {"description": "Recorded as an unverified claim."},
        404: {"model": ErrorResponse, "description": "No Work Passport yet."},
        422: {"model": ErrorResponse, "description": "Unknown type or impossible dates."},
        **AUTH_ERRORS,
    },
)
def create_my_credential(
    payload: CredentialCreateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[CredentialResponse]:
    service, profile = _service(session, current_user)
    credential = service.create_credential(actor=current_user, profile=profile, payload=payload)
    return ResponseEnvelope(
        data=to_credential_response(credential), meta=Meta(request_id=ctx.request_id)
    )


@router.get(
    "/credentials",
    response_model=CredentialListResponse,
    summary="List the caller's credentials",
    description="Newest first. Each one is a self-declared claim unless a verification says otherwise.",
)
def list_my_credentials(
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> CredentialListResponse:
    service, profile = _service(session, current_user)
    rows, total = service.list_credentials(
        profile=profile, limit=page_size, offset=(page - 1) * page_size
    )
    return CredentialListResponse(
        data=[to_credential_response(row) for row in rows],
        meta=PaginationMeta.build(
            page=page, page_size=page_size, total_items=total, request_id=ctx.request_id
        ),
    )


@router.get(
    "/credentials/{credential_id}",
    response_model=ResponseEnvelope[CredentialResponse],
    summary="Read one credential",
    responses={
        200: {"description": "The credential."},
        404: {"model": ErrorResponse, "description": "No such credential on this passport."},
        **AUTH_ERRORS,
    },
)
def read_my_credential(
    credential_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[CredentialResponse]:
    service, profile = _service(session, current_user)
    credential = service.get_credential(profile=profile, credential_id=credential_id)
    return ResponseEnvelope(
        data=to_credential_response(credential), meta=Meta(request_id=ctx.request_id)
    )


@router.patch(
    "/credentials/{credential_id}",
    response_model=ResponseEnvelope[CredentialResponse],
    summary="Update a credential",
    description=(
        "Revalidated against the stored dates, so a partial patch cannot leave an "
        "expiry before its issue. Unknown fields are refused, so a stray "
        "`verification_status`, `verified` or `user_id` is a 422."
    ),
    responses={
        200: {"description": "Updated."},
        404: {"model": ErrorResponse, "description": "No such credential on this passport."},
        422: {"model": ErrorResponse, "description": "Unknown type or impossible dates."},
        **AUTH_ERRORS,
    },
)
def update_my_credential(
    credential_id: uuid.UUID,
    payload: CredentialUpdateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[CredentialResponse]:
    service, profile = _service(session, current_user)
    credential = service.update_credential(
        profile=profile,
        credential_id=credential_id,
        payload=payload,
    )
    return ResponseEnvelope(
        data=to_credential_response(credential), meta=Meta(request_id=ctx.request_id)
    )


@router.delete(
    "/credentials/{credential_id}",
    response_model=ResponseEnvelope[StatusResponse],
    summary="Remove a credential",
    description=(
        "Soft delete. A verification may already target this credential, and history "
        "that becomes unresolvable when a worker edits their passport would undermine "
        "the trust model."
    ),
    responses={
        200: {"description": "Removed."},
        404: {"model": ErrorResponse, "description": "No such credential on this passport."},
        **AUTH_ERRORS,
    },
)
def delete_my_credential(
    credential_id: uuid.UUID,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[StatusResponse]:
    service, profile = _service(session, current_user)
    service.delete_credential(actor=current_user, profile=profile, credential_id=credential_id)
    return ResponseEnvelope(
        data=StatusResponse(status="DELETED"), meta=Meta(request_id=ctx.request_id)
    )


def to_credential_response(credential: Credential) -> CredentialResponse:
    """Owner-only mapping.

    ``verification`` is left ``None``: this layer never attests to anything, and a
    derived badge here would be a claim the service cannot support. ``file_id`` is
    not exposed either - the scanned document belongs to the files domain, which
    authorises access before issuing any URL.
    """
    return CredentialResponse(
        id=credential.id,
        title=credential.title,
        credential_type=credential.credential_type,
        issuer=credential.issuer,
        issuing_country_code=credential.issuing_country_code,
        credential_number=credential.credential_number,
        issue_date=credential.issue_date,
        expiry_date=credential.expiry_date,
        description=credential.description,
        is_expired=credential.expiry_date is not None and credential.expiry_date < utc_today(),
        verification=None,
        created_at=credential.created_at,
        updated_at=credential.updated_at,
    )


__all__ = ["router"]
