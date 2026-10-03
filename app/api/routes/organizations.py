"""Organization endpoints: the company, and the memberships that reach it.

Two routers, and the split is the authorisation boundary:

* ``/organizations`` - every route is scoped to the caller's **active
  membership**. ``organization_id`` from the URL is only ever used together with
  a membership row that proves the caller belongs to that company, so one
  company can never read or change another's members by substituting an id.
  A caller with no membership gets ``404``, because ``403`` would confirm the
  company exists.
* ``/admin/organizations`` - platform administrators only: the verification mark,
  the closure of a company, and the audit-facing read.

The administrator prefix is distinct rather than the same ``/organizations``
prefix used by ``app/api/routes/users.py``, because ``GET /organizations/{id}``
exists on both surfaces and the first registered route would shadow the other.

The company contact block is returned only to ``OWNER``/``ADMIN`` members. The
build helper is handed ``include_contact=False`` for everyone else, so a worker
in the company has nothing to receive - the same structural control the worker
privacy tiers use.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
import uuid

from fastapi import APIRouter, Depends, Path, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import (
    CurrentUser,
    DbSession,
    RequireAdmin,
    RequireEmployerOrAdmin,
    get_request_context,
)
from app.core.constants import ORG_ADMIN_ROLES, MembershipStatus, OrganizationRole
from app.db.models.organization import OrganizationMembership
from app.schemas.common import (
    ErrorResponse,
    Meta,
    PaginatedResponseEnvelope,
    PaginationMeta,
    ResponseEnvelope,
    StatusResponse,
)
from app.schemas.organizations import (
    MembershipCreateRequest,
    MembershipListResponse,
    MembershipResponse,
    MembershipUpdateRequest,
    MyMembershipResponse,
    OrganizationAdminResponse,
    OrganizationAdminUpdateRequest,
    OrganizationCreateRequest,
    OrganizationListResponse,
    OrganizationPublicResponse,
    OrganizationResponse,
    OrganizationUpdateRequest,
)
from app.services.auth_service import RequestContext
from app.services.organization_service import (
    MembershipView,
    OrganizationService,
    OrganizationView,
)

router = APIRouter(prefix="/organizations", tags=["Organizations"])
admin_router = APIRouter(prefix="/admin/organizations", tags=["Organizations (admin)"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]
PageQuery = Annotated[int, Query(ge=1, le=10_000)]
PageSizeQuery = Annotated[int, Query(ge=1, le=100)]
OrgId = Annotated[uuid.UUID, Path(description="Organization id.")]
MembershipId = Annotated[uuid.UUID, Path(description="Membership id, scoped to its organization.")]

#: Shared OpenAPI additions. Typed loosely because OpenAPI keys mix ints and strs.
AUTH_ERRORS: dict[int | str, Any] = {
    401: {"model": ErrorResponse, "description": "Authentication required."}
}
NOT_A_MEMBER_ERRORS: dict[int | str, Any] = {
    404: {"model": ErrorResponse, "description": "No such organization, or none of yours."},
    **AUTH_ERRORS,
}


def _service(session: Session, ctx: RequestContext) -> OrganizationService:
    """Bind the service to the request's session and audit context."""
    return OrganizationService(session, context=ctx)


# --------------------------------------------------------------------------- #
# Serialisation                                                               #
# --------------------------------------------------------------------------- #
def _organization_data(view: OrganizationView, *, include_contact: bool) -> dict[str, Any]:
    """Flatten an organization for a response model.

    ``include_contact`` is the whole privacy boundary of this endpoint: when it
    is false the contact fields are never even read, so they cannot reach a
    response by accident.
    """
    organization = view.organization
    data: dict[str, Any] = {
        "id": organization.id,
        "name": organization.name,
        "slug": organization.slug,
        "description": organization.description,
        "industry": organization.industry,
        "website_url": organization.website_url,
        "location": organization.location,
        "county_code": view.county.code if view.county is not None else None,
        "county_name": view.county.name if view.county is not None else None,
        "is_active": organization.is_active,
        "is_verified": organization.is_verified,
        "created_at": organization.created_at,
        "updated_at": organization.updated_at,
    }
    if include_contact:
        data["contact_email"] = organization.contact_email
        data["contact_phone"] = organization.contact_phone
    return data


def _organization_response(
    view: OrganizationView, *, include_contact: bool, deleted_at: datetime | None = None
) -> OrganizationResponse:
    data = _organization_data(view, include_contact=include_contact)
    if deleted_at is None:
        return OrganizationResponse(**data)
    return OrganizationAdminResponse(**data, deleted_at=deleted_at)


def _membership_response(view: MembershipView) -> MembershipResponse:
    """One roster row. The schema has no field that could hold contact details."""
    membership = view.membership
    return MembershipResponse(
        id=membership.id,
        organization_id=membership.organization_id,
        role=membership.role,
        status=membership.status,
        title=membership.title,
        display_name=view.display_name,
        joined_at=membership.joined_at,
        created_at=membership.created_at,
        updated_at=membership.updated_at,
    )


def _my_membership_response(membership: OrganizationMembership) -> MyMembershipResponse:
    """The caller's own membership."""
    return MyMembershipResponse(
        id=membership.id,
        organization_id=membership.organization_id,
        role=membership.role,
        status=membership.status,
        title=membership.title,
        joined_at=membership.joined_at,
    )


def _may_see_contact(role: OrganizationRole) -> bool:
    return role in ORG_ADMIN_ROLES


def _page(request_id: str | None, page: int, page_size: int, total: int) -> PaginationMeta:
    return PaginationMeta.build(
        page=page, page_size=page_size, total_items=total, request_id=request_id
    )


# --------------------------------------------------------------------------- #
# The company                                                                 #
# --------------------------------------------------------------------------- #
@router.post(
    "",
    response_model=ResponseEnvelope[OrganizationResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Register a company",
    description=(
        "The caller becomes the first `OWNER`. `EMPLOYER` and `ADMIN` platform "
        "roles only, re-checked in the service: a worker account registering "
        "companies could manufacture arbitrarily many tenants with itself as owner "
        "of each.\n\n"
        "`slug` is derived from the name when omitted and is never reused after a "
        "deletion, so historic audit records keep resolving. `is_verified` is "
        "absent from this schema by design - it is an administrator's mark."
    ),
    responses={
        201: {"description": "Created."},
        403: {"model": ErrorResponse, "description": "Not an employer account."},
        409: {"model": ErrorResponse, "description": "That slug is already taken."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
    },
)
def create_organization(
    payload: OrganizationCreateRequest,
    session: DbSession,
    actor: RequireEmployerOrAdmin,
    ctx: Ctx,
) -> ResponseEnvelope[OrganizationResponse]:
    view = _service(session, ctx).create(actor=actor, payload=payload)
    return ResponseEnvelope(
        data=_organization_response(view, include_contact=True),
        meta=Meta(request_id=ctx.request_id),
    )


@router.get(
    "",
    response_model=OrganizationListResponse,
    summary="List the companies the caller belongs to",
    description=(
        "Scoped by active membership, so a caller can never page through companies "
        "they are not a member of. Listing never includes the contact block, for "
        "any role."
    ),
    responses={200: {"description": "A page of companies."}, **AUTH_ERRORS},
)
def list_organizations(
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> PaginatedResponseEnvelope[OrganizationPublicResponse]:
    views, total = _service(session, ctx).list_for_actor(
        actor=current_user, limit=page_size, offset=(page - 1) * page_size
    )
    return OrganizationListResponse(
        data=[
            OrganizationPublicResponse(**_organization_data(v, include_contact=False))
            for v in views
        ],
        meta=_page(ctx.request_id, page, page_size, total),
    )


@router.get(
    "/{organization_id}",
    response_model=ResponseEnvelope[OrganizationResponse],
    summary="Read a company the caller belongs to",
    description=(
        "Any active member may read it. `OWNER`/`ADMIN` members additionally "
        "receive the company contact block; for everyone else those fields are "
        "never populated.\n\n"
        "A caller with no active membership gets `404`, not `403`, so this cannot "
        "be used to discover which company ids exist."
    ),
    responses={200: {"description": "The company."}, **NOT_A_MEMBER_ERRORS},
)
def read_organization(
    organization_id: OrgId,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[OrganizationResponse]:
    view, membership = _service(session, ctx).get_membership(
        actor=current_user, organization_id=organization_id
    )
    include_contact = _may_see_contact(OrganizationRole(membership.role))
    return ResponseEnvelope(
        data=_organization_response(view, include_contact=include_contact),
        meta=Meta(request_id=ctx.request_id),
    )


@router.patch(
    "/{organization_id}",
    response_model=ResponseEnvelope[OrganizationResponse],
    summary="Edit the company record",
    description=(
        "`OWNER`/`ADMIN` only. `slug` is absent from the schema: it is the stable "
        "public identifier that links and audit records resolve against, so "
        "changing it would break them - and a client trying gets `422` rather than "
        "a silent no-op."
    ),
    responses={
        200: {"description": "Updated."},
        403: {"model": ErrorResponse, "description": "Not an owner or admin here."},
        404: {"model": ErrorResponse, "description": "No such organization, or none of yours."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
    },
)
def update_organization(
    organization_id: OrgId,
    payload: OrganizationUpdateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[OrganizationResponse]:
    view = _service(session, ctx).update(
        actor=current_user, organization_id=organization_id, payload=payload
    )
    # `update` already refused anyone outside OWNER/ADMIN, so the contact block
    # may be returned here without a second membership read.
    return ResponseEnvelope(
        data=_organization_response(view, include_contact=True),
        meta=Meta(request_id=ctx.request_id),
    )


@router.delete(
    "/{organization_id}",
    response_model=ResponseEnvelope[StatusResponse],
    summary="Close a company",
    description=(
        "`OWNER` only, and refused for a company whose only owner is the caller: "
        "deletion is irreversible for every member at once, including the jobs "
        "posted under the company, so ownership must first be shared or an "
        "administrator must close it.\n\n"
        "Soft delete. The row, its slug and its history are retained so that jobs, "
        "applications and audit records keep a resolvable reference."
    ),
    responses={
        200: {"description": "Closed."},
        403: {"model": ErrorResponse, "description": "Not an owner here."},
        404: {"model": ErrorResponse, "description": "No such organization, or none of yours."},
        409: {"model": ErrorResponse, "description": "The caller is the only owner."},
        **AUTH_ERRORS,
    },
)
def delete_organization(
    organization_id: OrgId,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[StatusResponse]:
    _service(session, ctx).delete(actor=current_user, organization_id=organization_id)
    return ResponseEnvelope(
        data=StatusResponse(status="DELETED"), meta=Meta(request_id=ctx.request_id)
    )


# --------------------------------------------------------------------------- #
# The caller's own membership                                                 #
# --------------------------------------------------------------------------- #
@router.get(
    "/{organization_id}/me",
    response_model=ResponseEnvelope[MyMembershipResponse],
    summary="The caller's own membership in this company",
    description=(
        "What a client needs to decide which actions it may offer. Returns `404` "
        "for a non-member, which is also the answer for a company that does not "
        "exist."
    ),
    responses={200: {"description": "The caller's membership."}, **NOT_A_MEMBER_ERRORS},
)
def read_my_membership(
    organization_id: OrgId,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[MyMembershipResponse]:
    _, membership = _service(session, ctx).get_membership(
        actor=current_user, organization_id=organization_id
    )
    return ResponseEnvelope(
        data=_my_membership_response(membership), meta=Meta(request_id=ctx.request_id)
    )


# --------------------------------------------------------------------------- #
# Memberships                                                                 #
# --------------------------------------------------------------------------- #
@router.post(
    "/{organization_id}/members",
    response_model=ResponseEnvelope[MembershipResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Add an account to the company",
    description=(
        "Adds **somebody else**: the target is named by `user_id` or by the login "
        "`email` of a registered account, and exactly one of the two is required. "
        "A request naming the caller is refused, so this endpoint can never be used "
        "to join a company of one's own accord or to hand oneself a role.\n\n"
        "`OWNER`/`ADMIN` only, and a member may only be granted a role at or below "
        "their own: an `ADMIN` cannot create an `OWNER`, which is what makes "
        "self-escalation impossible rather than merely discouraged.\n\n"
        "The response carries no email address and no account id - only the "
        "membership id, role, status and the member's Work Passport display name."
    ),
    responses={
        201: {"description": "Added."},
        403: {"model": ErrorResponse, "description": "Not an owner or admin, or self-add."},
        404: {
            "model": ErrorResponse,
            "description": "No such organization, or none of yours.",
        },
        409: {"model": ErrorResponse, "description": "Already a member."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
    },
)
def add_organization_member(
    organization_id: OrgId,
    payload: MembershipCreateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[MembershipResponse]:
    view = _service(session, ctx).add_member(
        actor=current_user, organization_id=organization_id, payload=payload
    )
    return ResponseEnvelope(data=_membership_response(view), meta=Meta(request_id=ctx.request_id))


@router.get(
    "/{organization_id}/members",
    response_model=MembershipListResponse,
    summary="List the company's members",
    description=(
        "Readable by any active member: a roster is what makes an organization "
        "usable.\n\n"
        "Names, roles, statuses and titles only. There is no email, phone number or "
        "account id in the response schema, so no service bug can turn this into "
        "a directory of member contact details."
    ),
    responses={200: {"description": "A page of members."}, **NOT_A_MEMBER_ERRORS},
)
def list_organization_members(
    organization_id: OrgId,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
    role: Annotated[
        OrganizationRole | None, Query(description="Filter by organization role.")
    ] = None,
    membership_status: Annotated[
        MembershipStatus | None, Query(alias="status", description="Filter by membership status.")
    ] = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> MembershipListResponse:
    views, total = _service(session, ctx).list_members(
        actor=current_user,
        organization_id=organization_id,
        role=role,
        status=membership_status,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return MembershipListResponse(
        data=[_membership_response(view) for view in views],
        meta=_page(ctx.request_id, page, page_size, total),
    )


@router.patch(
    "/{organization_id}/members/{membership_id}",
    response_model=ResponseEnvelope[MembershipResponse],
    summary="Change a member's role, status or title",
    description=(
        "`OWNER`/`ADMIN` only, and only at or below the caller's own role.\n\n"
        "Refused with `409` when it would leave the company with no active owner, "
        "which is what stops an owner demoting or suspending the last owner - "
        "including themselves. The membership id is scoped to its organization, so "
        "an id belonging to another company matches nothing and returns `404`."
    ),
    responses={
        200: {"description": "Updated."},
        403: {
            "model": ErrorResponse,
            "description": "Not an owner or admin, or a change above your own role.",
        },
        404: {"model": ErrorResponse, "description": "No such organization or membership."},
        409: {"model": ErrorResponse, "description": "Would leave no active owner."},
        **AUTH_ERRORS,
    },
)
def update_organization_member(
    organization_id: OrgId,
    membership_id: MembershipId,
    payload: MembershipUpdateRequest,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[MembershipResponse]:
    view = _service(session, ctx).update_member(
        actor=current_user,
        organization_id=organization_id,
        membership_id=membership_id,
        payload=payload,
    )
    return ResponseEnvelope(data=_membership_response(view), meta=Meta(request_id=ctx.request_id))


@router.delete(
    "/{organization_id}/members/{membership_id}",
    response_model=ResponseEnvelope[StatusResponse],
    summary="Remove a member",
    description=(
        "`OWNER`/`ADMIN` only, and refused with `409` when the member is the last "
        "active owner - including when an owner is removing themselves. Ownership "
        "must be transferred or a second owner promoted first.\n\n"
        "Hard delete of the membership row: the table has no `deleted_at`, and a "
        "tombstone without a partial unique index on `(organization_id, user_id)` "
        "would stop a removed member ever being re-invited. The audit row references "
        "the organization, which is only ever soft deleted, and carries the removed "
        "membership's own id and role."
    ),
    responses={
        200: {"description": "Removed."},
        403: {"model": ErrorResponse, "description": "Not an owner or admin here."},
        404: {"model": ErrorResponse, "description": "No such organization or membership."},
        409: {"model": ErrorResponse, "description": "The member is the last active owner."},
        **AUTH_ERRORS,
    },
)
def delete_organization_member(
    organization_id: OrgId,
    membership_id: MembershipId,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[StatusResponse]:
    _service(session, ctx).remove_member(
        actor=current_user, organization_id=organization_id, membership_id=membership_id
    )
    return ResponseEnvelope(
        data=StatusResponse(status="DELETED"), meta=Meta(request_id=ctx.request_id)
    )


# --------------------------------------------------------------------------- #
# Administrator surface                                                       #
# --------------------------------------------------------------------------- #
@admin_router.get(
    "",
    response_model=PaginatedResponseEnvelope[OrganizationAdminResponse],
    summary="List every company (administrator only)",
    description="Moderation and support. Includes closed companies by default.",
    responses={
        200: {"description": "A page of companies."},
        403: {"model": ErrorResponse, "description": "Administrator role required."},
    },
)
def admin_list_organizations(
    session: DbSession,
    actor: RequireAdmin,
    ctx: Ctx,
    is_active: Annotated[bool | None, Query(description="Filter by open/closed.")] = None,
    is_verified: Annotated[bool | None, Query(description="Filter by verification mark.")] = None,
    include_deleted: Annotated[bool, Query(description="Include closed companies.")] = True,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> PaginatedResponseEnvelope[OrganizationAdminResponse]:
    views, total = _service(session, ctx).admin_list(
        actor=actor,
        is_active=is_active,
        is_verified=is_verified,
        include_deleted=include_deleted,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return PaginatedResponseEnvelope(
        data=[
            _organization_response(
                v,
                include_contact=True,
                deleted_at=v.organization.deleted_at,
            )
            for v in views
        ],
        meta=_page(ctx.request_id, page, page_size, total),
    )


@admin_router.get(
    "/{organization_id}",
    response_model=ResponseEnvelope[OrganizationAdminResponse],
    summary="Read any company (administrator only)",
    description="Includes the tombstone of a closed company.",
    responses={
        200: {"description": "The company."},
        403: {"model": ErrorResponse, "description": "Administrator role required."},
        404: {"model": ErrorResponse, "description": "No such company."},
    },
)
def admin_read_organization(
    organization_id: OrgId,
    session: DbSession,
    actor: RequireAdmin,
    ctx: Ctx,
) -> ResponseEnvelope[OrganizationAdminResponse]:
    view = _service(session, ctx).admin_get(actor=actor, organization_id=organization_id)
    return ResponseEnvelope(
        data=_organization_response(
            view, include_contact=True, deleted_at=view.organization.deleted_at
        ),
        meta=Meta(request_id=ctx.request_id),
    )


@admin_router.patch(
    "/{organization_id}",
    response_model=ResponseEnvelope[OrganizationAdminResponse],
    summary="Verify or close a company (administrator only)",
    description=(
        "The only way `is_verified` is ever set: it is a platform trust mark, not a "
        "claim the company makes about itself, and not a rating."
    ),
    responses={
        200: {"description": "Updated."},
        403: {"model": ErrorResponse, "description": "Administrator role required."},
        404: {"model": ErrorResponse, "description": "No such company."},
    },
)
def admin_update_organization(
    organization_id: OrgId,
    payload: OrganizationAdminUpdateRequest,
    session: DbSession,
    actor: RequireAdmin,
    ctx: Ctx,
) -> ResponseEnvelope[OrganizationAdminResponse]:
    view = _service(session, ctx).admin_update(
        actor=actor, organization_id=organization_id, payload=payload
    )
    return ResponseEnvelope(
        data=_organization_response(
            view, include_contact=True, deleted_at=view.organization.deleted_at
        ),
        meta=Meta(request_id=ctx.request_id),
    )


@admin_router.delete(
    "/{organization_id}",
    response_model=ResponseEnvelope[StatusResponse],
    summary="Close any company (administrator only)",
    description=(
        "The administrator override for the sole-owner rule: an administrator holds "
        "no membership to lose, so refusing them would leave a company that its "
        "owner cannot close and nobody else may close. Soft delete, audited."
    ),
    responses={
        200: {"description": "Closed."},
        403: {"model": ErrorResponse, "description": "Administrator role required."},
        404: {"model": ErrorResponse, "description": "No such company."},
    },
)
def admin_delete_organization(
    organization_id: OrgId,
    session: DbSession,
    actor: RequireAdmin,
    ctx: Ctx,
) -> ResponseEnvelope[StatusResponse]:
    _service(session, ctx).admin_delete(actor=actor, organization_id=organization_id)
    return ResponseEnvelope(
        data=StatusResponse(status="DELETED"), meta=Meta(request_id=ctx.request_id)
    )


__all__ = ["admin_router", "router"]
