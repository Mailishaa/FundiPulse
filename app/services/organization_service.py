"""Organizations and their memberships: the rules that decide who may do what.

Authorisation invariant, applied to every method in this module:

    access is granted by an **active membership row**, never by an id in the URL.

``organization_id`` is only ever used *together with* a membership that proves
the caller belongs to that company. A caller who substitutes another company's
id therefore matches nothing and receives ``404`` - which, unlike ``403``, does
not confirm that the company exists.

Three more rules live here rather than in a route, because a route is not the
only possible caller:

* **one owner minimum.** An organization always keeps at least one ``ACTIVE``
  ``OWNER``, so it can never be demoted into a state where nobody can administer
  it. This covers demotion, suspension, removal *and* deletion of the company.
* **a privilege lattice.** A member may only be granted, or acted upon, at or
  below their own organization role, so an ``ADMIN`` cannot manufacture an
  ``OWNER`` - including one for themselves.
* **self-service is never membership management.** A caller cannot add
  themselves to a company or hand themselves a role; the target of an add is
  always somebody else.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import NoReturn
import unicodedata
import uuid

from sqlalchemy import Select, case, func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.core.constants import (
    ORG_ADMIN_ROLES,
    AuditAction,
    MembershipStatus,
    OrganizationRole,
    UserRole,
)
from app.core.exceptions import (
    AppError,
    ConflictError,
    ForbiddenError,
    InsufficientRoleError,
    InvalidStateTransitionError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models.catalogue import County
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.user import User
from app.db.models.worker import WorkerProfile
from app.schemas.organizations import (
    MembershipCreateRequest,
    MembershipUpdateRequest,
    OrganizationAdminUpdateRequest,
    OrganizationCreateRequest,
    OrganizationUpdateRequest,
)
from app.services.audit_service import AuditService
from app.services.auth_service import RequestContext
from app.services.worker_service import CatalogueService
from app.utils.email import normalise_email

logger = get_logger(__name__)

#: The organization privilege lattice. A member may only be granted, or acted
#: upon, at or below the role their own membership holds.
ROLE_RANK: Mapping[OrganizationRole, int] = {
    OrganizationRole.OWNER: 4,
    OrganizationRole.ADMIN: 3,
    OrganizationRole.RECRUITER: 2,
    OrganizationRole.MEMBER: 1,
}

_SLUG_SEPARATORS = re.compile(r"[^a-z0-9]+")

#: Ordering for the roster: owners first, then admins, recruiters, members.
_ROLE_ORDER = case(
    (OrganizationMembership.role == OrganizationRole.OWNER.value, 0),
    (OrganizationMembership.role == OrganizationRole.ADMIN.value, 1),
    (OrganizationMembership.role == OrganizationRole.RECRUITER.value, 2),
    else_=3,
)


# --------------------------------------------------------------------------- #
# Errors                                                                      #
# --------------------------------------------------------------------------- #
class OrganizationNotFoundError(NotFoundError):
    public_message = "No such organization was found."


class MembershipNotFoundError(NotFoundError):
    public_message = "No such membership was found."


class MembershipExistsError(ConflictError):
    public_message = "That account is already a member of this organization."


class DuplicateSlugError(ConflictError):
    public_message = "That organization identifier is already taken."


class LastOwnerError(InvalidStateTransitionError):
    """Raised instead of leaving an organization with nobody able to own it."""

    public_message = "An organization must keep at least one active owner."


class OrganizationRoleEscalationError(ForbiddenError):
    public_message = "You cannot grant or change a role above your own."


class SelfMembershipError(ForbiddenError):
    public_message = "You cannot manage your own membership."


# --------------------------------------------------------------------------- #
# Views                                                                       #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class OrganizationView:
    """An organization with its county already resolved, so no route re-queries it."""

    organization: Organization
    county: County | None


@dataclass(frozen=True, slots=True)
class MembershipView:
    """A membership plus the member's public display name, if they published one."""

    membership: OrganizationMembership
    display_name: str | None


# --------------------------------------------------------------------------- #
# Service                                                                     #
# --------------------------------------------------------------------------- #
class OrganizationService:
    """Companies and the memberships that authorise access to them."""

    def __init__(self, session: Session, *, context: RequestContext | None = None) -> None:
        self._session = session
        self._audit = AuditService(session)
        self._catalogue = CatalogueService(session)
        self._ctx = context or RequestContext()

    # -- reads ----------------------------------------------------------- #

    def list_for_actor(
        self, *, actor: User, limit: int = 20, offset: int = 0
    ) -> tuple[list[OrganizationView], int]:
        """Every company the caller actively belongs to.

        Scoped by membership rather than by ``is_active`` alone: there is no
        query a caller can run that reaches a company they are not a member of.
        A pending or suspended membership confers nothing, so those companies are
        excluded rather than listed-but-unusable.
        """
        conditions = [
            OrganizationMembership.user_id == actor.id,
            OrganizationMembership.status == MembershipStatus.ACTIVE.value,
            Organization.deleted_at.is_(None),
        ]
        total = int(
            self._session.execute(
                select(func.count())
                .select_from(OrganizationMembership)
                .join(Organization, Organization.id == OrganizationMembership.organization_id)
                .where(*conditions)
            ).scalar_one()
        )
        # The county join is an outer join, so that column is nullable at runtime;
        # SQLAlchemy types it as County, which is why it is not annotated here.
        statement: Select[tuple[Organization, County]] = (
            select(Organization, County)
            .join(OrganizationMembership, OrganizationMembership.organization_id == Organization.id)
            .join(County, County.id == Organization.county_id, isouter=True)
            .where(*conditions)
            # Deterministic: newest company first, id last so paging is stable.
            .order_by(Organization.created_at.desc(), Organization.id)
            .limit(limit)
            .offset(offset)
        )
        rows = self._session.execute(statement).all()
        return [OrganizationView(organization=row[0], county=row[1]) for row in rows], total

    def get_membership(
        self, *, actor: User, organization_id: uuid.UUID
    ) -> tuple[OrganizationView, OrganizationMembership]:
        """The company, resolved together with the caller's own membership.

        Both come from one authorisation, so the read and the decision about what
        the caller may see of it cannot drift apart.
        """
        organization, membership = self._authorize(
            actor=actor, organization_id=organization_id, operation="read"
        )
        return self._with_county(organization), membership

    def list_members(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        role: OrganizationRole | None = None,
        status: MembershipStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[MembershipView], int]:
        """The roster. Any active member may read it.

        The response carries names, roles and statuses only - no email, phone or
        account id - so a worker in the roster cannot harvest a colleague's
        contact details by reading this endpoint.
        """
        organization, _ = self._authorize(
            actor=actor, organization_id=organization_id, operation="list_members"
        )
        conditions = [OrganizationMembership.organization_id == organization.id]
        if role is not None:
            conditions.append(OrganizationMembership.role == role.value)
        if status is not None:
            conditions.append(OrganizationMembership.status == status.value)

        total = int(
            self._session.execute(
                select(func.count()).select_from(OrganizationMembership).where(*conditions)
            ).scalar_one()
        )
        statement: Select[tuple[OrganizationMembership]] = (
            select(OrganizationMembership)
            .where(*conditions)
            .order_by(_ROLE_ORDER, OrganizationMembership.created_at, OrganizationMembership.id)
            .limit(limit)
            .offset(offset)
        )
        rows = list(self._session.execute(statement).scalars())
        names = self._display_names({row.user_id for row in rows})
        return [
            MembershipView(membership=row, display_name=names.get(row.user_id)) for row in rows
        ], total

    # -- create and update ----------------------------------------------- #

    def create(self, *, actor: User, payload: OrganizationCreateRequest) -> OrganizationView:
        """Register a company, with the caller as its first owner.

        Only an employer account may do this: a worker account registering
        companies would let any single account manufacture arbitrarily many
        tenants, each with itself as owner, and there is no business reason for
        it. An administrator may create a company on a company's behalf.
        """
        self._require_creator(actor)

        county = self._county(payload.county_code)
        slug = payload.slug or derive_slug(payload.name)
        # Soft-deleted rows keep their slug, so a retired company cannot be
        # impersonated by a successor claiming the same identifier.
        self._assert_slug_free(slug)

        organization = Organization(
            name=payload.name.strip(),
            slug=slug,
            description=payload.description,
            industry=payload.industry,
            website_url=payload.website_url,
            contact_email=payload.contact_email,
            contact_phone=payload.contact_phone,
            location=payload.location,
            county=county.name if county is not None else None,
            county_id=county.id if county is not None else None,
            is_active=True,
            is_verified=False,
        )
        self._session.add(organization)
        self._session.flush()

        membership = OrganizationMembership(
            organization_id=organization.id,
            user_id=actor.id,
            role=OrganizationRole.OWNER.value,
            status=MembershipStatus.ACTIVE.value,
            joined_at=utcnow(),
        )
        self._session.add(membership)
        self._session.flush()

        self._record(
            action=AuditAction.ADMIN_ACTION,
            actor=actor,
            organization=organization,
            operation="create_organization",
            metadata={
                "slug": organization.slug,
                "organization_role": OrganizationRole.OWNER.value,
                "membership_id": membership.id,
            },
        )
        logger.info(
            "Organization created",
            extra={"organization_id": str(organization.id), "actor_user_id": str(actor.id)},
        )
        return self._with_county(organization)

    def update(
        self, *, actor: User, organization_id: uuid.UUID, payload: OrganizationUpdateRequest
    ) -> OrganizationView:
        """Edit the company record. ``OWNER`` or ``ADMIN`` only."""
        organization, actor_membership = self._authorize(
            actor=actor,
            organization_id=organization_id,
            required_roles=ORG_ADMIN_ROLES,
            operation="update_organization",
            lock=True,
        )
        data = payload.model_dump(exclude_unset=True)
        if not data:
            return self._with_county(organization)

        if "county_code" in data:
            county = self._county(data.pop("county_code"))
            organization.county_id = county.id if county is not None else None
            organization.county = county.name if county is not None else None
        for field in (
            "description",
            "industry",
            "website_url",
            "location",
            "contact_email",
            "contact_phone",
        ):
            if field in data:
                value = data[field]
                setattr(organization, field, value.strip() if isinstance(value, str) else value)
        if "name" in data:
            organization.name = str(data["name"]).strip()

        self._session.flush()
        self._record(
            action=AuditAction.ADMIN_ACTION,
            actor=actor,
            organization=organization,
            organization_role=actor_membership.role,
            operation="update_organization",
            metadata={"fields": sorted(data)},
        )
        return self._with_county(organization)

    def delete(self, *, actor: User, organization_id: uuid.UUID) -> None:
        """Close a company. Soft delete, and refused for a sole owner.

        Soft delete because jobs, applications and audit rows reference the
        company: a hard delete would leave them pointing at nothing. The slug is
        retained for the same reason.

        A company whose only owner is the caller cannot be deleted by that
        caller. A sole owner can end up holding a company they never intended to
        own - a trial signup, a company split up, a shared account - and deletion
        is irreversible for every member at once, including the jobs posted under
        it. Ownership must first be shared (``PATCH`` the second owner to
        ``OWNER``), or the company closed by an administrator, who has no
        membership to lose.
        """
        organization, actor_membership = self._authorize(
            actor=actor,
            organization_id=organization_id,
            required_roles=frozenset({OrganizationRole.OWNER}),
            operation="delete_organization",
            lock=True,
        )
        if self._active_owner_count(organization.id) < 2:
            self._refuse(
                action=AuditAction.ADMIN_ACTION,
                actor=actor,
                organization_id=organization.id,
                organization_role=actor_membership.role,
                operation="delete_organization",
                code="LAST_OWNER_CANNOT_DELETE_ORGANIZATION",
                message=(
                    "An organization with a single owner cannot be deleted by that owner. "
                    "Promote another member to OWNER first, or ask an administrator to close it."
                ),
                error=LastOwnerError,
            )

        organization.deleted_at = utcnow()
        organization.is_active = False
        self._session.flush()
        self._record(
            action=AuditAction.ADMIN_ACTION,
            actor=actor,
            organization=organization,
            organization_role=actor_membership.role,
            operation="delete_organization",
        )

    # -- memberships ----------------------------------------------------- #

    def add_member(
        self, *, actor: User, organization_id: uuid.UUID, payload: MembershipCreateRequest
    ) -> MembershipView:
        """Add an existing account to a company. ``OWNER`` or ``ADMIN`` only.

        The target is always somebody other than the caller: this endpoint is
        how an administrator adds a colleague, not how a user joins a company.
        A consent-first flow is expressible (``status=INVITED``) but the
        acceptance step is not part of V1.
        """
        organization, actor_membership = self._authorize(
            actor=actor,
            organization_id=organization_id,
            required_roles=ORG_ADMIN_ROLES,
            operation="add_membership",
            lock=True,
        )
        # The role is checked before the target is resolved, so a caller who may
        # not grant the role gets the same refusal whether or not the account they
        # named exists - the endpoint must not double as an account oracle.
        self._assert_grantable(
            actor=actor,
            actor_membership=actor_membership,
            organization=organization,
            new_role=payload.role,
        )
        subject = self._resolve_subject(payload)
        if subject.id == actor.id:
            self._refuse(
                action=AuditAction.MEMBERSHIP_ADDED,
                actor=actor,
                organization_id=organization.id,
                organization_role=actor_membership.role,
                operation="add_membership",
                code="SELF_MEMBERSHIP_BLOCKED",
                message="You cannot add yourself to an organization.",
                error=SelfMembershipError,
            )
        if (
            self._session.execute(
                select(OrganizationMembership.id).where(
                    OrganizationMembership.organization_id == organization.id,
                    OrganizationMembership.user_id == subject.id,
                )
            ).scalar_one_or_none()
            is not None
        ):
            raise MembershipExistsError()

        membership = OrganizationMembership(
            organization_id=organization.id,
            user_id=subject.id,
            role=payload.role.value,
            status=payload.status.value,
            title=payload.title,
            invited_by_user_id=actor.id,
            joined_at=utcnow() if payload.status is MembershipStatus.ACTIVE else None,
        )
        self._session.add(membership)
        self._session.flush()

        self._record(
            action=AuditAction.MEMBERSHIP_ADDED,
            actor=actor,
            organization=organization,
            organization_role=actor_membership.role,
            operation="add_membership",
            metadata={
                "membership_id": membership.id,
                "subject_user_id": membership.user_id,
                "granted_role": membership.role,
                "membership_status": membership.status,
            },
        )
        return MembershipView(
            membership=membership, display_name=self._display_names({subject.id}).get(subject.id)
        )

    def update_member(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        membership_id: uuid.UUID,
        payload: MembershipUpdateRequest,
    ) -> MembershipView:
        """Change a membership's role, status or title. ``OWNER`` or ``ADMIN`` only."""
        organization, actor_membership = self._authorize(
            actor=actor,
            organization_id=organization_id,
            required_roles=ORG_ADMIN_ROLES,
            operation="update_membership",
            lock=True,
        )
        target = self._require_target_membership(organization.id, membership_id)
        self._assert_not_above(actor=actor, actor_membership=actor_membership, target=target)
        data = payload.model_dump(exclude_unset=True)
        if not data:
            return self._view_of(target)

        new_role = payload.role or OrganizationRole(target.role)
        new_status = payload.status or MembershipStatus(target.status)
        if "role" in data or "status" in data:
            self._assert_grantable(
                actor=actor,
                actor_membership=actor_membership,
                organization=organization,
                new_role=new_role,
            )
            self._assert_ownership_remains(
                actor=actor,
                actor_membership=actor_membership,
                organization=organization,
                target=target,
                new_role=new_role,
                new_status=new_status,
                operation="update_membership",
            )

        previous_role, previous_status = target.role, target.status
        if "role" in data:
            target.role = new_role.value
        if "status" in data:
            target.status = new_status.value
            target.joined_at = (
                utcnow() if new_status is MembershipStatus.ACTIVE else target.joined_at
            )
        if "title" in data:
            target.title = data["title"]

        self._session.flush()
        self._record(
            action=(
                AuditAction.MEMBERSHIP_ROLE_CHANGED if "role" in data else AuditAction.ADMIN_ACTION
            ),
            actor=actor,
            organization=organization,
            organization_role=actor_membership.role,
            operation="update_membership",
            metadata={
                "membership_id": target.id,
                "subject_user_id": target.user_id,
                "fields": sorted(data),
                "previous_role": previous_role,
                "new_role": target.role,
                "previous_status": previous_status,
                "new_status": target.status,
            },
        )
        return self._view_of(target)

    def remove_member(
        self, *, actor: User, organization_id: uuid.UUID, membership_id: uuid.UUID
    ) -> None:
        """Remove a membership. ``OWNER`` or ``ADMIN`` only.

        Hard delete, because ``organization_memberships`` has no ``deleted_at``
        and adding one would also need a partial unique index on
        ``(organization_id, user_id)`` - otherwise a removed member could never
        be re-invited. The audit row references the *organization*, which is only
        ever soft deleted, and carries the removed membership's own id, subject
        and role in its metadata, so the trail stays reconstructable.

        Refused when it would leave the organization without an active owner,
        which includes an owner removing themselves as the last owner.
        """
        organization, actor_membership = self._authorize(
            actor=actor,
            organization_id=organization_id,
            required_roles=ORG_ADMIN_ROLES,
            operation="remove_membership",
            lock=True,
        )
        target = self._require_target_membership(organization.id, membership_id)
        self._assert_not_above(actor=actor, actor_membership=actor_membership, target=target)
        self._assert_ownership_remains(
            actor=actor,
            actor_membership=actor_membership,
            organization=organization,
            target=target,
            new_role=None,
            new_status=None,
            operation="remove_membership",
        )

        removed = MembershipView(membership=target, display_name=None)
        # Captured before the delete: a deleted instance must not be read from
        # afterwards, and these are the values the audit row has to carry.
        audit_facts = {
            "membership_id": removed.membership.id,
            "subject_user_id": removed.membership.user_id,
            "previous_role": removed.membership.role,
            "previous_status": removed.membership.status,
            "removed_self": removed.membership.user_id == actor.id,
        }
        self._session.delete(target)
        self._session.flush()
        self._record(
            action=AuditAction.MEMBERSHIP_REMOVED,
            actor=actor,
            organization=organization,
            organization_role=actor_membership.role,
            operation="remove_membership",
            metadata=audit_facts,
        )

    # -- administrator surface ------------------------------------------- #

    def admin_list(
        self,
        *,
        actor: User,
        is_active: bool | None = None,
        is_verified: bool | None = None,
        include_deleted: bool = False,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[OrganizationView], int]:
        """Every company on the platform, for moderation and support."""
        self._require_admin(actor)
        conditions = self._admin_conditions(
            is_active=is_active, is_verified=is_verified, include_deleted=include_deleted
        )
        total = int(
            self._session.execute(
                select(func.count()).select_from(Organization).where(*conditions)
            ).scalar_one()
        )
        # The county join is an outer join, so that column is nullable at runtime;
        # SQLAlchemy types it as County, which is why it is not annotated here.
        statement: Select[tuple[Organization, County]] = (
            select(Organization, County)
            .join(County, County.id == Organization.county_id, isouter=True)
            .where(*conditions)
            .order_by(Organization.created_at.desc(), Organization.id)
            .limit(limit)
            .offset(offset)
        )
        rows = self._session.execute(statement).all()
        return [OrganizationView(organization=row[0], county=row[1]) for row in rows], total

    def admin_get(
        self, *, actor: User, organization_id: uuid.UUID, include_deleted: bool = True
    ) -> OrganizationView:
        """Read any company, tombstoned or not."""
        self._require_admin(actor)
        return self._with_county(
            self._admin_organization(organization_id, include_deleted=include_deleted)
        )

    def admin_update(
        self, *, actor: User, organization_id: uuid.UUID, payload: OrganizationAdminUpdateRequest
    ) -> OrganizationView:
        """Set the verification mark or reopen/close a company. Never self-asserted."""
        self._require_admin(actor)
        organization = self._admin_organization(organization_id, include_deleted=False)
        data = payload.model_dump(exclude_unset=True)
        if not data:
            return self._with_county(organization)

        previous = {
            "is_verified": organization.is_verified,
            "is_active": organization.is_active,
        }
        for field in ("is_verified", "is_active"):
            if field in data:
                setattr(organization, field, data[field])
        self._session.flush()
        self._record(
            action=AuditAction.ADMIN_ACTION,
            actor=actor,
            organization=organization,
            operation="admin_update_organization",
            metadata={"fields": sorted(data), "previous": previous},
        )
        return self._with_county(organization)

    def admin_delete(self, *, actor: User, organization_id: uuid.UUID) -> None:
        """Soft delete any company.

        The administrator override for the sole-owner rule: an administrator holds
        no membership to lose, so refusing them would leave a company that its
        owner cannot close and nobody else may close either.
        """
        self._require_admin(actor)
        organization = self._admin_organization(organization_id, include_deleted=False)
        organization.deleted_at = utcnow()
        organization.is_active = False
        self._session.flush()
        self._record(
            action=AuditAction.ADMIN_ACTION,
            actor=actor,
            organization=organization,
            operation="admin_delete_organization",
            metadata={"reason": "administrator_override"},
        )

    # -- authorisation --------------------------------------------------- #

    @staticmethod
    def _require_creator(actor: User) -> None:
        if actor.role not in (UserRole.EMPLOYER.value, UserRole.ADMIN.value):
            raise InsufficientRoleError("Only an employer account may register a company.")

    @staticmethod
    def _require_admin(actor: User) -> None:
        """Re-assert the administrator role inside the service, as users.py does.

        Two independent checks mean a future refactor that loosens the route
        dependency does not quietly open the moderation surface.
        """
        if actor.role != UserRole.ADMIN.value:
            raise InsufficientRoleError("This action requires administrator privileges.")

    def _authorize(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        required_roles: frozenset[OrganizationRole] | None = None,
        operation: str,
        lock: bool = False,
    ) -> tuple[Organization, OrganizationMembership]:
        """Resolve the caller's active membership and the company together.

        The membership is the authority: a caller without one gets ``404`` even
        when the company exists, and a caller with a membership that lacks the
        required role gets ``403`` - they already know the company exists, so
        there is nothing left to protect by hiding it.
        """
        membership = self._session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == actor.id,
            )
        ).scalar_one_or_none()
        if membership is None or membership.status != MembershipStatus.ACTIVE.value:
            self._refuse(
                action=AuditAction.ADMIN_ACTION,
                actor=actor,
                organization_id=organization_id,
                organization_role=membership.role if membership is not None else None,
                operation=operation,
                code="NOT_AN_ACTIVE_ORGANIZATION_MEMBER",
                message="No such organization was found.",
                error=OrganizationNotFoundError,
            )
        if required_roles is not None and OrganizationRole(membership.role) not in required_roles:
            self._refuse(
                action=AuditAction.ADMIN_ACTION,
                actor=actor,
                organization_id=organization_id,
                organization_role=membership.role,
                operation=operation,
                code="ORG_ROLE_INSUFFICIENT",
                message="Your role in this organization does not permit this action.",
                error=ForbiddenError,
            )

        statement = select(Organization).where(
            Organization.id == organization_id, Organization.deleted_at.is_(None)
        )
        if lock:
            # Row-locked so two concurrent membership edits cannot both pass the
            # last-owner check and then leave zero owners behind.
            statement = statement.with_for_update()
        organization = self._session.execute(statement).scalar_one_or_none()
        if organization is None:
            self._refuse(
                action=AuditAction.ADMIN_ACTION,
                actor=actor,
                organization_id=organization_id,
                organization_role=membership.role,
                operation=operation,
                code="NOT_AN_ACTIVE_ORGANIZATION_MEMBER",
                message="No such organization was found.",
                error=OrganizationNotFoundError,
            )
        return organization, membership

    def _assert_grantable(
        self,
        *,
        actor: User,
        actor_membership: OrganizationMembership,
        organization: Organization,
        new_role: OrganizationRole,
    ) -> None:
        """Refuse any grant above the caller's own organization role."""
        held = OrganizationRole(actor_membership.role)
        if ROLE_RANK[new_role] <= ROLE_RANK[held]:
            return
        self._refuse(
            action=AuditAction.MEMBERSHIP_ROLE_CHANGED,
            actor=actor,
            organization_id=organization.id,
            organization_role=held.value,
            operation="grant_membership_role",
            code=(
                "ORG_OWNERSHIP_GRANT_RESERVED"
                if new_role is OrganizationRole.OWNER
                else "ORG_ROLE_ESCALATION_BLOCKED"
            ),
            message=(
                "Only an owner may grant ownership of an organization."
                if new_role is OrganizationRole.OWNER
                else "You cannot grant a role above your own organization role."
            ),
            error=OrganizationRoleEscalationError,
        )

    def _assert_not_above(
        self,
        *,
        actor: User,
        actor_membership: OrganizationMembership,
        target: OrganizationMembership,
    ) -> None:
        """Refuse to act on a membership that outranks the caller's."""
        held = OrganizationRole(actor_membership.role)
        if ROLE_RANK[OrganizationRole(target.role)] <= ROLE_RANK[held]:
            return
        self._refuse(
            action=AuditAction.MEMBERSHIP_ROLE_CHANGED,
            actor=actor,
            organization_id=target.organization_id,
            organization_role=held.value,
            operation="manage_membership",
            code="ORG_ROLE_ESCALATION_BLOCKED",
            message="You cannot change a member whose role is above your own.",
            error=OrganizationRoleEscalationError,
        )

    def _assert_ownership_remains(
        self,
        *,
        actor: User,
        actor_membership: OrganizationMembership,
        organization: Organization,
        target: OrganizationMembership,
        new_role: OrganizationRole | None,
        new_status: MembershipStatus | None,
        operation: str,
    ) -> None:
        """Refuse any change that would leave the organization with no owner.

        ``new_role``/``new_status`` of ``None`` mean "this membership stops
        counting as an owner", which is what removal does - it is **not** "leave it
        as it was", or the sole owner could remove themselves. A caller that changes
        only one of the two passes the effective value for the other.
        """
        keeps_ownership = (
            new_role is OrganizationRole.OWNER and new_status is MembershipStatus.ACTIVE
        )
        if keeps_ownership:
            return
        if (
            target.role != OrganizationRole.OWNER.value
            or target.status != MembershipStatus.ACTIVE.value
        ):
            # Not an owner now, so nothing is lost.
            return
        remaining = self._session.execute(
            select(func.count())
            .select_from(OrganizationMembership)
            .where(
                OrganizationMembership.organization_id == organization.id,
                OrganizationMembership.role == OrganizationRole.OWNER.value,
                OrganizationMembership.status == MembershipStatus.ACTIVE.value,
                OrganizationMembership.id != target.id,
            )
        ).scalar_one()
        if int(remaining) > 0:
            return
        self._refuse(
            action=AuditAction.MEMBERSHIP_ROLE_CHANGED,
            actor=actor,
            organization_id=organization.id,
            organization_role=actor_membership.role,
            operation=operation,
            code="LAST_OWNER_PROTECTED",
            message=(
                "An organization must keep at least one active owner. Promote another "
                "member to OWNER first."
            ),
            error=LastOwnerError,
            metadata={"membership_id": target.id, "subject_user_id": target.user_id},
        )

    # -- lookups --------------------------------------------------------- #

    def _require_target_membership(
        self, organization_id: uuid.UUID, membership_id: uuid.UUID
    ) -> OrganizationMembership:
        """Scope the membership by its parent as well as its id.

        With the parent in the ``WHERE`` clause, a membership id from another
        organization simply matches nothing, so there is nothing left to
        authorise after the lookup.
        """
        target = self._session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.id == membership_id,
                OrganizationMembership.organization_id == organization_id,
            )
        ).scalar_one_or_none()
        if target is None:
            raise MembershipNotFoundError()
        return target

    def _resolve_subject(self, payload: MembershipCreateRequest) -> User:
        """Resolve the account being added, by id or by email.

        An unknown email is a 404: the caller is already an ``OWNER``/``ADMIN`` of
        a real company, so the only thing the lookup reveals is whether the
        address they are trying to invite is registered. A mailed invitation
        flow, which needs no such lookup, is the fix if that trade-off is ever
        judged unacceptable.
        """
        if payload.user_id is not None:
            user = self._session.execute(
                select(User).where(User.id == payload.user_id, User.deleted_at.is_(None))
            ).scalar_one_or_none()
            if user is None:
                raise NotFoundError("No account matching that user_id was found.")
            return user
        address = normalise_email(str(payload.email))
        user = self._session.execute(
            select(User).where(User.email == address, User.deleted_at.is_(None))
        ).scalar_one_or_none()
        if user is None:
            raise NotFoundError("No account matching that email address was found.")
        return user

    def _active_owner_count(self, organization_id: uuid.UUID) -> int:
        return int(
            self._session.execute(
                select(func.count())
                .select_from(OrganizationMembership)
                .where(
                    OrganizationMembership.organization_id == organization_id,
                    OrganizationMembership.role == OrganizationRole.OWNER.value,
                    OrganizationMembership.status == MembershipStatus.ACTIVE.value,
                )
            ).scalar_one()
        )

    def _assert_slug_free(self, slug: str) -> None:
        if (
            self._session.execute(
                select(Organization.id).where(func.lower(Organization.slug) == slug.lower())
            ).scalar_one_or_none()
            is not None
        ):
            raise DuplicateSlugError()

    def _county(self, code: str | None) -> County | None:
        if not code:
            return None
        county = self._catalogue.get_counties_by_codes([code]).get(code.upper())
        if county is None:
            raise ValidationError(f"Unknown county code: {code}", code="UNKNOWN_COUNTY_CODE")
        return county

    def _with_county(self, organization: Organization) -> OrganizationView:
        county = (
            self._session.execute(
                select(County).where(County.id == organization.county_id)
            ).scalar_one_or_none()
            if organization.county_id is not None
            else None
        )
        return OrganizationView(
            organization=organization, county=county if isinstance(county, County) else None
        )

    def _view_of(self, membership: OrganizationMembership) -> MembershipView:
        return MembershipView(
            membership=membership,
            display_name=self._display_names({membership.user_id}).get(membership.user_id),
        )

    def _display_names(self, user_ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
        """Display names for a page of members, in one query.

        Only the two passport columns are selected: the roster must never need a
        user row, so there is no code path by which an email address could reach
        a members response.
        """
        if not user_ids:
            return {}
        rows = self._session.execute(
            select(WorkerProfile.user_id, WorkerProfile.display_name).where(
                WorkerProfile.user_id.in_(user_ids), WorkerProfile.deleted_at.is_(None)
            )
        ).all()
        return {row[0]: row[1] for row in rows}

    def _admin_conditions(
        self,
        *,
        is_active: bool | None,
        is_verified: bool | None,
        include_deleted: bool,
    ) -> list[ColumnElement[bool]]:
        conditions: list[ColumnElement[bool]] = []
        if not include_deleted:
            conditions.append(Organization.deleted_at.is_(None))
        if is_active is not None:
            conditions.append(Organization.is_active.is_(is_active))
        if is_verified is not None:
            conditions.append(Organization.is_verified.is_(is_verified))
        return conditions

    def _admin_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool
    ) -> Organization:
        conditions = [Organization.id == organization_id]
        if not include_deleted:
            conditions.append(Organization.deleted_at.is_(None))
        organization = self._session.execute(
            select(Organization).where(*conditions)
        ).scalar_one_or_none()
        if organization is None:
            raise OrganizationNotFoundError()
        return organization

    # -- audit ----------------------------------------------------------- #

    def _record(
        self,
        *,
        action: AuditAction,
        actor: User,
        organization: Organization,
        operation: str,
        organization_role: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        """Record a successful effect, in the caller's transaction."""
        payload: dict[str, object] = {"operation": operation}
        if organization_role is not None:
            payload["organization_role"] = organization_role
        if metadata:
            payload.update(metadata)
        self._audit.record(
            action=action,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="organization",
            resource_id=organization.id,
            ip_address=self._ctx.ip_address,
            user_agent=self._ctx.user_agent,
            request_id=self._ctx.request_id,
            outcome="SUCCESS",
            metadata=payload,
        )

    def _refuse(
        self,
        *,
        action: AuditAction,
        actor: User,
        organization_id: uuid.UUID,
        operation: str,
        code: str,
        message: str,
        error: type[AppError],
        organization_role: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> NoReturn:
        """Record the refusal durably, then raise it.

        Durable rather than in-transaction: the request is about to be rolled
        back, and a security trail that only records the grants is worthless.
        Nothing is pending in the session at these points - every check runs
        before its mutation - so committing here persists no half-applied effect.
        """
        payload: dict[str, object] = {"operation": operation, "reason": code}
        if organization_role is not None:
            payload["organization_role"] = organization_role
        if metadata:
            payload.update(metadata)
        self._audit.record_durable(
            action=action,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="organization",
            resource_id=organization_id,
            ip_address=self._ctx.ip_address,
            user_agent=self._ctx.user_agent,
            request_id=self._ctx.request_id,
            outcome="DENIED",
            metadata=payload,
        )
        raise error(message, code=code)


def derive_slug(name: str) -> str:
    """Lower-case hyphenated form of a company name.

    Accented characters are folded to ASCII first, so ``M contractors`` becomes
    ``m-contractors``. Raises when nothing usable survives, rather than inventing
    an identifier: a company whose name is entirely non-Latin must choose its
    own slug.
    """
    folded = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    slug = _SLUG_SEPARATORS.sub("-", folded.lower()).strip("-")[:120].strip("-")
    if len(slug) < 2:
        raise ValidationError(
            "The organization name does not yield a usable identifier; provide a slug.",
            code="SLUG_REQUIRED",
        )
    return slug


__all__ = [
    "ROLE_RANK",
    "DuplicateSlugError",
    "LastOwnerError",
    "MembershipExistsError",
    "MembershipNotFoundError",
    "MembershipView",
    "OrganizationNotFoundError",
    "OrganizationRoleEscalationError",
    "OrganizationService",
    "OrganizationView",
    "SelfMembershipError",
    "derive_slug",
]
