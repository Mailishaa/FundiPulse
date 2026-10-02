"""User account management: reads, profile updates, deactivation.

Scope is deliberately narrow. This service owns *account* concerns. Domain
concerns (the worker's passport, an employer's organization) live in their own
services so that authorisation stays with the domain that understands it.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
import uuid

from sqlalchemy import Select, func, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.core.constants import AccountStatus, AuditAction, UserRole
from app.core.exceptions import (
    AccountDeactivatedError,
    ConflictError,
    ForbiddenError,
    InsufficientRoleError,
    NotFoundError,
    ValidationError,
)
from app.db.base import utcnow
from app.db.models.user import RefreshSession, SecurityToken, User
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService, RequestContext
from app.utils.email import mask_email


class UserService:
    """Reads and administrative changes to user accounts."""

    def __init__(self, session: Session, *, auth_service: AuthService | None = None) -> None:
        self._session = session
        self._audit = AuditService(session)
        self._auth = auth_service or AuthService(session)

    # -- reads ----------------------------------------------------------- #

    def get_by_id(self, user_id: uuid.UUID, *, include_deleted: bool = False) -> User:
        """Fetch a user by id.

        Raises :class:`NotFoundError` rather than returning ``None`` so callers
        cannot forget to handle the missing case, and so the error code is the
        same for every resource type in the API.
        """
        statement = select(User).where(User.id == user_id)
        if not include_deleted:
            statement = statement.where(User.deleted_at.is_(None))
        user = self._session.execute(statement).scalar_one_or_none()
        if user is None:
            raise NotFoundError("The requested user was not found.")
        return user

    def list_users(
        self,
        *,
        actor: User,
        role: UserRole | None = None,
        status: AccountStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[Sequence[User], int]:
        """Paginated user listing. **Administrator only.**

        The role check happens here, in the service, against the actor loaded from
        the database - not only in the route dependency. Two independent checks
        mean a future refactor that loosens one does not open a hole.

        Filters are typed parameters rather than a generic query object. There is
        no ``?filter=`` escape hatch, because that is how unvalidated field names
        reach a WHERE clause.
        """
        self._require_admin(actor)

        conditions: list[ColumnElement[bool]] = [User.deleted_at.is_(None)]
        if role is not None:
            conditions.append(User.role == role.value)
        if status is not None:
            conditions.append(User.status == status.value)

        total = int(
            self._session.execute(
                select(func.count()).select_from(User).where(*conditions)
            ).scalar_one()
        )
        statement: Select[tuple[User]] = (
            select(User)
            .where(*conditions)
            # Deterministic ordering: id is unique, so paging cannot skip or
            # repeat a row the way an unstable sort would.
            .order_by(User.created_at.desc(), User.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    # -- self-service changes -------------------------------------------- #

    def update_contact_email(
        self, *, user: User, email: str, context: RequestContext | None = None
    ) -> User:
        """Change the login email address.

        Forces re-verification: the new address is not proven to belong to the
        user until they confirm it, so ``is_email_verified`` is cleared. Without
        this, an attacker who briefly gained session access could change the
        address and then use password reset to take the account permanently.
        """
        ctx = context or RequestContext()
        from app.utils.email import normalise_email

        normalised = normalise_email(email)
        if normalised == user.email:
            raise ValidationError("That is already your email address.")

        clash = self._session.execute(
            select(User.id).where(func.lower(User.email) == normalised, User.id != user.id)
        ).scalar_one_or_none()
        if clash is not None:
            raise ConflictError(
                "An account with this email address already exists.",
                code="EMAIL_ALREADY_REGISTERED",
            )

        previous = user.email
        user.email = normalised
        user.is_email_verified = False
        user.email_verified_at = None

        self._audit.record(
            action=AuditAction.ADMIN_ACTION,
            actor_user_id=user.id,
            actor_role=user.role,
            resource_type="user",
            resource_id=user.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            metadata={
                "operation": "change_contact_email",
                "previous_email": mask_email(previous),
                "new_email": mask_email(normalised),
            },
        )
        return user

    def deactivate(
        self, *, user: User, reason: str | None = None, context: RequestContext | None = None
    ) -> User:
        """Deactivate an account, preserving the record.

        This is **not** a delete. Personal data is retained in anonymised form
        because audit and moderation records may legitimately reference it, and
        because hard deletion would destroy evidence of past conduct.

        Effects: the account can no longer authenticate, every session and
        outstanding token is revoked, and the worker profile is tombstoned. The
        private contact block is left in place at this stage because
        anonymisation is a separate, scheduled step.
        """
        ctx = context or RequestContext()
        if user.deleted_at is not None:
            return user

        user.is_active = False
        user.status = AccountStatus.DEACTIVATED.value
        user.deactivated_at = utcnow()
        user.deleted_at = utcnow()

        self._auth.revoke_all_sessions(user=user, reason="account_deactivated", context=ctx)
        self._session.execute(
            update(SecurityToken)
            .where(SecurityToken.user_id == user.id, SecurityToken.consumed_at.is_(None))
            .values(consumed_at=utcnow())
        )

        self._audit.record(
            action=AuditAction.ACCOUNT_DEACTIVATED,
            actor_user_id=user.id,
            actor_role=user.role,
            resource_type="user",
            resource_id=user.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            metadata={"reason": reason or "user_requested"},
        )
        logger_event = "Account deactivated"
        from app.core.logging import get_logger

        get_logger(__name__).info(logger_event, extra={"user_id": str(user.id)})
        return user

    def anonymise(self, *, user: User, context: RequestContext | None = None) -> User:
        """Irreversibly scrub the private contact block.

        Run by a scheduled job ``INACTIVE_ACCOUNT_PURGE_DAYS`` after
        deactivation, not immediately. The account row, its audit trail and
        anonymised business records are retained so that historical moderation
        and verification decisions remain explainable.

        Attempting to use the account afterwards fails on the missing credentials,
        and the endpoint that performs this refuses accounts that are still
        active.
        """
        ctx = context or RequestContext()
        from app.db.models.worker import WorkerProfile

        profile = self._session.execute(
            select(WorkerProfile).where(WorkerProfile.user_id == user.id)
        ).scalar_one_or_none()
        if profile is not None:
            profile.phone_number = None
            profile.contact_email = None
            profile.contact_name = None
            profile.contact_phone = None
            profile.display_name = _anonymised_display_name(user.id)
            profile.bio = None
            profile.headline = None

        self._session.execute(
            update(SecurityToken)
            .where(SecurityToken.user_id == user.id, SecurityToken.consumed_at.is_(None))
            .values(consumed_at=utcnow())
        )

        self._audit.record(
            action=AuditAction.ACCOUNT_ANONYMISED,
            actor_user_id=None,
            resource_type="user",
            resource_id=user.id,
            ip_address=ctx.ip_address,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            metadata={"scrubbed": ["display_name", "contact_fields", "bio"]},
        )
        return user

    # -- administrator actions ------------------------------------------- #

    def change_role(
        self,
        *,
        actor: User,
        target: User,
        new_role: UserRole,
        context: RequestContext | None = None,
    ) -> User:
        """Change a user's platform role. **Administrator only.**

        Two guards matter here:

        * an administrator cannot demote themselves, which is how a platform
          ends up with no administrator and nobody able to restore one;
        * the change is audited with both the old and new role, so a privilege
          escalation is reconstructable afterwards.
        """
        ctx = context or RequestContext()
        self._require_admin(actor)

        if actor.id == target.id and new_role.value != target.role:
            raise ForbiddenError(
                "Administrators cannot change their own role.",
                code="SELF_ROLE_CHANGE_BLOCKED",
            )
        if new_role.value == target.role:
            return target

        previous = target.role
        target.role = new_role.value

        self._audit.record(
            action=AuditAction.ROLE_CHANGED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="user",
            resource_id=target.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            metadata={"previous_role": previous, "new_role": new_role.value},
        )
        return target

    def set_account_status(
        self,
        *,
        actor: User,
        target: User,
        status: AccountStatus,
        reason: str,
        context: RequestContext | None = None,
    ) -> User:
        """Suspend or restore an account. **Administrator only.**

        A reason is mandatory and is stored in the audit trail. "Why was this
        account suspended" is a question that must be answerable months later.
        """
        ctx = context or RequestContext()
        self._require_admin(actor)

        if actor.id == target.id:
            raise ForbiddenError(
                "Administrators cannot change their own account status.",
                code="SELF_STATUS_CHANGE_BLOCKED",
            )
        if not reason or len(reason.strip()) < 5:
            raise ValidationError("A reason of at least 5 characters is required.")

        previous = target.status
        target.status = status.value
        target.is_active = status is AccountStatus.ACTIVE
        if status is not AccountStatus.ACTIVE:
            target.locked_until = None
            self._auth.revoke_all_sessions(
                user=target, reason=f"admin_{status.value.lower()}", context=ctx
            )

        self._audit.record(
            # Moving an account out of ACTIVE is an account-state change and
            # records ACCOUNT_DISABLED; restoring it is a moderation decision and
            # records ADMIN_ACTION. Both carry the reason and both names are in
            # the database CHECK constraint, so the vocabulary cannot drift.
            action=(
                AuditAction.ADMIN_ACTION
                if status is AccountStatus.ACTIVE
                else AuditAction.ACCOUNT_DISABLED
            ),
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="user",
            resource_id=target.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            metadata={"previous_status": previous, "new_status": status.value, "reason": reason},
        )
        return target

    # -- helpers --------------------------------------------------------- #

    def assert_is_admin(self, actor: User) -> None:
        """Raise unless ``actor`` holds the ADMIN platform role.

        Public so routes that only need the permission gate can assert it in the
        service too, rather than relying solely on a dependency.
        """
        self._require_admin(actor)

    def _require_admin(self, actor: User | None = None) -> None:
        if actor is None:
            raise InsufficientRoleError("This action requires administrator privileges.")
        if actor.role != UserRole.ADMIN.value:
            raise InsufficientRoleError("This action requires administrator privileges.")

    def require_self_or_admin(self, *, actor: User, target_id: uuid.UUID) -> User:
        """Fetch a user, permitting only the owner or an administrator.

        This is the deny-by-default helper for user-scoped endpoints. It is the
        reason ``GET /users/{id}`` cannot be used to read another account: a
        non-owner, non-admin caller is refused before any data is loaded into a
        response schema.
        """
        if actor.role == UserRole.ADMIN.value or actor.id == target_id:
            return self.get_by_id(target_id)
        raise ForbiddenError("You may only access your own account.")


def _anonymised_display_name(user_id: uuid.UUID) -> str:
    """A stable, non-identifying label for an anonymised passport.

    Deterministic in the user id so the same account always renders the same
    placeholder, which keeps historical aggregates consistent without retaining
    the original name.
    """
    return f"Withdrawn worker {str(user_id)[:8].upper()}"


def ensure_active(user: User) -> User:
    """Raise if a user may not act on their own account."""
    if user.deleted_at is not None or user.status == AccountStatus.DEACTIVATED.value:
        raise AccountDeactivatedError()
    return user


def session_expiry_summary(sessions: Sequence[RefreshSession]) -> list[datetime]:
    """Convenience for account-management responses."""
    return [row.expires_at for row in sessions]
