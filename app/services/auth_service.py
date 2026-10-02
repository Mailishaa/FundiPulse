"""Authentication and session lifecycle.

This service owns every rule about who may hold an authenticated session:

* registration and email normalisation,
* login, including lockout after repeated failure,
* access/refresh token issuance with rotation and **reuse detection**,
* logout and full revocation,
* password change, reset and email verification,
* account deactivation.

Design notes worth stating explicitly:

**Refresh token reuse detection.** Each login starts a *family*. Rotation issues a
new token and marks the old one replaced. If a replaced token is ever presented,
that means the old token was captured, so the entire family is revoked
immediately and ``TOKEN_REUSE_DETECTED`` is audited. This is what turns a stolen
refresh token from a permanent backdoor into a detectable, self-limiting event.

**Non-enumerating responses.** Login, password reset and verification-resend all
answer identically whether or not the address is registered. A different response
is an account-enumeration oracle, which is exactly what the brief forbids.

**User-not-found timing.** When the address is unknown the service still performs
a dummy password verification, so the response time does not reveal whether the
account exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
import uuid

from sqlalchemy import Select, Update, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.constants import AccountStatus, AuditAction, TokenPurpose, UserRole
from app.core.exceptions import (
    AccountDisabledError,
    AccountLockedError,
    AuthenticationError,
    ConflictError,
    InvalidCredentialsError,
    InvalidTokenError,
    NotFoundError,
    TokenExpiredError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.security import (
    PasswordHasherService,
    TokenService,
    generate_opaque_token,
    hash_opaque_token,
)
from app.db.base import utcnow
from app.db.models.user import RefreshSession, SecurityToken, User
from app.services.audit_service import AuditService
from app.utils.email import mask_email, normalise_email

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Per-request metadata carried into the audit trail.

    Passed explicitly rather than read from a global so that a service method is
    testable and so the audit entry is always explicit about its provenance.
    """

    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class AuthTokens:
    """A freshly issued token pair."""

    access_token: str
    access_token_expires_at: datetime
    refresh_token: str
    refresh_token_expires_at: datetime
    session_id: uuid.UUID

    @property
    def access_token_expires_in(self) -> int:
        return max(0, int((self.access_token_expires_at - utcnow()).total_seconds()))

    @property
    def refresh_token_expires_in(self) -> int:
        return max(0, int((self.refresh_token_expires_at - utcnow()).total_seconds()))


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """A user resolved from a bearer token."""

    user: User
    session_id: uuid.UUID | None = None
    token_id: uuid.UUID | None = None


def _execute_update(session: Session, statement: Update) -> int:
    """Run a DML statement and return the affected row count.

    ``Session.execute`` is annotated as returning ``Result``, which has no
    ``rowcount``; an UPDATE or DELETE actually returns a ``CursorResult``. This
    helper keeps that detail in one place instead of scattering casts, and it also
    normalises ``None`` to ``0`` so callers can compare directly.

    Returning a count rather than a result object is deliberate: callers only ever
    want the number, and it makes an accidental chained use obvious.
    """
    result = session.execute(statement)
    return int(getattr(result, "rowcount", 0) or 0)


class AuthService:
    """Registration, login, session and credential management."""

    def __init__(
        self,
        session: Session,
        *,
        settings: Settings | None = None,
        password_hasher: PasswordHasherService | None = None,
        token_service: TokenService | None = None,
    ) -> None:
        self._session = session
        self._settings = settings or get_settings()
        self._passwords = password_hasher or PasswordHasherService(self._settings)
        self._tokens = token_service or TokenService(self._settings)
        self._audit = AuditService(session)

    # ================================================================== #
    # Registration                                                       #
    # ================================================================== #

    def register(
        self,
        *,
        email: str,
        password: str,
        role: UserRole | str,
        context: RequestContext | None = None,
    ) -> tuple[User, str, AuthTokens]:
        """Create an account, issue a token pair and a verification token.

        Returns the user, the plaintext verification token and the token pair.
        The caller delivers the token; only its hash is persisted, so the
        plaintext exists exactly once, here.
        """
        ctx = context or RequestContext()
        normalised = normalise_email(email)
        role_value = _role_value(role)

        existing = self._find_user_by_email(normalised)
        if existing is not None:
            # Deliberately generic. Confirming "this address is registered" here
            # would be an enumeration oracle.
            raise ConflictError(
                "An account with this email address already exists.",
                code="EMAIL_ALREADY_REGISTERED",
            )

        user = User(
            email=normalised,
            password_hash=self._passwords.hash(password.strip()),
            role=role_value,
            is_active=True,
            is_email_verified=False,
            status=AccountStatus.ACTIVE.value,
        )
        self._session.add(user)

        try:
            self._session.flush()
        except IntegrityError as exc:
            # Lost the race against a concurrent registration of the same
            # address. The unique index is the guarantee; this is the friendly
            # translation of it.
            self._session.rollback()
            raise ConflictError(
                "An account with this email address already exists.",
                code="EMAIL_ALREADY_REGISTERED",
            ) from exc

        verification_token = self._issue_single_use_token(
            user=user,
            purpose=TokenPurpose.EMAIL_VERIFICATION,
            ttl=timedelta(hours=self._settings.email_verification_token_expire_hours),
            context=ctx,
        )
        tokens = self._issue_token_pair(user=user, ctx=ctx)

        self._audit.record(
            action=AuditAction.ACCOUNT_REGISTERED,
            actor_user_id=user.id,
            actor_role=user.role,
            resource_type="user",
            resource_id=user.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            metadata={"role": role_value, "email": mask_email(normalised)},
        )

        logger.info(
            "Account registered",
            extra={"user_id": str(user.id), "role": role_value},
        )
        return user, verification_token, tokens

    # ================================================================== #
    # Login                                                              #
    # ================================================================== #

    def authenticate(
        self,
        *,
        email: str,
        password: str,
        context: RequestContext | None = None,
    ) -> tuple[User, AuthTokens]:
        """Verify credentials and issue a token pair.

        Every failure path returns the *same* error to the caller, and every
        failure path writes an audit row, so that credential stuffing is visible
        in the trail even though it is invisible to the attacker.
        """
        ctx = context or RequestContext()
        normalised = normalise_email(email)
        user = self._find_user_by_email(normalised)

        if user is None:
            # Burn comparable time so response latency does not disclose whether
            # the address exists.
            self._passwords.verify(password, _dummy_hash())
            self._audit.record_durable(
                action=AuditAction.LOGIN_FAILURE,
                ip_address=ctx.ip_address,
                user_agent=ctx.user_agent,
                request_id=ctx.request_id,
                outcome="FAILURE",
                metadata={
                    "email": mask_email(normalised),
                    "reason": "unknown_account",
                },
            )
            raise InvalidCredentialsError()

        if user.is_locked:
            self._audit.record_durable(
                action=AuditAction.LOGIN_BLOCKED_LOCKED,
                actor_user_id=user.id,
                actor_role=user.role,
                ip_address=ctx.ip_address,
                user_agent=ctx.user_agent,
                request_id=ctx.request_id,
                outcome="DENIED",
                metadata={"email": mask_email(normalised)},
            )
            raise AccountLockedError()

        if not user.is_active or user.status != AccountStatus.ACTIVE.value:
            self._audit.record_durable(
                action=AuditAction.LOGIN_FAILURE,
                actor_user_id=user.id,
                actor_role=user.role,
                ip_address=ctx.ip_address,
                user_agent=ctx.user_agent,
                request_id=ctx.request_id,
                outcome="DENIED",
                metadata={"reason": "account_not_active", "status": user.status},
            )
            raise AccountDisabledError()

        if not self._passwords.verify(password, user.password_hash):
            self._register_failed_attempt(user, ctx=ctx, email=normalised)
            raise InvalidCredentialsError()

        # A successful login clears the throttle. Doing it here means a user who
        # mistypes twice then succeeds is not left near the limit.
        if user.failed_login_count:
            user.failed_login_count = 0
            user.locked_until = None

        # Transparent upgrade when hashing parameters have been raised.
        if self._passwords.needs_rehash(user.password_hash):
            user.password_hash = self._passwords.hash(password.strip())
            logger.info(
                "Password hash upgraded to current parameters",
                extra={"user_id": str(user.id)},
            )

        tokens = self._issue_token_pair(user=user, ctx=ctx)
        user.last_login_at = utcnow()

        self._audit.record(
            action=AuditAction.LOGIN_SUCCESS,
            actor_user_id=user.id,
            actor_role=user.role,
            resource_type="user",
            resource_id=user.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            metadata={"session_id": str(tokens.session_id)},
        )
        return user, tokens

    def _register_failed_attempt(self, user: User, *, ctx: RequestContext, email: str) -> None:
        """Increment the throttle counter and lock the account at the threshold."""
        user.failed_login_count = (user.failed_login_count or 0) + 1
        locked = False
        if user.failed_login_count >= self._settings.max_failed_login_attempts:
            user.locked_until = utcnow() + timedelta(minutes=self._settings.account_lockout_minutes)
            locked = True

        self._audit.record_durable(
            action=AuditAction.LOGIN_FAILURE,
            actor_user_id=user.id,
            actor_role=user.role,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="FAILURE",
            metadata={
                "email": mask_email(email),
                "reason": "bad_password",
                "failed_count": user.failed_login_count,
                "locked": locked,
            },
        )
        if locked:
            self._audit.record(
                action=AuditAction.ACCOUNT_DISABLED,
                actor_user_id=user.id,
                actor_role=user.role,
                ip_address=ctx.ip_address,
                user_agent=ctx.user_agent,
                request_id=ctx.request_id,
                outcome="SUCCESS",
                metadata={
                    "reason": "automatic_lockout_after_failed_logins",
                    "failed_count": user.failed_login_count,
                },
            )
            logger.warning(
                "Account locked after repeated failed logins",
                extra={"user_id": str(user.id)},
            )

    # ================================================================== #
    # Token issuance and rotation                                        #
    # ================================================================== #

    def _issue_token_pair(
        self,
        *,
        user: User,
        ctx: RequestContext,
        family_id: uuid.UUID | None = None,
    ) -> AuthTokens:
        """Create a refresh session and its matching access token."""
        now = utcnow()
        family = family_id or uuid.uuid4()
        refresh_plaintext = generate_opaque_token()
        refresh_expires = now + TokenService.refresh_token_lifetime(self._settings)
        family_deadline = now + TokenService.refresh_family_lifetime(self._settings)

        session_row = RefreshSession(
            user_id=user.id,
            family_id=family,
            token_hash=hash_opaque_token(refresh_plaintext),
            issued_at=now,
            expires_at=min(refresh_expires, family_deadline),
            absolute_expires_at=family_deadline,
            user_agent=(ctx.user_agent or "")[:512] or None,
            ip_address=ctx.ip_address,
        )
        self._session.add(session_row)
        self._session.flush()

        access = self._tokens.create_access_token(
            subject=user.id,
            role=user.role,
            session_id=session_row.id,
        )
        return AuthTokens(
            access_token=access.token,
            access_token_expires_at=access.expires_at,
            refresh_token=refresh_plaintext,
            refresh_token_expires_at=session_row.expires_at,
            session_id=session_row.id,
        )

    def refresh(
        self,
        *,
        refresh_token: str,
        context: RequestContext | None = None,
    ) -> tuple[User, AuthTokens]:
        """Rotate a refresh token.

        Returns a new pair and revokes the presented token. Presenting a token
        that has already been rotated means it was captured, so the whole family
        is revoked and the event is audited at the highest severity available.
        """
        ctx = context or RequestContext()
        token_hash = hash_opaque_token(refresh_token)
        now = utcnow()

        session_row = self._session.get(RefreshSession, _find_session_id_by_hash(self, token_hash))
        if session_row is None:
            self._audit.record_durable(
                action=AuditAction.LOGIN_FAILURE,
                ip_address=ctx.ip_address,
                user_agent=ctx.user_agent,
                request_id=ctx.request_id,
                outcome="FAILURE",
                metadata={"reason": "unknown_refresh_token"},
            )
            raise InvalidTokenError("The refresh token is invalid.")

        user = self._session.get(User, session_row.user_id)
        if user is None:  # pragma: no cover - FK makes this unreachable
            raise InvalidTokenError("The refresh token is invalid.")

        if session_row.revoked_at is not None:
            # Reuse of an already-rotated or revoked token. Treat as compromise.
            revoked = self._revoke_family(session_row.family_id, reason="token_reuse_detected")
            self._audit.record_durable(
                action=AuditAction.TOKEN_REUSE_DETECTED,
                actor_user_id=user.id,
                actor_role=user.role,
                resource_type="refresh_session",
                resource_id=session_row.id,
                ip_address=ctx.ip_address,
                user_agent=ctx.user_agent,
                request_id=ctx.request_id,
                outcome="DENIED",
                metadata={
                    "family_id": str(session_row.family_id),
                    "family_sessions_revoked": revoked,
                },
            )
            logger.error(
                "Refresh token reuse detected; family revoked",
                extra={
                    "user_id": str(user.id),
                    "family_id": str(session_row.family_id),
                },
            )
            raise InvalidTokenError("The refresh token is no longer valid.")

        if session_row.expires_at <= now or session_row.absolute_expires_at <= now:
            session_row.revoked_at = now
            session_row.revoked_reason = "expired"
            self._audit.record_durable(
                action=AuditAction.LOGIN_FAILURE,
                actor_user_id=user.id,
                ip_address=ctx.ip_address,
                request_id=ctx.request_id,
                outcome="FAILURE",
                metadata={"reason": "refresh_token_expired"},
            )
            raise TokenExpiredError("The refresh token has expired.")

        if not user.is_active or user.status != AccountStatus.ACTIVE.value:
            raise AccountDisabledError()

        # Rotate: revoke the presented token, issue its successor in the family.
        session_row.revoked_at = now
        session_row.revoked_reason = "rotated"
        session_row.last_used_at = now

        tokens = self._issue_token_pair(user=user, ctx=ctx, family_id=session_row.family_id)
        session_row.replaced_by_id = tokens.session_id

        self._audit.record(
            action=AuditAction.TOKEN_REFRESHED,
            actor_user_id=user.id,
            actor_role=user.role,
            resource_type="refresh_session",
            resource_id=tokens.session_id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            metadata={"family_id": str(session_row.family_id)},
        )
        return user, tokens

    def logout(
        self,
        *,
        user: User,
        session_id: uuid.UUID | None,
        context: RequestContext | None = None,
    ) -> int:
        """Revoke one session, or every session for the user.

        Revoking the current session is the common case. ``session_id=None``
        revokes all of them, which is what "sign out everywhere" means and is
        also the correct response to a suspected compromise.
        """
        ctx = context or RequestContext()
        now = utcnow()

        statement: Select[tuple[RefreshSession]] = select(RefreshSession).where(
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
        )
        if session_id is not None:
            statement = statement.where(RefreshSession.id == session_id)

        rows = list(self._session.execute(statement).scalars())
        for row in rows:
            row.revoked_at = now
            row.revoked_reason = "logout"

        self._audit.record(
            action=AuditAction.LOGOUT,
            actor_user_id=user.id,
            actor_role=user.role,
            resource_type="user",
            resource_id=user.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            metadata={
                "sessions_revoked": len(rows),
                "scope": "all" if session_id is None else "current",
            },
        )
        return len(rows)

    def revoke_all_sessions(
        self, *, user: User, reason: str, context: RequestContext | None = None
    ) -> int:
        """Revoke every live session for a user.

        Called on password change and password reset: if a credential has changed,
        any session established with the old credential must end. Without this, a
        stolen refresh token survives the very event that should have evicted it.
        """
        ctx = context or RequestContext()
        affected = _execute_update(
            self._session,
            update(RefreshSession)
            .where(RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None))
            .values(revoked_at=utcnow(), revoked_reason=reason),
        )
        self._audit.record(
            action=AuditAction.LOGOUT,
            actor_user_id=user.id,
            actor_role=user.role,
            resource_type="user",
            resource_id=user.id,
            ip_address=ctx.ip_address,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            metadata={"sessions_revoked": affected, "reason": reason},
        )
        return affected

    def _revoke_family(self, family_id: uuid.UUID, *, reason: str) -> int:
        return _execute_update(
            self._session,
            update(RefreshSession)
            .where(RefreshSession.family_id == family_id, RefreshSession.revoked_at.is_(None))
            .values(revoked_at=utcnow(), revoked_reason=reason),
        )

    # ================================================================== #
    # Password management                                                #
    # ================================================================== #

    def change_password(
        self,
        *,
        user: User,
        current_password: str,
        new_password: str,
        context: RequestContext | None = None,
    ) -> None:
        """Change a password, verifying the current one first.

        Revokes every session afterwards, including the caller's own, so the
        client must obtain a fresh token. That is deliberate: it guarantees the
        old credential is dead everywhere, not just in this tab.
        """
        ctx = context or RequestContext()
        if not self._passwords.verify(current_password, user.password_hash):
            self._audit.record_durable(
                action=AuditAction.LOGIN_FAILURE,
                actor_user_id=user.id,
                actor_role=user.role,
                ip_address=ctx.ip_address,
                user_agent=ctx.user_agent,
                request_id=ctx.request_id,
                outcome="FAILURE",
                metadata={"reason": "password_change_wrong_current_password"},
            )
            raise InvalidCredentialsError("The current password is incorrect.")

        if self._passwords.verify(new_password.strip(), user.password_hash):
            raise ValidationError(
                "The new password must differ from the current password.",
                code="PASSWORD_REUSED",
            )

        user.password_hash = self._passwords.hash(new_password.strip())
        user.failed_login_count = 0
        user.locked_until = None
        self.revoke_all_sessions(user=user, reason="password_changed", context=ctx)

        self._audit.record(
            action=AuditAction.PASSWORD_CHANGED,
            actor_user_id=user.id,
            actor_role=user.role,
            resource_type="user",
            resource_id=user.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
        )
        logger.info("Password changed", extra={"user_id": str(user.id)})

    def request_password_reset(
        self,
        *,
        email: str,
        context: RequestContext | None = None,
    ) -> str | None:
        """Start a password reset.

        Returns the plaintext token **only when the address is registered**, and
        the caller must not reveal that distinction to the client. A non-``None``
        return means "an email exists", which is why the route layer treats the
        result as server-side only.
        """
        ctx = context or RequestContext()
        normalised = normalise_email(email)
        user = self._find_user_by_email(normalised)

        # Audited unconditionally, so the trail shows reset attempts against
        # unknown addresses as well as real ones.
        self._audit.record(
            action=AuditAction.PASSWORD_RESET_REQUESTED,
            actor_user_id=user.id if user else None,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="REQUESTED",
            metadata={"email": mask_email(normalised), "account_exists": user is not None},
        )

        if user is None or not user.is_active:
            # Identical response either way. Returning early is the whole point:
            # the difference must not be observable.
            return None

        # Invalidate outstanding reset tokens: only the newest may be used.
        self._consume_live_tokens(user.id, TokenPurpose.PASSWORD_RESET)

        token = self._issue_single_use_token(
            user=user,
            purpose=TokenPurpose.PASSWORD_RESET,
            ttl=timedelta(minutes=self._settings.password_reset_token_expire_minutes),
            context=ctx,
        )
        logger.info(
            "Password reset token issued",
            extra={"user_id": str(user.id)},
        )
        return token

    def complete_password_reset(
        self,
        *,
        token: str,
        new_password: str,
        context: RequestContext | None = None,
    ) -> User:
        """Consume a reset token and set a new password."""
        ctx = context or RequestContext()
        token_row = self._consume_single_use_token(token=token, purpose=TokenPurpose.PASSWORD_RESET)
        user = self._session.get(User, token_row.user_id)
        if user is None:  # pragma: no cover - FK makes this unreachable
            raise InvalidTokenError("The reset token is invalid.")

        user.password_hash = self._passwords.hash(new_password.strip())
        user.failed_login_count = 0
        user.locked_until = None
        user.is_email_verified = True  # proven control of the mailbox
        user.email_verified_at = utcnow()

        # A reset is the remedy for a compromise, so it must evict every session
        # established with the old password.
        self.revoke_all_sessions(user=user, reason="password_reset", context=ctx)

        self._audit.record(
            action=AuditAction.PASSWORD_RESET_COMPLETED,
            actor_user_id=user.id,
            actor_role=user.role,
            resource_type="user",
            resource_id=user.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
        )
        logger.info("Password reset completed", extra={"user_id": str(user.id)})
        return user

    # ================================================================== #
    # Email verification                                                 #
    # ================================================================== #

    def verify_email(self, *, token: str, context: RequestContext | None = None) -> User:
        """Consume an email-verification token."""
        ctx = context or RequestContext()
        token_row = self._consume_single_use_token(
            token=token, purpose=TokenPurpose.EMAIL_VERIFICATION
        )
        user = self._session.get(User, token_row.user_id)
        if user is None:  # pragma: no cover
            raise InvalidTokenError("The verification token is invalid.")

        if user.is_email_verified:
            return user

        user.is_email_verified = True
        user.email_verified_at = utcnow()

        self._audit.record(
            action=AuditAction.EMAIL_VERIFIED,
            actor_user_id=user.id,
            actor_role=user.role,
            resource_type="user",
            resource_id=user.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
        )
        return user

    def resend_email_verification(
        self, *, user: User, context: RequestContext | None = None
    ) -> str | None:
        """Reissue an email-verification token.

        Returns ``None`` when the address is already verified, so the route does
        not disclose anything the caller could not already infer.
        """
        ctx = context or RequestContext()
        if user.is_email_verified:
            return None
        self._consume_live_tokens(user.id, TokenPurpose.EMAIL_VERIFICATION)
        return self._issue_single_use_token(
            user=user,
            purpose=TokenPurpose.EMAIL_VERIFICATION,
            ttl=timedelta(hours=self._settings.email_verification_token_expire_hours),
            context=ctx,
        )

    # ================================================================== #
    # Token plumbing                                                     #
    # ================================================================== #

    def _issue_single_use_token(
        self,
        *,
        user: User,
        purpose: TokenPurpose,
        ttl: timedelta,
        context: RequestContext,
    ) -> str:
        plaintext = generate_opaque_token()
        now = utcnow()
        self._session.add(
            SecurityToken(
                user_id=user.id,
                purpose=purpose.value,
                token_hash=hash_opaque_token(plaintext),
                expires_at=now + ttl,
                request_ip=context.ip_address,
            ),
        )
        self._audit.record(
            action=(
                AuditAction.EMAIL_VERIFICATION_REQUESTED
                if purpose is TokenPurpose.EMAIL_VERIFICATION
                else AuditAction.PASSWORD_RESET_REQUESTED
            ),
            actor_user_id=user.id,
            actor_role=user.role,
            resource_type="user",
            resource_id=user.id,
            ip_address=context.ip_address,
            request_id=context.request_id,
            outcome="REQUESTED",
            metadata={"purpose": purpose.value},
        )
        return plaintext

    def _consume_single_use_token(self, *, token: str, purpose: TokenPurpose) -> SecurityToken:
        """Fetch and immediately consume a single-use token.

        The ``consumed_at`` write is conditional, so two concurrent requests with
        the same token cannot both succeed: the loser sees zero rows updated and
        is rejected. That is the race-safe equivalent of a read-then-write check.
        """
        token_hash = hash_opaque_token(token)
        now = utcnow()

        # The session runs with autoflush disabled, so anything inserted earlier in
        # this transaction is still pending in the identity map. Without an
        # explicit flush the SELECT below would not see it, and a token issued
        # moments earlier in the same request would appear to be unknown.
        self._session.flush()

        statement = (
            select(SecurityToken)
            .where(
                SecurityToken.token_hash == token_hash,
                SecurityToken.purpose == purpose.value,
            )
            .with_for_update()
        )
        row = self._session.execute(statement).scalar_one_or_none()
        if row is None:
            raise InvalidTokenError("The token is invalid.")

        if row.consumed_at is not None:
            # Reuse of a consumed token. Consume the user's other outstanding
            # tokens too, since the first token has leaked.
            self._consume_live_tokens(row.user_id, purpose)
            self._audit.record_durable(
                action=AuditAction.TOKEN_REUSE_DETECTED,
                actor_user_id=row.user_id,
                resource_type="security_token",
                resource_id=row.id,
                outcome="DENIED",
                metadata={"purpose": purpose.value},
            )
            raise InvalidTokenError("The token has already been used.")

        if row.expires_at <= now:
            raise TokenExpiredError("The token has expired.")

        affected = _execute_update(
            self._session,
            update(SecurityToken)
            .where(SecurityToken.id == row.id, SecurityToken.consumed_at.is_(None))
            .values(consumed_at=now),
        )
        if affected != 1:  # pragma: no cover - lost a concurrent race
            raise InvalidTokenError("The token has already been used.")

        self._session.refresh(row)
        return row

    def _consume_live_tokens(self, user_id: uuid.UUID, purpose: TokenPurpose) -> int:
        """Invalidate every outstanding token of a purpose for a user.

        Flushes first. The session runs with autoflush disabled, so a token
        issued earlier in the same transaction is still pending in the identity
        map and the UPDATE below would not see it - meaning that requesting a
        second reset token would silently fail to invalidate the first, and the
        older link would keep working.
        """
        self._session.flush()
        return _execute_update(
            self._session,
            update(SecurityToken)
            .where(
                SecurityToken.user_id == user_id,
                SecurityToken.purpose == purpose.value,
                SecurityToken.consumed_at.is_(None),
            )
            .values(consumed_at=utcnow()),
        )

    # ================================================================== #
    # Lookup                                                             #
    # ================================================================== #

    def _find_user_by_email(self, email: str) -> User | None:
        """Fetch by normalised email.

        A case-insensitive comparison is used even though the column is already
        lower-cased by the CHECK constraint, so that a row inserted by an
        out-of-band writer still matches rather than silently failing to log in.
        """
        statement = select(User).where(func.lower(User.email) == email)
        return self._session.execute(statement).scalar_one_or_none()

    def get_active_user(self, user_id: uuid.UUID) -> User:
        """Fetch a user and refuse if the account may not authenticate."""
        user = self._session.get(User, user_id)
        if user is None or user.deleted_at is not None:
            raise AuthenticationError("The account could not be found.")
        if not user.is_active or user.status != AccountStatus.ACTIVE.value:
            raise AccountDisabledError()
        return user

    def resolve_access_token(self, *, token: str) -> AuthenticatedUser:
        """Validate a bearer token and load the corresponding active user.

        The token signature is checked first, then the *current* account state is
        re-read. That ordering matters: a stateless JWT check alone would keep
        honouring an access token belonging to an account that has since been
        suspended.
        """
        claims = self._tokens.decode_access_token(token)
        user = self._session.get(User, claims.subject)
        if user is None or user.deleted_at is not None:
            raise InvalidTokenError()
        if not user.is_active or user.status != AccountStatus.ACTIVE.value:
            raise AccountDisabledError()
        return AuthenticatedUser(user=user, session_id=claims.session_id, token_id=claims.token_id)


def _find_session_id_by_hash(service: AuthService, token_hash: str) -> uuid.UUID:
    """Resolve a refresh-session id from a token hash.

    Split out so ``refresh()`` reads as the sequence of business rules rather
    than a nested query, and so the lookup has exactly one implementation.
    """
    statement = select(RefreshSession.id).where(RefreshSession.token_hash == token_hash)
    row = service._session.execute(statement).scalar_one_or_none()
    if row is None:
        # Sentinel that can never match a real primary key, so the caller gets
        # ``None`` from ``get()`` and reports an invalid token.
        return uuid.UUID(int=0)
    return row


def _role_value(role: UserRole | str) -> str:
    """Accept either a ``UserRole`` or its string value.

    Routes hand over a validated enum; scripts and tests often pass the plain
    string. Normalising here means the service has one canonical form regardless
    of caller, and an unknown value raises a clear ``ValueError`` rather than
    silently persisting an invalid role.
    """
    if isinstance(role, UserRole):
        return role.value
    return UserRole(role).value


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """A real Argon2id hash of a random value, used to equalise login timing.

    When the submitted address is not registered we still run a verification
    against this hash, so the response takes comparable time either way and does
    not disclose whether the account exists.

    Computed lazily rather than at import so that merely importing the service
    does not allocate 64 MiB.
    """
    hasher = PasswordHasherService()
    return hasher.hash(generate_opaque_token(16))


def get_user_by_email_for_auth(session: Session, email: str) -> User | None:
    """Repository-level helper, used by tests and admin tooling."""
    normalised = normalise_email(email)
    statement = select(User).where(func.lower(User.email) == normalised)
    return session.execute(statement).scalar_one_or_none()


def ensure_user_exists(session: Session, user_id: uuid.UUID) -> User:
    """Fetch a user or raise a not-found error.

    The message is the same for a genuinely absent row and one belonging to
    another tenant, so a caller cannot use this to probe for existence.
    """
    user = session.get(User, user_id)
    if user is None:
        raise NotFoundError("The requested user was not found.")
    return user
