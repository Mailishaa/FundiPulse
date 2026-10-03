"""Shared FastAPI dependencies.

This module is where an HTTP request becomes a trustworthy identity and a
database session. Everything a route needs that is not route-specific lives
here, which keeps route functions short and makes the security-relevant parts of
request handling reviewable in one file.

The important property: **the current user is resolved from the database, never
from the request body.** A client that sends ``role: ADMIN`` is describing a
different user's request; it has no effect on anything.
"""

from __future__ import annotations

from typing import Annotated
import uuid

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.constants import AccountStatus, UserRole
from app.core.exceptions import (
    AccountDeactivatedError,
    AuthenticationError,
    EmailNotVerifiedError,
    InsufficientRoleError,
    NotFoundError,
)
from app.core.rate_limit import (
    RateLimitDecision,
    RateLimiter,
    get_rate_limiter,
    resolve_identity,
)
from app.db.models.user import User
from app.db.session import get_db
from app.services.auth_service import AuthenticatedUser, AuthService, RequestContext
from app.utils.net import coerce_ip_address

#: ``auto_error=False`` so that a missing header produces our standard error
#: envelope rather than FastAPI's default 403 with a different body shape.
_bearer_scheme = HTTPBearer(auto_error=False, description="Bearer access token")

DbSession = Annotated[Session, Depends(get_db)]


def get_bearer_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
) -> str:
    """Extract the bearer token or raise the standard 401."""
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("An access token is required.")
    if credentials.scheme.lower() != "bearer":  # pragma: no cover - HTTPBearer filters this
        raise AuthenticationError("The Authorization scheme must be Bearer.")
    return credentials.credentials


# --------------------------------------------------------------------------- #
# Request provenance                                                          #
# --------------------------------------------------------------------------- #
def get_request_context(request: Request) -> RequestContext:
    """Build the audit context from the live request."""
    return RequestContext(
        ip_address=resolve_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        request_id=getattr(request.state, "request_id", None),
    )


def resolve_client_ip(request: Request) -> str | None:
    """Determine the real client address, validating the proxy header.

    ``X-Forwarded-For`` is client-controllable in general. Render appends to it
    and the rightmost entry is the proxy chain, so the first entry is the client
    address. The value is parsed with :func:`~app.utils.net.coerce_ip_address` and
    discarded if it is not a real address: a junk header must never reach the
    ``INET`` column, where it would raise and turn a spoofed header into a 500.

    Falls back to the socket address, validated the same way. That fallback
    matters because the ASGI test client reports a non-address host name.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        validated = coerce_ip_address(forwarded.split(",")[0])
        if validated:
            return validated

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        validated = coerce_ip_address(real_ip)
        if validated:
            return validated

    if request.client is not None:
        return coerce_ip_address(request.client.host)
    return None


# --------------------------------------------------------------------------- #
# Identity                                                                    #
# --------------------------------------------------------------------------- #
def get_auth_service(session: DbSession) -> AuthService:
    """Provide an :class:`AuthService` bound to the request's session."""
    return AuthService(session)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


def get_current_user(
    request: Request,
    token: Annotated[str, Depends(get_bearer_token)],
    auth_service: AuthServiceDep,
) -> User:
    """Resolve the authenticated, active user for this request.

    Raises ``401`` for a missing/invalid/expired token and ``403`` for an account
    that exists but may not act. The distinction matters to the client: a 401 means
    "refresh or log in again", a 403 means "logging in again will not help".

    The resolved session id is stashed on ``request.state`` rather than a
    ``ContextVar``. FastAPI runs synchronous dependencies in a threadpool with a
    *copied* context, so a ``ContextVar.set()`` performed here is invisible to the
    route handler that runs afterwards; ``request.state`` is a plain attribute on
    the shared request object, so it propagates reliably.
    """
    authenticated: AuthenticatedUser = auth_service.resolve_access_token(token=token)
    user = authenticated.user
    if user.deleted_at is not None or user.status == AccountStatus.DEACTIVATED.value:
        raise AccountDeactivatedError()
    request.state.session_id = authenticated.session_id
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_session_id(request: Request) -> uuid.UUID | None:
    """The caller's refresh-session id, or ``None`` for a token without one."""
    return getattr(request.state, "session_id", None)


CurrentSessionId = Annotated[uuid.UUID | None, Depends(get_current_session_id)]


def get_optional_bearer_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
) -> str | None:
    """The bearer token, or ``None`` when no ``Authorization`` header was sent.

    Separate from :func:`get_bearer_token` because FastAPI resolves every
    sub-dependency before the dependant runs: reusing the raising version here
    would 401 an anonymous request before the ``credentials is None`` branch could
    be reached, which defeats the point of an optional dependency.
    """
    if credentials is None or not credentials.credentials:
        return None
    return credentials.credentials


def get_optional_user(
    request: Request,
    token: Annotated[str | None, Depends(get_optional_bearer_token)],
    auth_service: AuthServiceDep,
) -> User | None:
    """Resolve the caller if a token is present, otherwise ``None``.

    Used only by endpoints that serve genuinely public data with optional
    personalisation.

    An absent header yields ``None``; a header that is present but invalid raises,
    because treating a broken token as anonymous would return quietly different
    data to a client that believes it authenticated.
    """
    if token is None:
        return None
    return get_current_user(request=request, token=token, auth_service=auth_service)


OptionalUser = Annotated[User | None, Depends(get_optional_user)]


# --------------------------------------------------------------------------- #
# Authorisation                                                               #
# --------------------------------------------------------------------------- #
def require_roles(*allowed: UserRole) -> object:
    """Build a dependency that admits only the listed platform roles.

    Deny-by-default: an unlisted role is refused, and an empty allowlist refuses
    everyone. Adding a new :class:`~app.core.constants.UserRole` member therefore
    does **not** silently grant access anywhere, which is the opposite of the usual
    failure mode.
    """
    permitted = frozenset(role.value for role in allowed)

    def dependency(current_user: CurrentUser) -> User:
        if current_user.role not in permitted:
            raise InsufficientRoleError()
        return current_user

    return dependency


RequireWorker = Annotated[User, Depends(require_roles(UserRole.WORKER))]
RequireEmployer = Annotated[User, Depends(require_roles(UserRole.EMPLOYER))]
RequireAdmin = Annotated[User, Depends(require_roles(UserRole.ADMIN))]

#: Admins may act on any worker- or employer-capable endpoint.
RequireWorkerOrAdmin = Annotated[User, Depends(require_roles(UserRole.WORKER, UserRole.ADMIN))]
RequireEmployerOrAdmin = Annotated[User, Depends(require_roles(UserRole.EMPLOYER, UserRole.ADMIN))]


def require_email_verified(current_user: CurrentUser) -> User:
    """Refuse actions that need a proven mailbox.

    Applied to actions with an abuse or impersonation cost, not to the whole
    account, so a user is never locked out of their own passport by an undelivered
    email.
    """
    if not current_user.is_email_verified:
        raise EmailNotVerifiedError()
    return current_user


RequireVerifiedEmail = Annotated[User, Depends(require_email_verified)]


def get_path_uuid(name: str, value: str) -> uuid.UUID:
    """Parse a UUID that arrived as a string, or raise the standard 404.

    Declared as ``Annotated[uuid.UUID, Path(...)]`` in FastAPI for real path
    parameters; this helper exists for values embedded in query filters, where
    Pydantic validation does not run.

    Reports the same 404 as an absent row rather than a 422 naming the field: a
    caller probing identifiers should not learn which parameter names are valid.
    ``name`` is accepted for call-site readability and is deliberately not
    reflected in the response.
    """
    del name
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise NotFoundError("The requested resource was not found.") from exc


# --------------------------------------------------------------------------- #
# Rate limiting                                                               #
# --------------------------------------------------------------------------- #
RateLimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]


def rate_limit(rule_name: str, *, authenticated: bool = False) -> object:
    """Build a dependency enforcing one named rule for the current request.

    ``authenticated=True`` keys the bucket on the caller's user id, so many workers
    behind one site NAT do not share an allowance. The anonymous variant keys on the
    validated client address, which is the only thing available before login.

    Declaring this as a parameter rather than applying it in middleware means the
    limit is visible in the route's signature and in the OpenAPI document. A limit
    that lives only in a middleware list is invisible to the next person who adds an
    endpoint, and endpoints that forget it are unlimited forever.
    """

    def dependency(
        request: Request,
        limiter: RateLimiterDep,
        user: OptionalUser = None,
    ) -> RateLimitDecision:
        if not authenticated:
            user = None  # never let a stale token change an anonymous bucket
        identity = resolve_identity(
            rule_name,
            user_id=user.id if user is not None else None,
            client_ip=resolve_client_ip(request),
        )
        decision = limiter.enforce(limiter.rule_for(rule_name), identity)
        # Stashed so the response middleware can attach the standard headers to a
        # success as well as to a 429. Without this a client cannot tell how much
        # allowance it has left until it is already refused.
        request.state.rate_limit_decision = decision
        return decision

    return dependency


LoginRateLimit = Annotated[RateLimitDecision, Depends(rate_limit("login"))]
RegisterRateLimit = Annotated[RateLimitDecision, Depends(rate_limit("register"))]
PasswordResetRateLimit = Annotated[RateLimitDecision, Depends(rate_limit("password_reset"))]
FileUploadRateLimit = Annotated[
    RateLimitDecision, Depends(rate_limit("file_upload", authenticated=True))
]
JobApplyRateLimit = Annotated[
    RateLimitDecision, Depends(rate_limit("job_apply", authenticated=True))
]
SearchRateLimit = Annotated[RateLimitDecision, Depends(rate_limit("search"))]
