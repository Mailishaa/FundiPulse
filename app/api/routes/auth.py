"""Authentication endpoints.

Route handlers here are deliberately thin: parse, delegate to a service, wrap the
result in the standard envelope. No business rule, and no authorisation
decision, appears in this file.

**Token transport.** Access and refresh tokens are returned in the JSON body and
never placed in a URL. A token in a URL ends up in browser history, proxy logs,
``Referer`` headers and server access logs; a body does not.

**Non-enumerating responses.** ``/forgot-password`` and ``/resend-verification``
answer identically whether or not the address is registered or verified. A
different response is an account-enumeration oracle, which the brief explicitly
forbids.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Annotated

from fastapi import APIRouter, Body, Depends, status

from app.api.dependencies import (
    CurrentSessionId,
    CurrentUser,
    DbSession,
    LoginRateLimit,
    PasswordResetRateLimit,
    RegisterRateLimit,
    get_request_context,
)
from app.schemas.auth import (
    AuthSessionResponse,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    LogoutRequest,
    LogoutResponse,
    PasswordChangeResponse,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserResponse,
    VerificationDispatchResponse,
    VerifyEmailRequest,
)
from app.schemas.common import ErrorResponse, Meta, ResponseEnvelope
from app.services.auth_service import AuthService, AuthTokens, RequestContext
from app.services.delivery_service import (
    build_password_reset_email,
    build_verification_email,
    get_delivery_channel,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _token_response(tokens: AuthTokens) -> TokenResponse:
    """Adapt the service dataclass to the public token schema."""
    return TokenResponse(
        access_token=tokens.access_token,
        expires_in=tokens.access_token_expires_in,
        refresh_token=tokens.refresh_token,
        refresh_expires_in=tokens.refresh_token_expires_in,
    )


def _auth_response(
    user: object, tokens: AuthTokens, request_id: str | None
) -> ResponseEnvelope[AuthSessionResponse]:
    return ResponseEnvelope(
        data=AuthSessionResponse(
            user=UserResponse.model_validate(user),
            tokens=_token_response(tokens),
        ),
        meta=Meta(request_id=request_id),
    )


@router.post(
    "/register",
    response_model=ResponseEnvelope[AuthSessionResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Register a worker or employer account",
    description=(
        "Creates an account and returns a token pair.\n\n"
        "`role` must be `WORKER` or `EMPLOYER`. `ADMIN` is rejected: an "
        "administrator account cannot be self-provisioned by a client.\n\n"
        "A single-use email-verification token is issued at the same time. No "
        "mail provider is configured in this milestone, so the token is written "
        "to the development delivery log - see "
        "`app/services/delivery_service.py`."
    ),
    responses={
        201: {"description": "Account created."},
        409: {"model": ErrorResponse, "description": "The address is already registered."},
        422: {"model": ErrorResponse, "description": "Validation failed."},
        429: {"model": ErrorResponse, "description": "Too many registration attempts."},
    },
)
def register(
    payload: RegisterRequest,
    session: DbSession,
    context: Annotated[RequestContext, Depends(get_request_context)],
    _limit: RegisterRateLimit,
) -> ResponseEnvelope[AuthSessionResponse]:
    user, verification_token, tokens = AuthService(session).register(
        email=payload.email,
        password=payload.password,
        role=payload.role,
        context=context,
    )

    get_delivery_channel().send(
        replace(
            build_verification_email(
                recipient_name=payload.display_name or "",
                token=verification_token,
                expiry_hours=48,
            ),
            to_email=user.email,
        )
    )
    return _auth_response(user, tokens, context.request_id)


@router.post(
    "/login",
    response_model=ResponseEnvelope[AuthSessionResponse],
    summary="Exchange credentials for a token pair",
    description=(
        "Returns a short-lived access token and a rotating refresh token.\n\n"
        "Failure responses are identical for an unknown address and a wrong "
        "password, and the response time is equalised by performing a dummy hash "
        "verification, so this endpoint cannot be used to discover which "
        "addresses are registered.\n\n"
        "Repeated failures lock the account for "
        "`ACCOUNT_LOCKOUT_MINUTES`."
    ),
    responses={
        200: {"description": "Authenticated."},
        401: {"model": ErrorResponse, "description": "Invalid credentials."},
        403: {"model": ErrorResponse, "description": "The account is not active."},
        423: {"model": ErrorResponse, "description": "The account is temporarily locked."},
        429: {"model": ErrorResponse, "description": "Too many login attempts."},
    },
)
def login(
    payload: LoginRequest,
    session: DbSession,
    context: Annotated[RequestContext, Depends(get_request_context)],
    _limit: LoginRateLimit,
) -> ResponseEnvelope[AuthSessionResponse]:
    user, tokens = AuthService(session).authenticate(
        email=payload.email,
        password=payload.password,
        context=context,
    )
    return _auth_response(user, tokens, context.request_id)


@router.post(
    "/refresh",
    response_model=ResponseEnvelope[TokenResponse],
    summary="Rotate a refresh token",
    description=(
        "Returns a new token pair and revokes the presented token.\n\n"
        "Presenting a token that has already been rotated means it was "
        "captured, so the entire token family is revoked immediately and the "
        "event is recorded as `TOKEN_REUSE_DETECTED`. Both parties are signed "
        "out - intentional, because one of them is an attacker."
    ),
    responses={
        200: {"description": "New token pair issued."},
        401: {"model": ErrorResponse, "description": "The refresh token is invalid or expired."},
    },
)
def refresh_tokens(
    payload: RefreshRequest,
    session: DbSession,
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ResponseEnvelope[TokenResponse]:
    _, tokens = AuthService(session).refresh(
        refresh_token=payload.refresh_token,
        context=context,
    )
    return ResponseEnvelope(
        data=_token_response(tokens),
        meta=Meta(request_id=context.request_id),
    )


@router.post(
    "/logout",
    response_model=ResponseEnvelope[LogoutResponse],
    summary="Revoke the current session, or every session",
    description=(
        "Revokes the session that made the request. Send "
        '`{"all_sessions": true}` to sign out everywhere, which is also the '
        "correct response to a suspected compromise."
    ),
    responses={
        200: {"description": "Sessions revoked."},
        401: {"model": ErrorResponse, "description": "Authentication required."},
    },
)
def logout(
    session: DbSession,
    current_user: CurrentUser,
    current_session: CurrentSessionId,
    context: Annotated[RequestContext, Depends(get_request_context)],
    payload: LogoutRequest | None = Body(default=None),
) -> ResponseEnvelope[LogoutResponse]:
    sign_out_everywhere = bool(payload and payload.all_sessions)
    revoked = AuthService(session).logout(
        user=current_user,
        session_id=None if sign_out_everywhere else current_session,
        context=context,
    )
    return ResponseEnvelope(
        data=LogoutResponse(sessions_revoked=revoked),
        meta=Meta(request_id=context.request_id),
    )


@router.post(
    "/change-password",
    response_model=ResponseEnvelope[PasswordChangeResponse],
    summary="Change the current password",
    description=(
        "Requires the current password.\n\n"
        "**Every session is revoked, including this one**, so the client must "
        "sign in again. That is deliberate: it guarantees the old credential is "
        "dead everywhere rather than only in this tab."
    ),
    responses={
        200: {"description": "Password changed; sign in again."},
        401: {"model": ErrorResponse, "description": "The current password is incorrect."},
        422: {"model": ErrorResponse, "description": "The new password fails the policy."},
        429: {"model": ErrorResponse, "description": "Too many attempts."},
    },
)
def change_password(
    payload: ChangePasswordRequest,
    session: DbSession,
    current_user: CurrentUser,
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ResponseEnvelope[PasswordChangeResponse]:
    auth = AuthService(session)
    auth.change_password(
        user=current_user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        context=context,
    )
    # After the call every session is revoked; report how many that was.
    revoked = auth.logout(user=current_user, session_id=None, context=context)
    return ResponseEnvelope(
        data=PasswordChangeResponse(
            message="Your password has been changed. Please sign in again.",
            reauthenticate=True,
            sessions_revoked=revoked,
        ),
        meta=Meta(request_id=context.request_id),
    )


@router.post(
    "/forgot-password",
    response_model=ResponseEnvelope[VerificationDispatchResponse],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a password reset link",
    description=(
        "Always returns `202` with the same body, whether or not the address is "
        "registered. That uniformity is deliberate: a different response for an "
        "unknown address would let anyone test which addresses have accounts.\n\n"
        "Any previously issued reset tokens are invalidated, so only the newest "
        "link works."
    ),
    responses={
        202: {"description": "Request accepted."},
        429: {"model": ErrorResponse, "description": "Too many requests."},
    },
)
def forgot_password(
    payload: ForgotPasswordRequest,
    session: DbSession,
    context: Annotated[RequestContext, Depends(get_request_context)],
    _limit: PasswordResetRateLimit,
) -> ResponseEnvelope[VerificationDispatchResponse]:
    auth = AuthService(session)
    token = auth.request_password_reset(email=payload.email, context=context)

    if token:
        # Delivering the message can fail if no provider is configured. The
        # request must still succeed: telling the caller "delivery failed" would
        # disclose whether the account exists. The failure is logged instead.
        try:
            get_delivery_channel().send(
                replace(
                    build_password_reset_email(recipient_name="", token=token, expiry_minutes=30),
                    to_email=payload.email,
                )
            )
        except Exception:  # noqa: BLE001 - never leak delivery state to the client
            from app.core.logging import get_logger

            get_logger(__name__).error(
                "Password reset delivery failed",
                extra={"error_category": "delivery_failure"},
                exc_info=True,
            )

    return ResponseEnvelope(
        data=VerificationDispatchResponse(
            message=("If an account exists for that address, a password reset link has been sent."),
            email=payload.email,
        ),
        meta=Meta(request_id=context.request_id),
    )


@router.post(
    "/reset-password",
    response_model=ResponseEnvelope[PasswordChangeResponse],
    summary="Complete a password reset",
    description=(
        "Consumes a single-use reset token and sets the new password. All "
        "sessions are revoked. The account's email is marked verified, because "
        "proving control of the mailbox is precisely what the reset did."
    ),
    responses={
        200: {"description": "Password reset; sign in again."},
        401: {"model": ErrorResponse, "description": "The token is invalid or expired."},
        422: {"model": ErrorResponse, "description": "The new password fails the policy."},
    },
)
def reset_password(
    payload: ResetPasswordRequest,
    session: DbSession,
    context: Annotated[RequestContext, Depends(get_request_context)],
    _limit: PasswordResetRateLimit,
) -> ResponseEnvelope[PasswordChangeResponse]:
    AuthService(session).complete_password_reset(
        token=payload.token,
        new_password=payload.new_password,
        context=context,
    )
    return ResponseEnvelope(
        data=PasswordChangeResponse(
            message="Your password has been reset. Please sign in.",
            reauthenticate=True,
            sessions_revoked=0,
        ),
        meta=Meta(request_id=context.request_id),
    )


@router.post(
    "/verify-email",
    response_model=ResponseEnvelope[UserResponse],
    summary="Confirm an email address",
    description=(
        "Consumes a single-use verification token. Presented a token twice, the "
        "second attempt is rejected and the user's remaining tokens are "
        "invalidated."
    ),
    responses={
        200: {"description": "Email confirmed."},
        401: {"model": ErrorResponse, "description": "The token is invalid or expired."},
    },
)
def verify_email(
    payload: VerifyEmailRequest,
    session: DbSession,
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ResponseEnvelope[UserResponse]:
    user = AuthService(session).verify_email(token=payload.token, context=context)
    return ResponseEnvelope(
        data=UserResponse.model_validate(user),
        meta=Meta(request_id=context.request_id),
    )


@router.post(
    "/resend-verification",
    response_model=ResponseEnvelope[VerificationDispatchResponse],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Reissue an email verification link",
    description=(
        "Requires authentication, but deliberately **not** a verified address - "
        "the caller is by definition not yet verified.\n\n"
        "Returns `202` whether or not the address is already verified, so the "
        "response does not disclose verification state."
    ),
    responses={
        202: {"description": "Request accepted."},
        401: {"model": ErrorResponse, "description": "Authentication required."},
    },
)
def resend_verification(
    session: DbSession,
    current_user: CurrentUser,
    context: Annotated[RequestContext, Depends(get_request_context)],
    _limit: PasswordResetRateLimit,
) -> ResponseEnvelope[VerificationDispatchResponse]:
    token = AuthService(session).resend_email_verification(user=current_user, context=context)
    if token:
        try:
            get_delivery_channel().send(
                replace(
                    build_verification_email(recipient_name="", token=token, expiry_hours=48),
                    to_email=current_user.email,
                )
            )
        except Exception:  # noqa: BLE001 - see forgot_password
            from app.core.logging import get_logger

            get_logger(__name__).error(
                "Verification delivery failed",
                extra={"error_category": "delivery_failure"},
                exc_info=True,
            )

    return ResponseEnvelope(
        data=VerificationDispatchResponse(
            message=("If your address needs confirming, a new verification link has been sent."),
            email=current_user.email,
        ),
        meta=Meta(request_id=context.request_id),
    )


@router.get(
    "/me",
    response_model=ResponseEnvelope[UserResponse],
    summary="The authenticated account",
    description=(
        "Returns the caller's own account. There is deliberately no path "
        "parameter: reading another user's account is a separate, explicitly "
        "authorised endpoint."
    ),
    responses={
        200: {"description": "The current account."},
        401: {"model": ErrorResponse, "description": "Authentication required."},
    },
)
def read_current_user(
    current_user: CurrentUser,
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ResponseEnvelope[UserResponse]:
    return ResponseEnvelope(
        data=UserResponse.model_validate(current_user),
        meta=Meta(request_id=context.request_id),
    )


__all__ = ["router"]
