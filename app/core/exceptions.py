"""Application exception hierarchy and the standard error codes.

Every failure the API returns deliberately flows through one of these classes.
Two reasons:

1. **Predictable clients.** A mobile client can branch on a stable ``code``
   rather than parsing prose, and a client author never has to guess whether a
   failure is a 400 or a 500.
2. **No accidental leakage.** An unexpected exception becomes a generic
   ``INTERNAL_ERROR`` with no detail, because the handler for
   :class:`AppError` controls exactly what is serialised and the handler for
   ``Exception`` controls the rest.

The mapping from exception to HTTP status is declared once, on each class, in
:data:`_STATUS_BY_ERROR`. Adding an error type without deciding its status is
deliberately awkward.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final


class ErrorCode:
    """Stable machine-readable error identifiers.

    These are part of the API contract. Renaming one is a breaking change.
    """

    # --- 400 business / validation --------------------------------------- #
    BAD_REQUEST = "BAD_REQUEST"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    # Error code identifier, not a credential.
    PASSWORD_POLICY_VIOLATION = "PASSWORD_POLICY_VIOLATION"  # noqa: S105  # nosec B105

    # --- 401 authentication --------------------------------------------- #
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    # Error code identifier, not a credential.
    INVALID_TOKEN = "INVALID_TOKEN"  # noqa: S105  # nosec B105
    # Error code identifier, not a credential.
    TOKEN_EXPIRED = "TOKEN_EXPIRED"  # noqa: S105  # nosec B105
    EMAIL_NOT_VERIFIED = "EMAIL_NOT_VERIFIED"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"

    # --- 403 authorisation ---------------------------------------------- #
    FORBIDDEN = "FORBIDDEN"
    INSUFFICIENT_ROLE = "INSUFFICIENT_ROLE"
    NOT_RESOURCE_OWNER = "NOT_RESOURCE_OWNER"
    VERIFICATION_SELF_ATTESTATION_BLOCKED = "VERIFICATION_SELF_ATTESTATION_BLOCKED"
    SENSITIVE_EVIDENCE_NOT_VISIBLE = "SENSITIVE_EVIDENCE_NOT_VISIBLE"
    ACCOUNT_DEACTIVATED = "ACCOUNT_DEACTIVATED"

    # --- 404 ------------------------------------------------------------- #
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    ROUTE_NOT_FOUND = "ROUTE_NOT_FOUND"

    # --- 405 / 415 / 409 / 413 / 415 / 422 ------------------------------- #
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    CONFLICT = "CONFLICT"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    UNPROCESSABLE_ENTITY = "UNPROCESSABLE_ENTITY"
    RATE_LIMITED = "RATE_LIMITED"
    IDEMPOTENCY_KEY_REUSED = "IDEMPOTENCY_KEY_REUSED"

    # --- 415 / 422 file specific ----------------------------------------- #
    UNSUPPORTED_FILE_TYPE = "UNSUPPORTED_FILE_TYPE"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    FILE_NOT_SCANNED = "FILE_NOT_SCANNED"
    FILE_INFECTED = "FILE_INFECTED"

    # --- 500 ------------------------------------------------------------- #
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


@dataclass(slots=True)
class ErrorDetail:
    """One field-level or contextual problem inside an error response."""

    message: str
    field: str | None = None
    code: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"message": self.message}
        if self.field is not None:
            payload["field"] = self.field
        if self.code is not None:
            payload["code"] = self.code
        return payload


class AppError(Exception):
    """Base class for every error the API reports deliberately.

    ``message`` is written for the API consumer. It must never contain a
    database error string, a stack trace, a file path, or a secret. When in
    doubt, say less.
    """

    code: str = ErrorCode.BAD_REQUEST
    status_code: int = 400
    #: Whether the message is safe to show in production without review.
    public_message: str = "The request could not be processed."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: list[ErrorDetail] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.message = message or self.public_message
        if code is not None:
            self.code = code
        if status_code is not None:
            self.status_code = status_code
        self.details: list[ErrorDetail] = details or []
        self.headers: dict[str, str] = headers or {}
        super().__init__(self.message)

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            payload["details"] = [detail.as_dict() for detail in self.details]
        return payload


# --------------------------------------------------------------------------- #
# 400                                                                         #
# --------------------------------------------------------------------------- #
class BadRequestError(AppError):
    code = ErrorCode.BAD_REQUEST
    status_code = 400
    public_message = "The request could not be processed."


class ValidationError(AppError):
    code = ErrorCode.VALIDATION_FAILED
    status_code = 422
    public_message = "One or more fields are invalid."


class InvalidStateTransitionError(AppError):
    """A requested transition is not legal from the resource's current state.

    Used instead of a generic conflict so the client can distinguish "this is
    impossible now" from "this already exists".
    """

    code = ErrorCode.INVALID_STATE_TRANSITION
    status_code = 409
    public_message = "That action is not allowed in the current state."


class PasswordPolicyError(AppError):
    code = ErrorCode.PASSWORD_POLICY_VIOLATION
    status_code = 422
    public_message = "The password does not meet the required policy."


# --------------------------------------------------------------------------- #
# 401                                                                         #
# --------------------------------------------------------------------------- #
class AuthenticationError(AppError):
    code = ErrorCode.AUTHENTICATION_REQUIRED
    status_code = 401
    public_message = "Authentication is required."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        details: list[ErrorDetail] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        merged = headers or {}
        merged.setdefault("WWW-Authenticate", 'Bearer realm="fundipulse"')
        super().__init__(message, code=code, details=details, headers=merged)


class InvalidCredentialsError(AuthenticationError):
    """Deliberately identical for "no such user" and "wrong password".

    Distinguishing them turns the login endpoint into a user-enumeration oracle,
    which attackers can use to discover registered addresses.
    """

    code = ErrorCode.INVALID_CREDENTIALS
    public_message = "Invalid email or password."


class InvalidTokenError(AuthenticationError):
    code = ErrorCode.INVALID_TOKEN
    public_message = "The provided token is invalid."


class TokenExpiredError(AuthenticationError):
    code = ErrorCode.TOKEN_EXPIRED
    public_message = "The provided token has expired."


class EmailNotVerifiedError(AuthenticationError):
    code = ErrorCode.EMAIL_NOT_VERIFIED
    status_code = 403
    public_message = "Email verification is required for this action."


class AccountDisabledError(AuthenticationError):
    code = ErrorCode.ACCOUNT_DISABLED
    status_code = 403
    public_message = "This account is not active."


class AccountLockedError(AuthenticationError):
    code = ErrorCode.ACCOUNT_LOCKED
    status_code = 423
    public_message = "This account is temporarily locked after too many failed attempts."


# --------------------------------------------------------------------------- #
# 403                                                                         #
# --------------------------------------------------------------------------- #
class ForbiddenError(AppError):
    code = ErrorCode.FORBIDDEN
    status_code = 403
    public_message = "You do not have permission to perform this action."


class InsufficientRoleError(ForbiddenError):
    code = ErrorCode.INSUFFICIENT_ROLE
    public_message = "Your role does not permit this action."


class NotResourceOwnerError(ForbiddenError):
    """The caller is authenticated but does not own the target resource.

    Note that most ownership failures are reported as ``404`` rather than
    ``403``. Returning ``403`` for a resource that exists confirms its
    existence to someone who should not know it exists at all. Services pass
    ``expose_exists=False`` unless existence is already public.
    """

    code = ErrorCode.NOT_RESOURCE_OWNER
    public_message = "You do not have permission to access this resource."


class SelfVerificationBlockedError(ForbiddenError):
    """A worker attempted to verify their own claim.

    Audited separately because it is the single most important invariant in the
    verification system, and a violation of it is a serious signal.
    """

    code = ErrorCode.VERIFICATION_SELF_ATTESTATION_BLOCKED
    public_message = "You cannot verify your own claim."


class EvidenceNotVisibleError(ForbiddenError):
    code = ErrorCode.SENSITIVE_EVIDENCE_NOT_VISIBLE
    public_message = "This document is not available to you."


class AccountDeactivatedError(ForbiddenError):
    code = ErrorCode.ACCOUNT_DEACTIVATED
    public_message = "This account has been deactivated."


# --------------------------------------------------------------------------- #
# 404                                                                         #
# --------------------------------------------------------------------------- #
class NotFoundError(AppError):
    code = ErrorCode.RESOURCE_NOT_FOUND
    status_code = 404
    public_message = "The requested resource was not found."


class RouteNotFoundError(NotFoundError):
    code = ErrorCode.ROUTE_NOT_FOUND
    public_message = "No endpoint matches this request."


# --------------------------------------------------------------------------- #
# 405 / 409 / 413 / 415 / 422 / 429                                            #
# --------------------------------------------------------------------------- #
class MethodNotAllowedError(AppError):
    code = ErrorCode.METHOD_NOT_ALLOWED
    status_code = 405
    public_message = "That method is not allowed on this endpoint."


class ConflictError(AppError):
    code = ErrorCode.CONFLICT
    status_code = 409
    public_message = "The request conflicts with the current state."


class PayloadTooLargeError(AppError):
    code = ErrorCode.PAYLOAD_TOO_LARGE
    status_code = 413
    public_message = "The request body is too large."


class UnsupportedMediaTypeError(AppError):
    code = ErrorCode.UNSUPPORTED_MEDIA_TYPE
    status_code = 415
    public_message = "That content type is not supported."


class UnsupportedFileTypeError(UnsupportedMediaTypeError):
    code = ErrorCode.UNSUPPORTED_FILE_TYPE
    public_message = "That file type is not accepted."


class FileTooLargeError(PayloadTooLargeError):
    code = ErrorCode.FILE_TOO_LARGE
    public_message = "The uploaded file is too large."


class FileNotScannedError(AppError):
    code = ErrorCode.FILE_NOT_SCANNED
    status_code = 409
    public_message = "This file is not available until scanning completes."


class FileInfectedError(AppError):
    code = ErrorCode.FILE_INFECTED
    status_code = 409
    public_message = "This file was rejected by malware scanning."


class UnprocessableEntityError(AppError):
    code = ErrorCode.UNPROCESSABLE_ENTITY
    status_code = 422
    public_message = "The request could not be processed."


class RateLimitExceededError(AppError):
    code = ErrorCode.RATE_LIMITED
    status_code = 429
    public_message = "Too many requests. Please try again later."

    def __init__(
        self,
        message: str | None = None,
        *,
        retry_after_seconds: int = 60,
        **kwargs: Any,
    ) -> None:
        headers = kwargs.pop("headers", {}) or {}
        headers["Retry-After"] = str(retry_after_seconds)
        headers["X-RateLimit-Remaining"] = "0"
        super().__init__(message, headers=headers, **kwargs)
        self.retry_after_seconds = retry_after_seconds


class IdempotencyKeyReusedError(ConflictError):
    code = ErrorCode.IDEMPOTENCY_KEY_REUSED
    public_message = "This idempotency key was already used with a different request payload."


# --------------------------------------------------------------------------- #
# 500                                                                         #
# --------------------------------------------------------------------------- #
class InternalServerError(AppError):
    code = ErrorCode.INTERNAL_ERROR
    status_code = 500
    public_message = "An unexpected error occurred."


class ServiceUnavailableError(AppError):
    code = ErrorCode.SERVICE_UNAVAILABLE
    status_code = 503
    public_message = "The service is temporarily unavailable."


#: Lookup used by tests and documentation to assert that no error type has been
#: added without deciding its HTTP status.
ALL_ERROR_TYPES: Final[tuple[type[AppError], ...]] = (
    BadRequestError,
    ValidationError,
    InvalidStateTransitionError,
    PasswordPolicyError,
    AuthenticationError,
    InvalidCredentialsError,
    InvalidTokenError,
    TokenExpiredError,
    EmailNotVerifiedError,
    AccountDisabledError,
    AccountLockedError,
    ForbiddenError,
    InsufficientRoleError,
    NotResourceOwnerError,
    SelfVerificationBlockedError,
    EvidenceNotVisibleError,
    AccountDeactivatedError,
    NotFoundError,
    RouteNotFoundError,
    MethodNotAllowedError,
    ConflictError,
    PayloadTooLargeError,
    UnsupportedMediaTypeError,
    UnsupportedFileTypeError,
    FileTooLargeError,
    FileNotScannedError,
    FileInfectedError,
    UnprocessableEntityError,
    RateLimitExceededError,
    IdempotencyKeyReusedError,
    InternalServerError,
    ServiceUnavailableError,
)


@dataclass(slots=True)
class ErrorEnvelope:
    """The exact JSON body returned for every failure."""

    error: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"error": self.error}
