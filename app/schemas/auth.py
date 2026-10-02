"""Request and response schemas for authentication and user accounts.

Every response schema is an explicit allowlist of fields. A field that is not
declared here cannot be serialised, which is why ``password_hash`` cannot leak:
the schema has no such attribute to fill.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
import uuid

from pydantic import EmailStr, Field, field_validator

from app.core.config import get_settings
from app.core.constants import AccountStatus, UserRole
from app.core.security import check_password_policy
from app.schemas.common import (
    ApiModel,
    RequestSchema,
    ResponseSchema,
    TimestampMixinSchema,
)


# --------------------------------------------------------------------------- #
# Field types                                                                #
# --------------------------------------------------------------------------- #
def _password(value: str) -> str:
    """Validate a password against the policy at the schema boundary.

    Enforcing it here means an invalid password produces a precise, field-level
    422 before any database work, and the same rule cannot be forgotten at a
    second registration-like endpoint.

    The policy is checked, never enforced by mutation: silently rewriting a
    password would make a login fail later for reasons the user cannot see.
    """
    settings = get_settings()
    candidate = value.strip()
    result = check_password_policy(candidate, settings)
    if not result.ok and settings.enforce_password_policy:
        raise ValueError("The password " + ", ".join(result.failures) + ".")
    return candidate


PasswordField = Annotated[
    str, Field(min_length=1, max_length=256), Field(json_schema_extra={"format": "password"})
]

ShortText = Annotated[str, Field(min_length=1, max_length=120)]
DisplayName = Annotated[str, Field(min_length=2, max_length=120)]
FullName = Annotated[str, Field(min_length=1, max_length=160)]
UserAgent = Annotated[str, Field(min_length=1, max_length=512)]


# --------------------------------------------------------------------------- #
# Requests                                                                   #
# --------------------------------------------------------------------------- #
class RegisterRequest(RequestSchema):
    """Create a worker or employer account."""

    email: EmailStr = Field(description="Login address. Stored lower-cased.")
    password: PasswordField = Field(description="At least 12 characters.")
    role: UserRole = Field(
        description=(
            "WORKER or EMPLOYER. ADMIN is rejected: a client cannot create an "
            "administrator, and an administrator account is provisioned internally."
        )
    )
    display_name: DisplayName | None = Field(
        default=None,
        description=(
            "Required for WORKER. Ignored for EMPLOYER, where the company name "
            "belongs to the organization."
        ),
    )
    accepted_terms: bool = Field(
        description="Must be true. Records that the terms were shown and accepted.",
    )

    @field_validator("role")
    @classmethod
    def _reject_admin_self_registration(cls, value: UserRole) -> UserRole:
        """Refuse ``role=ADMIN`` at the schema boundary.

        This is the first of two guards. The second is in the service, which
        never reads the role from a trusted client without checking it. Relying on
        one guard would make a future refactor of either one a privilege
        escalation.
        """
        if value is UserRole.ADMIN:
            raise ValueError("Administrator accounts cannot be self-registered. Contact support.")
        return value

    @field_validator("password")
    @classmethod
    def _validate_password(cls, value: str) -> str:
        return _password(value)

    @field_validator("accepted_terms")
    @classmethod
    def _require_terms(cls, value: bool) -> bool:
        if not value:
            raise ValueError("The terms of service must be accepted.")
        return value


class LoginRequest(RequestSchema):
    email: EmailStr
    password: PasswordField


class RefreshRequest(RequestSchema):
    refresh_token: Annotated[str, Field(min_length=20, max_length=512)]


class ChangePasswordRequest(RequestSchema):
    current_password: PasswordField
    new_password: PasswordField

    @field_validator("new_password")
    @classmethod
    def _validate_new_password(cls, value: str) -> str:
        return _password(value)


class ForgotPasswordRequest(RequestSchema):
    """The response is identical whether or not the address is registered."""

    email: EmailStr


class ResetPasswordRequest(RequestSchema):
    token: Annotated[str, Field(min_length=20, max_length=512)]
    new_password: PasswordField

    @field_validator("new_password")
    @classmethod
    def _validate_new_password(cls, value: str) -> str:
        return _password(value)


class VerifyEmailRequest(RequestSchema):
    token: Annotated[str, Field(min_length=20, max_length=512)]


class LogoutRequest(RequestSchema):
    """Absent body means "log out this session"."""

    all_sessions: bool = Field(
        default=False,
        description="True revokes every session for the user, not just this one.",
    )


class UpdateUserRequest(RequestSchema):
    """Self-service account changes.

    There is no ``role``, ``is_active``, ``is_email_verified`` or ``status``
    field. ``extra="forbid"`` on the base class means a client that sends one
    gets a 422 rather than silently changing an account's privileges - which is
    the mass-assignment case OWASP A01 is about.
    """

    email: EmailStr | None = None


# --------------------------------------------------------------------------- #
# Responses                                                                  #
# --------------------------------------------------------------------------- #
class UserResponse(TimestampMixinSchema):
    """A user account as the owner or an administrator sees it.

    Contains no credential material and no professional profile: those are
    separate resources with their own visibility rules.
    """

    id: uuid.UUID
    email: EmailStr
    role: UserRole
    status: AccountStatus
    is_active: bool
    is_email_verified: bool
    last_login_at: datetime | None = None
    email_verified_at: datetime | None = None


class PublicUserResponse(ResponseSchema):
    """The minimal projection safe for another user to see.

    Used where a user must be referenced without disclosing anything private -
    for example as the owner of a reported item. Deliberately excludes email,
    status and login timestamps.
    """

    id: uuid.UUID
    role: UserRole


class TokenResponse(ResponseSchema):
    """A token pair.

    ``refresh_token`` is returned once, in the body, over TLS. It is never placed
    in a URL, never logged, and only its hash is stored server-side.
    """

    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - HTTP auth scheme name, not a credential
    expires_in: int = Field(description="Access token lifetime in seconds.")
    refresh_token: str
    refresh_expires_in: int = Field(description="Refresh token lifetime in seconds.")


class AuthSessionResponse(ResponseSchema):
    """Registration and login both return the user and a token pair."""

    user: UserResponse
    tokens: TokenResponse


class LogoutResponse(ResponseSchema):
    sessions_revoked: int = Field(description="How many refresh sessions were ended.")


class PasswordChangeResponse(ApiModel):
    """Password changed.

    Carries ``reauthenticate: true`` because changing a password revokes every
    session including the caller's own. Without that signal a client would sit on
    a dead token until its next request failed, and a user would think they had
    been logged out unexpectedly.
    """

    message: str = "Your password has been changed. Please sign in again."
    reauthenticate: bool = True
    sessions_revoked: int


class VerificationDispatchResponse(ApiModel):
    """Acknowledgement that an email was queued.

    Deliberately carries no token. In development the token is surfaced separately
    through the development-only delivery log; in production only the recipient
    ever receives it.
    """

    message: str
    email: EmailStr = Field(description="Echoed so the client can confirm what was entered.")


class UserListResponse(ApiModel):
    users: list[UserResponse]
