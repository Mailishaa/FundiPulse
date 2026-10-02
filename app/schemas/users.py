"""Schemas for the administrator user surface."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.core.constants import AccountStatus, UserRole
from app.schemas.auth import UserResponse
from app.schemas.common import RequestSchema


class UserDetailResponse(UserResponse):
    """The account as its owner or an administrator sees it.

    Identical to :class:`~app.schemas.auth.UserResponse` today; kept separate so
    the two audiences can diverge without breaking either. Notably it contains
    ``email`` - which is fine for self and administrators, and is exactly why
    :class:`~app.schemas.auth.PublicUserResponse` exists for other audiences.
    """

    deactivated_at: datetime | None = None
    deleted_at: datetime | None = None


class ChangeRoleRequest(RequestSchema):
    """Administrator role change.

    ``role`` is the only field. Because the schema forbids extras, a client
    cannot smuggle additional changes alongside it.
    """

    role: UserRole = Field(description="The new platform-wide role. Recorded in the audit log.")


class SetAccountStatusRequest(RequestSchema):
    status: AccountStatus = Field(description="The new account status.")
    reason: str = Field(
        min_length=5,
        max_length=512,
        description="Mandatory. Stored in the audit log with the change.",
    )
