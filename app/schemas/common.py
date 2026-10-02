"""Shared API conventions: response envelope, pagination, and base schemas.

Every endpoint in this API answers in one of exactly two shapes.

**Single resource**

```json
{
  "data": { "id": "...", "...": "..." },
  "meta": { "request_id": "..." }
}
```

**Collection**

```json
{
  "data": [ ... ],
  "meta": {
    "request_id": "...",
    "pagination": { "page": 1, "page_size": 20, "total_items": 137, "total_pages": 7, "has_next": true, "has_previous": false }
  }
}
```

**Error**

```json
{ "error": { "code": "RESOURCE_NOT_FOUND", "message": "...", "request_id": "...", "details": [] } }
```

One convention, everywhere. A client only has to learn it once, and a new
endpoint cannot accidentally invent a different one because the response type is
declared, not hand-built per route.
"""

from __future__ import annotations

from datetime import UTC, datetime
import math
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from app.core.constants import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_NUMBER,
    MAX_PAGE_SIZE,
    MIN_PAGE_SIZE,
)


class ApiModel(BaseModel):
    """Base for every schema in the API.

    ``extra="forbid"`` is the single most important setting here: it rejects
    unknown request fields instead of ignoring them. That is what stops mass
    assignment (a client sending ``"role": "ADMIN"``), and it makes a client-side
    typo a loud 422 rather than a silently ignored field.
    """

    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,
        str_strip_whitespace=False,
        populate_by_name=True,
        # `use_enum_values` is deliberately NOT enabled. It converts enum members
        # to plain strings at validation time, which strips `.value` before the
        # service layer can use them. Pydantic serialises a StrEnum to its string
        # value in JSON anyway, so the flag buys nothing and costs correctness.
    )


class RequestSchema(ApiModel):
    """Base for request bodies. Forbids unknown fields."""


class ResponseSchema(ApiModel):
    """Base for response bodies. Serialises from ORM objects."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore",
        populate_by_name=True,
    )


class Meta(BaseModel):
    """Metadata attached to every successful response."""

    model_config = ConfigDict(extra="forbid")

    request_id: str | None = Field(
        default=None,
        description="Correlation id. Quote this in a support request.",
    )


class PaginationMeta(Meta):
    """Pagination metadata for collection responses."""

    page: int = Field(ge=1)
    page_size: int = Field(ge=MIN_PAGE_SIZE, le=MAX_PAGE_SIZE)
    total_items: int = Field(ge=0)
    total_pages: int = Field(ge=0)
    has_next: bool
    has_previous: bool

    @classmethod
    def build(
        cls, *, page: int, page_size: int, total_items: int, request_id: str | None
    ) -> PaginationMeta:
        total_pages = math.ceil(total_items / page_size) if page_size else 0
        return cls(
            request_id=request_id,
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_previous=page > 1,
        )


class ResponseEnvelope[T](ApiModel):
    """A single resource plus metadata."""

    data: T
    meta: Meta = Field(default_factory=Meta)


class PaginatedResponseEnvelope[T](ApiModel):
    """A page of resources plus pagination metadata."""

    data: list[T]
    meta: PaginationMeta


class ErrorBody(BaseModel):
    """The error payload. Mirrors :class:`app.core.exceptions.AppError`."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(description="Stable, machine-readable error identifier.")
    message: str = Field(description="Human-readable, safe to display to a user.")
    request_id: str | None = None
    details: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Field-level problems, when the failure is validation-related.",
    )


class ErrorResponse(ApiModel):
    """The complete error envelope. Declared on routes for OpenAPI accuracy."""

    error: ErrorBody


class PageParams(ApiModel):
    """Validated ``?page`` / ``?page_size`` query parameters.

    Declared as a model rather than two bare ``Query`` parameters so the bounds
    live in one place and are enforced by the same validation as everything else.
    """

    page: Annotated[int, Field(ge=1, le=MAX_PAGE_NUMBER)] = 1
    page_size: Annotated[int, Field(ge=MIN_PAGE_SIZE, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        return self.page_size


class HealthStatus(BaseModel):
    """A health check component result. Deliberately terse.

    No versions, no hostnames, no exception text: a probe endpoint is reachable
    by anyone who can reach the service and must not become an information
    disclosure.
    """

    status: str = Field(description="ok | degraded | down")
    latency_ms: float | None = None


class MessageResponse(ApiModel):
    """A simple acknowledgement where no resource is returned.

    Used by deletes and by state transitions that produce nothing to show.
    """

    message: str
    meta: Meta = Field(default_factory=Meta)


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with a ``Z`` suffix.

    Used for ``created_at`` style passthrough values so every timestamp in every
    response has the same textual shape, which matters for a mobile client
    parsing timestamps on a low-end device.
    """
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def serialise_datetime(value: datetime | None) -> str | None:
    """Serialise a datetime to a consistent UTC ISO-8601 string."""
    if value is None:
        return None
    if value.tzinfo is None:
        # Should be impossible: the DB columns are TIMESTAMPTZ and the DTZ lint
        # rule forbids naive datetimes. Handled defensively rather than trusting.
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class TimestampMixinSchema(ResponseSchema):
    """Adds serialised ``created_at`` / ``updated_at`` to a response schema."""

    created_at: datetime
    updated_at: datetime

    @field_serializer("created_at", "updated_at")
    def _serialise_timestamps(self, value: datetime) -> str:
        return serialise_datetime(value) or ""
