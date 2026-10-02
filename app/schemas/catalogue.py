"""Schemas for the controlled catalogues: trades, skills and counties."""

from __future__ import annotations

from typing import Annotated
import uuid

from pydantic import Field

from app.schemas.common import (
    PaginatedResponseEnvelope,
    RequestSchema,
    ResponseSchema,
    TimestampMixinSchema,
)


class TradeResponse(TimestampMixinSchema):
    """A construction trade."""

    id: uuid.UUID
    code: str
    name: str
    description: str | None = None
    is_active: bool
    display_order: int


class SkillResponse(TimestampMixinSchema):
    """A specific capability."""

    id: uuid.UUID
    code: str
    name: str
    description: str | None = None
    trade_id: uuid.UUID | None = None
    trade_code: str | None = None
    is_active: bool
    display_order: int


class CountyResponse(ResponseSchema):
    """A Kenyan county."""

    id: uuid.UUID
    code: str
    name: str
    region: str | None = None
    capital: str | None = None
    is_active: bool


# --------------------------------------------------------------------------- #
# Administrator write schemas                                                #
# --------------------------------------------------------------------------- #
class TradeCreateRequest(RequestSchema):
    """Administrator trade creation."""

    code: Annotated[
        str,
        Field(
            min_length=2,
            max_length=50,
            pattern=r"^[A-Z][A-Z0-9_]*$",
            description="Stable machine key, upper-case, e.g. MASONRY. Never reused.",
        ),
    ]
    name: Annotated[str, Field(min_length=2, max_length=120)]
    description: Annotated[str, Field(min_length=1, max_length=500)] | None = None
    display_order: Annotated[int, Field(ge=0, le=9999)] = 100


class TradeUpdateRequest(RequestSchema):
    """Partial trade update."""

    code: (
        Annotated[
            str,
            Field(min_length=2, max_length=50, pattern=r"^[A-Z][A-Z0-9_]*$"),
        ]
        | None
    ) = Field(default=None, description="Refused once the trade is referenced.")
    name: Annotated[str, Field(min_length=2, max_length=120)] | None = None
    description: Annotated[str, Field(min_length=1, max_length=500)] | None = None
    display_order: Annotated[int, Field(ge=0, le=9999)] | None = None
    is_active: Annotated[
        bool | None,
        Field(
            default=None,
            description="Deactivate rather than delete, so historical records keep a "
            "resolvable reference.",
        ),
    ]


class SkillCreateRequest(RequestSchema):
    code: Annotated[str, Field(min_length=2, max_length=50, pattern=r"^[A-Z][A-Z0-9_]*$")]
    name: Annotated[str, Field(min_length=2, max_length=120)]
    description: Annotated[str, Field(min_length=1, max_length=500)] | None = None
    trade_code: Annotated[
        str | None,
        Field(max_length=50, description="Optional grouping trade code."),
    ] = None
    display_order: Annotated[int, Field(ge=0, le=9999)] = 100


class SkillUpdateRequest(RequestSchema):
    """Partial skill update. Not a subclass of the create schema, for the same."""

    code: (
        Annotated[str, Field(min_length=2, max_length=50, pattern=r"^[A-Z][A-Z0-9_]*$")] | None
    ) = None
    name: Annotated[str, Field(min_length=2, max_length=120)] | None = None
    description: Annotated[str, Field(min_length=1, max_length=500)] | None = None
    trade_code: Annotated[str | None, Field(max_length=50)] = None
    display_order: Annotated[int, Field(ge=0, le=9999)] | None = None
    is_active: bool | None = None


# --------------------------------------------------------------------------- #
# Convenience responses                                                       #
# --------------------------------------------------------------------------- #
class TradeListResponse(PaginatedResponseEnvelope[TradeResponse]):
    """Paginated trades. Exists so the OpenAPI schema names the collection."""


class SkillListResponse(PaginatedResponseEnvelope[SkillResponse]):
    """Paginated skills."""


class CountyListResponse(PaginatedResponseEnvelope[CountyResponse]):
    """Paginated counties."""


class TradeWithCountResponse(TradeResponse):
    """A trade plus how many workers list it."""

    worker_count: int = 0


class SkillWithCountResponse(SkillResponse):
    """A skill plus its worker count. Same audience rule as the trade variant."""

    worker_count: int = 0
