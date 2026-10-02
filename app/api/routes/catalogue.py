"""Catalogue endpoints: trades, skills, counties."""

from __future__ import annotations

from typing import Annotated
import uuid

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.dependencies import DbSession, RequireAdmin
from app.core.constants import AuditAction
from app.core.exceptions import NotFoundError
from app.db.models.catalogue import Skill, Trade
from app.db.models.user import User
from app.schemas.catalogue import (
    CountyListResponse,
    CountyResponse,
    SkillListResponse,
    SkillResponse,
    SkillUpdateRequest,
    TradeListResponse,
    TradeResponse,
    TradeUpdateRequest,
    TradeWithCountResponse,
)
from app.schemas.common import (
    ErrorResponse,
    Meta,
    PaginatedResponseEnvelope,
    PaginationMeta,
    ResponseEnvelope,
)
from app.services.audit_service import AuditService
from app.services.worker_service import CatalogueService

router = APIRouter(tags=["Catalogue"])
admin_router = APIRouter(prefix="/admin/catalogue", tags=["Catalogue (admin)"])

PageQuery = Annotated[int, Query(ge=1, le=10_000)]
PageSizeQuery = Annotated[int, Query(ge=1, le=100)]


def _page(request_id: str | None, page: int, page_size: int, total: int) -> PaginationMeta:
    return PaginationMeta.build(
        page=page, page_size=page_size, total_items=total, request_id=request_id
    )


@router.get(
    "/trades",
    response_model=TradeListResponse,
    summary="List trades",
    description="Admin-managed construction trades, ordered for a picker.",
)
def list_trades(
    session: DbSession,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> TradeListResponse:
    rows, total = CatalogueService(session).list_trades(
        limit=page_size, offset=(page - 1) * page_size
    )
    return TradeListResponse(
        data=[TradeResponse.model_validate(row) for row in rows],
        meta=_page(None, page, page_size, total),
    )


@router.get(
    "/skills",
    response_model=SkillListResponse,
    summary="List skills",
    description="Admin-managed skills. Narrow with `?trade=MASONRY`.",
)
def list_skills(
    session: DbSession,
    trade: Annotated[str | None, Query(max_length=50)] = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> SkillListResponse:
    rows, total = CatalogueService(session).list_skills(
        trade_code=trade, limit=page_size, offset=(page - 1) * page_size
    )
    return SkillListResponse(
        data=[SkillResponse.model_validate(row) for row in rows],
        meta=_page(None, page, page_size, total),
    )


@router.get(
    "/counties",
    response_model=CountyListResponse,
    summary="List counties",
    description="Controlled list, so location filters match the database rather than "
    "user-entered spelling.",
)
def list_counties(
    session: DbSession,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 47,
) -> CountyListResponse:
    rows, total = CatalogueService(session).list_counties(
        limit=page_size, offset=(page - 1) * page_size
    )
    return CountyListResponse(
        data=[CountyResponse.model_validate(row) for row in rows],
        meta=_page(None, page, page_size, total),
    )


# --------------------------------------------------------------------------- #
# Administrator                                                               #
# --------------------------------------------------------------------------- #
@admin_router.get(
    "/trades",
    response_model=PaginatedResponseEnvelope[TradeWithCountResponse],
    summary="List trades with worker counts",
    description="Counts are a catalogue-quality signal: a trade nobody holds may be miscoded.",
    responses={403: {"model": ErrorResponse, "description": "Administrator role required."}},
)
def admin_list_trades(
    session: DbSession,
    actor: RequireAdmin,  # noqa: ARG001 - the dependency is the permission gate
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> PaginatedResponseEnvelope[TradeWithCountResponse]:
    service = CatalogueService(session)
    rows, total = service.list_trades(
        include_inactive=True, limit=page_size, offset=(page - 1) * page_size
    )
    counts = service.worker_counts_by_trade([row.id for row in rows])
    return PaginatedResponseEnvelope(
        data=[
            TradeWithCountResponse(
                **TradeResponse.model_validate(row).model_dump(),
                worker_count=counts.get(row.id, 0),
            )
            for row in rows
        ],
        meta=_page(None, page, page_size, total),
    )


def _audit_catalogue_update(
    session: DbSession, actor: User, kind: str, row_id: uuid.UUID, fields: list[str]
) -> None:
    AuditService(session).record(
        action=AuditAction.CATALOGUE_ITEM_UPDATED,
        actor_user_id=actor.id,
        actor_role=actor.role,
        resource_type=kind,
        resource_id=row_id,
        outcome="SUCCESS",
        metadata={"operation": f"update_{kind}", "fields": sorted(fields)},
    )


@admin_router.patch(
    "/trades/{trade_id}",
    response_model=ResponseEnvelope[TradeResponse],
    summary="Update a trade",
    description="Deactivate rather than delete, so historical passports and jobs keep a "
    "resolvable reference.",
    responses={
        200: {"description": "Updated."},
        403: {"model": ErrorResponse, "description": "Administrator role required."},
        404: {"model": ErrorResponse, "description": "No such trade."},
    },
)
def admin_update_trade(
    trade_id: uuid.UUID,
    payload: TradeUpdateRequest,
    session: DbSession,
    actor: RequireAdmin,
) -> ResponseEnvelope[TradeResponse]:
    trade = session.execute(select(Trade).where(Trade.id == trade_id)).scalar_one_or_none()
    if not isinstance(trade, Trade):
        raise NotFoundError("The requested trade was not found.")

    data = payload.model_dump(exclude_unset=True)
    for field in ("code", "name", "description", "display_order", "is_active"):
        if field in data:
            setattr(trade, field, data[field])
    session.flush()
    _audit_catalogue_update(session, actor, "trade", trade.id, list(data))

    return ResponseEnvelope(data=TradeResponse.model_validate(trade), meta=Meta(request_id=None))


@admin_router.patch(
    "/skills/{skill_id}",
    response_model=ResponseEnvelope[SkillResponse],
    summary="Update a skill",
    responses={
        200: {"description": "Updated."},
        403: {"model": ErrorResponse, "description": "Administrator role required."},
        404: {"model": ErrorResponse, "description": "No such skill."},
    },
)
def admin_update_skill(
    skill_id: uuid.UUID,
    payload: SkillUpdateRequest,
    session: DbSession,
    actor: RequireAdmin,
) -> ResponseEnvelope[SkillResponse]:
    service = CatalogueService(session)
    skill = session.execute(select(Skill).where(Skill.id == skill_id)).scalar_one_or_none()
    if not isinstance(skill, Skill):
        raise NotFoundError("The requested skill was not found.")

    data = payload.model_dump(exclude_unset=True)
    for field in ("code", "name", "description", "display_order", "is_active"):
        if field in data:
            setattr(skill, field, data[field])
    if "trade_code" in data:
        code = data["trade_code"]
        skill.trade_id = service.get_trade_by_code(code).id if code else None
    session.flush()
    _audit_catalogue_update(session, actor, "skill", skill.id, list(data))

    return ResponseEnvelope(data=SkillResponse.model_validate(skill), meta=Meta(request_id=None))


__all__ = ["admin_router", "router"]
