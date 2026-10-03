"""Model -> schema mapping for worker responses."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from app.core.constants import ContactPreference, ProfileVisibility
from app.db.models.catalogue import County
from app.db.models.worker import Project, WorkerProfile, WorkerSkill, WorkExperience
from app.schemas.experiences import (
    CountyRefInExperience,
    TradeRefInExperience,
    VerificationBadgeResponse,
    WorkExperienceResponse,
)
from app.schemas.projects import ProjectResponse
from app.schemas.workers import (
    CountyRefResponse,
    ExperienceSummaryResponse,
    SkillRefResponse,
    TradeRefResponse,
    WorkerProfilePrivateResponse,
    WorkerProfilePublicResponse,
    WorkerProfileSummaryResponse,
)


def trade_ref(trade: Any, *, is_primary: bool = False) -> TradeRefResponse:
    return TradeRefResponse(id=trade.id, code=trade.code, name=trade.name, is_primary=is_primary)


def skill_ref(worker_skill: WorkerSkill) -> SkillRefResponse:
    return SkillRefResponse(
        id=worker_skill.skill.id,
        code=worker_skill.skill.code,
        name=worker_skill.skill.name,
        proficiency=worker_skill.proficiency,
        years_experience=worker_skill.years_experience,
    )


def county_ref(county: County | None) -> CountyRefResponse | None:
    if county is None:
        return None
    return CountyRefResponse(id=county.id, code=county.code, name=county.name)


def county_refs(counties: list[County]) -> list[CountyRefResponse]:
    return [CountyRefResponse(id=c.id, code=c.code, name=c.name) for c in counties]


def _trade_refs(profile: WorkerProfile) -> list[TradeRefResponse]:
    return [
        trade_ref(wt.trade, is_primary=wt.is_primary)
        for wt in sorted(profile.trades, key=lambda wt: not wt.is_primary)
    ]


def _primary(refs: list[TradeRefResponse]) -> TradeRefResponse | None:
    return next((ref for ref in refs if ref.is_primary), None)


def to_public_profile(
    profile: WorkerProfile,
    *,
    county: County | None = None,
    preferred: list[County] | None = None,
) -> WorkerProfilePublicResponse:
    """Professional information only."""
    trades = _trade_refs(profile)
    return WorkerProfilePublicResponse(
        id=profile.id,
        display_name=profile.display_name,
        headline=profile.headline,
        bio=profile.bio,
        visibility=profile.visibility,
        primary_trade=_primary(trades),
        trades=trades,
        skills=[skill_ref(ws) for ws in profile.skills],
        county=county_ref(county),
        location=profile.location,
        preferred_counties=county_refs(preferred or []),
        availability_status=profile.availability_status,
        available_from=profile.available_from,
        is_open_to_opportunities=profile.is_open_to_opportunities,
        self_declared_experience_years=profile.self_declared_experience_years,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


def to_private_profile(
    profile: WorkerProfile,
    *,
    county: County | None = None,
    preferred: list[County] | None = None,
) -> WorkerProfilePrivateResponse:
    """Owner-only view: adds the contact block and whether contact is permitted."""
    return WorkerProfilePrivateResponse(
        **to_public_profile(profile, county=county, preferred=preferred).model_dump(),
        user_id=profile.user_id,
        contact_preference=profile.contact_preference,
        is_contactable=(
            profile.visibility != ProfileVisibility.PRIVATE.value
            and profile.contact_preference != ContactPreference.NONE.value
        ),
        phone_number=profile.phone_number,
        contact_email=profile.contact_email,
        contact_name=profile.contact_name,
        contact_phone=profile.contact_phone,
    )


def to_summary(
    profile: WorkerProfile,
    *,
    county: County | None = None,
    experience: dict[str, Any] | None = None,
    verified: dict[str, int] | None = None,
) -> WorkerProfileSummaryResponse:
    """Search-result row. Factual signals only, no quality score (ADR 0010)."""
    summary = None
    if experience is not None:
        summary = ExperienceSummaryResponse(
            derived_years=experience.get("total_years", Decimal("0.0")),
            experience_record_count=int(experience.get("record_count", 0)),
            self_declared_years=experience.get("self_declared_years"),
            current_position_count=int(experience.get("current_record_count", 0)),
        )
    trades = _trade_refs(profile)
    return WorkerProfileSummaryResponse(
        id=profile.id,
        display_name=profile.display_name,
        headline=profile.headline,
        primary_trade=_primary(trades),
        trades=trades,
        skill_count=len(profile.skills),
        county=county_ref(county),
        availability_status=profile.availability_status,
        is_open_to_opportunities=profile.is_open_to_opportunities,
        experience_summary=summary,
        verified_experience_count=int((verified or {}).get("experiences", 0)),
        verified_project_count=int((verified or {}).get("projects", 0)),
        credential_count=int((verified or {}).get("credentials", 0)),
    )


def to_experience_response(
    record: WorkExperience,
    *,
    county: County | None = None,
    verification: Any | None = None,
) -> WorkExperienceResponse:
    """Verification is supplied by that domain, never derived here."""
    return WorkExperienceResponse(
        id=record.id,
        employer_name=record.employer_name,
        project_name=record.project_name,
        role_title=record.role_title,
        description=record.description,
        trade=(
            TradeRefInExperience(code=record.trade.code, name=record.trade.name)
            if record.trade is not None
            else None
        ),
        county=(
            CountyRefInExperience(code=county.code, name=county.name)
            if county is not None
            else None
        ),
        location=record.location,
        start_date=record.start_date,
        end_date=record.end_date,
        is_current=record.is_current,
        verification=_badge(verification),
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def to_project_response(
    project: Project,
    *,
    county: County | None = None,
    verification: Any | None = None,
    evidence_count: int = 0,
) -> ProjectResponse:
    return ProjectResponse(
        id=project.id,
        name=project.name,
        role_title=project.role_title,
        project_type=project.project_type,
        description=project.description,
        work_performed=project.work_performed,
        trade_code=project.trade.code if project.trade is not None else None,
        trade_name=project.trade.name if project.trade is not None else None,
        county_code=county.code if county is not None else None,
        county_name=county.name if county is not None else None,
        location=project.location,
        start_date=project.start_date,
        end_date=project.end_date,
        is_confidential=project.is_confidential,
        verification=_badge(verification),
        evidence_count=evidence_count,
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


def _badge(verification: Any | None) -> VerificationBadgeResponse | None:
    if verification is None:
        return None
    return VerificationBadgeResponse.model_validate(verification)
