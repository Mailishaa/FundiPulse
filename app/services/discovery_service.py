"""Worker discovery — employer-facing search.

Two properties drive the design.

**Search is an opt-in surface.** A worker appears only at ``DISCOVERABLE`` or
``PUBLIC`` visibility. The default is ``PRIVATE``, so nothing about anyone reaches
an employer until they choose that. The visibility predicate is applied in SQL,
not after loading, because filtering in Python would mean reading every passport
and then discarding most of them — and a bug in that loop would leak rows the
database never returned.

**The row is a summary, not a profile.** Results carry
:class:`~app.schemas.discovery.WorkerSearchResult`, which has no phone,
contact-email, contact-name or national-id field on it. Discovery therefore cannot
disclose a contact detail even if a query is wrong, which is the same structural
guarantee the public passport view relies on.

Filters are conjunctive, and each is an ``EXISTS`` or a column test, so the plan
stays flat however many are supplied.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any
import uuid

from sqlalchemy import Select, and_, exists, func, or_, select
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql.elements import ColumnElement

from app.core.constants import (
    SEARCHABLE_VISIBILITIES,
    VerificationStatus,
    VerificationTargetType,
)
from app.db.models.catalogue import County, Skill, Trade
from app.db.models.verification import Verification
from app.db.models.worker import (
    Credential,
    Project,
    WorkerPreferredCounty,
    WorkerProfile,
    WorkerSkill,
    WorkerTrade,
    WorkExperience,
)
from app.schemas.discovery import WorkerSearchQuery, WorkerSearchResult
from app.utils.dates import union_months


@dataclass(frozen=True, slots=True)
class DiscoveryPage:
    """One page of results plus the total, for the pagination envelope."""

    results: list[WorkerSearchResult]
    total: int


class WorkerDiscoveryService:
    """Read-only search over passports a worker has chosen to expose."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # -- entry point ------------------------------------------------------- #

    def search(self, query: WorkerSearchQuery) -> DiscoveryPage:
        base = self._base_query(query)

        total = int(
            self._session.execute(select(func.count()).select_from(base.subquery())).scalar_one()
        )
        if total == 0:
            return DiscoveryPage(results=[], total=0)

        rows = (
            self._session.execute(
                base.options(
                    selectinload(WorkerProfile.trades).selectinload(WorkerTrade.trade),
                    selectinload(WorkerProfile.skills).selectinload(WorkerSkill.skill),
                )
                .order_by(*_ordering(query.sort))
                .limit(query.page_size)
                .offset((query.page - 1) * query.page_size)
            )
            .unique()
            .scalars()
            .all()
        )
        return DiscoveryPage(results=[self._to_result(row) for row in rows], total=total)

    def _base_query(self, query: WorkerSearchQuery) -> Select[tuple[WorkerProfile]]:
        statement = select(WorkerProfile).where(
            WorkerProfile.deleted_at.is_(None),
            # The single most important line in this module.
            WorkerProfile.visibility.in_([v.value for v in SEARCHABLE_VISIBILITIES]),
        )
        for condition in self._filters(query):
            statement = statement.where(condition)
        return statement

    # -- filters ----------------------------------------------------------- #

    def _filters(self, query: WorkerSearchQuery) -> list[ColumnElement[bool]]:
        conditions: list[ColumnElement[bool]] = []

        if query.trade_code:
            trade_id = self._id_for(Trade, query.trade_code)
            if trade_id is None:
                return [_impossible()]
            conditions.append(
                exists().where(
                    and_(
                        WorkerTrade.worker_profile_id == WorkerProfile.id,
                        WorkerTrade.trade_id == trade_id,
                    )
                )
            )

        if query.primary_trade_code:
            primary = self._id_for(Trade, query.primary_trade_code)
            if primary is None:
                return [_impossible()]
            conditions.append(WorkerProfile.primary_trade_id == primary)

        if query.skill_code:
            skill_id = self._id_for(Skill, query.skill_code)
            if skill_id is None:
                return [_impossible()]
            conditions.append(
                exists().where(
                    and_(
                        WorkerSkill.worker_profile_id == WorkerProfile.id,
                        WorkerSkill.skill_id == skill_id,
                    )
                )
            )

        # A county matches the worker's own county *or* a preferred work county:
        # an employer hiring in Nakuru wants both groups.
        if query.county_code:
            county_id = self._id_for(County, query.county_code)
            if county_id is None:
                return [_impossible()]
            conditions.append(
                or_(
                    WorkerProfile.county_id == county_id,
                    exists().where(
                        and_(
                            WorkerPreferredCounty.worker_profile_id == WorkerProfile.id,
                            WorkerPreferredCounty.county_id == county_id,
                        )
                    ),
                )
            )

        if query.availability:
            conditions.append(
                and_(
                    WorkerProfile.availability_status == query.availability,
                    WorkerProfile.is_open_to_opportunities.is_(True),
                )
            )

        if query.minimum_experience_years is not None:
            # The declared figure. Deriving years needs a per-row aggregate, which
            # is not a WHERE predicate without a lateral join; both figures are
            # reported in the response so a client can see what it filtered on.
            conditions.append(
                and_(
                    WorkerProfile.self_declared_experience_years.is_not(None),
                    WorkerProfile.self_declared_experience_years >= query.minimum_experience_years,
                )
            )

        for flag, claim_model, target in (
            (query.has_verified_experience, WorkExperience, VerificationTargetType.EXPERIENCE),
            (query.has_verified_project, Project, VerificationTargetType.PROJECT),
        ):
            if flag is None:
                continue
            verified = self._has_verified_claim(claim_model, target)
            conditions.append(verified if flag else ~verified)

        if query.has_credentials is not None:
            has = exists().where(
                and_(
                    Credential.worker_profile_id == WorkerProfile.id,
                    Credential.deleted_at.is_(None),
                )
            )
            conditions.append(has if query.has_credentials else ~has)

        return conditions

    def _has_verified_claim(
        self, claim_model: type[Any], target: VerificationTargetType
    ) -> ColumnElement[bool]:
        """EXISTS a verification for one of this passport's live claims.

        Correlated on the passport, and filtered on the claim's own ``deleted_at``:
        without that, deleting an experience would leave its attestation behind and
        a worker could shed an unverifiable record while keeping the badge.
        """
        return exists().where(
            and_(
                Verification.worker_profile_id == WorkerProfile.id,
                Verification.target_type == target.value,
                Verification.status == VerificationStatus.VERIFIED.value,
                Verification.target_id.in_(
                    select(claim_model.id).where(
                        claim_model.worker_profile_id == WorkerProfile.id,
                        claim_model.deleted_at.is_(None),
                    )
                ),
            )
        )

    # -- resolution -------------------------------------------------------- #

    def _id_for(self, model: type[Any], code: str) -> uuid.UUID | None:
        return self._session.execute(
            select(model.id).where(func.upper(model.code) == code.upper())
        ).scalar_one_or_none()

    # -- projection -------------------------------------------------------- #

    def _to_result(self, profile: WorkerProfile) -> WorkerSearchResult:
        counties = self._counties(profile)
        return WorkerSearchResult(
            id=profile.id,
            display_name=profile.display_name,
            headline=profile.headline,
            visibility=profile.visibility,
            primary_trade=(_trade_ref(profile.primary_trade_id, profile.trades)),
            trades=[link.trade.code for link in profile.trades],
            skills=[
                {
                    "code": link.skill.code,
                    "name": link.skill.name,
                    "proficiency": link.proficiency,
                }
                for link in profile.skills
            ],
            county=(
                counties[profile.county_id]
                if profile.county_id is not None and profile.county_id in counties
                else None
            ),
            preferred_counties=[
                counties[link.county_id]
                for link in profile.preferred_counties
                if link.county_id in counties
            ],
            availability_status=profile.availability_status,
            is_open_to_opportunities=profile.is_open_to_opportunities,
            derived_experience_years=self._derived_experience(profile),
            self_declared_experience_years=profile.self_declared_experience_years,
            verified_experience_count=self._verified_count(
                profile, VerificationTargetType.EXPERIENCE
            ),
            verified_project_count=self._verified_count(profile, VerificationTargetType.PROJECT),
            credential_count=self._credential_count(profile),
        )

    def _counties(self, profile: WorkerProfile) -> dict[uuid.UUID, str]:
        """Resolve every county id on the passport to its code, in one query.

        N+1 avoidance: a page of 20 passports would otherwise issue 20 queries.
        """
        ids = {profile.county_id} | {link.county_id for link in profile.preferred_counties}
        ids.discard(None)
        if not ids:
            return {}
        rows = self._session.execute(select(County.id, County.code).where(County.id.in_(ids))).all()
        resolved: dict[uuid.UUID, str] = {}
        for county_id, code in rows:
            resolved[county_id] = code
        return resolved

    def _derived_experience(self, profile: WorkerProfile) -> Decimal:
        """Years from dated records, overlapping roles merged.

        Overlapping roles are unioned because double-counting concurrent work is
        exactly what an employer is being asked to trust. Merged in Python: doing
        it in SQL needs a window function that is harder to read than the loop.
        """
        rows = self._session.execute(
            select(WorkExperience.start_date, WorkExperience.end_date).where(
                WorkExperience.worker_profile_id == profile.id,
                WorkExperience.deleted_at.is_(None),
            )
        ).all()
        return union_months([(start, end) for start, end in rows])

    def _verified_count(self, profile: WorkerProfile, target: VerificationTargetType) -> int:
        model = WorkExperience if target is VerificationTargetType.EXPERIENCE else Project
        return int(
            self._session.execute(
                select(func.count())
                .select_from(Verification)
                .where(
                    Verification.worker_profile_id == profile.id,
                    Verification.target_type == target.value,
                    Verification.status == VerificationStatus.VERIFIED.value,
                    Verification.target_id.in_(
                        select(model.id).where(
                            model.worker_profile_id == profile.id,
                            model.deleted_at.is_(None),
                        )
                    ),
                )
            ).scalar_one()
        )

    def _credential_count(self, profile: WorkerProfile) -> int:
        return int(
            self._session.execute(
                select(func.count())
                .select_from(Credential)
                .where(
                    Credential.worker_profile_id == profile.id,
                    Credential.deleted_at.is_(None),
                )
            ).scalar_one()
        )


def _ordering(sort: str) -> tuple[Any, ...]:
    """Deterministic ordering, always tie-broken on id.

    ``id`` is in every ordering so two rows with an equal sort key cannot swap
    places between pages, which would make a worker appear on page 1 and page 2.
    """
    return {
        "recently_updated": (WorkerProfile.updated_at.desc(), WorkerProfile.id),
        "created_desc": (WorkerProfile.created_at.desc(), WorkerProfile.id),
        "experience_desc": (
            WorkerProfile.self_declared_experience_years.desc().nullslast(),
            WorkerProfile.id,
        ),
    }[sort]


def _trade_ref(primary_trade_id: uuid.UUID | None, trades: list[WorkerTrade]) -> str | None:
    if primary_trade_id is None:
        return None
    return next((link.trade.code for link in trades if link.trade_id == primary_trade_id), None)


def _impossible() -> ColumnElement[bool]:
    """A condition no row satisfies.

    Used when a filter names something absent from the catalogue. Matching nothing
    is the honest answer: silently dropping the filter would return workers the
    caller did not ask for, which for a location filter is a privacy problem.
    """
    return and_(WorkerProfile.id.is_(None), WorkerProfile.id.is_not(None))
