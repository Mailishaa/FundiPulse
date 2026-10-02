"""Work Passport service."""

from __future__ import annotations

from typing import Any
import uuid

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql.elements import ColumnElement

from app.core.constants import AuditAction, AvailabilityStatus, ProfileVisibility, UserRole
from app.core.exceptions import (
    ConflictError,
    ForbiddenError,
    InvalidStateTransitionError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models.catalogue import County, Skill, Trade
from app.db.models.user import User
from app.db.models.worker import (
    Project,
    WorkerPreferredCounty,
    WorkerProfile,
    WorkerSkill,
    WorkerTrade,
    WorkExperience,
)
from app.schemas.experiences import WorkExperienceCreateRequest, WorkExperienceUpdateRequest
from app.schemas.projects import ProjectCreateRequest, ProjectUpdateRequest
from app.schemas.workers import (
    PreferredCountiesUpdateRequest,
    WorkerProfileCreateRequest,
    WorkerProfileUpdateRequest,
    WorkerSkillsUpdateRequest,
    WorkerTradesUpdateRequest,
)
from app.services.audit_service import AuditService
from app.utils.dates import date_range_is_sane, union_months, utc_today

logger = get_logger(__name__)


class WorkerProfileNotFoundError(NotFoundError):
    public_message = "No Work Passport was found."


class PassportAlreadyExistsError(ConflictError):
    public_message = "This account already has a Work Passport."


class CatalogueEntryNotFoundError(ValidationError):
    public_message = "One of the referenced catalogue entries does not exist."


class NotPassportOwnerError(ForbiddenError):
    public_message = "You can only modify your own Work Passport."


class CatalogueService:
    """Public reference data: trades, skills, counties."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_trades(
        self, *, include_inactive: bool = False, limit: int = 20, offset: int = 0
    ) -> tuple[list[Trade], int]:
        conditions: list[ColumnElement[bool]] = []
        if not include_inactive:
            conditions.append(Trade.is_active.is_(True))
        total = self._count(Trade, conditions)
        statement = (
            select(Trade)
            .where(*conditions)
            # id last so paging cannot skip or repeat a row.
            .order_by(Trade.display_order, Trade.name, Trade.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    def get_trade_by_code(self, code: str, *, require_active: bool = True) -> Trade:
        trade = self._session.execute(
            self._by_code(Trade, code, Trade.code, require_active)
        ).scalar_one_or_none()
        if not isinstance(trade, Trade):
            raise CatalogueEntryNotFoundError(f"Unknown trade code: {code}")
        return trade

    def get_trades_by_codes(
        self, codes: list[str], *, require_active: bool = True
    ) -> dict[str, Trade]:
        if not codes:
            return {}
        statement = self._by_codes(Trade, codes, Trade.code, require_active)
        return {row.code: row for row in self._session.execute(statement).scalars()}

    def worker_counts_by_trade(self, trade_ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
        return self._worker_counts(WorkerTrade.trade_id, trade_ids, WorkerTrade)

    def list_skills(
        self,
        *,
        trade_code: str | None = None,
        include_inactive: bool = False,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[Skill], int]:
        conditions: list[ColumnElement[bool]] = []
        if not include_inactive:
            conditions.append(Skill.is_active.is_(True))
        if trade_code:
            conditions.append(Skill.trade_id == self.get_trade_by_code(trade_code).id)
        total = self._count(Skill, conditions)
        statement = (
            select(Skill)
            .where(*conditions)
            .order_by(Skill.display_order, Skill.name, Skill.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    def get_skills_by_codes(
        self, codes: list[str], *, require_active: bool = True
    ) -> dict[str, Skill]:
        if not codes:
            return {}
        statement = self._by_codes(Skill, codes, Skill.code, require_active)
        return {row.code: row for row in self._session.execute(statement).scalars()}

    def worker_counts_by_skill(self, skill_ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
        return self._worker_counts(WorkerSkill.skill_id, skill_ids, WorkerSkill)

    def list_counties(
        self, *, include_inactive: bool = False, limit: int = 20, offset: int = 0
    ) -> tuple[list[County], int]:
        conditions: list[ColumnElement[bool]] = []
        if not include_inactive:
            conditions.append(County.is_active.is_(True))
        total = self._count(County, conditions)
        statement = (
            select(County)
            .where(*conditions)
            .order_by(County.name, County.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    def get_counties_by_codes(
        self, codes: list[str], *, require_active: bool = True
    ) -> dict[str, County]:
        if not codes:
            return {}
        statement = self._by_codes(County, codes, County.code, require_active)
        return {row.code: row for row in self._session.execute(statement).scalars()}

    def _count(self, model: Any, conditions: list[ColumnElement[bool]]) -> int:
        return int(
            self._session.execute(
                select(func.count()).select_from(model).where(*conditions)
            ).scalar_one()
        )

    def _by_code(self, model: Any, code: str, column: Any, active: bool) -> Any:
        statement = select(model).where(func.upper(column) == code.upper())
        if active:
            statement = statement.where(model.is_active.is_(True))
        return statement

    def _by_codes(self, model: Any, codes: list[str], column: Any, active: bool) -> Any:
        statement = select(model).where(func.upper(column).in_([c.upper() for c in codes]))
        if active:
            statement = statement.where(model.is_active.is_(True))
        return statement

    def _worker_counts(
        self, column: Any, ids: list[uuid.UUID], association: Any
    ) -> dict[uuid.UUID, int]:
        if not ids:
            return {}
        statement = (
            select(column, func.count(func.distinct(association.worker_profile_id)))
            .join(WorkerProfile, WorkerProfile.id == association.worker_profile_id)
            .where(column.in_(ids), WorkerProfile.deleted_at.is_(None))
            .group_by(column)
        )
        return {row[0]: int(row[1]) for row in self._session.execute(statement)}


class WorkerProfileService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._audit = AuditService(session)
        self._catalogue = CatalogueService(session)

    # -- loading --------------------------------------------------------- #

    def get_for_user(self, user: User, *, include_deleted: bool = False) -> WorkerProfile:
        conditions = [WorkerProfile.user_id == user.id]
        if not include_deleted:
            conditions.append(WorkerProfile.deleted_at.is_(None))
        profile = self._session.execute(
            select(WorkerProfile)
            .where(*conditions)
            .options(
                selectinload(WorkerProfile.trades).selectinload(WorkerTrade.trade),
                selectinload(WorkerProfile.skills).selectinload(WorkerSkill.skill),
            )
        ).scalar_one_or_none()
        if profile is None:
            raise WorkerProfileNotFoundError()
        return profile

    def get_by_id(self, profile_id: uuid.UUID, *, include_deleted: bool = False) -> WorkerProfile:
        conditions = [WorkerProfile.id == profile_id]
        if not include_deleted:
            conditions.append(WorkerProfile.deleted_at.is_(None))
        profile = self._session.execute(
            select(WorkerProfile).where(*conditions)
        ).scalar_one_or_none()
        if profile is None:
            raise WorkerProfileNotFoundError()
        return profile

    def get_for_update(self, profile_id: uuid.UUID) -> WorkerProfile:
        """Row-locked, so concurrent edits cannot both pass a uniqueness check."""
        profile = self._session.execute(
            select(WorkerProfile)
            .where(WorkerProfile.id == profile_id, WorkerProfile.deleted_at.is_(None))
            .with_for_update()
        ).scalar_one_or_none()
        if profile is None:
            raise WorkerProfileNotFoundError()
        return profile

    def load_counties(self, profile: WorkerProfile) -> tuple[County | None, list[County]]:
        """Resolve the passport's county and preferred counties in two queries."""
        primary = (
            self._session.execute(
                select(County).where(County.id == profile.county_id)
            ).scalar_one_or_none()
            if profile.county_id
            else None
        )
        ids = (
            self._session.execute(
                select(WorkerPreferredCounty.county_id).where(
                    WorkerPreferredCounty.worker_profile_id == profile.id
                )
            )
            .scalars()
            .all()
        )
        preferred = (
            list(self._session.execute(select(County).where(County.id.in_(ids))).scalars())
            if ids
            else []
        )
        return primary, preferred

    # -- authorisation --------------------------------------------------- #

    def assert_owner_or_admin(self, *, actor: User, profile: WorkerProfile) -> None:
        if actor.role == UserRole.ADMIN.value or profile.user_id == actor.id:
            return
        raise NotPassportOwnerError()

    def assert_visible_to(self, *, viewer: User | None, profile: WorkerProfile) -> WorkerProfile:
        """``viewer=None`` means anonymous.

        A private passport reports 404 rather than 403, so a non-owner cannot use a
        read to discover which passport ids exist.
        """
        if viewer is not None and (
            profile.user_id == viewer.id or viewer.role == UserRole.ADMIN.value
        ):
            return profile
        if profile.visibility == ProfileVisibility.PRIVATE.value:
            raise WorkerProfileNotFoundError()
        return profile

    # -- create and update ----------------------------------------------- #

    def create(self, *, actor: User, payload: WorkerProfileCreateRequest) -> WorkerProfile:
        if actor.role == UserRole.ADMIN.value:
            raise ForbiddenError(
                "Administrator accounts do not have a Work Passport.",
                code="ADMIN_HAS_NO_PASSPORT",
            )
        if (
            self._session.execute(
                select(WorkerProfile.id).where(WorkerProfile.user_id == actor.id)
            ).scalar_one_or_none()
            is not None
        ):
            raise PassportAlreadyExistsError()

        county = self._one_county(payload.county_code)
        trades = self._catalogue.get_trades_by_codes(payload.trade_codes)
        self._require_all(trades, payload.trade_codes, "trade")

        # Resolved separately from the trade list: a client may name a primary
        # trade without listing it. Looking it up only in `trades` would silently
        # drop an unknown code instead of rejecting it, and the worker would
        # believe their primary trade was recorded.
        primary: Trade | None = None
        if payload.primary_trade_code:
            primary = self._catalogue.get_trade_by_code(payload.primary_trade_code)

        profile = WorkerProfile(
            user_id=actor.id,
            display_name=payload.display_name.strip(),
            bio=payload.bio,
            headline=payload.headline,
            primary_trade_id=primary.id if primary else None,
            county_id=county.id if county else None,
            location=payload.location,
            self_declared_experience_years=payload.self_declared_experience_years,
            availability_status=payload.availability_status.value,
            available_from=payload.available_from,
            visibility=payload.visibility.value,
            contact_preference=payload.contact_preference.value,
            phone_number=payload.phone_number,
            contact_email=payload.contact_email,
            contact_name=payload.contact_name,
            contact_phone=payload.contact_phone,
        )
        self._session.add(profile)
        self._session.flush()

        for code in payload.trade_codes:
            trade = trades.get(code.upper())
            if trade is not None:
                self._session.add(
                    WorkerTrade(
                        worker_profile_id=profile.id,
                        trade_id=trade.id,
                        is_primary=bool(primary and trade.id == primary.id),
                    )
                )
        for county_row in self._counties(payload.preferred_county_codes):
            self._session.add(
                WorkerPreferredCounty(worker_profile_id=profile.id, county_id=county_row.id)
            )
        self._session.flush()
        self._audit.record(
            action=AuditAction.ADMIN_ACTION,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="worker_profile",
            resource_id=profile.id,
            outcome="SUCCESS",
            metadata={"operation": "create_worker_profile"},
        )
        logger.info("Work Passport created", extra={"worker_profile_id": str(profile.id)})
        return self.get_for_user(actor)

    def update(
        self, *, actor: User, profile_id: uuid.UUID, payload: WorkerProfileUpdateRequest
    ) -> WorkerProfile:
        profile = self.get_by_id(profile_id)
        self.assert_owner_or_admin(actor=actor, profile=profile)
        data = payload.model_dump(exclude_unset=True)

        if "county_code" in data:
            county = self._one_county(data.pop("county_code"))
            profile.county_id = county.id if county else None
        if "primary_trade_code" in data:
            code = data.pop("primary_trade_code")
            profile.primary_trade_id = self._catalogue.get_trade_by_code(code).id if code else None

        for field in (
            "display_name",
            "bio",
            "headline",
            "location",
            "self_declared_experience_years",
            "phone_number",
            "contact_email",
            "contact_name",
            "contact_phone",
            "is_open_to_opportunities",
        ):
            if field in data:
                value = data[field]
                setattr(profile, field, value.strip() if isinstance(value, str) else value)

        for field in ("availability_status", "visibility", "contact_preference"):
            if field in data:
                value = data[field]
                setattr(profile, field, value.value if hasattr(value, "value") else str(value))
        if "available_from" in data:
            profile.available_from = data["available_from"]

        self._enforce_availability(profile)
        self._session.flush()
        return self._reload(profile, actor)

    # -- trades, skills, counties ---------------------------------------- #

    def replace_trades(
        self, *, actor: User, profile_id: uuid.UUID, payload: WorkerTradesUpdateRequest
    ) -> WorkerProfile:
        """Replaces the list wholesale so "one primary trade" is atomic; the."""
        profile = self.get_for_update(profile_id)
        self.assert_owner_or_admin(actor=actor, profile=profile)
        resolved = self._catalogue.get_trades_by_codes([t.trade_code for t in payload.trades])
        self._require_all(resolved, [t.trade_code for t in payload.trades], "trade")

        self._session.execute(
            delete(WorkerTrade).where(WorkerTrade.worker_profile_id == profile.id)
        )
        self._session.flush()

        primary_id: uuid.UUID | None = None
        for assignment in payload.trades:
            trade = resolved[assignment.trade_code.upper()]
            if assignment.is_primary and primary_id is None:
                primary_id = trade.id
            self._session.add(
                WorkerTrade(
                    worker_profile_id=profile.id,
                    trade_id=trade.id,
                    is_primary=trade.id == primary_id,
                    years_experience=assignment.years_experience,
                )
            )
        try:
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise ConflictError(
                "Only one trade can be the primary trade.", code="MULTIPLE_PRIMARY_TRADES"
            ) from exc

        profile.primary_trade_id = primary_id
        self._session.expire(profile, ["trades"])
        self._session.flush()
        return self._reload(profile, actor)

    def replace_skills(
        self, *, actor: User, profile_id: uuid.UUID, payload: WorkerSkillsUpdateRequest
    ) -> WorkerProfile:
        profile = self.get_for_update(profile_id)
        self.assert_owner_or_admin(actor=actor, profile=profile)
        resolved = self._catalogue.get_skills_by_codes([s.skill_code for s in payload.skills])
        self._require_all(resolved, [s.skill_code for s in payload.skills], "skill")

        self._session.execute(
            delete(WorkerSkill).where(WorkerSkill.worker_profile_id == profile.id)
        )
        self._session.flush()

        for assignment in payload.skills:
            skill = resolved[assignment.skill_code.upper()]
            proficiency = assignment.proficiency
            self._session.add(
                WorkerSkill(
                    worker_profile_id=profile.id,
                    skill_id=skill.id,
                    proficiency=proficiency.value
                    if hasattr(proficiency, "value")
                    else str(proficiency),
                    years_experience=assignment.years_experience,
                )
            )
        self._session.expire(profile, ["skills"])
        self._session.flush()
        return self._reload(profile, actor)

    def replace_preferred_counties(
        self, *, actor: User, profile_id: uuid.UUID, payload: PreferredCountiesUpdateRequest
    ) -> WorkerProfile:
        profile = self.get_for_update(profile_id)
        self.assert_owner_or_admin(actor=actor, profile=profile)
        resolved = self._catalogue.get_counties_by_codes(payload.county_codes)
        self._require_all(resolved, payload.county_codes, "county")

        self._session.execute(
            delete(WorkerPreferredCounty).where(
                WorkerPreferredCounty.worker_profile_id == profile.id
            )
        )
        self._session.flush()

        for code in payload.county_codes:
            self._session.add(
                WorkerPreferredCounty(
                    worker_profile_id=profile.id, county_id=resolved[code.upper()].id
                )
            )
        self._session.flush()
        return self._reload(profile, actor)

    # -- work experience -------------------------------------------------- #

    def create_experience(
        self, *, actor: User, profile_id: uuid.UUID, payload: WorkExperienceCreateRequest
    ) -> WorkExperience:
        """Records a claim. No parameter here can set a verification state."""
        profile = self.get_by_id(profile_id)
        self.assert_owner_or_admin(actor=actor, profile=profile)
        trade = (
            self._catalogue.get_trade_by_code(payload.trade_code) if payload.trade_code else None
        )
        county = self._one_county(payload.county_code)

        record = WorkExperience(
            worker_profile_id=profile.id,
            employer_name=payload.employer_name.strip(),
            project_name=payload.project_name,
            role_title=payload.role_title.strip(),
            trade_id=trade.id if trade else None,
            description=payload.description,
            start_date=payload.start_date,
            end_date=payload.end_date,
            is_current=payload.is_current,
            location=payload.location,
            county_id=county.id if county else None,
        )
        self._session.add(record)
        self._session.flush()
        self._audit.record(
            action=AuditAction.ADMIN_ACTION,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="work_experience",
            resource_id=record.id,
            outcome="SUCCESS",
            metadata={"operation": "create_work_experience"},
        )
        return record

    def list_experiences(
        self, *, profile: WorkerProfile, limit: int = 20, offset: int = 0
    ) -> tuple[list[WorkExperience], int]:
        base = WorkExperience.worker_profile_id == profile.id
        live = WorkExperience.deleted_at.is_(None)
        total = int(
            self._session.execute(
                select(func.count()).select_from(WorkExperience).where(base, live)
            ).scalar_one()
        )
        statement = (
            select(WorkExperience)
            .where(base, live)
            .options(selectinload(WorkExperience.trade))
            .order_by(
                WorkExperience.is_current.desc(),
                WorkExperience.start_date.desc(),
                WorkExperience.id,
            )
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    def get_experience(self, *, profile: WorkerProfile, experience_id: uuid.UUID) -> WorkExperience:
        """Scoped by passport as well as id, so another worker's record simply."""
        record = self._session.execute(
            select(WorkExperience).where(
                WorkExperience.id == experience_id,
                WorkExperience.worker_profile_id == profile.id,
                WorkExperience.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if record is None:
            raise NotFoundError("The requested work experience was not found.")
        return record

    def update_experience(
        self,
        *,
        actor: User,
        profile_id: uuid.UUID,
        experience_id: uuid.UUID,
        payload: WorkExperienceUpdateRequest,
    ) -> WorkExperience:
        """Revalidates the stored range, since a partial patch can produce an."""
        profile = self.get_by_id(profile_id)
        self.assert_owner_or_admin(actor=actor, profile=profile)
        record = self.get_experience(profile=profile, experience_id=experience_id)
        data = payload.model_dump(exclude_unset=True)

        if "trade_code" in data:
            code = data.pop("trade_code")
            record.trade_id = self._catalogue.get_trade_by_code(code).id if code else None
        if "county_code" in data:
            code = data.pop("county_code")
            county = self._one_county(code)
            record.county_id = county.id if county else None

        for field in ("employer_name", "role_title", "project_name", "description", "location"):
            if field in data:
                value = data[field]
                setattr(record, field, value.strip() if isinstance(value, str) else value)
        for field in ("start_date", "end_date", "is_current"):
            if field in data:
                setattr(record, field, data[field])

        if not date_range_is_sane(record.start_date, record.end_date):
            raise ValidationError(
                "The resulting dates are not valid: end_date must not precede "
                "start_date, and neither may be in the future."
            )
        if record.end_date is not None and record.is_current:
            raise InvalidStateTransitionError(
                "A record with an end_date cannot be marked as current."
            )
        if record.end_date is None and not record.is_current:
            raise ValidationError("Provide an end_date, or mark the role as current.")

        self._session.flush()
        return record

    def delete_experience(
        self, *, actor: User, profile_id: uuid.UUID, experience_id: uuid.UUID
    ) -> None:
        """Soft delete: a verification may already reference this record, and a."""
        profile = self.get_by_id(profile_id)
        self.assert_owner_or_admin(actor=actor, profile=profile)
        record = self.get_experience(profile=profile, experience_id=experience_id)
        record.deleted_at = utcnow()
        self._session.flush()
        self._audit.record(
            action=AuditAction.ADMIN_ACTION,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="work_experience",
            resource_id=record.id,
            outcome="SUCCESS",
            metadata={"operation": "delete_work_experience"},
        )

    def derive_experience_summary(self, profile: WorkerProfile) -> dict[str, Any]:
        """Computed from dated records; the self-declared figure is returned."""
        records = (
            self._session.execute(
                select(WorkExperience).where(
                    WorkExperience.worker_profile_id == profile.id,
                    WorkExperience.deleted_at.is_(None),
                )
            )
            .scalars()
            .all()
        )
        return {
            "total_years": union_months([(r.start_date, r.end_date) for r in records]),
            "completed_years": union_months(
                [(r.start_date, r.end_date) for r in records if not r.is_current]
            ),
            "current_years": union_months([(r.start_date, None) for r in records if r.is_current]),
            "record_count": len(records),
            "current_record_count": sum(1 for r in records if r.is_current),
            "earliest_start": min((r.start_date for r in records), default=None),
            "latest_end": max(
                (r.end_date for r in records if r.end_date is not None), default=None
            ),
        }

    # -- projects --------------------------------------------------------- #

    def create_project(
        self, *, actor: User, profile_id: uuid.UUID, payload: ProjectCreateRequest
    ) -> Project:
        profile = self.get_by_id(profile_id)
        self.assert_owner_or_admin(actor=actor, profile=profile)
        trade = (
            self._catalogue.get_trade_by_code(payload.trade_code) if payload.trade_code else None
        )
        county = self._one_county(payload.county_code)

        project = Project(
            worker_profile_id=profile.id,
            name=payload.name.strip(),
            project_type=payload.project_type,
            role_title=payload.role_title.strip(),
            description=payload.description,
            work_performed=payload.work_performed,
            trade_id=trade.id if trade else None,
            county_id=county.id if county else None,
            location=payload.location,
            start_date=payload.start_date,
            end_date=payload.end_date,
            is_confidential=payload.is_confidential,
        )
        self._session.add(project)
        self._session.flush()
        self._audit.record(
            action=AuditAction.ADMIN_ACTION,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="project",
            resource_id=project.id,
            outcome="SUCCESS",
            metadata={"operation": "create_project"},
        )
        return project

    def list_projects(
        self,
        *,
        profile: WorkerProfile,
        limit: int = 20,
        offset: int = 0,
        include_confidential: bool = False,
    ) -> tuple[list[Project], int]:
        """``include_confidential`` is False by default so a project the worker."""
        conditions: list[ColumnElement[bool]] = [
            Project.worker_profile_id == profile.id,
            Project.deleted_at.is_(None),
        ]
        if not include_confidential:
            conditions.append(Project.is_confidential.is_(False))

        total = int(
            self._session.execute(
                select(func.count()).select_from(Project).where(*conditions)
            ).scalar_one()
        )
        statement = (
            select(Project)
            .where(*conditions)
            .options(selectinload(Project.trade))
            .order_by(Project.start_date.desc().nulls_last(), Project.created_at.desc(), Project.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    def get_project(self, *, profile: WorkerProfile, project_id: uuid.UUID) -> Project:
        project = self._session.execute(
            select(Project).where(
                Project.id == project_id,
                Project.worker_profile_id == profile.id,
                Project.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if project is None:
            raise NotFoundError("The requested project was not found.")
        return project

    def update_project(
        self,
        *,
        actor: User,
        profile_id: uuid.UUID,
        project_id: uuid.UUID,
        payload: ProjectUpdateRequest,
    ) -> Project:
        profile = self.get_by_id(profile_id)
        self.assert_owner_or_admin(actor=actor, profile=profile)
        project = self.get_project(profile=profile, project_id=project_id)
        data = payload.model_dump(exclude_unset=True)

        if "trade_code" in data:
            code = data.pop("trade_code")
            project.trade_id = self._catalogue.get_trade_by_code(code).id if code else None
        if "county_code" in data:
            code = data.pop("county_code")
            county = self._one_county(code)
            project.county_id = county.id if county else None

        for field in ("name", "role_title", "description", "work_performed", "location"):
            if field in data:
                value = data[field]
                setattr(project, field, value.strip() if isinstance(value, str) else value)
        for field in ("project_type", "start_date", "end_date", "is_confidential"):
            if field in data:
                setattr(project, field, data[field])

        if project.start_date and project.end_date and project.end_date < project.start_date:
            raise ValidationError("end_date cannot be earlier than start_date.")
        if project.end_date and project.end_date > utc_today():
            raise ValidationError("end_date cannot be in the future.")
        if project.start_date and project.start_date > utc_today():
            raise ValidationError("start_date cannot be in the future.")

        self._session.flush()
        return project

    def delete_project(self, *, actor: User, profile_id: uuid.UUID, project_id: uuid.UUID) -> None:
        profile = self.get_by_id(profile_id)
        self.assert_owner_or_admin(actor=actor, profile=profile)
        project = self.get_project(profile=profile, project_id=project_id)
        project.deleted_at = utcnow()
        self._session.flush()
        self._audit.record(
            action=AuditAction.ADMIN_ACTION,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="project",
            resource_id=project.id,
            outcome="SUCCESS",
            metadata={"operation": "delete_project"},
        )

    # -- helpers ---------------------------------------------------------- #

    def _reload(self, profile: WorkerProfile, actor: User) -> WorkerProfile:
        """Re-read with the eager loads the response schema needs."""
        if profile.user_id == actor.id:
            return self.get_for_user(actor)
        refreshed = self.get_by_id(profile.id)
        return WorkerProfileService(self._session)._with_collections(refreshed)

    def _with_collections(self, profile: WorkerProfile) -> WorkerProfile:
        statement = (
            select(WorkerProfile)
            .where(WorkerProfile.id == profile.id)
            .options(
                selectinload(WorkerProfile.trades).selectinload(WorkerTrade.trade),
                selectinload(WorkerProfile.skills).selectinload(WorkerSkill.skill),
            )
        )
        return self._session.execute(statement).scalar_one()

    def _one_county(self, code: str | None) -> County | None:
        if not code:
            return None
        county = self._catalogue.get_counties_by_codes([code]).get(code.upper())
        if county is None:
            raise CatalogueEntryNotFoundError(f"Unknown county code: {code}")
        return county

    def _counties(self, codes: list[str]) -> list[County]:
        resolved = self._catalogue.get_counties_by_codes(codes)
        self._require_all(resolved, codes, "county")
        seen: set[str] = set()
        ordered: list[County] = []
        for code in codes:
            upper = code.upper()
            if upper not in seen:
                seen.add(upper)
                ordered.append(resolved[upper])
        return ordered

    @staticmethod
    def _require_all(resolved: dict[str, Any], codes: list[str], label: str) -> None:
        missing = [code for code in codes if code.upper() not in resolved]
        if missing:
            raise CatalogueEntryNotFoundError(
                f"Unknown {label} code(s): " + ", ".join(sorted(set(missing)))
            )

    @staticmethod
    def _enforce_availability(profile: WorkerProfile) -> None:
        """Mirrors the database CHECK constraint so a bad write gets a message."""
        if profile.availability_status == AvailabilityStatus.AVAILABLE_SOON.value:
            if profile.available_from is None:
                raise ValidationError(
                    "available_from is required when availability_status is AVAILABLE_SOON."
                )
        else:
            profile.available_from = None
