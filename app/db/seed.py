"""Development seed data."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal
import sys
from typing import Any, Final

from sqlalchemy import func, select
from sqlalchemy.orm import InstrumentedAttribute, Session
from sqlalchemy.sql.elements import ColumnElement

from app.core.config import Settings, get_settings
from app.core.constants import (
    AvailabilityStatus,
    ContactPreference,
    EmploymentType,
    ExperienceLevel,
    JobSourceType,
    JobStatus,
    MembershipStatus,
    OrganizationRole,
    ProfileVisibility,
    SkillProficiency,
    UserRole,
)
from app.core.security import PasswordHasherService
from app.db.base import utcnow
from app.db.models.catalogue import County, Skill, Trade
from app.db.models.job import Job
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.user import User
from app.db.models.worker import WorkerProfile, WorkerSkill, WorkerTrade
from app.db.seed_data import COUNTIES, SKILLS, TRADES, TRADES_BY_CODE
from app.db.seed_data.counties import CountySeed
from app.db.seed_data.skills import SkillSeed
from app.db.seed_data.trades import TradeSeed
from app.db.session import session_scope


class SeedNotPermittedError(RuntimeError):
    """Raised when seeding development data is not allowed here."""


#: Throwaway password shared by every development account.
#:
#: It is not a secret and must never become one. It is a constant in source so a
#: developer's login instructions never drift from the database, and it is only
#: ever stored as an Argon2id hash produced by
#: :class:`~app.core.security.PasswordHasherService`. No environment reachable
#: from outside the developer's own machine will accept this script; see
#: :func:`_ensure_seeding_permitted`.
DEVELOPMENT_PASSWORD: Final[str] = "Fundipulse-Dev-Only-1"  # noqa: S105

#: RFC 2606 reserves ``.test`` as a domain that never resolves, so a seeded
#: account cannot receive a real email or belong to a real person.
DEVELOPMENT_EMAIL_DOMAIN: Final[str] = "fundipulse.test"

_ORGANIZATION_NAME: Final[str] = "Mwangaza Construction Ltd"
_ORGANIZATION_SLUG: Final[str] = "mwangaza-construction"
_ORGANIZATION_CONTACT_EMAIL: Final[str] = f"info@{DEVELOPMENT_EMAIL_DOMAIN}"
_ORGANIZATION_INDUSTRY: Final[str] = "Building Construction"

_ADMIN_EMAIL: Final[str] = f"admin@{DEVELOPMENT_EMAIL_DOMAIN}"
_EMPLOYER_EMAIL: Final[str] = f"employer@{DEVELOPMENT_EMAIL_DOMAIN}"

_SALARY_CURRENCY: Final[str] = "KES"
_SALARY_PERIOD: Final[str] = "MONTHLY"


# --------------------------------------------------------------------------- #
# Development data specifications                                              #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class WorkerSpec:
    """Everything about one seeded worker, as data."""

    email: str
    display_name: str
    headline: str
    bio: str
    visibility: ProfileVisibility
    availability_status: AvailabilityStatus
    #: Days from today at which the worker becomes available. ``None`` for a
    #: worker who is not ``AVAILABLE_SOON``; a date is mandatory for that
    #: status, both by the database CHECK constraint and because "soon" without
    #: a date is not something an employer can act on.
    available_in_days: int | None
    county_code: str
    location: str
    phone_number: str
    contact_preference: ContactPreference
    declared_experience_years: Decimal
    #: Trade codes in order; the first is the primary trade.
    trade_codes: tuple[str, ...]
    skill_codes: tuple[str, ...]
    #: Years per trade, parallel to ``trade_codes``.
    trade_years: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class JobSpec:
    """Everything about one seeded job advertisement."""

    title: str
    description: str
    status: JobStatus
    trade_code: str | None
    county_code: str
    location: str
    employment_type: EmploymentType
    experience_level: ExperienceLevel
    experience_required_years: int | None
    #: Days from today at which applications close. ``None`` leaves the listing
    #: open ended, which is only sensible for a draft.
    closing_in_days: int | None
    salary_min: int | None = None
    salary_max: int | None = None


#: A deliberately mixed dataset: three different visibilities, three different
#: availability states and three different counties, so a developer exercising
#: search filters sees every branch rather than three identical rows.
_WORKER_SPECS: Final[tuple[WorkerSpec, ...]] = (
    WorkerSpec(
        email=f"daniel.otieno@{DEVELOPMENT_EMAIL_DOMAIN}",
        display_name="Daniel Otieno",
        headline="Block and stone mason with 12 years on residential estates in Kisumu",
        bio=(
            "I have built walls and foundations on housing estates around Kisumu "
            "since 2014, from foundation to plastering level. I own my own hand "
            "tools, and I am comfortable leading two or three labourers when a "
            "site needs a mason who also keeps the gang working."
        ),
        visibility=ProfileVisibility.DISCOVERABLE,
        availability_status=AvailabilityStatus.AVAILABLE,
        available_in_days=None,
        county_code="KISUMU",
        location="Kisumu Town, Kisumu County",
        phone_number="+254700000001",
        contact_preference=ContactPreference.IN_APP,
        declared_experience_years=Decimal("12.0"),
        trade_codes=("MASONRY", "PLASTERING", "GENERAL_LABOUR"),
        skill_codes=(
            "BLOCK_LAYING",
            "STONE_MASONRY",
            "MORTAR_AND_MIXING",
            "WALL_RENDERING",
            "SKIMMING_AND_FINISH_COATS",
            "SITE_MEASUREMENTS",
        ),
        trade_years=(12, 6, 8),
    ),
    WorkerSpec(
        email=f"esther.wanjiku@{DEVELOPMENT_EMAIL_DOMAIN}",
        display_name="Esther Wanjiku",
        headline="Formwork carpenter - shuttering and finishing work in Nakuru",
        bio=(
            "Ten years of formwork on columns, beams and staircases, plus "
            "finishing carpentry on institutional and residential buildings. I "
            "am used to working to programme against a strict pour schedule, and "
            "I know how to strike formwork at the right time."
        ),
        visibility=ProfileVisibility.PUBLIC,
        availability_status=AvailabilityStatus.AVAILABLE_SOON,
        available_in_days=14,
        county_code="NAKURU",
        location="Nakuru Town, Nakuru County",
        phone_number="+254700000002",
        contact_preference=ContactPreference.PHONE,
        declared_experience_years=Decimal("10.0"),
        trade_codes=("FORMWORK_CARPENTRY", "CARPENTRY", "TILING"),
        skill_codes=(
            "TIMBER_FORMWORK_ASSEMBLY",
            "STEEL_SHUTTERING_FIXING",
            "DOORS_WINDOWS_FITTING",
            "CERAMIC_TILE_FIXING",
            "READING_DRAWINGS",
            "WORKING_AT_HEIGHT",
        ),
        trade_years=(10, 8, 3),
    ),
    WorkerSpec(
        email=f"joseph.kimani@{DEVELOPMENT_EMAIL_DOMAIN}",
        display_name="Joseph Kimani",
        headline="Welder and steel fixer, currently on a coastal site in Mombasa",
        bio=(
            "I weld mild steel gates, tanks and staircases and fix structural "
            "steel on site. I am currently finishing a container terminal "
            "project in Mombasa and free from next month."
        ),
        visibility=ProfileVisibility.PRIVATE,
        availability_status=AvailabilityStatus.CURRENTLY_WORKING,
        available_in_days=None,
        county_code="MOMBASA",
        location="Changamwe, Mombasa County",
        phone_number="+254700000003",
        contact_preference=ContactPreference.NONE,
        declared_experience_years=Decimal("5.0"),
        trade_codes=("WELDING", "STEEL_FIXING", "MACHINE_OPERATION", "SCAFFOLDING"),
        skill_codes=(
            "ARC_WELDING",
            "MIG_MAG_WELDING",
            "BOLTING_AND_CONNECTIONS",
            "STRUCTURAL_STEEL_ERECTION",
            "EXCAVATOR_OPERATION",
            "SAFETY_COMPLIANCE",
        ),
        trade_years=(5, 3, 2, 2),
    ),
)

#: Two published adverts and one draft, so a developer can see both the draft
#: editor and the public listing without having to write a job first.
_JOB_SPECS: Final[tuple[JobSpec, ...]] = (
    JobSpec(
        title="Block Laying Crew for Housing Project",
        description=(
            "We are starting a 60-unit housing estate in Njoro and need a block "
            "laying crew for foundation and ground floor walls. Experience with "
            "concrete blocks, foundations and plastering is required. Camping "
            "accommodation is available for workers who are not local."
        ),
        status=JobStatus.DRAFT,
        trade_code="MASONRY",
        county_code="NAKURU",
        location="Njoro, Nakuru County",
        employment_type=EmploymentType.TEMPORARY,
        experience_level=ExperienceLevel.ENTRY,
        experience_required_years=1,
        closing_in_days=None,
    ),
    JobSpec(
        title="Experienced Plasterer and Painter Needed",
        description=(
            "A two-bedroom house and an adjacent classroom block need plastering, "
            "skimming and painting throughout. The plastering must come out flat "
            "enough to take a finish coat without patching. Starting next week and "
            "running for eight weeks."
        ),
        status=JobStatus.OPEN,
        trade_code="PLASTERING",
        county_code="NAKURU",
        location="Nakuru Town, Nakuru County",
        employment_type=EmploymentType.CONTRACT,
        experience_level=ExperienceLevel.EXPERIENCED,
        experience_required_years=3,
        closing_in_days=30,
        salary_min=45_000,
        salary_max=70_000,
    ),
    JobSpec(
        title="Construction Site Supervisor - Water and Roads Programme",
        description=(
            "We need a site supervisor for a rural water supply and access road "
            "programme across Kisumu County. You will coordinate the contractor's "
            "gangs, keep daily site records and weekly progress reporting, and be "
            "the point of contact for the client's engineers on site."
        ),
        status=JobStatus.OPEN,
        # No single owning trade: a supervisor role is filled from several
        # backgrounds, which the nullable trade reference expresses.
        trade_code=None,
        county_code="KISUMU",
        location="Kisumu County",
        employment_type=EmploymentType.FULL_TIME,
        experience_level=ExperienceLevel.EXPERIENCED,
        experience_required_years=5,
        closing_in_days=45,
        salary_min=80_000,
        salary_max=120_000,
    ),
)


# --------------------------------------------------------------------------- #
# Summaries                                                                    #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class CatalogueSeedSummary:
    """Row counts after :func:`seed_catalogue`, plus what this run changed."""

    counties: int
    trades: int
    skills: int
    created: int
    updated: int

    def as_dict(self) -> dict[str, int]:
        """Flat mapping, for printing and for assertions in tests."""
        return {
            "counties": self.counties,
            "trades": self.trades,
            "skills": self.skills,
            "created": self.created,
            "updated": self.updated,
        }


@dataclass(frozen=True, slots=True)
class DevelopmentSeedSummary:
    """Row counts after :func:`seed_development_users`."""

    users: int
    organizations: int
    memberships: int
    worker_profiles: int
    worker_trades: int
    worker_skills: int
    jobs: int

    def as_dict(self) -> dict[str, int]:
        """Flat mapping, for printing and for assertions in tests."""
        return {
            "users": self.users,
            "organizations": self.organizations,
            "memberships": self.memberships,
            "worker_profiles": self.worker_profiles,
            "worker_trades": self.worker_trades,
            "worker_skills": self.worker_skills,
            "jobs": self.jobs,
        }


# --------------------------------------------------------------------------- #
# Small helpers                                                                #
# --------------------------------------------------------------------------- #
def _count_rows(
    session: Session,
    column: InstrumentedAttribute[Any],
    *criteria: ColumnElement[Any],
) -> int:
    """Count rows of the table owning ``column`` that satisfy ``criteria``."""
    statement = select(func.count(column))
    for criterion in criteria:
        statement = statement.where(criterion)
    return session.scalar(statement) or 0


def _future_date(days: int | None) -> date | None:
    """A date ``days`` from today, or ``None``."""
    if days is None:
        return None
    return utcnow().date() + timedelta(days=days)


def _future_datetime(days: int | None) -> datetime | None:
    """A timezone-aware datetime ``days`` from now, or ``None``."""
    if days is None:
        return None
    return utcnow() + timedelta(days=days)


# --------------------------------------------------------------------------- #
# Catalogue seeding                                                            #
# --------------------------------------------------------------------------- #
def _apply_county(seed: CountySeed, county: County) -> None:
    """Copy a :class:`~app.db.seed_data.counties.CountySeed` onto an existing row."""
    county.name = seed.name
    county.region = seed.region
    county.capital = seed.capital


def _sync_counties(session: Session) -> tuple[int, int]:
    """Insert or refresh every county. Returns ``(created, updated)``."""
    existing = {county.code: county for county in session.scalars(select(County))}
    created = 0
    updated = 0

    for seed in COUNTIES:
        county = existing.get(seed.code)
        if county is None:
            session.add(
                County(
                    code=seed.code,
                    name=seed.name,
                    region=seed.region,
                    capital=seed.capital,
                    is_active=True,
                )
            )
            created += 1
            continue
        _apply_county(seed, county)
        updated += 1

    session.flush()
    return created, updated


def _apply_trade(seed: TradeSeed, trade: Trade) -> None:
    """Copy a :class:`~app.db.seed_data.trades.TradeSeed` onto an existing row."""
    trade.name = seed.name
    trade.description = seed.description
    trade.display_order = seed.display_order


def _sync_trades(session: Session) -> tuple[int, int]:
    """Insert or refresh every trade. Returns ``(created, updated)``."""
    existing = {trade.code: trade for trade in session.scalars(select(Trade))}
    created = 0
    updated = 0

    for seed in TRADES:
        trade = existing.get(seed.code)
        if trade is None:
            session.add(
                Trade(
                    code=seed.code,
                    name=seed.name,
                    description=seed.description,
                    display_order=seed.display_order,
                    is_active=True,
                )
            )
            created += 1
            continue
        _apply_trade(seed, trade)
        updated += 1

    session.flush()
    return created, updated


def _apply_skill(seed: SkillSeed, skill: Skill, trade_id: Any | None) -> None:
    """Copy a :class:`~app.db.seed_data.skills.SkillSeed` onto an existing row."""
    skill.name = seed.name
    skill.description = seed.description
    skill.display_order = seed.display_order
    skill.trade_id = trade_id


def _sync_skills(session: Session) -> tuple[int, int]:
    """Insert or refresh every skill. Returns ``(created, updated)``."""
    trade_by_code = {trade.code: trade for trade in session.scalars(select(Trade))}
    existing = {skill.code: skill for skill in session.scalars(select(Skill))}
    created = 0
    updated = 0

    for seed in SKILLS:
        trade_id: Any | None = None
        if seed.trade_code is not None:
            trade = trade_by_code.get(seed.trade_code)
            if trade is None:
                raise ValueError(
                    f"Skill {seed.code!r} references trade {seed.trade_code!r}, which is "
                    "not in the database. Trades are inserted first, so this means the "
                    "seed data and the catalogue have diverged."
                )
            trade_id = trade.id
        skill = existing.get(seed.code)
        if skill is None:
            session.add(
                Skill(
                    code=seed.code,
                    name=seed.name,
                    description=seed.description,
                    display_order=seed.display_order,
                    trade_id=trade_id,
                    is_active=True,
                )
            )
            created += 1
            continue
        _apply_skill(seed, skill, trade_id)
        updated += 1

    session.flush()
    return created, updated


def seed_catalogue(session: Session) -> CatalogueSeedSummary:
    """Load counties, trades and skills, updating or inserting as needed. Args: session: An open ses..."""
    created_counties, updated_counties = _sync_counties(session)
    created_trades, updated_trades = _sync_trades(session)
    created_skills, updated_skills = _sync_skills(session)

    return CatalogueSeedSummary(
        counties=_count_rows(session, County.id),
        trades=_count_rows(session, Trade.id),
        skills=_count_rows(session, Skill.id),
        created=created_counties + created_trades + created_skills,
        updated=updated_counties + updated_trades + updated_skills,
    )


# --------------------------------------------------------------------------- #
# Development user seeding                                                     #
# --------------------------------------------------------------------------- #
def _ensure_seeding_permitted(settings: Settings, *, force: bool) -> None:
    """Refuse to create sample accounts unless this is a development database. Raises: SeedNotPermit..."""
    if settings.is_production:
        raise SeedNotPermittedError(
            "Refusing to seed development users with APP_ENV=production. Every "
            f"development account shares the password {DEVELOPMENT_PASSWORD!r}, so "
            "running this against production would publish those credentials. Use "
            "--catalogues-only if you genuinely need the reference data."
        )
    if not settings.is_development and not force:
        raise SeedNotPermittedError(
            f"Refusing to seed development users with APP_ENV={settings.app_env!r}. "
            "Sample accounts are only created in development. Pass force=True if you "
            "are building a throwaway dataset in a test environment."
        )


def _get_or_create_user(
    session: Session,
    *,
    email: str,
    role: UserRole,
    hasher: PasswordHasherService,
) -> User:
    """Return the user with this address, creating it only if it is absent."""
    normalised = email.lower()
    existing = session.scalar(select(User).where(User.email == normalised))
    if existing is not None:
        return existing

    user = User(
        email=normalised,
        password_hash=hasher.hash(DEVELOPMENT_PASSWORD),
        role=role.value,
        is_active=True,
        # The addresses are @fundipulse.test and resolve nowhere, so there is no
        # verification round-trip to wait for.
        is_email_verified=True,
        email_verified_at=utcnow(),
    )
    session.add(user)
    session.flush()
    return user


def _validate_specs(
    counties: dict[str, County],
    trades: dict[str, Trade],
    skills: dict[str, Skill],
) -> None:
    """Fail before writing anything if a spec names a catalogue row that is gone."""
    missing_trades = set(TRADES_BY_CODE) - set(trades)
    if missing_trades:
        raise SeedNotPermittedError(f"Catalogue is missing trades: {sorted(missing_trades)}")

    catalogue_skill_codes = {skill.code for skill in SKILLS}

    for spec in _WORKER_SPECS:
        if spec.county_code not in counties:
            raise SeedNotPermittedError(f"Unknown county code {spec.county_code!r} in worker spec")
        if not spec.trade_codes:
            raise SeedNotPermittedError(f"Worker {spec.email} has no trades")
        for trade_code in spec.trade_codes:
            if trade_code not in trades:
                raise SeedNotPermittedError(
                    f"Unknown trade code {trade_code!r} in worker spec {spec.email}"
                )
        for skill_code in spec.skill_codes:
            if skill_code not in catalogue_skill_codes:
                raise SeedNotPermittedError(
                    f"Unknown skill code {skill_code!r} in worker spec {spec.email}"
                )
        if spec.trade_years and len(spec.trade_years) != len(spec.trade_codes):
            raise SeedNotPermittedError(
                f"Worker {spec.email} has {len(spec.trade_codes)} trades but "
                f"{len(spec.trade_years)} trade_years"
            )
        # Re-checking against the loaded rows, not only the module data: this is
        # what actually gets written.
        for skill_code in spec.skill_codes:
            if skill_code not in skills:
                raise SeedNotPermittedError(
                    f"Skill {skill_code!r} is missing from the database; seed_catalogue "
                    "should have inserted it"
                )

    for job_spec in _JOB_SPECS:
        if job_spec.county_code not in counties:
            raise SeedNotPermittedError(f"Unknown county code {job_spec.county_code!r} in job spec")
        if job_spec.trade_code is not None and job_spec.trade_code not in trades:
            raise SeedNotPermittedError(f"Unknown trade code {job_spec.trade_code!r} in job spec")


def _seed_organization(session: Session, employer: User) -> Organization:
    """Create or fetch the sample employer organization and its OWNER membership."""
    organization = session.scalar(
        select(Organization).where(Organization.slug == _ORGANIZATION_SLUG)
    )
    if organization is None:
        organization = Organization(
            name=_ORGANIZATION_NAME,
            slug=_ORGANIZATION_SLUG,
            description=(
                "A mid-sized building contractor working on residential estates, "
                "institutional buildings and water infrastructure across the Rift "
                "Valley and Western Kenya."
            ),
            industry=_ORGANIZATION_INDUSTRY,
            contact_email=_ORGANIZATION_CONTACT_EMAIL,
            location="Nakuru Town, Nakuru County",
            county="Nakuru",
            is_active=True,
            # Verification is an administrator's action; this script stands in for
            # that administrator, and only ever runs against a development
            # database.
            is_verified=True,
        )
        session.add(organization)
        session.flush()

    membership = session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == employer.id,
        )
    )
    if membership is None:
        session.add(
            OrganizationMembership(
                organization_id=organization.id,
                user_id=employer.id,
                role=OrganizationRole.OWNER.value,
                status=MembershipStatus.ACTIVE.value,
                title="Managing Director",
                joined_at=utcnow(),
            )
        )
        session.flush()
    return organization


def _seed_worker_profile(
    session: Session,
    *,
    user: User,
    spec: WorkerSpec,
    county: County,
    trades: dict[str, Trade],
    skills: dict[str, Skill],
) -> WorkerProfile | None:
    """Create one worker's passport, or return ``None`` if it already exists."""
    existing = session.scalar(select(WorkerProfile).where(WorkerProfile.user_id == user.id))
    if existing is not None:
        return None

    profile = WorkerProfile(
        user_id=user.id,
        display_name=spec.display_name,
        headline=spec.headline,
        bio=spec.bio,
        # Denormalised from worker_trades below so county-and-trade filtering is
        # a single indexed lookup.
        primary_trade_id=trades[spec.trade_codes[0]].id,
        county_id=county.id,
        location=spec.location,
        self_declared_experience_years=spec.declared_experience_years,
        availability_status=spec.availability_status.value,
        # Populated for AVAILABLE_SOON only. The database CHECK constraint
        # rejects an AVAILABLE_SOON profile with no date, and an employer cannot
        # act on "available soon" without knowing when.
        available_from=_future_date(spec.available_in_days),
        visibility=spec.visibility.value,
        contact_preference=spec.contact_preference.value,
        is_open_to_opportunities=True,
        phone_number=spec.phone_number,
    )
    session.add(profile)
    session.flush()

    for position, trade_code in enumerate(spec.trade_codes):
        years = spec.trade_years[position] if position < len(spec.trade_years) else None
        session.add(
            WorkerTrade(
                worker_profile_id=profile.id,
                trade_id=trades[trade_code].id,
                # Exactly one primary trade per passport, enforced by a partial
                # unique index rather than by this ordering alone.
                is_primary=position == 0,
                years_experience=Decimal(years) if years is not None else None,
            )
        )

    proficiencies = (
        SkillProficiency.EXPERT,
        SkillProficiency.ADVANCED,
        SkillProficiency.INTERMEDIATE,
        SkillProficiency.BEGINNER,
    )
    declared_years = int(spec.declared_experience_years)
    for position, skill_code in enumerate(spec.skill_codes):
        session.add(
            WorkerSkill(
                worker_profile_id=profile.id,
                skill_id=skills[skill_code].id,
                # Self-declared and varied, to show the UI's proficiency filter.
                proficiency=proficiencies[position % len(proficiencies)].value,
                years_experience=Decimal(min(declared_years, position + 1)),
            )
        )

    session.flush()
    return profile


def _seed_job(
    session: Session,
    *,
    spec: JobSpec,
    organization: Organization,
    employer: User,
    county: County,
    trades: dict[str, Trade],
) -> Job | None:
    """Create one job advertisement, or return ``None`` if it already exists."""
    existing = session.scalar(
        select(Job).where(
            Job.organization_id == organization.id,
            Job.title == spec.title,
        )
    )
    if existing is not None:
        return None

    published_at: datetime | None = None
    closing_at: datetime | None = None
    if spec.status is not JobStatus.DRAFT:
        # An OPEN listing is only meaningful once it has been published, and the
        # CHECK constraint requires closing_at >= published_at.
        published_at = utcnow()
        closing_at = _future_datetime(spec.closing_in_days)

    job = Job(
        title=spec.title,
        description=spec.description,
        trade_id=trades[spec.trade_code].id if spec.trade_code else None,
        # Set for a DRAFT too: it is the employer's own advert, and leaving it
        # unattached would make it invisible to the organization that wrote it.
        organization_id=organization.id,
        county_id=county.id,
        location=spec.location,
        employment_type=spec.employment_type.value,
        experience_level=spec.experience_level.value,
        experience_required_years=spec.experience_required_years,
        status=spec.status.value,
        published_at=published_at,
        closing_at=closing_at,
        source_type=JobSourceType.PLATFORM.value,
        source_name="FundiPulse",
        is_aggregated=False,
        created_by_user_id=employer.id,
        salary_min=spec.salary_min,
        salary_max=spec.salary_max,
        salary_currency=_SALARY_CURRENCY if spec.salary_min is not None else None,
        salary_period=_SALARY_PERIOD if spec.salary_min is not None else None,
    )
    session.add(job)
    session.flush()
    return job


def _summarise_development_data(session: Session) -> DevelopmentSeedSummary:
    """Count the rows this seed owns, so callers can assert on the result."""
    emails = [_ADMIN_EMAIL, _EMPLOYER_EMAIL, *(spec.email for spec in _WORKER_SPECS)]
    user_ids = list(session.scalars(select(User.id).where(User.email.in_(emails))))
    profile_ids = list(
        session.scalars(select(WorkerProfile.id).where(WorkerProfile.user_id.in_(user_ids)))
    )
    organization_id = session.scalar(
        select(Organization.id).where(Organization.slug == _ORGANIZATION_SLUG)
    )

    return DevelopmentSeedSummary(
        users=len(user_ids),
        organizations=0 if organization_id is None else 1,
        memberships=(
            0
            if organization_id is None
            else _count_rows(
                session,
                OrganizationMembership.id,
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id.in_(user_ids),
            )
        ),
        worker_profiles=len(profile_ids),
        worker_trades=(
            0
            if not profile_ids
            else _count_rows(
                session, WorkerTrade.id, WorkerTrade.worker_profile_id.in_(profile_ids)
            )
        ),
        worker_skills=(
            0
            if not profile_ids
            else _count_rows(
                session, WorkerSkill.id, WorkerSkill.worker_profile_id.in_(profile_ids)
            )
        ),
        # Scoped to this organization's adverts so a developer's own test rows
        # cannot make the summary overstate what the script produced.
        jobs=(
            0
            if organization_id is None
            else _count_rows(session, Job.id, Job.organization_id == organization_id)
        ),
    )


def seed_development_users(
    session: Session,
    *,
    force: bool = False,
    settings: Settings | None = None,
) -> DevelopmentSeedSummary:
    """Create the local-only sample accounts, organization and job adverts. Args: session: An open s..."""
    resolved_settings = settings or get_settings()
    _ensure_seeding_permitted(resolved_settings, force=force)

    # Passports, jobs and trades reference the catalogue by foreign key, so the
    # catalogues must exist first. Idempotent, so this is a cheap no-op when the
    # caller already ran seed_catalogue in the same transaction.
    seed_catalogue(session)

    counties = {county.code: county for county in session.scalars(select(County))}
    trades = {trade.code: trade for trade in session.scalars(select(Trade))}
    skills = {skill.code: skill for skill in session.scalars(select(Skill))}
    _validate_specs(counties, trades, skills)

    hasher = PasswordHasherService(resolved_settings)
    # The administrator exists so a developer can open the moderation screens.
    # No seeded row references it, so the object is deliberately not kept.
    _get_or_create_user(session, email=_ADMIN_EMAIL, role=UserRole.ADMIN, hasher=hasher)
    employer = _get_or_create_user(
        session, email=_EMPLOYER_EMAIL, role=UserRole.EMPLOYER, hasher=hasher
    )
    organization = _seed_organization(session, employer)

    for spec in _WORKER_SPECS:
        worker = _get_or_create_user(session, email=spec.email, role=UserRole.WORKER, hasher=hasher)
        _seed_worker_profile(
            session,
            user=worker,
            spec=spec,
            county=counties[spec.county_code],
            trades=trades,
            skills=skills,
        )

    for job_spec in _JOB_SPECS:
        _seed_job(
            session,
            spec=job_spec,
            organization=organization,
            employer=employer,
            county=counties[job_spec.county_code],
            trades=trades,
        )

    session.flush()
    return _summarise_development_data(session)


# --------------------------------------------------------------------------- #
# Command line entry point                                                     #
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for ``python -m app.db.seed``."""
    parser = argparse.ArgumentParser(
        prog="python -m app.db.seed",
        description="Seed FundiPulse reference data and, in development only, sample accounts.",
    )
    parser.add_argument(
        "--catalogues-only",
        action="store_true",
        help=(
            "Load counties, trades and skills only. Creates no accounts, so this is "
            "the option to use when populating a database that is not a developer's."
        ),
    )
    parser.add_argument(
        "--skip-users",
        action="store_true",
        help=(
            "Skip the sample accounts for this run. Same effect as --catalogues-only, "
            "spelled the way scripts and documentation tend to ask for it."
        ),
    )
    return parser


def _print_summary(catalogue: CatalogueSeedSummary, users: DevelopmentSeedSummary | None) -> None:
    """Print what was seeded so a developer need not query the database to check."""
    print("FundiPulse seed")  # noqa: T201
    print(  # noqa: T201
        f"  catalogues: {catalogue.counties} counties, {catalogue.trades} trades, "
        f"{catalogue.skills} skills "
        f"({catalogue.created} created, {catalogue.updated} updated)"
    )
    if users is None:
        print("  accounts:   skipped")  # noqa: T201
        return
    print(  # noqa: T201
        f"  accounts:   {users.users} users, {users.organizations} organization, "
        f"{users.worker_profiles} passports "
        f"({users.worker_trades} trades, {users.worker_skills} skills), {users.jobs} jobs"
    )
    print(f"  password:   {DEVELOPMENT_PASSWORD} (development only)")  # noqa: T201


def main(argv: Sequence[str] | None = None) -> int:
    """Run the seeder and return a process exit code. Args: argv: Arguments to parse, defaulting to ..."""
    args = _build_parser().parse_args(argv)
    seed_users = not (args.catalogues_only or args.skip_users)

    try:
        settings = get_settings()
        if seed_users:
            # Refuse before opening a connection. A guard that ran only after the
            # database was reachable would report an unreachable database instead
            # of the real reason the run is forbidden.
            _ensure_seeding_permitted(settings, force=False)
        with session_scope() as session:
            catalogue = seed_catalogue(session)
            users = seed_development_users(session, settings=settings) if seed_users else None
    except Exception as exc:  # a CLI reports the failure; it never traceback-dumps
        print(f"Seed failed: {exc}", file=sys.stderr)  # noqa: T201
        raise SystemExit(1) from exc

    _print_summary(catalogue, users)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
