"""Unit tests for the seed data and the seed script.

The most important test in this file is the production refusal. Every sample
account shares one published password, so a single missing guard would hand a
real deployment working credentials; that test is therefore written against the
strongest possible settings object, not a stubbed boolean.

The remaining tests exist because seed data rots quietly: a county dropped from
the list, a skill pointing at a trade that no longer exists, or a second run that
raises instead of converging are all invisible until a user hits them.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.constants import (
    AvailabilityStatus,
    JobStatus,
    OrganizationRole,
    ProfileVisibility,
    UserRole,
)
from app.core.security import PasswordHasherService
from app.db import seed as seed_module
from app.db.models.catalogue import County, Skill, Trade
from app.db.models.job import Job
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.user import User
from app.db.models.worker import WorkerProfile
from app.db.seed import (
    DEVELOPMENT_PASSWORD,
    SeedNotPermittedError,
    seed_catalogue,
    seed_development_users,
)
from app.db.seed_data import (
    COUNTIES,
    REGIONS,
    SKILLS,
    TRADES,
    TRADES_BY_CODE,
    counties as county_data,
    skills as skill_data,
    trades as trade_data,
)
from app.db.seed_data.counties import EXPECTED_COUNTY_COUNT

pytestmark = pytest.mark.unit


def _production_settings() -> Settings:
    """Build a genuinely production-shaped :class:`Settings`.

    Constructed rather than faked: ``Settings`` refuses to be ``production``
    with weak secrets, a wildcard-free but empty CORS list, or placeholder
    database credentials. Getting a valid object past those validators is what
    makes this test meaningful - a stubbed ``is_production`` would only prove the
    guard checks the attribute it was written to check.
    """
    return Settings(
        app_env="production",
        secret_key="production-only-secret-key-used-by-a-test-0123456789",
        jwt_secret="production-only-jwt-secret-used-by-a-test-0123456789",
        cors_allowed_origins=["https://app.fundipulse.example"],
        database_url=("postgresql+psycopg://app_user:app_password@db.example.com:5432/fundipulse"),
        debug=False,
        # The suite's own environment disables rate limiting for speed; a
        # production configuration must not.
        rate_limit_enabled=True,
    )


def _seed_emails() -> list[str]:
    """Every email address this seed owns."""
    return [
        f"admin@{seed_module.DEVELOPMENT_EMAIL_DOMAIN}",
        f"employer@{seed_module.DEVELOPMENT_EMAIL_DOMAIN}",
        *(spec.email for spec in seed_module._WORKER_SPECS),
    ]


def _seeded_users(session: Session) -> list[User]:
    """The seeded accounts, and only those.

    Scoped by address on purpose: the test database is shared, and rows other
    suites commit must not be mistaken for the seed's own output.
    """
    return list(session.scalars(select(User).where(User.email.in_(_seed_emails()))))


def _seeded_organization(session: Session) -> Organization | None:
    """The seeded organization, identified by the slug the seeder uses."""
    return session.scalar(
        select(Organization).where(Organization.slug == seed_module._ORGANIZATION_SLUG)
    )


def _count(session: Session, model: type[Any], *criteria: Any) -> int:
    """Rows of ``model`` matching ``criteria``, inside the current transaction."""
    statement = select(func.count()).select_from(model)
    for criterion in criteria:
        statement = statement.where(criterion)
    return session.scalar(statement) or 0


def _is_development() -> bool:
    """Whether the process settings report ``APP_ENV=development``."""
    from app.core.config import get_settings

    return get_settings().is_development


# --------------------------------------------------------------------------- #
# County reference data                                                        #
# --------------------------------------------------------------------------- #
class TestCountyData:
    def test_exactly_47_counties(self) -> None:
        """Kenya has 47 counties. A missing one hides a whole region of users."""
        assert len(COUNTIES) == 47
        assert len(COUNTIES) == EXPECTED_COUNTY_COUNT

    def test_codes_are_unique_upper_case_and_space_free(self) -> None:
        """Codes are the join key for every county filter, so they must be clean."""
        codes = [county.code for county in COUNTIES]
        assert len(set(codes)) == len(codes), "county codes must be unique"
        for code in codes:
            assert code, "a county code must not be empty"
            assert code == code.upper(), f"{code!r} must be upper case"
            assert " " not in code, f"{code!r} must not contain a space"
            assert code.replace("_", "").isalnum(), f"{code!r} must be alphanumeric"

    def test_required_fields_are_non_empty(self) -> None:
        """A blank capital or region renders as an empty filter option."""
        for county in COUNTIES:
            assert county.name.strip(), f"{county.code} has no name"
            assert county.capital.strip(), f"{county.code} has no capital"
            assert county.region.strip(), f"{county.code} has no region"

    def test_every_region_is_a_known_region(self) -> None:
        """Region drives grouping and copy; a typo fragments the whole filter."""
        for county in COUNTIES:
            assert county.region in REGIONS, f"{county.code} has region {county.region!r}"

    def test_nairobi_city_county_is_present(self) -> None:
        """The capital city is a county like any other, not a special case."""
        nairobi = next(county for county in COUNTIES if county.code == "NAIROBI")
        assert nairobi.name == "Nairobi City County"
        assert nairobi.region == "Nairobi"
        assert nairobi.capital == "Nairobi"

    @pytest.mark.parametrize(
        ("code", "name", "region", "capital"),
        [
            ("NAKURU", "Nakuru", "Rift Valley", "Nakuru"),
            ("BOMET", "Bomet", "Rift Valley", "Bomet"),
            ("MOMBASA", "Mombasa", "Coast", "Mombasa"),
            ("KISUMU", "Kisumu", "Western", "Kisumu"),
            ("MURANGA", "Murang'a", "Central", "Murang'a"),
            ("TANA_RIVER", "Tana River", "Coast", "Hola"),
            ("GARISSA", "Garissa", "North Eastern", "Garissa"),
            ("TURKANA", "Turkana", "Rift Valley", "Lodwar"),
            ("KISII", "Kisii", "Western", "Kisii"),
            ("NYAMIRA", "Nyamira", "Western", "Nyamira"),
            ("TRANS_NZOIA", "Trans Nzoia", "Rift Valley", "Kitale"),
            ("VIHIGA", "Vihiga", "Western", "Mbale"),
            ("MAKUENI", "Makueni", "Eastern", "Wote"),
            ("THARAKA_NITHI", "Tharaka-Nithi", "Eastern", "Kathwana"),
            ("NYANDARUA", "Nyandarua", "Central", "Ol Kalou"),
        ],
    )
    def test_recognisable_metadata(self, code: str, name: str, region: str, capital: str) -> None:
        """A Kenyan user must recognise the names, capitals and regions.

        Checked against counties a worker would actually filter by, including
        the ones whose headquarters is not the county's best-known town (Vihiga
        is administered from Mbale).
        """
        county = next(item for item in COUNTIES if item.code == code)
        assert (county.name, county.region, county.capital) == (name, region, capital)


# --------------------------------------------------------------------------- #
# Trade and skill reference data                                                #
# --------------------------------------------------------------------------- #
class TestTradeAndSkillData:
    def test_trades_are_unique_and_complete(self) -> None:
        codes = [trade.code for trade in TRADES]
        assert len(set(codes)) == len(codes)
        for expected in (
            "MASONRY",
            "CARPENTRY",
            "PLUMBING",
            "ELECTRICAL",
            "PAINTING_AND_DECORATING",
            "TILING",
            "WELDING",
            "ROOFING",
            "STEEL_FIXING",
            "GENERAL_LABOUR",
            "MACHINE_OPERATION",
            "PLASTERING",
            "SCAFFOLDING",
            "HVAC",
            "QUARRY_WORK",
            "REBAR_FIXING",
            "FORMWORK_CARPENTRY",
            "LANDSCAPING",
            "FLOORING",
            "GLAZING",
        ):
            assert expected in codes, f"{expected} must be in the trade catalogue"

    def test_trades_have_descriptions_and_ordering(self) -> None:
        for trade in TRADES:
            assert trade.name.strip(), f"{trade.code} has no name"
            assert len(trade.description.strip()) > 20, f"{trade.code} needs a real description"
            assert trade.display_order > 0, f"{trade.code} must sort before the defaults"

    def test_at_least_forty_skills(self) -> None:
        assert len(SKILLS) >= 40, "skill matching needs a catalogue worth matching against"

    def test_every_skill_trade_code_exists(self) -> None:
        """A dangling trade code becomes a skill with no trade after seeding."""
        for skill in SKILLS:
            if skill.trade_code is None:
                continue
            assert skill.trade_code in TRADES_BY_CODE, (
                f"skill {skill.code!r} references unknown trade {skill.trade_code!r}"
            )

    def test_skill_codes_are_unique(self) -> None:
        codes = [skill.code for skill in SKILLS]
        assert len(set(codes)) == len(codes)

    @pytest.mark.parametrize(
        "code",
        ["SITE_SUPERVISION", "SAFETY_COMPLIANCE", "READING_DRAWINGS", "TEAM_LEADERSHIP"],
    )
    def test_cross_trade_skills_are_ungrouped(self, code: str) -> None:
        """These span trades, so grouping them under one trade would mislead."""
        skill = next(item for item in SKILLS if item.code == code)
        assert skill.trade_code is None

    def test_every_trade_has_at_least_one_skill(self) -> None:
        """A trade an employer cannot filter by skill is dead weight in the UI."""
        grouped = {skill.trade_code for skill in SKILLS if skill.trade_code}
        assert set(TRADES_BY_CODE) <= grouped, (
            f"trades without skills: {sorted(set(TRADES_BY_CODE) - grouped)}"
        )


# --------------------------------------------------------------------------- #
# Catalogue seeding                                                            #
# --------------------------------------------------------------------------- #
class TestSeedCatalogue:
    def test_seeds_every_catalogue_row(self, db_session: Session) -> None:
        summary = seed_catalogue(db_session)

        assert summary.counties == len(COUNTIES)
        assert summary.trades == len(TRADES)
        assert summary.skills == len(SKILLS)
        assert summary.created == len(COUNTIES) + len(TRADES) + len(SKILLS)
        assert summary.updated == 0
        assert summary.as_dict()["counties"] == len(COUNTIES)

    def test_is_idempotent(self, db_session: Session) -> None:
        """A second run must converge, not raise a unique-constraint error."""
        first = seed_catalogue(db_session)
        second = seed_catalogue(db_session)

        assert second.counties == first.counties
        assert second.trades == first.trades
        assert second.skills == first.skills
        assert second.created == 0, "the second run must insert nothing"
        assert second.updated == first.counties + first.trades + first.skills

        assert _count(db_session, County) == len(COUNTIES)
        assert _count(db_session, Trade) == len(TRADES)
        assert _count(db_session, Skill) == len(SKILLS)

    def test_refreshes_names_without_reactivating_deactivated_rows(
        self, db_session: Session
    ) -> None:
        """A re-seed repairs descriptive drift but must not undo admin decisions.

        Deactivating a trade is how the catalogue retires one, and an
        administrator's decision must survive anyone running the seeder.
        """
        seed_catalogue(db_session)
        trade = db_session.scalar(select(Trade).where(Trade.code == "MASONRY"))
        assert trade is not None
        trade.is_active = False
        trade.name = "Stale Name"
        county = db_session.scalar(select(County).where(County.code == "KISUMU"))
        assert county is not None
        county.is_active = False
        db_session.flush()

        seed_catalogue(db_session)

        assert trade.name == "Masonry", "descriptive fields must be refreshed"
        assert trade.is_active is False, "an administrator's deactivation must survive"
        assert county.capital == "Kisumu"
        assert county.is_active is False

    def test_skills_are_linked_to_their_trades(self, db_session: Session) -> None:
        seed_catalogue(db_session)
        masonry = db_session.scalar(select(Trade).where(Trade.code == "MASONRY"))
        supervision = db_session.scalar(select(Skill).where(Skill.code == "SITE_SUPERVISION"))
        block_laying = db_session.scalar(select(Skill).where(Skill.code == "BLOCK_LAYING"))

        assert masonry is not None
        assert supervision is not None
        assert block_laying is not None
        assert block_laying.trade_id == masonry.id
        assert supervision.trade_id is None, "a cross-trade skill must have no trade"


# --------------------------------------------------------------------------- #
# The production refusal - the most important guard in this module             #
# --------------------------------------------------------------------------- #
class TestSeedDevelopmentUsersRefusal:
    def test_refuses_in_production_even_with_force(self, db_session: Session) -> None:
        """``force`` exists for the test suite; it must not open a production door.

        Every seeded account shares ``DEVELOPMENT_PASSWORD``, so running this
        against production would publish working credentials.
        """
        with pytest.raises(SeedNotPermittedError, match="production"):
            seed_development_users(db_session, force=True, settings=_production_settings())

    def test_refuses_in_production_using_live_settings(
        self, db_session: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The guard reads the settings the process actually has.

        Monkeypatching the module's ``get_settings`` proves the check is wired to
        live configuration rather than to the injectable parameter used above -
        the parameter could otherwise be the only thing under test.
        """
        production = _production_settings()
        monkeypatch.setattr(seed_module, "get_settings", lambda: production)

        with pytest.raises(SeedNotPermittedError, match="production"):
            seed_development_users(db_session, force=True)
        with pytest.raises(SeedNotPermittedError, match="production"):
            seed_development_users(db_session)

    def test_writes_nothing_when_it_refuses(self, db_session: Session) -> None:
        """A refusal that has already written rows would be no refusal at all."""
        with pytest.raises(SeedNotPermittedError):
            seed_development_users(db_session, force=True, settings=_production_settings())

        assert _seeded_users(db_session) == []
        assert _seeded_organization(db_session) is None

    def test_refuses_outside_development_without_force(self, db_session: Session) -> None:
        """The suite runs with ``APP_ENV=test``; that is not development."""
        assert not _is_development()

        with pytest.raises(SeedNotPermittedError, match="APP_ENV"):
            seed_development_users(db_session)

        assert _seeded_users(db_session) == []

    def test_force_allows_a_test_environment(self, db_session: Session) -> None:
        summary = seed_development_users(db_session, force=True)

        assert summary.users > 0


# --------------------------------------------------------------------------- #
# Development data content                                                     #
# --------------------------------------------------------------------------- #
class TestSeedDevelopmentUsers:
    def test_creates_the_expected_accounts(self, db_session: Session) -> None:
        summary = seed_development_users(db_session, force=True)
        db_session.flush()

        roles = {user.email: user.role for user in _seeded_users(db_session)}
        assert roles[f"admin@{seed_module.DEVELOPMENT_EMAIL_DOMAIN}"] == UserRole.ADMIN.value
        assert roles[f"employer@{seed_module.DEVELOPMENT_EMAIL_DOMAIN}"] == UserRole.EMPLOYER.value

        worker_emails = {spec.email for spec in seed_module._WORKER_SPECS}
        assert len(worker_emails) == 3
        for email in worker_emails:
            assert roles[email] == UserRole.WORKER.value

        assert summary.users == 5
        assert all(user.is_email_verified for user in _seeded_users(db_session)), (
            "sample accounts are pre-verified; there is no mail to wait for"
        )

    def test_password_hash_matches_the_documented_credential(self, db_session: Session) -> None:
        """The printed password must actually be the one that was hashed."""
        seed_development_users(db_session, force=True)
        employer = db_session.scalar(
            select(User).where(User.email == f"employer@{seed_module.DEVELOPMENT_EMAIL_DOMAIN}")
        )

        assert employer is not None
        assert employer.password_hash != DEVELOPMENT_PASSWORD, "the password must be hashed"
        assert PasswordHasherService().verify(DEVELOPMENT_PASSWORD, employer.password_hash)

    def test_creates_an_organization_with_an_owner_membership(self, db_session: Session) -> None:
        seed_development_users(db_session, force=True)

        organization = _seeded_organization(db_session)
        assert organization is not None
        assert organization.name == "Mwangaza Construction Ltd"
        assert organization.slug

        membership = db_session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id
            )
        )
        assert membership is not None
        assert membership.organization_id == organization.id
        assert membership.role == OrganizationRole.OWNER.value

        employer = db_session.scalar(
            select(User).where(User.email == f"employer@{seed_module.DEVELOPMENT_EMAIL_DOMAIN}")
        )
        assert employer is not None
        assert employer.role == UserRole.EMPLOYER.value
        assert membership.user_id == employer.id

    def test_worker_profiles_are_varied_and_attached_to_catalogue_rows(
        self, db_session: Session
    ) -> None:
        seed_development_users(db_session, force=True)
        organization = _seeded_organization(db_session)
        assert organization is not None
        profiles = list(
            db_session.scalars(
                select(WorkerProfile).where(
                    WorkerProfile.user_id.in_([user.id for user in _seeded_users(db_session)])
                )
            )
        )

        assert len(profiles) == 3
        assert len({profile.display_name for profile in profiles}) == 3
        assert len({profile.bio for profile in profiles}) == 3
        assert len({profile.headline for profile in profiles}) == 3
        assert {
            ProfileVisibility.PRIVATE.value,
            ProfileVisibility.DISCOVERABLE.value,
            ProfileVisibility.PUBLIC.value,
        } <= {profile.visibility for profile in profiles}
        assert len({profile.county_id for profile in profiles}) == 3
        assert all(profile.primary_trade_id is not None for profile in profiles)

        for profile in profiles:
            trade_count = len(profile.trades)
            skill_count = len(profile.skills)
            assert 2 <= trade_count <= 4, f"{profile.display_name} has {trade_count} trades"
            assert 3 <= skill_count <= 6, f"{profile.display_name} has {skill_count} skills"
            assert sum(1 for row in profile.trades if row.is_primary) == 1

    def test_creates_draft_and_open_jobs(self, db_session: Session) -> None:
        seed_development_users(db_session, force=True)
        organization = _seeded_organization(db_session)
        assert organization is not None
        jobs = list(db_session.scalars(select(Job).where(Job.organization_id == organization.id)))

        assert 2 <= len(jobs) <= 3
        statuses = {job.status for job in jobs}
        assert JobStatus.DRAFT.value in statuses
        assert JobStatus.OPEN.value in statuses

        for job in jobs:
            assert job.title.strip()
            assert len(job.description) > 50, "a job with a token description tests nothing"
            assert job.organization_id is not None, (
                "the jobs_published_requires_organization CHECK constraint "
                "demands an owner for anything that is not a draft"
            )
            if job.status == JobStatus.OPEN.value:
                assert job.published_at is not None
                assert job.closing_at is not None
                assert job.closing_at >= job.published_at
            else:
                assert job.published_at is None

    def test_is_idempotent(self, db_session: Session) -> None:
        """Run twice: same rows, no unique-constraint error, no duplicate account."""
        first = seed_development_users(db_session, force=True)
        second = seed_development_users(db_session, force=True)

        assert second.as_dict() == first.as_dict()
        assert len(_seeded_users(db_session)) == 5
        organization = _seeded_organization(db_session)
        assert organization is not None
        assert (
            _count(
                db_session,
                WorkerProfile,
                WorkerProfile.user_id.in_([user.id for user in _seeded_users(db_session)]),
            )
            == 3
        )
        assert (
            _count(
                db_session,
                OrganizationMembership,
                OrganizationMembership.organization_id == organization.id,
            )
            == 1
        )
        assert _count(db_session, Job, Job.organization_id == organization.id) == len(
            seed_module._JOB_SPECS
        )

    def test_does_not_reset_an_existing_account(self, db_session: Session) -> None:
        """Re-seeding must not promote, verify or re-hash an account it finds.

        Only the seeder's own dataset is in scope; anything a developer changed
        by hand stays changed, so a script run cannot quietly undo it.
        """
        seed_development_users(db_session, force=True)
        employer = db_session.scalar(
            select(User).where(User.email == f"employer@{seed_module.DEVELOPMENT_EMAIL_DOMAIN}")
        )
        assert employer is not None
        original_hash = employer.password_hash
        employer.role = UserRole.WORKER.value
        employer.is_email_verified = False
        db_session.flush()

        seed_development_users(db_session, force=True)

        assert employer.role == UserRole.WORKER.value
        assert employer.is_email_verified is False
        assert employer.password_hash == original_hash


# --------------------------------------------------------------------------- #
# Availability consistency                                                     #
# --------------------------------------------------------------------------- #
class TestAvailabilityConstraint:
    def test_seeded_available_soon_profiles_carry_a_date(self, db_session: Session) -> None:
        """ "Available soon" without a date is not something an employer can use."""
        seed_development_users(db_session, force=True)

        soon = [
            profile
            for profile in db_session.scalars(
                select(WorkerProfile).where(
                    WorkerProfile.user_id.in_([user.id for user in _seeded_users(db_session)])
                )
            )
            if profile.availability_status == AvailabilityStatus.AVAILABLE_SOON.value
        ]
        assert soon, "the development dataset should exercise the AVAILABLE_SOON path"
        for profile in soon:
            assert profile.available_from is not None
            assert profile.available_from >= profile.created_at.date()

    def test_database_rejects_available_soon_without_a_date(self, db_session: Session) -> None:
        """The CHECK constraint is the control, not this module's good intentions.

        Written as a negative test because the guarantee has to hold for every
        writer - a future service, admin tooling, or a direct ``psql`` session -
        not only for the seeder.
        """
        seed_catalogue(db_session)
        user = User(
            email="available-soon-check@fundipulse.test",
            password_hash="not-a-real-hash-but-non-empty",
            role=UserRole.WORKER.value,
            is_email_verified=True,
        )
        db_session.add(user)
        db_session.flush()
        db_session.add(
            WorkerProfile(
                user_id=user.id,
                display_name="No Date Yet",
                availability_status=AvailabilityStatus.AVAILABLE_SOON.value,
                available_from=None,
                visibility=ProfileVisibility.PRIVATE.value,
            )
        )

        with pytest.raises(IntegrityError):
            db_session.flush()
        db_session.rollback()


# --------------------------------------------------------------------------- #
# The defensive checks, exercised                                              #
# --------------------------------------------------------------------------- #
class TestReferenceDataIntegrity:
    """The validators that stop bad reference data at the door.

    A validator that is never called with bad data is indistinguishable from
    dead code, so each one is fed a deliberately corrupted copy of the data it
    guards. Without these, a future edit could drop a check and nothing would
    notice until a Kenyan user searched for a county that had gone missing.
    """

    def test_county_validator_rejects_an_incomplete_map(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(county_data, "COUNTIES", county_data.COUNTIES[:46])

        with pytest.raises(ValueError, match="46"):
            county_data._assert_counties_are_sound()

    @pytest.mark.parametrize(
        ("replacement", "expected"),
        [
            (replace(COUNTIES[1], code=COUNTIES[0].code), "Duplicate"),
            (replace(COUNTIES[1], code="nakuru county"), "upper-case"),
            (replace(COUNTIES[1], name="  "), "missing a name"),
            (replace(COUNTIES[1], region="Rift-valley"), "unknown region"),
        ],
    )
    def test_county_validator_rejects_a_broken_entry(
        self, monkeypatch: Any, replacement: Any, expected: str
    ) -> None:
        corrupt = (*COUNTIES[:1], replacement, *COUNTIES[2:])
        monkeypatch.setattr(county_data, "COUNTIES", corrupt)

        with pytest.raises(ValueError, match=expected):
            county_data._assert_counties_are_sound()

    @pytest.mark.parametrize(
        ("replacement", "expected"),
        [
            (replace(TRADES[1], code=TRADES[0].code), "Duplicate"),
            (replace(TRADES[1], description="  "), "missing a required field"),
            (replace(TRADES[1], code=""), "missing a required field"),
        ],
    )
    def test_trade_validator_rejects_a_broken_entry(
        self, monkeypatch: Any, replacement: Any, expected: str
    ) -> None:
        corrupt = (*TRADES[:1], replacement, *TRADES[2:])
        monkeypatch.setattr(trade_data, "TRADES", corrupt)

        with pytest.raises(ValueError, match=expected):
            trade_data._assert_trades_are_sound()

    @pytest.mark.parametrize(
        ("replacement", "expected"),
        [
            (replace(SKILLS[1], code=SKILLS[0].code), "Duplicate"),
            (replace(SKILLS[1], description="  "), "missing a required field"),
            (replace(SKILLS[1], trade_code="NOT_A_TRADE"), "unknown trade"),
        ],
    )
    def test_skill_validator_rejects_a_broken_entry(
        self, monkeypatch: Any, replacement: Any, expected: str
    ) -> None:
        corrupt = (*SKILLS[:1], replacement, *SKILLS[2:])
        monkeypatch.setattr(skill_data, "SKILLS", corrupt)

        with pytest.raises(ValueError, match=expected):
            skill_data._assert_skills_are_sound()

    def test_trade_validator_catches_a_stale_code_index(self, monkeypatch: Any) -> None:
        """``TRADES_BY_CODE`` is derived state and must never drift from ``TRADES``."""
        monkeypatch.setattr(trade_data, "TRADES_BY_CODE", {})

        with pytest.raises(ValueError, match="TRADES_BY_CODE"):
            trade_data._assert_trades_are_sound()

    def test_skill_divergence_from_the_database_is_refused(
        self, db_session: Session, monkeypatch: Any
    ) -> None:
        """A skill whose trade is absent must fail loudly, not land with no trade."""
        orphan = replace(SKILLS[0], code="ORPHAN_SKILL", trade_code="NOT_A_TRADE")
        monkeypatch.setattr(seed_module, "SKILLS", (orphan,))

        with pytest.raises(ValueError, match="NOT_A_TRADE"):
            seed_catalogue(db_session)


class TestSeedSpecValidation:
    """``_validate_specs``: a typo in the development data must stop the seed."""

    @pytest.mark.parametrize(
        ("break_it", "expected"),
        [
            (lambda spec: replace(spec, county_code="NOWHERE"), "NOWHERE"),
            (lambda spec: replace(spec, trade_codes=()), "no trades"),
            (lambda spec: replace(spec, trade_codes=("NOT_A_TRADE",)), "NOT_A_TRADE"),
            (lambda spec: replace(spec, skill_codes=("NOT_A_SKILL",)), "NOT_A_SKILL"),
            (lambda spec: replace(spec, trade_years=(1,)), "trade_years"),
        ],
    )
    def test_broken_worker_spec_is_refused(
        self, db_session: Session, monkeypatch: Any, break_it: Any, expected: str
    ) -> None:
        broken = break_it(seed_module._WORKER_SPECS[0])
        monkeypatch.setattr(seed_module, "_WORKER_SPECS", (broken,))

        with pytest.raises(SeedNotPermittedError, match=expected):
            seed_development_users(db_session, force=True)

    @pytest.mark.parametrize(
        ("break_it", "expected"),
        [
            (lambda spec: replace(spec, county_code="NOWHERE"), "NOWHERE"),
            (lambda spec: replace(spec, trade_code="NOT_A_TRADE"), "NOT_A_TRADE"),
        ],
    )
    def test_broken_job_spec_is_refused(
        self, db_session: Session, monkeypatch: Any, break_it: Any, expected: str
    ) -> None:
        broken = break_it(seed_module._JOB_SPECS[0])
        monkeypatch.setattr(seed_module, "_JOB_SPECS", (broken,))

        with pytest.raises(SeedNotPermittedError, match=expected):
            seed_development_users(db_session, force=True)

    def test_an_incomplete_catalogue_is_reported(self, db_session: Session) -> None:
        seed_catalogue(db_session)
        counties = {county.code: county for county in db_session.scalars(select(County))}

        with pytest.raises(SeedNotPermittedError, match="missing trades"):
            seed_module._validate_specs(counties, {}, {})

    def test_a_skill_missing_from_the_database_is_reported(self, db_session: Session) -> None:
        """Catches a database that skipped a skill the module data still lists."""
        seed_catalogue(db_session)
        counties = {county.code: county for county in db_session.scalars(select(County))}
        trades = {trade.code: trade for trade in db_session.scalars(select(Trade))}

        with pytest.raises(SeedNotPermittedError, match="BLOCK_LAYING"):
            seed_module._validate_specs(counties, trades, {})

    def test_no_offset_means_no_date(self) -> None:
        assert seed_module._future_date(None) is None
        assert seed_module._future_datetime(None) is None


# --------------------------------------------------------------------------- #
# Command line entry point                                                     #
# --------------------------------------------------------------------------- #
@contextmanager
def _fake_session_scope() -> Iterator[object]:
    """A session scope that writes nothing.

    ``main()`` commits through ``session_scope``, so the CLI's wiring has to be
    verified against a stand-in: running it for real would commit sample rows
    into the shared test database.
    """
    yield object()


class TestCommandLine:
    @pytest.fixture
    def recorded_calls(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
        """Replace the seeding functions and the session scope with recorders.

        Settings are presented as ``development`` so that the flag wiring is what
        these tests exercise; the refusal itself is covered by
        :class:`TestSeedDevelopmentUsersRefusal`.
        """
        calls = {"users": False}

        monkeypatch.setattr(seed_module, "get_settings", lambda: Settings(app_env="development"))
        monkeypatch.setattr(seed_module, "session_scope", _fake_session_scope)
        monkeypatch.setattr(
            seed_module,
            "seed_catalogue",
            lambda _session: seed_module.CatalogueSeedSummary(47, 20, 64, 131, 0),
        )

        def _fake_users(_session: Session, **_kwargs: Any) -> Any:
            calls["users"] = True
            return seed_module.DevelopmentSeedSummary(5, 1, 1, 3, 10, 18, 3)

        monkeypatch.setattr(seed_module, "seed_development_users", _fake_users)
        return calls

    @pytest.mark.parametrize("flag", ["--catalogues-only", "--skip-users"])
    def test_flags_skip_the_accounts(self, recorded_calls: dict[str, bool], flag: str) -> None:
        """Reference data is safe anywhere; sample accounts are not."""
        assert seed_module.main([flag]) == 0
        assert recorded_calls["users"] is False

    def test_default_run_seeds_both(self, recorded_calls: dict[str, bool]) -> None:
        assert seed_module.main([]) == 0
        assert recorded_calls["users"] is True

    def test_prints_a_summary(
        self, recorded_calls: dict[str, bool], capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A developer running this must see what landed without a query."""
        seed_module.main([])

        output = capsys.readouterr().out
        assert "FundiPulse seed" in output
        assert "47 counties" in output
        assert "accounts:" in output

    def test_exits_one_when_seeding_fails(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A CI step must stop, not carry on with a half-populated database."""
        monkeypatch.setattr(seed_module, "get_settings", lambda: Settings(app_env="development"))
        monkeypatch.setattr(seed_module, "session_scope", _fake_session_scope)

        def _unreachable(_session: Session) -> None:
            raise RuntimeError("database is unreachable")

        monkeypatch.setattr(seed_module, "seed_catalogue", _unreachable)

        with pytest.raises(SystemExit) as excinfo:
            seed_module.main([])

        assert excinfo.value.code == 1
        assert "database is unreachable" in capsys.readouterr().err

    def test_refuses_before_touching_the_database(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A refusal must not depend on the database being reachable.

        Otherwise an operator running this against a production deployment is
        told the database is unreachable, which hides the one fact they needed:
        that the run was never allowed.
        """
        entered: list[bool] = []

        @contextmanager
        def _tracking_scope() -> Iterator[object]:
            entered.append(True)
            yield object()

        monkeypatch.setattr(seed_module, "get_settings", _production_settings)
        monkeypatch.setattr(seed_module, "session_scope", _tracking_scope)

        with pytest.raises(SystemExit) as excinfo:
            seed_module.main([])

        assert excinfo.value.code == 1
        assert entered == [], "the guard must run before any connection is opened"
        assert "production" in capsys.readouterr().err

    def test_catalogues_only_still_runs_in_production(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Reference data is what a production database legitimately needs."""
        catalogue = seed_module.CatalogueSeedSummary(47, 20, 64, 131, 0)
        monkeypatch.setattr(seed_module, "get_settings", _production_settings)
        monkeypatch.setattr(seed_module, "session_scope", _fake_session_scope)
        monkeypatch.setattr(seed_module, "seed_catalogue", lambda _session: catalogue)

        assert seed_module.main(["--catalogues-only"]) == 0
