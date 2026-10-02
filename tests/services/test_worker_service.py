"""Service-level tests for the gaps the HTTP suite does not reach.

The API tests exercise the happy path and the authorisation boundary. What they
cannot reach is the code behind a branch the router never takes: an admin acting
on another worker's passport, a partial patch that changes a foreign key, the
helpers that only run when a code is missing from the catalogue. Those are exactly
the branches where a silent wrong answer would be worst, so they are tested here
against a real session.
"""

from __future__ import annotations

from datetime import timedelta
import uuid

from pydantic import ValidationError as PydanticValidationError
import pytest
from sqlalchemy import select

from app.core.constants import AvailabilityStatus, UserRole
from app.core.exceptions import (
    ForbiddenError,
    InvalidStateTransitionError,
    ValidationError,
)
from app.db.base import utcnow
from app.db.models.catalogue import County, Skill, Trade
from app.db.models.worker import WorkerProfile, WorkerTrade
from app.schemas.experiences import WorkExperienceCreateRequest, WorkExperienceUpdateRequest
from app.schemas.projects import ProjectCreateRequest, ProjectUpdateRequest
from app.schemas.workers import (
    PreferredCountiesUpdateRequest,
    WorkerProfileCreateRequest,
    WorkerProfileUpdateRequest,
    WorkerTradesUpdateRequest,
)
from app.services.worker_service import (
    CatalogueEntryNotFoundError,
    CatalogueService,
    NotPassportOwnerError,
    WorkerProfileNotFoundError,
    WorkerProfileService,
)
from app.utils.dates import utc_today

pytestmark = pytest.mark.integration

TODAY = utc_today()


@pytest.fixture
def catalogue(db_session) -> dict:
    """Three trades, two skills, three counties, all committed to the session."""
    counties = {
        code: County(id=uuid.uuid4(), code=code, name=name)
        for code, name in (("NAKURU", "Nakuru"), ("BOMET", "Bomet"), ("MOMBASA", "Mombasa"))
    }
    trades = {
        code: Trade(id=uuid.uuid4(), code=code, name=name)
        for code, name in (("MASONRY", "Masonry"), ("PLUMBING", "Plumbing"), ("WELDING", "Welding"))
    }
    skills = {
        code: Skill(id=uuid.uuid4(), code=code, name=name)
        for code, name in (("BLOCK_LAYING", "Block laying"), ("PIPE_FITTING", "Pipe fitting"))
    }
    db_session.add_all([*counties.values(), *trades.values(), *skills.values()])
    db_session.flush()
    return {"counties": counties, "trades": trades, "skills": skills}


@pytest.fixture
def owner(db_session, make_user) -> object:
    return make_user(role=UserRole.WORKER)


@pytest.fixture
def other(db_session, make_user) -> object:
    return make_user(role=UserRole.WORKER)


@pytest.fixture
def passport(db_session, owner) -> WorkerProfile:
    profile = WorkerProfile(user_id=owner.id, display_name="Service Level")
    db_session.add(profile)
    db_session.flush()
    return profile


@pytest.fixture
def service(db_session) -> WorkerProfileService:
    return WorkerProfileService(db_session)


@pytest.fixture
def catalogue_service(db_session) -> CatalogueService:
    return CatalogueService(db_session)


# --------------------------------------------------------------------------- #
# Ownership                                                                   #
# --------------------------------------------------------------------------- #
class TestOwnership:
    def test_another_worker_cannot_write(self, service, passport, other) -> None:
        with pytest.raises(NotPassportOwnerError):
            service.update(
                actor=other,
                profile_id=passport.id,
                payload=WorkerProfileUpdateRequest(display_name="Hijacked"),
            )

    def test_an_admin_may_write(self, service, passport, make_admin) -> None:
        admin = make_admin()
        updated = service.update(
            actor=admin,
            profile_id=passport.id,
            payload=WorkerProfileUpdateRequest(display_name="Corrected By Admin"),
        )
        assert updated.display_name == "Corrected By Admin"

    def test_an_admin_may_replace_trades(self, service, passport, catalogue, make_admin) -> None:
        """The admin path re-reads with eager loads instead of via the owner."""
        admin = make_admin()
        updated = service.replace_trades(
            actor=admin,
            profile_id=passport.id,
            payload=WorkerTradesUpdateRequest.model_validate(
                {"trades": [{"trade_code": "MASONRY", "is_primary": True}]}
            ),
        )
        assert [link.trade.code for link in updated.trades] == ["MASONRY"]
        assert updated.primary_trade_id == catalogue["trades"]["MASONRY"].id

    def test_a_private_passport_is_invisible_to_another_worker(
        self, service, passport, other
    ) -> None:
        with pytest.raises(WorkerProfileNotFoundError):
            service.assert_visible_to(viewer=other, profile=passport)

    def test_an_anonymous_viewer_cannot_see_a_private_passport(self, service, passport) -> None:
        with pytest.raises(WorkerProfileNotFoundError):
            service.assert_visible_to(viewer=None, profile=passport)

    def test_an_anonymous_viewer_can_see_a_discoverable_passport(
        self, service, passport, db_session
    ) -> None:
        passport.visibility = "DISCOVERABLE"
        db_session.flush()
        assert service.assert_visible_to(viewer=None, profile=passport) is passport

    def test_an_admin_account_cannot_hold_a_passport(self, service, make_admin) -> None:
        with pytest.raises(ForbiddenError):
            service.create(
                actor=make_admin(),
                payload=WorkerProfileCreateRequest(display_name="Administrator"),
            )

    def test_a_soft_deleted_passport_is_not_found(
        self, service, passport, owner, db_session
    ) -> None:
        passport.deleted_at = utcnow()
        db_session.flush()
        with pytest.raises(WorkerProfileNotFoundError):
            service.get_for_user(owner)

    def test_a_soft_deleted_passport_can_still_be_read_explicitly(
        self, service, passport, owner, db_session
    ) -> None:
        passport.deleted_at = utcnow()
        db_session.flush()
        assert service.get_for_user(owner, include_deleted=True).id == passport.id


# --------------------------------------------------------------------------- #
# Catalogue resolution                                                        #
# --------------------------------------------------------------------------- #
class TestCatalogueResolution:
    def test_an_unknown_primary_trade_is_rejected_not_dropped(
        self, service, owner, catalogue
    ) -> None:
        """A silently ignored code would leave the worker believing it was set."""
        with pytest.raises(CatalogueEntryNotFoundError, match="TIME_TRAVEL"):
            service.create(
                actor=owner,
                payload=WorkerProfileCreateRequest(
                    display_name="Unknown Trade",
                    primary_trade_code="TIME_TRAVEL",
                ),
            )

    def test_an_unknown_listed_trade_is_rejected(self, service, owner) -> None:
        with pytest.raises(CatalogueEntryNotFoundError, match="NOT_A_TRADE"):
            service.create(
                actor=owner,
                payload=WorkerProfileCreateRequest(
                    display_name="Unknown Listed Trade",
                    trade_codes=["NOT_A_TRADE"],
                ),
            )

    def test_an_unknown_county_on_create_is_rejected(self, service, owner) -> None:
        with pytest.raises(CatalogueEntryNotFoundError, match="ATLANTIS"):
            service.create(
                actor=owner,
                payload=WorkerProfileCreateRequest(
                    display_name="Unknown County", county_code="ATLANTIS"
                ),
            )

    def test_every_missing_code_is_named(self, service, passport, catalogue, owner) -> None:
        with pytest.raises(CatalogueEntryNotFoundError) as caught:
            service.replace_preferred_counties(
                actor=owner,
                profile_id=passport.id,
                payload=PreferredCountiesUpdateRequest(
                    county_codes=["NAKURU", "GONE_A", "ALSO_GONE_B"]
                ),
            )
        message = str(caught.value)
        assert "ALSO_GONE_B" in message
        assert "GONE_A" in message

    def test_duplicate_county_codes_collapse(self, service, catalogue, owner) -> None:
        profile = service.create(
            actor=owner,
            payload=WorkerProfileCreateRequest(
                display_name="Duplicates",
                preferred_county_codes=["NAKURU", "BOMET", "NAKURU"],
            ),
        )
        _primary, preferred = service.load_counties(profile)
        assert sorted(county.code for county in preferred) == ["BOMET", "NAKURU"]

    def test_a_cleared_county_sets_the_column_to_null(self, service, catalogue, owner) -> None:
        profile = service.create(
            actor=owner,
            payload=WorkerProfileCreateRequest(display_name="Clearing", county_code="NAKURU"),
        )
        updated = service.update(
            actor=owner,
            profile_id=profile.id,
            payload=WorkerProfileUpdateRequest(county_code=None),
        )
        assert updated.county_id is None

    def test_a_cleared_primary_trade_sets_the_column_to_null(
        self, service, catalogue, owner
    ) -> None:
        profile = service.create(
            actor=owner,
            payload=WorkerProfileCreateRequest(
                display_name="Clearing Trade", primary_trade_code="MASONRY"
            ),
        )
        updated = service.update(
            actor=owner,
            profile_id=profile.id,
            payload=WorkerProfileUpdateRequest(primary_trade_code=None),
        )
        assert updated.primary_trade_id is None


# --------------------------------------------------------------------------- #
# Availability invariant                                                     #
# --------------------------------------------------------------------------- #
class TestAvailabilityInvariant:
    def test_switching_to_available_soon_without_a_date_is_refused(self, service, owner) -> None:
        profile = service.create(
            actor=owner, payload=WorkerProfileCreateRequest(display_name="Available Soon")
        )
        with pytest.raises(ValidationError, match="available_from"):
            service.update(
                actor=owner,
                profile_id=profile.id,
                payload=WorkerProfileUpdateRequest(
                    availability_status=AvailabilityStatus.AVAILABLE_SOON
                ),
            )

    def test_switching_away_clears_a_stale_date(self, service, owner) -> None:
        profile = service.create(
            actor=owner,
            payload=WorkerProfileCreateRequest(
                display_name="Clearing Date",
                availability_status=AvailabilityStatus.AVAILABLE_SOON,
                available_from=TODAY + timedelta(days=7),
            ),
        )
        updated = service.update(
            actor=owner,
            profile_id=profile.id,
            payload=WorkerProfileUpdateRequest(availability_status=AvailabilityStatus.AVAILABLE),
        )
        assert updated.available_from is None


# --------------------------------------------------------------------------- #
# Experience patching                                                        #
# --------------------------------------------------------------------------- #
class TestExperiencePatching:
    def _create(self, service, passport, owner, **overrides) -> object:
        payload = {
            "employer_name": "Original Employer",
            "role_title": "Mason",
            "start_date": TODAY - timedelta(days=400),
            "end_date": TODAY - timedelta(days=100),
            "is_current": False,
        }
        payload.update(overrides)
        return service.create_experience(
            actor=owner, profile_id=passport.id, payload=WorkExperienceCreateRequest(**payload)
        )

    def test_patching_the_trade_repoints_the_foreign_key(
        self, service, passport, owner, catalogue
    ) -> None:
        record = self._create(service, passport, owner, trade_code="MASONRY")
        updated = service.update_experience(
            actor=owner,
            profile_id=passport.id,
            experience_id=record.id,
            payload=WorkExperienceUpdateRequest(trade_code="PLUMBING"),
        )
        assert updated.trade_id == catalogue["trades"]["PLUMBING"].id

    def test_clearing_the_trade_sets_it_to_null(self, service, passport, owner, catalogue) -> None:
        record = self._create(service, passport, owner, trade_code="MASONRY")
        updated = service.update_experience(
            actor=owner,
            profile_id=passport.id,
            experience_id=record.id,
            payload=WorkExperienceUpdateRequest(trade_code=None),
        )
        assert updated.trade_id is None

    def test_an_unknown_trade_is_rejected_on_patch(self, service, passport, owner) -> None:
        record = self._create(service, passport, owner)
        with pytest.raises(CatalogueEntryNotFoundError):
            service.update_experience(
                actor=owner,
                profile_id=passport.id,
                experience_id=record.id,
                payload=WorkExperienceUpdateRequest(trade_code="TIME_TRAVEL"),
            )

    def test_patching_the_county_repoints_the_foreign_key(
        self, service, passport, owner, catalogue
    ) -> None:
        record = self._create(service, passport, owner, county_code="NAKURU")
        updated = service.update_experience(
            actor=owner,
            profile_id=passport.id,
            experience_id=record.id,
            payload=WorkExperienceUpdateRequest(county_code="BOMET"),
        )
        assert updated.county_id == catalogue["counties"]["BOMET"].id

    def test_patching_dates_into_an_invalid_range_is_refused(
        self, service, passport, owner
    ) -> None:
        """The stored row is revalidated, not just the supplied fields."""
        record = self._create(service, passport, owner)
        with pytest.raises(ValidationError):
            service.update_experience(
                actor=owner,
                profile_id=passport.id,
                experience_id=record.id,
                payload=WorkExperienceUpdateRequest(start_date=TODAY - timedelta(days=10)),
            )

    def test_patching_into_an_ended_but_current_row_is_refused(
        self, service, passport, owner
    ) -> None:
        record = self._create(service, passport, owner)
        with pytest.raises(InvalidStateTransitionError):
            service.update_experience(
                actor=owner,
                profile_id=passport.id,
                experience_id=record.id,
                payload=WorkExperienceUpdateRequest(is_current=True),
            )

    def test_patching_into_an_open_but_not_current_row_is_refused(
        self, service, passport, owner
    ) -> None:
        record = self._create(service, passport, owner)
        with pytest.raises(ValidationError):
            service.update_experience(
                actor=owner,
                profile_id=passport.id,
                experience_id=record.id,
                payload=WorkExperienceUpdateRequest(is_current=False, end_date=None),
            )


# --------------------------------------------------------------------------- #
# Project patching                                                           #
# --------------------------------------------------------------------------- #
class TestProjectPatching:
    def _create(self, service, passport, owner, **overrides) -> object:
        payload = {"name": "Original Site", "role_title": "Mason"}
        payload.update(overrides)
        return service.create_project(
            actor=owner, profile_id=passport.id, payload=ProjectCreateRequest(**payload)
        )

    def test_patching_the_trade_repoints_the_foreign_key(
        self, service, passport, owner, catalogue
    ) -> None:
        project = self._create(service, passport, owner, trade_code="MASONRY")
        updated = service.update_project(
            actor=owner,
            profile_id=passport.id,
            project_id=project.id,
            payload=ProjectUpdateRequest(trade_code="WELDING"),
        )
        assert updated.trade_id == catalogue["trades"]["WELDING"].id

    def test_clearing_the_trade_sets_it_to_null(self, service, passport, owner, catalogue) -> None:
        project = self._create(service, passport, owner, trade_code="MASONRY")
        updated = service.update_project(
            actor=owner,
            profile_id=passport.id,
            project_id=project.id,
            payload=ProjectUpdateRequest(trade_code=None),
        )
        assert updated.trade_id is None

    def test_an_unknown_trade_is_rejected_on_patch(self, service, passport, owner) -> None:
        project = self._create(service, passport, owner)
        with pytest.raises(CatalogueEntryNotFoundError):
            service.update_project(
                actor=owner,
                profile_id=passport.id,
                project_id=project.id,
                payload=ProjectUpdateRequest(trade_code="TIME_TRAVEL"),
            )

    def test_patching_the_county_repoints_the_foreign_key(
        self, service, passport, owner, catalogue
    ) -> None:
        project = self._create(service, passport, owner, county_code="NAKURU")
        updated = service.update_project(
            actor=owner,
            profile_id=passport.id,
            project_id=project.id,
            payload=ProjectUpdateRequest(county_code="MOMBASA"),
        )
        assert updated.county_id == catalogue["counties"]["MOMBASA"].id

    def test_clearing_the_county_sets_it_to_null(self, service, passport, owner, catalogue) -> None:
        project = self._create(service, passport, owner, county_code="NAKURU")
        updated = service.update_project(
            actor=owner,
            profile_id=passport.id,
            project_id=project.id,
            payload=ProjectUpdateRequest(county_code=None),
        )
        assert updated.county_id is None

    def test_an_unknown_county_is_rejected_on_patch(self, service, passport, owner) -> None:
        project = self._create(service, passport, owner)
        with pytest.raises(CatalogueEntryNotFoundError):
            service.update_project(
                actor=owner,
                profile_id=passport.id,
                project_id=project.id,
                payload=ProjectUpdateRequest(county_code="ATLANTIS"),
            )

    def test_patching_dates_into_an_invalid_range_is_refused(
        self, service, passport, owner
    ) -> None:
        """Only the service can see this: the payload carries one field, and the
        counterpart lives on the stored row."""
        project = self._create(
            service,
            passport,
            owner,
            start_date=TODAY - timedelta(days=400),
            end_date=TODAY - timedelta(days=100),
        )
        with pytest.raises(ValidationError, match="earlier than"):
            service.update_project(
                actor=owner,
                profile_id=passport.id,
                project_id=project.id,
                payload=ProjectUpdateRequest(start_date=TODAY - timedelta(days=10)),
            )

    def test_the_schema_blocks_a_future_date_before_the_service_sees_it(
        self, service, passport, owner
    ) -> None:
        project = self._create(service, passport, owner)
        with pytest.raises(PydanticValidationError, match="future"):
            service.update_project(
                actor=owner,
                profile_id=passport.id,
                project_id=project.id,
                payload=ProjectUpdateRequest(end_date=TODAY + timedelta(days=30)),
            )

    def test_the_service_still_guards_a_row_the_schema_could_not_have_written(
        self, service, passport, owner, db_session
    ) -> None:
        """Defence in depth for a row written by an import or a future schema change."""
        project = self._create(service, passport, owner, end_date=TODAY - timedelta(days=1))
        project.end_date = TODAY + timedelta(days=30)
        db_session.flush()

        with pytest.raises(ValidationError, match="future"):
            service.update_project(
                actor=owner,
                profile_id=passport.id,
                project_id=project.id,
                payload=ProjectUpdateRequest(name="Renamed"),
            )


# --------------------------------------------------------------------------- #
# Derived experience                                                         #
# --------------------------------------------------------------------------- #
class TestDerivedExperience:
    def test_overlapping_roles_are_not_double_counted(self, service, passport, owner) -> None:
        for name, start, end in (
            ("Alpha", TODAY - timedelta(days=730), TODAY - timedelta(days=365)),
            ("Beta", TODAY - timedelta(days=700), TODAY - timedelta(days=400)),
        ):
            service.create_experience(
                actor=owner,
                profile_id=passport.id,
                payload=WorkExperienceCreateRequest(
                    employer_name=name,
                    role_title="Mason",
                    start_date=start,
                    end_date=end,
                    is_current=False,
                ),
            )
        summary = service.derive_experience_summary(passport)
        # The union of both is 365 days, not the 630 the naive sum would give.
        assert float(summary["total_years"]) == pytest.approx(1.0, abs=0.05)
        assert summary["record_count"] == 2

    def test_a_current_role_counts_up_to_today(self, service, passport, owner) -> None:
        service.create_experience(
            actor=owner,
            profile_id=passport.id,
            payload=WorkExperienceCreateRequest(
                employer_name="Current Employer",
                role_title="Mason",
                start_date=TODAY - timedelta(days=730),
                is_current=True,
            ),
        )
        summary = service.derive_experience_summary(passport)
        assert float(summary["current_years"]) == pytest.approx(2.0, abs=0.05)
        assert float(summary["completed_years"]) == 0.0
        assert summary["current_record_count"] == 1
        assert summary["latest_end"] is None

    def test_soft_deleted_records_are_excluded(self, service, passport, owner) -> None:
        record = service.create_experience(
            actor=owner,
            profile_id=passport.id,
            payload=WorkExperienceCreateRequest(
                employer_name="Gone",
                role_title="Mason",
                start_date=TODAY - timedelta(days=100),
                is_current=True,
            ),
        )
        service.delete_experience(actor=owner, profile_id=passport.id, experience_id=record.id)
        assert service.derive_experience_summary(passport)["record_count"] == 0

    def test_extremes_are_reported(self, service, passport, owner) -> None:
        service.create_experience(
            actor=owner,
            profile_id=passport.id,
            payload=WorkExperienceCreateRequest(
                employer_name="Old",
                role_title="Mason",
                start_date=TODAY - timedelta(days=2000),
                end_date=TODAY - timedelta(days=1900),
                is_current=False,
            ),
        )
        summary = service.derive_experience_summary(passport)
        assert summary["earliest_start"] == TODAY - timedelta(days=2000)
        assert summary["latest_end"] == TODAY - timedelta(days=1900)


# --------------------------------------------------------------------------- #
# Catalogue listing                                                          #
# --------------------------------------------------------------------------- #
class TestCatalogueListing:
    def test_paging_does_not_repeat_or_skip_a_row(self, catalogue_service, catalogue) -> None:
        first, total = catalogue_service.list_trades(limit=1, offset=0)
        second, _ = catalogue_service.list_trades(limit=1, offset=1)
        third, _ = catalogue_service.list_trades(limit=1, offset=2)
        assert total == 3
        assert len({t.id for t in [*first, *second, *third]}) == 3

    def test_inactive_entries_are_hidden_unless_asked_for(
        self, catalogue_service, catalogue, db_session
    ) -> None:
        catalogue["trades"]["WELDING"].is_active = False
        db_session.flush()
        visible, _ = catalogue_service.list_trades()
        assert "WELDING" not in {t.code for t in visible}

        everything, _ = catalogue_service.list_trades(include_inactive=True)
        assert "WELDING" in {t.code for t in everything}

    def test_an_inactive_trade_cannot_be_selected(
        self, catalogue_service, catalogue, db_session
    ) -> None:
        catalogue["trades"]["WELDING"].is_active = False
        db_session.flush()
        with pytest.raises(CatalogueEntryNotFoundError):
            catalogue_service.get_trade_by_code("WELDING")

    def test_an_inactive_trade_still_resolves_when_inactive_is_allowed(
        self, catalogue_service, catalogue, db_session
    ) -> None:
        """History must stay resolvable so an old passport still renders."""
        catalogue["trades"]["WELDING"].is_active = False
        db_session.flush()
        assert catalogue_service.get_trade_by_code("WELDING", require_active=False).code == (
            "WELDING"
        )

    def test_codes_are_matched_case_insensitively(self, catalogue_service, catalogue) -> None:
        assert catalogue_service.get_trade_by_code("mAsOnRy").code == "MASONRY"
        assert "MASONRY" in catalogue_service.get_trades_by_codes(["masonry"])
        assert "NAKURU" in catalogue_service.get_counties_by_codes(["nakuru"])

    def test_empty_lookups_return_empty(self, catalogue_service) -> None:
        assert catalogue_service.get_trades_by_codes([]) == {}
        assert catalogue_service.get_skills_by_codes([]) == {}
        assert catalogue_service.get_counties_by_codes([]) == {}
        assert catalogue_service.worker_counts_by_trade([]) == {}
        assert catalogue_service.worker_counts_by_skill([]) == {}

    def test_worker_counts_exclude_deleted_passports(
        self, catalogue_service, catalogue, passport, db_session
    ) -> None:
        db_session.add(
            WorkerTrade(worker_profile_id=passport.id, trade_id=catalogue["trades"]["MASONRY"].id)
        )
        db_session.flush()
        trade_id = catalogue["trades"]["MASONRY"].id
        assert catalogue_service.worker_counts_by_trade([trade_id])[trade_id] == 1

        passport.deleted_at = utcnow()
        db_session.flush()
        # The join drops the row entirely rather than reporting zero, so a caller
        # must use .get(id, 0) rather than indexing.
        assert catalogue_service.worker_counts_by_trade([trade_id]).get(trade_id, 0) == 0

    def test_skills_can_be_filtered_by_trade(self, catalogue_service, catalogue) -> None:
        skills, total = catalogue_service.list_skills(trade_code="MASONRY")
        assert total == 0  # the fixture leaves trade_id unset
        assert skills == []

    def test_an_unknown_trade_filter_is_rejected(self, catalogue_service) -> None:
        with pytest.raises(CatalogueEntryNotFoundError):
            catalogue_service.list_skills(trade_code="TIME_TRAVEL")

    def test_counties_page(self, catalogue_service, catalogue) -> None:
        rows, total = catalogue_service.list_counties(limit=2, offset=1)
        assert total == 3
        assert len(rows) == 2


# --------------------------------------------------------------------------- #
# Loading helpers                                                            #
# --------------------------------------------------------------------------- #
class TestLoading:
    def test_counties_resolve_the_primary_and_the_preferred(
        self, service, catalogue, owner
    ) -> None:
        profile = service.create(
            actor=owner,
            payload=WorkerProfileCreateRequest(
                display_name="Loader",
                county_code="NAKURU",
                preferred_county_codes=["BOMET", "MOMBASA"],
            ),
        )
        primary, preferred = service.load_counties(profile)
        assert primary is not None and primary.code == "NAKURU"
        assert {c.code for c in preferred} == {"BOMET", "MOMBASA"}

    def test_a_passport_with_no_counties_resolves_to_none(self, service, passport) -> None:
        primary, preferred = service.load_counties(passport)
        assert primary is None
        assert preferred == []

    def test_an_unknown_id_is_not_found(self, service) -> None:
        with pytest.raises(WorkerProfileNotFoundError):
            service.get_by_id(uuid.uuid4())

    def test_a_row_lock_is_taken_for_update(self, service, passport) -> None:
        locked = service.get_for_update(passport.id)
        assert locked.id == passport.id

    def test_a_soft_deleted_row_cannot_be_locked(self, service, passport, db_session) -> None:
        passport.deleted_at = utcnow()
        db_session.flush()
        with pytest.raises(WorkerProfileNotFoundError):
            service.get_for_update(passport.id)

    def test_replacing_trades_replaces_rather_than_accumulates(
        self, service, passport, owner, catalogue, db_session
    ) -> None:
        updated = passport
        for codes in (["MASONRY"], ["PLUMBING"], ["MASONRY", "PLUMBING"]):
            payload = WorkerTradesUpdateRequest.model_validate(
                {"trades": [{"trade_code": c, "is_primary": c == codes[-1]} for c in codes]}
            )
            updated = service.replace_trades(actor=owner, profile_id=passport.id, payload=payload)
        rows = (
            db_session.execute(
                select(WorkerTrade).where(WorkerTrade.worker_profile_id == passport.id)
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2
        primaries = [row for row in rows if row.is_primary]
        assert len(primaries) == 1
        assert updated.primary_trade_id == primaries[0].trade_id
        assert updated.primary_trade_id == catalogue["trades"]["PLUMBING"].id
