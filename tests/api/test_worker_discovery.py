"""Worker discovery: filters, visibility and the privacy boundary.

The assertions that matter here are negative. A test that only checks a private
worker *is* returned proves nothing; what has to hold is that a private worker is
never returned and that no contact detail appears in a response body at all.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
import uuid

import pytest

from app.core.constants import (
    ProfileVisibility,
    SkillProficiency,
    VerificationStatus,
    VerificationTargetType,
)
from app.db.base import utcnow
from app.db.models.catalogue import County, Skill, Trade
from app.db.models.verification import Verification, VerificationRequest, VerificationRequestStatus
from app.db.models.worker import (
    Credential,
    WorkerPreferredCounty,
    WorkerProfile,
    WorkerSkill,
    WorkerTrade,
    WorkExperience,
)
from app.utils.dates import utc_today

pytestmark = [pytest.mark.api, pytest.mark.integration]

TODAY = utc_today()


@pytest.fixture
def catalogue(db_session):
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


def make_passport(
    db_session,
    make_user,
    catalogue,
    *,
    visibility: str = ProfileVisibility.DISCOVERABLE.value,
    display_name: str = "Amina Wanjiru",
    county: str | None = None,
    trade: str | None = "MASONRY",
    skill: str | None = None,
    declared_years: Decimal | None = None,
    open_to_work: bool = True,
):
    user = make_user()
    from app.db.models.worker import WorkerProfile

    profile = WorkerProfile(
        user_id=user.id,
        display_name=display_name,
        visibility=visibility,
        county_id=catalogue["counties"][county].id if county else None,
        self_declared_experience_years=declared_years,
        is_open_to_opportunities=open_to_work,
        availability_status="AVAILABLE",
    )
    db_session.add(profile)
    db_session.flush()
    if trade:
        db_session.add(
            WorkerTrade(
                worker_profile_id=profile.id,
                trade_id=catalogue["trades"][trade].id,
                is_primary=True,
            )
        )
    if skill:
        db_session.add(
            WorkerSkill(
                worker_profile_id=profile.id,
                skill_id=catalogue["skills"][skill].id,
                proficiency=SkillProficiency.EXPERT.value,
            )
        )
    db_session.flush()
    return profile


@pytest.fixture
def headers(client, make_user):
    def _factory(email: str) -> dict[str, str]:
        r = client.post(
            "/auth/login",
            json={"email": email, "password": "Correct-Horse-9-Battery"},
        )
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['data']['tokens']['access_token']}"}

    return _factory


class TestVisibility:
    def test_a_private_worker_never_appears(self, client, db_session, make_user, catalogue) -> None:
        make_passport(
            db_session,
            make_user,
            catalogue,
            visibility=ProfileVisibility.PRIVATE.value,
            display_name="Hidden Person",
        )
        body = client.get("/workers").text
        assert "Hidden Person" not in body

    def test_discoverable_and_public_workers_appear(
        self, client, db_session, make_user, catalogue
    ) -> None:
        make_passport(
            db_session,
            make_user,
            catalogue,
            visibility=ProfileVisibility.DISCOVERABLE.value,
            display_name="Discoverable One",
        )
        make_passport(
            db_session,
            make_user,
            catalogue,
            visibility=ProfileVisibility.PUBLIC.value,
            display_name="Public One",
        )
        names = {row["display_name"] for row in client.get("/workers").json()["data"]}
        assert {"Discoverable One", "Public One"} <= names

    def test_search_is_available_without_authentication(
        self, client, db_session, make_user, catalogue
    ) -> None:
        """PUBLIC means public. A 401 here would make the visibility setting a lie."""
        make_passport(db_session, make_user, catalogue, visibility=ProfileVisibility.PUBLIC.value)
        assert client.get("/workers").status_code == 200

    def test_a_soft_deleted_passport_is_absent(
        self, client, db_session, make_user, catalogue
    ) -> None:
        profile = make_passport(db_session, make_user, catalogue, display_name="Deleted One")
        profile.deleted_at = utcnow()
        db_session.flush()
        assert "Deleted One" not in client.get("/workers").text


class TestPrivacyBoundary:
    """The response type has no contact field, so assert on the raw body."""

    @pytest.fixture
    def exposed(self, client, db_session, make_user, catalogue):
        profile = make_passport(
            db_session, make_user, catalogue, visibility=ProfileVisibility.PUBLIC.value
        )
        row = db_session.get(WorkerProfile, profile.id)
        row.phone_number = "0712345678"
        row.contact_email = "private@example.com"
        row.contact_name = "Private Name"
        row.contact_phone = "0722000000"
        db_session.flush()
        return profile

    def test_no_contact_detail_appears_in_any_search_row(self, client, exposed) -> None:
        body = client.get("/workers").text
        for leak in (
            "0712345678",
            "private@example.com",
            "Private Name",
            "0722000000",
            "phone_number",
            "contact_email",
            "contact_name",
        ):
            assert leak not in body, f"search leaked {leak}"

    def test_an_employer_cannot_read_another_workers_private_block(
        self, client, db_session, make_user, catalogue, exposed, headers
    ) -> None:
        employer = make_user()
        response = client.get(f"/workers/{exposed.id}", headers=headers(employer.email))
        assert response.status_code == 200
        for leak in ("0712345678", "private@example.com"):
            assert leak not in response.text

    def test_there_is_no_search_parameter_that_widens_the_row(
        self, client, db_session, make_user, catalogue, exposed
    ) -> None:
        """No filter combination may surface a contact field."""
        for query in (
            "",
            "?trade=MASONRY",
            "?county=NAKURU",
            "?has_credentials=true",
            "?page_size=100",
        ):
            body = client.get(f"/workers{query}").text
            assert "0712345678" not in body
            assert "private@example.com" not in body

    def test_no_score_or_rating_field_exists(self, client, exposed) -> None:
        row = client.get("/workers").json()["data"][0]
        for forbidden in (
            "score",
            "rating",
            "stars",
            "rank",
            "trust",
            "reputation",
            "match_score",
        ):
            assert forbidden not in row, f"search row exposes a {forbidden} field"


class TestFilters:
    @pytest.fixture
    def populated(self, client, db_session, make_user, catalogue):
        mason = make_passport(
            db_session,
            make_user,
            catalogue,
            display_name="Nakuru Mason",
            county="NAKURU",
            skill="BLOCK_LAYING",
            declared_years=Decimal("8"),
        )
        db_session.add(
            WorkerPreferredCounty(
                worker_profile_id=mason.id, county_id=catalogue["counties"]["MOMBASA"].id
            )
        )
        plumber = make_passport(
            db_session,
            make_user,
            catalogue,
            display_name="Bomet Plumber",
            county="BOMET",
            trade="PLUMBING",
            skill="PIPE_FITTING",
        )
        db_session.add(
            WorkerPreferredCounty(
                worker_profile_id=plumber.id, county_id=catalogue["counties"]["NAKURU"].id
            )
        )
        closed = make_passport(
            db_session,
            make_user,
            catalogue,
            display_name="Closed For Work",
            trade="WELDING",
            open_to_work=False,
        )
        db_session.flush()
        return {"mason": mason, "plumber": plumber, "closed": closed}

    def names(self, client, query: str = "") -> set[str]:
        return {row["display_name"] for row in client.get(f"/workers{query}").json()["data"]}

    def test_filter_by_trade(self, client, populated) -> None:
        assert self.names(client, "?trade=MASONRY") == {"Nakuru Mason"}
        assert self.names(client, "?trade=PLUMBING") == {"Bomet Plumber"}

    def test_filter_by_skill(self, client, populated) -> None:
        assert self.names(client, "?skill=PIPE_FITTING") == {"Bomet Plumber"}

    def test_filter_by_own_county(self, client, populated) -> None:
        assert "Bomet Plumber" in self.names(client, "?county=BOMET")

    def test_a_preferred_work_county_also_matches(self, client, populated) -> None:
        """The plumber is based in Bomet but will work in Nakuru."""
        assert "Bomet Plumber" in self.names(client, "?county=NAKURU")

    def test_filter_by_minimum_experience(self, client, populated) -> None:
        assert self.names(client, "?minimum_experience_years=5") == {"Nakuru Mason"}
        assert self.names(client, "?minimum_experience_years=50") == set()

    def test_availability_filter_excludes_a_closed_passport(self, client, populated) -> None:
        assert "Closed For Work" in self.names(client)
        assert "Closed For Work" not in self.names(client, "?availability=AVAILABLE")

    def test_filters_are_conjunctive(self, client, populated) -> None:
        assert self.names(client, "?trade=MASONRY&county=NAKURU") == {"Nakuru Mason"}
        # The mason prefers MOMBASA, so trade and county must both hold for an
        # intersection: the plumber is in BOMET and is not a mason.
        assert self.names(client, "?trade=MASONRY&county=BOMET") == set()
        assert self.names(client, "?trade=PLUMBING&county=NAKURU") == {"Bomet Plumber"}

    def test_an_unknown_catalogue_code_matches_nothing(self, client, populated) -> None:
        """Silently dropping a location filter would return unrequested workers."""
        assert self.names(client, "?county=ATLANTIS") == set()
        assert self.names(client, "?trade=TIME_TRAVEL") == set()

    def test_filter_names_are_case_insensitive(self, client, populated) -> None:
        assert self.names(client, "?trade=masonry") == {"Nakuru Mason"}

    def test_an_unknown_sort_is_rejected_rather_than_ignored(self, client) -> None:
        assert client.get("/workers?sort=nonsense").status_code == 422

    def test_a_ranking_sort_is_rejected(self, client) -> None:
        """There is no score to sort by, by design."""
        assert client.get("/workers?sort=match_score").status_code == 422

    def test_pagination(self, client, db_session, make_user, catalogue) -> None:
        for index in range(5):
            make_passport(db_session, make_user, catalogue, display_name=f"Worker {index}")
        first = client.get("/workers?page=1&page_size=2").json()
        second = client.get("/workers?page=2&page_size=2").json()
        assert first["meta"]["total_items"] == 5
        assert len(first["data"]) == 2
        assert {r["id"] for r in first["data"]}.isdisjoint({r["id"] for r in second["data"]})

    def test_pagination_abuse_is_refused(self, client) -> None:
        assert client.get("/workers?page_size=100000").status_code == 422
        assert client.get("/workers?page=99999999").status_code == 422


class TestVerifiedClaimFilters:
    def _verify(self, db_session, profile, record, status: str):

        request = VerificationRequest(
            worker_profile_id=profile.id,
            requested_by_user_id=profile.user_id,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=record.id,
            verifier_email="foreman@example.com",
            status=VerificationRequestStatus.VERIFIED.value,
            requested_at=utcnow(),
            expires_at=utcnow() + timedelta(days=30),
        )
        db_session.add(request)
        db_session.flush()
        verification = Verification(
            verification_request_id=request.id,
            worker_profile_id=profile.id,
            requested_by_user_id=profile.user_id,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=record.id,
            status=status,
            verifier_display_name="Foreman Name",
            verified_at=utcnow(),
        )
        db_session.add(verification)
        db_session.flush()
        return verification

    def _experience(self, db_session, profile):
        record = WorkExperience(
            worker_profile_id=profile.id,
            employer_name="Mwangaza Ltd",
            role_title="Mason",
            start_date=TODAY - timedelta(days=900),
            is_current=True,
        )
        db_session.add(record)
        db_session.flush()
        return record

    def test_has_verified_experience_true(self, client, db_session, make_user, catalogue) -> None:
        profile = make_passport(db_session, make_user, catalogue)
        record = self._experience(db_session, profile)
        self._verify(db_session, profile, record, VerificationStatus.VERIFIED.value)
        ids = {r["id"] for r in client.get("/workers?has_verified_experience=true").json()["data"]}
        assert str(profile.id) in ids

    def test_an_unverified_worker_is_excluded_by_the_true_filter(
        self, client, db_session, make_user, catalogue
    ) -> None:
        make_passport(db_session, make_user, catalogue)
        assert client.get("/workers?has_verified_experience=true").json()["data"] == []

    def test_a_rejected_verification_does_not_count(
        self, client, db_session, make_user, catalogue
    ) -> None:
        profile = make_passport(db_session, make_user, catalogue)
        record = self._experience(db_session, profile)
        self._verify(db_session, profile, record, VerificationStatus.REJECTED.value)
        ids = {r["id"] for r in client.get("/workers?has_verified_experience=false").json()["data"]}
        assert str(profile.id) in ids

    def test_deleting_a_claim_withdraws_its_verification(
        self, client, db_session, make_user, catalogue
    ) -> None:
        """Otherwise a worker could drop an unverifiable record and keep the badge."""
        profile = make_passport(db_session, make_user, catalogue)
        record = self._experience(db_session, profile)
        self._verify(db_session, profile, record, VerificationStatus.VERIFIED.value)
        assert str(profile.id) in {
            r["id"] for r in client.get("/workers?has_verified_experience=true").json()["data"]
        }
        record.deleted_at = utcnow()
        db_session.flush()
        assert str(profile.id) not in {
            r["id"] for r in client.get("/workers?has_verified_experience=true").json()["data"]
        }

    def test_has_credentials(self, client, db_session, make_user, catalogue) -> None:
        profile = make_passport(db_session, make_user, catalogue)
        db_session.add(
            Credential(
                worker_profile_id=profile.id,
                title="Trade Test Certificate",
                credential_type="TRADE_TEST_CERTIFICATE",
            )
        )
        db_session.flush()
        ids = {r["id"] for r in client.get("/workers?has_credentials=true").json()["data"]}
        assert str(profile.id) in ids

    def test_a_deleted_credential_does_not_count(
        self, client, db_session, make_user, catalogue
    ) -> None:
        profile = make_passport(db_session, make_user, catalogue)
        credential = Credential(
            worker_profile_id=profile.id,
            title="Trade Test Certificate",
            credential_type="TRADE_TEST_CERTIFICATE",
        )
        db_session.add(credential)
        db_session.flush()
        credential.deleted_at = utcnow()
        db_session.flush()
        ids = {r["id"] for r in client.get("/workers?has_credentials=true").json()["data"]}
        assert str(profile.id) not in ids


class TestDerivedExperience:
    def test_overlapping_experiences_are_not_double_counted(
        self, client, db_session, make_user, catalogue
    ) -> None:
        profile = make_passport(db_session, make_user, catalogue)
        for start, end in (
            (TODAY - timedelta(days=730), TODAY - timedelta(days=365)),
            (TODAY - timedelta(days=700), TODAY - timedelta(days=400)),
        ):
            db_session.add(
                WorkExperience(
                    worker_profile_id=profile.id,
                    employer_name="Somewhere",
                    role_title="Mason",
                    start_date=start,
                    end_date=end,
                    is_current=False,
                )
            )
        db_session.flush()
        row = next(r for r in client.get("/workers").json()["data"] if r["id"] == str(profile.id))
        # The union is 365 days, not the 630 a naive sum would report.
        assert float(row["derived_experience_years"]) == pytest.approx(1.0, abs=0.05)

    def test_derived_and_declared_are_reported_separately(
        self, client, db_session, make_user, catalogue
    ) -> None:
        """They are different claims about the same worker and are never merged."""
        profile = make_passport(db_session, make_user, catalogue, declared_years=Decimal("20"))
        row = next(r for r in client.get("/workers").json()["data"] if r["id"] == str(profile.id))
        assert float(row["self_declared_experience_years"]) == 20.0
        assert float(row["derived_experience_years"]) == 0.0
