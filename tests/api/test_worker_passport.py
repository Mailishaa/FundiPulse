"""End-to-end tests for the Work Passport: profile, trades, skills, experiences, projects.

Real HTTP, real database, real constraints. The privacy assertions are the point:
a test that only checks the happy path would pass while a contact detail leaked.
"""

from __future__ import annotations

from datetime import timedelta
import uuid

import pytest

from app.core.constants import ContactPreference, ProfileVisibility
from app.db.models.catalogue import County, Skill, Trade
from app.schemas.workers import SkillRefResponse
from app.utils.dates import utc_today

pytestmark = [pytest.mark.api, pytest.mark.integration]

TODAY = utc_today()


@pytest.fixture
def catalogue(db_session):
    """Insert trades, skills and counties, and return them keyed by code."""
    counties = {
        code: County(id=uuid.uuid4(), code=code, name=name)
        for code, name in (("NAKURU", "Nakuru"), ("BOMET", "Bomet"), ("MOMBASA", "Mombasa"))
    }
    trades = {
        code: Trade(id=uuid.uuid4(), code=code, name=name)
        for code, name in (("MASONRY", "Masonry"), ("PLUMBING", "Plumbing"), ("WELDING", "Welding"))
    }
    skills = {
        code: Skill(id=uuid.uuid4(), code=code, name=name, trade_id=trade_id)
        for code, name, trade_id in (
            ("BLOCK_LAYING", "Block laying", trades["MASONRY"].id),
            ("PIPE_FITTING", "Pipe fitting", trades["PLUMBING"].id),
            ("WELDING_QUALIFICATION", "Welding qualification", None),
        )
    }
    db_session.add_all([*counties.values(), *trades.values(), *skills.values()])
    db_session.flush()
    return {"counties": counties, "trades": trades, "skills": skills}


@pytest.fixture
def worker(client, make_user, catalogue):
    """A registered worker with a passport and a valid bearer token."""
    user = make_user()
    response = client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "Correct-Horse-9-Battery"},
    )
    assert response.status_code == 200, response.text
    token = response.json()["data"]["tokens"]["access_token"]
    created = client.post(
        "/api/v1/workers/me/profile",
        headers={"Authorization": f"Bearer {token}"},
        json={"display_name": "Amina Wanjiru", "primary_trade_code": "MASONRY"},
    )
    assert created.status_code == 201, created.text
    return {
        "user": user,
        "token": token,
        "headers": {"Authorization": f"Bearer {token}"},
        "profile_id": created.json()["data"]["id"],
    }


# --------------------------------------------------------------------------- #
# Passport                                                                    #
# --------------------------------------------------------------------------- #
class TestProfile:
    def test_creates_a_passport(self, client, worker) -> None:
        response = client.get("/api/v1/workers/me/profile", headers=worker["headers"])
        assert response.status_code == 200
        assert response.json()["data"]["display_name"] == "Amina Wanjiru"

    def test_defaults_to_private_and_not_contactable(self, client, worker) -> None:
        data = client.get("/api/v1/workers/me/profile", headers=worker["headers"]).json()["data"]
        assert data["visibility"] == ProfileVisibility.PRIVATE.value
        assert data["contact_preference"] == ContactPreference.NONE.value
        assert data["is_contactable"] is False

    def test_one_passport_per_account(self, client, worker) -> None:
        response = client.post(
            "/api/v1/workers/me/profile",
            headers=worker["headers"],
            json={"display_name": "Second Attempt"},
        )
        assert response.status_code == 409

    def test_requires_authentication(self, client) -> None:
        assert client.get("/api/v1/workers/me/profile").status_code == 401

    def test_unknown_trade_code_is_rejected(self, client, make_user) -> None:
        user = make_user()
        response = client.post(
            "/api/v1/workers/me/profile",
            headers=_headers(client, user.email),
            json={"display_name": "Nobody", "primary_trade_code": "TIME_TRAVEL"},
        )
        assert response.status_code == 422

    @pytest.mark.parametrize("name", ["A", "", "   x" * 60])
    def test_rejects_a_bad_display_name(self, client, make_user, name) -> None:
        user = make_user()
        token = _token(client, user.email)
        response = client.post(
            "/api/v1/workers/me/profile",
            headers={"Authorization": f"Bearer {token}"},
            json={"display_name": name},
        )
        assert response.status_code == 422

    @pytest.mark.parametrize(
        ("phone", "stored"),
        [
            ("0712345678", "0712345678"),
            ("+254712345678", "0712345678"),
            ("0712 345 678", "0712345678"),
            ("020-123-4567", "0201234567"),
        ],
    )
    def test_accepts_kenyan_phone_formats(self, client, make_user, phone, stored) -> None:
        user = make_user()
        response = client.post(
            "/api/v1/workers/me/profile",
            headers=_headers(client, user.email),
            json={"display_name": "Phone Tester", "phone_number": phone},
        )
        assert response.status_code == 201, response.text
        assert response.json()["data"]["phone_number"] == stored

    @pytest.mark.parametrize(
        "phone", ["12345", "0712345678901", "not-a-number", "+447712345678", "012345678"]
    )
    def test_rejects_non_kenyan_phone_formats(self, client, make_user, phone) -> None:
        user = make_user()
        response = client.post(
            "/api/v1/workers/me/profile",
            headers=_headers(client, user.email),
            json={"display_name": "Phone Tester", "phone_number": phone},
        )
        assert response.status_code == 422

    def test_available_soon_requires_a_date(self, client, make_user) -> None:
        user = make_user()
        token = _token(client, user.email)
        response = client.post(
            "/api/v1/workers/me/profile",
            headers={"Authorization": f"Bearer {token}"},
            json={"display_name": "Soon", "availability_status": "AVAILABLE_SOON"},
        )
        assert response.status_code == 422

    def test_available_soon_with_a_date_is_accepted(self, client, make_user) -> None:
        user = make_user()
        token = _token(client, user.email)
        response = client.post(
            "/api/v1/workers/me/profile",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "display_name": "Soon",
                "availability_status": "AVAILABLE_SOON",
                "available_from": str(TODAY + timedelta(days=14)),
            },
        )
        assert response.status_code == 201
        assert response.json()["data"]["available_from"] is not None

    def test_switching_away_from_available_soon_clears_the_date(self, client, worker) -> None:
        client.patch(
            "/api/v1/workers/me/profile",
            headers=worker["headers"],
            json={"availability_status": "AVAILABLE_SOON", "available_from": str(TODAY)},
        )
        response = client.patch(
            "/api/v1/workers/me/profile",
            headers=worker["headers"],
            json={"availability_status": "AVAILABLE"},
        )
        assert response.status_code == 200
        assert response.json()["data"]["available_from"] is None

    def test_mass_assignment_of_visibility_beyond_the_permitted_set_is_rejected(
        self, client, worker
    ) -> None:
        response = client.patch(
            "/api/v1/workers/me/profile",
            headers=worker["headers"],
            json={"user_id": str(uuid.uuid4()), "is_email_verified": True},
        )
        assert response.status_code == 422


class TestPrivacyBoundary:
    """The control is structural: the public schema has no contact field."""

    def test_the_owner_sees_their_own_contact_details(self, client, worker) -> None:
        client.patch(
            "/api/v1/workers/me/profile",
            headers=worker["headers"],
            json={
                "phone_number": "0712345678",
                "contact_email": "personal@example.com",
                "visibility": "DISCOVERABLE",
                "contact_preference": "IN_APP",
            },
        )
        data = client.get("/api/v1/workers/me/profile", headers=worker["headers"]).json()["data"]
        assert data["phone_number"] == "0712345678"
        assert data["contact_email"] == "personal@example.com"
        assert data["is_contactable"] is True

    def test_another_user_never_sees_contact_details(self, client, worker, make_user) -> None:
        client.patch(
            "/api/v1/workers/me/profile",
            headers=worker["headers"],
            json={
                "phone_number": "0712345678",
                "contact_email": "personal@example.com",
                "visibility": "PUBLIC",
            },
        )
        stranger = make_user()
        response = client.get(
            f"/api/v1/workers/{worker['profile_id']}", headers=_headers(client, stranger.email)
        )
        assert response.status_code == 200
        body = response.text
        assert "0712345678" not in body, "phone number leaked"
        assert "personal@example.com" not in body, "contact email leaked"
        assert "phone_number" not in body
        assert "contact_email" not in body

    def test_anonymous_never_sees_contact_details(self, client, worker) -> None:
        client.patch(
            "/api/v1/workers/me/profile",
            headers=worker["headers"],
            json={"phone_number": "0712345678", "visibility": "PUBLIC"},
        )
        response = client.get(f"/api/v1/workers/{worker['profile_id']}")
        assert response.status_code == 200
        assert "0712345678" not in response.text

    def test_a_private_passport_is_a_404_not_a_403(self, client, worker, make_user) -> None:
        """403 would confirm the passport exists."""
        stranger = make_user()
        response = client.get(
            f"/api/v1/workers/{worker['profile_id']}", headers=_headers(client, stranger.email)
        )
        assert response.status_code == 404

    def test_confidential_projects_are_absent_from_the_public_view(self, client, worker) -> None:
        client.post(
            "/api/v1/workers/me/projects",
            headers=worker["headers"],
            json={
                "name": "Confidential Hospital Wing",
                "role_title": "Mason",
                "is_confidential": True,
            },
        )
        client.patch(
            "/api/v1/workers/me/profile",
            headers=worker["headers"],
            json={"visibility": "PUBLIC"},
        )
        assert (
            "Confidential Hospital Wing"
            not in client.get(f"/api/v1/workers/{worker['profile_id']}").text
        )

    def test_a_worker_always_sees_their_own_private_passport(self, client, worker) -> None:
        assert (
            client.get(
                f"/api/v1/workers/{worker['profile_id']}", headers=worker["headers"]
            ).status_code
            == 200
        )


class TestTradesAndSkills:
    def test_replaces_the_trade_list(self, client, worker) -> None:
        response = client.put(
            "/api/v1/workers/me/trades",
            headers=worker["headers"],
            json={
                "trades": [
                    {"trade_code": "PLUMBING", "is_primary": True},
                    {"trade_code": "WELDING"},
                ]
            },
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["primary_trade"]["code"] == "PLUMBING"
        assert {t["code"] for t in data["trades"]} == {"PLUMBING", "WELDING"}

    def test_two_primary_trades_are_rejected(self, client, worker) -> None:
        response = client.put(
            "/api/v1/workers/me/trades",
            headers=worker["headers"],
            json={
                "trades": [
                    {"trade_code": "MASONRY", "is_primary": True},
                    {"trade_code": "PLUMBING", "is_primary": True},
                ]
            },
        )
        assert response.status_code == 422

    def test_a_duplicate_trade_is_rejected(self, client, worker) -> None:
        response = client.put(
            "/api/v1/workers/me/trades",
            headers=worker["headers"],
            json={"trades": [{"trade_code": "MASONRY"}, {"trade_code": "MASONRY"}]},
        )
        assert response.status_code == 422

    def test_an_unknown_trade_is_rejected(self, client, worker) -> None:
        response = client.put(
            "/api/v1/workers/me/trades",
            headers=worker["headers"],
            json={"trades": [{"trade_code": "NOT_A_TRADE"}]},
        )
        assert response.status_code == 422

    def test_replacing_trades_does_not_leave_a_stale_primary(self, client, worker) -> None:
        client.put(
            "/api/v1/workers/me/trades",
            headers=worker["headers"],
            json={"trades": [{"trade_code": "MASONRY", "is_primary": True}]},
        )
        response = client.put(
            "/api/v1/workers/me/trades",
            headers=worker["headers"],
            json={"trades": [{"trade_code": "PLUMBING"}]},
        )
        data = response.json()["data"]
        assert data["primary_trade"] is None
        assert len(data["trades"]) == 1

    def test_replaces_the_skill_list(self, client, worker) -> None:
        response = client.put(
            "/api/v1/workers/me/skills",
            headers=worker["headers"],
            json={
                "skills": [
                    {"skill_code": "BLOCK_LAYING", "proficiency": "EXPERT"},
                    {"skill_code": "PIPE_FITTING"},
                ]
            },
        )
        assert response.status_code == 200
        assert {s["code"] for s in response.json()["data"]["skills"]} == {
            "BLOCK_LAYING",
            "PIPE_FITTING",
        }

    def test_proficiency_is_labelled_as_declared(self, client, worker) -> None:
        """The payload carries no flag, so the contract must label it instead."""
        client.put(
            "/api/v1/workers/me/skills",
            headers=worker["headers"],
            json={"skills": [{"skill_code": "BLOCK_LAYING", "proficiency": "EXPERT"}]},
        )
        data = client.get("/api/v1/workers/me/profile", headers=worker["headers"]).json()["data"]
        assert data["skills"][0]["proficiency"] == "EXPERT"
        assert "self-declared" in SkillRefResponse.model_fields["proficiency"].description.lower()

    def test_replaces_preferred_counties(self, client, worker) -> None:
        response = client.put(
            "/api/v1/workers/me/preferred-counties",
            headers=worker["headers"],
            json={"county_codes": ["NAKURU", "BOMET"]},
        )
        assert response.status_code == 200
        assert {c["code"] for c in response.json()["data"]["preferred_counties"]} == {
            "NAKURU",
            "BOMET",
        }

    def test_an_unknown_county_is_rejected(self, client, worker) -> None:
        response = client.put(
            "/api/v1/workers/me/preferred-counties",
            headers=worker["headers"],
            json={"county_codes": ["ATLANTIS"]},
        )
        assert response.status_code == 422


class TestWorkExperience:
    def _create(self, client, worker, **overrides):
        payload = {
            "employer_name": "Mwangaza Construction Ltd",
            "role_title": "Site Mason",
            "start_date": str(TODAY - timedelta(days=730)),
            "is_current": False,
            "end_date": str(TODAY - timedelta(days=400)),
            "trade_code": "MASONRY",
        }
        payload.update(overrides)
        return client.post(
            "/api/v1/workers/me/experiences", headers=worker["headers"], json=payload
        )

    def test_records_and_returns_a_claim(self, client, worker) -> None:
        response = self._create(client, worker)
        assert response.status_code == 201, response.text
        assert response.json()["data"]["employer_name"] == "Mwangaza Construction Ltd"

    def test_a_fresh_claim_is_not_verified(self, client, worker) -> None:
        response = self._create(client, worker)
        assert response.json()["data"]["verification"] is None
        assert "is_verified" not in response.text

    def test_current_role_needs_no_end_date(self, client, worker) -> None:
        response = self._create(client, worker, is_current=True, end_date=None)
        assert response.status_code == 201
        assert response.json()["data"]["is_current"] is True

    def test_no_end_date_and_not_current_is_rejected(self, client, worker) -> None:
        response = self._create(client, worker, is_current=False, end_date=None)
        assert response.status_code == 422

    def test_a_current_role_with_an_end_date_is_rejected(self, client, worker) -> None:
        response = self._create(client, worker, is_current=True)
        assert response.status_code == 422

    def test_end_before_start_is_rejected(self, client, worker) -> None:
        response = self._create(
            client,
            worker,
            start_date=str(TODAY - timedelta(days=100)),
            end_date=str(TODAY - timedelta(days=500)),
        )
        assert response.status_code == 422

    def test_a_future_start_is_rejected(self, client, worker) -> None:
        response = self._create(client, worker, start_date=str(TODAY + timedelta(days=30)))
        assert response.status_code == 422

    def test_lists_and_reads_back(self, client, worker) -> None:
        created = self._create(client, worker).json()["data"]
        listing = client.get("/api/v1/workers/me/experiences", headers=worker["headers"])
        assert listing.status_code == 200
        assert listing.json()["meta"]["total_items"] == 1

        single = client.get(
            f"/api/v1/workers/me/experiences/{created['id']}", headers=worker["headers"]
        )
        assert single.status_code == 200
        assert single.json()["data"]["id"] == created["id"]

    def test_paginates(self, client, worker) -> None:
        for _ in range(3):
            self._create(client, worker)
        response = client.get(
            "/api/v1/workers/me/experiences?page=1&page_size=2", headers=worker["headers"]
        )
        assert len(response.json()["data"]) == 2
        assert response.json()["meta"]["total_items"] == 3

    def test_deletes_are_soft(self, client, worker) -> None:
        created = self._create(client, worker).json()["data"]
        assert (
            client.delete(
                f"/api/v1/workers/me/experiences/{created['id']}", headers=worker["headers"]
            ).status_code
            == 200
        )
        assert (
            client.get(
                f"/api/v1/workers/me/experiences/{created['id']}", headers=worker["headers"]
            ).status_code
            == 404
        )
        assert (
            client.get("/api/v1/workers/me/experiences", headers=worker["headers"]).json()["meta"][
                "total_items"
            ]
            == 0
        )

    def test_an_unknown_id_is_a_404(self, client, worker) -> None:
        assert (
            client.get(
                f"/api/v1/workers/me/experiences/{uuid.uuid4()}", headers=worker["headers"]
            ).status_code
            == 404
        )

    def test_derived_experience_merges_overlapping_roles(self, client, worker) -> None:
        """Concurrent jobs must not double-count."""
        self._create(
            client,
            worker,
            employer_name="Alpha",
            start_date=str(TODAY - timedelta(days=730)),
            end_date=str(TODAY - timedelta(days=365)),
        )
        self._create(
            client,
            worker,
            employer_name="Beta",
            start_date=str(TODAY - timedelta(days=700)),
            end_date=str(TODAY - timedelta(days=400)),
        )
        summary = client.get("/api/v1/workers/me/experience-summary", headers=worker["headers"])
        assert summary.status_code == 200, summary.text
        data = summary.json()["data"]
        # The outer record spans 365 days and the second sits wholly inside it, so
        # the union is 365 days. Summing the two would report 1030 days.
        assert float(data["total_years"]) == pytest.approx(1.0, abs=0.05)
        assert data["record_count"] == 2
        assert data["earliest_start"] is not None

    def test_no_experiences_yields_zero(self, client, worker) -> None:
        data = client.get(
            "/api/v1/workers/me/experience-summary", headers=worker["headers"]
        ).json()["data"]
        assert float(data["total_years"]) == 0.0
        assert data["record_count"] == 0


class TestIdor:
    """Substituting another worker's id must not reach their data."""

    def test_cannot_read_another_workers_experience(self, client, worker, make_user) -> None:
        created = client.post(
            "/api/v1/workers/me/experiences",
            headers=worker["headers"],
            json={
                "employer_name": "Secret Employer",
                "role_title": "Mason",
                "start_date": str(TODAY - timedelta(days=100)),
                "is_current": True,
            },
        ).json()["data"]

        attacker = make_user()
        _create_passport(client, attacker)
        response = client.get(
            f"/api/v1/workers/me/experiences/{created['id']}",
            headers=_headers(client, attacker.email),
        )
        assert response.status_code == 404
        assert "Secret Employer" not in response.text

    def test_cannot_modify_another_workers_experience(self, client, worker, make_user) -> None:
        created = client.post(
            "/api/v1/workers/me/experiences",
            headers=worker["headers"],
            json={
                "employer_name": "Secret Employer",
                "role_title": "Mason",
                "start_date": str(TODAY - timedelta(days=100)),
                "is_current": True,
            },
        ).json()["data"]

        attacker = make_user()
        _create_passport(client, attacker)
        response = client.patch(
            f"/api/v1/workers/me/experiences/{created['id']}",
            headers=_headers(client, attacker.email),
            json={"employer_name": "Hijacked"},
        )
        assert response.status_code == 404

        still_there = client.get(
            f"/api/v1/workers/me/experiences/{created['id']}", headers=worker["headers"]
        )
        assert still_there.json()["data"]["employer_name"] == "Secret Employer"

    def test_cannot_delete_another_workers_project(self, client, worker, make_user) -> None:
        project = client.post(
            "/api/v1/workers/me/projects",
            headers=worker["headers"],
            json={"name": "Private Site", "role_title": "Mason"},
        ).json()["data"]

        attacker = make_user()
        _create_passport(client, attacker)
        response = client.delete(
            f"/api/v1/workers/me/projects/{project['id']}",
            headers=_headers(client, attacker.email),
        )
        assert response.status_code == 404
        assert (
            client.get(
                f"/api/v1/workers/me/projects/{project['id']}", headers=worker["headers"]
            ).status_code
            == 200
        )

    def test_an_employer_cannot_modify_a_worker_passport(self, client, worker, make_user) -> None:
        employer = make_user()
        headers = _headers(client, employer.email)
        for payload in (
            {"display_name": "Rewritten By Employer"},
            {"visibility": "PUBLIC"},
        ):
            response = client.patch("/api/v1/workers/me/profile", headers=headers, json=payload)
            assert response.status_code in {403, 404}
        unchanged = client.get("/api/v1/workers/me/profile", headers=worker["headers"]).json()[
            "data"
        ]
        assert unchanged["display_name"] == "Amina Wanjiru"
        assert unchanged["visibility"] == ProfileVisibility.PRIVATE.value

    def test_an_admin_may_read_but_still_gets_no_contact_leak_in_public_view(
        self, client, worker, make_admin
    ) -> None:
        client.patch(
            "/api/v1/workers/me/profile",
            headers=worker["headers"],
            json={"phone_number": "0712345678", "visibility": "PUBLIC"},
        )
        admin = make_admin()
        response = client.get(
            f"/api/v1/workers/{worker['profile_id']}", headers=_headers(client, admin.email)
        )
        assert response.status_code == 200
        assert "0712345678" not in response.text, "admin role must not widen the public schema"


class TestProjects:
    def test_documents_a_project(self, client, worker) -> None:
        response = client.post(
            "/api/v1/workers/me/projects",
            headers=worker["headers"],
            json={
                "name": "Nakuru Mall Extension",
                "role_title": "Lead Mason",
                "project_type": "COMMERCIAL",
                "work_performed": "Set out and supervised block laying to first floor.",
                "start_date": str(TODAY - timedelta(days=400)),
                "end_date": str(TODAY - timedelta(days=100)),
                "county_code": "NAKURU",
            },
        )
        assert response.status_code == 201, response.text
        assert response.json()["data"]["project_type"] == "COMMERCIAL"
        assert response.json()["data"]["county_code"] == "NAKURU"

    def test_an_unknown_project_type_is_rejected(self, client, worker) -> None:
        response = client.post(
            "/api/v1/workers/me/projects",
            headers=worker["headers"],
            json={"name": "X", "role_title": "Mason", "project_type": "SPACE_STATION"},
        )
        assert response.status_code == 422

    def test_the_role_on_the_project_is_required(self, client, worker) -> None:
        response = client.post(
            "/api/v1/workers/me/projects",
            headers=worker["headers"],
            json={"name": "Nameless Role"},
        )
        assert response.status_code == 422

    def test_crud_round_trip(self, client, worker) -> None:
        created = client.post(
            "/api/v1/workers/me/projects",
            headers=worker["headers"],
            json={"name": "Warehouse", "role_title": "Mason"},
        ).json()["data"]

        updated = client.patch(
            f"/api/v1/workers/me/projects/{created['id']}",
            headers=worker["headers"],
            json={"role_title": "Senior Mason"},
        )
        assert updated.json()["data"]["role_title"] == "Senior Mason"

        assert (
            client.delete(
                f"/api/v1/workers/me/projects/{created['id']}", headers=worker["headers"]
            ).status_code
            == 200
        )
        assert (
            client.get(
                f"/api/v1/workers/me/projects/{created['id']}", headers=worker["headers"]
            ).status_code
            == 404
        )

    def test_future_dates_are_rejected(self, client, worker) -> None:
        response = client.post(
            "/api/v1/workers/me/projects",
            headers=worker["headers"],
            json={
                "name": "Tomorrow",
                "role_title": "Mason",
                "end_date": str(TODAY + timedelta(days=30)),
            },
        )
        assert response.status_code == 422

    def test_the_owner_listing_includes_confidential_projects(self, client, worker) -> None:
        client.post(
            "/api/v1/workers/me/projects",
            headers=worker["headers"],
            json={"name": "Secret Client", "role_title": "Mason", "is_confidential": True},
        )
        listed = client.get("/api/v1/workers/me/projects", headers=worker["headers"])
        assert "Secret Client" in listed.text


class TestCatalogueEndpoints:
    def test_trades_are_public(self, client, catalogue) -> None:
        response = client.get("/api/v1/trades")
        assert response.status_code == 200
        assert {t["code"] for t in response.json()["data"]} >= {"MASONRY", "PLUMBING"}

    def test_skills_filter_by_trade(self, client, catalogue) -> None:
        response = client.get("/api/v1/skills?trade=MASONRY")
        assert response.status_code == 200
        assert response.json()["data"]

    def test_counties_are_public(self, client, catalogue) -> None:
        response = client.get("/api/v1/counties")
        assert response.status_code == 200
        assert "NAKURU" in {c["code"] for c in response.json()["data"]}

    def test_an_unknown_trade_filter_is_a_422(self, client, catalogue) -> None:
        assert client.get("/api/v1/skills?trade=NOPE").status_code == 422

    def test_trade_counts_require_an_admin(self, client, catalogue, make_user) -> None:
        worker_user = make_user(email=f"w-{uuid.uuid4().hex[:8]}@example.com")
        assert (
            client.get(
                "/api/v1/admin/catalogue/trades", headers=_headers(client, worker_user.email)
            ).status_code
            == 403
        )

    def test_an_admin_sees_worker_counts(self, client, catalogue, make_admin) -> None:
        admin = make_admin()
        response = client.get(
            "/api/v1/admin/catalogue/trades", headers=_headers(client, admin.email)
        )
        assert response.status_code == 200
        assert all("worker_count" in t for t in response.json()["data"])

    def test_a_deactivated_catalogue_entry_disappears(self, client, catalogue, db_session) -> None:
        catalogue["trades"]["WELDING"].is_active = False
        db_session.flush()
        response = client.get("/api/v1/trades")
        assert "WELDING" not in {t["code"] for t in response.json()["data"]}

    def test_only_an_admin_may_edit_the_catalogue(self, client, catalogue, make_user) -> None:
        trade_id = catalogue["trades"]["WELDING"].id
        user = make_user()
        assert (
            client.patch(
                f"/api/v1/admin/catalogue/trades/{trade_id}",
                headers=_headers(client, user.email),
                json={"is_active": False},
            ).status_code
            == 403
        )

    def test_an_admin_edit_is_audited(self, client, catalogue, make_admin, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        admin = make_admin()
        response = client.patch(
            f"/api/v1/admin/catalogue/trades/{catalogue['trades']['WELDING'].id}",
            headers=_headers(client, admin.email),
            json={"name": "Welding & Fabrication"},
        )
        assert response.status_code == 200
        assert response.json()["data"]["name"] == "Welding & Fabrication"

        # Read through the shared session: the harness never commits, so a second
        # connection would not see the row.
        rows = db_session.execute(select(AuditLog)).scalars().all()
        matching = [r for r in rows if r.action == "CATALOGUE_ITEM_UPDATED"]
        assert matching, "the catalogue edit was not audited"
        assert matching[-1].resource_id == catalogue["trades"]["WELDING"].id
        assert matching[-1].actor_user_id == admin.id


#: Shared with tests/conftest.py. Not a secret: the suite only ever runs
#: against the dedicated test database.
DEFAULT_TEST_PASSWORD = "Correct-Horse-9-Battery"


def _token(client, email: str, password: str = DEFAULT_TEST_PASSWORD) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["data"]["tokens"]["access_token"]


def _headers(client, email: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(client, email)}"}


def _create_passport(client, user) -> dict:
    return client.post(
        "/api/v1/workers/me/profile",
        headers=_headers(client, user.email),
        json={"display_name": "Second Worker"},
    ).json()
