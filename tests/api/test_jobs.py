"""End-to-end tests for the Jobs domain: creation, lifecycle, provenance, discovery.

The assertions that matter here are the security ones. A suite that checked only
the happy path would pass while a worker published another employer's draft, or
while an aggregated listing from someone else's website was rendered under a
FundiPulse employer's name.
"""

from __future__ import annotations

from datetime import timedelta
import uuid

import pytest
from sqlalchemy import select

from app.api.routes.jobs import router as jobs_router
from app.core.constants import (
    EmploymentType,
    ExperienceLevel,
    JobSourceRobotsStatus,
    JobSourceTermsStatus,
    JobSourceType,
    JobStatus,
    MembershipStatus,
    OrganizationRole,
    UserRole,
)
from app.db.base import utcnow
from app.db.models.audit import AuditLog
from app.db.models.catalogue import County, Skill, Trade
from app.db.models.job import Job, JobSkill, JobSource
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.user import User

pytestmark = [pytest.mark.api, pytest.mark.integration]


@pytest.fixture(autouse=True)
def _mount_jobs(app):
    """Mount the jobs router on the test app.

    Idempotent: skipped once the domain router is wired into
    ``app/api/router.py``, so these tests keep working either way.
    """
    existing = {getattr(route, "path", None) for route in app.router.routes}
    if "/jobs" not in existing:
        app.include_router(jobs_router)
    return app


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture
def catalogue(db_session):
    """Trades, skills and counties, keyed by code."""
    counties = {
        code: County(id=uuid.uuid4(), code=code, name=name)
        for code, name in (("NAKURU", "Nakuru"), ("BOMET", "Bomet"), ("MOMBASA", "Mombasa"))
    }
    trades = {
        code: Trade(id=uuid.uuid4(), code=code, name=name)
        for code, name in (
            ("MASONRY", "Masonry"),
            ("PLUMBING", "Plumbing"),
            ("WELDING", "Welding"),
        )
    }
    skills = {
        code: Skill(id=uuid.uuid4(), code=code, name=name, trade_id=trade_id)
        for code, name, trade_id in (
            ("BLOCK_LAYING", "Block laying", trades["MASONRY"].id),
            ("PIPE_FITTING", "Pipe fitting", trades["PLUMBING"].id),
            ("WELDING_QUALIFICATION", "Welding qualification", trades["WELDING"].id),
        )
    }
    db_session.add_all([*counties.values(), *trades.values(), *skills.values()])
    db_session.flush()
    return {"counties": counties, "trades": trades, "skills": skills}


@pytest.fixture
def org_factory(db_session):
    def _factory(name: str = "Buildwell Contractors", *, verified: bool = True) -> Organization:
        org = Organization(
            id=uuid.uuid4(),
            name=name,
            slug=f"org-{uuid.uuid4().hex[:10]}",
            is_active=True,
            is_verified=verified,
        )
        db_session.add(org)
        db_session.flush()
        return org

    return _factory


@pytest.fixture
def join_org(db_session):
    def _join(
        org: Organization,
        user: User,
        *,
        role: OrganizationRole = OrganizationRole.OWNER,
        status: MembershipStatus = MembershipStatus.ACTIVE,
    ) -> OrganizationMembership:
        membership = OrganizationMembership(
            organization_id=org.id,
            user_id=user.id,
            role=role.value,
            status=status.value,
            joined_at=utcnow(),
        )
        db_session.add(membership)
        db_session.flush()
        return membership

    return _join


@pytest.fixture
def employer(client, db_session, catalogue, org_factory, join_org, make_user, auth_headers):
    """An OWNER of one organization, with a bearer token."""

    def _factory(
        *,
        role: OrganizationRole = OrganizationRole.OWNER,
        platform_role: UserRole = UserRole.EMPLOYER,
        org_name: str = "Buildwell Contractors",
        membership_status: MembershipStatus = MembershipStatus.ACTIVE,
    ) -> dict:
        org = org_factory(org_name)
        user = make_user(role=platform_role)
        join_org(org, user, role=role, status=membership_status)
        return {
            "org_id": str(org.id),
            "user": user,
            "headers": auth_headers(user),
        }

    return _factory


@pytest.fixture
def employer_a(employer) -> dict:
    return employer(org_name="Buildwell Contractors")


@pytest.fixture
def employer_b(employer) -> dict:
    return employer(org_name="Ridgeline Developers")


@pytest.fixture
def worker(client, make_user, auth_headers) -> dict:
    user = make_user(role=UserRole.WORKER)
    return {"user": user, "headers": auth_headers(user)}


@pytest.fixture
def outsider(client, make_user, auth_headers) -> dict:
    """An employer with no membership in anybody's organization."""
    user = make_user(role=UserRole.EMPLOYER)
    return {"user": user, "headers": auth_headers(user)}


@pytest.fixture
def job_source(db_session):
    """An approved, permitted source. Ingestion is gated on exactly these flags."""
    source = JobSource(
        id=uuid.uuid4(),
        code=f"src-{uuid.uuid4().hex[:8]}",
        name="Coastal Jobs Board",
        source_type=JobSourceType.AGGREGATED_PUBLIC.value,
        base_url="https://jobs.example.com",
        terms_status=JobSourceTermsStatus.APPROVED.value,
        robots_status=JobSourceRobotsStatus.PERMITTED.value,
        is_active=True,
    )
    db_session.add(source)
    db_session.flush()
    return source


@pytest.fixture
def external_job(db_session, catalogue, job_source, org_factory):
    """An aggregated listing, as ingestion would store it.

    ``origin_org`` is the entity *named on the external site*. It is on the row only
    because ``ck_jobs_jobs_published_requires_organization`` currently forces every
    non-``DRAFT`` job to name an organization; the API is forbidden from presenting
    the listing as that employer's own posting, and
    ``test_external_listing_is_never_attributed_to_an_organization`` proves it. The
    constraint should read
    ``organization_id IS NOT NULL OR source_type <> 'PLATFORM'``.
    """
    origin = org_factory("Coastal Fabrication Ltd", verified=False)
    now = utcnow()
    job = Job(
        id=uuid.uuid4(),
        title="Welder wanted for port expansion",
        description=(
            "SMAW welder needed for structural steelwork on the port expansion. "
            "Minimum three years on heavy fabrication."
        ),
        trade_id=catalogue["trades"]["WELDING"].id,
        county_id=catalogue["counties"]["MOMBASA"].id,
        organization_id=origin.id,
        location="Mombasa Port",
        employment_type=EmploymentType.CONTRACT.value,
        experience_level=ExperienceLevel.EXPERIENCED.value,
        status=JobStatus.OPEN.value,
        published_at=now - timedelta(days=2),
        closing_at=now + timedelta(days=5),
        source_id=job_source.id,
        source_type=JobSourceType.AGGREGATED_PUBLIC.value,
        source_name=job_source.name,
        source_url="https://jobs.example.com/listing/ext-9911",
        source_job_id="ext-9911",
        external_apply_url="https://jobs.example.com/listing/ext-9911/apply",
        first_seen_at=now - timedelta(days=9),
        last_seen_at=now - timedelta(days=1),
        last_verified_at=now - timedelta(days=1),
        is_aggregated=True,
    )
    db_session.add(job)
    db_session.flush()
    return {"job": job, "id": str(job.id), "origin_org_id": str(origin.id)}


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def payload(**overrides) -> dict:
    body = {
        "title": "Experienced mason needed",
        "description": "Two masons required for a residential development of 24 units.",
        "trade_code": "MASONRY",
        "county_code": "NAKURU",
        "location": "Nakuru Town",
        "employment_type": "FULL_TIME",
        "experience_level": "ENTRY",
        "skills": [{"skill_code": "BLOCK_LAYING", "is_required": True}],
    }
    body.update(overrides)
    return body


def create_draft(client, actor: dict, **overrides) -> dict:
    response = client.post(
        f"/organizations/{actor['org_id']}/jobs",
        headers=actor["headers"],
        json=payload(**overrides),
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def publish(client, actor: dict, job_id: str):
    return client.post(
        f"/organizations/{actor['org_id']}/jobs/{job_id}/publish", headers=actor["headers"]
    )


def act(client, actor: dict, job_id: str, action: str):
    return client.post(
        f"/organizations/{actor['org_id']}/jobs/{job_id}/{action}", headers=actor["headers"]
    )


def backdate(job: Job, *, closed_days_ago: int = 1) -> None:
    """Move a published job's dates so its closing date has already passed.

    ``ck_jobs_jobs_closing_after_publish`` forbids a closing date before publication,
    so ``published_at`` moves back too - which is exactly how a listing lapses in
    production: published once, then left to run out.
    """
    job.published_at = utcnow() - timedelta(days=closed_days_ago + 2)
    job.closing_at = utcnow() - timedelta(days=closed_days_ago)


def pagination_of(body: dict) -> dict:
    """Read the pagination block, whichever way the shared envelope nests it."""
    meta = body["meta"]
    return meta.get("pagination") or meta


def public_ids(client, query: str = "") -> set[str]:
    response = client.get(f"/jobs{query}")
    assert response.status_code == 200, response.text
    return {row["id"] for row in response.json()["data"]}


# --------------------------------------------------------------------------- #
# Creation and roles                                                          #
# --------------------------------------------------------------------------- #
class TestCreate:
    @pytest.mark.parametrize(
        "role", [OrganizationRole.OWNER, OrganizationRole.ADMIN, OrganizationRole.RECRUITER]
    )
    def test_each_job_managing_role_may_create(self, client, employer, role) -> None:
        actor = employer(role=role)
        response = client.post(
            f"/organizations/{actor['org_id']}/jobs",
            headers=actor["headers"],
            json=payload(),
        )
        assert response.status_code == 201, response.text
        data = response.json()["data"]
        assert data["status"] == JobStatus.DRAFT.value
        assert data["organization"]["id"] == actor["org_id"]

    def test_a_plain_member_may_not_create(self, client, employer) -> None:
        actor = employer(role=OrganizationRole.MEMBER)
        response = client.post(
            f"/organizations/{actor['org_id']}/jobs", headers=actor["headers"], json=payload()
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "JOB_MANAGEMENT_FORBIDDEN"

    def test_a_suspended_membership_may_not_create(self, client, employer) -> None:
        actor = employer(membership_status=MembershipStatus.SUSPENDED)
        response = client.post(
            f"/organizations/{actor['org_id']}/jobs", headers=actor["headers"], json=payload()
        )
        assert response.status_code == 403

    def test_an_invited_membership_is_not_active_yet(self, client, employer) -> None:
        actor = employer(membership_status=MembershipStatus.INVITED)
        response = client.post(
            f"/organizations/{actor['org_id']}/jobs", headers=actor["headers"], json=payload()
        )
        assert response.status_code == 403

    def test_a_worker_cannot_create(self, client, worker, employer_a) -> None:
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs",
            headers=worker["headers"],
            json=payload(),
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "INSUFFICIENT_ROLE"

    def test_a_worker_who_is_an_org_owner_still_cannot_create(
        self, client, db_session, org_factory, join_org, make_user, auth_headers, employer_a
    ) -> None:
        """The platform role gate and the membership gate are independent."""
        user = make_user(role=UserRole.WORKER)
        join_org(org_factory("Shadow Org"), user, role=OrganizationRole.OWNER)
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs",
            headers=auth_headers(user),
            json=payload(),
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "INSUFFICIENT_ROLE"

    def test_requires_authentication(self, client, employer_a) -> None:
        response = client.post(f"/organizations/{employer_a['org_id']}/jobs", json=payload())
        assert response.status_code == 401

    def test_is_audited(self, client, employer_a, audit_rows) -> None:
        created = create_draft(client, employer_a)
        rows = audit_rows(resource_type="job", resource_id=uuid.UUID(created["id"]))
        actions = [row.action for row in rows]
        assert "JOB_CREATED" in actions

    def test_defaults_are_deterministic(self, client, employer_a) -> None:
        """No closing date supplied still produces one, so expiry is server-side."""
        data = create_draft(client, employer_a)
        assert data["closing_at"] is not None
        assert data["published_at"] is None
        assert data["provenance"]["source_type"] == JobSourceType.PLATFORM.value
        assert data["provenance"]["platform_published"] is True
        assert data["accepts_applications"] is False


class TestMassAssignment:
    def test_organization_id_in_the_body_is_refused(self, client, employer_a, employer_b) -> None:
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs",
            headers=employer_a["headers"],
            json=payload(organization_id=employer_b["org_id"]),
        )
        assert response.status_code == 422
        assert "organization_id" not in response.text.replace('"organization_id"', "")

    def test_status_in_the_body_is_refused(self, client, employer_a) -> None:
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs",
            headers=employer_a["headers"],
            json=payload(status="OPEN"),
        )
        assert response.status_code == 422

    @pytest.mark.parametrize(
        "spoof",
        [
            {"source_type": "AGGREGATED_PUBLIC"},
            {"source_type": "PARTNER_FEED"},
            {"source_type": "EMPLOYER_SUBMITTED"},
        ],
    )
    def test_external_provenance_cannot_be_asserted(self, client, employer_a, spoof) -> None:
        """A worker-side client must not be able to mint an aggregated listing."""
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs",
            headers=employer_a["headers"],
            json=payload(**spoof),
        )
        assert response.status_code == 422
        assert public_ids(client) == set()

    def test_platform_source_type_is_accepted_and_meaningless(self, client, employer_a) -> None:
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs",
            headers=employer_a["headers"],
            json=payload(source_type="PLATFORM"),
        )
        assert response.status_code == 201, response.text
        data = response.json()["data"]
        assert data["provenance"]["source_type"] == JobSourceType.PLATFORM.value
        assert data["provenance"]["source_id"] is None

    @pytest.mark.parametrize(
        "field",
        [
            "source_id",
            "source_url",
            "source_job_id",
            "source_name",
            "first_seen_at",
            "last_seen_at",
            "last_verified_at",
            "external_apply_url",
            "is_aggregated",
            "created_by_user_id",
            "published_at",
        ],
    )
    def test_provenance_and_ownership_fields_are_not_writable(
        self, client, employer_a, field
    ) -> None:
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs",
            headers=employer_a["headers"],
            json=payload(**{field: "2026-01-01T00:00:00Z"}),
        )
        assert response.status_code == 422, f"{field} was accepted"


# --------------------------------------------------------------------------- #
# Draft visibility                                                            #
# --------------------------------------------------------------------------- #
class TestDraftVisibility:
    def test_a_draft_is_absent_from_discovery(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        assert created["id"] not in public_ids(client)
        assert created["id"] not in public_ids(client, "?status=OPEN")

    def test_a_draft_is_404_to_an_anonymous_caller(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        response = client.get(f"/jobs/{created['id']}")
        assert response.status_code == 404

    def test_a_draft_is_404_to_a_worker(self, client, employer_a, worker) -> None:
        created = create_draft(client, employer_a)
        response = client.get(f"/jobs/{created['id']}", headers=worker["headers"])
        assert response.status_code == 404

    def test_a_draft_is_404_to_a_non_member_employer(self, client, employer_a, outsider) -> None:
        created = create_draft(client, employer_a)
        response = client.get(f"/jobs/{created['id']}", headers=outsider["headers"])
        assert response.status_code == 404

    def test_a_draft_is_404_to_a_member_of_another_organization(
        self, client, employer_a, employer_b
    ) -> None:
        """404, not 403: a different code would confirm the job exists."""
        created = create_draft(client, employer_a)
        response = client.get(f"/jobs/{created['id']}", headers=employer_b["headers"])
        assert response.status_code == 404

    def test_a_draft_is_visible_to_its_own_organization(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        response = client.get(f"/jobs/{created['id']}", headers=employer_a["headers"])
        assert response.status_code == 200
        assert response.json()["data"]["status"] == JobStatus.DRAFT.value

    def test_a_draft_is_404_to_an_admin_without_membership(
        self, client, employer_a, make_admin, auth_headers
    ) -> None:
        """Platform role is not a claim on another organization's listings."""
        created = create_draft(client, employer_a)
        response = client.get(f"/jobs/{created['id']}", headers=auth_headers(make_admin()))
        assert response.status_code == 404

    def test_the_organization_list_includes_drafts(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        response = client.get(
            f"/organizations/{employer_a['org_id']}/jobs", headers=employer_a["headers"]
        )
        assert response.status_code == 200
        assert [row["id"] for row in response.json()["data"]] == [created["id"]]

    def test_the_organization_list_is_closed_to_others(self, client, employer_a, outsider) -> None:
        create_draft(client, employer_a)
        response = client.get(
            f"/organizations/{employer_a['org_id']}/jobs", headers=outsider["headers"]
        )
        assert response.status_code == 403
        assert "Experienced mason needed" not in response.text


# --------------------------------------------------------------------------- #
# Lifecycle                                                                   #
# --------------------------------------------------------------------------- #
class TestLifecycle:
    def test_publish_moves_a_draft_to_open(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        response = publish(client, employer_a, created["id"])
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["status"] == JobStatus.OPEN.value
        assert data["published_at"] is not None
        assert data["accepts_applications"] is True
        assert created["id"] in public_ids(client)

    def test_publication_is_audited(self, client, employer_a, audit_rows) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        rows = audit_rows(resource_type="job", resource_id=uuid.UUID(created["id"]))
        changes = [row for row in rows if row.action == "JOB_STATUS_CHANGED"]
        assert len(changes) == 1
        assert changes[0].outcome == "SUCCESS"
        assert changes[0].metadata_["new_status"] == JobStatus.OPEN.value

    def test_close_moves_an_open_job_to_closed(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        response = act(client, employer_a, created["id"], "close")
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["status"] == JobStatus.CLOSED.value
        assert data["closed_at"] is not None
        assert data["accepts_applications"] is False

    def test_a_closed_job_leaves_discovery(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        act(client, employer_a, created["id"], "close")
        assert created["id"] not in public_ids(client)

    def test_closure_is_audited(self, client, employer_a, audit_rows) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        act(client, employer_a, created["id"], "close")
        rows = audit_rows(resource_type="job", resource_id=uuid.UUID(created["id"]))
        closes = [
            row
            for row in rows
            if row.action == "JOB_STATUS_CHANGED" and row.metadata_.get("operation") == "close_job"
        ]
        assert len(closes) == 1
        assert closes[0].metadata_["new_status"] == JobStatus.CLOSED.value

    def test_cancel_a_draft(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        response = act(client, employer_a, created["id"], "cancel")
        assert response.status_code == 200
        assert response.json()["data"]["status"] == JobStatus.CANCELLED.value

    def test_cancel_an_open_job(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        response = act(client, employer_a, created["id"], "cancel")
        assert response.status_code == 200
        assert response.json()["data"]["status"] == JobStatus.CANCELLED.value
        assert created["id"] not in public_ids(client)

    def test_cancellation_is_audited(self, client, employer_a, audit_rows) -> None:
        created = create_draft(client, employer_a)
        act(client, employer_a, created["id"], "cancel")
        rows = audit_rows(resource_type="job", resource_id=uuid.UUID(created["id"]))
        cancels = [
            row
            for row in rows
            if row.action == "JOB_STATUS_CHANGED" and row.metadata_.get("operation") == "cancel_job"
        ]
        assert len(cancels) == 1


class TestIllegalTransitions:
    def _illegal(self, response) -> None:
        assert response.status_code == 409, response.text
        assert response.json()["error"]["code"] == "INVALID_STATE_TRANSITION"

    def test_publishing_an_open_job_is_a_conflict(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        response = publish(client, employer_a, created["id"])
        self._illegal(response)
        assert "already open" in response.json()["error"]["message"]

    def test_publishing_a_closed_job_is_a_conflict_not_a_no_op(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        act(client, employer_a, created["id"], "close")
        response = publish(client, employer_a, created["id"])
        self._illegal(response)
        assert "closed" in response.json()["error"]["message"]

    def test_publishing_a_cancelled_job_is_refused(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        act(client, employer_a, created["id"], "cancel")
        self._illegal(publish(client, employer_a, created["id"]))

    def test_closing_a_draft_is_refused(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        response = act(client, employer_a, created["id"], "close")
        self._illegal(response)
        assert "draft" in response.json()["error"]["message"]

    def test_closing_a_closed_job_is_handled_deliberately(self, client, employer_a) -> None:
        """A repeated close must not look like a successful transition."""
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        assert act(client, employer_a, created["id"], "close").status_code == 200
        response = act(client, employer_a, created["id"], "close")
        self._illegal(response)
        assert "closed" in response.json()["error"]["message"]

    def test_cancelling_a_closed_job_is_refused(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        act(client, employer_a, created["id"], "close")
        self._illegal(act(client, employer_a, created["id"], "cancel"))

    def test_cancelling_a_cancelled_job_is_refused(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        act(client, employer_a, created["id"], "cancel")
        self._illegal(act(client, employer_a, created["id"], "cancel"))

    def test_a_refused_transition_is_audited_durably(self, client, employer_a, audit_rows) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        publish(client, employer_a, created["id"])
        rows = audit_rows(resource_type="job", resource_id=uuid.UUID(created["id"]))
        denied = [row for row in rows if row.outcome == "DENIED"]
        assert len(denied) == 1
        assert denied[0].metadata_["previous_status"] == JobStatus.OPEN.value

    def test_a_refused_transition_leaves_the_status_alone(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        publish(client, employer_a, created["id"])
        response = client.get(f"/jobs/{created['id']}")
        assert response.json()["data"]["status"] == JobStatus.OPEN.value


# --------------------------------------------------------------------------- #
# Closing dates                                                               #
# --------------------------------------------------------------------------- #
class TestClosingDate:
    def test_a_past_closing_date_is_refused_on_create(self, client, employer_a) -> None:
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs",
            headers=employer_a["headers"],
            json=payload(closing_at="2020-01-01T00:00:00Z"),
        )
        assert response.status_code == 422
        assert "future" in response.text

    def test_a_closing_date_too_far_ahead_is_refused(self, client, employer_a) -> None:
        far = (utcnow() + timedelta(days=400)).isoformat()
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs",
            headers=employer_a["headers"],
            json=payload(closing_at=far),
        )
        assert response.status_code == 422

    def test_publishing_a_draft_whose_date_has_lapsed_is_refused(
        self, client, db_session, employer_a
    ) -> None:
        """A draft can sit for weeks; publication re-checks the stored date."""
        created = create_draft(client, employer_a)
        job = db_session.get(Job, uuid.UUID(created["id"]))
        job.closing_at = utcnow() - timedelta(hours=1)
        db_session.flush()

        response = publish(client, employer_a, created["id"])
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "JOB_CLOSING_DATE_PASSED"

    def test_extending_the_date_makes_it_publishable(self, client, db_session, employer_a) -> None:
        created = create_draft(client, employer_a)
        job = db_session.get(Job, uuid.UUID(created["id"]))
        job.closing_at = utcnow() - timedelta(hours=1)
        db_session.flush()

        future = (utcnow() + timedelta(days=7)).isoformat()
        patched = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{created['id']}",
            headers=employer_a["headers"],
            json={"closing_at": future},
        )
        assert patched.status_code == 200, patched.text
        assert publish(client, employer_a, created["id"]).status_code == 200

    def test_a_lapsed_open_job_reads_as_expired(self, client, db_session, employer_a) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        job = db_session.get(Job, uuid.UUID(created["id"]))
        backdate(job)
        db_session.flush()

        data = client.get(f"/jobs/{created['id']}").json()["data"]
        assert data["status"] == JobStatus.EXPIRED.value
        assert data["accepts_applications"] is False
        assert created["id"] not in public_ids(client)

    def test_a_manager_can_filter_for_expired(self, client, db_session, employer_a) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        job = db_session.get(Job, uuid.UUID(created["id"]))
        backdate(job)
        db_session.flush()

        response = client.get("/jobs?status=EXPIRED", headers=employer_a["headers"])
        assert response.status_code == 200
        assert created["id"] in {row["id"] for row in response.json()["data"]}

    def test_a_non_manager_cannot_filter_for_expired(self, client, employer_a) -> None:
        response = client.get("/jobs?status=EXPIRED")
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "JOB_STATUS_FILTER_FORBIDDEN"


# --------------------------------------------------------------------------- #
# External provenance                                                         #
# --------------------------------------------------------------------------- #
class TestExternalProvenance:
    def test_an_external_listing_is_discoverable(self, client, external_job) -> None:
        response = client.get(f"/jobs/{external_job['id']}")
        assert response.status_code == 200
        assert response.json()["data"]["status"] == JobStatus.OPEN.value

    def test_external_listing_is_never_attributed_to_an_organization(
        self, client, external_job
    ) -> None:
        """The named entity came from the source site, not from an employer here."""
        data = client.get(f"/jobs/{external_job['id']}").json()["data"]
        assert data["organization"] is None
        assert data["provenance"]["platform_published"] is False
        assert data["provenance"]["source_type"] == JobSourceType.AGGREGATED_PUBLIC.value

    def test_external_listing_keeps_its_provenance(self, client, external_job) -> None:
        provenance = client.get(f"/jobs/{external_job['id']}").json()["data"]["provenance"]
        assert provenance["source_id"] is not None
        assert provenance["source_name"] == "Coastal Jobs Board"
        assert provenance["source_url"] == "https://jobs.example.com/listing/ext-9911"
        assert provenance["source_job_id"] == "ext-9911"
        assert provenance["first_seen_at"] is not None
        assert provenance["last_seen_at"] is not None
        assert provenance["last_verified_at"] is not None
        assert provenance["external_apply_url"].endswith("/apply")

    def test_external_listing_routes_the_worker_to_the_original_site(
        self, client, external_job
    ) -> None:
        data = client.get(f"/jobs/{external_job['id']}").json()["data"]
        assert data["accepts_applications"] is False
        assert data["provenance"]["is_aggregated"] is True

    def test_external_listing_names_no_creator(self, client, external_job) -> None:
        body = client.get(f"/jobs/{external_job['id']}").text
        assert "created_by_user_id" not in body

    def test_external_listing_becomes_expired_past_its_date(
        self, client, db_session, external_job
    ) -> None:
        job = db_session.get(Job, external_job["job"].id)
        backdate(job)
        db_session.flush()

        data = client.get(f"/jobs/{external_job['id']}").json()["data"]
        assert data["status"] == JobStatus.EXPIRED.value
        assert data["accepts_applications"] is False
        assert external_job["id"] not in public_ids(client)

    def test_external_listing_appears_in_discovery_with_provenance(
        self, client, external_job
    ) -> None:
        rows = client.get("/jobs").json()["data"]
        row = next(r for r in rows if r["id"] == external_job["id"])
        assert row["organization"] is None
        assert row["provenance"]["platform_published"] is False
        assert row["accepts_applications"] is False

    def test_aggregation_cannot_be_claimed_by_an_employer(self, client, employer_a) -> None:
        """Creating many platform jobs must not surface anything aggregated."""
        for index in range(3):
            create_draft(client, employer_a, title=f"Vacancy number {index}")
        response = client.get("/jobs?source_type=AGGREGATED_PUBLIC")
        assert response.status_code == 200
        assert response.json()["data"] == []


# --------------------------------------------------------------------------- #
# Update                                                                      #
# --------------------------------------------------------------------------- #
class TestUpdate:
    def test_updates_editable_fields(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{created['id']}",
            headers=employer_a["headers"],
            json={"title": "Senior mason needed", "location": "Nakuru West"},
        )
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["title"] == "Senior mason needed"
        assert data["location"] == "Nakuru West"

    def test_a_partial_update_leaves_other_fields_alone(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{created['id']}",
            headers=employer_a["headers"],
            json={"title": "Renamed role"},
        )
        data = client.get(f"/jobs/{created['id']}", headers=employer_a["headers"]).json()["data"]
        assert data["location"] == "Nakuru Town"
        assert data["county_code"] == "NAKURU"

    def test_status_cannot_be_set_by_patch(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{created['id']}",
            headers=employer_a["headers"],
            json={"status": "OPEN"},
        )
        assert response.status_code == 422

    def test_update_is_audited(self, client, employer_a, audit_rows) -> None:
        created = create_draft(client, employer_a)
        client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{created['id']}",
            headers=employer_a["headers"],
            json={"title": "Renamed role"},
        )
        rows = audit_rows(resource_type="job", resource_id=uuid.UUID(created["id"]))
        assert "JOB_UPDATED" in [row.action for row in rows]

    def test_unknown_skill_is_rejected_and_nothing_is_deleted(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{created['id']}",
            headers=employer_a["headers"],
            json={"skills": [{"skill_code": "TIME_TRAVEL"}]},
        )
        assert response.status_code == 422
        assert "TIME_TRAVEL" in response.text
        data = client.get(f"/jobs/{created['id']}", headers=employer_a["headers"]).json()["data"]
        assert [s["code"] for s in data["skills"]] == ["BLOCK_LAYING"]

    def test_unknown_trade_is_rejected(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{created['id']}",
            headers=employer_a["headers"],
            json={"trade_code": "TIME_TRAVEL"},
        )
        assert response.status_code == 422
        assert "TIME_TRAVEL" in response.text

    def test_an_unknown_job_is_404_before_the_body_is_validated(self, client, employer_a) -> None:
        """Scoping wins: the lookup runs first, so an unknown trade cannot be probed."""
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{uuid.uuid4()}",
            headers=employer_a["headers"],
            json={"trade_code": "TIME_TRAVEL"},
        )
        assert response.status_code == 404


class TestSkills:
    def test_skills_are_replaced_atomically(self, client, employer_a) -> None:
        """Keeping one skill and adding another must not trip the unique index."""
        created = create_draft(
            client,
            employer_a,
            skills=[
                {"skill_code": "BLOCK_LAYING"},
                {"skill_code": "PIPE_FITTING"},
            ],
        )
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{created['id']}",
            headers=employer_a["headers"],
            json={
                "skills": [{"skill_code": "PIPE_FITTING"}, {"skill_code": "WELDING_QUALIFICATION"}]
            },
        )
        assert response.status_code == 200, response.text
        codes = sorted(s["code"] for s in response.json()["data"]["skills"])
        assert codes == ["PIPE_FITTING", "WELDING_QUALIFICATION"]

    def test_replacing_with_an_empty_list_clears_the_skills(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{created['id']}",
            headers=employer_a["headers"],
            json={"skills": []},
        )
        assert response.status_code == 200, response.text
        assert response.json()["data"]["skills"] == []

    def test_a_failed_replacement_leaves_the_stored_rows_untouched(
        self, client, db_session, employer_a
    ) -> None:
        created = create_draft(
            client,
            employer_a,
            skills=[{"skill_code": "BLOCK_LAYING"}, {"skill_code": "PIPE_FITTING"}],
        )
        job_id = uuid.UUID(created["id"])
        client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{created['id']}",
            headers=employer_a["headers"],
            json={"skills": [{"skill_code": "PIPE_FITTING"}, {"skill_code": "NOT_A_SKILL"}]},
        )
        db_session.expire_all()
        stored = {
            row.skill_id for row in db_session.query(JobSkill).filter(JobSkill.job_id == job_id)
        }
        assert len(stored) == 2

    def test_duplicate_skills_are_refused(self, client, employer_a) -> None:
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs",
            headers=employer_a["headers"],
            json=payload(skills=[{"skill_code": "BLOCK_LAYING"}, {"skill_code": "BLOCK_LAYING"}]),
        )
        assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Discovery                                                                   #
# --------------------------------------------------------------------------- #
class TestDiscovery:
    def test_open_jobs_are_public(self, client, employer_a) -> None:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        response = client.get("/jobs")
        assert response.status_code == 200
        assert created["id"] in {row["id"] for row in response.json()["data"]}

    def test_filters_by_trade(self, client, employer_a) -> None:
        mason = create_draft(client, employer_a, trade_code="MASONRY", title="Mason needed")
        publish(client, employer_a, mason["id"])
        plumber = create_draft(
            client,
            employer_a,
            trade_code="PLUMBING",
            county_code="BOMET",
            location="Bomet Town",
            title="Plumber needed",
        )
        publish(client, employer_a, plumber["id"])
        assert public_ids(client, "?trade=MASONRY") == {mason["id"]}

    def test_filters_by_skill(self, client, employer_a) -> None:
        mason = create_draft(client, employer_a)
        publish(client, employer_a, mason["id"])
        plumber = create_draft(
            client, employer_a, trade_code="PLUMBING", skills=[{"skill_code": "PIPE_FITTING"}]
        )
        publish(client, employer_a, plumber["id"])
        assert public_ids(client, "?skill=PIPE_FITTING") == {plumber["id"]}

    def test_filters_by_county(self, client, employer_a) -> None:
        nakuru = create_draft(client, employer_a)
        publish(client, employer_a, nakuru["id"])
        bomet = create_draft(client, employer_a, county_code="BOMET")
        publish(client, employer_a, bomet["id"])
        assert public_ids(client, "?county=BOMET") == {bomet["id"]}

    def test_filters_by_location(self, client, employer_a) -> None:
        nakuru = create_draft(client, employer_a, location="Nakuru Town")
        publish(client, employer_a, nakuru["id"])
        bomet = create_draft(client, employer_a, location="Bomet Town")
        publish(client, employer_a, bomet["id"])
        assert public_ids(client, "?location=bomet") == {bomet["id"]}

    def test_location_search_does_not_treat_wildcards_as_patterns(self, client, employer_a) -> None:
        job = create_draft(client, employer_a, location="Nakuru Town")
        publish(client, employer_a, job["id"])
        assert public_ids(client, "?location=%25") == set()

    def test_filters_by_employment_type(self, client, employer_a) -> None:
        full = create_draft(client, employer_a, employment_type="FULL_TIME")
        publish(client, employer_a, full["id"])
        casual = create_draft(client, employer_a, employment_type="CASUAL")
        publish(client, employer_a, casual["id"])
        assert public_ids(client, "?employment_type=CASUAL") == {casual["id"]}

    def test_filters_by_experience(self, client, employer_a) -> None:
        entry = create_draft(client, employer_a, experience_level="ENTRY")
        publish(client, employer_a, entry["id"])
        experienced = create_draft(client, employer_a, experience_level="EXPERIENCED")
        publish(client, employer_a, experienced["id"])
        assert public_ids(client, "?experience=EXPERIENCED") == {experienced["id"]}

    def test_filters_by_source_type(self, client, employer_a, external_job) -> None:
        platform = create_draft(client, employer_a)
        publish(client, employer_a, platform["id"])
        assert public_ids(client, "?source_type=PLATFORM") == {platform["id"]}
        assert public_ids(client, "?source_type=AGGREGATED_PUBLIC") == {external_job["id"]}

    def test_filters_by_status(self, client, employer_a) -> None:
        closed = create_draft(client, employer_a)
        publish(client, employer_a, closed["id"])
        act(client, employer_a, closed["id"], "close")
        still_open = create_draft(client, employer_a, title="Another role")
        publish(client, employer_a, still_open["id"])
        assert public_ids(client, "?status=OPEN") == {still_open["id"]}

    def test_unknown_trade_filter_is_a_422(self, client) -> None:
        response = client.get("/jobs?trade=TIME_TRAVEL")
        assert response.status_code == 422
        assert "TIME_TRAVEL" in response.text

    def test_unknown_county_filter_is_a_422(self, client) -> None:
        assert client.get("/jobs?county=ATLANTIS").status_code == 422

    def test_unknown_skill_filter_is_a_422(self, client) -> None:
        assert client.get("/jobs?skill=TELEPORTATION").status_code == 422

    def test_an_unknown_status_filter_is_a_422(self, client) -> None:
        assert client.get("/jobs?status=IMAGINARY").status_code == 422

    @pytest.mark.parametrize("role", ["CLOSED", "CANCELLED", "DRAFT"])
    def test_a_non_open_status_filter_is_refused_for_outsiders(self, client, role) -> None:
        response = client.get(f"/jobs?status={role}")
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "JOB_STATUS_FILTER_FORBIDDEN"

    def test_a_manager_sees_only_their_own_non_open_jobs(
        self, client, employer_a, employer_b
    ) -> None:
        mine = create_draft(client, employer_a)
        theirs = create_draft(client, employer_b, title="Their draft")
        response = client.get("/jobs?status=DRAFT", headers=employer_a["headers"])
        assert response.status_code == 200
        assert [row["id"] for row in response.json()["data"]] == [mine["id"]]
        assert theirs["id"] not in {row["id"] for row in response.json()["data"]}

    def test_a_manager_still_sees_everyones_open_jobs(self, client, employer_a, employer_b) -> None:
        theirs = create_draft(client, employer_b, title="Their open role")
        publish(client, employer_b, theirs["id"])
        assert theirs["id"] in public_ids(client)
        assert theirs["id"] in public_ids(client, "?status=OPEN")


class TestPagination:
    def test_paginates(self, client, employer_a) -> None:
        ids = []
        for index in range(5):
            job = create_draft(client, employer_a, title=f"Vacancy {index}")
            publish(client, employer_a, job["id"])
            ids.append(job["id"])

        first = client.get("/jobs?page=1&page_size=2").json()
        page = pagination_of(first)
        assert len(first["data"]) == 2
        assert page["total_items"] == 5
        assert page["total_pages"] == 3
        assert page["has_next"] is True
        assert page["has_previous"] is False

        seen: set[str] = set()
        for page in (1, 2, 3):
            body = client.get(f"/jobs?page={page}&page_size=2").json()
            seen.update(row["id"] for row in body["data"])
        assert seen == set(ids)

    def test_a_page_past_the_end_is_empty_not_an_error(self, client, employer_a) -> None:
        response = client.get("/jobs?page=50&page_size=20")
        assert response.status_code == 200
        assert response.json()["data"] == []

    def test_page_size_is_capped(self, client) -> None:
        assert client.get("/jobs?page_size=500").status_code == 422
        assert client.get("/jobs?page_size=0").status_code == 422
        assert client.get("/jobs?page=0").status_code == 422

    def test_page_size_at_the_cap_is_accepted(self, client, employer_a) -> None:
        create_draft(client, employer_a)
        assert client.get("/jobs?page_size=100").status_code == 200

    def test_the_organization_list_paginates(self, client, employer_a) -> None:
        for index in range(3):
            create_draft(client, employer_a, title=f"Vacancy {index}")
        response = client.get(
            f"/organizations/{employer_a['org_id']}/jobs?page=1&page_size=2",
            headers=employer_a["headers"],
        )
        assert response.status_code == 200
        assert len(response.json()["data"]) == 2
        assert pagination_of(response.json())["total_items"] == 3


# --------------------------------------------------------------------------- #
# Cross-organization isolation                                                #
# --------------------------------------------------------------------------- #
class TestCrossOrganization:
    @pytest.fixture
    def victim_job(self, client, employer_a) -> dict:
        created = create_draft(client, employer_a)
        publish(client, employer_a, created["id"])
        return created

    def test_another_employer_cannot_read_the_organization_list(
        self, client, employer_a, employer_b, victim_job
    ) -> None:
        response = client.get(
            f"/organizations/{employer_a['org_id']}/jobs", headers=employer_b["headers"]
        )
        assert response.status_code == 403
        assert victim_job["id"] not in response.text

    def test_another_employer_cannot_edit(self, client, employer_a, employer_b, victim_job) -> None:
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{victim_job['id']}",
            headers=employer_b["headers"],
            json={"title": "Hijacked"},
        )
        assert response.status_code == 403
        assert (
            "Hijacked"
            not in client.get(f"/jobs/{victim_job['id']}", headers=employer_a["headers"]).text
        )

    def test_another_employer_cannot_publish(self, client, employer_a, employer_b) -> None:
        draft = create_draft(client, employer_a)
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs/{draft['id']}/publish",
            headers=employer_b["headers"],
        )
        assert response.status_code == 403

    def test_another_employer_cannot_close(
        self, client, employer_a, employer_b, victim_job
    ) -> None:
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs/{victim_job['id']}/close",
            headers=employer_b["headers"],
        )
        assert response.status_code == 403
        assert client.get(f"/jobs/{victim_job['id']}").json()["data"]["status"] == "OPEN"

    def test_another_employer_cannot_cancel(
        self, client, employer_a, employer_b, victim_job
    ) -> None:
        response = client.post(
            f"/organizations/{employer_a['org_id']}/jobs/{victim_job['id']}/cancel",
            headers=employer_b["headers"],
        )
        assert response.status_code == 403
        assert client.get(f"/jobs/{victim_job['id']}").json()["data"]["status"] == "OPEN"

    def test_a_worker_cannot_edit_employer_jobs(
        self, client, employer_a, worker, victim_job
    ) -> None:
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{victim_job['id']}",
            headers=worker["headers"],
            json={"title": "Worker edit"},
        )
        assert response.status_code == 403

    def test_an_admin_without_membership_cannot_edit(
        self, client, employer_a, make_admin, auth_headers, victim_job
    ) -> None:
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{victim_job['id']}",
            headers=auth_headers(make_admin()),
            json={"title": "Admin edit"},
        )
        assert response.status_code == 403

    def test_a_member_cannot_edit(self, client, employer, employer_a, victim_job) -> None:
        plain = employer(role=OrganizationRole.MEMBER)
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{victim_job['id']}",
            headers=plain["headers"],
            json={"title": "Member edit"},
        )
        assert response.status_code == 403

    def test_a_denied_mutation_is_audited_durably(
        self, client, db_session, employer_a, employer_b
    ) -> None:
        draft = create_draft(client, employer_a)
        client.post(
            f"/organizations/{employer_a['org_id']}/jobs/{draft['id']}/publish",
            headers=employer_b["headers"],
        )
        rows = db_session.execute(select(AuditLog).where(AuditLog.outcome == "DENIED")).scalars()
        denied = [row for row in rows if row.metadata_.get("operation") == "publish_job"]
        assert denied, "a refused cross-tenant publish left no audit row"

    def test_substituting_the_organization_matches_nothing(
        self, client, employer_a, employer_b, victim_job
    ) -> None:
        """Employer B is refused the job before the row is even looked at."""
        response = client.patch(
            f"/organizations/{employer_b['org_id']}/jobs/{victim_job['id']}",
            headers=employer_b["headers"],
            json={"title": "Moved"},
        )
        assert response.status_code == 404
        assert (
            client.get(f"/jobs/{victim_job['id']}", headers=employer_a["headers"]).json()["data"][
                "title"
            ]
            == "Experienced mason needed"
        )

    def test_an_unknown_job_id_is_404(self, client, employer_a) -> None:
        response = client.patch(
            f"/organizations/{employer_a['org_id']}/jobs/{uuid.uuid4()}",
            headers=employer_a["headers"],
            json={"title": "Nothing"},
        )
        assert response.status_code == 404

    def test_an_unknown_job_id_is_404_for_every_action(self, client, employer_a) -> None:
        missing = uuid.uuid4()
        for action in ("publish", "close", "cancel"):
            response = client.post(
                f"/organizations/{employer_a['org_id']}/jobs/{missing}/{action}",
                headers=employer_a["headers"],
            )
            assert response.status_code == 404


# --------------------------------------------------------------------------- #
# Envelope                                                                    #
# --------------------------------------------------------------------------- #
class TestResponseShape:
    def test_errors_use_the_standard_envelope(self, client, employer_a, error_code) -> None:
        response = client.get("/jobs/00000000-0000-0000-0000-000000000000")
        assert error_code(response) == "RESOURCE_NOT_FOUND"
        assert response.json()["error"]["request_id"] is not None

    def test_a_list_carries_pagination_meta(self, client, employer_a) -> None:
        job = create_draft(client, employer_a)
        publish(client, employer_a, job["id"])
        body = client.get("/jobs").json()
        assert set(pagination_of(body)) == {
            "request_id",
            "page",
            "page_size",
            "total_items",
            "total_pages",
            "has_next",
            "has_previous",
        }

    def test_no_route_is_versioned(self, client) -> None:
        assert client.get("/api/v1/jobs").status_code == 404
