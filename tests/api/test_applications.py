"""End-to-end tests for the applications domain: submit, decide, withdraw.

The assertions that matter are the security ones. A suite that checked only the
happy path would pass while a worker shortlisted themselves, while Organization B
read Organization A's pipeline, or while a second application row appeared beside
the first because the one-per-worker rule was a pre-check instead of a constraint.
"""

from __future__ import annotations

from datetime import timedelta
import json
import uuid

import pytest
from sqlalchemy import select

from app.api.routes.applications import router as applications_router
from app.core.constants import (
    ApplicationStatus,
    JobSourceRobotsStatus,
    JobSourceTermsStatus,
    JobSourceType,
    JobStatus,
    MembershipStatus,
    OrganizationRole,
    UserRole,
)
from app.core.exceptions import InvalidStateTransitionError
from app.db.base import utcnow
from app.db.models.audit import AuditLog
from app.db.models.catalogue import County, Skill, Trade
from app.db.models.job import Job, JobApplication, JobSource
from app.db.models.notification import Notification
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.user import User
from app.db.models.worker import WorkerProfile, WorkerTrade
from app.schemas.applications import ApplicationStatusChangeRequest
from app.services.application_service import (
    EMPLOYER_TRANSITIONS,
    WORKER_TRANSITIONS,
    ApplicationNotFoundError,
    ApplicationService,
)

pytestmark = [pytest.mark.api, pytest.mark.integration]

#: Every legal employer transition, derived from the table itself so the test can
#: never drift into asserting a hand-written list that has fallen behind.
LEGAL: list[tuple[str, str]] = [
    (source.value, target.value)
    for source, targets in EMPLOYER_TRANSITIONS.items()
    for target in targets
]

#: Every illegal jump: anything the table does not list, plus every self-transition.
ILLEGAL: list[tuple[str, str]] = [
    (source.value, target.value)
    for source in ApplicationStatus
    for target in ApplicationStatus
    if target not in EMPLOYER_TRANSITIONS[source] or target is source
]

#: Words that would mean the platform had told somebody they are better than
#: somebody else. A count is allowed; a ranking is not (ADR 0010).
RANKING_WORDS = ("score", "rank", "rating", "stars", "best", "top candidate")


@pytest.fixture(autouse=True)
def _mount_applications(app):
    """Mount the applications router on the test app.

    Idempotent: skipped once the domain router is wired into
    ``app/api/router.py``, so these tests keep working either way.
    """
    existing = {getattr(route, "path", None) for route in app.router.routes}
    if "/jobs/{job_id}/applications" not in existing:
        app.include_router(applications_router)
    return app


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture
def catalogue(db_session):
    counties = {
        code: County(id=uuid.uuid4(), code=code, name=name)
        for code, name in (("NAKURU", "Nakuru"), ("MOMBASA", "Mombasa"))
    }
    trades = {
        code: Trade(id=uuid.uuid4(), code=code, name=name)
        for code, name in (("MASONRY", "Masonry"), ("WELDING", "Welding"))
    }
    skills = {
        code: Skill(
            id=uuid.uuid4(),
            code=code,
            name=code.replace("_", " ").title(),
            trade_id=trades[trade].id,
        )
        for code, trade in (("BLOCK_LAYING", "MASONRY"), ("WELDING_QUALIFICATION", "WELDING"))
    }
    db_session.add_all([*counties.values(), *trades.values(), *skills.values()])
    db_session.flush()
    return {"counties": counties, "trades": trades, "skills": skills}


@pytest.fixture
def org_factory(db_session):
    def _factory(name: str = "Buildwell Contractors") -> Organization:
        org = Organization(
            id=uuid.uuid4(),
            name=name,
            slug=f"org-{uuid.uuid4().hex[:10]}",
            is_active=True,
            is_verified=True,
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
    """An employer of one organization, with a bearer token."""

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
        return {"org_id": str(org.id), "user": user, "headers": auth_headers(user)}

    return _factory


@pytest.fixture
def employer_a(employer) -> dict:
    return employer(org_name="Buildwell Contractors")


@pytest.fixture
def employer_b(employer) -> dict:
    return employer(org_name="Ridgeline Developers")


@pytest.fixture
def outsider(make_user, auth_headers) -> dict:
    """An employer with no membership in anybody's organization."""
    user = make_user(role=UserRole.EMPLOYER)
    return {"user": user, "headers": auth_headers(user)}


@pytest.fixture
def make_worker(db_session, catalogue, make_user, auth_headers):
    """A factory of worker accounts, each with a Work Passport.

    Applying requires a passport, and a fresh worker per case keeps the
    one-application-per-worker rule from leaking between cases. Every passport
    carries the same private contact details so tests can assert they never reach
    an employer.
    """

    def _factory(display_name: str = "Amina Wanjiru") -> dict:
        user = make_user(role=UserRole.WORKER)
        profile = WorkerProfile(
            id=uuid.uuid4(),
            user_id=user.id,
            display_name=display_name,
            headline="Block layer, six years on residential sites",
            primary_trade_id=catalogue["trades"]["MASONRY"].id,
            county_id=catalogue["counties"]["NAKURU"].id,
            location="Nakuru Town",
            phone_number="0712345678",
            contact_email="amina.private@example.com",
            contact_name="Halima Wanjiru",
            contact_phone="0712345679",
        )
        db_session.add(profile)
        db_session.add(
            WorkerTrade(
                worker_profile_id=profile.id,
                trade_id=catalogue["trades"]["MASONRY"].id,
                is_primary=True,
            )
        )
        db_session.flush()
        return {"user": user, "profile": profile, "headers": auth_headers(user)}

    return _factory


@pytest.fixture
def worker(make_worker) -> dict:
    return make_worker()


@pytest.fixture
def other_worker(make_worker) -> dict:
    return make_worker("Brian Otieno")


@pytest.fixture
def passportless(make_user, auth_headers) -> dict:
    """A worker account with no Work Passport yet."""
    user = make_user(role=UserRole.WORKER)
    return {"user": user, "headers": auth_headers(user)}


@pytest.fixture
def aggregated_job(db_session, catalogue, org_factory):
    """An externally sourced listing: visible, but applications route elsewhere."""
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
    job = Job(
        id=uuid.uuid4(),
        title="Welder wanted for port expansion",
        description="SMAW welder needed for structural steelwork on the port expansion.",
        trade_id=catalogue["trades"]["WELDING"].id,
        organization_id=org_factory("Coastal Fabrication Ltd").id,
        status=JobStatus.OPEN.value,
        published_at=utcnow() - timedelta(days=2),
        closing_at=utcnow() + timedelta(days=5),
        source_id=source.id,
        source_type=JobSourceType.AGGREGATED_PUBLIC.value,
        source_name=source.name,
        source_job_id="ext-9911",
        external_apply_url="https://jobs.example.com/listing/ext-9911/apply",
        is_aggregated=True,
    )
    db_session.add_all([source, job])
    db_session.flush()
    return {"job": job, "id": str(job.id)}


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def job_payload(**overrides) -> dict:
    body = {
        "title": "Experienced mason needed",
        "description": "Two masons required for a residential development of 24 units.",
        "trade_code": "MASONRY",
        "county_code": "NAKURU",
        "location": "Nakuru Town",
        "employment_type": "FULL_TIME",
        "experience_level": "ENTRY",
    }
    body.update(overrides)
    return body


def create_draft(client, actor: dict, **overrides) -> dict:
    response = client.post(
        f"/organizations/{actor['org_id']}/jobs",
        headers=actor["headers"],
        json=job_payload(**overrides),
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


def open_job(client, actor: dict, **overrides) -> dict:
    created = create_draft(client, actor, **overrides)
    assert publish(client, actor, created["id"]).status_code == 200
    return created


def apply(client, actor: dict, job: str, **body):
    return client.post(f"/jobs/{job}/applications", headers=actor["headers"], json=body)


def submit(client, actor: dict, job: str, **body) -> dict:
    response = apply(client, actor, job, **body)
    assert response.status_code == 201, response.text
    return response.json()["data"]


def withdraw(client, actor: dict, application_id: str):
    return client.post(f"/applications/{application_id}/withdraw", headers=actor["headers"])


def move(client, actor: dict, application_id: str, status: str, **body):
    return client.patch(
        f"/applications/{application_id}/status",
        headers=actor["headers"],
        json={"status": status, **body},
    )


def listing(client, actor: dict, job_id: str, query: str = ""):
    return client.get(
        f"/organizations/{actor['org_id']}/jobs/{job_id}/applications{query}",
        headers=actor["headers"],
    )


def pagination_of(body: dict) -> dict:
    meta = body["meta"]
    return meta.get("pagination") or meta


def as_text(value) -> str:
    return json.dumps(value, default=str)


def same_error(first, second) -> bool:
    """Two refusals must be indistinguishable apart from their request ids."""
    return (
        first["error"]["code"] == second["error"]["code"]
        and first["error"]["message"] == second["error"]["message"]
    )


def stored_applications(db_session, job_id: str) -> list[JobApplication]:
    return list(
        db_session.execute(select(JobApplication).where(JobApplication.job_id == uuid.UUID(job_id)))
        .scalars()
        .all()
    )


def competing_application(
    db_session, job_id: str, worker_profile_id, *, idempotency_key: str | None = None
) -> JobApplication:
    """Write the row a concurrent submit would have committed first."""
    row = JobApplication(
        job_id=uuid.UUID(job_id),
        worker_profile_id=worker_profile_id,
        status=ApplicationStatus.SUBMITTED.value,
        submitted_at=utcnow(),
        idempotency_key=idempotency_key,
    )
    db_session.add(row)
    db_session.flush()
    return row


def force_status(db_session, application_id: str, status: str) -> None:
    """Put an application into a state no single request would reach."""
    row = db_session.get(JobApplication, uuid.UUID(application_id))
    row.status = status
    row.updated_status_at = utcnow()
    db_session.flush()


def inbox(db_session, user_id) -> list[Notification]:
    return list(
        db_session.execute(
            select(Notification)
            .where(Notification.recipient_user_id == user_id)
            .order_by(Notification.created_at)
        )
        .scalars()
        .all()
    )


def denied_rows(db_session, operation: str) -> list[AuditLog]:
    return [
        row
        for row in db_session.execute(select(AuditLog).where(AuditLog.outcome == "DENIED"))
        .scalars()
        .all()
        if row.metadata_.get("operation") == operation
    ]


# --------------------------------------------------------------------------- #
# Applying                                                                     #
# --------------------------------------------------------------------------- #
class TestApply:
    def test_a_worker_can_apply(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        data = submit(client, worker, job["id"], cover_note="Available from Monday.")
        assert data["status"] == ApplicationStatus.SUBMITTED.value
        assert data["job"]["id"] == job["id"]
        assert data["worker"]["id"] == str(worker["profile"].id)
        assert data["cover_note"] == "Available from Monday."
        assert data["submitted_at"] is not None
        assert data["withdrawn_at"] is None
        assert data["decided_at"] is None
        assert data["is_active"] is True

    def test_the_job_status_is_derived_not_stored(
        self, client, db_session, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        row = db_session.get(Job, uuid.UUID(job["id"]))
        row.published_at = utcnow() - timedelta(days=4)
        row.closing_at = utcnow() - timedelta(hours=1)
        db_session.flush()
        read = client.get(
            f"/workers/me/applications/{application['id']}", headers=worker["headers"]
        ).json()["data"]
        assert read["job"]["status"] == JobStatus.EXPIRED.value

    @pytest.mark.parametrize("status", ["SHORTLISTED", "HIRED", "VIEWED", "WITHDRAWN"])
    def test_the_status_cannot_be_supplied(
        self, client, db_session, worker, employer_a, status
    ) -> None:
        job = open_job(client, employer_a)
        assert apply(client, worker, job["id"], status=status).status_code == 422
        assert stored_applications(db_session, job["id"]) == []

    def test_worker_identity_cannot_be_supplied(
        self, client, worker, other_worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        response = apply(
            client,
            worker,
            job["id"],
            worker_id=str(other_worker["profile"].id),
            worker_profile_id=str(other_worker["profile"].id),
        )
        assert response.status_code == 422
        assert listing(client, employer_a, job["id"]).json()["meta"]["total_items"] == 0

    def test_the_job_id_cannot_be_supplied(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        assert apply(client, worker, job["id"], job_id=str(uuid.uuid4())).status_code == 422

    def test_the_counter_is_not_writable(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        assert apply(client, worker, job["id"], application_count=99).status_code == 422

    def test_the_job_application_count_is_maintained(
        self, client, worker, other_worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        submit(client, worker, job["id"])
        assert client.get(f"/jobs/{job['id']}").json()["data"]["application_count"] == 1

        other = open_job(client, employer_a, title="Second mason vacancy")
        submit(client, other_worker, other["id"])
        assert client.get(f"/jobs/{other['id']}").json()["data"]["application_count"] == 1

    def test_withdrawing_lowers_the_counter(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        assert withdraw(client, worker, application["id"]).status_code == 200
        assert client.get(f"/jobs/{job['id']}").json()["data"]["application_count"] == 0

    def test_requires_authentication(self, client, employer_a) -> None:
        job = open_job(client, employer_a)
        assert client.post(f"/jobs/{job['id']}/applications", json={}).status_code == 401

    def test_an_employer_may_not_apply(self, client, employer_a) -> None:
        job = open_job(client, employer_a)
        response = apply(client, employer_a, job["id"])
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "INSUFFICIENT_ROLE"

    def test_a_worker_without_a_passport_is_a_404(
        self, client, db_session, passportless, employer_a
    ) -> None:
        """There is nothing to attach the application to, so nothing is written."""
        job = open_job(client, employer_a)
        assert apply(client, passportless, job["id"]).status_code == 404
        assert stored_applications(db_session, job["id"]) == []

    def test_submission_is_audited(self, client, worker, employer_a, audit_rows) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        rows = audit_rows(resource_type="job_application", resource_id=uuid.UUID(application["id"]))
        submitted = [row for row in rows if row.action == "APPLICATION_SUBMITTED"]
        assert len(submitted) == 1
        assert submitted[0].outcome == "SUCCESS"
        assert submitted[0].actor_user_id == worker["user"].id
        assert submitted[0].metadata_["job_id"] == job["id"]


# --------------------------------------------------------------------------- #
# One application per worker per job                                           #
# --------------------------------------------------------------------------- #
class TestUniqueness:
    def test_a_second_application_is_a_conflict(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        submit(client, worker, job["id"])
        response = apply(client, worker, job["id"])
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "DUPLICATE_APPLICATION"
        assert "already applied" in response.json()["error"]["message"]

    def test_another_worker_may_apply_to_the_same_job(
        self, client, worker, other_worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        submit(client, worker, job["id"])
        assert apply(client, other_worker, job["id"]).status_code == 201

    def test_a_withdrawn_worker_cannot_reapply(self, client, worker, employer_a) -> None:
        """Withdrawal is not a reset: the row, and the constraint, both remain."""
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        withdraw(client, worker, application["id"])
        assert apply(client, worker, job["id"]).status_code == 409

    def test_the_loser_of_a_race_loses_on_the_constraint(
        self, client, db_session, worker, employer_a
    ) -> None:
        """Two simultaneous submits must not both succeed, and one row must survive.

        The service has no duplicate pre-check, so the state a race leaves behind -
        the competing row already written, with nothing to notice it - is exactly
        what the losing request meets. A second connection cannot be used here
        because the fixtures live in this test's uncommitted transaction, so the
        race is reproduced rather than raced. What matters is that the refusal
        comes from ``uq_job_applications_job_worker`` and not from a read.
        """
        job = open_job(client, employer_a)
        competing_application(db_session, job["id"], worker["profile"].id)

        response = apply(client, worker, job["id"])
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "DUPLICATE_APPLICATION"

        db_session.expire_all()
        assert len(stored_applications(db_session, job["id"])) == 1

    def test_the_refusal_records_which_rule_fired(
        self, client, db_session, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        competing_application(db_session, job["id"], worker["profile"].id)
        apply(client, worker, job["id"])

        refusals = denied_rows(db_session, "submit_application")
        assert any(
            row.metadata_.get("constraint") == "uq_job_applications_job_worker" for row in refusals
        )

    def test_a_retry_with_the_same_idempotency_key_replays(
        self, client, worker, employer_a
    ) -> None:
        """A retry over a poor connection must not look like a refusal."""
        job = open_job(client, employer_a)
        body = {"idempotency_key": "apply-nakuru-mason-0001"}
        first = submit(client, worker, job["id"], **body)
        second = apply(client, worker, job["id"], **body)
        assert second.status_code == 200
        assert second.json()["data"]["id"] == first["id"]

    def test_reusing_a_key_for_another_job_is_a_conflict(self, client, worker, employer_a) -> None:
        one = open_job(client, employer_a)
        two = open_job(client, employer_a, title="Second mason vacancy")
        body = {"idempotency_key": "apply-nakuru-mason-0002"}
        submit(client, worker, one["id"], **body)
        response = apply(client, worker, two["id"], **body)
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "IDEMPOTENCY_KEY_REUSED"

    @pytest.mark.parametrize("key", ["short", "spaces are out", "x" * 101])
    def test_a_malformed_idempotency_key_is_a_422(self, client, worker, employer_a, key) -> None:
        job = open_job(client, employer_a)
        assert apply(client, worker, job["id"], idempotency_key=key).status_code == 422

    def test_two_identical_retries_on_one_key_leave_one_row(
        self, client, db_session, monkeypatch, worker, employer_a
    ) -> None:
        """The same request racing itself is a retry, not a refusal.

        The competing commit lands between the replay lookup and the insert, which
        is the window a real race occupies and is unreachable from a single
        connection. Patching the lookup to commit the competitor there reproduces
        exactly that, and the answer must be the row the winner created.
        """
        job = open_job(client, employer_a)
        key = "apply-nakuru-mason-0003"
        original = ApplicationService._idempotent_replay
        injected: list[bool] = []

        def racing(self, **kwargs):
            result = original(self, **kwargs)
            if not injected:
                injected.append(True)
                competing_application(
                    db_session, job["id"], worker["profile"].id, idempotency_key=key
                )
            return result

        monkeypatch.setattr(ApplicationService, "_idempotent_replay", racing)
        response = apply(client, worker, job["id"], idempotency_key=key)
        assert response.status_code == 200, response.text
        assert len(stored_applications(db_session, job["id"])) == 1


# --------------------------------------------------------------------------- #
# Which jobs accept applications                                               #
# --------------------------------------------------------------------------- #
class TestJobEligibility:
    def _refusal(self, response) -> dict:
        assert response.status_code == 409, response.text
        return response.json()["error"]

    def test_a_closed_job_refuses_with_a_reason(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        assert act(client, employer_a, job["id"], "close").status_code == 200
        error = self._refusal(apply(client, worker, job["id"]))
        assert error["code"] == "JOB_NOT_ACCEPTING_APPLICATIONS"
        assert "closed" in error["message"]

    def test_a_cancelled_job_refuses_with_a_reason(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        act(client, employer_a, job["id"], "cancel")
        assert "cancelled" in self._refusal(apply(client, worker, job["id"]))["message"]

    def test_an_expired_job_refuses_with_a_reason(
        self, client, db_session, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        row = db_session.get(Job, uuid.UUID(job["id"]))
        row.published_at = utcnow() - timedelta(days=4)
        row.closing_at = utcnow() - timedelta(days=1)
        db_session.flush()
        assert "closing date" in self._refusal(apply(client, worker, job["id"]))["message"]

    def test_a_draft_is_a_404_exactly_like_an_unknown_id(self, client, worker, employer_a) -> None:
        """A worker must not be able to learn that an unpublished listing exists."""
        draft = create_draft(client, employer_a)
        draft_response = apply(client, worker, draft["id"])
        unknown_response = apply(client, worker, str(uuid.uuid4()))
        assert draft_response.status_code == unknown_response.status_code == 404
        assert same_error(draft_response.json(), unknown_response.json())

    def test_an_aggregated_listing_routes_the_worker_elsewhere(
        self, client, worker, aggregated_job
    ) -> None:
        error = self._refusal(apply(client, worker, aggregated_job["id"]))
        assert "another site" in error["message"]

    def test_an_unknown_job_is_a_404(self, client, worker) -> None:
        assert apply(client, worker, str(uuid.uuid4())).status_code == 404

    def test_a_refused_job_writes_no_application(
        self, client, db_session, worker, employer_a
    ) -> None:
        draft = create_draft(client, employer_a)
        apply(client, worker, draft["id"])
        assert stored_applications(db_session, draft["id"]) == []


# --------------------------------------------------------------------------- #
# A worker's own applications                                                  #
# --------------------------------------------------------------------------- #
class TestWorkerScope:
    def test_a_worker_lists_their_own(self, client, worker, other_worker, employer_a) -> None:
        job = open_job(client, employer_a)
        submit(client, worker, job["id"])
        submit(client, other_worker, job["id"])

        response = client.get("/workers/me/applications", headers=worker["headers"])
        assert response.status_code == 200
        rows = response.json()["data"]
        assert len(rows) == 1
        assert rows[0]["worker"]["id"] == str(worker["profile"].id)

    def test_the_list_is_scoped_by_the_caller(
        self, client, worker, other_worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        theirs = submit(client, other_worker, job["id"])
        response = client.get("/workers/me/applications", headers=worker["headers"])
        assert theirs["id"] not in response.text

    def test_another_worker_cannot_read_it(self, client, worker, other_worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        response = client.get(
            f"/workers/me/applications/{application['id']}", headers=other_worker["headers"]
        )
        assert response.status_code == 404
        assert "Amina" not in response.text

    def test_another_worker_cannot_withdraw_it(
        self, client, worker, other_worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        assert withdraw(client, other_worker, application["id"]).status_code == 404
        assert client.get(f"/jobs/{job['id']}").json()["data"]["application_count"] == 1

    def test_a_foreign_id_is_the_same_404_as_an_invented_one(
        self, client, worker, other_worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        foreign = client.get(
            f"/workers/me/applications/{application['id']}", headers=other_worker["headers"]
        )
        invented = client.get(
            f"/workers/me/applications/{uuid.uuid4()}", headers=other_worker["headers"]
        )
        assert foreign.status_code == invented.status_code == 404
        assert same_error(foreign.json(), invented.json())

    def test_the_worker_reads_their_own(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        response = client.get(
            f"/workers/me/applications/{application['id']}", headers=worker["headers"]
        )
        assert response.status_code == 200
        assert response.json()["data"]["status"] == ApplicationStatus.SUBMITTED.value

    def test_the_listing_requires_authentication(self, client) -> None:
        assert client.get("/workers/me/applications").status_code == 401

    def test_an_employer_has_no_worker_view(self, client, employer_a) -> None:
        response = client.get("/workers/me/applications", headers=employer_a["headers"])
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "INSUFFICIENT_ROLE"

    def test_the_worker_view_never_carries_contact_details(
        self, client, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        submit(client, worker, job["id"])
        body = client.get("/workers/me/applications", headers=worker["headers"]).text
        assert "0712345678" not in body
        assert "amina.private@example.com" not in body

    def test_a_filter_and_pagination(self, client, worker, employer_a) -> None:
        for index in range(3):
            job = open_job(client, employer_a, title=f"Vacancy {index}")
            submit(client, worker, job["id"])

        page = client.get(
            "/workers/me/applications?page=1&page_size=2", headers=worker["headers"]
        ).json()
        assert len(page["data"]) == 2
        assert pagination_of(page)["total_items"] == 3
        assert pagination_of(page)["total_pages"] == 2

    def test_a_filter_for_a_status_nobody_is_in(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        submit(client, worker, job["id"])
        response = client.get(
            "/workers/me/applications?status=WITHDRAWN", headers=worker["headers"]
        )
        assert response.status_code == 200
        assert response.json()["data"] == []

    def test_an_unknown_status_filter_is_a_422(self, client, worker) -> None:
        response = client.get(
            "/workers/me/applications?status=IMAGINARY", headers=worker["headers"]
        )
        assert response.status_code == 422

    @pytest.mark.parametrize("query", ["?page_size=500", "?page=0"])
    def test_page_bounds_are_enforced(self, client, worker, query) -> None:
        assert (
            client.get(f"/workers/me/applications{query}", headers=worker["headers"]).status_code
            == 422
        )


# --------------------------------------------------------------------------- #
# Withdrawing                                                                  #
# --------------------------------------------------------------------------- #
class TestWithdraw:
    def test_withdraw(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        response = withdraw(client, worker, application["id"])
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["status"] == ApplicationStatus.WITHDRAWN.value
        assert data["withdrawn_at"] is not None
        assert data["is_active"] is False

    def test_withdrawing_twice_is_refused(self, client, worker, employer_a) -> None:
        """A repeated action must not answer 200 as though something happened."""
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        assert withdraw(client, worker, application["id"]).status_code == 200
        second = withdraw(client, worker, application["id"])
        assert second.status_code == 409
        assert second.json()["error"]["code"] == "INVALID_STATE_TRANSITION"
        assert "withdrawn" in second.json()["error"]["message"]

    def test_withdraw_after_hired_is_refused(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        assert move(client, employer_a, application["id"], "HIRED").status_code == 200
        response = withdraw(client, worker, application["id"])
        assert response.status_code == 409
        assert "hire" in response.json()["error"]["message"]
        assert (
            client.get(
                f"/workers/me/applications/{application['id']}", headers=worker["headers"]
            ).json()["data"]["status"]
            == "HIRED"
        )

    @pytest.mark.parametrize("status", ["VIEWED", "SHORTLISTED", "REJECTED"])
    def test_withdraw_is_legal_before_a_hire(self, client, worker, employer_a, status) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        assert move(client, employer_a, application["id"], status).status_code == 200
        response = withdraw(client, worker, application["id"])
        assert response.status_code == 200, response.text
        assert response.json()["data"]["status"] == "WITHDRAWN"

    def test_the_row_survives_withdrawal(self, client, worker, employer_a) -> None:
        """The employer needs to see that the candidate withdrew, not that it vanished."""
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        withdraw(client, worker, application["id"])

        rows = listing(client, employer_a, job["id"]).json()["data"]
        assert len(rows) == 1
        assert rows[0]["status"] == "WITHDRAWN"
        assert rows[0]["withdrawn_at"] is not None

    def test_a_withdrawn_application_is_still_readable(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        withdraw(client, worker, application["id"])
        response = client.get(
            f"/workers/me/applications/{application['id']}", headers=worker["headers"]
        )
        assert response.status_code == 200
        assert response.json()["data"]["status"] == "WITHDRAWN"

    def test_there_is_no_delete(self, client, db_session, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        response = client.delete(f"/applications/{application['id']}", headers=worker["headers"])
        assert response.status_code in (404, 405)
        assert len(stored_applications(db_session, job["id"])) == 1

    def test_withdrawal_is_audited(self, client, worker, employer_a, audit_rows) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        withdraw(client, worker, application["id"])
        rows = audit_rows(resource_type="job_application", resource_id=uuid.UUID(application["id"]))
        events = [row for row in rows if row.action == "APPLICATION_WITHDRAWN"]
        assert len(events) == 1
        assert events[0].outcome == "SUCCESS"

    def test_a_job_with_no_organization_tells_nobody(self, client, db_session, worker) -> None:
        """An organization-less listing has no employer to address; the move stands."""
        job = Job(
            id=uuid.uuid4(),
            title="Unpublished mason vacancy",
            description="Two masons required for a residential development of 24 units.",
            status=JobStatus.DRAFT.value,
        )
        application = JobApplication(
            job_id=job.id,
            worker_profile_id=worker["profile"].id,
            status=ApplicationStatus.SUBMITTED.value,
            submitted_at=utcnow(),
        )
        db_session.add_all([job, application])
        db_session.flush()

        withdrawn = ApplicationService(db_session).withdraw(
            actor=worker["user"], application_id=application.id
        )
        assert withdrawn.status_enum is ApplicationStatus.WITHDRAWN
        assert inbox(db_session, worker["user"].id) == []

    def test_a_refused_withdrawal_is_audited_durably(
        self, client, worker, employer_a, audit_rows
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        move(client, employer_a, application["id"], "HIRED")
        withdraw(client, worker, application["id"])

        rows = audit_rows(resource_type="job_application", resource_id=uuid.UUID(application["id"]))
        denied = [
            row for row in rows if row.action == "APPLICATION_WITHDRAWN" and row.outcome == "DENIED"
        ]
        assert len(denied) == 1
        assert denied[0].metadata_["previous_status"] == "HIRED"


# --------------------------------------------------------------------------- #
# Employer transitions                                                         #
# --------------------------------------------------------------------------- #
class TestEmployerTransitions:
    def test_every_legal_transition_is_accepted(
        self, client, db_session, make_worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        for source, target in LEGAL:
            application = submit(client, make_worker(), job["id"])
            force_status(db_session, application["id"], source)
            response = move(client, employer_a, application["id"], target)
            assert response.status_code == 200, f"{source}->{target}: {response.text}"
            assert response.json()["data"]["status"] == target

    def test_every_illegal_transition_is_refused(
        self, client, db_session, make_worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        for source, target in ILLEGAL:
            application = submit(client, make_worker(), job["id"])
            force_status(db_session, application["id"], source)
            response = move(client, employer_a, application["id"], target)
            assert response.status_code == 409, f"{source}->{target} was allowed"
            assert response.json()["error"]["code"] == "INVALID_STATE_TRANSITION"

    def test_a_refused_transition_leaves_the_row_alone(
        self, client, db_session, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        move(client, employer_a, application["id"], "HIRED")
        assert move(client, employer_a, application["id"], "SHORTLISTED").status_code == 409
        row = db_session.get(JobApplication, uuid.UUID(application["id"]))
        assert row.status == ApplicationStatus.HIRED.value

    def test_a_decision_records_who_decided(self, client, db_session, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        data = move(
            client, employer_a, application["id"], "REJECTED", decision_note="Trade mismatch"
        ).json()["data"]
        assert data["decided_at"] is not None
        assert data["decision_note"] == "Trade mismatch"
        row = db_session.get(JobApplication, uuid.UUID(application["id"]))
        assert row.decided_by_user_id == employer_a["user"].id

    def test_viewing_does_not_record_a_decision(
        self, client, db_session, worker, employer_a
    ) -> None:
        """`VIEWED` is an acknowledgement, so it must not claim somebody decided."""
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        data = move(client, employer_a, application["id"], "VIEWED").json()["data"]
        assert data["status"] == "VIEWED"
        assert data["decided_at"] is None
        row = db_session.get(JobApplication, uuid.UUID(application["id"]))
        assert row.decided_by_user_id is None

    def test_a_self_transition_is_refused(self, client, db_session, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        move(client, employer_a, application["id"], "SHORTLISTED")
        assert move(client, employer_a, application["id"], "SHORTLISTED").status_code == 409

    def test_a_rejection_can_be_undone(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        assert move(client, employer_a, application["id"], "REJECTED").status_code == 200
        assert move(client, employer_a, application["id"], "SHORTLISTED").status_code == 200

    def test_a_withdrawal_keeps_the_decision_before_it(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        move(client, employer_a, application["id"], "REJECTED", decision_note="No site work")
        data = withdraw(client, worker, application["id"]).json()["data"]
        assert data["status"] == "WITHDRAWN"
        assert data["decided_at"] is not None
        assert data["decision_note"] == "No site work"

    def test_a_status_change_is_audited(self, client, worker, employer_a, audit_rows) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        move(client, employer_a, application["id"], "SHORTLISTED")
        rows = audit_rows(resource_type="job_application", resource_id=uuid.UUID(application["id"]))
        changes = [row for row in rows if row.action == "APPLICATION_STATUS_CHANGED"]
        assert len(changes) == 1
        assert changes[0].outcome == "SUCCESS"
        assert changes[0].metadata_["previous_status"] == "SUBMITTED"
        assert changes[0].metadata_["new_status"] == "SHORTLISTED"

    def test_a_refused_transition_is_audited_durably(
        self, client, db_session, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        move(client, employer_a, application["id"], "HIRED")
        move(client, employer_a, application["id"], "SHORTLISTED")
        refusals = denied_rows(db_session, "change_application_status")
        assert refusals
        assert refusals[-1].metadata_["previous_status"] == "HIRED"

    def test_an_employer_cannot_withdraw_for_the_worker(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        response = move(client, employer_a, application["id"], "WITHDRAWN")
        assert response.status_code == 409
        assert "WITHDRAWN" in response.json()["error"]["message"]

    def test_the_worker_role_cannot_reach_the_employer_route(
        self, client, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        response = move(client, worker, application["id"], "SHORTLISTED")
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "INSUFFICIENT_ROLE"

    @pytest.mark.parametrize("target", ["SHORTLISTED", "HIRED", "REJECTED", "VIEWED"])
    def test_the_state_machine_refuses_a_worker_decision(
        self, client, db_session, worker, employer_a, target
    ) -> None:
        """The lifecycle, not the route, is what says no.

        Reaching this through the service rather than over HTTP proves the refusal
        comes from the state machine. The route's role gate is a second, independent
        line of defence, not the only one.
        """
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        with pytest.raises(InvalidStateTransitionError) as raised:
            ApplicationService(db_session).change_status(
                actor=worker["user"],
                application_id=uuid.UUID(application["id"]),
                payload=ApplicationStatusChangeRequest(status=ApplicationStatus(target)),
            )
        assert "employer's decision" in str(raised.value)

    def test_a_worker_cannot_move_somebody_elses_application(
        self, client, db_session, worker, other_worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, other_worker, job["id"])
        with pytest.raises(ApplicationNotFoundError):
            ApplicationService(db_session).change_status(
                actor=worker["user"],
                application_id=uuid.UUID(application["id"]),
                payload=ApplicationStatusChangeRequest(status=ApplicationStatus.SHORTLISTED),
            )

    def test_the_worker_table_holds_no_employer_decision(self) -> None:
        """The structural guarantee, asserted directly."""
        for source, targets in WORKER_TRANSITIONS.items():
            assert targets <= {ApplicationStatus.WITHDRAWN}, source

    def test_hired_and_withdrawn_are_terminal(self) -> None:
        assert EMPLOYER_TRANSITIONS[ApplicationStatus.HIRED] == frozenset()
        assert EMPLOYER_TRANSITIONS[ApplicationStatus.WITHDRAWN] == frozenset()
        assert WORKER_TRANSITIONS[ApplicationStatus.HIRED] == frozenset()
        assert WORKER_TRANSITIONS[ApplicationStatus.WITHDRAWN] == frozenset()

    def test_an_unknown_status_is_a_422(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        response = client.patch(
            f"/applications/{application['id']}/status",
            headers=employer_a["headers"],
            json={"status": "PROMOTED"},
        )
        assert response.status_code == 422

    def test_worker_id_cannot_be_supplied_on_a_status_change(
        self, client, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        response = client.patch(
            f"/applications/{application['id']}/status",
            headers=employer_a["headers"],
            json={"status": "VIEWED", "worker_id": str(uuid.uuid4())},
        )
        assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Cross-organization isolation                                                 #
# --------------------------------------------------------------------------- #
class TestCrossOrganization:
    @pytest.fixture
    def victim(self, client, employer_a, worker) -> dict:
        job = open_job(client, employer_a)
        return {
            "org_id": employer_a["org_id"],
            "job": job,
            "application": submit(client, worker, job["id"]),
        }

    def test_an_employer_sees_only_their_own_pipeline(
        self, client, employer_a, employer_b, victim, other_worker
    ) -> None:
        their_job = open_job(client, employer_b)
        submit(client, other_worker, their_job["id"])

        mine = listing(client, employer_a, victim["job"]["id"])
        assert victim["application"]["id"] in {row["id"] for row in mine.json()["data"]}
        assert victim["application"]["id"] not in listing(client, employer_b, their_job["id"]).text

    def test_another_employer_cannot_list(self, client, employer_b, victim) -> None:
        response = listing(client, employer_b, victim["job"]["id"])
        assert response.status_code == 404
        assert victim["application"]["id"] not in response.text

    def test_a_non_member_employer_cannot_list(self, client, outsider, victim) -> None:
        response = client.get(
            f"/organizations/{victim['org_id']}/jobs/{victim['job']['id']}/applications",
            headers=outsider["headers"],
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "JOB_MANAGEMENT_FORBIDDEN"

    def test_a_plain_member_cannot_list(self, client, employer, victim) -> None:
        plain = employer(role=OrganizationRole.MEMBER)
        assert listing(client, plain, victim["job"]["id"]).status_code == 403

    def test_a_suspended_membership_cannot_list(self, client, employer, victim) -> None:
        suspended = employer(membership_status=MembershipStatus.SUSPENDED)
        assert listing(client, suspended, victim["job"]["id"]).status_code == 403

    def test_a_worker_cannot_list(self, client, worker, victim) -> None:
        response = client.get(
            f"/organizations/{victim['org_id']}/jobs/{victim['job']['id']}/applications",
            headers=worker["headers"],
        )
        assert response.status_code == 403

    def test_another_employer_cannot_change_the_status(self, client, employer_b, victim) -> None:
        response = move(client, employer_b, victim["application"]["id"], "REJECTED")
        assert response.status_code == 404
        assert "Amina" not in response.text

    def test_a_denied_status_change_is_audited_durably(
        self, client, db_session, employer_b, victim
    ) -> None:
        move(client, employer_b, victim["application"]["id"], "REJECTED")
        assert denied_rows(db_session, "change_application_status"), (
            "a refused cross-tenant status change left no audit row"
        )

    def test_a_non_member_gets_the_same_404_as_a_guessed_id(self, client, outsider, victim) -> None:
        """Same answer either way, so nothing is confirmed by probing."""
        real = move(client, outsider, victim["application"]["id"], "REJECTED")
        invented = move(client, outsider, str(uuid.uuid4()), "REJECTED")
        assert real.status_code == invented.status_code == 404
        assert same_error(real.json(), invented.json())

    def test_substituting_the_organization_matches_nothing(
        self, client, employer_b, victim
    ) -> None:
        response = client.get(
            f"/organizations/{employer_b['org_id']}/jobs/{victim['job']['id']}/applications",
            headers=employer_b["headers"],
        )
        assert response.status_code == 404

    def test_an_admin_without_membership_cannot_change_the_status(
        self, client, make_admin, auth_headers, victim
    ) -> None:
        admin = {"headers": auth_headers(make_admin())}
        assert move(client, admin, victim["application"]["id"], "REJECTED").status_code == 404

    def test_an_unknown_application_id_is_a_404(self, client, employer_a) -> None:
        assert move(client, employer_a, str(uuid.uuid4()), "SHORTLISTED").status_code == 404

    def test_an_unknown_job_id_is_a_404(self, client, employer_a) -> None:
        response = client.get(
            f"/organizations/{employer_a['org_id']}/jobs/{uuid.uuid4()}/applications",
            headers=employer_a["headers"],
        )
        assert response.status_code == 404


# --------------------------------------------------------------------------- #
# The employer's view                                                           #
# --------------------------------------------------------------------------- #
class TestEmployerListing:
    def test_the_employer_lists_the_applicants(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        response = listing(client, employer_a, job["id"])
        assert response.status_code == 200
        rows = response.json()["data"]
        assert len(rows) == 1
        assert rows[0]["id"] == application["id"]
        assert rows[0]["worker"]["display_name"] == "Amina Wanjiru"
        assert rows[0]["worker"]["primary_trade_code"] == "MASONRY"
        assert rows[0]["job"]["organization_name"] == "Buildwell Contractors"

    def test_the_listing_never_carries_contact_details(self, client, worker, employer_a) -> None:
        """Assert on the security property, not on the status code."""
        job = open_job(client, employer_a)
        submit(client, worker, job["id"])
        response = listing(client, employer_a, job["id"])
        assert "0712345678" not in response.text
        assert "amina.private@example.com" not in response.text
        assert "Halima" not in response.text

    def test_the_listing_carries_no_rank_or_score(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        submit(client, worker, job["id"])
        row = listing(client, employer_a, job["id"]).json()["data"][0]
        text = as_text(row).lower()
        assert not any(word in text for word in RANKING_WORDS)

    def test_filters_by_status(self, client, worker, other_worker, employer_a) -> None:
        job = open_job(client, employer_a)
        kept = submit(client, worker, job["id"])
        dropped = submit(client, other_worker, job["id"])
        move(client, employer_a, kept["id"], "SHORTLISTED")

        response = listing(client, employer_a, job["id"], "?status=SHORTLISTED")
        assert [row["id"] for row in response.json()["data"]] == [kept["id"]]
        assert dropped["id"] not in response.text

    def test_paginates(self, client, make_worker, employer_a) -> None:
        job = open_job(client, employer_a)
        ids = [submit(client, make_worker(), job["id"])["id"] for _ in range(3)]

        page = listing(client, employer_a, job["id"], "?page=1&page_size=2").json()
        assert len(page["data"]) == 2
        assert pagination_of(page)["total_items"] == 3

        seen: set[str] = set()
        for number in (1, 2):
            body = listing(client, employer_a, job["id"], f"?page={number}&page_size=2").json()
            seen.update(row["id"] for row in body["data"])
        assert seen == set(ids)

    def test_the_list_is_newest_first(self, client, make_worker, employer_a) -> None:
        job = open_job(client, employer_a)
        ids = [submit(client, make_worker(), job["id"])["id"] for _ in range(3)]
        newest_first = [row["id"] for row in listing(client, employer_a, job["id"]).json()["data"]]
        assert newest_first == list(reversed(ids))

    def test_a_status_change_is_visible_to_both_sides(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        move(client, employer_a, application["id"], "HIRED")
        assert listing(client, employer_a, job["id"]).json()["data"][0]["status"] == "HIRED"

    def test_the_cover_note_is_shown_to_the_employer(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        submit(client, worker, job["id"], cover_note="I can start on site tomorrow.")
        assert "start on site tomorrow" in listing(client, employer_a, job["id"]).text

    def test_an_empty_pipeline_is_an_empty_page(self, client, employer_a) -> None:
        job = open_job(client, employer_a)
        response = listing(client, employer_a, job["id"])
        assert response.status_code == 200
        assert response.json()["data"] == []


# --------------------------------------------------------------------------- #
# Notifications                                                                #
# --------------------------------------------------------------------------- #
class TestNotifications:
    def test_a_status_change_notifies_the_worker(
        self, client, db_session, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        move(client, employer_a, application["id"], "SHORTLISTED")

        events = [
            row
            for row in inbox(db_session, worker["user"].id)
            if row.event_type == "APPLICATION_STATUS_CHANGED"
        ]
        assert len(events) == 1
        assert "SHORTLISTED" in events[0].body
        assert events[0].related_resource_id == uuid.UUID(application["id"])

    def test_the_worker_is_the_only_recipient(self, client, db_session, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        move(client, employer_a, application["id"], "REJECTED")
        assert inbox(db_session, employer_a["user"].id) == []

    def test_a_withdrawal_notifies_the_employer(
        self, client, db_session, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        withdraw(client, worker, application["id"])

        events = [
            row
            for row in inbox(db_session, employer_a["user"].id)
            if row.event_type == "APPLICATION_WITHDRAWN"
        ]
        assert len(events) == 1
        assert job["title"] in events[0].body

    def test_the_worker_is_not_told_their_own_withdrawal(
        self, client, db_session, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        withdraw(client, worker, application["id"])
        assert inbox(db_session, worker["user"].id) == []

    def test_the_wording_ranks_nobody(self, client, db_session, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        move(client, employer_a, application["id"], "SHORTLISTED")
        withdraw(client, worker, application["id"])

        rows = [
            *inbox(db_session, worker["user"].id),
            *inbox(db_session, employer_a["user"].id),
        ]
        assert rows
        for row in rows:
            text = as_text({"title": row.title, "body": row.body}).lower()
            assert not any(word in text for word in RANKING_WORDS), text

    def test_a_refused_transition_notifies_nobody(
        self, client, db_session, worker, employer_a
    ) -> None:
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        move(client, employer_a, application["id"], "HIRED")
        before = len(inbox(db_session, worker["user"].id))
        assert move(client, employer_a, application["id"], "SHORTLISTED").status_code == 409
        assert len(inbox(db_session, worker["user"].id)) == before

    def test_an_owner_is_told_when_the_job_has_no_poster(
        self, client, db_session, worker, employer_a
    ) -> None:
        """A row written by ingestion has no ``created_by_user_id`` to address."""
        job = open_job(client, employer_a)
        application = submit(client, worker, job["id"])
        db_session.get(Job, uuid.UUID(job["id"])).created_by_user_id = None
        db_session.flush()
        withdraw(client, worker, application["id"])

        events = [
            row
            for row in inbox(db_session, employer_a["user"].id)
            if row.event_type == "APPLICATION_WITHDRAWN"
        ]
        assert len(events) == 1


# --------------------------------------------------------------------------- #
# Envelope                                                                     #
# --------------------------------------------------------------------------- #
class TestResponseShape:
    def test_errors_use_the_standard_envelope(self, client, error_code) -> None:
        response = client.get(f"/workers/me/applications/{uuid.uuid4()}")
        assert response.status_code == 401
        assert error_code(response) == "AUTHENTICATION_REQUIRED"
        assert response.json()["error"]["request_id"] is not None

    def test_a_list_carries_pagination_meta(self, client, worker, employer_a) -> None:
        job = open_job(client, employer_a)
        submit(client, worker, job["id"])
        body = client.get("/workers/me/applications", headers=worker["headers"]).json()
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
        assert client.get("/api/v1/workers/me/applications").status_code == 404
