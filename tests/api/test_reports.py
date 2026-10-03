"""End-to-end tests for moderation reports.

The security properties are the point of this file. A report test that only
checked the happy path would pass while another user's report became readable,
while a private passport turned into an existence oracle, or while a reporter
decided their own report's outcome - so each of those is asserted directly.
"""

from __future__ import annotations

from datetime import timedelta
import uuid

import pytest
from sqlalchemy import select

from app.core.constants import (
    AuditAction,
    JobStatus,
    NotificationEventType,
    OrganizationRole,
    ProfileVisibility,
    ReportReason,
    ReportStatus,
    ReportSubjectType,
    VerificationRequestStatus,
    VerificationStatus,
    VerificationTargetType,
)
from app.db.base import utcnow
from app.db.models.job import Job
from app.db.models.moderation import NotificationEvent, Report
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.verification import Verification, VerificationRequest
from app.db.models.worker import WorkerProfile
from app.schemas.reports import ReportDecision, ReportDecisionRequest
from app.services.report_service import REPORTABLE_SUBJECT_TYPES

pytestmark = [pytest.mark.api, pytest.mark.integration]

#: The product's four report targets. ``ORGANIZATION`` is the employer.
REPORTABLE: tuple[str, ...] = (
    ReportSubjectType.WORKER_PROFILE.value,
    ReportSubjectType.ORGANIZATION.value,
    ReportSubjectType.JOB.value,
    ReportSubjectType.VERIFICATION.value,
)

#: One subject key and one entitled reporter per reportable type.
SUBJECT_KEYS: tuple[tuple[str, str, str], ...] = (
    (ReportSubjectType.WORKER_PROFILE.value, "public_profile", "reporter"),
    (ReportSubjectType.ORGANIZATION.value, "organization", "reporter"),
    (ReportSubjectType.JOB.value, "published_job", "reporter"),
    # A verification is visible only to the parties who already know about it, so
    # the entitled reporter here is the worker whose claim it covers.
    (ReportSubjectType.VERIFICATION.value, "verification", "passport_owner"),
)

#: Every moderation field a client might try to set on a report.
FORBIDDEN_FIELDS = ("status", "resolution_note", "resolved_by_user_id", "outcome")

#: Fields the administrator queue is allowed to return. If the reporter's contact
#: details ever appear here, the assertion in `TestAdminQueue` fails.
ADMIN_RESPONSE_FIELDS = {
    "id",
    "subject_type",
    "subject_id",
    "reason",
    "details",
    "status",
    "resolved_at",
    "created_at",
    "updated_at",
    "reporter_ref",
    "resolution_note",
    "resolved_by_user_id",
}


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture
def accounts(make_user, make_admin):
    """A reporter, an unrelated second user, the subjects' owners and an admin."""
    return {
        "reporter": make_user(),
        "intruder": make_user(),
        "passport_owner": make_user(),
        "org_member": make_user(),
        "job_poster": make_user(),
        "verifier": make_user(),
        "admin": make_admin(),
    }


@pytest.fixture
def subjects(db_session, accounts):
    """One reportable subject of every reportable kind, plus three unreportables.

    Ids are assigned explicitly because the primary key default is applied at flush
    time: anything referenced by another fixture row needs a known id up front.
    """
    now = utcnow()

    private_profile = WorkerProfile(
        id=uuid.uuid4(),
        user_id=accounts["passport_owner"].id,
        display_name="Hidden Builder",
        visibility=ProfileVisibility.PRIVATE.value,
    )
    public_profile = WorkerProfile(
        id=uuid.uuid4(),
        user_id=accounts["verifier"].id,
        display_name="Visible Builder",
        visibility=ProfileVisibility.PUBLIC.value,
        phone_number="0712345678",
    )
    organization = Organization(
        id=uuid.uuid4(),
        name="Riverside Contractors",
        slug=f"riverside-{uuid.uuid4().hex[:8]}",
    )
    membership = OrganizationMembership(
        organization_id=organization.id,
        user_id=accounts["org_member"].id,
        role=OrganizationRole.OWNER.value,
    )
    published_job = Job(
        id=uuid.uuid4(),
        title="Site Foreman",
        description="Supervise a Nairobi site.",
        organization_id=organization.id,
        created_by_user_id=accounts["job_poster"].id,
        status=JobStatus.OPEN.value,
        published_at=now,
    )
    draft_job = Job(
        id=uuid.uuid4(),
        title="Unlisted Role",
        description="Never published to anyone.",
        organization_id=organization.id,
        created_by_user_id=accounts["job_poster"].id,
        status=JobStatus.DRAFT.value,
    )
    request = VerificationRequest(
        id=uuid.uuid4(),
        worker_profile_id=private_profile.id,
        requested_by_user_id=accounts["passport_owner"].id,
        target_type=VerificationTargetType.SKILL.value,
        target_id=uuid.uuid4(),
        verifier_email="foreman@example.com",
        status=VerificationRequestStatus.VERIFIED.value,
        requested_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=29),
    )
    verification = Verification(
        id=uuid.uuid4(),
        verification_request_id=request.id,
        worker_profile_id=private_profile.id,
        requested_by_user_id=accounts["passport_owner"].id,
        target_type=VerificationTargetType.SKILL.value,
        target_id=request.target_id,
        status=VerificationStatus.VERIFIED.value,
        verified_by_user_id=accounts["verifier"].id,
        verifier_display_name="Njoroge Foreman",
        verified_at=now - timedelta(days=1),
    )
    db_session.add_all(
        [
            private_profile,
            public_profile,
            organization,
            membership,
            published_job,
            draft_job,
            request,
            verification,
        ]
    )
    db_session.flush()
    return {
        "private_profile": private_profile,
        "public_profile": public_profile,
        "organization": organization,
        "published_job": published_job,
        "draft_job": draft_job,
        "verification": verification,
    }


@pytest.fixture
def auth(auth_headers):
    """Bearer headers for an account created by the ``accounts`` fixture."""

    def _headers(account) -> dict[str, str]:
        return auth_headers(account)

    return _headers


def _body(subject_type: str, subject_id, reason: str = "FRAUD", **extra) -> dict:
    payload: dict = {
        "subject_type": subject_type,
        "subject_id": str(subject_id),
        "reason": reason,
    }
    payload.update(extra)
    return payload


def _file(client, accounts, auth, subjects) -> dict:
    """File one report as the reporter and return its response body."""
    response = client.post(
        "/reports",
        headers=auth(accounts["reporter"]),
        json=_body(ReportSubjectType.WORKER_PROFILE.value, subjects["public_profile"].id),
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


# --------------------------------------------------------------------------- #
# Filing                                                                      #
# --------------------------------------------------------------------------- #
class TestFiling:
    def test_creates_a_report_against_a_visible_passport(
        self, client, accounts, auth, subjects
    ) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(ReportSubjectType.WORKER_PROFILE.value, subjects["public_profile"].id),
        )
        assert response.status_code == 201, response.text
        data = response.json()["data"]
        assert data["subject_type"] == ReportSubjectType.WORKER_PROFILE.value
        assert data["subject_id"] == str(subjects["public_profile"].id)
        assert data["reason"] == ReportReason.FRAUD.value
        assert data["status"] == ReportStatus.OPEN.value
        # The reporter is the caller; the response never names a reporter account.
        assert "reporter_user_id" not in data
        assert "reporter_ref" not in data

    @pytest.mark.parametrize("reason", [member.value for member in ReportReason])
    def test_every_reason_is_accepted(self, client, accounts, auth, subjects, reason) -> None:
        """One case per enum member, so a new member cannot be unusable."""
        payload = _body(
            ReportSubjectType.WORKER_PROFILE.value, subjects["public_profile"].id, reason
        )
        if reason == ReportReason.OTHER.value:
            payload["details"] = "Claims a licence he does not hold."
        response = client.post("/reports", headers=auth(accounts["reporter"]), json=payload)
        assert response.status_code == 201, response.text
        assert response.json()["data"]["reason"] == reason

    @pytest.mark.parametrize(("subject_type", "key", "account"), SUBJECT_KEYS)
    def test_every_subject_type_is_accepted(
        self, client, accounts, auth, subjects, subject_type, key, account
    ) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts[account]),
            json=_body(subject_type, subjects[key].id),
        )
        assert response.status_code == 201, response.text
        assert response.json()["data"]["subject_type"] == subject_type

    def test_the_creation_matrix_matches_the_service(self) -> None:
        """A new reportable type must be added here, not silently left untested."""
        assert {subject for subject, _, _ in SUBJECT_KEYS} == set(REPORTABLE)
        assert {ReportSubjectType(name) for name in REPORTABLE} == REPORTABLE_SUBJECT_TYPES

    def test_details_are_stored_verbatim(self, client, accounts, auth, subjects) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(
                ReportSubjectType.WORKER_PROFILE.value,
                subjects["public_profile"].id,
                details="Claimed a quantity surveyor certificate.",
            ),
        )
        assert response.status_code == 201
        assert response.json()["data"]["details"].startswith("Claimed a quantity")

    def test_requires_authentication(self, client, subjects) -> None:
        response = client.post(
            "/reports",
            json=_body(ReportSubjectType.WORKER_PROFILE.value, subjects["public_profile"].id),
        )
        assert response.status_code == 401

    def test_the_outbox_event_carries_no_free_text(
        self, client, db_session, accounts, auth, subjects
    ) -> None:
        """A future delivery worker may read this row, so it must hold ids only."""
        client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(
                ReportSubjectType.WORKER_PROFILE.value,
                subjects["public_profile"].id,
                details="My mother's phone number is 0712345678",
            ),
        )
        db_session.expire_all()
        event = db_session.execute(
            select(NotificationEvent).where(
                NotificationEvent.event_type == NotificationEventType.CONTENT_REPORTED.value
            )
        ).scalar_one()
        assert event.user_id == accounts["reporter"].id
        assert "0712345678" not in str(event.payload)
        assert set(event.payload) == {"report_id", "subject_type", "reason"}


# --------------------------------------------------------------------------- #
# Duplicate, self-report and subject existence                                 #
# --------------------------------------------------------------------------- #
class TestRefusals:
    def test_a_duplicate_report_is_refused(self, client, accounts, auth, subjects) -> None:
        payload = _body(ReportSubjectType.WORKER_PROFILE.value, subjects["public_profile"].id)
        first = client.post("/reports", headers=auth(accounts["reporter"]), json=payload)
        assert first.status_code == 201, first.text
        second = client.post("/reports", headers=auth(accounts["reporter"]), json=payload)
        assert second.status_code == 409, second.text
        assert second.json()["error"]["code"] == "DUPLICATE_REPORT"

    def test_the_constraint_is_on_the_subject_not_the_reason(
        self, client, accounts, auth, subjects
    ) -> None:
        """One report per reporter per subject: a second reason is still a duplicate."""
        client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(
                ReportSubjectType.WORKER_PROFILE.value,
                subjects["public_profile"].id,
                ReportReason.FRAUD.value,
            ),
        )
        again = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(
                ReportSubjectType.WORKER_PROFILE.value,
                subjects["public_profile"].id,
                ReportReason.SCAM.value,
            ),
        )
        assert again.status_code == 409

    def test_a_different_user_may_report_the_same_subject(
        self, client, accounts, auth, subjects
    ) -> None:
        payload = _body(ReportSubjectType.WORKER_PROFILE.value, subjects["public_profile"].id)
        for account in ("reporter", "intruder"):
            response = client.post("/reports", headers=auth(accounts[account]), json=payload)
            assert response.status_code == 201, response.text

    def test_reporting_your_own_passport_is_refused(self, client, accounts, auth, subjects):
        response = client.post(
            "/reports",
            headers=auth(accounts["verifier"]),
            json=_body(ReportSubjectType.WORKER_PROFILE.value, subjects["public_profile"].id),
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "SELF_REPORT_BLOCKED"

    def test_reporting_your_own_organization_is_refused(
        self, client, accounts, auth, subjects
    ) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["org_member"]),
            json=_body(ReportSubjectType.ORGANIZATION.value, subjects["organization"].id),
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "SELF_REPORT_BLOCKED"

    def test_reporting_your_own_job_is_refused(self, client, accounts, auth, subjects) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["job_poster"]),
            json=_body(ReportSubjectType.JOB.value, subjects["published_job"].id),
        )
        assert response.status_code == 403

    def test_a_member_may_not_report_their_own_organizations_job(
        self, client, accounts, auth, subjects
    ) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["org_member"]),
            json=_body(ReportSubjectType.JOB.value, subjects["published_job"].id),
        )
        assert response.status_code == 403

    def test_reporting_your_own_attestation_is_refused(
        self, client, accounts, auth, subjects
    ) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["verifier"]),
            json=_body(ReportSubjectType.VERIFICATION.value, subjects["verification"].id),
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "SELF_REPORT_BLOCKED"

    def test_a_worker_may_report_a_verification_of_their_own_claim(
        self, client, accounts, auth, subjects
    ) -> None:
        """A forged attestation attributed to you is abuse worth reporting."""
        response = client.post(
            "/reports",
            headers=auth(accounts["passport_owner"]),
            json=_body(ReportSubjectType.VERIFICATION.value, subjects["verification"].id),
        )
        assert response.status_code == 201, response.text

    @pytest.mark.parametrize("subject_type", REPORTABLE)
    def test_a_nonexistent_subject_is_refused(self, client, accounts, auth, subject_type) -> None:
        response = client.post(
            "/reports", headers=auth(accounts["reporter"]), json=_body(subject_type, uuid.uuid4())
        )
        assert response.status_code == 404, response.text
        assert response.json()["error"]["code"] == "RESOURCE_NOT_FOUND"

    def test_a_malformed_subject_id_is_refused(self, client, accounts, auth) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(ReportSubjectType.WORKER_PROFILE.value, "not-a-uuid"),
        )
        assert response.status_code == 422

    def test_an_unreportable_subject_type_is_refused(self, client, accounts, auth) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(ReportSubjectType.USER.value, accounts["intruder"].id),
        )
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "VALIDATION_FAILED"


class TestExistenceIsNotProbeable:
    """A report must not be a way to discover which ids exist."""

    def test_a_private_passport_answers_exactly_as_a_missing_one(
        self, client, accounts, auth, subjects
    ) -> None:
        hidden = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(ReportSubjectType.WORKER_PROFILE.value, subjects["private_profile"].id),
        )
        missing = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(ReportSubjectType.WORKER_PROFILE.value, uuid.uuid4()),
        )
        assert hidden.status_code == missing.status_code == 404
        assert hidden.json()["error"]["code"] == missing.json()["error"]["code"]
        assert hidden.json()["error"]["message"] == missing.json()["error"]["message"]

    def test_a_discoverable_passport_is_reportable(
        self, client, db_session, accounts, auth, subjects
    ) -> None:
        subjects["private_profile"].visibility = ProfileVisibility.DISCOVERABLE.value
        db_session.flush()
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(ReportSubjectType.WORKER_PROFILE.value, subjects["private_profile"].id),
        )
        assert response.status_code == 201, response.text

    def test_an_administrator_may_report_a_private_passport(
        self, client, accounts, auth, subjects
    ) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["admin"]),
            json=_body(ReportSubjectType.WORKER_PROFILE.value, subjects["private_profile"].id),
        )
        assert response.status_code == 201, response.text

    def test_a_draft_job_answers_exactly_as_a_missing_one(
        self, client, accounts, auth, subjects
    ) -> None:
        draft = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(ReportSubjectType.JOB.value, subjects["draft_job"].id),
        )
        missing = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(ReportSubjectType.JOB.value, uuid.uuid4()),
        )
        assert draft.status_code == missing.status_code == 404
        assert draft.json()["error"]["message"] == missing.json()["error"]["message"]

    def test_a_strangers_verification_is_not_reportable(self, client, accounts, auth, subjects):
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(ReportSubjectType.VERIFICATION.value, subjects["verification"].id),
        )
        assert response.status_code == 404, response.text

    def test_a_deleted_passport_is_not_reportable(
        self, client, db_session, accounts, auth, subjects
    ):
        subjects["public_profile"].deleted_at = utcnow()
        db_session.flush()
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(ReportSubjectType.WORKER_PROFILE.value, subjects["public_profile"].id),
        )
        assert response.status_code == 404


# --------------------------------------------------------------------------- #
# Mass assignment                                                             #
# --------------------------------------------------------------------------- #
class TestMassAssignment:
    @pytest.mark.parametrize("field", FORBIDDEN_FIELDS)
    def test_a_reporter_cannot_set_moderation_fields(
        self, client, accounts, auth, subjects, field
    ) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(
                ReportSubjectType.WORKER_PROFILE.value,
                subjects["public_profile"].id,
                **{field: "RESOLVED"},
            ),
        )
        assert response.status_code == 422, response.text

    def test_a_reporter_cannot_claim_a_reporter_identity(
        self, client, db_session, accounts, auth, subjects
    ) -> None:
        """No ``user_id`` in a request schema: a report belongs to the caller."""
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(
                ReportSubjectType.WORKER_PROFILE.value,
                subjects["public_profile"].id,
                reporter_user_id=str(accounts["intruder"].id),
            ),
        )
        assert response.status_code == 422
        assert _stored_report(db_session, accounts["reporter"].id) is None

    @pytest.mark.parametrize("field", FORBIDDEN_FIELDS)
    def test_an_administrator_cannot_send_a_raw_state_either(
        self, client, accounts, auth, subjects, field
    ) -> None:
        filed = _file(client, accounts, auth, subjects)
        response = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "DISMISS", "note": "Nothing actionable.", field: "RESOLVED"},
        )
        assert response.status_code == 422, response.text

    @pytest.mark.parametrize("value", ["DELETE", "NUKED", "RESOLVE_NOW", "resolved"])
    def test_an_unknown_decision_is_refused(self, client, accounts, auth, subjects, value) -> None:
        filed = _file(client, accounts, auth, subjects)
        response = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": value},
        )
        assert response.status_code == 422

    @pytest.mark.parametrize("value", ["NOPE", "fraud", ""])
    def test_an_invalid_reason_is_refused(self, client, accounts, auth, subjects, value) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(
                ReportSubjectType.WORKER_PROFILE.value, subjects["public_profile"].id, value
            ),
        )
        assert response.status_code == 422

    @pytest.mark.parametrize("value", ["PROFILE", "worker_profile", "ACCOUNT", ""])
    def test_an_invalid_subject_type_is_refused(
        self, client, accounts, auth, subjects, value
    ) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(value, subjects["public_profile"].id),
        )
        assert response.status_code == 422

    def test_other_requires_details(self, client, accounts, auth, subjects) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(
                ReportSubjectType.WORKER_PROFILE.value,
                subjects["public_profile"].id,
                ReportReason.OTHER.value,
            ),
        )
        assert response.status_code == 422

    def test_blank_details_are_refused(self, client, accounts, auth, subjects) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(
                ReportSubjectType.WORKER_PROFILE.value,
                subjects["public_profile"].id,
                details="   ",
            ),
        )
        assert response.status_code == 422

    def test_an_oversized_body_is_refused(self, client, accounts, auth, subjects) -> None:
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(
                ReportSubjectType.WORKER_PROFILE.value,
                subjects["public_profile"].id,
                details="x" * 4001,
            ),
        )
        assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Reading your own reports                                                    #
# --------------------------------------------------------------------------- #
class TestReadingOwnReports:
    def test_the_list_shows_only_my_reports(self, client, accounts, auth, subjects) -> None:
        mine = _file(client, accounts, auth, subjects)
        theirs = client.post(
            "/reports",
            headers=auth(accounts["intruder"]),
            json=_body(ReportSubjectType.JOB.value, subjects["published_job"].id),
        ).json()["data"]

        body = client.get("/reports", headers=auth(accounts["reporter"])).json()
        ids = [row["id"] for row in body["data"]]
        assert ids == [mine["id"]]
        assert theirs["id"] not in ids
        assert _total(body) == 1

    def test_the_list_can_be_filtered_by_status(self, client, accounts, auth, subjects) -> None:
        _file(client, accounts, auth, subjects)
        open_rows = client.get(
            f"/reports?status={ReportStatus.OPEN.value}", headers=auth(accounts["reporter"])
        ).json()["data"]
        resolved_rows = client.get(
            f"/reports?status={ReportStatus.RESOLVED.value}",
            headers=auth(accounts["reporter"]),
        ).json()["data"]
        assert len(open_rows) == 1
        assert resolved_rows == []

    def test_an_invalid_status_filter_is_refused(self, client, accounts, auth) -> None:
        response = client.get("/reports?status=IGNORED", headers=auth(accounts["intruder"]))
        assert response.status_code == 422

    def test_paging_is_capped(self, client, accounts, auth) -> None:
        response = client.get("/reports?page_size=1000", headers=auth(accounts["intruder"]))
        assert response.status_code == 422

    def test_i_can_read_my_own_report(self, client, accounts, auth, subjects) -> None:
        filed = _file(client, accounts, auth, subjects)
        response = client.get(f"/reports/{filed['id']}", headers=auth(accounts["reporter"]))
        assert response.status_code == 200, response.text
        assert response.json()["data"]["id"] == filed["id"]

    def test_another_users_report_is_404(self, client, accounts, auth, subjects) -> None:
        """404, not 403: a 403 would confirm the report exists."""
        filed = _file(client, accounts, auth, subjects)
        response = client.get(f"/reports/{filed['id']}", headers=auth(accounts["intruder"]))
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "RESOURCE_NOT_FOUND"

    def test_the_administrator_route_also_shows_only_my_reports(
        self, client, accounts, auth, subjects
    ) -> None:
        """An administrator is a user: their own list is the reports they filed."""
        others = _file(client, accounts, auth, subjects)
        admin_filed = client.post(
            "/reports",
            headers=auth(accounts["admin"]),
            json=_body(ReportSubjectType.JOB.value, subjects["published_job"].id),
        ).json()["data"]
        ids = [
            row["id"]
            for row in client.get("/reports", headers=auth(accounts["admin"])).json()["data"]
        ]
        assert ids == [admin_filed["id"]]
        assert others["id"] not in ids

    def test_my_own_response_hides_the_reviewers_note(
        self, client, accounts, auth, subjects
    ) -> None:
        filed = _file(client, accounts, auth, subjects)
        client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "DISMISS", "note": "Checked, nothing actionable."},
        )
        mine = client.get(f"/reports/{filed['id']}", headers=auth(accounts["reporter"])).json()[
            "data"
        ]
        assert "resolution_note" not in mine
        assert mine["status"] == ReportStatus.DISMISSED.value
        assert mine["resolved_at"] is not None

    def test_reading_requires_authentication(self, client) -> None:
        assert client.get("/reports").status_code == 401
        assert client.get(f"/reports/{uuid.uuid4()}").status_code == 401


# --------------------------------------------------------------------------- #
# The administration queue                                                    #
# --------------------------------------------------------------------------- #
class TestAdminQueue:
    def test_an_administrator_sees_every_report(self, client, accounts, auth, subjects) -> None:
        first = _file(client, accounts, auth, subjects)
        second = client.post(
            "/reports",
            headers=auth(accounts["intruder"]),
            json=_body(ReportSubjectType.JOB.value, subjects["published_job"].id),
        ).json()["data"]

        body = client.get("/admin/reports", headers=auth(accounts["admin"])).json()
        assert {row["id"] for row in body["data"]} == {first["id"], second["id"]}
        assert _total(body) == 2

    def test_the_queue_can_be_filtered(self, client, accounts, auth, subjects) -> None:
        _file(client, accounts, auth, subjects)
        client.post(
            "/reports",
            headers=auth(accounts["intruder"]),
            json=_body(ReportSubjectType.JOB.value, subjects["published_job"].id),
        )
        headers = auth(accounts["admin"])
        assert _total(client.get("/admin/reports?subject_type=JOB", headers=headers).json()) == 1
        assert _total(client.get("/admin/reports?status=OPEN", headers=headers).json()) == 2
        assert _total(client.get("/admin/reports?status=DISMISSED", headers=headers).json()) == 0

    def test_an_invalid_queue_filter_is_refused(self, client, accounts, auth) -> None:
        response = client.get(
            "/admin/reports?subject_type=ANYTHING", headers=auth(accounts["admin"])
        )
        assert response.status_code == 422

    def test_the_queue_exposes_no_reporter_contact_details(
        self, client, accounts, auth, subjects
    ) -> None:
        """A reviewer needs the subject and the reason, not the reporter's inbox."""
        _file(client, accounts, auth, subjects)
        response = client.get("/admin/reports", headers=auth(accounts["admin"]))
        assert response.status_code == 200
        assert accounts["reporter"].email not in response.text
        assert "0712345678" not in response.text
        assert set(response.json()["data"][0]) == ADMIN_RESPONSE_FIELDS

    def test_the_reporter_is_a_pseudonym_not_an_account(
        self, client, accounts, auth, subjects
    ) -> None:
        _file(client, accounts, auth, subjects)
        row = client.get("/admin/reports", headers=auth(accounts["admin"])).json()["data"][0]
        assert row["reporter_ref"] == f"reporter-{str(accounts['reporter'].id)[:8]}"
        assert str(accounts["reporter"].id) not in row["reporter_ref"]

    @pytest.mark.parametrize("account", ["intruder", "org_member"])
    def test_a_worker_cannot_reach_the_queue(self, client, accounts, auth, account) -> None:
        response = client.get("/admin/reports", headers=auth(accounts[account]))
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "INSUFFICIENT_ROLE"

    def test_a_worker_cannot_decide_a_report(
        self, client, db_session, accounts, auth, subjects
    ) -> None:
        filed = _file(client, accounts, auth, subjects)
        response = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["intruder"]),
            json={"decision": "DISMISS", "note": "I do not like this person."},
        )
        assert response.status_code == 403
        row = _stored_report(db_session, accounts["reporter"].id)
        assert row is not None
        assert row.status == ReportStatus.OPEN.value
        assert row.resolved_by_user_id is None

    def test_the_queue_requires_authentication(self, client) -> None:
        assert client.get("/admin/reports").status_code == 401

    def test_the_service_rejects_a_non_admin_without_the_dependency(
        self, db_session, accounts, subjects
    ) -> None:
        """Two independent checks: a loosened route must not open the queue.

        Called directly on the service because the route dependency refuses a
        non-administrator before the service is ever reached.
        """
        from app.core.exceptions import InsufficientRoleError
        from app.services.report_service import ReportService

        with pytest.raises(InsufficientRoleError):
            ReportService(db_session).list_all(actor=accounts["intruder"])
        with pytest.raises(InsufficientRoleError):
            ReportService(db_session).decide(
                actor=accounts["intruder"],
                report_id=uuid.uuid4(),
                payload=ReportDecisionRequest(decision=ReportDecision.DISMISS, note="No."),
            )

    def test_deciding_an_unknown_report_is_404(self, client, accounts, auth) -> None:
        response = client.patch(
            f"/admin/reports/{uuid.uuid4()}",
            headers=auth(accounts["admin"]),
            json={"decision": "DISMISS", "note": "Nothing to dismiss."},
        )
        assert response.status_code == 404


class TestAdminDecisions:
    def test_an_administrator_resolves_a_report(self, client, accounts, auth, subjects) -> None:
        filed = _file(client, accounts, auth, subjects)
        response = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "RESOLVE", "note": "Passport removed after review."},
        )
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["status"] == ReportStatus.RESOLVED.value
        assert data["resolved_by_user_id"] == str(accounts["admin"].id)
        assert data["resolution_note"] == "Passport removed after review."
        assert data["resolved_at"] is not None

    def test_an_administrator_dismisses_a_report(self, client, accounts, auth, subjects) -> None:
        filed = _file(client, accounts, auth, subjects)
        response = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "DISMISS", "note": "Claim was accurate at the time."},
        )
        assert response.status_code == 200
        assert response.json()["data"]["status"] == ReportStatus.DISMISSED.value

    def test_review_then_escalate(self, client, accounts, auth, subjects) -> None:
        filed = _file(client, accounts, auth, subjects)
        review = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "REVIEW"},
        )
        assert review.status_code == 200, review.text
        assert review.json()["data"]["status"] == ReportStatus.IN_REVIEW.value
        # Being picked up for review is not a resolution, so nothing is stamped.
        assert review.json()["data"]["resolved_at"] is None

        escalate = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "ESCALATE", "note": "Account suspended by moderation."},
        )
        assert escalate.status_code == 200, escalate.text
        assert escalate.json()["data"]["status"] == ReportStatus.ACTIONED.value

    def test_a_client_cannot_name_the_status(self, client, accounts, auth, subjects) -> None:
        """The decision vocabulary is deliberately narrower than ReportStatus."""
        filed = _file(client, accounts, auth, subjects)
        response = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"status": ReportStatus.DISMISSED.value, "note": "Because I said so."},
        )
        assert response.status_code == 422

    @pytest.mark.parametrize("decision", ["RESOLVE", "DISMISS", "ESCALATE"])
    @pytest.mark.parametrize("note", [None, "", "no", "   "])
    def test_closing_a_report_requires_a_note(
        self, client, accounts, auth, subjects, decision, note
    ) -> None:
        filed = _file(client, accounts, auth, subjects)
        payload: dict = {"decision": decision}
        if note is not None:
            payload["note"] = note
        response = client.patch(
            f"/admin/reports/{filed['id']}", headers=auth(accounts["admin"]), json=payload
        )
        assert response.status_code == 422, response.text

    def test_the_shortest_acceptable_note_is_five_characters(
        self, client, accounts, auth, subjects
    ) -> None:
        filed = _file(client, accounts, auth, subjects)
        too_short = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "DISMISS", "note": "abcd"},
        )
        assert too_short.status_code == 422
        exact = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "DISMISS", "note": "abcde"},
        )
        assert exact.status_code == 200, exact.text

    def test_a_closed_report_cannot_be_reopened(self, client, accounts, auth, subjects) -> None:
        filed = _file(client, accounts, auth, subjects)
        client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "DISMISS", "note": "Nothing actionable."},
        )
        again = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "RESOLVE", "note": "Changed my mind entirely."},
        )
        assert again.status_code == 409
        assert again.json()["error"]["code"] == "INVALID_STATE_TRANSITION"

    def test_reviewing_twice_is_refused(self, client, accounts, auth, subjects) -> None:
        filed = _file(client, accounts, auth, subjects)
        first = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "REVIEW"},
        )
        assert first.status_code == 200, first.text
        again = client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "REVIEW"},
        )
        assert again.status_code == 409

    def test_the_report_row_survives_adjudication(
        self, client, db_session, accounts, auth, subjects
    ) -> None:
        """Resolution closes a report; it does not delete it."""
        filed = _file(client, accounts, auth, subjects)
        client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "RESOLVE", "note": "Subject dealt with."},
        )
        db_session.expire_all()
        row = db_session.execute(
            select(Report).where(Report.id == uuid.UUID(filed["id"]))
        ).scalar_one()
        assert row.status == ReportStatus.RESOLVED.value


# --------------------------------------------------------------------------- #
# Audit                                                                       #
# --------------------------------------------------------------------------- #
class TestAudit:
    def test_filing_is_audited_without_the_report_body(
        self, client, audit_rows, accounts, auth, subjects
    ) -> None:
        client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(
                ReportSubjectType.WORKER_PROFILE.value,
                subjects["public_profile"].id,
                ReportReason.SCAM.value,
                details="He asked for a 5000 shilling transfer.",
            ),
        )
        rows = audit_rows(action=AuditAction.CONTENT_REPORTED.value)
        assert len(rows) == 1
        row = rows[0]
        assert row.actor_user_id == accounts["reporter"].id
        assert row.actor_role == "WORKER"
        assert row.resource_type == "report"
        assert row.outcome == "SUCCESS"
        assert row.metadata_["operation"] == "report_filed"
        assert row.metadata_["subject_type"] == ReportSubjectType.WORKER_PROFILE.value
        assert row.metadata_["reason"] == ReportReason.SCAM.value
        # The body is free text and is exactly what must not accumulate here.
        assert "5000 shilling" not in str(row.metadata_)

    @pytest.mark.parametrize(
        ("decision", "note", "action", "new_status"),
        [
            ("REVIEW", None, AuditAction.ADMIN_ACTION, ReportStatus.IN_REVIEW),
            (
                "RESOLVE",
                "Subject dealt with.",
                AuditAction.REPORT_RESOLVED,
                ReportStatus.RESOLVED,
            ),
            ("DISMISS", "Nothing actionable.", AuditAction.ADMIN_ACTION, ReportStatus.DISMISSED),
            ("ESCALATE", "Account suspended.", AuditAction.ADMIN_ACTION, ReportStatus.ACTIONED),
        ],
    )
    def test_every_decision_is_audited(
        self, client, audit_rows, accounts, auth, subjects, decision, note, action, new_status
    ) -> None:
        filed = _file(client, accounts, auth, subjects)
        payload: dict = {"decision": decision}
        if note is not None:
            payload["note"] = note
        client.patch(f"/admin/reports/{filed['id']}", headers=auth(accounts["admin"]), json=payload)
        matching = [row for row in audit_rows(action=action.value) if row.resource_id is not None]
        decision_rows = [row for row in matching if str(row.resource_id) == filed["id"]]
        assert len(decision_rows) == 1
        row = decision_rows[0]
        assert row.actor_user_id == accounts["admin"].id
        assert row.actor_role == "ADMIN"
        assert row.outcome == "SUCCESS"
        assert row.metadata_["operation"] == f"report_{decision.lower()}"
        assert row.metadata_["previous_status"] == ReportStatus.OPEN.value
        assert row.metadata_["new_status"] == new_status.value

    def test_the_note_is_not_copied_into_audit_metadata(
        self, client, audit_rows, accounts, auth, subjects
    ) -> None:
        filed = _file(client, accounts, auth, subjects)
        client.patch(
            f"/admin/reports/{filed['id']}",
            headers=auth(accounts["admin"]),
            json={"decision": "DISMISS", "note": "Spoke to the foreman on 0722999888."},
        )
        row = audit_rows(action=AuditAction.ADMIN_ACTION.value)[-1]
        assert "0722999888" not in str(row.metadata_)
        assert row.metadata_["has_note"] is True

    def test_a_refused_request_writes_no_audit_row(
        self, client, audit_rows, accounts, auth
    ) -> None:
        """A rejected request has no effect, so it has no successful audit row."""
        response = client.post(
            "/reports",
            headers=auth(accounts["reporter"]),
            json=_body(ReportSubjectType.JOB.value, uuid.uuid4()),
        )
        assert response.status_code == 404
        assert audit_rows(action=AuditAction.CONTENT_REPORTED.value) == []


# --------------------------------------------------------------------------- #
# Reports are never deleted                                                   #
# --------------------------------------------------------------------------- #
class TestNoDeletion:
    def test_a_reporter_cannot_delete_their_report(self, client, accounts, auth, subjects) -> None:
        filed = _file(client, accounts, auth, subjects)
        response = client.delete(f"/reports/{filed['id']}", headers=auth(accounts["reporter"]))
        assert response.status_code == 405
        assert response.json()["error"]["code"] == "METHOD_NOT_ALLOWED"

    def test_an_administrator_cannot_delete_a_report(
        self, client, accounts, auth, subjects
    ) -> None:
        filed = _file(client, accounts, auth, subjects)
        response = client.delete(f"/admin/reports/{filed['id']}", headers=auth(accounts["admin"]))
        assert response.status_code == 405

    def test_the_report_is_still_readable_afterwards(self, client, accounts, auth, subjects):
        filed = _file(client, accounts, auth, subjects)
        client.delete(f"/reports/{filed['id']}", headers=auth(accounts["reporter"]))
        response = client.get(f"/reports/{filed['id']}", headers=auth(accounts["reporter"]))
        assert response.status_code == 200


def _stored_report(db_session, reporter_user_id):
    """The reporter's report row, read outside the request's own flush."""
    db_session.expire_all()
    return (
        db_session.execute(select(Report).where(Report.reporter_user_id == reporter_user_id))
        .scalars()
        .first()
    )


def _total(body: dict) -> int:
    """``total_items`` for a page, from either pagination envelope shape.

    :class:`~app.schemas.common.PaginatedResponseEnvelope` currently puts the
    counters flat in ``meta`` while ``docs/conventions.md`` documents them nested
    under ``meta.pagination``. Reading both keeps these assertions about the
    property under test - how many rows the caller may see - rather than about
    where the counter sits.
    """
    meta = body.get("meta") or {}
    pagination = meta.get("pagination") or meta
    return int(pagination["total_items"])
