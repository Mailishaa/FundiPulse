"""End-to-end tests for the verification workflow.

The point of this file is the security property, not the happy path: a suite that
only checks that a verifier can confirm a claim would still pass while a worker
verified their own experience, while one verifier read another's queue, or while a
second response silently overwrote the first. Each of those is asserted directly.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any
import uuid

import pytest
from sqlalchemy import select

from app.core.constants import (
    AuditAction,
    MembershipStatus,
    NotificationEventType,
    OrganizationRole,
    UserRole,
    VerificationRequestStatus,
    VerificationStatus,
    VerificationTargetType,
)
from app.db.base import utcnow
from app.db.models.moderation import NotificationEvent
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.user import User
from app.db.models.verification import Verification, VerificationRequest
from app.db.models.worker import Credential, Project, WorkerProfile, WorkExperience
from app.services.verification_service import VerificationService

pytestmark = [pytest.mark.api, pytest.mark.integration]

#: Substrings no verification field may contain. A score is the failure mode this
#: whole workflow exists to avoid, so it is checked structurally rather than by eye.
FORBIDDEN_FIELD_SUBSTINGS = (
    "score",
    "rating",
    "star",
    "trust",
    "certified",
    "guarantee",
    "quality",
    "rank",
    "grade",
)


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture
def worker_user(make_user):
    return make_user(role=UserRole.WORKER)


@pytest.fixture
def worker_profile(db_session, worker_user):
    profile = WorkerProfile(user_id=worker_user.id, display_name="Amina Wanjiru")
    db_session.add(profile)
    db_session.flush()
    return profile


@pytest.fixture
def worker_headers(worker_user, auth_headers):
    return auth_headers(worker_user)


def _experience(profile: WorkerProfile, employer: str, role: str) -> WorkExperience:
    return WorkExperience(
        worker_profile_id=profile.id,
        employer_name=employer,
        project_name="Riverside Flats",
        role_title=role,
        location="Nakuru",
        start_date=date(2022, 3, 1),
        end_date=date(2023, 6, 30),
        is_current=False,
    )


@pytest.fixture
def experience(db_session, worker_profile):
    record = _experience(worker_profile, "ABC Builders", "Mason")
    db_session.add(record)
    db_session.flush()
    return record


@pytest.fixture
def second_experience(db_session, worker_profile):
    record = _experience(worker_profile, "Delta Contractors", "Mason")
    db_session.add(record)
    db_session.flush()
    return record


@pytest.fixture
def project(db_session, worker_profile):
    record = Project(
        worker_profile_id=worker_profile.id,
        name="Riverside Flats",
        project_type="RESIDENTIAL",
        role_title="Lead mason",
        start_date=date(2022, 4, 1),
        end_date=date(2023, 5, 1),
    )
    db_session.add(record)
    db_session.flush()
    return record


@pytest.fixture
def credential(db_session, worker_profile):
    record = Credential(
        worker_profile_id=worker_profile.id,
        title="Trade test certificate",
        issuer="NCTVET",
    )
    db_session.add(record)
    db_session.flush()
    return record


@pytest.fixture
def verifier_user(make_user):
    """A third party with an account: a site manager who can answer."""
    return make_user(role=UserRole.EMPLOYER)


@pytest.fixture
def verifier_headers(verifier_user, auth_headers):
    return auth_headers(verifier_user)


@pytest.fixture
def outsider_user(make_user):
    """An unrelated account nobody asked, belonging to no organization."""
    return make_user(role=UserRole.EMPLOYER)


@pytest.fixture
def outsider_headers(outsider_user, auth_headers):
    return auth_headers(outsider_user)


def _body(target_type: str, target_id: uuid.UUID, verifier_email: str) -> dict[str, Any]:
    return {
        "target_type": target_type,
        "target_id": str(target_id),
        "verifier_email": verifier_email,
        "verifier_full_name": "Peter Otieno",
        "verifier_relationship": "Site manager at ABC Builders",
        "message": "Please confirm you supervised me here.",
    }


def _raise(
    client,
    headers: dict[str, str],
    *,
    target_type: str,
    target_id: uuid.UUID,
    verifier_email: str,
) -> dict[str, Any]:
    response = client.post(
        "/verification-requests",
        headers=headers,
        json=_body(target_type, target_id, verifier_email),
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def _events(db_session, event_type: NotificationEventType) -> list[NotificationEvent]:
    return list(
        db_session.execute(
            select(NotificationEvent).where(NotificationEvent.event_type == event_type.value)
        ).scalars()
    )


# --------------------------------------------------------------------------- #
# Creating a request                                                           #
# --------------------------------------------------------------------------- #
class TestCreateRequest:
    def test_creates_a_request_against_own_experience(
        self, client, worker_headers, worker_user, experience, verifier_user
    ) -> None:
        data = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )

        assert data["status"] == VerificationRequestStatus.PENDING.value
        assert data["target_type"] == VerificationTargetType.EXPERIENCE.value
        assert data["target_id"] == str(experience.id)
        assert data["requested_by_user_id"] == str(worker_user.id)
        assert data["responded_by_user_id"] is None
        assert data["verification"] is None
        assert data["verifier_relationship"] == "Site manager at ABC Builders"

    def test_freezes_the_claim_exactly_as_the_worker_wrote_it(
        self, client, worker_headers, experience, verifier_user
    ) -> None:
        """A later edit must not change what the verifier was asked about."""
        data = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )

        assert data["target_snapshot"]["employer_name"] == "ABC Builders"
        assert data["target_snapshot"]["role_title"] == "Mason"
        assert data["target_snapshot"]["start_date"] == "2022-03-01"
        assert data["target_label"] == "Mason at ABC Builders"

    def test_sets_a_server_deadline_the_client_cannot_influence(
        self, client, worker_headers, experience, verifier_user
    ) -> None:
        data = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        assert data["expires_at"].endswith("Z")
        assert data["expires_at"] > data["requested_at"]

    @pytest.mark.parametrize(
        ("target_type", "fixture_name"),
        [
            (VerificationTargetType.EXPERIENCE, "experience"),
            (VerificationTargetType.PROJECT, "project"),
            (VerificationTargetType.CREDENTIAL, "credential"),
        ],
    )
    def test_accepts_every_supported_claim_type(
        self, request, client, worker_headers, verifier_user, target_type, fixture_name
    ) -> None:
        claim = request.getfixturevalue(fixture_name)
        data = _raise(
            client,
            worker_headers,
            target_type=target_type.value,
            target_id=claim.id,
            verifier_email=verifier_user.email,
        )
        assert data["target_id"] == str(claim.id)

    def test_a_claim_belonging_to_another_worker_is_not_found(
        self, client, db_session, worker_headers, make_user, verifier_user
    ) -> None:
        """Another worker's record is not found, not forbidden: existence undisclosed."""
        other_user = make_user(role=UserRole.WORKER)
        other_profile = WorkerProfile(user_id=other_user.id, display_name="Someone Else")
        db_session.add(other_profile)
        db_session.flush()
        other_claim = _experience(other_profile, "Their Employer", "Welder")
        db_session.add(other_claim)
        db_session.flush()

        response = client.post(
            "/verification-requests",
            headers=worker_headers,
            json=_body(
                VerificationTargetType.EXPERIENCE.value, other_claim.id, verifier_user.email
            ),
        )

        assert response.status_code == 404
        assert response.json()["error"]["code"] == "RESOURCE_NOT_FOUND"

    def test_nonexistent_claim_is_not_found(self, client, worker_headers, verifier_user) -> None:
        response = client.post(
            "/verification-requests",
            headers=worker_headers,
            json=_body(VerificationTargetType.EXPERIENCE.value, uuid.uuid4(), verifier_user.email),
        )
        assert response.status_code == 404

    def test_a_soft_deleted_claim_is_not_found(
        self, client, db_session, worker_headers, experience, verifier_user
    ) -> None:
        experience.deleted_at = utcnow()
        db_session.flush()

        response = client.post(
            "/verification-requests",
            headers=worker_headers,
            json=_body(VerificationTargetType.EXPERIENCE.value, experience.id, verifier_user.email),
        )
        assert response.status_code == 404

    @pytest.mark.parametrize(
        "target_type",
        [VerificationTargetType.SKILL.value, VerificationTargetType.REFERENCE.value],
    )
    def test_unsupported_claim_type_is_refused(
        self, client, worker_headers, worker_profile, verifier_user, target_type
    ) -> None:
        response = client.post(
            "/verification-requests",
            headers=worker_headers,
            json=_body(target_type, uuid.uuid4(), verifier_user.email),
        )
        assert response.status_code == 422

    def test_the_client_cannot_supply_a_status(
        self, client, worker_headers, experience, verifier_user
    ) -> None:
        """Mass-assignment guard: the outcome is never a request field."""
        body = _body(VerificationTargetType.EXPERIENCE.value, experience.id, verifier_user.email)
        body["status"] = VerificationRequestStatus.VERIFIED.value
        body["verified_by"] = "Peter Otieno"
        response = client.post("/verification-requests", headers=worker_headers, json=body)
        assert response.status_code == 422

    def test_requires_authentication(self, client, experience, verifier_user) -> None:
        response = client.post(
            "/verification-requests",
            json=_body(VerificationTargetType.EXPERIENCE.value, experience.id, verifier_user.email),
        )
        assert response.status_code == 401

    def test_second_pending_request_for_the_same_claim_conflicts(
        self, client, worker_headers, experience, verifier_user, make_user
    ) -> None:
        _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        second = client.post(
            "/verification-requests",
            headers=worker_headers,
            json=_body(
                VerificationTargetType.EXPERIENCE.value,
                experience.id,
                make_user(role=UserRole.EMPLOYER).email,
            ),
        )
        assert second.status_code == 409


# --------------------------------------------------------------------------- #
# Self-verification: the invariant that matters most                           #
# --------------------------------------------------------------------------- #
class TestSelfVerificationBlocked:
    def test_a_worker_cannot_nominate_themselves_as_verifier(
        self, client, worker_headers, worker_user, experience, audit_rows
    ) -> None:
        response = client.post(
            "/verification-requests",
            headers=worker_headers,
            json=_body(VerificationTargetType.EXPERIENCE.value, experience.id, worker_user.email),
        )

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "VERIFICATION_SELF_ATTESTATION_BLOCKED"

        denials = audit_rows(action=AuditAction.VERIFICATION_REJECTED.value, outcome="DENIED")
        assert len(denials) == 1
        assert denials[0].metadata_["reason"] == "self_verification_blocked"
        assert denials[0].metadata_["stage"] == "request"

    def test_a_refused_nomination_creates_no_request(
        self, client, db_session, worker_headers, worker_user, experience
    ) -> None:
        client.post(
            "/verification-requests",
            headers=worker_headers,
            json=_body(VerificationTargetType.EXPERIENCE.value, experience.id, worker_user.email),
        )
        assert list(db_session.execute(select(VerificationRequest)).scalars()) == []

    def test_a_worker_cannot_answer_a_request_about_their_own_claim(
        self, client, db_session, worker_headers, worker_user, worker_profile, experience
    ) -> None:
        """The responder half of the rule, on a row that got past creation.

        Written directly because self-nomination is refused at creation time; this
        proves the responder check stands on its own rather than trusting that the
        creation-time refusal can never be bypassed.
        """
        request_row = _self_addressed(db_session, worker_user, worker_profile, experience)

        response = client.post(
            f"/verification-requests/{request_row.id}/respond",
            headers=worker_headers,
            json={"confirm": True},
        )

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "VERIFICATION_SELF_ATTESTATION_BLOCKED"
        assert list(db_session.execute(select(Verification)).scalars()) == []

    def test_a_blocked_answer_is_audited(
        self,
        client,
        db_session,
        worker_headers,
        worker_user,
        worker_profile,
        experience,
        audit_rows,
    ) -> None:
        request_row = _self_addressed(db_session, worker_user, worker_profile, experience)
        client.post(
            f"/verification-requests/{request_row.id}/respond",
            headers=worker_headers,
            json={"confirm": True},
        )

        denials = audit_rows(action=AuditAction.VERIFICATION_REJECTED.value, outcome="DENIED")
        assert [row.metadata_["stage"] for row in denials] == ["respond"]
        assert denials[0].resource_id == request_row.id


def _self_addressed(
    db_session,
    worker_user: User,
    worker_profile: WorkerProfile,
    claim: WorkExperience,
) -> VerificationRequest:
    """A request the worker is both the asker of and the named verifier of."""
    row = VerificationRequest(
        worker_profile_id=worker_profile.id,
        requested_by_user_id=worker_user.id,
        target_type=VerificationTargetType.EXPERIENCE.value,
        target_id=claim.id,
        verifier_email=worker_user.email,
        status=VerificationRequestStatus.PENDING.value,
        requested_at=utcnow(),
        expires_at=utcnow() + timedelta(days=30),
    )
    db_session.add(row)
    db_session.flush()
    return row


# --------------------------------------------------------------------------- #
# Listing and reading: scoping                                                #
# --------------------------------------------------------------------------- #
class TestListAndRead:
    def test_the_list_covers_both_directions(
        self,
        client,
        worker_headers,
        verifier_headers,
        outsider_headers,
        experience,
        project,
        verifier_user,
        worker_user,
    ) -> None:
        """One page holds what the caller raised and what the caller was asked."""
        first = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        second = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.PROJECT.value,
            target_id=project.id,
            verifier_email=verifier_user.email,
        )

        as_requester = client.get("/verification-requests", headers=worker_headers).json()
        as_verifier = client.get("/verification-requests", headers=verifier_headers).json()
        as_outsider = client.get("/verification-requests", headers=outsider_headers).json()

        assert as_requester["meta"]["total_items"] == 2
        assert as_verifier["meta"]["total_items"] == 2
        assert as_outsider["meta"]["total_items"] == 0
        # Newest first, and the worker is identifiable to the person they asked.
        assert [row["id"] for row in as_verifier["data"]] == [second["id"], first["id"]]
        assert as_verifier["data"][0]["worker_display_name"] == "Amina Wanjiru"
        assert as_verifier["data"][0]["requested_by_user_id"] == str(worker_user.id)

    def test_the_list_paginates(self, client, worker_headers, experience, verifier_user) -> None:
        _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        body = client.get(
            "/verification-requests", headers=worker_headers, params={"page_size": 1}
        ).json()
        assert body["meta"]["page"] == 1
        assert body["meta"]["page_size"] == 1
        assert body["meta"]["total_pages"] == 1
        assert body["meta"]["has_next"] is False
        assert body["meta"]["has_previous"] is False

    def test_the_list_filters_by_status_and_claim_type(
        self, client, worker_headers, experience, project, verifier_user, verifier_headers
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.PROJECT.value,
            target_id=project.id,
            verifier_email=verifier_user.email,
        )
        client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": True},
        )

        by_type = client.get(
            "/verification-requests",
            headers=worker_headers,
            params={"target_type": VerificationTargetType.PROJECT.value},
        ).json()
        assert by_type["meta"]["total_items"] == 1

        by_status = client.get(
            "/verification-requests",
            headers=worker_headers,
            params={"status": VerificationRequestStatus.VERIFIED.value},
        ).json()
        assert by_status["meta"]["total_items"] == 1
        assert by_status["data"][0]["target_type"] == VerificationTargetType.EXPERIENCE.value

        withdrawn = client.get(
            "/verification-requests",
            headers=worker_headers,
            params={"status": VerificationRequestStatus.CANCELLED.value},
        ).json()
        assert withdrawn["meta"]["total_items"] == 0

    def test_a_stranger_sees_nothing_and_cannot_read(
        self, client, worker_headers, outsider_headers, experience, verifier_user
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        assert client.get("/verification-requests", headers=outsider_headers).json()["data"] == []
        assert (
            client.get(
                f"/verification-requests/{created['id']}", headers=outsider_headers
            ).status_code
            == 404
        )

    def test_another_verifiers_request_is_not_found(
        self,
        client,
        worker_headers,
        verifier_headers,
        make_user,
        auth_headers,
        experience,
        project,
        verifier_user,
    ) -> None:
        """Two verifiers, two claims: neither can see the other's."""
        other_verifier = make_user(role=UserRole.EMPLOYER)
        mine = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        theirs = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.PROJECT.value,
            target_id=project.id,
            verifier_email=other_verifier.email,
        )
        other_headers = auth_headers(other_verifier)

        assert (
            client.get(
                f"/verification-requests/{theirs['id']}", headers=verifier_headers
            ).status_code
            == 404
        )
        assert (
            client.get(f"/verification-requests/{mine['id']}", headers=other_headers).status_code
            == 404
        )
        assert (
            client.get(f"/verification-requests/{mine['id']}", headers=verifier_headers).status_code
            == 200
        )
        assert (
            client.get(f"/verification-requests/{theirs['id']}", headers=other_headers).status_code
            == 200
        )

    def test_the_requester_can_read_their_own_request(
        self, client, worker_headers, experience, verifier_user
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        response = client.get(f"/verification-requests/{created['id']}", headers=worker_headers)
        assert response.status_code == 200
        assert response.json()["data"]["id"] == created["id"]

    def test_an_unknown_id_is_not_found(self, client, worker_headers) -> None:
        response = client.get(f"/verification-requests/{uuid.uuid4()}", headers=worker_headers)
        assert response.status_code == 404

    def test_reading_requires_authentication(self, client) -> None:
        assert client.get(f"/verification-requests/{uuid.uuid4()}").status_code == 401

    def test_listing_requires_authentication(self, client) -> None:
        assert client.get("/verification-requests").status_code == 401


# --------------------------------------------------------------------------- #
# Organization-scoped verifiers                                               #
# --------------------------------------------------------------------------- #
class TestOrganizationScope:
    def test_a_colleague_in_the_named_organization_may_answer(
        self, db_session, client, worker_headers, make_user, auth_headers, verifier_user, experience
    ) -> None:
        """The request names a company, so its other staff carry verifier standing."""
        organization = Organization(name="ABC Builders", slug=f"abc-{uuid.uuid4().hex[:8]}")
        db_session.add(organization)
        db_session.flush()
        colleague = make_user(role=UserRole.EMPLOYER)
        for member in (verifier_user, colleague):
            db_session.add(
                OrganizationMembership(
                    organization_id=organization.id,
                    user_id=member.id,
                    role=OrganizationRole.MEMBER.value,
                    status=MembershipStatus.ACTIVE.value,
                )
            )
        db_session.flush()

        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        response = client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=auth_headers(colleague),
            json={"confirm": True},
        )

        assert response.status_code == 200, response.text
        assert response.json()["data"]["status"] == VerificationRequestStatus.VERIFIED.value

    @pytest.mark.parametrize(
        ("membership_status", "org_deleted"),
        [
            (MembershipStatus.SUSPENDED, False),
            (MembershipStatus.ACTIVE, True),
        ],
        ids=["suspended_membership", "deleted_organization"],
    )
    def test_standing_requires_an_active_membership_in_a_live_organization(
        self,
        db_session,
        client,
        worker_headers,
        make_user,
        auth_headers,
        verifier_user,
        experience,
        membership_status,
        org_deleted,
    ) -> None:
        organization = Organization(
            name="Outsiders Ltd",
            slug=f"outs-{uuid.uuid4().hex[:8]}",
            deleted_at=utcnow() if org_deleted else None,
        )
        db_session.add(organization)
        db_session.flush()
        colleague = make_user(role=UserRole.EMPLOYER)
        for member, status in (
            (verifier_user, MembershipStatus.ACTIVE),
            (colleague, membership_status),
        ):
            db_session.add(
                OrganizationMembership(
                    organization_id=organization.id,
                    user_id=member.id,
                    role=OrganizationRole.MEMBER.value,
                    status=status.value,
                )
            )
        db_session.flush()

        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        response = client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=auth_headers(colleague),
            json={"confirm": True},
        )
        assert response.status_code == 404


# --------------------------------------------------------------------------- #
# Answering                                                                   #
# --------------------------------------------------------------------------- #
class TestRespond:
    def test_a_verifier_accepts(
        self, client, worker_headers, verifier_headers, verifier_user, experience
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        response = client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": True, "notes": "I supervised her on all eight floors."},
        )

        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["status"] == VerificationRequestStatus.VERIFIED.value
        assert data["responded_by_user_id"] == str(verifier_user.id)
        assert data["response_notes"] == "I supervised her on all eight floors."
        assert data["verification"]["status"] == VerificationStatus.VERIFIED.value
        assert data["verification"]["verifier_display_name"] == "Peter Otieno"
        assert data["verification"]["response_statement"] == "I supervised her on all eight floors."
        assert data["verification"]["target_id"] == str(experience.id)
        # The caveat travels with the payload, so no client can render a badge
        # without the boundary attached to it.
        assert "not a trust score" in data["verification"]["caveat"]

    def test_a_verifier_rejects_with_a_note(
        self, client, worker_headers, verifier_headers, verifier_user, experience
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        response = client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": False, "notes": "She was on the plastering crew, not masonry."},
        )

        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["status"] == VerificationRequestStatus.REJECTED.value
        assert data["verification"]["status"] == VerificationStatus.REJECTED.value
        assert data["response_notes"] == "She was on the plastering crew, not masonry."

    def test_declining_requires_a_note(
        self, client, worker_headers, verifier_headers, verifier_user, experience
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        response = client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": False},
        )
        assert response.status_code == 422

    def test_the_verifier_display_name_falls_back_to_the_account(
        self, client, worker_headers, verifier_headers, verifier_user, experience
    ) -> None:
        body = _body(VerificationTargetType.EXPERIENCE.value, experience.id, verifier_user.email)
        body.pop("verifier_full_name")
        created = client.post("/verification-requests", headers=worker_headers, json=body)
        assert created.status_code == 201, created.text

        response = client.post(
            f"/verification-requests/{created.json()['data']['id']}/respond",
            headers=verifier_headers,
            json={"confirm": True},
        )
        local_part = verifier_user.email.split("@", 1)[0]
        assert response.json()["data"]["verification"]["verifier_display_name"] == local_part

    def test_a_responder_who_was_not_asked_is_not_found(
        self, client, worker_headers, outsider_headers, experience, verifier_user
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        response = client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=outsider_headers,
            json={"confirm": True},
        )
        assert response.status_code == 404

    def test_responding_twice_is_refused_and_the_first_answer_stands(
        self, client, db_session, worker_headers, verifier_headers, verifier_user, experience
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        first = client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": True, "notes": "Confirmed on site."},
        )
        assert first.status_code == 200, first.text

        second = client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": False, "notes": "Changed my mind."},
        )
        assert second.status_code == 409
        assert second.json()["error"]["code"] == "INVALID_STATE_TRANSITION"

        stored = db_session.execute(
            select(VerificationRequest).where(VerificationRequest.id == created["id"])
        ).scalar_one()
        assert stored.status == VerificationRequestStatus.VERIFIED.value
        assert stored.response_notes == "Confirmed on site."
        assert len(list(db_session.execute(select(Verification)).scalars())) == 1

    def test_an_expired_request_cannot_be_answered(
        self, client, db_session, worker_headers, verifier_headers, verifier_user, experience
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        stored = db_session.execute(
            select(VerificationRequest).where(VerificationRequest.id == created["id"])
        ).scalar_one()
        stored.expires_at = utcnow() - timedelta(days=1)
        db_session.flush()

        response = client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": True},
        )
        assert response.status_code == 409
        assert "deadline" in response.json()["error"]["message"]

    def test_responding_requires_authentication(
        self, client, worker_headers, experience, verifier_user
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        response = client.post(
            f"/verification-requests/{created['id']}/respond", json={"confirm": True}
        )
        assert response.status_code == 401

    def test_the_indicator_is_derived_from_the_verifications_row(
        self, client, db_session, worker_headers, verifier_headers, verifier_user, experience
    ) -> None:
        """Nothing is written onto the claim; the badge is a read of the record."""
        service = VerificationService(db_session)
        target = experience.id

        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=target,
            verifier_email=verifier_user.email,
        )
        assert (
            service.verification_for_target(
                target_type=VerificationTargetType.EXPERIENCE.value, target_id=target
            )
            is None
        )

        client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": True},
        )
        db_session.expire_all()

        record = service.verification_for_target(
            target_type=VerificationTargetType.EXPERIENCE.value, target_id=target
        )
        assert record is not None
        assert record.status == VerificationStatus.VERIFIED.value
        # The claim tables carry no verification column that could drift out of step.
        assert not hasattr(WorkExperience, "verification_status")
        assert not hasattr(Project, "is_verified")

    def test_a_declined_claim_reads_as_no_current_attestation(
        self, client, db_session, worker_headers, verifier_headers, verifier_user, experience
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": False, "notes": "Wrong crew."},
        )
        db_session.expire_all()

        assert (
            VerificationService(db_session).verification_for_target(
                target_type=VerificationTargetType.EXPERIENCE.value, target_id=experience.id
            )
            is None
        )


# --------------------------------------------------------------------------- #
# Cancelling                                                                  #
# --------------------------------------------------------------------------- #
class TestCancel:
    def test_the_requester_withdraws(
        self, client, worker_headers, verifier_headers, experience, verifier_user
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        response = client.post(
            f"/verification-requests/{created['id']}/cancel", headers=worker_headers
        )
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["status"] == VerificationRequestStatus.CANCELLED.value
        assert data["responded_by_user_id"] is None

        # Withdrawn means unanswered: the verifier is locked out of it now.
        assert (
            client.post(
                f"/verification-requests/{created['id']}/respond",
                headers=verifier_headers,
                json={"confirm": True},
            ).status_code
            == 409
        )

    def test_a_verifier_cannot_withdraw_somebody_elses_request(
        self, client, worker_headers, verifier_headers, experience, verifier_user
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        response = client.post(
            f"/verification-requests/{created['id']}/cancel", headers=verifier_headers
        )
        assert response.status_code == 404

    def test_cancelling_twice_is_refused(
        self, client, worker_headers, experience, verifier_user
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        client.post(f"/verification-requests/{created['id']}/cancel", headers=worker_headers)
        assert (
            client.post(
                f"/verification-requests/{created['id']}/cancel", headers=worker_headers
            ).status_code
            == 409
        )

    def test_answering_then_cancelling_is_refused(
        self, client, worker_headers, verifier_headers, experience, verifier_user
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": True},
        )
        assert (
            client.post(
                f"/verification-requests/{created['id']}/cancel", headers=worker_headers
            ).status_code
            == 409
        )

    def test_cancelling_an_unknown_request_is_not_found(self, client, worker_headers) -> None:
        response = client.post(
            f"/verification-requests/{uuid.uuid4()}/cancel", headers=worker_headers
        )
        assert response.status_code == 404

    def test_cancelling_requires_authentication(
        self, client, worker_headers, experience, verifier_user
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        assert client.post(f"/verification-requests/{created['id']}/cancel").status_code == 401


# --------------------------------------------------------------------------- #
# Audit and the notification outbox                                           #
# --------------------------------------------------------------------------- #
class TestAuditAndOutbox:
    def test_every_transition_is_audited(
        self,
        client,
        worker_headers,
        verifier_headers,
        make_user,
        experience,
        second_experience,
        project,
        credential,
        verifier_user,
        audit_rows,
    ) -> None:
        requested = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        accepted = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.PROJECT.value,
            target_id=project.id,
            verifier_email=verifier_user.email,
        )
        declined = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.CREDENTIAL.value,
            target_id=credential.id,
            verifier_email=verifier_user.email,
        )
        withdrawn = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=second_experience.id,
            verifier_email=make_user(role=UserRole.EMPLOYER).email,
        )

        client.post(
            f"/verification-requests/{accepted['id']}/respond",
            headers=verifier_headers,
            json={"confirm": True},
        )
        client.post(
            f"/verification-requests/{declined['id']}/respond",
            headers=verifier_headers,
            json={"confirm": False, "notes": "Not the crew I recall."},
        )
        client.post(f"/verification-requests/{withdrawn['id']}/cancel", headers=worker_headers)

        assert len(audit_rows(action=AuditAction.VERIFICATION_REQUESTED.value)) == 4
        assert [
            row.outcome
            for row in audit_rows(
                action=AuditAction.VERIFICATION_REQUESTED.value, resource_id=requested["id"]
            )
        ] == ["REQUESTED"]
        assert [
            row.outcome
            for row in audit_rows(
                action=AuditAction.VERIFICATION_COMPLETED.value, resource_id=accepted["id"]
            )
        ] == ["SUCCESS"]
        # A refusal is a failure event: that is the row an investigator needs.
        assert [
            row.outcome
            for row in audit_rows(
                action=AuditAction.VERIFICATION_REJECTED.value, resource_id=declined["id"]
            )
        ] == ["FAILURE"]
        assert [
            row.outcome
            for row in audit_rows(
                action=AuditAction.VERIFICATION_CANCELLED.value, resource_id=withdrawn["id"]
            )
        ] == ["SUCCESS"]

    def test_audit_metadata_never_stores_the_address(
        self, client, worker_headers, experience, verifier_user, audit_rows
    ) -> None:
        _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        row = audit_rows(action=AuditAction.VERIFICATION_REQUESTED.value)[0]
        assert verifier_user.email not in str(row.metadata_)
        assert "*" in row.metadata_["verifier_email"]

    def test_transitions_append_outbox_events_without_sending_anything(
        self,
        client,
        db_session,
        worker_headers,
        worker_user,
        verifier_headers,
        verifier_user,
        experience,
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        requested = _events(db_session, NotificationEventType.VERIFICATION_REQUESTED)
        assert len(requested) == 1
        assert requested[0].user_id == verifier_user.id
        assert requested[0].processed_at is None
        assert requested[0].attempts == 0

        client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": True},
        )
        completed = _events(db_session, NotificationEventType.VERIFICATION_COMPLETED)
        assert len(completed) == 1
        assert completed[0].user_id == worker_user.id
        assert completed[0].payload["status"] == VerificationStatus.VERIFIED.value

    def test_a_verifier_without_an_account_is_still_addressable(
        self, client, db_session, worker_headers, experience
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email="foreman@external-site.example",
        )
        assert created["verifier_email"] == "foreman@external-site.example"
        event = _events(db_session, NotificationEventType.VERIFICATION_REQUESTED)[0]
        assert event.user_id is None
        assert event.recipient_email == "foreman@external-site.example"


# --------------------------------------------------------------------------- #
# The absence of a score                                                     #
# --------------------------------------------------------------------------- #
class TestNoScoreAnywhere:
    def test_no_verification_schema_exposes_a_rating_or_score(self, client) -> None:
        schemas = client.get("/openapi.json").json()["components"]["schemas"]
        verification_schemas = {
            name: body for name, body in schemas.items() if name.startswith("Verification")
        }
        assert verification_schemas, "no verification schemas found in the OpenAPI document"

        for name, body in verification_schemas.items():
            for field in body.get("properties", {}):
                lowered = field.lower()
                for banned in FORBIDDEN_FIELD_SUBSTINGS:
                    assert banned not in lowered, f"{name}.{field} looks like a score field"

    def test_the_endpoint_inventory_is_exactly_what_is_documented(self, client) -> None:
        paths = {
            path
            for path in client.get("/openapi.json").json()["paths"]
            if path.startswith("/verification-requests")
        }
        assert paths == {
            "/verification-requests",
            "/verification-requests/{request_id}",
            "/verification-requests/{request_id}/respond",
            "/verification-requests/{request_id}/cancel",
        }

    def test_the_openapi_document_states_what_a_verification_is_not(self, client) -> None:
        rendered = str(client.get("/openapi.json").json())
        assert "not a trust score" in rendered
        assert "not a guarantee" in rendered

    def test_no_response_payload_carries_a_score_field(
        self, client, worker_headers, verifier_headers, verifier_user, experience
    ) -> None:
        created = _raise(
            client,
            worker_headers,
            target_type=VerificationTargetType.EXPERIENCE.value,
            target_id=experience.id,
            verifier_email=verifier_user.email,
        )
        client.post(
            f"/verification-requests/{created['id']}/respond",
            headers=verifier_headers,
            json={"confirm": True, "notes": "Supervised her throughout."},
        )

        for record in (
            client.get("/verification-requests", headers=worker_headers).json()["data"][0],
            client.get(f"/verification-requests/{created['id']}", headers=worker_headers).json()[
                "data"
            ],
            client.get("/verification-requests", headers=verifier_headers).json()["data"][0],
        ):
            assert record["verification"]["status"] == VerificationStatus.VERIFIED.value
            for key in record:
                assert not any(banned in key.lower() for banned in FORBIDDEN_FIELD_SUBSTINGS)
            for key in record["verification"]:
                assert not any(banned in key.lower() for banned in FORBIDDEN_FIELD_SUBSTINGS)
