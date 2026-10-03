"""Contact requests: the only path by which a worker's details are released.

The central assertion is negative and appears in several forms: filing a request
must not disclose anything, and an employer must never receive a phone number or
email from any endpoint in this flow — including after the worker accepts, because
the employer is told the request was accepted and then makes a *separate*,
authorised request for the details.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.constants import (
    ContactPreference,
    NotificationEventType,
    OrganizationRole,
    UserRole,
)
from app.db.models.catalogue import County, Trade
from app.db.models.contact import ContactRequest
from app.db.models.notification import Notification

pytestmark = [pytest.mark.api, pytest.mark.integration]


@pytest.fixture
def catalogue(db_session):
    db_session.add_all(
        [
            County(id=uuid.uuid4(), code="NAKURU", name="Nakuru"),
            Trade(id=uuid.uuid4(), code="MASONRY", name="Masonry"),
        ]
    )
    db_session.flush()


def login(client, account) -> dict[str, str]:
    r = client.post(
        "/auth/login", json={"email": account.email, "password": "Correct-Horse-9-Battery"}
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['data']['tokens']['access_token']}"}


@pytest.fixture
def employer(client, db_session, make_user, catalogue):
    """An employer who owns an organization and can therefore recruit."""
    account = make_user(role=UserRole.EMPLOYER)
    headers = login(client, account)
    created = client.post(
        "/organizations",
        headers=headers,
        json={"name": "Riverside Contractors", "industry": "Construction"},
    )
    assert created.status_code == 201, created.text
    return {
        "user": account,
        "headers": headers,
        "organization_id": created.json()["data"]["id"],
    }


@pytest.fixture
def worker(client, db_session, make_user, catalogue):
    """A discoverable worker who has listed a way to be contacted."""
    account = make_user()
    headers = login(client, account)
    created = client.post(
        "/workers/me/profile",
        headers=headers,
        json={
            "display_name": "Amina Wanjiru",
            "primary_trade_code": "MASONRY",
            "visibility": "PUBLIC",
            "contact_preference": ContactPreference.IN_APP.value,
            "phone_number": "0712345678",
            "contact_email": "amina.private@example.com",
        },
    )
    assert created.status_code == 201, created.text
    return {"user": account, "headers": headers, "id": created.json()["data"]["id"]}


def file_request(client, employer, worker, **overrides):
    payload = {
        "organization_id": employer["organization_id"],
        "message": "We have a masonry contract in Nakuru starting next month.",
    }
    payload.update(overrides)
    return client.post(
        f"/workers/{worker['id']}/contact-requests",
        headers=employer["headers"],
        json=payload,
    )


class TestFiling:
    def test_files_a_request(self, client, employer, worker) -> None:
        response = file_request(client, employer, worker)
        assert response.status_code == 201, response.text
        data = response.json()["data"]
        assert data["status"] == "PENDING"
        assert data["worker_profile_id"] == str(worker["id"])
        assert data["contact_details_shared"] is False

    def test_filing_discloses_nothing(self, client, employer, worker) -> None:
        """The whole point: asking is not being told."""
        body = file_request(client, employer, worker).text
        for leak in ("0712345678", "amina.private@example.com", "Amina Wanjiru"):
            assert leak not in body, f"filing leaked {leak}"

    def test_the_request_is_not_addressed_to_a_private_worker(
        self, client, employer, db_session, make_user, catalogue
    ) -> None:
        hidden = make_user()
        headers = login(client, hidden)
        created = client.post(
            "/workers/me/profile", headers=headers, json={"display_name": "Hidden Person"}
        )
        response = client.post(
            f"/workers/{created.json()['data']['id']}/contact-requests",
            headers=employer["headers"],
            json={"organization_id": employer["organization_id"]},
        )
        assert response.status_code == 404

    def test_a_worker_who_declined_all_contact_is_refused(
        self, client, employer, db_session, make_user, catalogue
    ) -> None:
        account = make_user()
        headers = login(client, account)
        created = client.post(
            "/workers/me/profile",
            headers=headers,
            json={
                "display_name": "Not Contactable",
                "visibility": "PUBLIC",
                "contact_preference": "NONE",
            },
        )
        response = client.post(
            f"/workers/{created.json()['data']['id']}/contact-requests",
            headers=employer["headers"],
            json={"organization_id": employer["organization_id"]},
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "WORKER_NOT_CONTACTABLE"

    def test_a_second_pending_request_is_a_conflict(self, client, employer, worker) -> None:
        assert file_request(client, employer, worker).status_code == 201
        assert file_request(client, employer, worker).status_code == 409

    def test_authentication_is_required(self, client, employer, worker) -> None:
        response = client.post(
            f"/workers/{worker['id']}/contact-requests",
            json={"organization_id": employer["organization_id"]},
        )
        assert response.status_code == 401

    def test_no_user_id_field_is_accepted(self, client, employer, worker) -> None:
        """The requester is the caller; accepting a user_id would be an IDOR."""
        response = file_request(client, employer, worker, user_id=str(uuid.uuid4()))
        assert response.status_code == 422


class TestCrossOrganization:
    def test_a_non_member_cannot_file_for_an_organization(
        self, client, employer, worker, make_user
    ) -> None:
        outsider = make_user()
        response = client.post(
            f"/workers/{worker['id']}/contact-requests",
            headers=login(client, outsider),
            json={"organization_id": employer["organization_id"]},
        )
        assert response.status_code == 404

    def test_a_plain_member_may_not_recurse(
        self, client, employer, worker, db_session, make_user, catalogue
    ) -> None:
        member = make_user()
        client.post(
            f"/organizations/{employer['organization_id']}/members",
            headers=employer["headers"],
            json={"email": member.email, "role": OrganizationRole.MEMBER.value},
        )
        response = file_request_from(client, member, worker, employer["organization_id"])
        assert response.status_code == 403

    def test_a_recruiter_may_file(
        self, client, employer, worker, db_session, make_user, catalogue
    ) -> None:
        recruiter = make_user()
        client.post(
            f"/organizations/{employer['organization_id']}/members",
            headers=employer["headers"],
            json={"email": recruiter.email, "role": OrganizationRole.RECRUITER.value},
        )
        assert (
            file_request_from(client, recruiter, worker, employer["organization_id"]).status_code
            == 201
        )

    def test_organization_a_cannot_read_organization_bs_request(
        self, client, employer, worker, make_user
    ) -> None:
        filed = file_request(client, employer, worker)
        request_id = filed.json()["data"]["id"]

        other_owner = make_user(role=UserRole.EMPLOYER)
        other_headers = login(client, other_owner)
        other_org = client.post(
            "/organizations", headers=other_headers, json={"name": "Someone Else Ltd"}
        ).json()["data"]["id"]

        response = client.get(f"/contact-requests/{request_id}", headers=other_headers)
        assert response.status_code == 404
        assert other_org


def file_request_from(client, account, worker, organization_id) -> object:
    return client.post(
        f"/workers/{worker['id']}/contact-requests",
        headers=login(client, account),
        json={"organization_id": organization_id},
    )


class TestWorkerSide:
    def test_the_worker_sees_received_requests(self, client, employer, worker) -> None:
        file_request(client, employer, worker)
        listing = client.get("/workers/me/contact-requests", headers=worker["headers"])
        assert listing.status_code == 200
        assert listing.json()["meta"]["total_items"] == 1
        assert "Nakuru" in listing.json()["data"][0]["message"]

    def test_accepting_records_disclosure_and_the_answer(self, client, employer, worker) -> None:
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        response = client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=worker["headers"],
            json={"accept": True, "response_note": "Happy to hear about it."},
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "ACCEPTED"
        assert data["contact_details_shared"] is True
        assert data["responded_at"] is not None

    def test_rejecting_records_no_disclosure(self, client, employer, worker) -> None:
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        response = client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=worker["headers"],
            json={"accept": False, "response_note": "Not looking right now."},
        )
        assert response.json()["data"]["status"] == "REJECTED"
        assert response.json()["data"]["contact_details_shared"] is False

    def test_a_request_can_only_be_answered_once(self, client, employer, worker) -> None:
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        first = client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=worker["headers"],
            json={"accept": True},
        )
        assert first.status_code == 200
        second = client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=worker["headers"],
            json={"accept": False},
        )
        assert second.status_code == 409

    def test_the_answer_cannot_be_overwritten(self, client, employer, worker, db_session) -> None:
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=worker["headers"],
            json={"accept": True, "response_note": "Original note"},
        )
        client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=worker["headers"],
            json={"accept": False, "response_note": "Changed my mind"},
        )
        row = db_session.get(ContactRequest, uuid.UUID(request_id))
        assert row.response_note == "Original note"
        assert row.status == "ACCEPTED"

    def test_a_different_worker_cannot_answer(
        self, client, employer, worker, db_session, make_user, catalogue
    ) -> None:
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        stranger = make_user()
        headers = login(client, stranger)
        client.post("/workers/me/profile", headers=headers, json={"display_name": "Meddler"})
        response = client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=headers,
            json={"accept": True},
        )
        assert response.status_code == 404
        assert db_session.get(ContactRequest, uuid.UUID(request_id)).status == "PENDING"

    def test_a_requester_cannot_answer_their_own_request(self, client, employer, worker) -> None:
        """Only the worker decides; the employer cannot press their own button."""
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        response = client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=employer["headers"],
            json={"accept": True},
        )
        assert response.status_code == 404


class TestEmployerReads:
    def test_the_requester_sees_the_outcome_but_never_the_details(
        self, client, employer, worker
    ) -> None:
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=worker["headers"],
            json={"accept": True},
        )
        body = client.get(f"/contact-requests/{request_id}", headers=employer["headers"])
        assert body.status_code == 200
        assert body.json()["data"]["contact_details_shared"] is True
        # Acceptance is recorded; the address is released by a separate,
        # authorised step and never appears in this payload.
        assert body.json()["data"].get("worker_contact") is None
        for leak in ("0712345678", "amina.private@example.com"):
            assert leak not in body.text

    def test_the_worker_sees_their_own_contact_block(self, client, employer, worker) -> None:
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        body = client.get(f"/workers/me/contact-requests/{request_id}", headers=worker["headers"])
        assert body.json()["data"]["worker_contact"]["phone_number"] == "0712345678"


class TestCancellation:
    def test_the_requester_can_cancel(self, client, employer, worker) -> None:
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        response = client.post(
            f"/contact-requests/{request_id}/cancel", headers=employer["headers"]
        )
        assert response.status_code == 200
        assert response.json()["data"]["status"] == "CANCELLED"

    def test_a_cancelled_request_cannot_be_answered(self, client, employer, worker) -> None:
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        client.post(f"/contact-requests/{request_id}/cancel", headers=employer["headers"])
        response = client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=worker["headers"],
            json={"accept": True},
        )
        assert response.status_code == 409

    def test_cancelling_does_not_undo_an_earlier_disclosure(
        self, client, employer, worker, db_session
    ) -> None:
        """`contact_details_shared` is a fact about what happened, not a status."""
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=worker["headers"],
            json={"accept": True},
        )
        # 409: it is already answered, so it cannot also be cancelled. The stored
        # fact that disclosure happened is untouched.
        response = client.post(
            f"/contact-requests/{request_id}/cancel", headers=employer["headers"]
        )
        assert response.status_code == 409
        row = db_session.get(ContactRequest, uuid.UUID(request_id))
        assert row.contact_details_shared is True
        assert row.status == "ACCEPTED"

    def test_a_worker_cannot_cancel(self, client, employer, worker) -> None:
        request_id = file_request(client, employer, worker).json()["data"]["id"]
        assert (
            client.post(
                f"/contact-requests/{request_id}/cancel", headers=worker["headers"]
            ).status_code
            == 404
        )


class TestNotifications:
    def test_the_worker_is_notified_when_a_request_arrives(
        self, client, employer, worker, db_session
    ) -> None:
        from sqlalchemy import select

        file_request(client, employer, worker)
        rows = (
            db_session.execute(
                select(Notification).where(
                    Notification.recipient_user_id == worker["user"].id,
                    Notification.event_type == NotificationEventType.EMPLOYER_CONTACT_REQUEST.value,
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1

    def test_the_requester_is_notified_of_the_answer(
        self, client, employer, worker, db_session
    ) -> None:
        from sqlalchemy import select

        request_id = file_request(client, employer, worker).json()["data"]["id"]
        client.post(
            f"/workers/me/contact-requests/{request_id}/respond",
            headers=worker["headers"],
            json={"accept": True},
        )
        rows = (
            db_session.execute(
                select(Notification).where(Notification.recipient_user_id == employer["user"].id)
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert "0712345678" not in rows[0].body, "a notification carried a contact detail"

    def test_audit_records_the_request(self, client, employer, worker, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        request_id = file_request(client, employer, worker).json()["data"]["id"]
        rows = db_session.execute(select(AuditLog)).scalars().all()
        assert any(r.resource_id is not None and str(r.resource_id) == request_id for r in rows)


class TestJobAttribution:
    def test_a_job_from_another_organization_cannot_be_attached(
        self, client, employer, worker, make_user
    ) -> None:
        """Otherwise an employer could borrow another company's vacancy as pretext."""
        other_owner = make_user(role=UserRole.EMPLOYER)
        other_headers = login(client, other_owner)
        other_org = client.post(
            "/organizations", headers=other_headers, json={"name": "Rival Ltd"}
        ).json()["data"]["id"]
        job = client.post(
            f"/organizations/{other_org}/jobs",
            headers=other_headers,
            json={"title": "Rival Site", "description": "A rival site with enough description."},
        ).json()["data"]["id"]

        response = file_request(client, employer, worker, job_id=job)
        assert response.status_code == 404

    def test_the_workers_own_organization_job_can_be_attached(
        self, client, employer, worker
    ) -> None:
        job = client.post(
            f"/organizations/{employer['organization_id']}/jobs",
            headers=employer["headers"],
            json={"title": "Nakuru Site", "description": "A Nakuru site with enough description."},
        )
        assert job.status_code == 201, job.text
        response = file_request(client, employer, worker, job_id=job.json()["data"]["id"])
        assert response.status_code == 201
        assert response.json()["data"]["job_title"] == "Nakuru Site"
