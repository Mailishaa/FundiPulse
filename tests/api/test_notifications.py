"""Notifications: recipient isolation, unread counting and read receipts.

The security property is that a notification belongs to exactly one recipient and
nothing about another user's is reachable — including marking it read, which is a
write and therefore the more dangerous of the two.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.constants import NotificationEventType
from app.db.models.notification import Notification

pytestmark = [pytest.mark.api, pytest.mark.integration]


@pytest.fixture
def user(client, make_user):
    account = make_user()
    r = client.post(
        "/auth/login", json={"email": account.email, "password": "Correct-Horse-9-Battery"}
    )
    token = r.json()["data"]["tokens"]["access_token"]
    return {"account": account, "headers": {"Authorization": f"Bearer {token}"}}


def notify(db_session, recipient_id, *, title="Application shortlisted", unread=True):
    row = Notification(
        recipient_user_id=recipient_id,
        event_type=NotificationEventType.APPLICATION_STATUS_CHANGED.value,
        title=title,
        body="An employer moved your application to SHORTLISTED.",
        payload={"job_id": str(uuid.uuid4())},
    )
    db_session.add(row)
    db_session.flush()
    return row


class TestListing:
    def test_lists_the_callers_notifications(self, client, user, db_session) -> None:
        notify(db_session, user["account"].id)
        response = client.get("/notifications", headers=user["headers"])
        assert response.status_code == 200
        assert response.json()["meta"]["total_items"] == 1
        assert response.json()["data"][0]["is_read"] is False

    def test_an_empty_inbox_is_an_empty_list_not_an_error(self, client, user) -> None:
        response = client.get("/notifications", headers=user["headers"])
        assert response.status_code == 200
        assert response.json()["data"] == []
        assert response.json()["meta"]["total_items"] == 0

    def test_unread_only_filter(self, client, user, db_session) -> None:
        from app.services.notification_service import NotificationService

        notify(db_session, user["account"].id, title="Unread one")
        read = notify(db_session, user["account"].id, title="Already read")
        NotificationService(db_session).mark_read(
            recipient_user_id=user["account"].id, notification_id=read.id
        )
        listing = client.get("/notifications?unread_only=true", headers=user["headers"])
        assert [n["title"] for n in listing.json()["data"]] == ["Unread one"]

    def test_newest_first(self, client, user, db_session) -> None:
        notify(db_session, user["account"].id, title="First")
        notify(db_session, user["account"].id, title="Second")
        titles = [
            n["title"] for n in client.get("/notifications", headers=user["headers"]).json()["data"]
        ]
        assert titles == ["Second", "First"]

    def test_pagination(self, client, user, db_session) -> None:
        for index in range(4):
            notify(db_session, user["account"].id, title=f"Note {index}")
        page = client.get("/notifications?page=1&page_size=3", headers=user["headers"])
        assert len(page.json()["data"]) == 3
        assert page.json()["meta"]["total_items"] == 4
        assert page.json()["meta"]["has_next"] is True

    def test_pagination_abuse_is_refused(self, client, user) -> None:
        assert (
            client.get("/notifications?page_size=99999", headers=user["headers"]).status_code == 422
        )
        assert (
            client.get("/notifications?page=99999999", headers=user["headers"]).status_code == 422
        )

    def test_authentication_is_required(self, client) -> None:
        assert client.get("/notifications").status_code == 401
        assert client.get("/notifications/unread-count").status_code == 401


class TestRecipientIsolation:
    def test_another_user_sees_none_of_them(self, client, make_user, db_session) -> None:
        owner = make_user()
        notify(db_session, owner.id, title="Secret To Owner")
        r = client.post(
            "/auth/login", json={"email": owner.email, "password": "Correct-Horse-9-Battery"}
        )
        owner_headers = {"Authorization": f"Bearer {r.json()['data']['tokens']['access_token']}"}

        stranger = make_user()
        r2 = client.post(
            "/auth/login",
            json={"email": stranger.email, "password": "Correct-Horse-9-Battery"},
        )
        stranger_headers = {
            "Authorization": f"Bearer {r2.json()['data']['tokens']['access_token']}"
        }

        assert "Secret To Owner" in client.get("/notifications", headers=owner_headers).text
        assert client.get("/notifications", headers=stranger_headers).json()["data"] == []

    def test_another_user_cannot_mark_it_read(self, client, make_user, db_session) -> None:
        owner = make_user()
        row = notify(db_session, owner.id)

        stranger = make_user()
        r = client.post(
            "/auth/login",
            json={"email": stranger.email, "password": "Correct-Horse-9-Battery"},
        )
        stranger_headers = {"Authorization": f"Bearer {r.json()['data']['tokens']['access_token']}"}

        response = client.patch(f"/notifications/{row.id}/read", headers=stranger_headers)
        assert response.status_code == 404
        assert row.read_at is None, "a stranger marked someone else's notification read"

    def test_marking_an_unknown_id_is_a_404(self, client, user) -> None:
        assert (
            client.patch(f"/notifications/{uuid.uuid4()}/read", headers=user["headers"]).status_code
            == 404
        )

    def test_unread_count_is_per_recipient(self, client, make_user, db_session) -> None:
        owner = make_user()
        for _ in range(3):
            notify(db_session, owner.id)
        r = client.post(
            "/auth/login", json={"email": owner.email, "password": "Correct-Horse-9-Battery"}
        )
        owner_headers = {"Authorization": f"Bearer {r.json()['data']['tokens']['access_token']}"}
        stranger = make_user()
        r2 = client.post(
            "/auth/login",
            json={"email": stranger.email, "password": "Correct-Horse-9-Battery"},
        )
        stranger_headers = {
            "Authorization": f"Bearer {r2.json()['data']['tokens']['access_token']}"
        }

        assert (
            client.get("/notifications/unread-count", headers=owner_headers).json()["data"][
                "unread_count"
            ]
            == 3
        )
        assert (
            client.get("/notifications/unread-count", headers=stranger_headers).json()["data"][
                "unread_count"
            ]
            == 0
        )


class TestReadReceipts:
    def test_marking_read_sets_the_timestamp(self, client, user, db_session) -> None:
        row = notify(db_session, user["account"].id)
        response = client.patch(f"/notifications/{row.id}/read", headers=user["headers"])
        assert response.status_code == 200
        assert response.json()["data"]["is_read"] is True
        assert response.json()["data"]["read_at"] is not None

    def test_marking_read_twice_is_idempotent(self, client, user, db_session) -> None:
        """A client retrying after a dropped response keeps the original time."""
        row = notify(db_session, user["account"].id)
        first = client.patch(f"/notifications/{row.id}/read", headers=user["headers"])
        second = client.patch(f"/notifications/{row.id}/read", headers=user["headers"])
        assert second.status_code == 200
        assert first.json()["data"]["read_at"] == second.json()["data"]["read_at"]

    def test_reading_reduces_the_unread_count(self, client, user, db_session) -> None:
        rows = [notify(db_session, user["account"].id, title=f"Note {i}") for i in range(2)]
        client.patch(f"/notifications/{rows[0].id}/read", headers=user["headers"])
        count = client.get("/notifications/unread-count", headers=user["headers"])
        assert count.json()["data"]["unread_count"] == 1

    def test_mark_all_read_clears_the_badge(self, client, user, db_session) -> None:
        for index in range(3):
            notify(db_session, user["account"].id, title=f"Note {index}")
        response = client.post("/notifications/read-all", headers=user["headers"])
        assert response.status_code == 200
        assert response.json()["data"]["unread_count"] == 0
        assert client.get("/notifications", headers=user["headers"]).json()["data"]
        assert all(
            n["is_read"]
            for n in client.get("/notifications", headers=user["headers"]).json()["data"]
        )

    def test_mark_all_read_leaves_other_recipients_alone(
        self, client, make_user, db_session
    ) -> None:
        other = make_user()
        their_row = notify(db_session, other.id, title="Not Mine")
        mine = notify(db_session, other.id, title="Also Not Mine")

        owner = make_user()
        notify(db_session, owner.id)
        r = client.post(
            "/auth/login", json={"email": owner.email, "password": "Correct-Horse-9-Battery"}
        )
        headers = {"Authorization": f"Bearer {r.json()['data']['tokens']['access_token']}"}
        client.post("/notifications/read-all", headers=headers)
        assert their_row.read_at is None
        assert mine.read_at is None
