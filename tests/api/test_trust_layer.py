"""References and credentials — the worker's trust layer.

Two rules carry the whole domain and are asserted negatively here:

* **A reference is not a verification.** A person the worker names as a referee is
  not an attestation, and nothing in this layer may create one or set a status.
* **Uploading a certificate does not verify it.** A credential is a document the
  worker claims holds. Only the verification domain can conclude anything.

Plus the boring but important part: every route is scoped to the caller's own
passport, so substituting another worker's id matches nothing.
"""

from __future__ import annotations

from datetime import timedelta
import uuid

import pytest

from app.db.base import utcnow
from app.db.models.catalogue import County, Skill, Trade
from app.db.models.verification import Verification
from app.utils.dates import utc_today

pytestmark = [pytest.mark.api, pytest.mark.integration]

TODAY = utc_today()


@pytest.fixture
def catalogue(db_session):
    db_session.add_all(
        [
            County(id=uuid.uuid4(), code="NAKURU", name="Nakuru"),
            Trade(id=uuid.uuid4(), code="MASONRY", name="Masonry"),
            Skill(id=uuid.uuid4(), code="BLOCK_LAYING", name="Block laying"),
        ]
    )
    db_session.flush()


@pytest.fixture
def worker(client, db_session, make_user, catalogue):
    """A worker with a passport and bearer headers."""
    user = make_user()
    r = client.post(
        "/auth/login", json={"email": user.email, "password": "Correct-Horse-9-Battery"}
    )
    token = r.json()["data"]["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post(
        "/workers/me/profile",
        headers=headers,
        json={"display_name": "Amina Wanjiru", "primary_trade_code": "MASONRY"},
    )
    assert created.status_code == 201, created.text
    return {
        "user": user,
        "headers": headers,
        "id": created.json()["data"]["id"],
    }


@pytest.fixture
def other(client, db_session, make_user, catalogue):
    """A second worker, for cross-worker IDOR attempts."""
    user = make_user()
    r = client.post(
        "/auth/login", json={"email": user.email, "password": "Correct-Horse-9-Battery"}
    )
    token = r.json()["data"]["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/workers/me/profile", headers=headers, json={"display_name": "Second Worker"})
    return {"user": user, "headers": headers}


CREDENTIAL = {
    "title": "Trade Test Certificate",
    "credential_type": "TRADE_TEST_CERTIFICATE",
    "issuing_country_code": "KE",
    "issue_date": str(TODAY - timedelta(days=400)),
}

REFERENCE = {
    "full_name": "Joseph Kamau",
    "email": "joseph.kamau@example.com",
    "relationship_type": "FOREMAN",
    "organization_name": "Mwangaza Construction Ltd",
}


class TestCredentials:
    def test_create_and_read_back(self, client, worker) -> None:
        created = client.post("/workers/me/credentials", headers=worker["headers"], json=CREDENTIAL)
        assert created.status_code == 201, created.text
        credential_id = created.json()["data"]["id"]

        single = client.get(f"/workers/me/credentials/{credential_id}", headers=worker["headers"])
        assert single.status_code == 200
        assert single.json()["data"]["title"] == "Trade Test Certificate"

    def test_list_and_paginate(self, client, worker) -> None:
        for index in range(3):
            client.post(
                "/workers/me/credentials",
                headers=worker["headers"],
                json={**CREDENTIAL, "title": f"Certificate {index}"},
            )
        listing = client.get("/workers/me/credentials", headers=worker["headers"])
        assert listing.status_code == 200
        assert listing.json()["meta"]["total_items"] == 3

        page = client.get("/workers/me/credentials?page=1&page_size=2", headers=worker["headers"])
        assert len(page.json()["data"]) == 2

    def test_update(self, client, worker) -> None:
        created = client.post("/workers/me/credentials", headers=worker["headers"], json=CREDENTIAL)
        credential_id = created.json()["data"]["id"]
        updated = client.patch(
            f"/workers/me/credentials/{credential_id}",
            headers=worker["headers"],
            json={"title": "Trade Test Certificate (renewed)"},
        )
        assert updated.status_code == 200
        assert updated.json()["data"]["title"] == "Trade Test Certificate (renewed)"

    def test_delete_is_soft(self, client, worker, db_session) -> None:
        created = client.post("/workers/me/credentials", headers=worker["headers"], json=CREDENTIAL)
        credential_id = created.json()["data"]["id"]
        assert (
            client.delete(
                f"/workers/me/credentials/{credential_id}", headers=worker["headers"]
            ).status_code
            == 200
        )
        assert (
            client.get(
                f"/workers/me/credentials/{credential_id}", headers=worker["headers"]
            ).status_code
            == 404
        )

    def test_an_unknown_type_is_rejected(self, client, worker) -> None:
        response = client.post(
            "/workers/me/credentials",
            headers=worker["headers"],
            json={**CREDENTIAL, "credential_type": "DOCTORATE_IN_MAGIC"},
        )
        assert response.status_code == 422

    def test_an_expiry_before_issue_is_rejected(self, client, worker) -> None:
        response = client.post(
            "/workers/me/credentials",
            headers=worker["headers"],
            json={**CREDENTIAL, "expiry_date": str(TODAY - timedelta(days=800))},
        )
        assert response.status_code == 422

    def test_a_future_issue_date_is_rejected(self, client, worker) -> None:
        response = client.post(
            "/workers/me/credentials",
            headers=worker["headers"],
            json={**CREDENTIAL, "issue_date": str(TODAY + timedelta(days=10))},
        )
        assert response.status_code == 422

    def test_authentication_is_required(self, client, worker) -> None:
        assert client.get("/workers/me/credentials").status_code == 401


class TestCredentialVerificationBoundary:
    """Uploading a document is a claim, not a verification."""

    def test_a_new_credential_is_not_verified(self, client, worker) -> None:
        created = client.post("/workers/me/credentials", headers=worker["headers"], json=CREDENTIAL)
        data = created.json()["data"]
        assert data["verification"] is None
        assert "certified" not in created.text.lower()

    def test_no_endpoint_can_set_the_verification_status(self, client, worker) -> None:
        """A client must not be able to mark its own document verified."""
        created = client.post("/workers/me/credentials", headers=worker["headers"], json=CREDENTIAL)
        credential_id = created.json()["data"]["id"]
        for field, value in (
            ("verification", {"status": "VERIFIED"}),
            ("verification_status", "VERIFIED"),
            ("is_verified", True),
            ("verified_at", str(utcnow())),
            ("worker_profile_id", str(uuid.uuid4())),
            ("user_id", str(uuid.uuid4())),
        ):
            response = client.patch(
                f"/workers/me/credentials/{credential_id}",
                headers=worker["headers"],
                json={field: value},
            )
            assert response.status_code == 422, f"{field} was accepted"
        still = client.get(f"/workers/me/credentials/{credential_id}", headers=worker["headers"])
        assert still.json()["data"]["verification"] is None

    def test_the_create_request_also_refuses_a_status(self, client, worker) -> None:
        response = client.post(
            "/workers/me/credentials",
            headers=worker["headers"],
            json={**CREDENTIAL, "verification": {"status": "VERIFIED"}},
        )
        assert response.status_code == 422

    def test_no_verification_row_is_created_by_an_upload(self, client, worker, db_session) -> None:
        from sqlalchemy import select

        client.post("/workers/me/credentials", headers=worker["headers"], json=CREDENTIAL)
        client.post("/workers/me/references", headers=worker["headers"], json=REFERENCE)
        rows = db_session.execute(select(Verification)).scalars().all()
        assert rows == [], "creating trust-layer records produced a verification"


class TestReferences:
    def test_create_and_read_back(self, client, worker) -> None:
        created = client.post("/workers/me/references", headers=worker["headers"], json=REFERENCE)
        assert created.status_code == 201, created.text
        reference_id = created.json()["data"]["id"]
        single = client.get(f"/workers/me/references/{reference_id}", headers=worker["headers"])
        assert single.status_code == 200
        assert single.json()["data"]["full_name"] == "Joseph Kamau"

    def test_list_and_paginate(self, client, worker) -> None:
        for index in range(3):
            client.post(
                "/workers/me/references",
                headers=worker["headers"],
                json={
                    **REFERENCE,
                    "full_name": f"Referee {index}",
                    "email": f"ref{index}@example.com",
                },
            )
        assert (
            client.get("/workers/me/references", headers=worker["headers"]).json()["meta"][
                "total_items"
            ]
            == 3
        )
        page = client.get("/workers/me/references?page=1&page_size=2", headers=worker["headers"])
        assert len(page.json()["data"]) == 2

    def test_update(self, client, worker) -> None:
        created = client.post("/workers/me/references", headers=worker["headers"], json=REFERENCE)
        reference_id = created.json()["data"]["id"]
        updated = client.patch(
            f"/workers/me/references/{reference_id}",
            headers=worker["headers"],
            json={"organization_name": "Mwangaza Construction (Nakuru)"},
        )
        assert updated.status_code == 200

    def test_delete_is_soft(self, client, worker) -> None:
        created = client.post("/workers/me/references", headers=worker["headers"], json=REFERENCE)
        reference_id = created.json()["data"]["id"]
        assert (
            client.delete(
                f"/workers/me/references/{reference_id}", headers=worker["headers"]
            ).status_code
            == 200
        )
        assert (
            client.get(
                f"/workers/me/references/{reference_id}", headers=worker["headers"]
            ).status_code
            == 404
        )

    def test_an_unknown_relationship_is_rejected(self, client, worker) -> None:
        response = client.post(
            "/workers/me/references",
            headers=worker["headers"],
            json={**REFERENCE, "relationship_type": "BEST_FRIEND"},
        )
        assert response.status_code == 422

    def test_a_reference_is_not_a_verification(self, client, worker) -> None:
        """Naming a referee must not produce a verification or a verified badge."""
        created = client.post("/workers/me/references", headers=worker["headers"], json=REFERENCE)
        assert created.status_code == 201
        for field in ("verification_status", "is_verified", "verified_at", "verification_id"):
            assert field not in created.json()["data"]

    def test_another_worker_cannot_read_the_referees_contact_details(
        self, client, worker, other
    ) -> None:
        """The owner records a referee's address to invite them. Nobody else sees it."""
        client.post("/workers/me/references", headers=worker["headers"], json=REFERENCE)
        assert client.get("/workers/me/references", headers=other["headers"]).json()["data"] == []
        assert (
            "joseph.kamau@example.com"
            not in client.get("/workers/me/references", headers=other["headers"]).text
        )

    def test_an_anonymous_caller_cannot_read_references(self, client, worker) -> None:
        client.post("/workers/me/references", headers=worker["headers"], json=REFERENCE)
        assert client.get("/workers/me/references").status_code == 401
        assert "joseph.kamau@example.com" not in client.get("/workers/me/references").text


class TestCrossWorkerIsolation:
    """Worker A must not reach Worker B's trust records."""

    @pytest.fixture
    def credential_id(self, client, worker):
        return client.post(
            "/workers/me/credentials", headers=worker["headers"], json=CREDENTIAL
        ).json()["data"]["id"]

    @pytest.fixture
    def reference_id(self, client, worker):
        return client.post(
            "/workers/me/references", headers=worker["headers"], json=REFERENCE
        ).json()["data"]["id"]

    def test_another_worker_cannot_read_a_credential(self, client, other, credential_id) -> None:
        assert (
            client.get(
                f"/workers/me/credentials/{credential_id}", headers=other["headers"]
            ).status_code
            == 404
        )

    def test_another_worker_cannot_update_a_credential(
        self, client, worker, other, credential_id
    ) -> None:
        response = client.patch(
            f"/workers/me/credentials/{credential_id}",
            headers=other["headers"],
            json={"title": "Hijacked"},
        )
        assert response.status_code == 404
        owner = client.get(f"/workers/me/credentials/{credential_id}", headers=worker["headers"])
        assert owner.json()["data"]["title"] == "Trade Test Certificate"

    def test_another_worker_cannot_delete_a_credential(
        self, client, worker, other, credential_id
    ) -> None:
        assert (
            client.delete(
                f"/workers/me/credentials/{credential_id}", headers=other["headers"]
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/workers/me/credentials/{credential_id}", headers=worker["headers"]
            ).status_code
            == 200
        )

    def test_another_worker_cannot_read_a_reference(self, client, other, reference_id) -> None:
        assert (
            client.get(
                f"/workers/me/references/{reference_id}", headers=other["headers"]
            ).status_code
            == 404
        )

    def test_another_worker_cannot_update_a_reference(self, client, other, reference_id) -> None:
        assert (
            client.patch(
                f"/workers/me/references/{reference_id}",
                headers=other["headers"],
                json={"full_name": "Hijacked"},
            ).status_code
            == 404
        )

    def test_another_worker_cannot_delete_a_reference(self, client, other, reference_id) -> None:
        assert (
            client.delete(
                f"/workers/me/references/{reference_id}", headers=other["headers"]
            ).status_code
            == 404
        )

    def test_guessing_a_random_id_is_a_404(self, client, worker) -> None:
        for path in ("credentials", "references"):
            assert (
                client.get(
                    f"/workers/me/{path}/{uuid.uuid4()}", headers=worker["headers"]
                ).status_code
                == 404
            )

    def test_a_listing_shows_only_the_callers_own_records(
        self, client, other, credential_id
    ) -> None:
        listing = client.get("/workers/me/credentials", headers=other["headers"])
        assert listing.json()["data"] == []
        assert (
            credential_id
            not in client.get("/workers/me/credentials", headers=other["headers"]).text
        )
