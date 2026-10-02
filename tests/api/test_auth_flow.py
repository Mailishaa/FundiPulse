"""End-to-end tests for the authentication flow, through real HTTP.

These run against the real PostgreSQL test database with real Argon2 hashing and
real signed JWTs. Nothing is mocked: a failure here means the flow is broken,
not that a test double drifted.
"""

from __future__ import annotations

import uuid

import pytest

pytestmark = [pytest.mark.api, pytest.mark.integration]

VALID_PASSWORD = "Correct-Horse-9-Battery"
OTHER_PASSWORD = "Different-Mule-7-Ridge"


def _register(client, **overrides) -> dict:
    payload = {
        "email": f"user-{uuid.uuid4().hex[:10]}@example.com",
        "password": VALID_PASSWORD,
        "role": "WORKER",
        "display_name": "Test Worker",
        "accepted_terms": True,
    }
    payload.update(overrides)
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


# --------------------------------------------------------------------------- #
# Registration                                                                #
# --------------------------------------------------------------------------- #
class TestRegistration:
    def test_creates_an_account_and_returns_a_token_pair(self, client) -> None:
        body = _register(client)

        assert body["data"]["user"]["role"] == "WORKER"
        assert body["data"]["user"]["is_email_verified"] is False
        assert body["data"]["tokens"]["token_type"] == "Bearer"
        assert body["data"]["tokens"]["access_token"]
        assert body["data"]["tokens"]["refresh_token"]
        assert body["meta"]["request_id"]

    def test_never_returns_the_password_hash(self, client) -> None:
        body = _register(client)
        assert "password_hash" not in str(body)
        assert VALID_PASSWORD not in str(body)

    def test_lower_cases_the_email(self, client) -> None:
        body = _register(client, email=f"Mixed-{uuid.uuid4().hex[:6]}@Example.COM")
        assert body["data"]["user"]["email"].startswith("mixed-")

    def test_rejects_a_duplicate_address(self, client, error_code) -> None:
        address = f"dup-{uuid.uuid4().hex[:10]}@example.com"
        _register(client, email=address)

        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": address,
                "password": VALID_PASSWORD,
                "role": "WORKER",
                "display_name": "Duplicate",
                "accepted_terms": True,
            },
        )
        assert response.status_code == 409
        assert error_code(response) == "EMAIL_ALREADY_REGISTERED"

    def test_duplicate_registration_is_case_insensitive(self, client, error_code) -> None:
        """The unique index is on the normalised value, so case must not matter."""
        address = f"case-{uuid.uuid4().hex[:10]}@example.com"
        _register(client, email=address)

        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": address.upper(),
                "password": VALID_PASSWORD,
                "role": "WORKER",
                "display_name": "Duplicate",
                "accepted_terms": True,
            },
        )
        assert response.status_code == 409
        assert error_code(response) == "EMAIL_ALREADY_REGISTERED"

    @pytest.mark.parametrize(
        "password",
        ["short1", "password123", "abc"],
    )
    def test_rejects_a_weak_password(self, client, password) -> None:
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": f"weak-{uuid.uuid4().hex[:10]}@example.com",
                "password": password,
                "role": "WORKER",
                "display_name": "Weak",
                "accepted_terms": True,
            },
        )
        assert response.status_code == 422
        body = response.json()
        assert body["error"]["code"] == "VALIDATION_FAILED"
        assert any("password" in str(d.get("field", "")) for d in body["error"]["details"])

    def test_refuses_self_registration_as_admin(self, client, error_code) -> None:
        """A client must not be able to mint itself an administrator."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": f"sneaky-{uuid.uuid4().hex[:10]}@example.com",
                "password": VALID_PASSWORD,
                "role": "ADMIN",
                "display_name": "Sneaky",
                "accepted_terms": True,
            },
        )
        assert response.status_code == 422
        details = response.json()["error"]["details"]
        assert any("dministrator" in str(d.get("message", "")) for d in details), details

    def test_mass_assignment_via_role_is_rejected(self, client) -> None:
        """OWASP A01: an unexpected privilege field must not be silently ignored."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": f"mass-{uuid.uuid4().hex[:10]}@example.com",
                "password": VALID_PASSWORD,
                "role": "WORKER",
                "display_name": "Mass",
                "accepted_terms": True,
                "is_active": True,
                "is_email_verified": True,
                "id": str(uuid.uuid4()),
            },
        )
        assert response.status_code == 422
        body = response.json()
        fields = {d.get("field") for d in body["error"]["details"]}
        assert {"is_active", "is_email_verified", "id"} & fields, fields

    def test_requires_terms_acceptance(self, client) -> None:
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": f"terms-{uuid.uuid4().hex[:10]}@example.com",
                "password": VALID_PASSWORD,
                "role": "WORKER",
                "display_name": "No Terms",
                "accepted_terms": False,
            },
        )
        assert response.status_code == 422

    def test_rejects_a_malformed_email(self, client) -> None:
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "not-an-email",
                "password": VALID_PASSWORD,
                "role": "WORKER",
                "display_name": "Bad Email",
                "accepted_terms": True,
            },
        )
        assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Login                                                                       #
# --------------------------------------------------------------------------- #
class TestLogin:
    def test_returns_a_token_pair_for_valid_credentials(self, client, make_user) -> None:
        user = make_user(email=f"login-{uuid.uuid4().hex[:10]}@example.com")
        response = client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": VALID_PASSWORD},
        )
        assert response.status_code == 200
        assert response.json()["data"]["user"]["id"] == str(user.id)

    def test_login_is_case_insensitive_on_the_address(self, client, make_user) -> None:
        user = make_user(email=f"case-{uuid.uuid4().hex[:10]}@example.com")
        response = client.post(
            "/api/v1/auth/login",
            json={"email": user.email.upper(), "password": VALID_PASSWORD},
        )
        assert response.status_code == 200

    def test_wrong_password_is_rejected(self, client, make_user, error_code) -> None:
        user = make_user()
        response = client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": OTHER_PASSWORD},
        )
        assert response.status_code == 401
        assert error_code(response) == "INVALID_CREDENTIALS"

    def test_unknown_account_gives_the_same_answer_as_a_wrong_password(
        self, client, make_user, error_code
    ) -> None:
        """OWASP A07: the two failures must be indistinguishable."""
        existing = make_user()
        wrong_password = client.post(
            "/api/v1/auth/login",
            json={"email": existing.email, "password": OTHER_PASSWORD},
        )
        unknown_account = client.post(
            "/api/v1/auth/login",
            json={
                "email": f"ghost-{uuid.uuid4().hex[:10]}@example.com",
                "password": OTHER_PASSWORD,
            },
        )

        assert wrong_password.status_code == unknown_account.status_code == 401
        assert error_code(wrong_password) == error_code(unknown_account)
        assert (
            wrong_password.json()["error"]["message"] == unknown_account.json()["error"]["message"]
        )

    def test_missing_password_is_a_422_not_a_401(self, client) -> None:
        response = client.post("/api/v1/auth/login", json={"email": "a@b.test"})
        assert response.status_code == 422

    def test_inactive_account_cannot_log_in(self, client, make_user, error_code) -> None:
        user = make_user(is_active=False)
        response = client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": VALID_PASSWORD},
        )
        assert response.status_code == 403
        assert error_code(response) == "ACCOUNT_DISABLED"

    def test_a_deactivated_account_cannot_log_in(self, client, make_user) -> None:
        from sqlalchemy import update

        from app.db.models.user import User

        user = make_user()
        # Simulate deactivation, which is exercised in detail in its own tests.
        user.is_active = False
        user.status = "DEACTIVATED"

        response = client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": VALID_PASSWORD},
        )
        assert response.status_code == 403
        _ = update, User

    def test_repeated_failures_lock_the_account(self, client, make_user, error_code) -> None:
        from app.core.config import get_settings

        settings = get_settings()
        user = make_user()

        for _ in range(settings.max_failed_login_attempts):
            client.post(
                "/api/v1/auth/login",
                json={"email": user.email, "password": OTHER_PASSWORD},
            )

        # The correct password now fails too, because the account is locked.
        response = client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": VALID_PASSWORD},
        )
        assert response.status_code == 423
        assert error_code(response) == "ACCOUNT_LOCKED"

    def test_a_successful_login_resets_the_failure_counter(self, client, make_user) -> None:
        user = make_user()
        client.post("/api/v1/auth/login", json={"email": user.email, "password": OTHER_PASSWORD})
        client.post("/api/v1/auth/login", json={"email": user.email, "password": OTHER_PASSWORD})
        client.post("/api/v1/auth/login", json={"email": user.email, "password": VALID_PASSWORD})
        assert user.failed_login_count == 0


# --------------------------------------------------------------------------- #
# Authenticated access                                                        #
# --------------------------------------------------------------------------- #
class TestAuthenticatedEndpoints:
    def test_me_returns_the_callers_account(self, client, make_user, auth_headers) -> None:
        user = make_user()
        response = client.get("/api/v1/auth/me", headers=auth_headers(user))
        assert response.status_code == 200
        assert response.json()["data"]["id"] == str(user.id)

    def test_me_requires_a_token(self, client, error_code) -> None:
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401
        assert error_code(response) == "AUTHENTICATION_REQUIRED"

    @pytest.mark.parametrize(
        "header",
        [
            {"Authorization": "Bearer not-a-real-token"},
            {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."},
            {"Authorization": "Basic dXNlcjpwYXNz"},
            {"Authorization": "Bearer "},
        ],
    )
    def test_rejects_malformed_authorization(self, client, header, error_code) -> None:
        response = client.get("/api/v1/auth/me", headers=header)
        assert response.status_code == 401
        assert error_code(response) in {"AUTHENTICATION_REQUIRED", "INVALID_TOKEN"}

    def test_rejects_a_token_signed_with_the_wrong_secret(self, client, make_user) -> None:
        from app.core.security import TokenService

        foreign = TokenService.__new__(TokenService)
        foreign._settings = type(
            "S",
            (),
            {
                "jwt_secret": type(
                    "X", (), {"get_secret_value": staticmethod(lambda: "wrong" * 10)}
                )(),
                "jwt_algorithm": "HS256",
                "jwt_issuer": "fundipulse",
                "jwt_audience": "fundipulse-api",
                "access_token_expire_minutes": 15,
            },
        )()
        forged = foreign.create_access_token(subject=make_user().id, role="ADMIN")

        response = client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {forged.token}"}
        )
        assert response.status_code == 401

    def test_a_suspended_user_loses_access_immediately(
        self, client, make_user, auth_headers
    ) -> None:
        """A valid JWT must not outlive the account state it was issued under."""
        user = make_user()
        headers = auth_headers(user)
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

        user.is_active = False
        user.status = "SUSPENDED"

        response = client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == 403


# --------------------------------------------------------------------------- #
# Refresh rotation and reuse detection                                       #
# --------------------------------------------------------------------------- #
class TestTokenRotation:
    def _login(self, client, make_user) -> tuple[object, dict]:
        user = make_user()
        response = client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": VALID_PASSWORD},
        )
        assert response.status_code == 200
        return user, response.json()["data"]["tokens"]

    def test_refresh_returns_a_new_pair(self, client, make_user) -> None:
        _, tokens = self._login(client, make_user)
        response = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert response.status_code == 200
        new_tokens = response.json()["data"]
        assert new_tokens["access_token"] != tokens["access_token"]
        assert new_tokens["refresh_token"] != tokens["refresh_token"]

    def test_the_new_access_token_works(self, client, make_user) -> None:
        _, tokens = self._login(client, make_user)
        refreshed = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        ).json()["data"]

        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {refreshed['access_token']}"},
        )
        assert response.status_code == 200

    def test_reusing_a_rotated_token_revokes_the_whole_family(
        self, client, make_user, error_code, db_session
    ) -> None:
        """The critical case: a captured refresh token must be detectable."""
        from sqlalchemy import select

        from app.db.models.user import RefreshSession

        user, tokens = self._login(client, make_user)

        # Legitimate rotation.
        rotated = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        ).json()["data"]

        # Attacker replays the now-replaced token.
        replay = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert replay.status_code == 401
        assert error_code(replay) == "INVALID_TOKEN"

        # The legitimate holder is signed out too, because one of them is the
        # attacker. This is intentional.
        after = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": rotated["refresh_token"]}
        )
        assert after.status_code == 401

        live = (
            db_session.execute(
                select(RefreshSession).where(
                    RefreshSession.user_id == user.id,
                    RefreshSession.revoked_at.is_(None),
                )
            )
            .scalars()
            .all()
        )
        assert live == [], "every session in the family should be revoked"

    def test_reuse_is_audited(self, client, make_user, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        user, tokens = self._login(client, make_user)
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})

        rows = (
            db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "TOKEN_REUSE_DETECTED",
                    AuditLog.actor_user_id == user.id,
                )
            )
            .scalars()
            .all()
        )
        assert rows, "TOKEN_REUSE_DETECTED must be recorded"
        # A failure audit must survive the rollback of the request that raised.
        assert rows[-1].outcome == "DENIED"

    def test_an_unknown_refresh_token_is_rejected(self, client, error_code) -> None:
        response = client.post("/api/v1/auth/refresh", json={"refresh_token": "x" * 40})
        assert response.status_code == 401
        assert error_code(response) == "INVALID_TOKEN"

    def test_the_refresh_token_is_not_stored_in_the_clear(
        self, client, make_user, db_session
    ) -> None:
        from sqlalchemy import select

        from app.db.models.user import RefreshSession

        _, tokens = self._login(client, make_user)
        rows = db_session.execute(select(RefreshSession)).scalars().all()
        assert rows
        for row in rows:
            assert tokens["refresh_token"] not in row.token_hash
            assert row.token_hash != tokens["refresh_token"]


# --------------------------------------------------------------------------- #
# Logout                                                                      #
# --------------------------------------------------------------------------- #
class TestLogout:
    def test_revokes_the_current_session(self, client, make_user, auth_headers, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.user import RefreshSession

        user = make_user()
        response = client.post("/api/v1/auth/logout", headers=auth_headers(user))
        assert response.status_code == 200
        assert response.json()["data"]["sessions_revoked"] == 1

        live = (
            db_session.execute(
                select(RefreshSession).where(
                    RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None)
                )
            )
            .scalars()
            .all()
        )
        assert live == []

    def test_logout_everywhere_revokes_all_sessions(self, client, make_user, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.user import RefreshSession

        user = make_user()
        for _ in range(3):
            client.post(
                "/api/v1/auth/login",
                json={"email": user.email, "password": VALID_PASSWORD},
            )

        response = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": _login_header(client, user)},
            json={"all_sessions": True},
        )
        assert response.status_code == 200
        assert response.json()["data"]["sessions_revoked"] >= 3

        live = (
            db_session.execute(
                select(RefreshSession).where(
                    RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None)
                )
            )
            .scalars()
            .all()
        )
        assert live == []

    def test_the_refresh_token_stops_working_after_logout(self, client, make_user) -> None:
        user = make_user()
        tokens = client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": VALID_PASSWORD},
        ).json()["data"]["tokens"]

        client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )

        response = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert response.status_code == 401


def _login_header(client, user) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": VALID_PASSWORD},
    )
    return f"Bearer {response.json()['data']['tokens']['access_token']}"


# --------------------------------------------------------------------------- #
# Password change and reset                                                   #
# --------------------------------------------------------------------------- #
class TestPasswordChange:
    def test_changes_the_password(self, client, make_user, auth_headers) -> None:
        user = make_user()
        response = client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers(user),
            json={"current_password": VALID_PASSWORD, "new_password": OTHER_PASSWORD},
        )
        assert response.status_code == 200
        assert response.json()["data"]["reauthenticate"] is True

        # The new password works.
        assert (
            client.post(
                "/api/v1/auth/login",
                json={"email": user.email, "password": OTHER_PASSWORD},
            ).status_code
            == 200
        )

    def test_requires_the_correct_current_password(
        self, client, make_user, auth_headers, error_code
    ) -> None:
        user = make_user()
        response = client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers(user),
            json={"current_password": OTHER_PASSWORD, "new_password": "Yet-Another-3-Key"},
        )
        assert response.status_code == 401
        assert error_code(response) == "INVALID_CREDENTIALS"

    def test_rejects_reusing_the_current_password(self, client, make_user, auth_headers) -> None:
        user = make_user()
        response = client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers(user),
            json={"current_password": VALID_PASSWORD, "new_password": VALID_PASSWORD},
        )
        assert response.status_code == 422

    def test_enforces_the_password_policy(self, client, make_user, auth_headers) -> None:
        user = make_user()
        response = client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers(user),
            json={"current_password": VALID_PASSWORD, "new_password": "weak"},
        )
        assert response.status_code == 422

    def test_revokes_every_including_the_current_session(
        self, client, make_user, db_session
    ) -> None:
        """A stolen refresh token must not survive a password change."""
        from sqlalchemy import select

        from app.db.models.user import RefreshSession

        user = make_user()
        for _ in range(2):
            client.post(
                "/api/v1/auth/login",
                json={"email": user.email, "password": VALID_PASSWORD},
            )

        client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": _login_header(client, user)},
            json={"current_password": VALID_PASSWORD, "new_password": OTHER_PASSWORD},
        )

        live = (
            db_session.execute(
                select(RefreshSession).where(
                    RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None)
                )
            )
            .scalars()
            .all()
        )
        assert live == []


class TestPasswordReset:
    def test_unknown_address_gets_the_same_answer_as_a_known_one(self, client, make_user) -> None:
        """OWASP A07: no account enumeration through the reset endpoint."""
        known = make_user()
        known_response = client.post("/api/v1/auth/forgot-password", json={"email": known.email})
        unknown_response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": f"nobody-{uuid.uuid4().hex[:10]}@example.com"},
        )

        assert known_response.status_code == unknown_response.status_code == 202
        assert (
            known_response.json()["error" if "error" in known_response.json() else "data"][
                "message"
            ]
            == (
                unknown_response.json()["error" if "error" in unknown_response.json() else "data"][
                    "message"
                ]
            )
        )

    def test_completing_the_reset_sets_a_new_password(self, client, make_user, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.user import SecurityToken
        from app.services.auth_service import AuthService

        user = make_user(email=f"reset-{uuid.uuid4().hex[:10]}@example.com")
        token = AuthService(db_session).request_password_reset(email=user.email)
        assert token

        response = client.post(
            "/api/v1/auth/reset-password",
            json={"token": token, "new_password": OTHER_PASSWORD},
        )
        assert response.status_code == 200

        assert (
            client.post(
                "/api/v1/auth/login",
                json={"email": user.email, "password": OTHER_PASSWORD},
            ).status_code
            == 200
        )

        # The token is consumed and cannot be replayed.
        row = db_session.execute(
            select(SecurityToken).where(SecurityToken.user_id == user.id)
        ).scalar_one()
        assert row.consumed_at is not None

    def test_a_reset_token_is_single_use(self, client, make_user, db_session, error_code) -> None:
        from app.services.auth_service import AuthService

        user = make_user()
        token = AuthService(db_session).request_password_reset(email=user.email)

        first = client.post(
            "/api/v1/auth/reset-password",
            json={"token": token, "new_password": OTHER_PASSWORD},
        )
        assert first.status_code == 200

        replay = client.post(
            "/api/v1/auth/reset-password",
            json={"token": token, "new_password": "Third-Password-4-Now"},
        )
        assert replay.status_code == 401
        assert error_code(replay) == "INVALID_TOKEN"

    def test_requesting_a_new_reset_invalidates_the_old_token(
        self, client, make_user, db_session
    ) -> None:
        """Only the most recently issued reset link may be used."""
        from app.services.auth_service import AuthService

        user = make_user()
        first_token = AuthService(db_session).request_password_reset(email=user.email)
        second_token = AuthService(db_session).request_password_reset(email=user.email)
        assert first_token != second_token

        stale = client.post(
            "/api/v1/auth/reset-password",
            json={"token": first_token, "new_password": OTHER_PASSWORD},
        )
        assert stale.status_code == 401

    def test_replaying_a_consumed_reset_token_revokes_the_remaining_one(
        self, client, make_user, db_session
    ) -> None:
        """Presenting an already-used token is treated as a possible compromise.

        Every outstanding token for that user is invalidated rather than only the
        replayed one. This is deliberately fail-secure: the cost is that a user who
        clicks an old email must request a fresh link, while the benefit is that a
        leaked token cannot be paired with a still-valid one.
        """
        from app.services.auth_service import AuthService

        user = make_user()
        used_token = AuthService(db_session).request_password_reset(email=user.email)
        latest_token = AuthService(db_session).request_password_reset(email=user.email)

        # The stale token is already consumed, so using it is a replay.
        replay = client.post(
            "/api/v1/auth/reset-password",
            json={"token": used_token, "new_password": OTHER_PASSWORD},
        )
        assert replay.status_code == 401

        after = client.post(
            "/api/v1/auth/reset-password",
            json={"token": latest_token, "new_password": OTHER_PASSWORD},
        )
        assert after.status_code == 401, "outstanding tokens must be revoked on replay"

    def test_a_reset_token_cannot_be_used_for_email_verification(
        self, client, make_user, db_session, error_code
    ) -> None:
        """OWASP A01: the two token purposes must not be interchangeable."""
        from app.services.auth_service import AuthService

        user = make_user(is_email_verified=False)
        token = AuthService(db_session).request_password_reset(email=user.email)

        response = client.post("/api/v1/auth/verify-email", json={"token": token})
        assert response.status_code == 401
        assert error_code(response) == "INVALID_TOKEN"

    def test_reset_revokes_existing_sessions(self, client, make_user, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.user import RefreshSession
        from app.services.auth_service import AuthService

        user = make_user()
        client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": VALID_PASSWORD},
        )
        token = AuthService(db_session).request_password_reset(email=user.email)
        client.post(
            "/api/v1/auth/reset-password",
            json={"token": token, "new_password": OTHER_PASSWORD},
        )

        live = (
            db_session.execute(
                select(RefreshSession).where(
                    RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None)
                )
            )
            .scalars()
            .all()
        )
        assert live == [], "a reset must evict sessions established with the old password"


# --------------------------------------------------------------------------- #
# Email verification                                                          #
# --------------------------------------------------------------------------- #
class TestEmailVerification:
    def test_verifies_the_address(self, client, db_session) -> None:
        from app.services.auth_service import AuthService

        user, verification_token, _ = AuthService(db_session).register(
            email=f"verify-{uuid.uuid4().hex[:10]}@example.com",
            password=VALID_PASSWORD,
            role="WORKER",
        )
        assert user.is_email_verified is False

        response = client.post("/api/v1/auth/verify-email", json={"token": verification_token})
        assert response.status_code == 200
        assert response.json()["data"]["is_email_verified"] is True

    def test_a_verification_token_is_single_use(self, client, db_session, error_code) -> None:
        from app.services.auth_service import AuthService

        _, token, _ = AuthService(db_session).register(
            email=f"once-{uuid.uuid4().hex[:10]}@example.com",
            password=VALID_PASSWORD,
            role="WORKER",
        )
        assert client.post("/api/v1/auth/verify-email", json={"token": token}).status_code == 200

        replay = client.post("/api/v1/auth/verify-email", json={"token": token})
        assert replay.status_code == 401
        assert error_code(replay) == "INVALID_TOKEN"

    def test_a_password_reset_token_cannot_verify_an_email(
        self, client, db_session, make_user, error_code
    ) -> None:
        from app.services.auth_service import AuthService

        user = make_user()
        reset_token = AuthService(db_session).request_password_reset(email=user.email)
        response = client.post("/api/v1/auth/verify-email", json={"token": reset_token})
        assert response.status_code == 401
        assert error_code(response) == "INVALID_TOKEN"
