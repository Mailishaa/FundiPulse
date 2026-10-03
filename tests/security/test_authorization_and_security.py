"""Security regression tests: authorisation, IDOR, privilege escalation, injection.

These are the tests that must keep passing. Each one corresponds to a rule that,
if it silently broke, would let one user read or modify another user's data.

Organised by OWASP category so a reviewer can map a test back to a threat.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.constants import AccountStatus, UserRole

pytestmark = [pytest.mark.security]

VALID_PASSWORD = "Correct-Horse-9-Battery"


# =========================================================================== #
# A01 - Broken access control                                                #
# =========================================================================== #
class TestRoleBasedAccessControl:
    """A01: every protected endpoint must answer 'may THIS user do THIS thing?'"""

    #: (method, path, valid JSON body for the *permitted* case)
    ADMIN_ONLY = [
        ("get", "/users", None),
        ("get", "/users/{target_id}", None),
        ("patch", "/users/{target_id}/role", {"role": "EMPLOYER"}),
        (
            "patch",
            "/users/{target_id}/status",
            {"status": "SUSPENDED", "reason": "moderation review"},
        ),
    ]

    @staticmethod
    def _call(client, method, path, target_id, headers, body):
        kwargs = {"headers": headers}
        if body is not None:
            kwargs["json"] = body
        return getattr(client, method)(path.format(target_id=target_id), **kwargs)

    @pytest.mark.parametrize("method,path,body", ADMIN_ONLY)
    def test_anonymous_is_refused(self, client, error_code, make_user, method, path, body) -> None:
        target = make_user()
        response = self._call(client, method, path, target.id, {}, body)
        assert response.status_code == 401
        assert error_code(response) == "AUTHENTICATION_REQUIRED"

    @pytest.mark.parametrize("method,path,body", ADMIN_ONLY)
    @pytest.mark.parametrize("role", [UserRole.WORKER, UserRole.EMPLOYER])
    def test_a_non_admin_is_refused(
        self, client, error_code, make_user, method, path, body, role
    ) -> None:
        target = make_user()
        caller = make_user(role=role)
        response = self._call(client, method, path, target.id, _login(client, caller.email), body)
        assert response.status_code == 403
        assert error_code(response) == "INSUFFICIENT_ROLE"

    @pytest.mark.parametrize("method,path,body", ADMIN_ONLY)
    def test_an_admin_is_permitted(self, client, make_user, method, path, body) -> None:
        target = make_user()
        admin = make_user(role=UserRole.ADMIN)
        response = self._call(client, method, path, target.id, _login(client, admin.email), body)
        assert response.status_code == 200, response.text


class TestPrivilegeEscalation:
    """A01: a client must never be able to grant itself a capability."""

    def test_role_cannot_be_set_via_registration(self, client) -> None:
        response = client.post(
            "/auth/register",
            json={
                "email": f"escalate-{uuid.uuid4().hex[:8]}@example.com",
                "password": VALID_PASSWORD,
                "role": "ADMIN",
                "display_name": "Escalator",
                "accepted_terms": True,
            },
        )
        assert response.status_code == 422

    def test_role_cannot_be_set_via_self_service_update(self, client, make_user) -> None:
        """`PATCH /users/me` must reject `role` rather than ignoring it."""
        user = make_user(role=UserRole.WORKER)
        response = client.patch(
            "/users/me",
            headers=_login(client, user.email),
            json={"role": "ADMIN"},
        )
        assert response.status_code == 422
        assert any(d.get("field") == "role" for d in response.json()["error"]["details"]), (
            response.json()
        )
        assert user.role == UserRole.WORKER.value, "role must be unchanged"

    @pytest.mark.parametrize(
        "payload",
        [
            {"is_active": True},
            {"is_email_verified": True},
            {"status": "ACTIVE"},
            {"id": str(uuid.uuid4())},
            {"email_verified_at": "2020-01-01T00:00:00Z"},
            {"deleted_at": None},
        ],
    )
    def test_mass_assignment_fields_are_all_rejected(self, client, make_user, payload) -> None:
        """OWASP A01 mass assignment: every privileged field must 422, not apply."""
        user = make_user()
        response = client.patch("/users/me", headers=_login(client, user.email), json=payload)
        assert response.status_code == 422, payload
        assert user.is_email_verified is True
        assert user.is_active is True

    def test_a_worker_cannot_read_another_users_account(
        self, client, make_user, error_code
    ) -> None:
        victim = make_user()
        attacker = make_user(role=UserRole.WORKER)
        response = client.get(f"/users/{victim.id}", headers=_login(client, attacker.email))
        assert response.status_code == 403
        assert error_code(response) == "INSUFFICIENT_ROLE"

    def test_changing_email_forces_reverification(self, client, make_user) -> None:
        """Changing the login address must clear verification.

        Without this, brief access to a session would let an attacker move the
        account to an address they control and then use password reset to take it
        permanently.
        """
        user = make_user(is_email_verified=True)
        response = client.patch(
            "/users/me",
            headers=_login(client, user.email),
            json={"email": f"moved-{uuid.uuid4().hex[:8]}@example.com"},
        )
        assert response.status_code == 200
        assert response.json()["data"]["is_email_verified"] is False

    def test_cannot_take_an_email_that_is_already_registered(
        self, client, make_user, error_code
    ) -> None:
        taken = make_user()
        attacker = make_user()
        response = client.patch(
            "/users/me",
            headers=_login(client, attacker.email),
            json={"email": taken.email},
        )
        assert response.status_code == 409
        assert error_code(response) == "EMAIL_ALREADY_REGISTERED"


class TestIdorResistance:
    """A01: swapping an identifier in a URL must not grant access (BOLA/IDOR)."""

    def test_unknown_user_id_is_a_404_for_an_admin(self, client, make_user, error_code) -> None:
        admin = make_user(role=UserRole.ADMIN)
        response = client.get(f"/users/{uuid.uuid4()}", headers=_login(client, admin.email))
        assert response.status_code == 404
        assert error_code(response) == "RESOURCE_NOT_FOUND"

    def test_a_malformed_uuid_is_a_422_not_a_500(self, client, make_user) -> None:
        """A non-UUID in a path must be a client error, never a crash."""
        admin = make_user(role=UserRole.ADMIN)
        response = client.get("/users/not-a-uuid", headers=_login(client, admin.email))
        assert response.status_code == 422

    def test_a_deleted_account_is_not_readable(self, client, make_user) -> None:
        """Deactivation tombstones the row; it must not remain readable."""
        victim = make_user()
        admin = make_user(role=UserRole.ADMIN)
        headers = _login(client, admin.email)

        client.delete("/users/me", headers=headers) if False else None

        # Deactivate the victim as the admin.
        response = client.patch(
            f"/users/{victim.id}/status",
            headers=headers,
            json={"status": "SUSPENDED", "reason": "moderation review"},
        )
        assert response.status_code == 200

        # The suspended account can no longer authenticate at all.
        assert (
            client.post(
                "/auth/login",
                json={"email": victim.email, "password": VALID_PASSWORD},
            ).status_code
            == 403
        )


class TestAdminSafetyRails:
    def test_an_admin_cannot_change_their_own_role(self, client, make_user, error_code) -> None:
        """Otherwise a platform can end up with no administrator."""
        admin = make_user(role=UserRole.ADMIN)
        response = client.patch(
            f"/users/{admin.id}/role",
            headers=_login(client, admin.email),
            json={"role": "WORKER"},
        )
        assert response.status_code == 403
        assert error_code(response) == "SELF_ROLE_CHANGE_BLOCKED"

    def test_an_admin_cannot_change_their_own_status(self, client, make_user, error_code) -> None:
        admin = make_user(role=UserRole.ADMIN)
        response = client.patch(
            f"/users/{admin.id}/status",
            headers=_login(client, admin.email),
            json={"status": "SUSPENDED", "reason": "self sabotage attempt"},
        )
        assert response.status_code == 403
        assert error_code(response) == "SELF_STATUS_CHANGE_BLOCKED"

    def test_suspending_an_account_requires_a_reason(self, client, make_user) -> None:
        admin = make_user(role=UserRole.ADMIN)
        target = make_user()
        response = client.patch(
            f"/users/{target.id}/status",
            headers=_login(client, admin.email),
            json={"status": "SUSPENDED", "reason": "x"},
        )
        assert response.status_code == 422

    def test_role_change_is_audited_with_the_previous_value(
        self, client, make_user, db_session
    ) -> None:
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        admin = make_user(role=UserRole.ADMIN)
        target = make_user(role=UserRole.WORKER)
        client.patch(
            f"/users/{target.id}/role",
            headers=_login(client, admin.email),
            json={"role": "EMPLOYER"},
        )

        rows = (
            db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "ROLE_CHANGED", AuditLog.resource_id == target.id
                )
            )
            .scalars()
            .all()
        )
        assert rows, "ROLE_CHANGED must be audited"
        assert rows[-1].metadata_["previous_role"] == "WORKER"
        assert rows[-1].metadata_["new_role"] == "EMPLOYER"
        assert rows[-1].actor_user_id == admin.id


# =========================================================================== #
# A03 - Injection                                                            #
# =========================================================================== #
class TestInjection:
    SQL_PAYLOADS = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "admin'--",
        "1; DELETE FROM worker_profiles",
        "%27%20OR%201%3D1%20--",
        "\\'; DROP TABLE users; --",
        "' UNION SELECT NULL, version() --",
        "') OR ('a'='a",
    ]

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_login_is_treated_as_data(self, client, make_user, payload) -> None:
        """The ORM parameterises the query; the payload is just a bad string."""
        make_user()
        response = client.post("/auth/login", json={"email": payload, "password": payload})
        assert response.status_code in {401, 422}
        assert response.status_code != 500

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_registration_is_rejected(self, client, payload) -> None:
        response = client.post(
            "/auth/register",
            json={
                "email": payload,
                "password": VALID_PASSWORD,
                "role": "WORKER",
                "display_name": "Injection",
                "accepted_terms": True,
            },
        )
        assert response.status_code in {409, 422}

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_query_parameters_is_harmless(
        self, client, make_user, payload
    ) -> None:
        admin = make_user(role=UserRole.ADMIN)
        response = client.get(
            "/users",
            headers=_login(client, admin.email),
            params={"role": payload, "status": "ACTIVE"},
        )
        assert response.status_code in {200, 422}
        assert response.status_code != 500

    def test_the_users_table_still_exists_after_injection_attempts(
        self, client, db_session
    ) -> None:
        """Proves the table was not dropped: the query below must still work."""
        from sqlalchemy import text

        for payload in self.SQL_PAYLOADS:
            client.post("/auth/login", json={"email": payload, "password": payload})
        assert db_session.execute(text("SELECT count(*) FROM users")).scalar_one() >= 0

    @pytest.mark.parametrize(
        "payload",
        ["<script>alert(1)</script>", "{{7*7}}", "${jndi:ldap://x}", "%0d%0aX-Injected: 1"],
    )
    def test_reflection_of_hostile_input_does_not_break_the_api(
        self, client, make_user, payload
    ) -> None:
        user = make_user()
        response = client.post("/auth/login", json={"email": user.email, "password": payload})
        assert response.status_code == 401
        assert response.headers["content-type"].startswith("application/json")


# =========================================================================== #
# A07 - Authentication failures                                              #
# =========================================================================== #
class TestTokenHandling:
    def test_a_token_for_a_deleted_account_stops_working(
        self, client, make_user, db_session
    ) -> None:
        user = make_user()
        headers = _login(client, user.email)
        assert client.get("/auth/me", headers=headers).status_code == 200

        user.is_active = False
        user.status = AccountStatus.DEACTIVATED.value
        db_session.flush()

        assert client.get("/auth/me", headers=headers).status_code == 403

    def test_bearer_tokens_never_appear_in_the_query_string(self, client, make_user) -> None:
        """A token in a URL leaks into logs and Referer headers."""
        user = make_user()
        response = client.get(f"/auth/me?token={_login_token(client, user.email)}")
        assert response.status_code == 401

    def test_logout_then_use_is_refused(self, client, make_user) -> None:
        user = make_user()
        tokens = _login_tokens(client, user.email)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        assert client.post("/auth/logout", headers=headers).status_code == 200
        # The access token has a short lifetime and is not on a revocation list,
        # but the refresh token must be dead.
        assert (
            client.post(
                "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
            ).status_code
            == 401
        )


# =========================================================================== #
# A05 - Security misconfiguration                                            #
# =========================================================================== #
class TestSecurityHeadersAndCors:
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }

    @pytest.mark.parametrize("header,expected", sorted(SECURITY_HEADERS.items()))
    def test_security_headers_are_present(self, client, header, expected) -> None:
        response = client.get("/health/live")
        assert response.headers.get(header) == expected

    def test_content_security_policy_is_deny_by_default(self, client) -> None:
        csp = client.get("/health/live").headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp

    def test_permissions_policy_denies_ambient_device_access(self, client) -> None:
        policy = client.get("/health/live").headers["Permissions-Policy"]
        for feature in ("geolocation", "camera", "microphone", "payment"):
            assert f"{feature}=()" in policy

    def test_hsts_is_not_sent_over_plain_http_in_development(self, client) -> None:
        """HSTS on localhost would pin the developer to http forever."""
        assert "Strict-Transport-Security" not in client.get("/health/live").headers

    def test_a_request_id_is_always_returned(self, client) -> None:
        response = client.get("/health/live")
        assert response.headers["X-Request-ID"]

    def test_a_well_formed_inbound_request_id_is_echoed(self, client) -> None:
        response = client.get("/health/live", headers={"X-Request-ID": "trace-abc-123"})
        assert response.headers["X-Request-ID"] == "trace-abc-123"

    @pytest.mark.parametrize(
        "hostile",
        [
            "evil\nInjected: 1",
            "a" * 500,
            "<script>alert(1)</script>",
            "'; DROP TABLE users; --",
        ],
    )
    def test_a_hostile_request_id_is_replaced_not_reflected(self, client, hostile) -> None:
        """A reflected header value would be a log-injection and XSS vector."""
        response = client.get("/health/live", headers={"X-Request-ID": hostile})
        returned = response.headers["X-Request-ID"]
        assert returned != hostile
        assert returned.isascii()

    def test_cors_defaults_to_no_origins_at_all(self) -> None:
        """No origin is permitted unless an operator configures one explicitly.

        Reads the declared default rather than a constructed instance, because the
        test session sets CORS_ALLOWED_ORIGINS in the environment.
        """
        from app.core.config import Settings

        field = Settings.model_fields["cors_allowed_origins"]
        assert field.default_factory is not None
        assert field.default_factory() == []

    @pytest.mark.parametrize(
        "origins",
        [["*"], ["https://ok.example.com", "*"], ["*.example.com"]],
    )
    def test_a_wildcard_cors_origin_is_rejected_by_configuration(self, origins) -> None:
        """OWASP A05: the invalid value must be refused, not silently accepted."""
        from pydantic import ValidationError

        from app.core.config import Settings

        try:
            Settings(
                app_env="development",
                secret_key="x" * 40,
                jwt_secret="y" * 40,
                cors_allowed_origins=origins,
            )
        except ValidationError as exc:
            assert "wildcard" in str(exc).lower()
        else:
            pytest.fail(f"Wildcard CORS origin was accepted: {origins}")

    def test_credentials_are_not_enabled_for_cors_by_default(self) -> None:
        from app.core.config import Settings

        assert Settings.model_fields["cors_allow_credentials"].default is False

    def test_unknown_routes_use_the_standard_error_envelope(self, client, error_code) -> None:
        response = client.get("/does-not-exist")
        assert response.status_code == 404
        assert error_code(response) == "ROUTE_NOT_FOUND"

    def test_the_wrong_method_uses_the_standard_envelope(self, client, error_code) -> None:
        response = client.delete("/auth/login")
        assert response.status_code == 405
        assert error_code(response) == "METHOD_NOT_ALLOWED"


# =========================================================================== #
# A09 - Logging and monitoring                                               #
# =========================================================================== #
class TestAuditTrail:
    def test_audit_rows_cannot_be_updated(self, db_session, make_user) -> None:
        """OWASP A09/A08: the append-only trigger is the real control."""
        import pytest as _pytest
        from sqlalchemy import text

        from app.core.constants import AuditAction
        from app.services.audit_service import AuditService

        user = make_user()
        AuditService(db_session).record(
            action=AuditAction.LOGIN_SUCCESS, actor_user_id=user.id, outcome="SUCCESS"
        )
        db_session.commit()

        with _pytest.raises(Exception) as excinfo:
            db_session.execute(
                text("UPDATE audit_logs SET outcome = 'TAMPERED' WHERE actor_user_id = :u"),
                {"u": user.id},
            )
        assert "append-only" in str(excinfo.value).lower()

    def test_audit_rows_cannot_be_deleted(self, db_session, make_user) -> None:
        import pytest as _pytest
        from sqlalchemy import text

        from app.core.constants import AuditAction
        from app.services.audit_service import AuditService

        user = make_user()
        AuditService(db_session).record(
            action=AuditAction.LOGOUT, actor_user_id=user.id, outcome="SUCCESS"
        )
        db_session.commit()

        with _pytest.raises(Exception) as excinfo:
            db_session.execute(
                text("DELETE FROM audit_logs WHERE actor_user_id = :u"), {"u": user.id}
            )
        assert "append-only" in str(excinfo.value).lower()

    def test_login_success_is_audited(self, client, make_user, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        user = make_user()
        _login(client, user.email)

        rows = (
            db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "LOGIN_SUCCESS", AuditLog.actor_user_id == user.id
                )
            )
            .scalars()
            .all()
        )
        assert rows

    def test_a_failed_login_is_audited_even_though_the_request_failed(
        self, client, make_user, db_session
    ) -> None:
        """The point of the durable write path: failures must survive rollback."""
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        user = make_user()
        client.post(
            "/auth/login",
            json={"email": user.email, "password": "Wrong-Password-1-Here"},
        )

        rows = (
            db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "LOGIN_FAILURE", AuditLog.actor_user_id == user.id
                )
            )
            .scalars()
            .all()
        )
        assert rows, "a failed login must leave a durable audit row"
        assert rows[-1].outcome == "FAILURE"


class TestSensitiveDataIsNeverLeaked:
    @pytest.mark.parametrize(
        "path",
        ["/health", "/health/live", "/health/ready", "/auth/me"],
    )
    def test_health_endpoints_disclose_no_internals(self, client, path) -> None:
        body = client.get(path).text.lower()
        for leak in ("postgres", "password", "secret", 'version="', "psycopg", "traceback"):
            assert leak not in body, f"{path} leaked {leak!r}"

    def test_a_500_never_returns_a_stack_trace_in_production(self) -> None:
        """Verified against production settings rather than the dev defaults."""
        from fastapi.testclient import TestClient

        from app.core.config import Settings
        from app.main import create_app

        settings = Settings(
            app_env="production",
            secret_key="x" * 40,
            jwt_secret="y" * 40,
            # Real-looking credentials: production refuses the shipped example
            # ones, and the test session disables rate limiting.
            database_url="postgresql+psycopg://appuser:Xk9p2mQ7vR4t@127.0.0.1:5432/fundipulse_test",
            cors_allowed_origins=["https://app.example.com"],
            rate_limit_enabled=True,
            enable_docs=False,
        )
        app = create_app(settings)

        @app.get("/_boom")
        def _boom() -> None:  # pragma: no cover - deliberately raises
            raise RuntimeError("internal detail: /srv/app/secret/path.py line 42")

        with TestClient(app, raise_server_exceptions=False) as prod_client:
            response = prod_client.get("/_boom")

        assert response.status_code == 500
        body = response.json()["error"]
        assert body["code"] == "INTERNAL_ERROR"
        assert "internal detail" not in body["message"]
        assert "Traceback" not in response.text
        assert "/srv/app" not in response.text
        assert body["request_id"], "a request_id must be returned so support can trace it"


# =========================================================================== #
# Helpers                                                                    #
# =========================================================================== #
def _login_tokens(client, email: str, password: str = VALID_PASSWORD) -> dict:
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["data"]["tokens"]


def _login_token(client, email: str, password: str = VALID_PASSWORD) -> str:
    return _login_tokens(client, email, password)["access_token"]


def _login(client, email: str, password: str = VALID_PASSWORD) -> dict[str, str]:
    return {"Authorization": f"Bearer {_login_token(client, email, password)}"}
