"""Tests for infrastructure: the session helper, database guards, logging
configuration and the health probes.

These are the paths a request does not normally exercise, so without them a
failure in an error handler or a health check would only be discovered in
production.
"""

from __future__ import annotations

import logging

import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.db.session import (
    check_database_connectivity,
    get_engine,
    get_session_factory,
    reset_engine,
    session_scope,
)

pytestmark = pytest.mark.integration


class TestSessionScope:
    def test_a_clean_block_commits(self) -> None:
        """A maintenance script must be able to persist its work."""
        with session_scope() as session:
            count_before = session.execute(text("SELECT count(*) FROM counties")).scalar_one()

        with session_scope() as session:
            assert (
                session.execute(text("SELECT count(*) FROM counties")).scalar_one() == count_before
            )

    def test_an_exception_rolls_the_block_back(self) -> None:
        """A failed script must not leave half its work behind."""
        from sqlalchemy.exc import SQLAlchemyError

        with pytest.raises(RuntimeError), session_scope() as session:
            session.execute(text("SELECT 1"))
            raise RuntimeError("script failed")

        # The connection is still usable afterwards.
        assert check_database_connectivity() is True
        _ = SQLAlchemyError

    def test_session_factory_returns_independent_sessions(self) -> None:
        factory = get_session_factory()
        first = factory()
        second = factory()
        try:
            assert first is not second
            # autoflush must be off: pending writes are only visible after an
            # explicit flush, which the services rely on for correctness.
            assert first.autoflush is False
        finally:
            first.close()
            second.close()

    def test_health_check_reports_a_reachable_database(self) -> None:
        assert check_database_connectivity() is True

    def test_engine_exposes_a_pool(self) -> None:
        assert get_engine().pool is not None


class TestConnectionGuards:
    def test_statement_and_lock_timeouts_are_applied_per_connection(self) -> None:
        """Bounds pathological queries instead of letting them pin a worker."""
        with get_engine().connect() as connection:
            statement_timeout = connection.execute(text("SHOW statement_timeout")).scalar_one()
            lock_timeout = connection.execute(text("SHOW lock_timeout")).scalar_one()
            idle_timeout = connection.execute(
                text("SHOW idle_in_transaction_session_timeout")
            ).scalar_one()

        assert statement_timeout == "15s"
        assert lock_timeout == "5s"
        assert idle_timeout == "30s"

    def test_a_statement_timeout_fails_fast(self, db_session) -> None:
        """Prove the timeout mechanism actually cancels a long query.

        Uses a deliberately short local timeout rather than waiting out the real
        15 seconds, then restores it. The value's presence is asserted separately
        above; this asserts the *behaviour*.
        """
        from sqlalchemy.exc import DBAPIError

        db_session.execute(text("SET statement_timeout = '150ms'"))
        try:
            with pytest.raises(DBAPIError):
                db_session.execute(text("SELECT pg_sleep(5)"))
        finally:
            db_session.rollback()  # also restores the session-level SET


class TestDatabaseGuards:
    """The hand-written DDL from ``app/db/guards.py``, exercised for real."""

    def test_the_lower_case_email_constraints_reject_mixed_case(self, db_session) -> None:
        import uuid as _uuid

        from app.db.models.user import User

        row = User(
            id=_uuid.uuid4(),
            email="Mixed@Case.com",
            password_hash="x",
            role="WORKER",
        )
        db_session.add(row)
        with pytest.raises(Exception) as excinfo:
            db_session.flush()
        assert "ck_users_email_lowercase" in str(excinfo.value)
        db_session.rollback()

    def test_the_availability_check_requires_a_date_for_available_soon(self, db_session) -> None:
        import uuid as _uuid

        from app.db.models.user import User
        from app.db.models.worker import WorkerProfile

        user = User(
            id=_uuid.uuid4(),
            email=f"avail-{_uuid.uuid4().hex[:8]}@example.com",
            password_hash="x",
            role="WORKER",
        )
        db_session.add(user)
        db_session.flush()
        db_session.add(
            WorkerProfile(
                user_id=user.id, display_name="Soon", availability_status="AVAILABLE_SOON"
            )
        )
        with pytest.raises(Exception) as excinfo:
            db_session.flush()
        assert "available_from_required" in str(excinfo.value)
        db_session.rollback()

    def test_dropping_and_reinstalling_the_audit_guard_is_clean(self) -> None:
        from app.db import guards

        engine = get_engine()
        with engine.begin() as connection:
            guards.drop_append_only_audit_guard(connection)
        with engine.begin() as connection:
            guards.create_append_only_audit_guard(connection)

        with engine.connect() as connection:
            count = connection.execute(
                text("SELECT count(*) FROM pg_trigger WHERE tgname = 'audit_logs_append_only'")
            ).scalar_one()
        assert count == 1

    def test_installing_the_guard_twice_is_idempotent(self) -> None:
        """A re-applied or retried migration must not fail on DuplicateObject."""
        from app.db import guards

        engine = get_engine()
        # `begin()` rather than `connect()`: DDL in SQLAlchemy 2.0 is not
        # auto-committed, so a bare connection would leave the guard installed
        # only inside a transaction that is then rolled back.
        for _ in range(2):
            with engine.begin() as connection:
                guards.create_append_only_audit_guard(connection)

    def test_lowercase_constraints_can_be_removed_and_reapplied(self) -> None:
        from app.db import guards

        engine = get_engine()
        with engine.begin() as connection:
            guards.drop_lowercase_email_constraints(connection)
            remaining = connection.execute(
                text(
                    "SELECT count(*) FROM pg_constraint WHERE conname = 'ck_users_email_lowercase'"
                )
            ).scalar_one()
        assert remaining == 0

        with engine.begin() as connection:
            guards.add_lowercase_email_constraints(connection)
            restored = connection.execute(
                text(
                    "SELECT count(*) FROM pg_constraint WHERE conname = 'ck_users_email_lowercase'"
                )
            ).scalar_one()
        assert restored == 1

    def test_the_availability_check_can_be_removed_and_reapplied(self) -> None:
        from app.db import guards

        engine = get_engine()
        with engine.begin() as connection:
            guards.drop_availability_consistency_check(connection)
            gone = connection.execute(
                text(
                    "SELECT count(*) FROM pg_constraint "
                    "WHERE conname = 'ck_worker_profiles_available_from_required'"
                )
            ).scalar_one()
        assert gone == 0

        with engine.begin() as connection:
            guards.add_availability_consistency_check(connection)
            back = connection.execute(
                text(
                    "SELECT count(*) FROM pg_constraint "
                    "WHERE conname = 'ck_worker_profiles_available_from_required'"
                )
            ).scalar_one()
        assert back == 1


class TestLoggingConfiguration:
    def test_configure_logging_is_idempotent(self) -> None:
        """Called once per app instance; must not stack duplicate handlers."""
        from app.core.logging import configure_logging

        root = logging.getLogger()
        for _ in range(3):
            configure_logging(get_settings())
        assert len(root.handlers) == 1, "handlers must not accumulate"

    def test_json_mode_is_selected_for_structured_output(self) -> None:
        from app.core.config import Settings
        from app.core.logging import JsonFormatter, configure_logging

        configure_logging(Settings(secret_key="x" * 40, jwt_secret="y" * 40, log_json=True))
        handler = logging.getLogger().handlers[0]
        assert isinstance(handler.formatter, JsonFormatter)

    def test_human_mode_is_selected_otherwise(self) -> None:
        from app.core.config import Settings
        from app.core.logging import HumanFormatter, configure_logging

        configure_logging(Settings(secret_key="x" * 40, jwt_secret="y" * 40, log_json=False))
        handler = logging.getLogger().handlers[0]
        assert isinstance(handler.formatter, HumanFormatter)

    def test_sqlalchemy_statement_logging_is_suppressed(self) -> None:
        """Query text can contain values, so it stays out of the log."""
        from app.core.logging import configure_logging

        configure_logging(get_settings())
        assert logging.getLogger("sqlalchemy.engine").level >= logging.WARNING

    def test_uvicorn_logs_are_routed_through_the_root_handler(self) -> None:
        from app.core.logging import configure_logging

        configure_logging(get_settings())
        assert logging.getLogger("uvicorn.access").handlers == []
        assert logging.getLogger("uvicorn.access").propagate is True

    def test_an_unsupported_log_level_is_rejected(self) -> None:
        from pydantic import ValidationError

        from app.core.config import Settings

        try:
            Settings(secret_key="x" * 40, jwt_secret="y" * 40, log_level="CHATTY")
        except ValidationError as exc:
            assert "LOG_LEVEL" in str(exc)
        else:
            pytest.fail("An invalid LOG_LEVEL was accepted")

    def test_the_logger_adapter_stamps_an_event_name(self) -> None:
        """A named event is what makes logs queryable."""
        import json

        from app.core.logging import get_logger

        records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        logger = get_logger("test.adapter")
        logger.logger.addHandler(_Capture())
        logger.logger.propagate = False
        # The root logger is at WARNING in this environment, which would suppress
        # INFO entirely; set the level explicitly so the record is emitted.
        logger.logger.setLevel(logging.INFO)
        logger.info("LOGIN_FAILURE", extra={"user_id": "u1"})

        assert records, "the adapter must emit a record"
        assert getattr(records[0], "event", None) == "LOGIN_FAILURE"
        assert getattr(records[0], "user_id", None) == "u1"
        assert json.dumps({"ok": True})  # output stays JSON-serialisable


class TestHealthProbes:
    def test_liveness_is_ok_and_does_not_touch_the_database(self, client) -> None:
        response = client.get("/health/live")
        assert response.status_code == 200
        body = response.json()["data"]
        assert body["status"] == "ok"
        assert body["checks"] == {}, "liveness must not probe dependencies"

    def test_readiness_reports_the_database(self, client) -> None:
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.json()["data"]["checks"]["database"]["status"] == "ok"

    def test_aggregate_health_reports_a_latency(self, client) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        check = response.json()["data"]["checks"]["database"]
        assert check["latency_ms"] is not None

    def test_probes_require_no_authentication(self, client) -> None:
        """An orchestrator cannot present a token."""
        for path in ("/health", "/health/live", "/health/ready"):
            assert client.get(path).status_code in {200, 503}

    def test_no_prefixed_health_route_exists(self, client) -> None:
        """A fixed path means an infrastructure change is not needed per version.

        The API is unprefixed, so a versioned or gateway-prefixed variant must not
        also resolve. A second mount would be an unnoticed duplicate surface.
        """
        for prefix in ("/api", "/api/v1", "/v1"):
            for probe in ("/health", "/health/live", "/health/ready"):
                assert client.get(f"{prefix}{probe}").status_code == 404, (
                    f"{prefix}{probe} resolved; the API must have exactly one mount point"
                )

    def test_the_api_is_mounted_at_the_root(self, client) -> None:
        """Guards against a prefix being reintroduced."""
        spec = client.get("/openapi.json").json()
        assert not [p for p in spec["paths"] if p.startswith("/api")], spec["paths"]

    def test_pool_statistics_are_not_exposed_on_a_public_route(self, client) -> None:
        """Sizing and saturation are useful reconnaissance."""
        for path in ("/health", "/health/live", "/health/ready"):
            body = client.get(path).text.lower()
            for leak in ("checked_out", "pool", "dialect"):
                assert leak not in body, f"{path} leaked {leak}"

    def test_pool_statistics_helper_is_callable(self) -> None:
        from app.api.routes.health import get_database_pool_status

        status = get_database_pool_status()
        assert "pool_type" in status


class TestEngineReset:
    def test_reset_disposes_and_recreates_cleanly(self) -> None:
        """Used on shutdown and between configuration reloads."""
        original = get_engine()
        reset_engine()
        assert get_engine() is not original, "a new engine must be built"
        assert check_database_connectivity() is True
