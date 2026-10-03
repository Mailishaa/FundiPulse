"""Shared pytest fixtures.

Test environment design:

* **A dedicated database.** ``fundipulse_test``, pointed at by
  ``TEST_DATABASE_URL`` or derived from ``DATABASE_URL``. Production data is never
  at risk, and the suite refuses to run against a database whose name does not
  look like a test database.
* **Migrations, not ``create_all()``.** The schema is built by running Alembic at
  session start. That makes the suite prove the migrations work, which is the
  same code path production uses.
* **Function-scoped transaction rollback.** Each test runs inside a transaction
  that is rolled back afterwards, so tests cannot leak state into one another and
  the database does not need truncating between tests.
* **Cheap hashing.** Argon2 parameters are lowered so the suite is fast. The
  parameter is verified by a dedicated test so it cannot silently weaken
  production.
"""

from __future__ import annotations

from collections.abc import Generator
import os
from pathlib import Path
import uuid

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------- #
# Environment must be configured before any application import.               #
# --------------------------------------------------------------------------- #
# Set here rather than in a fixture: `app.core.config` caches Settings on first
# use, and an import can happen during collection.
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/fundipulse_test",
)
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-not-used-anywhere-0123456789")
os.environ.setdefault("JWT_SECRET", "test-only-jwt-secret-not-used-anywhere-012345678")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("LOG_LEVEL", "WARNING")
os.environ.setdefault("LOG_JSON", "false")
os.environ.setdefault("ENABLE_DOCS", "true")
os.environ.setdefault("CORS_ALLOWED_ORIGINS", "http://testserver.local")
# Deliberately non-production values so the suite is fast. `test_argon2_is_not_weaker_than_production`
# asserts the real defaults are still strong.
os.environ.setdefault("ARGON2_TIME_COST", "1")
os.environ.setdefault("ARGON2_MEMORY_COST", "8192")
os.environ.setdefault("ARGON2_PARALLELISM", "1")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("STORAGE_BACKEND", "memory")

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import Engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.constants import UserRole  # noqa: E402
from app.db.session import get_db, get_engine, reset_engine  # noqa: E402


# --------------------------------------------------------------------------- #
# Safety rails                                                                #
# --------------------------------------------------------------------------- #
def _assert_test_database(url: str) -> None:
    """Refuse to run destructive tests against anything but a test database.

    A typo in ``DATABASE_URL`` pointing at production would otherwise let the
    suite truncate real tables. The name must contain "test".
    """
    lowered = url.lower()
    if "test" not in lowered:
        pytest.exit(
            "REFUSING TO RUN: DATABASE_URL does not look like a test database.\n"
            f"  DATABASE_URL={url}\n"
            "The test suite manages schema and must never target a real database.",
            returncode=1,
        )


@pytest.fixture(scope="session", autouse=True)
def _verify_test_database() -> None:
    _assert_test_database(get_settings().database_url)


@pytest.fixture(scope="session", autouse=True)
def _migrated_database() -> Generator[None, None, None]:
    """Bring the test database to head once per session using Alembic."""
    _assert_test_database(get_settings().database_url)
    settings = get_settings()

    alembic_cfg = Config(str(REPO_ROOT / "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    alembic_cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))

    command.upgrade(alembic_cfg, "head")

    yield

    # Dispose pooled connections before the session ends so the engine does not
    # keep the transaction-then-rollback machinery alive.
    reset_engine()


@pytest.fixture
def engine() -> Generator[Engine, None, None]:
    yield get_engine()


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """A session whose every write is discarded at the end of the test.

    Two layers, because one is not enough:

    1. The connection opens an explicit transaction that is rolled back in the
       teardown. Nothing a test writes can survive.
    2. The session joins that transaction in ``create_savepoint`` mode, so a
       ``commit()`` *inside* a test releases a savepoint instead of committing.

    Layer 2 is what makes isolation actually hold. ``AuditService.record_durable``
    commits on the caller's session by design - a failure event must outlive the
    rollback of the effect it describes. With an ordinary session that commit
    escapes the test boundary and takes any uncommitted fixture rows with it, so
    ``LOGIN_FAILURE``, ``TOKEN_REUSE_DETECTED`` and ``ACCOUNT_DISABLED`` tests
    leaked rows into the shared test database on every run.

    A savepoint on the same connection keeps the durable write real - it is
    visible to the rest of the test - while still being undone at teardown. A
    second connection would not work: the row it wrote would reference a user the
    first connection has not committed yet, so its own foreign key would fail.
    """
    connection = get_engine().connect()
    outer = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        if outer.is_active:
            outer.rollback()
        connection.close()


@pytest.fixture
def app():
    """A fresh application instance.

    Created per test so middleware and router state cannot leak between tests.
    """
    from app.main import create_app

    settings = get_settings()
    application = create_app(settings)
    return application


@pytest.fixture
def client(app, db_session: Session) -> Generator[TestClient, None, None]:
    """A TestClient whose requests share the test's database session.

    Overriding ``get_db`` is what makes fixtures and HTTP calls see the same data.
    Without it, a user created through ``db_session`` would be uncommitted on one
    connection and therefore invisible to the request handler's separate session,
    and every test mixing fixtures with HTTP would fail for a reason that has
    nothing to do with the code under test.

    The outer transaction is rolled back at the end of the test, so nothing
    survives regardless of what the request did.
    """

    def _override_get_db() -> Generator[Session, None, None]:
        # Flush at the request boundary, mirroring the commit that the real
        # `get_db` performs. The session has autoflush disabled, so without this
        # a handler's pending writes would still be invisible to a subsequent
        # read - and to the test's own assertions. The enclosing transaction is
        # rolled back afterwards, so nothing leaks between tests.
        yield db_session
        db_session.flush()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        with TestClient(app, raise_server_exceptions=False) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


# --------------------------------------------------------------------------- #
# Domain factories                                                            #
# --------------------------------------------------------------------------- #
@pytest.fixture
def make_user(db_session: Session):
    """Create a user with a valid, policy-compliant password."""
    from app.core.security import PasswordHasherService
    from app.db.models.user import User

    hasher = PasswordHasherService()
    created: list[User] = []

    def _factory(
        *,
        role: UserRole = UserRole.WORKER,
        email: str | None = None,
        # A fixed test credential keeps assertions readable. Not a secret: the
        # suite only ever runs against the dedicated test database.
        password: str = "Correct-Horse-9-Battery",  # noqa: S107
        is_email_verified: bool = True,
        is_active: bool = True,
    ) -> User:
        address = email or f"user-{uuid.uuid4().hex[:10]}@example.com"
        user = User(
            email=address.lower(),
            password_hash=hasher.hash(password),
            role=role.value,
            is_active=is_active,
            is_email_verified=is_email_verified,
        )
        db_session.add(user)
        db_session.flush()
        created.append(user)
        return user

    return _factory


@pytest.fixture
def make_admin(make_user):
    def _factory(**kwargs):
        # setdefault so a test can create a non-admin through this helper.
        kwargs.setdefault("role", UserRole.ADMIN)
        return make_user(**kwargs)

    return _factory


@pytest.fixture
def auth_headers(client, make_user):
    """Log in a freshly created user and return its bearer headers.

    Goes through the real login endpoint rather than minting a token directly, so
    a test using these headers exercises the actual auth path.
    """

    def _factory(user) -> dict[str, str]:
        response = client.post(
            "/auth/login",
            json={"email": user.email, "password": "Correct-Horse-9-Battery"},
        )
        assert response.status_code == 200, response.text
        token = response.json()["data"]["tokens"]["access_token"]
        return {"Authorization": f"Bearer {token}"}

    return _factory


@pytest.fixture
def register(client):
    """Register through the API, returning the response body."""

    def _factory(
        *,
        email: str | None = None,
        # A fixed test credential keeps assertions readable. Not a secret: the
        # suite only ever runs against the dedicated test database.
        password: str = "Correct-Horse-9-Battery",  # noqa: S107
        role: str = "WORKER",
        display_name: str | None = "Test Worker",
        accept_terms: bool = True,
    ) -> dict:
        address = email or f"new-{uuid.uuid4().hex[:10]}@example.com"
        response = client.post(
            "/auth/register",
            json={
                "email": address,
                "password": password,
                "role": role,
                "display_name": display_name,
                "accepted_terms": accept_terms,
            },
        )
        return (
            response.json()
            if response.headers.get("content-type", "").startswith("application/json")
            else {}
        )

    return _factory


# --------------------------------------------------------------------------- #
# Assertions helpers                                                          #
# --------------------------------------------------------------------------- #
@pytest.fixture
def error_code(client):
    """Extract the stable error code from a response, failing loudly if absent."""

    def _extract(response) -> str:
        body = response.json()
        assert "error" in body, f"Expected an error envelope, got: {body}"
        assert "code" in body["error"], f"Error envelope has no code: {body}"
        assert "message" in body["error"], f"Error envelope has no message: {body}"
        return str(body["error"]["code"])

    return _extract


@pytest.fixture
def audit_rows(db_session: Session):
    """Read audit rows written by the service under test."""
    from app.db.models.audit import AuditLog

    def _fetch(**filters) -> list[AuditLog]:
        from sqlalchemy import select

        statement = select(AuditLog)
        for key, value in filters.items():
            statement = statement.where(getattr(AuditLog, key) == value)
        return list(db_session.execute(statement.order_by(AuditLog.created_at)).scalars())

    return _fetch
