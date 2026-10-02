"""Database engine, session factory and the FastAPI session dependency.

Synchronous SQLAlchemy sessions are used deliberately:

* FastAPI runs sync path operations in a threadpool, so blocking I/O costs
  nothing on the event loop;
* the transaction semantics required for race-free application and verification
  creation (select/insert against a unique index, plus row locks) map directly
  onto a single database session and a single unit of work;
* operational behaviour (connection pooling, statement timeouts) is easier to
  reason about than a dual async/sync stack.

The trade-off is that this design assumes one process per worker rather than
thousands of concurrent connections per process. That is the correct shape for
the Render deployment described in ``docs/deployment.md``.
"""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _create_engine(settings: Settings) -> Engine:
    """Build the process-wide engine with pool tuning and server-side guards."""
    connect_args: dict[str, object] = {}
    if settings.database_require_ssl:
        connect_args["sslmode"] = "require"

    engine = create_engine(
        settings.database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_recycle=settings.database_pool_recycle_seconds,
        pool_pre_ping=True,
        echo=settings.database_echo,
        future=True,
        connect_args=connect_args,
    )

    @event.listens_for(engine, "connect")
    def _apply_connection_guards(dbapi_connection: object, _record: object) -> None:
        """Per-connection safety settings (OWASP A03: bound query resources).

        A statement timeout converts an unbounded or pathological query into a
        fast, recoverable error instead of a stuck worker holding a connection.
        """
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SET statement_timeout = '15s'")
            cursor.execute("SET idle_in_transaction_session_timeout = '30s'")
            cursor.execute("SET lock_timeout = '5s'")
        finally:
            cursor.close()

    return engine


def get_engine() -> Engine:
    """Return the lazily constructed engine singleton."""
    global _engine
    if _engine is None:
        _engine = _create_engine(get_settings())
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Return the lazily constructed session factory singleton."""
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
            future=True,
        )
    return _session_factory


def reset_engine() -> None:
    """Dispose the engine and session factory.

    Used by the test suite and by long-lived processes that reload settings.
    """
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a request-scoped session.

    The session is rolled back on any exception, so a failed request can never
    leave partial writes committed.
    """
    session = get_session_factory()()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Context manager for a transactional session outside a request.

    Commits on clean exit and rolls back on error. Used by migrations-adjacent
    scripts, seeding and background jobs.
    """
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_database_connectivity() -> bool:
    """Execute a trivial query to verify the database is reachable.

    Used by the readiness probe. Returns a boolean rather than raising so the
    probe can report an unhealthy state without leaking connection details.
    """
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 - a health probe must never raise
        return False
