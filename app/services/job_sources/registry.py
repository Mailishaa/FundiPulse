"""The source registry: which sources may be fetched, at what rate, and when.

Everything an operator can decide about ingestion is decided by a row in
``job_sources``, not by a deploy. That is the point of this module.

**Terms first.** ``JobSource.terms_status`` must be ``APPROVED``. Anything else -
``UNKNOWN``, ``UNDER_REVIEW``, ``REJECTED``, ``PROHIBITED`` - is refused by
:func:`require_permitted`, with the reason named. A source defaults to
``UNKNOWN``, so forgetting to review one fails closed. ``robots_status`` is
required to be ``PERMITTED`` while ``respect_robots`` is true, which is the
default; an operator who has explicitly recorded otherwise is obeyed, but only
after the terms gate has already passed, so the flag cannot be used to launder an
unreviewed source.

**Disabling is data.** ``is_active`` takes a source out of the rotation
immediately, with no deploy and no code change. :meth:`refusals` explains every
source that is *not* being ingested and why, which is the question an operator
actually asks when the job list looks quiet.

**Rate limiting is ledger-based.** A source's ``rate_limit_per_minute`` and
``last_checked_at`` are enough to enforce its own budget, so the limit survives a
restart and holds across every worker, with no extra table and no in-memory state
that a second process would not share.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import (
    INGESTION_ALLOWED_ROBOTS_STATUSES,
    INGESTION_ALLOWED_TERMS_STATUSES,
    JobSourceType,
)
from app.core.exceptions import AppError, ErrorCode
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models.job import JobSource
from app.services.job_sources.base import JobSourceConnector

logger = get_logger(__name__)

#: Longest ``job_sources.last_error``. Anything longer is truncated before it is
#: written; the column is ``VARCHAR(512)`` and a stack trace is not an error report.
MAX_LAST_ERROR_LENGTH: int = 512

#: Seconds in the rate-limit window ``rate_limit_per_minute`` is expressed over.
RATE_LIMIT_WINDOW_SECONDS: int = 60


class RefusalReason:
    """Why a source is not being ingested."""

    INACTIVE = "inactive"
    TERMS_NOT_APPROVED = "terms_not_approved"
    ROBOTS_NOT_PERMITTED = "robots_not_permitted"
    NO_CONNECTOR = "no_connector_registered"
    NO_BASE_URL = "no_base_url"
    NOT_POLL_DUE = "not_poll_due"


class SourceNotPermittedError(AppError):
    """A source without the operator's permission to ingest it.

    Raised before any fetch is attempted, and the reason is structural - which
    gate failed - so a refused source is diagnosable from the log line alone.
    """

    code = ErrorCode.FORBIDDEN
    status_code = 403
    public_message = "This job source is not permitted for ingestion."

    def __init__(self, reason: str, *, code: str | None = None) -> None:
        super().__init__(f"source ingestion refused ({reason})")
        self.reason = reason
        if code is not None:
            self.code = code


@dataclass(frozen=True, slots=True)
class Refusal:
    """One source that will not be ingested, and the gate that stopped it."""

    source_id: uuid.UUID
    code: str
    reason: str

    @property
    def is_disabled(self) -> bool:
        """Deliberately switched off, as opposed to not yet cleared."""
        return self.reason == RefusalReason.INACTIVE


class JobSourceRegistry:
    """Reads ``job_sources`` and answers the two questions ingestion asks."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # -- gating ----------------------------------------------------------- #

    def require_permitted(self, source: JobSource) -> None:
        """Refuse a source that has not been cleared, naming the gate.

        Terms are checked before robots because terms is the gate that cannot be
        overridden: ``respect_robots`` is an operator's recorded decision about
        automation, not a licence to fetch.
        """
        reason = refusal_reason(source)
        if reason is not None:
            logger.warning(
                "JOB_SOURCE_INGESTION_REFUSED",
                extra={
                    "source_code": source.code,
                    "reason": reason,
                    "terms_status": source.terms_status,
                    "robots_status": source.robots_status,
                    "is_active": source.is_active,
                },
            )
            raise SourceNotPermittedError(reason)

    def enabled(self) -> list[JobSource]:
        """Every source that may be ingested right now.

        The SQL filter narrows on the cheap, indexed predicates
        (``is_active``, ``terms_status``); :attr:`JobSource.ingestion_permitted`
        then applies the robots nuance, so the model's own rule stays the single
        definition rather than being restated here.
        """
        allowed_terms = [status.value for status in INGESTION_ALLOWED_TERMS_STATUSES]
        statement = (
            select(JobSource)
            .where(
                JobSource.is_active.is_(True),
                JobSource.terms_status.in_(allowed_terms),
            )
            .order_by(JobSource.code)
        )
        return [
            row for row in self._session.execute(statement).scalars() if row.ingestion_permitted
        ]

    def refusals(self, *, connectors: Iterable[str] = ()) -> dict[uuid.UUID, Refusal]:
        """Every source that is *not* enabled, with the gate that stopped it.

        The operational counterpart to :meth:`enabled`: "why has this source gone
        quiet" is answered from data, with no deploy and no log archaeology.
        """
        known = set(connectors)
        rows = list(self._session.execute(select(JobSource).order_by(JobSource.code)).scalars())
        out: dict[uuid.UUID, Refusal] = {}
        for source in rows:
            reason = refusal_reason(source)
            if reason is not None:
                out[source.id] = Refusal(source.id, source.code, reason)
            elif known and source.code not in known:
                out[source.id] = Refusal(source.id, source.code, RefusalReason.NO_CONNECTOR)
            elif not source.base_url:
                out[source.id] = Refusal(source.id, source.code, RefusalReason.NO_BASE_URL)
        return out

    # -- connectors -------------------------------------------------------- #

    def connector_for(
        self,
        source: JobSource,
        connectors: Sequence[JobSourceConnector],
    ) -> JobSourceConnector:
        """The connector registered for this source's ``code``, or a refusal.

        Matched by code, never by insertion order or by "the first one": a
        connector is only ever applied to the source whose legal review it
        accompanies.
        """
        matches = [connector for connector in connectors if connector.code == source.code]
        if len(matches) != 1:
            raise SourceNotPermittedError(
                RefusalReason.NO_CONNECTOR if not matches else "ambiguous_connector",
            )
        connector = matches[0]
        if JobSourceType(connector.source_type) is not JobSourceType(source.source_type):
            logger.warning(
                "JOB_SOURCE_CONNECTOR_TYPE_MISMATCH",
                extra={
                    "source_code": source.code,
                    "connector_source_type": str(connector.source_type),
                    "source_type": source.source_type,
                },
            )
        return connector

    # -- rate limiting and scheduling -------------------------------------- #

    def minimum_interval(self, source: JobSource) -> timedelta:
        """The shortest gap two polls of this source may have.

        ``rate_limit_per_minute`` is a per-minute budget, so the interval between
        requests is the window divided by it. A misconfigured zero would make the
        interval zero and the guard meaningless, so it floors at one second.
        """
        per_minute = max(int(source.rate_limit_per_minute or 0), 1)
        seconds = max(RATE_LIMIT_WINDOW_SECONDS / per_minute, 1.0)
        return timedelta(seconds=seconds)

    def is_due(self, source: JobSource, *, now: datetime | None = None) -> bool:
        """Whether this source's own rate limit permits another poll."""
        if source.last_checked_at is None:
            return True
        moment = now or utcnow()
        return (moment - source.last_checked_at) >= self.minimum_interval(source)

    def require_within_budget(self, source: JobSource, *, now: datetime | None = None) -> None:
        """Refuse a poll that would exceed the source's rate limit.

        Raising rather than sleeping: ingestion is scheduled, and a poll that had
        to wait would be a poll whose freshness nobody asked for.
        """
        if self.is_due(source, now=now):
            return
        raise SourceNotPermittedError(RefusalReason.NOT_POLL_DUE, code=ErrorCode.RATE_LIMITED)

    def due(self, *, now: datetime | None = None) -> list[JobSource]:
        """Every enabled source whose own budget permits a poll now."""
        moment = now or utcnow()
        return [source for source in self.enabled() if self.is_due(source, now=moment)]

    # -- outcome ----------------------------------------------------------- #

    def record_outcome(
        self,
        source: JobSource,
        *,
        now: datetime | None = None,
        error: str | None = None,
    ) -> None:
        """Stamp ``last_checked_at`` and, on failure, a bounded ``last_error``.

        The message is a reason code and a count. Response bodies are third-party
        content that may carry personal data, so none is stored here.
        """
        moment = (now or utcnow()).astimezone(UTC)
        source.last_checked_at = moment
        source.last_error = error[:MAX_LAST_ERROR_LENGTH] if error else None
        self._session.flush()

    def codes(self) -> list[str]:
        """Every registered source code, for wiring and diagnostics."""
        statement = select(JobSource.code).order_by(JobSource.code)
        return list(self._session.execute(statement).scalars())


def refusal_reason(source: JobSource) -> str | None:
    """The gate that stopped this source, or ``None`` if it may be ingested.

    Order: inactive, then terms, then robots. A disabled source is disabled
    whatever its review status, and an unreviewed one is unreviewed whatever the
    robots flag says.
    """
    if not source.is_active:
        return RefusalReason.INACTIVE
    if source.terms_status not in {status.value for status in INGESTION_ALLOWED_TERMS_STATUSES}:
        return f"{RefusalReason.TERMS_NOT_APPROVED}:{source.terms_status}"
    robots_ok = source.robots_status in {
        status.value for status in INGESTION_ALLOWED_ROBOTS_STATUSES
    }
    if not robots_ok and source.respect_robots:
        return f"{RefusalReason.ROBOTS_NOT_PERMITTED}:{source.robots_status}"
    return None


__all__ = [
    "MAX_LAST_ERROR_LENGTH",
    "RATE_LIMIT_WINDOW_SECONDS",
    "JobSourceRegistry",
    "Refusal",
    "RefusalReason",
    "SourceNotPermittedError",
    "refusal_reason",
]
