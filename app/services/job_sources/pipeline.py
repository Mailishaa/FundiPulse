"""The ingestion pipeline, as six separately testable stages.

``fetch -> parse -> normalise -> deduplicate -> detect -> store``

Each stage is a method that takes its inputs and returns its outputs, with no
hidden state, so a test can drive one of them without the five around it and a
reviewer can read one without the rest. :meth:`IngestionPipeline.run` is only an
ordering.

The properties the stages hold between them:

* **Provenance is written once and never derived.** :func:`~app.services.job_sources.changes.initialise_record`
  stamps ``source_id``, ``source_url``, ``source_job_id``, ``first_seen_at``,
  ``last_seen_at`` and ``last_verified_at`` on a new row, and no stage ever
  infers one of them.
* **Identity is the natural key.** Deduplication reads and writes
  ``(source_id, source_job_id)`` and nothing else, so a retitle is an update and a
  second listing with the same title is a second job.
* **Changes are diffs.** An update writes only the fields that differ and records
  what differed by name. ``first_seen_at`` is not in the write set.
* **Absence is an observation.** A complete poll that no longer mentions a listing
  emits ``JOB_REMOVED``; a partial poll says nothing at all. Neither closes
  anything unless a policy says so.

Logging in this module is counts and identifiers. A response body is third-party
content and may carry personal data, so it is never logged, never stored in
``last_error`` and never put in an event's ``detail``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
import uuid

from sqlalchemy.orm import Session

from app.core.constants import JobChangeType, JobSourceType, JobStatus
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models.job import Job, JobSource, JobSourceEvent
from app.services.job_sources.base import (
    FetchPayload,
    IngestionRunResult,
    JobSourceConnector,
    ParsedPayload,
    PayloadCoverage,
    Rejection,
    StageCounts,
)
from app.services.job_sources.changes import (
    AbsencePolicy,
    ChangeSet,
    PublicationDecision,
    absence_signals,
    apply_change_set,
    decide_status,
    diff_record,
    initialise_record,
    new_record_changes,
    removed_changes,
)
from app.services.job_sources.dedupe import (
    DedupeOutcome,
    deduplicate,
    external_identity,
    load_existing,
)
from app.services.job_sources.normalize import NormaliseOutcome, NormalizedJob
from app.services.job_sources.registry import JobSourceRegistry
from app.services.job_sources.safety import FetchGuard, FetchRefusedError

logger = get_logger(__name__)

#: Default policy for a poll. ``close_after_absences=0`` means a listing that
#: stops appearing is recorded and otherwise left alone - absence from one poll is
#: not evidence that a job closed.
DEFAULT_POLICY: AbsencePolicy = AbsencePolicy(close_after_absences=0)


@dataclass(frozen=True, slots=True)
class StageOutcome:
    """The store stage's product: rows written and events recorded."""

    new_job_ids: tuple[uuid.UUID, ...] = ()
    events: tuple[JobSourceEvent, ...] = ()
    counts: StageCounts = field(default_factory=StageCounts)

    @property
    def changed_job_ids(self) -> tuple[uuid.UUID, ...]:
        seen: dict[uuid.UUID, None] = {}
        for event in self.events:
            if event.job_id is not None:
                seen.setdefault(event.job_id, None)
        return tuple(seen)


@dataclass(frozen=True, slots=True)
class PlanEntry:
    """One row's intended fate this poll, before anything is written."""

    change_set: ChangeSet
    record: NormalizedJob | None
    job: Job | None
    decision: PublicationDecision | None = None


class IngestionPipeline:
    """Runs one source through one poll."""

    def __init__(
        self,
        session: Session,
        *,
        guard: FetchGuard,
        registry: JobSourceRegistry | None = None,
        policy: AbsencePolicy = DEFAULT_POLICY,
    ) -> None:
        self._session = session
        self._guard = guard
        self._registry = registry or JobSourceRegistry(session)
        self._policy = policy

    @property
    def guard(self) -> FetchGuard:
        return self._guard

    @property
    def policy(self) -> AbsencePolicy:
        return self._policy

    # -- stage 1: fetch -------------------------------------------------- #

    def fetch(self, connector: JobSourceConnector, source: JobSource) -> FetchPayload:
        """Fetch the source's endpoint through the guard.

        The registry gate runs first, so an unapproved source is refused before a
        socket could exist, let alone open.
        """
        self._registry.require_permitted(source)
        payload = connector.collect(source)
        logger.info(
            "JOB_SOURCE_FETCH_STAGE",
            extra={
                "source_code": source.code,
                "bytes": payload.size_bytes,
                "coverage": str(payload.coverage.value),
            },
        )
        return payload

    # -- stage 2: parse -------------------------------------------------- #

    def parse(self, connector: JobSourceConnector, payload: FetchPayload) -> ParsedPayload:
        """Decode a payload into raw records."""
        parsed = connector.parse(payload)
        logger.info(
            "JOB_SOURCE_PARSE_STAGE",
            extra={"source_code": connector.code, "records": len(parsed.records)},
        )
        return parsed

    # -- stage 3: normalise ---------------------------------------------- #

    def normalise(
        self,
        connector: JobSourceConnector,
        parsed: ParsedPayload,
        *,
        source: JobSource,
        now: datetime | None = None,
    ) -> NormaliseOutcome:
        """Coerce raw records into canonical listings, counting the rest."""
        outcome = connector.normalise(parsed.records, source=source, now=now)
        logger.info(
            "JOB_SOURCE_NORMALISE_STAGE",
            extra={
                "source_code": source.code,
                "normalised": len(outcome.records),
                "rejected": outcome.rejected_count,
                "reasons": outcome.rejection_counts(),
            },
        )
        return outcome

    # -- stage 4: deduplicate -------------------------------------------- #

    def deduplicate(
        self,
        records: Sequence[NormalizedJob],
        *,
        source: JobSource,
    ) -> DedupeOutcome:
        """Split into listings we have never seen and listings we have."""
        outcome = deduplicate(self._session, records, source_id=source.id)
        logger.info(
            "JOB_SOURCE_DEDUPE_STAGE",
            extra={
                "source_code": source.code,
                "new": len(outcome.new),
                "known": len(outcome.known),
                "collapsed": len(outcome.collapsed),
            },
        )
        return outcome

    # -- stage 5: detect -------------------------------------------------- #

    def plan(
        self,
        outcome: DedupeOutcome,
        *,
        source: JobSource,
        coverage: PayloadCoverage,
        now: datetime | None = None,
    ) -> list[PlanEntry]:
        """Diff every candidate against the stored row, and decide the removals.

        Nothing is written here. Detecting before writing is what makes the ledger
        trustworthy: the diff is against the committed row, not against a
        half-updated session.
        """
        moment = now or utcnow()
        stored = load_existing(
            self._session,
            source_id=source.id,
            source_job_ids=[external_identity(record) for record in (*outcome.new, *outcome.known)],
        )
        entries: list[PlanEntry] = []
        for record in outcome.new:
            decision = decide_status(
                source_type=source.source_type,
                has_organization=False,
                requested=JobStatus.OPEN,
            )
            entries.append(
                PlanEntry(
                    change_set=new_record_changes(record, decision),
                    record=record,
                    job=None,
                    decision=decision,
                )
            )
        for record in outcome.known:
            job = stored[external_identity(record)]
            entries.append(
                PlanEntry(
                    change_set=diff_record(record, job),
                    record=record,
                    job=job,
                    decision=None,
                )
            )

        if coverage is not PayloadCoverage.COMPLETE:
            # A truncated or paginated payload accounts for nothing it left out, so
            # it produces no removal signal at all.
            return entries

        seen = {external_identity(record) for record in (*outcome.new, *outcome.known)}
        for observation in absence_signals(
            self._session, source_id=source.id, seen_source_job_ids=seen, now=moment
        ):
            signal = observation.signal
            change_set = removed_changes(signal)
            if self._policy.should_close(signal.prior_removals):
                # The only path by which absence closes anything, and only once the
                # ledger already holds the agreed number of prior absences.
                change_set = ChangeSet(
                    change_types=(JobChangeType.JOB_REMOVED, JobChangeType.JOB_CLOSED),
                    detail=signal.describe() + "; closure applied by absence policy",
                )
            entries.append(PlanEntry(change_set=change_set, record=None, job=observation.job))
        return entries

    # -- stage 6: store -------------------------------------------------- #

    def store(
        self,
        entries: Sequence[PlanEntry],
        *,
        source: JobSource,
        now: datetime | None = None,
    ) -> StageOutcome:
        """Write the rows and the ledger, and return what changed."""
        moment = now or utcnow()
        source_type = JobSourceType(source.source_type)
        new_ids: list[uuid.UUID] = []
        events: list[JobSourceEvent] = []
        tally = _Tally()
        change_types: set[JobChangeType] = set()

        for entry in entries:
            change_set = entry.change_set
            if not change_set.has_changes:
                tally.unchanged += 1
                if entry.record is not None and entry.job is not None:
                    # Nothing material changed, but the listing was re-seen: that is
                    # what `last_seen_at` is for.
                    apply_change_set(entry.job, entry.record, now=moment, decision=None)
                continue

            job = entry.job
            if entry.record is not None and job is None:
                job = Job(
                    title=entry.record.title,
                    description=entry.record.description,
                    employment_type=entry.record.employment_type.value,
                    experience_level=entry.record.experience_level.value,
                    status=JobStatus.DRAFT.value,
                )
                initialise_record(
                    job,
                    entry.record,
                    source_id=source.id,
                    source_name=source.name,
                    source_type=source_type,
                    now=moment,
                    decision=entry.decision
                    or decide_status(
                        source_type=source.source_type,
                        has_organization=False,
                        requested=JobStatus.OPEN,
                    ),
                )
                self._session.add(job)
                self._session.flush()
                new_ids.append(job.id)
                tally.new += 1
                if entry.decision is not None and not entry.decision.publishable:
                    tally.staged += 1
            elif entry.record is not None and job is not None:
                apply_change_set(job, entry.record, now=moment, decision=None)
                if JobChangeType.JOB_UPDATED in change_set.change_types:
                    tally.updated += 1

            if change_set.deadline_changed:
                tally.deadline_changed += 1
            if change_set.closed:
                tally.closed += 1
                _close(job, source, moment)

            for change_type in change_set.change_types:
                change_types.add(change_type)
                events.append(
                    JobSourceEvent(
                        job_id=job.id if job is not None else None,
                        source_id=source.id,
                        change_type=change_type.value,
                        detail=change_set.describe(),
                        detected_at=moment,
                        payload_hash=change_set.payload_hash or None,
                    )
                )
                self._session.add(events[-1])
                if change_type is JobChangeType.JOB_REMOVED:
                    tally.removed += 1

        if events:
            self._session.flush()
        counts = tally.build(len(events))
        logger.info(
            "JOB_SOURCE_STORE_STAGE",
            extra={
                "source_code": source.code,
                "new": counts.new,
                "updated": counts.updated,
                "deadline_changed": counts.deadline_changed,
                "closed": counts.closed,
                "removed": counts.removed,
                "unchanged": counts.unchanged,
                "events": counts.events,
                "staged": counts.staged,
                "change_types": sorted(change.value for change in change_types),
            },
        )
        return StageOutcome(new_job_ids=tuple(new_ids), events=tuple(events), counts=counts)

    # -- orchestration ---------------------------------------------------- #

    def run(
        self,
        connector: JobSourceConnector,
        source: JobSource,
        *,
        now: datetime | None = None,
        enforce_rate_limit: bool = True,
    ) -> IngestionRunResult:
        """Every stage in order, for one source.

        A fetch refusal is not an exception the caller has to know about: it is
        recorded against the source and returned as a result, because "the feed was
        unreachable" is a normal operational fact and the run must still finish.
        """
        moment = now or utcnow()
        if enforce_rate_limit:
            # A source's own budget, from its own row. ``False`` is for a manual
            # re-ingest; the scheduler never sets it.
            self._registry.require_within_budget(source, now=moment)
        try:
            payload = self.fetch(connector, source)
        except FetchRefusedError as exc:
            self._registry.record_outcome(source, now=moment, error=exc.reason)
            logger.warning(
                "JOB_SOURCE_FETCH_REFUSED",
                extra={
                    "source_code": source.code,
                    "reason": exc.reason,
                    "detail": exc.detail,
                },
            )
            return IngestionRunResult(
                source_id=source.id,
                source_code=source.code,
                coverage=PayloadCoverage.PARTIAL,
                finished_at=moment,
            )

        parsed = self.parse(connector, payload)
        outcome = self.normalise(connector, parsed, source=source, now=moment)
        deduped = self.deduplicate(outcome.records, source=source)
        entries = self.plan(deduped, source=source, coverage=parsed.coverage, now=moment)
        stored = self.store(entries, source=source, now=moment)

        counts = (
            StageCounts(
                fetched_bytes=payload.size_bytes,
                parsed=len(parsed.records),
                normalised=len(outcome.records),
                rejected=outcome.rejected_count,
                collapsed=len(deduped.collapsed),
            )
            + stored.counts
        )
        warnings = _warning_counts(outcome.records)
        result = IngestionRunResult(
            source_id=source.id,
            source_code=source.code,
            coverage=parsed.coverage,
            counts=counts,
            rejections=_rejections(outcome),
            warnings=warnings,
            change_types=tuple(sorted({event.change_type for event in stored.events})),
            job_ids=stored.changed_job_ids,
            finished_at=moment,
        )
        self._registry.record_outcome(source, now=moment)
        logger.info("JOB_SOURCE_POLL_COMPLETE", extra=result.summary())
        return result

    def poll_error(self, source: JobSource, error: BaseException, *, now: datetime | None) -> None:
        """Record a failed poll against the source, in code and never in content."""
        self._registry.record_outcome(source, now=now, error=f"{type(error).__name__}")


@dataclass(slots=True)
class _Tally:
    """Mutable counters for one pass of the store stage."""

    new: int = 0
    updated: int = 0
    deadline_changed: int = 0
    closed: int = 0
    removed: int = 0
    unchanged: int = 0
    staged: int = 0

    def build(self, events: int) -> StageCounts:
        """Freeze the counters into the immutable result type."""
        return StageCounts(
            new=self.new,
            updated=self.updated,
            deadline_changed=self.deadline_changed,
            closed=self.closed,
            removed=self.removed,
            unchanged=self.unchanged,
            staged=self.staged,
            events=events,
        )


def _close(job: Job | None, source: JobSource, now: datetime) -> None:
    """Record that a listing the source says has ended has ended.

    ``closed_at`` is stamped whether or not the status can move: it is the fact
    itself, and for a staged aggregated listing it is the only place the fact can
    live. The status moves only when the schema permits it.
    """
    if job is None:
        return
    decision = decide_status(
        source_type=source.source_type,
        has_organization=job.organization_id is not None,
        requested=JobStatus.CLOSED,
    )
    job.status = decision.status.value
    job.closed_at = job.closed_at or now
    if decision.publishable:
        job.closing_at = job.closing_at or now


def _rejections(outcome: NormaliseOutcome) -> tuple[Rejection, ...]:
    counts = outcome.rejection_counts()
    fields = dict(outcome.rejections)
    return tuple(
        Rejection(reason=reason, field_name=fields.get(reason), count=count)
        for reason, count in sorted(counts.items())
    )


def _warning_counts(records: Sequence[NormalizedJob]) -> dict[str, int]:
    """Counts of coercion warnings across a poll. Codes and counts only."""
    counts: dict[str, int] = {}
    for record in records:
        for code in record.warnings:
            counts[code] = counts.get(code, 0) + 1
    return counts


__all__ = [
    "DEFAULT_POLICY",
    "IngestionPipeline",
    "PlanEntry",
    "StageOutcome",
]
