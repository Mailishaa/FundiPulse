"""Change detection: a diff against the stored row, never a blind overwrite.

Each incoming record is compared field by field with the row that is already in
the database, and the differences become :class:`JobChangeType` events in
``job_source_events``. The rules are deliberately conservative, because every one
of them protects a fact a worker may have relied on:

**``first_seen_at`` never moves.** It is when *we* first saw the listing, and it
is the only thing that orders how long a worker has had to notice one. Recomputing
it from "now" on every update would silently age every listing on every poll.

**A changed ``closing_at`` is ``DEADLINE_CHANGED``, not ``JOB_UPDATED``.** A
deadline is the field a worker plans around. A diff that folded it into a generic
"updated" event would make "this got shorter" indistinguishable from "the
description was retyped", and the ledger would be unable to answer why.

**Absence from a poll is not closure.** A listing missing from one payload is
recorded as ``JOB_REMOVED`` - an observation, with its own event - and nothing
else changes. One poll can be truncated, paginated, cached or simply stale. Only a
complete poll is treated as evidence at all, and only an explicit policy may turn
repeated absence into a closure, with the grace period derived from the ledger
rather than from in-memory state.

**A source's own "closed" flag is positive evidence.** That is different from
absence, so it does produce ``JOB_CLOSED``. It is still not allowed to close a row
the platform cannot publish; :func:`decide_status` refuses rather than lying.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import EXTERNAL_JOB_SOURCE_TYPES, JobChangeType, JobSourceType, JobStatus
from app.db.base import utcnow
from app.db.models.job import Job
from app.services.job_sources.normalize import NormalizedJob

#: Statuses that mean the listing is no longer open, by source vocabulary.
_CLOSING_STATES = frozenset({"CLOSED", "CANCELLED"})


class PublicationRefusal:
    """Why a row cannot be given the status the source says it has."""

    PUBLISHABLE = ""
    ATTRIBUTION_REQUIRED = "attribution_required"


@dataclass(frozen=True, slots=True)
class PublicationDecision:
    """The status an ingested row may actually be stored with.

    ``jobs`` carries ``CHECK (status = 'DRAFT' OR organization_id IS NOT NULL OR
    source_type = 'EXTERNAL')``. An aggregated listing has no organization, and
    ``JobSourceType`` has no ``EXTERNAL`` member, so today the only status such a
    row can hold is ``DRAFT``. Rather than misattribute it to an employer - which
    would present someone else's vacancy as that employer's posting - the pipeline
    stages it and says so. See ``docs/decisions`` for the open schema question.
    """

    status: JobStatus
    refusal: str = PublicationRefusal.PUBLISHABLE
    reason: str = ""

    @property
    def publishable(self) -> bool:
        return not self.refusal


def decide_status(
    *,
    source_type: str,
    has_organization: bool,
    requested: JobStatus,
) -> PublicationDecision:
    """The status a row may be written with, given what the schema permits.

    Refuses rather than substitutes something false. A row that cannot be published
    is staged as ``DRAFT`` and the reason travels with it, so an operator sees why
    twelve listings are invisible instead of assuming they were dropped.
    """
    external = JobSourceType(source_type) in EXTERNAL_JOB_SOURCE_TYPES
    if not external or has_organization or requested is JobStatus.DRAFT:
        return PublicationDecision(status=requested)
    return PublicationDecision(
        status=JobStatus.DRAFT,
        refusal=PublicationRefusal.ATTRIBUTION_REQUIRED,
        reason=(
            "jobs_published_requires_organization demands an owning organization and "
            "JobSourceType has no EXTERNAL member, so this aggregated listing is staged "
            "as DRAFT rather than attributed to an employer"
        ),
    )


@dataclass(frozen=True, slots=True)
class DeadlineChange:
    """A closing date that moved, in both directions."""

    previous: datetime | None
    current: datetime | None

    @property
    def extended(self) -> bool:
        """Whether the deadline moved further out."""
        if self.previous is None:
            return self.current is not None
        if self.current is None:
            return False
        return self.current > self.previous

    def describe(self) -> str:
        """A short, value-free summary for ``job_source_events.detail``."""
        if self.previous is None:
            return "closing_at added"
        if self.current is None:
            return "closing_at removed"
        return "closing_at extended" if self.extended else "closing_at shortened"


@dataclass(frozen=True, slots=True)
class ChangeSet:
    """What differs between an incoming record and the stored row."""

    change_types: tuple[JobChangeType, ...] = ()
    field_changes: tuple[str, ...] = ()
    deadline: DeadlineChange | None = None
    payload_hash: str = ""
    detail: str = ""

    @property
    def has_changes(self) -> bool:
        return bool(self.change_types)

    @property
    def deadline_changed(self) -> bool:
        return JobChangeType.DEADLINE_CHANGED in self.change_types

    @property
    def closed(self) -> bool:
        return JobChangeType.JOB_CLOSED in self.change_types

    def describe(self) -> str:
        """Ledger detail: which fields, never their values.

        ``jobs.description`` is third-party text that may carry personal data, so
        the ledger records the *name* of what changed and nothing more.
        """
        if not self.change_types:
            return self.detail or "no material change"
        if self.detail:
            return self.detail
        parts = [str(change.value) for change in self.change_types]
        if self.deadline is not None:
            parts.append(self.deadline.describe())
        if self.field_changes:
            parts.append("fields=" + ",".join(sorted(self.field_changes)))
        return "; ".join(parts)


@dataclass(frozen=True, slots=True)
class RemovalSignal:
    """A stored listing the latest complete poll did not mention."""

    job_id: uuid.UUID
    source_job_id: str
    last_seen_at: datetime | None
    prior_removals: int = 0
    detected_at: datetime = field(default_factory=utcnow)

    def describe(self) -> str:
        """Ledger detail for the absence itself."""
        detail = "absent from a complete poll; status unchanged pending review"
        if self.prior_removals:
            detail += f"; {self.prior_removals} prior absence(s) already recorded"
        return detail


@dataclass(frozen=True, slots=True)
class AbsenceObservation:
    """A listing a complete poll did not mention, with the row to attach it to."""

    signal: RemovalSignal
    job: Job


@dataclass(frozen=True, slots=True)
class AbsencePolicy:
    """When repeated absence may become a closure.

    ``close_after_absences=0`` is the default and means *never*: absence is
    recorded and nothing else happens. A deployment that has concluded its feeds
    are reliable may set it, and then the count comes from the ledger rather than
    from process memory, so it survives a restart and cannot be reset by one.
    """

    close_after_absences: int = 0

    def should_close(self, prior_removals: int) -> bool:
        return self.close_after_absences > 0 and prior_removals + 1 >= self.close_after_absences


#: ``jobs`` column -> the :class:`NormalizedJob` field that fills it. The exact set
#: an update may write, declared once: anything absent from this table cannot be
#: rewritten by a poll, which is what keeps ``first_seen_at`` and the provenance
#: identifiers safe by construction rather than by remembering.
TRACKED_FIELDS: tuple[tuple[str, str], ...] = (
    ("title", "title"),
    ("description", "description"),
    ("location", "location"),
    ("employment_type", "employment_type"),
    ("experience_level", "experience_level"),
    ("experience_required_years", "experience_required_years"),
    ("salary_min", "salary_min"),
    ("salary_max", "salary_max"),
    ("salary_currency", "salary_currency"),
    ("salary_period", "salary_period"),
    ("source_url", "source_url"),
    ("external_apply_url", "apply_url"),
)

#: The same set as plain column names, in report order.
TRACKED_COLUMNS: tuple[str, ...] = tuple(column for column, _field in TRACKED_FIELDS)


def diff_record(incoming: NormalizedJob, stored: Job) -> ChangeSet:
    """Compare an incoming record with the stored row.

    Returns an empty :class:`ChangeSet` when nothing material differs - a poll that
    re-sees an unchanged listing writes no events at all, which is what keeps the
    ledger readable.
    """
    differences = tuple(
        column
        for column, field_name in TRACKED_FIELDS
        if getattr(incoming, field_name) != getattr(stored, column)
    )
    deadline = _deadline_change(incoming, stored)
    changes: list[JobChangeType] = []

    if deadline is not None:
        changes.append(JobChangeType.DEADLINE_CHANGED)
    # A source that states the listing has ended is positive evidence, unlike
    # absence. Keyed on `closed_at` rather than on the status, because the status of
    # a staged aggregated listing cannot be moved by the schema - and re-emitting
    # the same closure on every poll would bury the ledger.
    if incoming.is_closed_by_source and stored.closed_at is None:
        changes.append(JobChangeType.JOB_CLOSED)
    non_deadline = tuple(name for name in differences if name != "closing_at")
    if non_deadline:
        changes.append(JobChangeType.JOB_UPDATED)

    return ChangeSet(
        change_types=tuple(changes),
        field_changes=differences,
        deadline=deadline,
        payload_hash=incoming.payload_hash,
    )


def _deadline_change(incoming: NormalizedJob, stored: Job) -> DeadlineChange | None:
    if incoming.closing_at == stored.closing_at:
        return None
    return DeadlineChange(previous=stored.closing_at, current=incoming.closing_at)


def new_record_changes(incoming: NormalizedJob, decision: PublicationDecision) -> ChangeSet:
    """The change set for a listing seen for the first time.

    The decision travels with the event: if the row is staged rather than
    published, the ledger says why, so "invisible" is explainable later.
    """
    detail = "first observation for this source"
    if decision.refusal:
        detail += f"; staged without publication ({decision.refusal}): {decision.reason}"
    return ChangeSet(
        change_types=(JobChangeType.NEW_JOB,),
        deadline=DeadlineChange(previous=None, current=incoming.closing_at)
        if incoming.closing_at is not None
        else None,
        payload_hash=incoming.payload_hash,
        detail=detail,
    )


def removed_changes(signal: RemovalSignal) -> ChangeSet:
    """The change set for a listing absent from a complete poll."""
    return ChangeSet(
        change_types=(JobChangeType.JOB_REMOVED,),
        detail=signal.describe(),
    )


def absence_signals(
    session: Session,
    *,
    source_id: uuid.UUID,
    seen_source_job_ids: Iterable[str],
    now: datetime | None = None,
) -> list[AbsenceObservation]:
    """Stored listings this poll did not mention.

    Only ever called for a complete poll. Soft-deleted rows are excluded, and so
    are rows for listings the platform deliberately closed, which cannot be
    "absent" - they ended here, not over there.
    """
    moment = now or utcnow()
    seen = set(seen_source_job_ids)
    statement = select(Job).where(
        Job.source_id == source_id,
        Job.deleted_at.is_(None),
        Job.status.notin_(_CLOSING_STATES),
    )
    if seen:
        statement = statement.where(Job.source_job_id.notin_(list(seen)))
    stored = list(session.execute(statement).scalars())
    observations: list[AbsenceObservation] = []
    for job in stored:
        if not job.source_job_id:
            continue
        observations.append(
            AbsenceObservation(
                signal=RemovalSignal(
                    job_id=job.id,
                    source_job_id=job.source_job_id,
                    last_seen_at=job.last_seen_at,
                    prior_removals=count_removals(session, job_id=job.id, since=job.last_seen_at),
                    detected_at=moment,
                ),
                job=job,
            )
        )
    return observations


def count_removals(session: Session, *, job_id: uuid.UUID, since: datetime | None) -> int:
    """``JOB_REMOVED`` events already recorded for this listing since it was last seen.

    Derived from the ledger so the grace period survives a restart, and counted
    only since ``last_seen_at`` so a listing that reappeared and vanished again
    starts its count over.
    """
    from app.db.models.job import JobSourceEvent

    conditions = [
        JobSourceEvent.job_id == job_id,
        JobSourceEvent.change_type == JobChangeType.JOB_REMOVED.value,
    ]
    if since is not None:
        conditions.append(JobSourceEvent.detected_at > since)
    result = session.execute(select(func.count()).select_from(JobSourceEvent).where(*conditions))
    return int(result.scalar_one())


def apply_change_set(
    job: Job,
    incoming: NormalizedJob,
    *,
    now: datetime,
    decision: PublicationDecision | None = None,
) -> None:
    """Copy an incoming record onto a stored row.

    ``first_seen_at`` is not among the assignments, by construction rather than by
    convention: the only fields written are the ones this module lists. Provenance
    identifiers are likewise never rewritten - a row that changed source would
    need a new identity, and that is a migration, not an update.
    """
    for column, field_name in TRACKED_FIELDS:
        setattr(job, column, getattr(incoming, field_name))
    job.published_at = incoming.published_at or job.published_at
    job.closing_at = incoming.closing_at
    job.last_seen_at = now
    # "Confirmed to still exist" means this poll confirmed it is still open. An
    # `UNKNOWN` or `CLOSED` listing is seen but not verified, and must not be able
    # to advance this field.
    job.last_verified_at = now if incoming.is_confirmed_open else job.last_verified_at
    if decision is not None:
        job.status = decision.status.value


def initialise_record(
    job: Job,
    incoming: NormalizedJob,
    *,
    source_id: uuid.UUID,
    source_name: str,
    source_type: JobSourceType,
    now: datetime,
    decision: PublicationDecision,
) -> None:
    """Stamp every provenance field on a new row.

    All six provenance fields are written here and nowhere else: ``source_id``,
    ``source_url``, ``source_job_id``, ``first_seen_at``, ``last_seen_at`` and
    ``last_verified_at``. They are set from the source row and the payload, never
    derived, because "where did this come from" must survive any later failure to
    fetch it again.
    """
    job.source_id = source_id
    job.source_type = source_type.value
    job.source_name = source_name
    job.source_url = incoming.source_url
    job.source_job_id = incoming.source_job_id
    job.external_apply_url = incoming.apply_url
    job.first_seen_at = now
    job.last_seen_at = now
    job.last_verified_at = now if incoming.is_confirmed_open else None
    # A listing the source already reported as ended on its first appearance: stamp
    # the fact now, so no later poll has to re-derive it and re-announce it forever.
    job.closed_at = now if incoming.is_closed_by_source else None
    job.is_aggregated = True
    # An aggregated listing is owned by its source, never by an employer.
    job.organization_id = None
    apply_change_set(job, incoming, now=now, decision=decision)


__all__ = [
    "TRACKED_COLUMNS",
    "TRACKED_FIELDS",
    "AbsenceObservation",
    "AbsencePolicy",
    "ChangeSet",
    "DeadlineChange",
    "PublicationDecision",
    "PublicationRefusal",
    "RemovalSignal",
    "absence_signals",
    "apply_change_set",
    "count_removals",
    "decide_status",
    "diff_record",
    "initialise_record",
    "new_record_changes",
    "removed_changes",
]
