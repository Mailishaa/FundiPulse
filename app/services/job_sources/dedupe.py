"""Stable identity for a job across polls.

The natural key is ``(source_id, source_job_id)``, which is what
``uq_jobs_source_external_id`` enforces in the database:

    CREATE UNIQUE INDEX uq_jobs_source_external_id ON jobs (source_id, source_job_id)
    WHERE (source_job_id IS NOT NULL AND deleted_at IS NULL)

Two rules follow from that and are worth stating plainly, because both are ways an
aggregator silently corrupts its own data:

**Never deduplicate on the title.** Two different vacancies can share one - "Mason
required" is published by fifty contractors in Mombasa - and one vacancy can be
retitled mid-campaign. Keying on the title therefore both merges distinct jobs
and splits a single job in two when it is renamed, and the row that gets orphaned
is the one a worker applied to.

**Identity is scoped to a source.** The same third-party identifier reused by a
different source is a different listing, because the two are independently
permitted, independently rate limited and independently liable. ``source_id`` is
part of the key, so they cannot collide.

Within a single payload, records are collapsed by the same key. A feed that
repeats an entry would otherwise hit the unique index mid-poll and lose the whole
batch; the duplicate is counted rather than silently dropped.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import uuid

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.models.job import Job
from app.services.job_sources.normalize import NormalizedJob

logger = get_logger(__name__)

#: Name of the partial unique index that makes ``(source_id, source_job_id)``
#: authoritative. Asserted against the model metadata by the test suite, so
#: renaming or dropping it in a migration fails a test rather than silently
#: turning deduplication into a no-op.
NATURAL_KEY_INDEX = "uq_jobs_source_external_id"

#: Longest ``jobs.source_job_id``. Matches ``MAX_EXTERNAL_ID_LENGTH`` and
#: ``jobs.source_job_id`` is ``VARCHAR(255)``.
MAX_SOURCE_JOB_ID_LENGTH = 255


def natural_key(source_id: uuid.UUID, source_job_id: str) -> tuple[uuid.UUID, str]:
    """The identity tuple every lookup and every write is keyed on."""
    return (source_id, source_job_id.strip())


def external_identity(record: NormalizedJob) -> str:
    """The stored form of a record's source identifier.

    Whitespace-stripped so a feed that pads one entry with a trailing space
    cannot mint a second row for one vacancy.
    """
    return record.source_job_id.strip()[:MAX_SOURCE_JOB_ID_LENGTH]


def identity_is_storable(source_job_id: str) -> bool:
    """Whether an identifier can be stored and still identify anything."""
    return bool(source_job_id.strip())


@dataclass(frozen=True, slots=True)
class CollapsedDuplicate:
    """A record dropped because the same key appeared earlier in this payload."""

    source_job_id: str
    payload_hash: str


@dataclass(frozen=True, slots=True)
class DedupeOutcome:
    """One payload split into what is genuinely new and what is already stored."""

    new: tuple[NormalizedJob, ...] = ()
    known: tuple[NormalizedJob, ...] = ()
    collapsed: tuple[CollapsedDuplicate, ...] = ()

    @property
    def total(self) -> int:
        return len(self.new) + len(self.known) + len(self.collapsed)


def collapse_within_payload(
    records: Iterable[NormalizedJob],
) -> tuple[list[NormalizedJob], list[CollapsedDuplicate]]:
    """Keep the first record per key; count the rest.

    First-wins rather than last-wins so the outcome does not depend on a feed's
    ordering, and so the retained record is the one an operator would see first
    when tracing a bad entry.
    """
    kept: list[NormalizedJob] = []
    collapsed: list[CollapsedDuplicate] = []
    seen: set[str] = set()
    for record in records:
        identity = external_identity(record)
        if identity in seen:
            collapsed.append(
                CollapsedDuplicate(source_job_id=identity, payload_hash=record.payload_hash)
            )
            logger.info(
                "JOB_SOURCE_DUPLICATE_COLLAPSED",
                extra={"source_job_id": identity, "payload_hash": record.payload_hash},
            )
            continue
        seen.add(identity)
        kept.append(record)
    return kept, collapsed


def load_existing(
    session: Session,
    *,
    source_id: uuid.UUID,
    source_job_ids: Sequence[str],
) -> dict[str, Job]:
    """Load the stored rows for these keys in one query.

    Scoped by ``source_id`` exactly like the index, and filtered on
    ``deleted_at IS NULL`` to match the partial index's predicate: a soft-deleted
    row is outside the identity constraint, so including it here would let the
    pipeline believe a listing is still known when the index says otherwise.
    """
    ids = [value for value in dict.fromkeys(source_job_ids) if identity_is_storable(value)]
    if not ids:
        return {}
    statement: Select[tuple[Job]] = select(Job).where(
        Job.source_id == source_id,
        Job.source_job_id.in_(ids),
        Job.deleted_at.is_(None),
    )
    rows = session.execute(statement).scalars()
    return {row.source_job_id: row for row in rows if row.source_job_id}


def split_known(
    records: Sequence[NormalizedJob],
    existing: Mapping[str, Job],
) -> tuple[list[NormalizedJob], list[NormalizedJob]]:
    """Partition into ``(new, known)`` against the stored rows.

    Matching is on the key and nothing else. A retitled listing is the same
    listing; a different listing that happens to share a title is a different one.
    """
    new: list[NormalizedJob] = []
    known: list[NormalizedJob] = []
    for record in records:
        if external_identity(record) in existing:
            known.append(record)
        else:
            new.append(record)
    return new, known


def deduplicate(
    session: Session,
    records: Sequence[NormalizedJob],
    *,
    source_id: uuid.UUID,
) -> DedupeOutcome:
    """The whole dedupe stage: collapse, then split against the database."""
    kept, collapsed = collapse_within_payload(records)
    existing = load_existing(
        session, source_id=source_id, source_job_ids=[external_identity(r) for r in kept]
    )
    new, known = split_known(kept, existing)
    return DedupeOutcome(new=tuple(new), known=tuple(known), collapsed=tuple(collapsed))


__all__ = [
    "MAX_SOURCE_JOB_ID_LENGTH",
    "NATURAL_KEY_INDEX",
    "CollapsedDuplicate",
    "DedupeOutcome",
    "collapse_within_payload",
    "deduplicate",
    "external_identity",
    "identity_is_storable",
    "load_existing",
    "natural_key",
    "split_known",
]
