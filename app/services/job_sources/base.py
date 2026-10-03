"""The connector contract and the pipeline's result types.

A connector answers three questions for one registered source and nothing else:
where to fetch (answered by :mod:`app.services.job_sources.safety`, never by the
connector), how to read the payload, and how to present each entry as the canonical
mapping the normaliser expects.

There is deliberately no connector for any real site in this milestone. A connector
is a legal and technical statement - *this* site permits this, at this rate, with
these hosts - and that statement belongs to an administrator who has reviewed the
source's terms, not to a library that has never read them. What is here instead is
the interface, plus :class:`MappingConnector`, a declarative parser that turns a
declared field map over a fetched payload. That is enough to exercise every stage
against fixtures without pretending any particular site has been cleared.

No connector may reach the network by itself: the transport it holds only accepts a
:class:`~app.services.job_sources.safety.FetchRequest`, and that type cannot be
built without an approval from the guard.
"""

from __future__ import annotations

import abc
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import json
from typing import Any, Final
import uuid

from app.core.constants import JobSourceType
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models.job import JobSource
from app.services.job_sources.normalize import (
    NormaliseOutcome,
    RecordRejectedError,
    RejectionReason,
    normalize_all,
)
from app.services.job_sources.safety import FetchGuard

logger = get_logger(__name__)

#: Content types a payload may claim. A feed that answers ``text/html`` is either
#: misconfigured or serving an error page, and parsing it as a feed would produce
#: nonsense listings rather than an error.
JSON_CONTENT_TYPES: Final[frozenset[str]] = frozenset({"application/json"})

#: Prefix form of the same allowlist, for the cheap check a parser makes.
JSON_CONTENT_TYPES_PREFIX: Final[str] = "application/json"


class PayloadCoverage(StrEnum):
    """Whether a payload accounted for every listing the source holds.

    ``COMPLETE`` means absence from the payload is evidence of something. A
    paginated or truncated payload is ``PARTIAL``, and a partial payload never
    produces a removal signal - a page that stopped halfway is not a source
    deleting its vacancies.
    """

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


@dataclass(frozen=True, slots=True)
class FetchPayload:
    """A fetched document, still bytes.

    Never a decoded string on purpose: decoding happens once, in the connector,
    after the byte cap has already been enforced.
    """

    url: str
    body: bytes
    content_type: str | None = None
    coverage: PayloadCoverage = PayloadCoverage.COMPLETE
    page: int = 1
    page_count: int = 1

    @property
    def size_bytes(self) -> int:
        return len(self.body)

    def json(self) -> Any:
        """Parse the payload. Raises ``json.JSONDecodeError`` on a non-JSON body."""
        return json.loads(self.body)


@dataclass(frozen=True, slots=True)
class RawJobRecord:
    """One entry as the source presented it, before normalisation.

    ``payload`` keeps the original mapping so the digest recorded in
    ``job_source_events.payload_hash`` identifies exactly what arrived. It is not
    retained beyond the poll.
    """

    external_id: str | int | None
    payload: Mapping[str, Any]
    detail_url: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedPayload:
    """Raw records plus what the payload claimed to cover."""

    records: tuple[RawJobRecord, ...] = ()
    coverage: PayloadCoverage = PayloadCoverage.COMPLETE

    def __len__(self) -> int:
        return len(self.records)


@dataclass(frozen=True, slots=True)
class FieldMap:
    """A declarative mapping from one payload's keys to canonical keys.

    ``required`` names canonical fields a record cannot do without. Naming the id
    is what stops a connector from inventing an identity for an entry the source
    never identified.
    """

    source: Mapping[str, str]
    constants: Mapping[str, Any] = field(default_factory=dict)
    required: tuple[str, ...] = ("external_id", "title", "description")

    def canonical(self, entry: Mapping[str, Any]) -> dict[str, Any]:
        """Project one payload entry onto the canonical keys."""
        canonical: dict[str, Any] = dict(self.constants)
        for raw_key, canonical_key in self.source.items():
            if raw_key in entry:
                canonical[canonical_key] = entry[raw_key]
            elif canonical_key in self.constants:
                continue
            else:
                canonical.setdefault(canonical_key, None)
        for key in self.required:
            if canonical.get(key) in (None, ""):
                raise RecordRejectedError(RejectionReason.MISSING_REQUIRED_FIELD, field_name=key)
        return canonical


class JobSourceConnector(abc.ABC):
    """One registered source, as code.

    ``code`` must equal the ``JobSource.code`` it serves; the registry refuses any
    pairing it cannot match, so a connector cannot be pointed at a source it was
    not written for.
    """

    def __init__(
        self,
        *,
        guard: FetchGuard,
        code: str,
        source_type: JobSourceType = JobSourceType.AGGREGATED_PUBLIC,
        apply_hosts: frozenset[str] = frozenset(),
    ) -> None:
        """Bind a connector to the one source it was written for.

        Per instance rather than per class: a class-level ``code`` would be shared
        state, and the second connector built in a process would silently rename the
        first - which for this system means one source's connector serving another
        source's rows.
        """
        if not code.strip():
            raise ValueError("a connector must declare the JobSource.code it serves")
        self._guard = guard
        self._code = code.strip()
        self._source_type = source_type
        self._apply_hosts = apply_hosts

    @property
    def guard(self) -> FetchGuard:
        return self._guard

    @property
    def code(self) -> str:
        """The ``JobSource.code`` this connector implements."""
        return self._code

    @property
    def source_type(self) -> JobSourceType:
        """The provenance recorded on every listing it produces."""
        return self._source_type

    @property
    def apply_hosts(self) -> frozenset[str]:
        """Applicant-tracking hosts this connector may point workers at.

        Explicit, never a wildcard: a link nobody reviewed is not a link we render.
        """
        return self._apply_hosts

    def collect(self, source: JobSource) -> FetchPayload:
        """Fetch the source's registered endpoint through the guard.

        The default implementation fetches ``JobSource.base_url``, which is the only
        URL in the system that is ever fetched. A connector with pagination
        overrides this and must call :meth:`guard.fetch` for every page, because
        every page is a request and every request needs approving.
        """
        if not source.base_url:
            raise ValueError(f"source {source.code} has no base_url to fetch")
        result = self._guard.fetch(source.base_url)
        return FetchPayload(
            url=result.url,
            body=result.body,
            content_type=result.content_type,
            coverage=PayloadCoverage.COMPLETE,
        )

    @abc.abstractmethod
    def parse(self, payload: FetchPayload) -> ParsedPayload:
        """Turn a fetched document into raw records."""

    def normalise(
        self,
        records: Sequence[RawJobRecord],
        *,
        source: JobSource,
        now: datetime | None = None,
    ) -> NormaliseOutcome:
        """Normalise raw records into canonical listings."""
        return normalize_all(
            (record.payload for record in records),
            source=source,
            policy=self._guard.policy,
            now=now or utcnow(),
            apply_hosts=self.apply_hosts,
            ids=[record.external_id for record in records],
        )


class MappingConnector(JobSourceConnector):
    """A connector defined by a field map over a JSON object.

    Two shapes cover most feeds and both are handled: a JSON array of records,
    and a single object wrapping records under a key with paging metadata beside
    it. Paging metadata decides coverage: a payload that says "there is more" is
    ``PARTIAL``, which suppresses removal signals for everything absent from it.
    """

    def __init__(
        self,
        *,
        guard: FetchGuard,
        code: str,
        field_map: FieldMap,
        source_type: JobSourceType = JobSourceType.AGGREGATED_PUBLIC,
        records_key: str | None = None,
        paging_key: str = "meta",
        apply_hosts: frozenset[str] = frozenset(),
        page_count: int = 1,
    ) -> None:
        self._field_map = field_map
        self._records_key = records_key
        self._paging_key = paging_key
        self._page_count = page_count
        super().__init__(guard=guard, code=code, source_type=source_type, apply_hosts=apply_hosts)

    @property
    def field_map(self) -> FieldMap:
        return self._field_map

    def entries(self, document: Any) -> list[Mapping[str, Any]]:
        """The record list inside a decoded document."""
        if isinstance(document, list):
            return [entry for entry in document if isinstance(entry, Mapping)]
        if isinstance(document, Mapping):
            if self._records_key is None:
                return [document]
            candidate = document.get(self._records_key)
            if isinstance(candidate, list):
                return [entry for entry in candidate if isinstance(entry, Mapping)]
        return []

    def coverage(self, document: Any) -> PayloadCoverage:
        """Completeness as the payload declares it.

        A next-page cursor or a ``has_more`` flag means the payload is part of a
        larger whole, and absence from it means nothing.
        """
        if self._page_count > 1:
            return PayloadCoverage.PARTIAL
        for candidate in self._paging_objects(document):
            for key in ("next", "next_cursor", "next_page", "has_more", "more"):
                value = candidate.get(key)
                if value in (None, False, "", 0):
                    continue
                return PayloadCoverage.PARTIAL
        return PayloadCoverage.COMPLETE

    def _paging_objects(self, document: Any) -> list[Mapping[str, Any]]:
        """Where a feed may keep its paging metadata: beside the records, or beside a header."""
        if not isinstance(document, Mapping):
            return []
        candidates: list[Mapping[str, Any]] = [document]
        header = document.get(self._paging_key)
        if isinstance(header, Mapping):
            candidates.append(header)
        return candidates

    def parse(self, payload: FetchPayload) -> ParsedPayload:
        if payload.content_type and not payload.content_type.lower().startswith(
            JSON_CONTENT_TYPES_PREFIX
        ):
            logger.info(
                "JOB_SOURCE_UNEXPECTED_CONTENT_TYPE",
                extra={"source_code": self.code, "content_type": payload.content_type},
            )
            return ParsedPayload(records=(), coverage=PayloadCoverage.PARTIAL)
        document = payload.json()
        records: list[RawJobRecord] = []
        for entry in self.entries(document):
            try:
                canonical = self._field_map.canonical(entry)
            except RecordRejectedError as exc:
                logger.info(
                    "JOB_SOURCE_ENTRY_UNMAPPED",
                    extra={
                        "source_code": self.code,
                        "reason": exc.reason,
                        "field": exc.field_name,
                    },
                )
                records.append(
                    RawJobRecord(
                        external_id=entry.get("id"),
                        payload={},
                        detail_url=None,
                    )
                )
                continue
            records.append(
                RawJobRecord(
                    external_id=canonical.get("external_id"),
                    payload=canonical,
                    detail_url=_first_str(canonical.get("detail_url")),
                )
            )
        return ParsedPayload(
            records=tuple(records),
            coverage=self.coverage(document),
        )


def _first_str(value: Any) -> str | None:
    if value is None or isinstance(value, bool | Mapping | list):
        return None
    return str(value)


@dataclass(frozen=True, slots=True)
class Rejection:
    """One refused payload entry. Codes only, never the entry's content."""

    reason: str
    field_name: str | None = None
    count: int = 1


@dataclass(frozen=True, slots=True)
class StageCounts:
    """What each stage produced, for one poll.

    Every field is a count or an identifier. Nothing here is response content,
    which is why the pipeline can log the whole result object.
    """

    fetched_bytes: int = 0
    parsed: int = 0
    normalised: int = 0
    rejected: int = 0
    collapsed: int = 0
    new: int = 0
    updated: int = 0
    deadline_changed: int = 0
    closed: int = 0
    removed: int = 0
    unchanged: int = 0
    events: int = 0
    staged: int = 0

    def __add__(self, other: StageCounts) -> StageCounts:
        return StageCounts(
            fetched_bytes=self.fetched_bytes + other.fetched_bytes,
            parsed=self.parsed + other.parsed,
            normalised=self.normalised + other.normalised,
            rejected=self.rejected + other.rejected,
            collapsed=self.collapsed + other.collapsed,
            new=self.new + other.new,
            updated=self.updated + other.updated,
            deadline_changed=self.deadline_changed + other.deadline_changed,
            closed=self.closed + other.closed,
            removed=self.removed + other.removed,
            unchanged=self.unchanged + other.unchanged,
            events=self.events + other.events,
            staged=self.staged + other.staged,
        )


@dataclass(frozen=True, slots=True)
class IngestionRunResult:
    """Everything one poll of one source produced."""

    source_id: uuid.UUID
    source_code: str
    coverage: PayloadCoverage
    counts: StageCounts = StageCounts()
    rejections: tuple[Rejection, ...] = ()
    warnings: dict[str, int] = field(default_factory=dict)
    change_types: tuple[str, ...] = ()
    job_ids: tuple[uuid.UUID, ...] = ()
    finished_at: datetime = field(default_factory=utcnow)

    @property
    def changed(self) -> int:
        return self.counts.new + self.counts.updated + self.counts.closed + self.counts.removed

    def summary(self) -> dict[str, object]:
        """Loggable counts. Safe to log whole: no third-party content in it."""
        payload = {
            "source_code": self.source_code,
            "coverage": str(self.coverage.value),
            "fetched_bytes": self.counts.fetched_bytes,
            "parsed": self.counts.parsed,
            "normalised": self.counts.normalised,
            "rejected": self.counts.rejected,
            "collapsed": self.counts.collapsed,
            "new": self.counts.new,
            "updated": self.counts.updated,
            "deadline_changed": self.counts.deadline_changed,
            "closed": self.counts.closed,
            "removed": self.counts.removed,
            "unchanged": self.counts.unchanged,
            "events": self.counts.events,
            "staged": self.counts.staged,
        }
        payload.update(self.warnings)
        return payload


__all__ = [
    "JSON_CONTENT_TYPES",
    "FetchPayload",
    "FieldMap",
    "IngestionRunResult",
    "JobSourceConnector",
    "MappingConnector",
    "ParsedPayload",
    "PayloadCoverage",
    "RawJobRecord",
    "Rejection",
    "StageCounts",
]
