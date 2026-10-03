"""External job ingestion: the connector interface and its pipeline.

Seven modules, one direction of dependency:

``safety``
    The SSRF guard. Everything outbound goes through :func:`safe_fetch`, which
    approves a URL or raises. No other module opens a socket, and no endpoint
    anywhere in this API accepts a URL from a client for it to fetch.
``normalize``
    One canonical :class:`NormalizedJob`, or a rejection with a reason.
``dedupe``
    Stable identity - ``(source_id, source_job_id)``, the key
    ``uq_jobs_source_external_id`` already enforces - and nothing else.
``changes``
    A diff against the stored row, emitted as ``JobChangeType`` events.
``base``
    The connector ABC and the pipeline's result types.
``registry``
    Which sources are permitted, at what rate, and when.
``pipeline``
    The six stages, each separately callable, and their ordering.

What is deliberately absent: a connector for any real site. Ingesting a site is a
statement that its terms permit it, and that statement belongs to an administrator
who has reviewed them and set ``job_sources.terms_status = APPROVED``. A library
that has read no terms cannot make it.
"""

from app.services.job_sources.base import (
    FetchPayload,
    FieldMap,
    IngestionRunResult,
    JobSourceConnector,
    MappingConnector,
    ParsedPayload,
    PayloadCoverage,
    RawJobRecord,
    Rejection,
    StageCounts,
)
from app.services.job_sources.changes import (
    AbsenceObservation,
    AbsencePolicy,
    ChangeSet,
    DeadlineChange,
    PublicationDecision,
    PublicationRefusal,
    RemovalSignal,
    decide_status,
    diff_record,
)
from app.services.job_sources.dedupe import (
    NATURAL_KEY_INDEX,
    CollapsedDuplicate,
    DedupeOutcome,
    external_identity,
    natural_key,
)
from app.services.job_sources.normalize import (
    ListingState,
    NormalisationWarning,
    NormaliseOutcome,
    NormalizedJob,
    RecordRejectedError,
    RejectionReason,
    normalize_record,
)
from app.services.job_sources.pipeline import (
    DEFAULT_POLICY,
    IngestionPipeline,
    StageOutcome,
)
from app.services.job_sources.registry import (
    JobSourceRegistry,
    Refusal,
    RefusalReason,
    SourceNotPermittedError,
)
from app.services.job_sources.safety import (
    AddressResolver,
    FetchGuard,
    FetchPolicy,
    FetchRefusedError,
    FetchRefusedReason,
    FetchRequest,
    FetchResponse,
    SafeFetchResult,
    Transport,
    validate_url,
)

__all__ = [
    "DEFAULT_POLICY",
    "NATURAL_KEY_INDEX",
    "AbsenceObservation",
    "AbsencePolicy",
    "AddressResolver",
    "ChangeSet",
    "CollapsedDuplicate",
    "DeadlineChange",
    "DedupeOutcome",
    "FetchGuard",
    "FetchPayload",
    "FetchPolicy",
    "FetchRefusedError",
    "FetchRefusedReason",
    "FetchRequest",
    "FetchResponse",
    "FieldMap",
    "IngestionPipeline",
    "IngestionRunResult",
    "JobSourceConnector",
    "JobSourceRegistry",
    "ListingState",
    "MappingConnector",
    "NormalisationWarning",
    "NormaliseOutcome",
    "NormalizedJob",
    "ParsedPayload",
    "PayloadCoverage",
    "PublicationDecision",
    "PublicationRefusal",
    "RawJobRecord",
    "RecordRejectedError",
    "Refusal",
    "RefusalReason",
    "Rejection",
    "RejectionReason",
    "RemovalSignal",
    "SafeFetchResult",
    "SourceNotPermittedError",
    "StageCounts",
    "StageOutcome",
    "Transport",
    "decide_status",
    "diff_record",
    "external_identity",
    "natural_key",
    "normalize_record",
    "validate_url",
]
