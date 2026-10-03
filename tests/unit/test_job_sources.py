"""The ingestion pipeline, driven entirely from fixture payloads.

Every test here builds its payload by reading a file from
``tests/fixtures/job_sources/`` or by feeding an injected fake transport, so the
suite exercises the real normalising, deduplication and change-detection logic
without a network. The fake transport records the requests it was handed, which is
how the tests assert that the guard - and not the connector - decided the URL.

The claims worth protecting, and the tests that hold them:

* provenance is written once, on creation, and survives every later poll;
* ``(source_id, source_job_id)`` is the identity, so a retitle is an update and a
  second job with the same title is a second job;
* ``first_seen_at`` never moves;
* every change type is emitted, including ``JOB_REMOVED`` on absence, and absence
  alone closes nothing;
* the natural key really is the one the database constrains.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
import pathlib
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import (
    EmploymentType,
    ExperienceLevel,
    JobChangeType,
    JobSourceRobotsStatus,
    JobSourceTermsStatus,
    JobSourceType,
    JobStatus,
)
from app.db.base import utcnow
from app.db.models.job import Job, JobSource, JobSourceEvent
from app.services.job_sources.base import (
    FetchPayload,
    FieldMap,
    IngestionRunResult,
    MappingConnector,
    PayloadCoverage,
    StageCounts,
)
from app.services.job_sources.changes import (
    TRACKED_FIELDS,
    AbsencePolicy,
    ChangeSet,
    PublicationRefusal,
    decide_status,
    diff_record,
)
from app.services.job_sources.dedupe import (
    NATURAL_KEY_INDEX,
    external_identity,
    natural_key,
)
from app.services.job_sources.normalize import (
    ListingState,
    NormalisationWarning,
    NormalizedJob,
    RecordRejectedError,
    RejectionReason,
    normalize_record,
    payload_source_hosts,
)
from app.services.job_sources.pipeline import IngestionPipeline
from app.services.job_sources.registry import (
    JobSourceRegistry,
    RefusalReason,
    SourceNotPermittedError,
)
from app.services.job_sources.safety import (
    FetchGuard,
    FetchPolicy,
    FetchRefusedError,
    FetchRequest,
    FetchResponse,
    Transport,
    host_is_allowed,
)

#: Ingestion writes provenance the database constrains, so these tests need a real
#: session even though they live beside the other unit tests.
pytestmark = [pytest.mark.unit, pytest.mark.integration]

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "job_sources"

BOARD_URL = "https://jobs.example.com/feed.json"
PARTNER_URL = "https://partner.example.com/api/v2/listings"

NOW = datetime(2026, 9, 1, 6, 0, tzinfo=UTC)
LATER = datetime(2026, 9, 12, 6, 0, tzinfo=UTC)

DNS: dict[str, tuple[str, ...]] = {
    "jobs.example.com": ("93.184.216.34",),
    "partner.example.com": ("93.184.216.34",),
}


def resolver(host: str, port: int = 443) -> tuple[str, ...]:
    """A resolver that reads a table. Raises on anything unknown, so nothing dials out."""
    if host in DNS:
        return DNS[host]
    raise OSError(f"Name or service not known: {host}")


def fixture_bytes(name: str) -> bytes:
    """Read a fixture payload from disk. Never from the network."""
    return (FIXTURES / name).read_bytes()


class FixtureTransport(Transport):
    """Serves fixture bytes, optionally following a scripted sequence of URLs."""

    def __init__(
        self,
        bodies: dict[str, bytes] | None = None,
        default: bytes = b"{}",
        content_type: str = "application/json; charset=utf-8",
    ) -> None:
        self.bodies = dict(bodies or {})
        self.default = default
        self.content_type = content_type
        self.requests: list[FetchRequest] = []

    def fetch(self, request: FetchRequest) -> FetchResponse:
        self.requests.append(request)
        body = self.bodies.get(request.target.url, self.default)
        return FetchResponse(
            url=request.target.url,
            status_code=200,
            body=body,
            headers={"Content-Type": self.content_type},
            declared_length=len(body),
        )


def make_source(
    session: Session,
    *,
    code: str | None = None,
    base_url: str | None = BOARD_URL,
    source_type: JobSourceType = JobSourceType.AGGREGATED_PUBLIC,
    terms_status: JobSourceTermsStatus = JobSourceTermsStatus.APPROVED,
    robots_status: JobSourceRobotsStatus = JobSourceRobotsStatus.PERMITTED,
    is_active: bool = True,
    **kwargs: object,
) -> JobSource:
    source = JobSource(
        code=code or f"src-{uuid.uuid4().hex[:8]}",
        name="Coastal Jobs Board",
        source_type=source_type.value,
        base_url=base_url,
        terms_status=terms_status.value,
        robots_status=robots_status.value,
        is_active=is_active,
        **kwargs,  # type: ignore[arg-type]
    )
    session.add(source)
    session.flush()
    return source


#: The canonical mapping for the coastal aggregator fixture.
BOARD_FIELDS = FieldMap(
    source={
        "id": "external_id",
        "headline": "title",
        "body_html": "description",
        "town": "location",
        "contract_type": "employment_type",
        "seniority": "experience_level",
        "years_required": "experience_required_years",
        "pay": "salary",
        "pay_text": "salary",
        "listed_at": "published_at",
        "closing_at": "closing_at",
        "applications_close": "closing_in",
        "closing_in_days": "closing_in_days",
        "state": "status",
        "web_url": "detail_url",
        "apply_url": "apply_url",
    },
    required=("external_id", "title", "description"),
)


def board_connector(
    source: JobSource,
    *,
    transport: Transport | None = None,
    bodies: dict[str, bytes] | None = None,
) -> MappingConnector:
    fetch_transport = transport or FixtureTransport(
        bodies or {BOARD_URL: fixture_bytes("coastal_board.json")}
    )
    return MappingConnector(
        guard=FetchGuard(
            FetchPolicy.from_source(source), resolver=resolver, transport=fetch_transport
        ),
        code=source.code,
        records_key="results",
        field_map=BOARD_FIELDS,
        apply_hosts=frozenset({"apply.partner-ats.example.com"}),
    )


PARTNER_FIELDS = FieldMap(
    source={
        "reference": "external_id",
        "title": "title",
        "summary": "description",
        "location": "location",
        "engagement": "employment_type",
        "grade": "experience_level",
        "experience": "experience_required_years",
        "compensation": "salary",
        "posted": "published_at",
        "deadline": "closing_at",
        "status": "status",
        "href": "detail_url",
        "apply_href": "apply_url",
    }
)


def partner_source(session: Session) -> JobSource:
    return make_source(session, base_url=PARTNER_URL, source_type=JobSourceType.PARTNER_FEED)


def partner_connector(source: JobSource, *, transport: Transport | None = None) -> MappingConnector:
    fetch_transport = transport or FixtureTransport(
        {PARTNER_URL: fixture_bytes("partner_feed.json")}
    )
    return MappingConnector(
        guard=FetchGuard(
            FetchPolicy.from_source(source), resolver=resolver, transport=fetch_transport
        ),
        code=source.code,
        records_key="data",
        field_map=PARTNER_FIELDS,
        source_type=JobSourceType.PARTNER_FEED,
        apply_hosts=frozenset({"partner.example.com"}),
    )


def run_pipeline(
    session: Session,
    connector: MappingConnector,
    source: JobSource,
    *,
    now: datetime = NOW,
    policy: AbsencePolicy | None = None,
) -> IngestionRunResult:
    pipeline = IngestionPipeline(session, guard=connector.guard, policy=policy or AbsencePolicy())
    return pipeline.run(connector, source, now=now)


def jobs_for(session: Session, source: JobSource) -> list[Job]:
    return list(
        session.execute(
            select(Job)
            .where(Job.source_id == source.id, Job.deleted_at.is_(None))
            .order_by(Job.source_job_id)
        ).scalars()
    )


def events_for(session: Session, source: JobSource) -> list[JobSourceEvent]:
    return list(
        session.execute(
            select(JobSourceEvent)
            .where(JobSourceEvent.source_id == source.id)
            .order_by(JobSourceEvent.detected_at, JobSourceEvent.change_type)
        ).scalars()
    )


def event_types(session: Session, source: JobSource) -> list[str]:
    return [event.change_type for event in events_for(session, source)]


def job_by_id(session: Session, source: JobSource, external_id: str) -> Job:
    return next(job for job in jobs_for(session, source) if job.source_job_id == external_id)


# --------------------------------------------------------------------------- #
# Stage 1-3: fetch, parse, normalise                                         #
# --------------------------------------------------------------------------- #
def test_the_fetch_stage_asks_the_guard_for_the_registered_endpoint(db_session: Session) -> None:
    source = make_source(db_session)
    transport = FixtureTransport({BOARD_URL: fixture_bytes("coastal_board.json")})
    connector = board_connector(source, transport=transport)
    pipeline = IngestionPipeline(db_session, guard=connector.guard)

    payload = pipeline.fetch(connector, source)

    assert payload.url == BOARD_URL
    assert payload.content_type == "application/json; charset=utf-8"
    assert payload.coverage is PayloadCoverage.COMPLETE
    assert payload.size_bytes == len(fixture_bytes("coastal_board.json"))
    assert [request.target.host for request in transport.requests] == ["jobs.example.com"]
    assert transport.requests[0].max_bytes == pipeline.guard.policy.max_response_bytes
    assert transport.requests[0].timeout_seconds > 0


def test_the_parse_stage_finds_every_entry_including_the_duplicate(db_session: Session) -> None:
    source = make_source(db_session)
    connector = board_connector(source)
    pipeline = IngestionPipeline(db_session, guard=connector.guard)

    payload = pipeline.fetch(connector, source)
    parsed = pipeline.parse(connector, payload)

    assert len(parsed) == 6
    assert parsed.coverage is PayloadCoverage.COMPLETE
    assert [str(record.external_id) for record in parsed.records][:3] == [
        "CB-4411",
        "CB-4412",
        "CB-4411",
    ]


def test_the_normalise_stage_coerces_a_third_party_payload(db_session: Session) -> None:
    source = make_source(db_session)
    connector = board_connector(source)
    pipeline = IngestionPipeline(db_session, guard=connector.guard)

    outcome = pipeline.normalise(
        connector,
        pipeline.parse(connector, pipeline.fetch(connector, source)),
        source=source,
        now=NOW,
    )

    # Positional: the fixture deliberately repeats one id, and a dict keyed by it
    # would keep whichever came last.
    assert len(outcome.records) == 6
    # The sixth is a duplicate of the first under the same id with a different
    # headline, which is what the dedupe stage exists for.
    duplicate_index = next(
        index
        for index, record in enumerate(outcome.records)
        if index > 0 and record.source_job_id == outcome.records[0].source_job_id
    )
    first = outcome.records[0]
    assert outcome.records[duplicate_index].title != first.title
    by_id = {record.source_job_id: record for record in outcome.records}
    # Keep the first sighting: which of a duplicate pair survives is the dedupe
    # stage's decision, not this stage's.
    by_id[first.source_job_id] = first
    assert outcome.rejected_count == 0
    mason = by_id["CB-4411"]
    assert mason.title == "Experienced Mason Needed for Residential Development"
    # HTML is projected to plain text and entities are decoded.
    assert "<b>" not in mason.description
    assert "Bamburi" in mason.description
    assert NormalisationWarning.DESCRIPTION_STRIPPED in mason.warnings
    assert mason.location == "Mombasa"
    assert mason.experience_required_years == 5
    assert (mason.salary_min, mason.salary_max) == (45000, 60000)
    assert mason.salary_currency == "KES"
    assert mason.salary_period == "MONTHLY"
    assert mason.published_at == datetime(2026, 8, 28, 9, 15, tzinfo=UTC)
    # "21 days" after the posting date, not after whenever we happened to poll.
    assert mason.closing_at == datetime(2026, 8, 28, 9, 15, tzinfo=UTC) + timedelta(days=21)
    assert mason.listing_state is ListingState.OPEN
    assert mason.is_confirmed_open
    assert mason.apply_url == "https://jobs.example.com/listing/cb-4411/apply"

    plumber = by_id["CB-4412"]
    # Prose salary: "KSh 1,200 per day".
    assert (plumber.salary_min, plumber.salary_max, plumber.salary_period) == (1200, 1200, "DAILY")
    assert plumber.salary_currency == "KES"
    # Epoch seconds are understood, and relative deadlines are translated.
    assert plumber.published_at == datetime.fromtimestamp(1755000000, tz=UTC)
    assert plumber.closing_at == plumber.published_at + timedelta(days=3)
    # An applicant-tracking host the connector declared explicitly is kept.
    assert plumber.apply_url == "https://apply.partner-ats.example.com/jobs/4412"

    unrecognised = by_id["CB-4416"]
    assert unrecognised.listing_state is ListingState.UNKNOWN
    assert not unrecognised.is_confirmed_open
    # "Mid" is in our vocabulary; the rest of that record's vocabulary is not.
    assert unrecognised.experience_level == ExperienceLevel.INTERMEDIATE
    assert unrecognised.employment_type == EmploymentType.FULL_TIME
    # "2+ years" is readable; "lots" in the other fixture is not.
    assert unrecognised.experience_required_years == 2
    # "USD 900 per month" is readable after all, and is stored in its own currency.
    assert (unrecognised.salary_min, unrecognised.salary_currency) == (900, "USD")
    assert unrecognised.salary_period == "MONTHLY"
    assert unrecognised.closing_at == datetime(2026, 8, 20, 11, 30, tzinfo=UTC) + timedelta(days=10)

    closed = by_id["CB-4415"]
    assert closed.listing_state is ListingState.CLOSED
    assert closed.is_closed_by_source
    assert not closed.is_confirmed_open
    # A naive date is recorded as UTC with a warning, never dropped.
    naive = by_id["CB-4414"]
    assert naive.published_at == datetime(2026, 8, 30, tzinfo=UTC)
    assert NormalisationWarning.DATE_ASSUMED_UTC in naive.warnings


def test_the_payload_hash_identifies_the_exact_entry(db_session: Session) -> None:
    source = make_source(db_session)
    connector = board_connector(source)
    pipeline = IngestionPipeline(db_session, guard=connector.guard)
    outcome = pipeline.normalise(
        connector,
        pipeline.parse(connector, pipeline.fetch(connector, source)),
        source=source,
        now=NOW,
    )
    hashes = {record.source_job_id: record.payload_hash for record in outcome.records}
    assert len(hashes["CB-4411"]) == 64
    assert hashes["CB-4411"] != hashes["CB-4412"]


def test_a_second_parser_shape_is_supported(db_session: Session) -> None:
    """A partner feed: records under a key, cursor paging, snake_case fields."""
    source = partner_source(db_session)
    connector = partner_connector(source)
    pipeline = IngestionPipeline(db_session, guard=connector.guard)

    payload = pipeline.fetch(connector, source)
    parsed = pipeline.parse(connector, payload)
    outcome = pipeline.normalise(connector, parsed, source=source, now=NOW)

    assert len(parsed) == 3
    # A cursor is present, so the payload accounts for only part of the source.
    assert parsed.coverage is PayloadCoverage.PARTIAL
    by_id = {record.source_job_id: record for record in outcome.records}
    assert set(by_id) == {"PF-2026-0001", "PF-2026-0002", "PF-2026-0003"}
    supervisor = by_id["PF-2026-0003"]
    assert supervisor.listing_state is ListingState.EXPIRED
    assert supervisor.salary_min == 180000
    assert supervisor.salary_period == "MONTHLY"
    assert supervisor.closing_at == datetime(2026, 9, 20, 17, 0, tzinfo=UTC)
    # A relative deadline in the partner vocabulary is translated, not dropped.
    carpenter = by_id["PF-2026-0002"]
    assert carpenter.closing_at is not None
    # The apply link on the source's own host is kept...
    assert by_id["PF-2026-0001"].apply_url == ("https://partner.example.com/apply/PF-2026-0001")
    # ...and one on a host nobody reviewed is dropped rather than rendered.
    assert by_id["PF-2026-0003"].apply_url is None
    assert NormalisationWarning.APPLY_URL_DROPPED in by_id["PF-2026-0003"].warnings


def test_a_html_response_is_not_parsed_as_a_feed(db_session: Session) -> None:
    source = make_source(db_session)
    transport = FixtureTransport(
        {BOARD_URL: b"<html><body>maintenance</body></html>"},
        content_type="text/html; charset=utf-8",
    )
    connector = board_connector(source, transport=transport)
    pipeline = IngestionPipeline(db_session, guard=connector.guard)

    payload = pipeline.fetch(connector, source)
    parsed = pipeline.parse(connector, payload)

    assert len(parsed) == 0
    assert parsed.coverage is PayloadCoverage.PARTIAL


# --------------------------------------------------------------------------- #
# Stage 4: deduplicate                                                        #
# --------------------------------------------------------------------------- #
def test_a_duplicate_inside_one_payload_is_collapsed(db_session: Session) -> None:
    source = make_source(db_session)
    connector = board_connector(source)
    pipeline = IngestionPipeline(db_session, guard=connector.guard)
    outcome = pipeline.normalise(
        connector,
        pipeline.parse(connector, pipeline.fetch(connector, source)),
        source=source,
        now=NOW,
    )

    deduped = pipeline.deduplicate(outcome.records, source=source)

    # Five distinct ids in the fixture, one of which arrives twice.
    assert len(outcome.records) == 6
    assert len(deduped.new) == 5
    assert [item.source_job_id for item in deduped.collapsed] == ["CB-4411"]
    assert deduped.total == 6


def test_two_listings_sharing_a_title_are_two_jobs(db_session: Session) -> None:
    """``CB-4411`` and ``CB-4414`` have the same headline and are both ingested."""
    source = make_source(db_session)
    result = run_pipeline(db_session, board_connector(source), source)

    jobs = jobs_for(db_session, source)
    titles = {job.title for job in jobs}
    assert result.counts.new == 5
    assert len(jobs) == 5
    assert titles == {
        "Experienced Mason Needed for Residential Development",
        "Plumber - Immediate Start",
        "Scaffolder for High Rise Project",
        "Electrician - Site Maintenance",
    }
    shared = [
        job for job in jobs if job.title == "Experienced Mason Needed for Residential Development"
    ]
    assert len(shared) == 2
    assert {job.source_job_id for job in shared} == {"CB-4411", "CB-4414"}
    assert {job.location for job in shared} == {"Mombasa", "Nyali"}


def test_the_same_id_from_two_sources_is_two_jobs(db_session: Session) -> None:
    """Identity is scoped to a source: the same identifier elsewhere is its own job."""
    first = make_source(db_session)
    second = make_source(db_session)
    board = board_connector(first)
    partner = board_connector(second)

    run_pipeline(db_session, board, first)
    run_pipeline(db_session, partner, second)

    assert len(jobs_for(db_session, first)) == 5
    assert len(jobs_for(db_session, second)) == 5
    assert natural_key(first.id, "CB-4411") != natural_key(second.id, "CB-4411")
    assert (
        external_identity(
            normalize_record(
                {
                    "external_id": "CB-4411",
                    "title": "Mason",
                    "description": "A mason is required for a residential development.",
                    "detail_url": "https://jobs.example.com/listing/cb-4411",
                },
                source=first,
                policy=board.guard.policy,
            )
        )
        == "CB-4411"
    )


def test_the_natural_key_is_the_one_the_database_constrains() -> None:
    """The dedupe key and the unique index must agree, or dedupe is a no-op."""
    indexes = {index.name: index for index in Job.__table__.indexes}
    assert NATURAL_KEY_INDEX in indexes
    unique_index = indexes[NATURAL_KEY_INDEX]
    assert unique_index.unique
    assert [column.name for column in unique_index.columns] == ["source_id", "source_job_id"]
    assert "source_job_id IS NOT NULL" in str(unique_index.dialect_options["postgresql"]["where"])


# --------------------------------------------------------------------------- #
# Stage 5-6: detect and store                                                  #
# --------------------------------------------------------------------------- #
def test_provenance_is_complete_on_every_ingested_row(db_session: Session) -> None:
    source = make_source(db_session)
    result = run_pipeline(db_session, board_connector(source), source)

    assert result.counts.new == 5
    for job in jobs_for(db_session, source):
        assert job.source_id == source.id
        assert job.source_type == JobSourceType.AGGREGATED_PUBLIC.value
        assert job.source_name == source.name
        assert job.source_url.startswith("https://jobs.example.com/listing/")
        assert job.source_job_id
        assert job.first_seen_at == NOW
        assert job.last_seen_at == NOW
        assert job.is_aggregated is True
        # An aggregated listing is owned by its source, never by an employer.
        assert job.organization_id is None
        assert job.created_by_user_id is None


def test_last_verified_at_advances_only_for_a_listing_confirmed_open(
    db_session: Session,
) -> None:
    source = make_source(db_session)
    run_pipeline(db_session, board_connector(source), source, now=NOW)

    confirmed = job_by_id(db_session, source, "CB-4411")
    not_confirmed = job_by_id(db_session, source, "CB-4415")
    unknown = job_by_id(db_session, source, "CB-4416")
    assert confirmed.last_verified_at == NOW
    # CB-4415 states it is closed and CB-4416 says something we do not recognise.
    # Neither was confirmed, so neither may claim to have been.
    assert not_confirmed.last_verified_at is None
    assert unknown.last_verified_at is None


def test_the_second_poll_creates_nothing_new(db_session: Session) -> None:
    """Re-seeing the same payload is a no-op: identity, not similarity."""
    source = make_source(db_session)
    board = board_connector(source)

    first = run_pipeline(db_session, board, source, now=NOW)
    second = run_pipeline(db_session, board, source, now=LATER)

    assert first.counts.new == 5
    assert second.counts.new == 0
    assert second.counts.unchanged == 5
    assert len(jobs_for(db_session, source)) == 5
    assert event_types(db_session, source) == [JobChangeType.NEW_JOB.value] * 5
    # Unchanged listings are still re-seen, which is what last_seen_at records.
    assert job_by_id(db_session, source, "CB-4411").last_seen_at == LATER


def test_a_retitle_is_the_same_job_and_not_a_new_one(db_session: Session) -> None:
    source = make_source(db_session)
    run_pipeline(db_session, board_connector(source), source, now=NOW)
    before = job_by_id(db_session, source, "CB-4411")
    original_id = before.id

    next_poll = FixtureTransport({BOARD_URL: fixture_bytes("coastal_board_next_poll.json")})
    result = run_pipeline(
        db_session, board_connector(source, transport=next_poll), source, now=LATER
    )

    after = job_by_id(db_session, source, "CB-4411")
    assert result.counts.new == 0
    assert len(jobs_for(db_session, source)) == 5
    assert after.id == original_id
    assert after.source_job_id == "CB-4411"
    assert after.title == "Experienced Mason (Blockwork) - Housing Estate"
    assert JobChangeType.JOB_UPDATED.value in event_types(db_session, source)


def test_a_changed_deadline_emits_deadline_changed(db_session: Session) -> None:
    source = make_source(db_session)
    run_pipeline(db_session, board_connector(source), source, now=NOW)
    before = job_by_id(db_session, source, "CB-4411").closing_at

    next_poll = FixtureTransport({BOARD_URL: fixture_bytes("coastal_board_next_poll.json")})
    result = run_pipeline(
        db_session, board_connector(source, transport=next_poll), source, now=LATER
    )

    after = job_by_id(db_session, source, "CB-4411")
    assert after.closing_at > before
    assert result.counts.deadline_changed == 1
    events = events_for(db_session, source)
    deadline = next(e for e in events if e.change_type == JobChangeType.DEADLINE_CHANGED.value)
    assert deadline.job_id == after.id
    assert "closing_at extended" in (deadline.detail or "")
    assert deadline.payload_hash == after.source_job_id[:0] + (deadline.payload_hash or "")
    assert deadline.detected_at == LATER


def test_a_source_that_says_closed_emits_job_closed(db_session: Session) -> None:
    source = make_source(db_session)
    run_pipeline(db_session, board_connector(source), source, now=NOW)

    next_poll = FixtureTransport({BOARD_URL: fixture_bytes("coastal_board_next_poll.json")})
    result = run_pipeline(
        db_session, board_connector(source, transport=next_poll), source, now=LATER
    )

    closed = job_by_id(db_session, source, "CB-4416")
    assert result.counts.closed == 1
    assert JobChangeType.JOB_CLOSED.value in event_types(db_session, source)
    assert closed.last_seen_at == LATER
    # The source said it ended, so the listing is no longer confirmed open.
    assert closed.last_verified_at is None


def test_absence_from_a_complete_poll_emits_job_removed_and_closes_nothing(
    db_session: Session,
) -> None:
    source = make_source(db_session)
    run_pipeline(db_session, board_connector(source), source, now=NOW)
    before = job_by_id(db_session, source, "CB-4415")

    next_poll = FixtureTransport({BOARD_URL: fixture_bytes("coastal_board_next_poll.json")})
    result = run_pipeline(
        db_session, board_connector(source, transport=next_poll), source, now=LATER
    )

    after = job_by_id(db_session, source, "CB-4415")
    assert result.counts.removed == 1
    removal = next(
        event
        for event in events_for(db_session, source)
        if event.change_type == JobChangeType.JOB_REMOVED.value
    )
    assert removal.job_id == after.id
    assert "absent from a complete poll" in (removal.detail or "")
    # One missing entry is an observation, not a closure.
    assert after.status == before.status
    assert after.deleted_at is None
    assert after.last_seen_at == before.last_seen_at
    assert after.first_seen_at == before.first_seen_at


def test_an_absence_policy_may_close_after_the_agreed_number_of_absences(
    db_session: Session,
) -> None:
    """Only a policy closes on absence, and it counts from the ledger, not memory."""
    source = make_source(db_session)
    board = board_connector(source)
    run_pipeline(db_session, board, source, now=NOW)

    closing_in_one = FixtureTransport({BOARD_URL: fixture_bytes("coastal_board_next_poll.json")})
    pipeline = IngestionPipeline(
        db_session, guard=board.guard, policy=AbsencePolicy(close_after_absences=1)
    )
    pipeline.run(board_connector(source, transport=closing_in_one), source, now=LATER)

    after = job_by_id(db_session, source, "CB-4415")
    types = event_types(db_session, source)
    assert types.count(JobChangeType.JOB_REMOVED.value) == 1
    assert JobChangeType.JOB_CLOSED.value in types
    # The schema refuses to close an unattributed aggregated listing, so the row
    # stays where it was and the event records what the source said.
    assert after.status == JobStatus.DRAFT.value


def test_a_partial_poll_proves_nothing(db_session: Session) -> None:
    """A truncated page must never remove a listing."""
    source = partner_source(db_session)
    board = partner_connector(source)
    run_pipeline(db_session, board, source, now=NOW, policy=AbsencePolicy(close_after_absences=1))
    assert len(jobs_for(db_session, source)) == 3

    one_record = json.loads(fixture_bytes("partner_feed.json"))
    one_record["data"] = one_record["data"][:1]
    one_record["meta"]["next_cursor"] = "still-more"
    narrowed = FixtureTransport({PARTNER_URL: json.dumps(one_record).encode("utf-8")})
    run_pipeline(
        db_session,
        partner_connector(source, transport=narrowed),
        source,
        now=LATER,
        policy=AbsencePolicy(close_after_absences=1),
    )

    assert len(jobs_for(db_session, source)) == 3
    assert JobChangeType.JOB_REMOVED.value not in event_types(db_session, source)
    assert JobChangeType.NEW_JOB.value in event_types(db_session, source)


def test_first_seen_at_never_moves(db_session: Session) -> None:
    """Not on a retitle, not on a deadline change, not on a re-poll."""
    source = make_source(db_session)
    run_pipeline(db_session, board_connector(source), source, now=NOW)
    original = {job.source_job_id: job.first_seen_at for job in jobs_for(db_session, source)}

    next_poll = FixtureTransport({BOARD_URL: fixture_bytes("coastal_board_next_poll.json")})
    run_pipeline(db_session, board_connector(source, transport=next_poll), source, now=LATER)
    run_pipeline(
        db_session,
        board_connector(source, transport=next_poll),
        source,
        now=LATER + timedelta(days=1),
    )

    for job in jobs_for(db_session, source):
        assert job.first_seen_at == original[job.source_job_id] == NOW
        assert job.last_seen_at >= NOW


def test_every_change_type_can_be_emitted(db_session: Session) -> None:
    """All five members, from two polls of the same fixtures."""
    source = make_source(db_session)
    run_pipeline(db_session, board_connector(source), source, now=NOW)
    next_poll = FixtureTransport({BOARD_URL: fixture_bytes("coastal_board_next_poll.json")})
    run_pipeline(db_session, board_connector(source, transport=next_poll), source, now=LATER)

    emitted = set(event_types(db_session, source))
    assert emitted == {
        JobChangeType.NEW_JOB.value,
        JobChangeType.JOB_UPDATED.value,
        JobChangeType.DEADLINE_CHANGED.value,
        JobChangeType.JOB_CLOSED.value,
        JobChangeType.JOB_REMOVED.value,
    }
    for event in events_for(db_session, source):
        assert event.detected_at in {NOW, LATER}
        assert event.source_id == source.id
        assert event.detail
        # A response body is third-party text; the ledger records names, not content.
        assert "Bamburi" not in (event.detail or "")


def test_a_changed_field_is_named_and_its_value_is_not_recorded(
    db_session: Session,
) -> None:
    source = make_source(db_session)
    run_pipeline(db_session, board_connector(source), source, now=NOW)
    next_poll = FixtureTransport({BOARD_URL: fixture_bytes("coastal_board_next_poll.json")})
    run_pipeline(db_session, board_connector(source, transport=next_poll), source, now=LATER)

    update = next(
        event
        for event in events_for(db_session, source)
        if event.change_type == JobChangeType.JOB_UPDATED.value
    )
    assert "fields=" in (update.detail or "")
    assert "title" in (update.detail or "")
    assert "description" in (update.detail or "")
    assert "Housing Estate" not in (update.detail or "")


def test_malformed_entries_are_refused_with_a_reason_and_the_poll_continues(
    db_session: Session,
) -> None:
    source = make_source(db_session)
    transport = FixtureTransport({BOARD_URL: fixture_bytes("malformed_board.json")})
    result = run_pipeline(db_session, board_connector(source, transport=transport), source, now=NOW)

    reasons = {item.reason: item.count for item in result.rejections}
    assert reasons == {
        RejectionReason.MISSING_EXTERNAL_ID: 1,
        RejectionReason.MISSING_TITLE: 1,
        RejectionReason.TITLE_TOO_LONG: 1,
        RejectionReason.SOURCE_URL_NOT_ALLOWED: 2,  # unreviewed host, and http
        RejectionReason.MISSING_SOURCE_URL: 1,
        RejectionReason.LOCATION_TOO_LONG: 1,
    }
    assert result.counts.rejected == 7
    # The one good entry still lands, and nothing from the bad ones does.
    assert result.counts.new == 2
    assert {job.source_job_id for job in jobs_for(db_session, source)} == {"CB-9007", "CB-9008"}
    salvaged = job_by_id(db_session, source, "CB-9007")
    # Nothing is invented for the parts the feed would not state.
    assert salvaged.salary_min is None
    assert salvaged.experience_required_years is None
    assert salvaged.closing_at is None
    # An apply URL on a host nobody reviewed is dropped rather than rendered.
    assert salvaged.external_apply_url is None
    # ...while the listing itself is still ingested, with its provenance intact.
    assert salvaged.source_job_id == "CB-9007"
    assert salvaged.source_url == "https://jobs.example.com/listing/cb-9007"
    assert result.warnings[NormalisationWarning.EMPLOYMENT_TYPE_DEFAULTED] == 1
    assert result.warnings[NormalisationWarning.APPLY_URL_DROPPED] == 1


def test_a_publication_refusal_is_recorded_rather_than_misattributed(
    db_session: Session,
) -> None:
    """The schema forbids publishing an aggregated listing with no owner."""
    source = make_source(db_session)
    result = run_pipeline(db_session, board_connector(source), source, now=NOW)

    assert result.counts.staged == 5
    for job in jobs_for(db_session, source):
        assert job.status == JobStatus.DRAFT.value
    new_job = next(
        event
        for event in events_for(db_session, source)
        if event.change_type == JobChangeType.NEW_JOB.value
    )
    assert "staged without publication" in (new_job.detail or "")
    assert PublicationRefusal.ATTRIBUTION_REQUIRED in (new_job.detail or "")


def test_decide_status_publishes_when_an_owner_exists() -> None:
    decision = decide_status(
        source_type=JobSourceType.AGGREGATED_PUBLIC.value,
        has_organization=True,
        requested=JobStatus.OPEN,
    )
    assert decision.publishable
    assert decision.status is JobStatus.OPEN


def test_decide_status_refuses_rather_than_inventing_an_owner() -> None:
    decision = decide_status(
        source_type=JobSourceType.AGGREGATED_PUBLIC.value,
        has_organization=False,
        requested=JobStatus.OPEN,
    )
    assert not decision.publishable
    assert decision.status is JobStatus.DRAFT
    assert decision.refusal == PublicationRefusal.ATTRIBUTION_REQUIRED


def test_an_ingested_row_is_not_reported_as_an_employers_posting(db_session: Session) -> None:
    """The disclosure rule that makes an aggregated listing lawful: no owner."""
    source = make_source(db_session)
    run_pipeline(db_session, board_connector(source), source, now=NOW)
    for job in jobs_for(db_session, source):
        assert job.organization_id is None
        assert job.is_platform_owned is False
        assert job.accepts_applications is False
        assert job.source_name == source.name


def test_a_refused_fetch_is_recorded_against_the_source_and_runs_nothing(
    db_session: Session,
) -> None:
    """An unreachable feed is an operational fact, not a crashed poll."""
    source = make_source(db_session, base_url="http://jobs.example.com")
    connector = board_connector(source)
    result = run_pipeline(db_session, connector, source, now=NOW)

    assert result.counts == StageCounts()
    assert result.coverage is PayloadCoverage.PARTIAL
    assert jobs_for(db_session, source) == []
    assert source.last_checked_at == NOW
    assert source.last_error is not None
    assert len(source.last_error) <= 512


def test_a_source_is_polled_within_its_own_rate_limit(db_session: Session) -> None:
    source = make_source(db_session, rate_limit_per_minute=10)
    connector = board_connector(source)
    registry = JobSourceRegistry(db_session)

    run_pipeline(db_session, connector, source, now=NOW)
    assert source.last_checked_at == NOW
    assert not registry.is_due(source, now=NOW)
    # 10 per minute is one request every six seconds.
    assert not registry.is_due(source, now=NOW + timedelta(seconds=5))
    assert registry.is_due(source, now=NOW + timedelta(seconds=7))
    assert [source] == registry.due(now=NOW + timedelta(seconds=7))

    with pytest.raises(SourceNotPermittedError):
        run_pipeline(db_session, connector, source, now=NOW + timedelta(seconds=1))


def test_a_manual_re_ingest_may_decline_to_enforce_the_rate_limit(
    db_session: Session,
) -> None:
    source = make_source(db_session, rate_limit_per_minute=1)
    connector = board_connector(source)
    pipeline = IngestionPipeline(db_session, guard=connector.guard)

    pipeline.run(connector, source, now=NOW)
    second = pipeline.run(connector, source, now=NOW, enforce_rate_limit=False)

    assert second.counts.unchanged == 5
    assert len(jobs_for(db_session, source)) == 5


def test_the_registry_refuses_to_ingest_an_unapproved_source(db_session: Session) -> None:
    source = make_source(db_session, terms_status=JobSourceTermsStatus.UNDER_REVIEW, is_active=True)
    connector = board_connector(source)
    with pytest.raises(SourceNotPermittedError) as excinfo:
        run_pipeline(db_session, connector, source)
    assert excinfo.value.reason.startswith("terms_not_approved")
    assert jobs_for(db_session, source) == []


def test_a_connector_is_only_applied_to_the_source_it_was_written_for(
    db_session: Session,
) -> None:
    source = make_source(db_session)
    connector = board_connector(source)
    registry = JobSourceRegistry(db_session)

    assert registry.connector_for(source, [connector]) is connector
    with pytest.raises(SourceNotPermittedError):
        registry.connector_for(source, [])
    other = make_source(db_session)
    with pytest.raises(SourceNotPermittedError):
        registry.connector_for(other, [connector])


def stored_equivalent(job: Job) -> NormalizedJob:
    """A normalised record that would produce no change at all.

    Built from the stored row through the tracked-field table, so it stays correct
    if that table changes: this is what "nothing material differed" means.
    """
    values: dict[str, object] = {
        "source_job_id": job.source_job_id or "",
        "listing_state": ListingState.OPEN,
        # Not a tracked column: the deadline has its own change type.
        "closing_at": job.closing_at,
    }
    for column, field_name in TRACKED_FIELDS:
        values[field_name] = getattr(job, column)
    return NormalizedJob(**values)  # type: ignore[arg-type]


def test_diff_record_reports_only_what_differed(db_session: Session) -> None:
    source = make_source(db_session)
    run_pipeline(db_session, board_connector(source), source, now=NOW)
    job = job_by_id(db_session, source, "CB-4411")

    unchanged = stored_equivalent(job)
    assert not diff_record(unchanged, job).has_changes

    change_set = diff_record(replace(unchanged, title="Something else entirely"), job)
    assert change_set.change_types == (JobChangeType.JOB_UPDATED,)
    assert change_set.field_changes == ("title",)
    assert "fields=title" in change_set.describe()

    deadline_set = diff_record(
        replace(unchanged, closing_at=(job.closing_at or NOW) + timedelta(days=7)), job
    )
    assert deadline_set.change_types == (JobChangeType.DEADLINE_CHANGED,)
    assert deadline_set.deadline is not None
    assert deadline_set.deadline.extended
    assert "closing_at extended" in deadline_set.describe()

    shortened = diff_record(
        replace(unchanged, closing_at=(job.closing_at or NOW) - timedelta(days=7)), job
    )
    assert shortened.deadline is not None
    assert not shortened.deadline.extended
    assert "closing_at shortened" in shortened.describe()

    # A deadline the source removed is still a change, and saying which way matters.
    removed_deadline = diff_record(replace(unchanged, closing_at=None), job)
    assert removed_deadline.deadline_changed
    assert "closing_at removed" in removed_deadline.describe()

    # Nothing changed here, so the ledger stays silent rather than churning.
    assert not diff_record(replace(unchanged, title=job.title or ""), job).has_changes


# --------------------------------------------------------------------------- #
# Stages are separately callable                                               #
# --------------------------------------------------------------------------- #
def test_every_stage_runs_on_its_own(db_session: Session) -> None:
    """The stages compose, but none of them needs the ones above it to be exercised."""
    source = make_source(db_session)
    connector = board_connector(source)
    pipeline = IngestionPipeline(db_session, guard=connector.guard)

    payload = connector.collect(source)
    parsed = connector.parse(payload)
    outcome = connector.normalise(parsed.records, source=source, now=NOW)
    deduped = pipeline.deduplicate(outcome.records, source=source)
    entries = pipeline.plan(deduped, source=source, coverage=parsed.coverage, now=NOW)
    stored = pipeline.store(entries, source=source, now=NOW)

    assert len(parsed.records) == 6
    assert len(outcome.records) == 6
    assert len(deduped.new) == 5
    assert len(entries) == 5
    assert stored.counts.new == 5
    assert stored.counts.events == 5
    assert len(stored.new_job_ids) == 5
    assert len(stored.changed_job_ids) == 5
    assert len(jobs_for(db_session, source)) == 5


def test_the_result_object_carries_counts_and_never_content(db_session: Session) -> None:
    source = make_source(db_session)
    result = run_pipeline(db_session, board_connector(source), source, now=NOW)
    summary = result.summary()
    assert summary["source_code"] == source.code
    assert summary["coverage"] == "COMPLETE"
    assert summary["new"] == 5
    assert summary["parsed"] == 6
    assert summary["rejected"] == 0
    rendered = json.dumps(summary, default=str)
    assert "Mombasa" not in rendered
    assert "Bamburi" not in rendered
    assert result.changed == 5


def test_a_connector_must_declare_the_source_code_it_serves(db_session: Session) -> None:
    source = make_source(db_session)
    with pytest.raises(ValueError):
        MappingConnector(
            guard=FetchGuard(FetchPolicy.from_source(source), resolver=resolver),
            code="",
            field_map=BOARD_FIELDS,
        )


def test_a_connector_cannot_point_the_guard_at_an_unregistered_host(
    db_session: Session,
) -> None:
    source = make_source(db_session)
    transport = FixtureTransport({BOARD_URL: fixture_bytes("coastal_board.json")})
    connector = board_connector(source, transport=transport)

    with pytest.raises(FetchRefusedError) as excinfo:
        connector.guard.fetch("https://elsewhere.example.net/feed.json")

    assert excinfo.value.reason == "host_not_allowlisted"
    assert transport.requests == []
    assert payload_source_hosts(source) == frozenset({"jobs.example.com"})
    assert host_is_allowed("elsewhere.example.net", payload_source_hosts(source)) is False


def test_the_default_now_is_timezone_aware() -> None:
    assert utcnow().tzinfo is UTC


def test_the_source_last_error_is_bounded_and_carries_no_content(
    db_session: Session,
) -> None:
    source = make_source(db_session)
    registry = JobSourceRegistry(db_session)
    registry.record_outcome(source, now=NOW, error="x" * 5000)
    assert source.last_error is not None
    assert len(source.last_error) == 512
    registry.record_outcome(source, now=LATER, error=None)
    assert source.last_error is None
    assert source.last_checked_at == LATER


# --------------------------------------------------------------------------- #
# Coercion rules, one at a time                                               #
# --------------------------------------------------------------------------- #
def transient_source() -> JobSource:
    """An unregistered source object. Nothing here writes, so no session is needed."""
    return JobSource(
        id=uuid.uuid4(),
        code="unit-source",
        name="Unit Source",
        source_type=JobSourceType.AGGREGATED_PUBLIC.value,
        base_url=BOARD_URL,
        terms_status=JobSourceTermsStatus.APPROVED.value,
        robots_status=JobSourceRobotsStatus.PERMITTED.value,
    )


def coerce(**overrides: object) -> object:
    """Normalise a valid record with one field changed, and return the result."""
    payload: dict[str, object] = {
        "external_id": "X-1",
        "title": "Mason",
        "description": "A mason is required for a residential development of 24 units.",
        "detail_url": "https://jobs.example.com/listing/x-1",
        "status": "open",
    }
    payload.update(overrides)
    return normalize_record(
        payload,
        source=transient_source(),
        policy=FetchPolicy.from_source(transient_source()),
        now=NOW,
    )


def test_the_natural_key_is_the_source_identifier() -> None:
    record = coerce()
    assert isinstance(record, NormalizedJob)
    assert record.natural_key == "X-1"
    assert record.is_confirmed_open
    assert not record.is_closed_by_source


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"external_id": None}, RejectionReason.MISSING_EXTERNAL_ID),
        ({"external_id": "   "}, RejectionReason.MISSING_EXTERNAL_ID),
        ({"external_id": "X" * 300}, RejectionReason.EXTERNAL_ID_TOO_LONG),
        ({"title": None}, RejectionReason.MISSING_TITLE),
        ({"description": "<p>  </p>"}, RejectionReason.MISSING_DESCRIPTION),
        ({"description": "mason " * 2000}, RejectionReason.DESCRIPTION_TOO_LONG),
        ({"detail_url": None}, RejectionReason.MISSING_SOURCE_URL),
        (
            {"detail_url": "https://jobs.example.com/" + "a" * 1100},
            RejectionReason.SOURCE_URL_NOT_ALLOWED,
        ),
        ({"detail_url": "https://elsewhere.example.net/x"}, RejectionReason.SOURCE_URL_NOT_ALLOWED),
        ({"location": "x" * 300}, RejectionReason.LOCATION_TOO_LONG),
    ],
)
def test_a_record_that_cannot_carry_its_provenance_is_refused(
    overrides: dict[str, object], reason: str
) -> None:
    with pytest.raises(RecordRejectedError) as excinfo:
        coerce(**overrides)
    assert excinfo.value.reason == reason


def test_an_employer_name_that_cannot_be_stored_is_refused() -> None:
    with pytest.raises(RecordRejectedError) as excinfo:
        coerce(employer_name="A" * 300)
    assert excinfo.value.reason == RejectionReason.EMPLOYER_NAME_TOO_LONG
    assert excinfo.value.field_name == "employer_name"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("", None),
        (3, 3),
        ("4", 4),
        ("3-5", 3),
        ("3 to 5", 3),
        ("2+ years", 2),
        ("lots", None),
        (True, None),
        (99, None),
    ],
)
def test_experience_years_are_read_from_everything_a_feed_says(
    raw: object, expected: int | None
) -> None:
    record = coerce(experience_required_years=raw)
    assert isinstance(record, NormalizedJob)
    assert record.experience_required_years == expected


@pytest.mark.parametrize(
    ("salary", "expected"),
    [
        ({"min": 10, "max": 20}, (10, 20)),
        ({"from": 10, "to": 20}, (10, 20)),
        ([10, 20], (10, 20)),
        ("KSh 30,000 - 40,000 monthly", (30000, 40000)),
        ("KSh 50,000", (50000, 50000)),
        ({"min": 40, "max": 10}, (10, 40)),
        ({"min": 10}, (10, 10)),
        ({"max": 10}, (10, 10)),
        ("Ask us", (None, None)),
        ({}, (None, None)),
    ],
)
def test_a_salary_is_never_invented(salary: object, expected: tuple[int, int]) -> None:
    record = coerce(salary=salary)
    assert isinstance(record, NormalizedJob)
    assert (record.salary_min, record.salary_max) == expected


@pytest.mark.parametrize(
    ("raw", "currency"),
    [
        ("KSh", "KES"),
        ("kes", "KES"),
        ("KES", "KES"),
        ("usd", "USD"),
        ("EUR", "EUR"),
        ("Euro", None),
        ("", None),
    ],
)
def test_a_currency_is_an_iso_code_or_nothing(raw: str, currency: str | None) -> None:
    record = coerce(salary={"min": 1, "currency": raw})
    assert isinstance(record, NormalizedJob)
    assert record.salary_currency == currency


def test_an_unknown_salary_period_is_dropped_with_a_warning() -> None:
    record = coerce(salary={"min": 1, "period": "fortnightly-ish"})
    assert isinstance(record, NormalizedJob)
    assert record.salary_period is None
    assert NormalisationWarning.SALARY_PERIOD_UNRECOGNISED in record.warnings


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-08-28T09:15:00Z", datetime(2026, 8, 28, 9, 15, tzinfo=UTC)),
        (1755000000, datetime.fromtimestamp(1755000000, tz=UTC)),
        ("1755000000", datetime.fromtimestamp(1755000000, tz=UTC)),
        (datetime(2026, 8, 28, 9, 15, tzinfo=UTC), datetime(2026, 8, 28, 9, 15, tzinfo=UTC)),
        (True, None),
        ("sometime", None),
        (1e30, None),
    ],
)
def test_a_timestamp_is_read_or_declared_unreadable(raw: object, expected: datetime | None) -> None:
    record = coerce(published_at=raw)
    assert isinstance(record, NormalizedJob)
    assert record.published_at == expected


def test_a_naive_datetime_is_recorded_as_utc_with_a_warning() -> None:
    naive = datetime(2026, 8, 28, 9, 15)  # noqa: DTZ001 - the input is the point
    record = coerce(published_at=naive)
    assert isinstance(record, NormalizedJob)
    assert record.published_at == datetime(2026, 8, 28, 9, 15, tzinfo=UTC)
    assert NormalisationWarning.DATE_ASSUMED_UTC in record.warnings


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"closing_in_days": 10}, NOW + timedelta(days=10)),
        ({"closing_in": "2 weeks"}, NOW + timedelta(days=14)),
        ({"closing_at": "in 3 days"}, NOW + timedelta(days=3)),
        ({"closing_in": "nonsense"}, None),
        ({"closing_at": "when the job is done"}, None),
        ({}, None),
    ],
)
def test_a_relative_deadline_is_translated_and_an_unreadable_one_is_dropped(
    overrides: dict[str, object], expected: datetime | None
) -> None:
    record = coerce(**overrides)
    assert isinstance(record, NormalizedJob)
    assert record.closing_at == expected


def test_a_deadline_anchored_on_the_posting_date_not_on_the_poll() -> None:
    record = coerce(
        published_at="2026-08-01T00:00:00Z",
        closing_in_days=10,
        now=NOW,  # type: ignore[call-arg]
    )
    assert isinstance(record, NormalizedJob)
    assert record.closing_at == datetime(2026, 8, 11, tzinfo=UTC)


@pytest.mark.parametrize(
    ("raw", "state"),
    [
        ("open", ListingState.OPEN),
        ("ACCEPTING APPLICATIONS", ListingState.OPEN),
        ("closed", ListingState.CLOSED),
        ("filled", ListingState.CLOSED),
        ("expired", ListingState.EXPIRED),
        ("weird", ListingState.UNKNOWN),
        (None, ListingState.UNKNOWN),
        (1, ListingState.UNKNOWN),
    ],
)
def test_an_unrecognised_status_is_never_read_as_open(raw: object, state: ListingState) -> None:
    record = coerce(status=raw)
    assert isinstance(record, NormalizedJob)
    assert record.listing_state is state


@pytest.mark.parametrize(
    ("raw", "employment", "experience"),
    [
        ("Full Time", EmploymentType.FULL_TIME, ExperienceLevel.NOT_SPECIFIED),
        ("apprentice", EmploymentType.APPRENTICESHIP, ExperienceLevel.NOT_SPECIFIED),
        ("Senior", EmploymentType.FULL_TIME, ExperienceLevel.EXPERIENCED),
        ("weekend", EmploymentType.FULL_TIME, ExperienceLevel.NOT_SPECIFIED),
        (None, EmploymentType.FULL_TIME, ExperienceLevel.NOT_SPECIFIED),
    ],
)
def test_controlled_vocabulary_is_coerced_or_defaulted(
    raw: str | None, employment: EmploymentType, experience: ExperienceLevel
) -> None:
    record = coerce(employment_type=raw, experience_level=raw)
    assert isinstance(record, NormalizedJob)
    assert record.employment_type is employment
    assert record.experience_level is experience
    defaulted = record.employment_type is EmploymentType.FULL_TIME and raw not in {
        "Full Time",
        "apprentice",
    }
    assert defaulted == (NormalisationWarning.EMPLOYMENT_TYPE_DEFAULTED in record.warnings)


@pytest.mark.parametrize(
    "apply_url",
    [
        "https://elsewhere.example.org/apply",
        "http://jobs.example.com/apply",
        "https://jobs.example.com/" + "a" * 1100,
    ],
)
def test_an_apply_url_we_may_not_point_workers_at_is_dropped(apply_url: str) -> None:
    record = coerce(apply_url=apply_url)
    assert isinstance(record, NormalizedJob)
    assert record.apply_url is None
    assert NormalisationWarning.APPLY_URL_DROPPED in record.warnings


def test_an_empty_or_absent_field_is_simply_absent() -> None:
    blank = coerce(location="", apply_url="   ")
    assert isinstance(blank, NormalizedJob)
    assert blank.location is None
    assert blank.apply_url is None
    # Nothing was dropped, so nothing is warned about.
    assert NormalisationWarning.APPLY_URL_DROPPED not in blank.warnings
    assert coerce(location=None).location is None


def test_an_id_is_trimmed_so_a_padded_entry_cannot_mint_a_second_row() -> None:
    record = coerce(external_id="  X-1  ")
    assert isinstance(record, NormalizedJob)
    assert external_identity(record) == "X-1"


# --------------------------------------------------------------------------- #
# The corners the stage tests do not reach                                     #
# --------------------------------------------------------------------------- #
def test_the_connector_exposes_its_field_map_and_its_guard(db_session: Session) -> None:
    source = make_source(db_session)
    connector = board_connector(source)
    assert connector.field_map is BOARD_FIELDS
    assert connector.guard.policy.allowed_hosts == frozenset({"jobs.example.com"})
    assert connector.apply_hosts == frozenset({"apply.partner-ats.example.com"})
    assert connector.source_type is JobSourceType.AGGREGATED_PUBLIC


def test_a_bare_array_document_is_accepted(db_session: Session) -> None:
    source = make_source(db_session)
    body = json.dumps(
        [
            {
                "id": "ARR-1",
                "headline": "Painter",
                "body_html": "<p>Painter required for repainting a school.</p>",
                "state": "open",
                "web_url": "https://jobs.example.com/listing/arr-1",
            },
            "not a mapping",
        ]
    )
    connector = MappingConnector(
        guard=FetchGuard(
            FetchPolicy.from_source(source),
            resolver=resolver,
            transport=FixtureTransport({BOARD_URL: body.encode("utf-8")}),
        ),
        code=source.code,
        field_map=BOARD_FIELDS,
    )
    parsed = connector.parse(connector.collect(source))
    assert len(parsed) == 1
    assert parsed.records[0].external_id == "ARR-1"
    assert parsed.coverage is PayloadCoverage.COMPLETE


def test_a_document_that_is_neither_a_list_nor_a_wrapper_yields_nothing(
    db_session: Session,
) -> None:
    source = make_source(db_session)
    connector = MappingConnector(
        guard=FetchGuard(
            FetchPolicy.from_source(source),
            resolver=resolver,
            transport=FixtureTransport({BOARD_URL: b'{"nothing": "useful"}'}),
        ),
        code=source.code,
        records_key="results",
        field_map=BOARD_FIELDS,
    )
    parsed = connector.parse(connector.collect(source))
    assert len(parsed) == 0
    # No records and no way to know what was left out: nothing may be removed.
    assert parsed.coverage is PayloadCoverage.COMPLETE


def test_a_field_map_missing_a_required_field_yields_an_empty_record(
    db_session: Session,
) -> None:
    source = make_source(db_session)
    body = json.dumps({"results": [{"id": "NO-TITLE", "body_html": "<p>No headline here.</p>"}]})
    connector = MappingConnector(
        guard=FetchGuard(
            FetchPolicy.from_source(source),
            resolver=resolver,
            transport=FixtureTransport({BOARD_URL: body.encode("utf-8")}),
        ),
        code=source.code,
        records_key="results",
        field_map=BOARD_FIELDS,
    )
    pipeline = IngestionPipeline(db_session, guard=connector.guard)

    parsed = pipeline.parse(connector, pipeline.fetch(connector, source))
    outcome = pipeline.normalise(connector, parsed, source=source, now=NOW)

    assert len(parsed) == 1
    assert parsed.records[0].payload == {}
    assert outcome.rejected_count == 1
    assert outcome.rejection_counts() == {RejectionReason.MISSING_TITLE: 1}


def test_a_connector_cannot_collect_a_source_with_no_base_url(db_session: Session) -> None:
    source = make_source(db_session, base_url=None)
    connector = board_connector(source)
    with pytest.raises(ValueError, match="no base_url"):
        connector.collect(source)


def test_a_declared_page_count_makes_a_payload_partial(db_session: Session) -> None:
    source = make_source(db_session)
    connector = MappingConnector(
        guard=FetchGuard(
            FetchPolicy.from_source(source),
            resolver=resolver,
            transport=FixtureTransport({BOARD_URL: fixture_bytes("coastal_board.json")}),
        ),
        code=source.code,
        records_key="results",
        field_map=BOARD_FIELDS,
        page_count=2,
    )
    parsed = connector.parse(connector.collect(source))
    assert parsed.coverage is PayloadCoverage.PARTIAL


def test_a_payload_with_has_more_false_is_complete(db_session: Session) -> None:
    source = make_source(db_session)
    connector = board_connector(source)
    document = json.loads(fixture_bytes("coastal_board.json"))
    document["page"]["has_more"] = False
    document["next_cursor"] = None
    parsed = connector.parse(FetchPayload(url=BOARD_URL, body=json.dumps(document).encode("utf-8")))
    assert parsed.coverage is PayloadCoverage.COMPLETE


def test_an_unusable_identifier_is_never_looked_up(db_session: Session) -> None:
    from app.services.job_sources.dedupe import load_existing

    source = make_source(db_session)
    assert load_existing(db_session, source_id=source.id, source_job_ids=["  "]) == {}
    assert load_existing(db_session, source_id=source.id, source_job_ids=[]) == {}


def test_the_pipeline_exposes_its_policy(db_session: Session) -> None:
    source = make_source(db_session)
    connector = board_connector(source)
    policy = AbsencePolicy(close_after_absences=3)
    assert IngestionPipeline(db_session, guard=connector.guard, policy=policy).policy is policy


def test_a_failed_poll_records_only_the_exception_kind(db_session: Session) -> None:
    source = make_source(db_session)
    pipeline = IngestionPipeline(db_session, guard=board_connector(source).guard)

    pipeline.poll_error(source, TimeoutError("upstream timed out"), now=LATER)

    assert source.last_checked_at == LATER
    # The exception's own text could be third-party content; the kind cannot.
    assert source.last_error == "TimeoutError"
    assert "timed out" not in (source.last_error or "")


def test_a_removal_with_no_row_to_attach_is_a_no_op(db_session: Session) -> None:
    from app.services.job_sources.pipeline import _close

    _close(None, transient_source(), NOW)


def test_the_registry_reports_every_source_it_is_not_ingesting(db_session: Session) -> None:
    enabled = make_source(db_session, code="live-feed")
    disabled = make_source(db_session, code="switched-off", is_active=False)
    unreviewed = make_source(
        db_session, code="unreviewed", terms_status=JobSourceTermsStatus.PROHIBITED
    )
    no_url = make_source(db_session, code="no-url", base_url=None)
    registered = make_source(db_session, code="no-connector")
    registry = JobSourceRegistry(db_session)

    # ``no-url`` has a connector but no target, so the base_url gate is what stops
    # it; ``no-connector`` has a target and nothing that may fetch it.
    refusals = registry.refusals(connectors=["live-feed", "no-url"])

    assert set(refusals) == {disabled.id, unreviewed.id, no_url.id, registered.id}
    assert refusals[disabled.id].reason == RefusalReason.INACTIVE
    assert refusals[unreviewed.id].reason.startswith(RefusalReason.TERMS_NOT_APPROVED)
    assert refusals[no_url.id].reason == RefusalReason.NO_BASE_URL
    assert refusals[registered.id].reason == RefusalReason.NO_CONNECTOR
    assert enabled.id not in refusals
    assert "live-feed" in registry.codes()
    assert set(registry.enabled()) == {enabled.id} or enabled in registry.enabled()


def test_the_source_row_decides_provenance_even_if_a_connector_disagrees(
    db_session: Session,
) -> None:
    """A connector's own declaration never overrides the registered source row.

    The disagreement is logged as ``JOB_SOURCE_CONNECTOR_TYPE_MISMATCH``; the test
    asserts the outcome rather than the log line, because this suite's root handler
    replaces pytest's log capture handler.
    """
    source = make_source(db_session)
    connector = MappingConnector(
        guard=FetchGuard(
            FetchPolicy.from_source(source),
            resolver=resolver,
            transport=FixtureTransport({BOARD_URL: fixture_bytes("coastal_board.json")}),
        ),
        code=source.code,
        records_key="results",
        field_map=BOARD_FIELDS,
        # A partner feed connector pointed at a public aggregator: the row still
        # decides, and the disagreement is logged rather than silently applied.
        source_type=JobSourceType.PARTNER_FEED,
    )
    registry = JobSourceRegistry(db_session)

    assert registry.connector_for(source, [connector]) is connector
    # What a poll then writes is the row's provenance, not the connector's.
    result = run_pipeline(db_session, connector, source, now=NOW)
    assert result.counts.new == 5
    for job in jobs_for(db_session, source):
        assert job.source_type == JobSourceType.AGGREGATED_PUBLIC.value


def test_two_connectors_keep_their_own_identity(db_session: Session) -> None:
    """A class-level code would be shared state and would rename the first one."""
    first = make_source(db_session, code="feed-one")
    second = make_source(db_session, code="feed-two")
    first_connector = board_connector(first)
    second_connector = board_connector(second)

    assert first_connector.code == "feed-one"
    assert second_connector.code == "feed-two"
    assert first_connector.code == "feed-one"


def test_a_rate_limit_of_zero_cannot_mean_no_limit(db_session: Session) -> None:
    source = make_source(db_session, rate_limit_per_minute=0)
    registry = JobSourceRegistry(db_session)
    assert registry.minimum_interval(source).total_seconds() == 60.0
    source.rate_limit_per_minute = 600
    assert registry.minimum_interval(source).total_seconds() == 1.0


def test_a_deadline_added_and_removed_are_both_described(db_session: Session) -> None:
    from app.services.job_sources.changes import DeadlineChange

    assert DeadlineChange(previous=None, current=NOW).describe() == "closing_at added"
    assert DeadlineChange(previous=NOW, current=None).describe() == "closing_at removed"
    assert DeadlineChange(previous=None, current=None).extended is False
    assert DeadlineChange(previous=NOW, current=NOW - timedelta(days=1)).extended is False
    assert ChangeSet().describe() == "no material change"


def test_a_closure_the_schema_permits_also_sets_a_deadline() -> None:
    """With an owner present the row can actually close, and it gets a deadline."""
    from app.services.job_sources.pipeline import _close

    job = Job(
        id=uuid.uuid4(),
        title="Mason",
        description="A mason is required for a residential development.",
        status=JobStatus.OPEN.value,
        source_type=JobSourceType.AGGREGATED_PUBLIC.value,
        organization_id=uuid.uuid4(),
    )
    _close(job, transient_source(), NOW)

    assert job.status == JobStatus.CLOSED.value
    assert job.closed_at == NOW
    assert job.closing_at == NOW


def test_a_deadline_removed_is_not_an_extension() -> None:
    from app.services.job_sources.changes import DeadlineChange

    assert DeadlineChange(previous=NOW, current=None).extended is False


def test_a_field_map_constant_fills_a_key_the_feed_omits() -> None:
    mapped = FieldMap(
        source={"id": "external_id", "headline": "title"},
        constants={"description": "Imported from a nightly feed with no body."},
    )
    assert (
        mapped.canonical({"id": "K-1", "headline": "Painter"})["description"]
        == "Imported from a nightly feed with no body."
    )
    overriding = FieldMap(
        source={"id": "external_id", "description": "description"},
        constants={"description": "Imported."},
        required=("external_id", "description"),
    )
    assert overriding.canonical({"id": "K-1", "description": "Real text."})["description"] == (
        "Real text."
    )


def test_a_bare_object_document_is_one_record(db_session: Session) -> None:
    source = make_source(db_session)
    body = json.dumps(
        {
            "id": "BARE-1",
            "headline": "Welder",
            "body_html": "<p>Welder required for structural steelwork.</p>",
            "state": "open",
            "web_url": "https://jobs.example.com/listing/bare-1",
        }
    )
    connector = MappingConnector(
        guard=FetchGuard(
            FetchPolicy.from_source(source),
            resolver=resolver,
            transport=FixtureTransport({BOARD_URL: body.encode("utf-8")}),
        ),
        code=source.code,
        field_map=BOARD_FIELDS,
    )
    parsed = connector.parse(connector.collect(source))
    assert [record.external_id for record in parsed.records] == ["BARE-1"]


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"salary": {"min": 45000.0}}, ("salary_min", 45000)),
        ({"salary": "KSh 45,000.50 monthly"}, ("salary_min", 45000)),
        ({"salary": {"min": 1, "currency": "JPY"}}, ("salary_currency", "JPY")),
        ({"salary": {"min": 1, "period": ""}}, ("salary_period", None)),
        ({"published_at": ""}, ("published_at", None)),
    ],
)
def test_the_remaining_coercion_corners(
    overrides: dict[str, object], expected: tuple[str, object]
) -> None:
    record = coerce(**overrides)
    assert isinstance(record, NormalizedJob)
    assert getattr(record, expected[0]) == expected[1]


def test_a_blank_url_is_no_url_at_all() -> None:
    with pytest.raises(RecordRejectedError) as excinfo:
        coerce(detail_url="   ")
    assert excinfo.value.reason == RejectionReason.MISSING_SOURCE_URL
