"""The canonical shape of an ingested listing, and the rules that produce it.

Third-party payloads disagree about everything: they name fields differently,
write dates as ISO strings or epoch numbers or "3 weeks from now", wrap salaries
in prose, and disagree about whether a job is open. This module turns all of
that into one :class:`NormalizedJob`, or refuses the record with a reason.

Three rules shape the coercion:

**Provenance is not derivable and is never defaulted.** ``source_job_id`` and
``source_url`` come from the payload or the record is rejected. A listing whose
identity we cannot name cannot be de-duplicated, cannot be re-found next poll,
and cannot be traced back to the site that published it - so a plausible title
is not a substitute.

**A bounded column overflow is a rejection, not a truncation.** ``jobs.title``
and ``jobs.location`` are ``VARCHAR(255)``. Silently cutting a title at 255
characters produces a listing nobody can match to its source again, so the record
is refused and counted. The caller sees the count; nobody sees a mangled job.

**Untrusted vocabulary never becomes a decision.** An unrecognised employment
type or status is coerced to a documented default and recorded as a warning. It
never raises, and it never quietly reads as "open": an unknown status stays
``UNKNOWN``, because assuming a listing is open is how a closed job keeps being
advertised.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import html
import json
import re
from typing import Any, Final
from urllib.parse import urljoin, urlsplit

from app.core.constants import (
    MAX_DESCRIPTION_LENGTH,
    MAX_SHORT_TEXT,
    EmploymentType,
    ExperienceLevel,
)
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models.job import JobSource
from app.services.job_sources.safety import (
    FetchPolicy,
    allowed_hosts_from_base_url,
    host_is_allowed,
)

logger = get_logger(__name__)

#: Upper bounds mirrored from the columns an ingested listing lands in. They live
#: here rather than being read from the model so that a normalisation failure is a
#: rejection with a reason instead of a database error.
MAX_EXTERNAL_ID_LENGTH: Final[int] = 255
MAX_SOURCE_URL_LENGTH: Final[int] = 1024

#: Tags in a description. A plain-text projection for display, not a security
#: boundary: the API escapes on render and no HTML is ever stored.
_TAG = re.compile(r"<[^>]{0,4096}>")

#: Any run of whitespace, including the newlines feeds use for paragraph breaks.
_WHITESPACE = re.compile(r"\s+")

#: ``"3"``, ``"3+"``, ``"3-5"``, ``"3 to 5"``, ``"3 years"``, ``"3+ years"``.
_YEARS = re.compile(r"^\s*(\d{1,2})\s*(?:(?:\+|to|-)\s*\d*\s*(?:years?)?|years?)?\s*$", re.I)

#: ``"45,000"``, ``"KSh 45000"``, ``"45000.00"``, ``"USD 1,200 per month"``.
_AMOUNT = re.compile(r"(\d[\d,]*(?:\.\d{1,2})?)")

#: A period stated inside prose rather than as its own field.
_PERIOD_IN_PROSE = re.compile(
    r"per (?:month|day|hour|year)|monthly|daily|hourly|yearly|annually|per annum",
    re.I,
)

_CURRENCY = re.compile(r"\b(kes|ksh|usd|eur|gbp|zar|ugx|tzs|ngn)\b", re.I)

#: ``"3 weeks"``, ``"2 days"``, ``"1 month"``. Feeds state deadlines relatively.
_RELATIVE = re.compile(r"^\s*(?:in\s+)?(\d{1,3})\s*(day|days|week|weeks|month|months)\s*$", re.I)

#: Bare epoch values, seconds or milliseconds. Above ``YEAR_2000_MS`` the number
#: is assumed to be milliseconds, which is how every feed that sends them means it.
YEAR_2000_MS: Final[int] = 946_684_800_000

_RELATIVE_UNIT_DAYS: Final[dict[str, int]] = {
    "day": 1,
    "week": 7,
    "month": 30,
}


class ListingState(StrEnum):
    """What the *source* says about a listing.

    Deliberately local rather than in :mod:`app.core.constants`: nothing here is
    stored in a constrained column, and this is a third party's vocabulary rather
    than a platform one. ``UNKNOWN`` is the default and never means "open".
    """

    OPEN = "OPEN"
    CLOSED = "CLOSED"
    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"


class RejectionReason:
    """Why a record was refused. Codes only: a reason may name a field, never a value."""

    MISSING_REQUIRED_FIELD = "missing_required_field"
    MISSING_EXTERNAL_ID = "missing_external_id"
    EXTERNAL_ID_TOO_LONG = "external_id_too_long"
    MISSING_TITLE = "missing_title"
    TITLE_TOO_LONG = "title_too_long"
    MISSING_DESCRIPTION = "missing_description"
    DESCRIPTION_TOO_LONG = "description_too_long"
    MISSING_SOURCE_URL = "missing_source_url"
    SOURCE_URL_NOT_ALLOWED = "source_url_not_allowed"
    LOCATION_TOO_LONG = "location_too_long"
    EMPLOYER_NAME_TOO_LONG = "employer_name_too_long"


class RecordRejectedError(Exception):
    """A payload entry could not be turned into a listing.

    Raised per record and counted by the pipeline. One bad entry never aborts a
    poll, but it is never swallowed either.
    """

    def __init__(self, reason: str, *, field_name: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.field_name = field_name


class NormalisationWarning:
    """Coercions that were applied, by code. Counts are what get logged."""

    EMPLOYMENT_TYPE_DEFAULTED = "employment_type_defaulted"
    EXPERIENCE_LEVEL_DEFAULTED = "experience_level_defaulted"
    EXPERIENCE_YEARS_UNREADABLE = "experience_years_unreadable"
    SALARY_UNREADABLE = "salary_unreadable"
    CURRENCY_UNRECOGNISED = "currency_unrecognised"
    SALARY_PERIOD_UNRECOGNISED = "salary_period_unrecognised"
    DATE_UNPARSED = "date_unparsed"
    DATE_ASSUMED_UTC = "date_assumed_utc"
    DEADLINE_DERIVED = "deadline_derived"
    STATUS_UNRECOGNISED = "status_unrecognised"
    APPLY_URL_DROPPED = "apply_url_dropped"
    DESCRIPTION_STRIPPED = "description_stripped"


#: Free text -> platform vocabulary. Anything outside these maps is defaulted.
EMPLOYMENT_ALIASES: Final[dict[str, EmploymentType]] = {
    "full time": EmploymentType.FULL_TIME,
    "fulltime": EmploymentType.FULL_TIME,
    "permanent": EmploymentType.FULL_TIME,
    "full": EmploymentType.FULL_TIME,
    "part time": EmploymentType.PART_TIME,
    "parttime": EmploymentType.PART_TIME,
    "contract": EmploymentType.CONTRACT,
    "contractor": EmploymentType.CONTRACT,
    "temporary": EmploymentType.TEMPORARY,
    "temp": EmploymentType.TEMPORARY,
    "casual": EmploymentType.CASUAL,
    "apprenticeship": EmploymentType.APPRENTICESHIP,
    "apprentice": EmploymentType.APPRENTICESHIP,
    "internship": EmploymentType.INTERNSHIP,
    "intern": EmploymentType.INTERNSHIP,
}

EXPERIENCE_ALIASES: Final[dict[str, ExperienceLevel]] = {
    "entry": ExperienceLevel.ENTRY,
    "entry level": ExperienceLevel.ENTRY,
    "graduate": ExperienceLevel.ENTRY,
    "junior": ExperienceLevel.ENTRY,
    "no experience": ExperienceLevel.ENTRY,
    "intermediate": ExperienceLevel.INTERMEDIATE,
    "mid": ExperienceLevel.INTERMEDIATE,
    "experienced": ExperienceLevel.EXPERIENCED,
    "senior": ExperienceLevel.EXPERIENCED,
    "expert": ExperienceLevel.EXPERIENCED,
    "3+ years": ExperienceLevel.EXPERIENCED,
}

LISTING_STATE_ALIASES: Final[dict[str, ListingState]] = {
    "open": ListingState.OPEN,
    "active": ListingState.OPEN,
    "live": ListingState.OPEN,
    "accepting applications": ListingState.OPEN,
    # A numeric status is deliberately absent: guessing that 1 means open is how a
    # closed vacancy keeps being advertised. A connector maps numbers explicitly.
    "closed": ListingState.CLOSED,
    "filled": ListingState.CLOSED,
    "no longer accepting applications": ListingState.CLOSED,
    "withdrawn": ListingState.CLOSED,
    "cancelled": ListingState.CLOSED,
    "expired": ListingState.EXPIRED,
}

SALARY_PERIOD_ALIASES: Final[dict[str, str]] = {
    "monthly": "MONTHLY",
    "per month": "MONTHLY",
    "month": "MONTHLY",
    "pm": "MONTHLY",
    "annually": "ANNUALLY",
    "yearly": "ANNUALLY",
    "per annum": "ANNUALLY",
    "pa": "ANNUALLY",
    "daily": "DAILY",
    "per day": "DAILY",
    "day": "DAILY",
    "hourly": "HOURLY",
    "per hour": "HOURLY",
    "hour": "HOURLY",
    "negotiable": "NEGOTIABLE",
}

#: Longest ``jobs.salary_period`` is 16 characters.
MAX_SALARY_PERIOD_LENGTH: Final[int] = 16


@dataclass(frozen=True, slots=True)
class NormalizedJob:
    """One listing, canonical, with everything needed to store it and trace it.

    ``payload_hash`` is a digest of the exact payload entry this came from, so a
    provenance question ("what did the source actually say?") is answerable by
    comparing digests without retaining third-party text.
    """

    source_job_id: str
    title: str
    description: str
    source_url: str
    employment_type: EmploymentType = EmploymentType.FULL_TIME
    experience_level: ExperienceLevel = ExperienceLevel.NOT_SPECIFIED
    location: str | None = None
    employer_name: str | None = None
    experience_required_years: int | None = None
    salary_min: int | None = None
    salary_max: int | None = None
    salary_currency: str | None = None
    salary_period: str | None = None
    published_at: datetime | None = None
    closing_at: datetime | None = None
    listing_state: ListingState = ListingState.UNKNOWN
    apply_url: str | None = None
    payload_hash: str = ""
    warnings: tuple[str, ...] = ()

    @property
    def natural_key(self) -> str:
        """The source's own identifier. Stable across polls; never the title."""
        return self.source_job_id

    @property
    def is_confirmed_open(self) -> bool:
        """Whether this poll positively confirmed the listing is still open.

        ``UNKNOWN`` is not open. ``last_verified_at`` is advanced only for a
        listing this returns true for, so "verified" never means "we did not hear
        otherwise".
        """
        return self.listing_state is ListingState.OPEN

    @property
    def is_closed_by_source(self) -> bool:
        """The source states the listing has ended. Positive evidence, not absence."""
        return self.listing_state is ListingState.CLOSED


class _Warnings:
    """Ordered, de-duplicated warning codes for one record."""

    def __init__(self) -> None:
        self._codes: list[str] = []

    def add(self, code: str) -> None:
        if code not in self._codes:
            self._codes.append(code)

    def codes(self) -> tuple[str, ...]:
        return tuple(self._codes)


def normalize_record(
    payload: Mapping[str, Any],
    *,
    source: JobSource,
    policy: FetchPolicy | None = None,
    now: datetime | None = None,
    apply_hosts: frozenset[str] = frozenset(),
    external_id: str | int | None = None,
    detail_url: str | None = None,
) -> NormalizedJob:
    """Coerce one canonical payload mapping into a :class:`NormalizedJob`.

    Raises :class:`RecordRejectedError` when the record cannot carry the
    provenance the schema requires.
    """
    moment = now or utcnow()
    guard_policy = policy or FetchPolicy.from_source(source)
    warnings = _Warnings()

    external = _external_id(payload.get("external_id"), external_id)
    title = _title(payload.get("title"))
    description = _description(payload.get("description"), warnings)
    source_url = _source_url(
        payload.get("detail_url", detail_url),
        base_url=source.base_url,
        policy=guard_policy,
    )
    apply_url = _apply_url(
        payload.get("apply_url"),
        base_url=source.base_url,
        policy=guard_policy,
        apply_hosts=apply_hosts,
        warnings=warnings,
    )

    employment_type = _employment_type(payload.get("employment_type"), warnings)
    experience_level = _experience_level(payload.get("experience_level"), warnings)
    years = _years(payload.get("experience_required_years"), warnings)
    salary_min, salary_max, currency, period = _salary(payload, warnings)
    published_at = _timestamp(payload.get("published_at"), warnings)
    closing_at = _closing_at(payload, published_at, moment, warnings)
    listing_state = _listing_state(payload.get("status"))

    return NormalizedJob(
        source_job_id=external,
        title=title,
        description=description,
        source_url=source_url,
        employment_type=employment_type,
        experience_level=experience_level,
        location=_bounded(
            payload.get("location"),
            MAX_SHORT_TEXT,
            RejectionReason.LOCATION_TOO_LONG,
        ),
        employer_name=_bounded(
            payload.get("employer_name"),
            MAX_SHORT_TEXT,
            RejectionReason.EMPLOYER_NAME_TOO_LONG,
        ),
        experience_required_years=years,
        salary_min=salary_min,
        salary_max=salary_max,
        salary_currency=currency,
        salary_period=period,
        published_at=published_at,
        closing_at=closing_at,
        listing_state=listing_state,
        apply_url=apply_url,
        payload_hash=payload_hash(payload),
        warnings=warnings.codes(),
    )


# --------------------------------------------------------------------------- #
# Field coercion                                                              #
# --------------------------------------------------------------------------- #
def _external_id(
    raw: Any,
    override: str | int | None,
) -> str:
    """The source's own identifier, or a rejection.

    Never falls back to the title, a slug of the title, or a digest of the
    description: an identity invented here would collide on the next retitle.
    """
    candidate = raw if override is None else override
    if candidate is None:
        raise RecordRejectedError(RejectionReason.MISSING_EXTERNAL_ID, field_name="external_id")
    text_value = _text(candidate)
    if not text_value:
        raise RecordRejectedError(RejectionReason.MISSING_EXTERNAL_ID, field_name="external_id")
    if len(text_value) > MAX_EXTERNAL_ID_LENGTH:
        raise RecordRejectedError(RejectionReason.EXTERNAL_ID_TOO_LONG, field_name="external_id")
    return text_value


def _title(raw: Any) -> str:
    title = _text(raw)
    if not title:
        raise RecordRejectedError(RejectionReason.MISSING_TITLE, field_name="title")
    if len(title) > MAX_SHORT_TEXT:
        raise RecordRejectedError(RejectionReason.TITLE_TOO_LONG, field_name="title")
    return title


def _description(raw: Any, warnings: _Warnings) -> str:
    value = "" if raw is None else str(raw)
    if _TAG.search(value):
        value = _TAG.sub(" ", value)
        warnings.add(NormalisationWarning.DESCRIPTION_STRIPPED)
    value = _collapse(html.unescape(value))
    if not value:
        raise RecordRejectedError(RejectionReason.MISSING_DESCRIPTION, field_name="description")
    if len(value) > MAX_DESCRIPTION_LENGTH:
        raise RecordRejectedError(RejectionReason.DESCRIPTION_TOO_LONG, field_name="description")
    return value


def _source_url(raw: Any, *, base_url: str | None, policy: FetchPolicy) -> str:
    """The listing's own URL, which must be one we would have been allowed to fetch.

    It is rendered as a link a worker clicks, so an off-allowlist value is a
    rejection rather than a warning: the platform would be pointing workers at a
    host no operator ever reviewed.
    """
    candidate = _absolute_url(raw, base_url=base_url)
    if not candidate:
        raise RecordRejectedError(RejectionReason.MISSING_SOURCE_URL, field_name="detail_url")
    if len(candidate) > MAX_SOURCE_URL_LENGTH:
        raise RecordRejectedError(RejectionReason.SOURCE_URL_NOT_ALLOWED, field_name="detail_url")
    if not url_is_permitted(candidate, policy):
        raise RecordRejectedError(RejectionReason.SOURCE_URL_NOT_ALLOWED, field_name="detail_url")
    return candidate


def _apply_url(
    raw: Any,
    *,
    base_url: str | None,
    policy: FetchPolicy,
    apply_hosts: frozenset[str],
    warnings: _Warnings,
) -> str | None:
    """The apply destination, or ``None`` if we may not point workers at it.

    Applicant-tracking hosts are not the source's host, so a connector may declare
    them explicitly. They are dropped with a warning rather than failing the
    record: a listing we can still attribute is worth keeping even if we cannot
    route its applications.
    """
    candidate = _absolute_url(raw, base_url=base_url)
    if not candidate:
        return None
    if len(candidate) > MAX_SOURCE_URL_LENGTH:
        warnings.add(NormalisationWarning.APPLY_URL_DROPPED)
        return None
    if not url_is_permitted(candidate, policy, extra_hosts=apply_hosts):
        warnings.add(NormalisationWarning.APPLY_URL_DROPPED)
        return None
    return candidate


def url_is_permitted(
    url: str,
    policy: FetchPolicy,
    *,
    extra_hosts: frozenset[str] = frozenset(),
) -> bool:
    """Whether *url* is https on a host the source is permitted to point at."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        return False
    allowed = policy.allowed_hosts | extra_hosts
    return host_is_allowed(parts.hostname, allowed)


def _absolute_url(raw: Any, *, base_url: str | None) -> str | None:
    if raw is None:
        return None
    value = str(raw).strip()
    if not value:
        return None
    if base_url:
        try:
            value = urljoin(base_url.rstrip("/") + "/", value)
        except ValueError:
            return None
    return value


def _employment_type(raw: Any, warnings: _Warnings) -> EmploymentType:
    mapped = EMPLOYMENT_ALIASES.get(_key(raw))
    if mapped is not None:
        return mapped
    warnings.add(NormalisationWarning.EMPLOYMENT_TYPE_DEFAULTED)
    return EmploymentType.FULL_TIME


def _experience_level(raw: Any, warnings: _Warnings) -> ExperienceLevel:
    mapped = EXPERIENCE_ALIASES.get(_key(raw))
    if mapped is not None:
        return mapped
    warnings.add(NormalisationWarning.EXPERIENCE_LEVEL_DEFAULTED)
    return ExperienceLevel.NOT_SPECIFIED


def _years(raw: Any, warnings: _Warnings) -> int | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool):
        warnings.add(NormalisationWarning.EXPERIENCE_YEARS_UNREADABLE)
        return None
    if isinstance(raw, int):
        return raw if 0 <= raw <= 60 else None
    match = _YEARS.match(str(raw))
    if match is None:
        warnings.add(NormalisationWarning.EXPERIENCE_YEARS_UNREADABLE)
        return None
    return int(match.group(1))


def _salary(
    payload: Mapping[str, Any], warnings: _Warnings
) -> tuple[int | None, int | None, str | None, str | None]:
    """Read salary from a structured object or from prose, without guessing.

    A salary is never invented. If the payload does not state one, the listing
    has no salary - which is the common and honest case for an external listing.
    """
    structured = payload.get("salary")
    prose: str | None = None
    low_raw = payload.get("salary_min")
    high_raw = payload.get("salary_max")
    currency_raw = payload.get("salary_currency")
    period_raw = payload.get("salary_period")

    if isinstance(structured, Mapping):
        # ``from``/``to``/``ccy``/``unit`` are as common as min/max/currency/period.
        low_raw = _first_present(structured, ("min", "from", "minimum"), low_raw)
        high_raw = _first_present(structured, ("max", "to", "maximum"), high_raw)
        currency_raw = _first_present(structured, ("currency", "ccy"), currency_raw)
        period_raw = _first_present(structured, ("period", "unit"), period_raw)
    elif isinstance(structured, str):
        prose = structured
    elif isinstance(structured, Sequence) and len(structured) == 2:
        low_raw, high_raw = structured[0], structured[1]
        prose = None
    else:
        prose = None

    low = _amount(low_raw)
    high = _amount(high_raw)
    if low is None and high is None:
        # "KSh 45,000 - 60,000 per month": two ordered amounts in one string.
        found = [_whole_number(value) for value in _AMOUNT.findall(str(prose or ""))]
        if len(found) == 2:
            low, high = min(found), max(found)
        elif len(found) == 1:
            # One figure is both bounds: "KSh 1,200 per day" is a single rate.
            low = high = found[0]
        elif low_raw is not None or high_raw is not None or prose:
            warnings.add(NormalisationWarning.SALARY_UNREADABLE)
    elif low is None:
        low = high
    elif high is None:
        high = low
    if low is not None and high is not None and low > high:
        low, high = high, low

    currency = _currency(currency_raw if currency_raw is not None else prose, warnings)
    period = _salary_period(
        period_raw if period_raw is not None else _period_in_prose(prose), warnings
    )
    return low, high, currency, period


def _period_in_prose(prose: str | None) -> str | None:
    """Pull a pay period out of a sentence, if the sentence states one."""
    if not prose:
        return None
    match = _PERIOD_IN_PROSE.search(prose)
    return match.group(0) if match else None


def _first_present(mapping: Mapping[str, Any], keys: Sequence[str], fallback: Any) -> Any:
    """The first of *keys* the mapping actually carries, else *fallback*."""
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return fallback


def _whole_number(text_value: str) -> int:
    """``"45,000.50"`` -> ``45000``. Cents are not a thing in this column."""
    return int(text_value.replace(",", "").split(".", 1)[0])


def _amount(raw: Any) -> int | None:
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    if isinstance(raw, float):
        return int(raw) if raw >= 0 else None
    match = _AMOUNT.search(str(raw))
    if match is None:
        return None
    return int(match.group(1).replace(",", ""))


def _currency(raw: Any, warnings: _Warnings) -> str | None:
    """An ISO 4217 code, or ``None``.

    The alias table is consulted before the generic three-letter rule, because
    "KSh" is three letters and would otherwise be stored as a currency code that
    does not exist. A listing with no stated currency keeps no currency.
    """
    if raw is None:
        return None
    value = str(raw).strip()
    match = _CURRENCY.search(value)
    if match is not None:
        mapped = match.group(1).upper()
        return "KES" if mapped in {"KES", "KSH"} else mapped
    if len(value) == 3 and value.isalpha():
        return value.upper()
    if value:
        warnings.add(NormalisationWarning.CURRENCY_UNRECOGNISED)
    return None


def _salary_period(raw: Any, warnings: _Warnings) -> str | None:
    if raw is None:
        return None
    value = _key(raw)
    mapped = SALARY_PERIOD_ALIASES.get(value)
    if mapped is not None and len(mapped) <= MAX_SALARY_PERIOD_LENGTH:
        return mapped
    if value:
        warnings.add(NormalisationWarning.SALARY_PERIOD_UNRECOGNISED)
    return None


def _timestamp(raw: Any, warnings: _Warnings) -> datetime | None:
    """Parse a third-party timestamp into an aware UTC datetime.

    Naive values are *recorded* as UTC with a warning rather than rejected: they
    are overwhelmingly the site's own local posting time in a Kenyan deployment,
    and dropping a whole listing over a missing ``Z`` loses more than it protects.
    """
    if raw is None or raw == "":
        return None
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            # Same rule as the string path: a naive value is recorded as UTC and
            # said so, whether the feed sent it as a string or as a value already.
            warnings.add(NormalisationWarning.DATE_ASSUMED_UTC)
            return raw.replace(tzinfo=UTC)
        return raw.astimezone(UTC)
    if isinstance(raw, bool):
        warnings.add(NormalisationWarning.DATE_UNPARSED)
        return None
    if isinstance(raw, int | float):
        return _from_epoch(float(raw), warnings)
    text_value = str(raw).strip()
    if not text_value:
        return None
    if text_value.isdigit():
        return _from_epoch(float(text_value), warnings)
    candidate = text_value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        warnings.add(NormalisationWarning.DATE_UNPARSED)
        return None
    if parsed.tzinfo is None:
        warnings.add(NormalisationWarning.DATE_ASSUMED_UTC)
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _from_epoch(value: float, warnings: _Warnings) -> datetime | None:
    seconds = value / 1000 if value >= YEAR_2000_MS else value
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        warnings.add(NormalisationWarning.DATE_UNPARSED)
        return None


def _closing_at(
    payload: Mapping[str, Any],
    published_at: datetime | None,
    now: datetime,
    warnings: _Warnings,
) -> datetime | None:
    """The deadline, absolute or relative.

    A feed that says "applications close in 3 weeks" is stating a deadline, and
    translating it is what stops the platform re-deriving one on the source's
    behalf. The relative form is read from whichever key it turns up in, because
    feeds put "in 2 weeks" in the deadline field often enough to be worth
    handling. If the anchor is unknown the deadline is unknown: deriving it from
    the current time would make a listing's expiry depend on when we polled.
    """
    raw = payload.get("closing_at")
    attempted = _Warnings()
    absolute = _timestamp(raw, attempted)
    if absolute is not None:
        return absolute
    days = _relative_days(raw, payload.get("closing_in"), payload.get("closing_in_days"))
    if days is not None:
        anchor = published_at or now
        warnings.add(NormalisationWarning.DEADLINE_DERIVED)
        return anchor + timedelta(days=days)
    if raw or payload.get("closing_in") or payload.get("closing_in_days") is not None:
        # The failed absolute parse is only a problem once nothing else worked.
        for code in attempted.codes():
            warnings.add(code)
        warnings.add(NormalisationWarning.DATE_UNPARSED)
    return None


def _relative_days(*candidates: Any) -> int | None:
    """Days from a relative deadline, whichever candidate states one."""
    for candidate in candidates:
        if candidate is None:
            continue
        match = _RELATIVE.match(str(candidate))
        if match is not None:
            unit = _RELATIVE_UNIT_DAYS[match.group(2).lower().rstrip("s")]
            return int(match.group(1)) * unit
        count = _amount(candidate)
        if count is not None:
            return count
    return None


def _listing_state(raw: Any) -> ListingState:
    """Map a source's status onto the three states we act on.

    Anything unrecognised is ``UNKNOWN``. Never ``OPEN`` by default: a listing
    nobody has confirmed should not be advertised as confirmed.
    """
    return LISTING_STATE_ALIASES.get(_key(raw), ListingState.UNKNOWN)


#: Rejection reason -> the field it was raised for. Named rather than passed so a
#: rejection cannot claim a field it did not read.
_REJECTION_FIELDS: Final[dict[str, str]] = {
    RejectionReason.LOCATION_TOO_LONG: "location",
    RejectionReason.EMPLOYER_NAME_TOO_LONG: "employer_name",
}


def _bounded(raw: Any, limit: int, reason: str) -> str | None:
    """Short text, or a rejection when it cannot be stored."""
    value = _text(raw)
    if not value:
        return None
    if len(value) > limit:
        raise RecordRejectedError(reason, field_name=_REJECTION_FIELDS[reason])
    return value


def _text(raw: Any) -> str:
    if raw is None or isinstance(raw, bool | int | float):
        return "" if raw is None or isinstance(raw, bool) else str(raw)
    return _collapse(str(raw))


def _collapse(value: str) -> str:
    return _WHITESPACE.sub(" ", value).strip()


def _key(raw: Any) -> str:
    """Comparison key for a controlled vocabulary: case- and separator-insensitive."""
    if raw is None or isinstance(raw, bool):
        return ""
    return _collapse(str(raw)).lower().replace("-", " ").replace("_", " ")


def payload_hash(payload: Mapping[str, Any]) -> str:
    """A stable digest of one payload entry.

    Sorted keys and no whitespace, so the same entry hashes identically however
    it was serialised. Stored in ``job_source_events.payload_hash``: it identifies
    the exact bytes without retaining third-party text that may carry personal
    data.
    """
    encoded = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class NormaliseOutcome:
    """The result of normalising one poll's records."""

    records: tuple[NormalizedJob, ...] = ()
    rejections: tuple[tuple[str, str | None], ...] = ()
    """``(reason, field_name)`` pairs. Codes only - a payload value is never kept."""

    @property
    def rejected_count(self) -> int:
        return len(self.rejections)

    def rejection_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for reason, _field_name in self.rejections:
            counts[reason] = counts.get(reason, 0) + 1
        return counts


def normalize_all(
    entries: Iterable[Mapping[str, Any]],
    *,
    source: JobSource,
    policy: FetchPolicy | None = None,
    now: datetime | None = None,
    apply_hosts: frozenset[str] = frozenset(),
    ids: Sequence[str | int | None] | None = None,
) -> NormaliseOutcome:
    """Normalise every entry, collecting rejections instead of raising.

    One malformed entry must not cost a whole poll: the rest of the feed is
    still valid, and silently dropping the bad one would hide a feed that has
    started returning garbage.
    """
    moment = now or utcnow()
    records: list[NormalizedJob] = []
    rejections: list[tuple[str, str | None]] = []
    for index, entry in enumerate(entries):
        external_id = ids[index] if ids is not None and index < len(ids) else None
        try:
            records.append(
                normalize_record(
                    entry,
                    source=source,
                    policy=policy,
                    now=moment,
                    apply_hosts=apply_hosts,
                    external_id=external_id,
                )
            )
        except RecordRejectedError as exc:
            rejections.append((exc.reason, exc.field_name))
            logger.info(
                "JOB_SOURCE_RECORD_REJECTED",
                extra={
                    "source_code": source.code,
                    "reason": exc.reason,
                    "field": exc.field_name,
                },
            )
    return NormaliseOutcome(records=tuple(records), rejections=tuple(rejections))


def payload_source_hosts(source: JobSource) -> frozenset[str]:
    """The host allowlist a source's own ``base_url`` implies."""
    return allowed_hosts_from_base_url(source.base_url)


__all__ = [
    "EMPLOYMENT_ALIASES",
    "EXPERIENCE_ALIASES",
    "LISTING_STATE_ALIASES",
    "MAX_EXTERNAL_ID_LENGTH",
    "MAX_SOURCE_URL_LENGTH",
    "SALARY_PERIOD_ALIASES",
    "ListingState",
    "NormalisationWarning",
    "NormaliseOutcome",
    "NormalizedJob",
    "RecordRejectedError",
    "RejectionReason",
    "normalize_all",
    "normalize_record",
    "payload_hash",
    "payload_source_hosts",
    "url_is_permitted",
]
