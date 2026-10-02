"""Date helpers.

Date boundaries are computed in UTC, never server-local time: a worker in Nairobi
and a server in UTC differ by six hours, so a local-time "today" accepts a
record that is still in the future for half the day. Replaces ``date.today()``,
which ruff's ``DTZ`` rule flags for the same reason.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

DAYS_PER_YEAR = Decimal("365.25")
TENTH = Decimal("0.1")


def utc_today() -> date:
    return datetime.now(UTC).date()


def years_between(start: date, end: date) -> Decimal:
    """Years between two dates, to one decimal.

    Calendar-aware: a six-month job should read as 0.5 years, not 0.16. Returns 0
    for an inverted range rather than a negative figure an employer would find
    meaningless.
    """
    if end <= start:
        return Decimal("0.0")
    return (Decimal((end - start).days) / DAYS_PER_YEAR).quantize(TENTH)


def union_months(intervals: list[tuple[date, date | None]]) -> Decimal:
    """Total years covered by possibly-overlapping date ranges.

    Merges overlaps because concurrent roles must not double-count: overstating
    experience is exactly what an employer is being asked to trust. An open-ended
    range runs until today.
    """
    if not intervals:
        return Decimal("0.0")

    resolved = sorted((start, end if end is not None else utc_today()) for start, end in intervals)
    merged: list[list[date]] = []
    for start, end in resolved:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        elif end > merged[-1][1]:
            merged[-1][1] = end

    total_days = sum((end - start).days for start, end in merged)
    return (Decimal(total_days) / DAYS_PER_YEAR).quantize(TENTH)


def date_range_is_sane(start: date, end: date | None) -> bool:
    return start <= end <= utc_today() if end is not None else start <= utc_today()


def clamp_to_today(value: date) -> date:
    """So a clock skew or bad import cannot credit days that have not happened."""
    return min(value, utc_today())


def days_ago(value: datetime) -> int:
    return max(0, (datetime.now(UTC) - value).days)


def add_days(value: date, days: int) -> date:
    return value + timedelta(days=days)
