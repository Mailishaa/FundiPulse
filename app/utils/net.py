"""Network helpers shared by the audit writer and the request context.

Both need the same rule: *never let an unvalidated address reach the database*,
because ``audit_logs.ip_address`` is an ``INET`` column and a malformed value
raises at flush time. A spoofed ``X-Forwarded-For`` header would then turn into a
500 and, worse, a failure right where a security event was being recorded.

Keeping one implementation means the two call sites cannot drift apart - which is
how the audit writer ended up accepting values the request context rejected.
"""

from __future__ import annotations

import ipaddress


def coerce_ip_address(value: str | None) -> str | None:
    """Return a normalised address string, or ``None`` if it is not one.

    Accepts only a literal IPv4 or IPv6 address. Host names, Unix socket paths and
    arbitrary strings are rejected, because the column is ``INET`` and those would
    raise at write time.

    Fails closed: an unusable address is simply absent from the audit row rather
    than crashing the write.
    """
    if not value:
        return None

    candidate = value.strip()
    # An IPv6 link-local address may carry a scope id ("fe80::1%eth0"); PostgreSQL
    # INET does not accept it.
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None
