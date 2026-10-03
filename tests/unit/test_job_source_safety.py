"""The guard, tested exhaustively and offline.

Every test here drives :mod:`app.services.job_sources.safety` with an injected
resolver (a table of addresses, never DNS) and an injected transport (a queue of
canned responses, never a socket). Nothing in this file, or anywhere else in this
suite, opens a network connection - which is the point: an SSRF guard whose tests
reach the network are tests that assert against whatever the internet happened to
answer that day.

The cases below are the ones that decide whether the guard is worth having: the
allowlist on a label boundary, the schemes, every private range and its
neighbours, the metadata endpoints, IPv4-mapped IPv6, redirects that leave the
allowlist, the byte cap, and the limits a caller cannot exceed. Then the registry
gate, because a guard that a source with unreviewed terms can still reach is not a
gate.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from app.core.constants import (
    JobSourceRobotsStatus,
    JobSourceTermsStatus,
    JobSourceType,
)
from app.db.base import utcnow
from app.db.models.job import JobSource
from app.services.job_sources.base import FieldMap, MappingConnector
from app.services.job_sources.registry import (
    JobSourceRegistry,
    RefusalReason,
    SourceNotPermittedError,
)
from app.services.job_sources.safety import (
    ALLOWED_SCHEMES,
    DEFAULT_MAX_RESPONSE_BYTES,
    HARD_MAX_RESPONSE_BYTES,
    HARD_MAX_TIMEOUT_SECONDS,
    ApprovedTarget,
    FetchGuard,
    FetchPolicy,
    FetchRefusedError,
    FetchRefusedReason,
    FetchRequest,
    FetchResponse,
    Transport,
    allowed_hosts_from_base_url,
    classify_address,
    host_is_allowed,
    validate_url,
)

pytestmark = [pytest.mark.unit, pytest.mark.integration]

PUBLIC_IP = "93.184.216.34"

#: A host that resolves to a public address, and nothing else. Any hostname a test
#: uses that is not in this table fails closed with ``dns_empty``, which keeps a
#: typo from accidentally becoming a live lookup.
DNS: dict[str, tuple[str, ...]] = {
    "localhost": ("127.0.0.1", "::1"),
    "jobs.example.com": (PUBLIC_IP,),
    "feeds.example.com": (PUBLIC_IP,),
    "cdn.jobs.example.com": (PUBLIC_IP,),
    "apply.partner-ats.example.com": (PUBLIC_IP,),
    "partner.example.com": (PUBLIC_IP,),
    "evil-attacker.example.net": (PUBLIC_IP,),
    "notexample.com": (PUBLIC_IP,),
    "rebinding.example.com": (PUBLIC_IP, "10.1.2.3"),
    "nxdomain.example.com": (),
}


def resolver(host: str, port: int = 443) -> tuple[str, ...]:
    """A resolver that reads a table. Raises like a real one on an unknown host."""
    if host in DNS:
        return DNS[host]
    raise OSError(f"Name or service not known: {host}")


class ScriptedTransport(Transport):
    """Replays canned responses and records what it was asked to do."""

    def __init__(self, responses: list[FetchResponse] | None = None) -> None:
        self.responses = list(responses or [])
        self.requests: list[FetchRequest] = []

    def fetch(self, request: FetchRequest) -> FetchResponse:
        self.requests.append(request)
        if not self.responses:
            return FetchResponse(url=request.target.url, status_code=200, body=b"{}")
        return self.responses.pop(0)


def policy(*hosts: str, **kwargs: object) -> FetchPolicy:
    kwargs.setdefault("source_code", "coastal-board")
    return FetchPolicy(allowed_hosts=frozenset(hosts), **kwargs)  # type: ignore[arg-type]


def guard(
    *hosts: str,
    responses: list[FetchResponse] | None = None,
    **kwargs: object,
) -> FetchGuard:
    transport = ScriptedTransport(responses)
    return FetchGuard(policy(*hosts, **kwargs), resolver=resolver, transport=transport)


def refusal_reason(excinfo: pytest.ExceptionInfo[FetchRefusedError]) -> str:
    return str(excinfo.value.reason)


# --------------------------------------------------------------------------- #
# Allowlist                                                                   #
# --------------------------------------------------------------------------- #
def test_allowlisted_https_host_is_approved() -> None:
    target = validate_url(
        "https://jobs.example.com/feed.json?page=1", policy("jobs.example.com"), resolver=resolver
    )
    assert target.scheme == "https"
    assert target.host == "jobs.example.com"
    assert target.port == 443
    assert target.resolved == (PUBLIC_IP,)
    assert target.url == "https://jobs.example.com/feed.json?page=1"


def test_a_domain_the_source_did_not_register_is_refused() -> None:
    with pytest.raises(FetchRefusedError) as excinfo:
        validate_url(
            "https://evil-attacker.example.net/jobs", policy("jobs.example.com"), resolver=resolver
        )
    assert refusal_reason(excinfo) == FetchRefusedReason.HOST_NOT_ALLOWLISTED
    assert excinfo.value.detail == "evil-attacker.example.net"


def test_a_suffix_match_without_a_label_boundary_is_refused() -> None:
    """``notexample.com`` must not satisfy an allowlist of ``example.com``."""
    assert host_is_allowed("example.com", frozenset({"example.com"}))
    assert host_is_allowed("feeds.example.com", frozenset({"example.com"}))
    assert host_is_allowed("EXAMPLE.COM.", frozenset({"example.com"}))
    assert not host_is_allowed("notexample.com", frozenset({"example.com"}))
    assert not host_is_allowed("example.com.evil.net", frozenset({"example.com"}))
    assert not host_is_allowed("", frozenset({"example.com"}))
    with pytest.raises(FetchRefusedError) as excinfo:
        validate_url("https://notexample.com/feed", policy("example.com"), resolver=resolver)
    assert refusal_reason(excinfo) == FetchRefusedReason.HOST_NOT_ALLOWLISTED


def test_a_host_on_the_allowlist_is_still_judged_by_its_addresses() -> None:
    """Allowlisting is about who we may ask, not about what we may reach."""
    allowed = guard("rebinding.example.com")
    with pytest.raises(FetchRefusedError) as excinfo:
        allowed.fetch("https://rebinding.example.com/feed.json")
    assert refusal_reason(excinfo) == FetchRefusedReason.PRIVATE


def test_a_source_with_no_usable_base_url_can_allowlist_nothing() -> None:
    assert allowed_hosts_from_base_url(None) == frozenset()
    assert allowed_hosts_from_base_url("http://jobs.example.com") == frozenset()
    assert allowed_hosts_from_base_url("https://jobs.example.com") == frozenset(
        {"jobs.example.com"}
    )
    with pytest.raises(FetchRefusedError) as excinfo:
        validate_url("https://jobs.example.com/feed", policy(), resolver=resolver)
    assert refusal_reason(excinfo) == FetchRefusedReason.NO_ALLOWLIST_CONFIGURED


# --------------------------------------------------------------------------- #
# Scheme                                                                      #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url",
    [
        "http://jobs.example.com/feed.json",
        "ftp://jobs.example.com/feed.json",
        "file:///etc/passwd",
        "data:text/html,<script>alert(1)</script>",
        "gopher://jobs.example.com/",
        "//jobs.example.com/feed.json",
    ],
)
def test_only_https_is_ever_fetched(url: str) -> None:
    with pytest.raises(FetchRefusedError) as excinfo:
        validate_url(url, policy("jobs.example.com"), resolver=resolver)
    assert refusal_reason(excinfo) == FetchRefusedReason.SCHEME_NOT_ALLOWED


def test_the_scheme_allowlist_is_exactly_https() -> None:
    assert frozenset({"https"}) == ALLOWED_SCHEMES


# --------------------------------------------------------------------------- #
# Addresses                                                                   #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("host", "reason"),
    [
        ("127.0.0.1", FetchRefusedReason.LOOPBACK),
        ("127.53.1.9", FetchRefusedReason.LOOPBACK),
        ("localhost", FetchRefusedReason.LOOPBACK),
        ("[::1]", FetchRefusedReason.LOOPBACK),
        ("::1", FetchRefusedReason.LOOPBACK),
        ("169.254.169.254", FetchRefusedReason.METADATA_ENDPOINT),
        ("169.254.170.2", FetchRefusedReason.METADATA_ENDPOINT),
        ("100.100.100.200", FetchRefusedReason.METADATA_ENDPOINT),
        ("10.0.0.1", FetchRefusedReason.PRIVATE),
        ("10.255.255.254", FetchRefusedReason.PRIVATE),
        ("192.168.1.1", FetchRefusedReason.PRIVATE),
        ("172.16.0.1", FetchRefusedReason.PRIVATE),
        ("172.31.255.254", FetchRefusedReason.PRIVATE),
        ("fd00::1", FetchRefusedReason.PRIVATE),
        ("fe80::1", FetchRefusedReason.LINK_LOCAL),
        ("224.0.0.1", FetchRefusedReason.MULTICAST),
        ("240.0.0.1", FetchRefusedReason.RESERVED),
        ("0.0.0.0", FetchRefusedReason.UNSPECIFIED),  # noqa: S104
        ("::ffff:10.0.0.1", FetchRefusedReason.PRIVATE),
        ("::ffff:192.168.0.1", FetchRefusedReason.PRIVATE),
        ("::ffff:169.254.169.254", FetchRefusedReason.METADATA_ENDPOINT),
        ("::ffff:127.0.0.1", FetchRefusedReason.LOOPBACK),
    ],
)
def test_no_address_outside_the_public_internet_is_reachable(host: str, reason: str) -> None:
    """Each host is allowlisted, so only the address rule can be what refuses it."""
    is_ipv6_literal = ":" in host and not host.startswith("[")
    url = f"https://[{host}]/feed.json" if is_ipv6_literal else f"https://{host}/feed.json"
    allowed = frozenset({host.strip("[]")})
    with pytest.raises(FetchRefusedError) as excinfo:
        validate_url(url, policy(*allowed), resolver=resolver)
    assert refusal_reason(excinfo) == reason


@pytest.mark.parametrize(
    "address",
    ["172.15.255.254", "172.32.0.1", "9.255.255.254", "11.0.0.0", "192.167.255.255", "192.169.0.0"],
)
def test_the_addresses_beside_the_private_ranges_are_not_refused_by_range(address: str) -> None:
    assert classify_address(address) == ""


def test_an_ipv4_mapped_private_address_is_judged_as_ipv4() -> None:
    """``::ffff:10.0.0.1`` is a costume, and the costume must not change the verdict."""
    assert classify_address("::ffff:10.0.0.1") == FetchRefusedReason.PRIVATE
    assert classify_address("::ffff:8.8.8.8") == ""


def test_an_unresolvable_name_is_refused_rather_than_assumed_safe() -> None:
    with pytest.raises(FetchRefusedError) as excinfo:
        validate_url(
            "https://nxdomain.example.com/feed", policy("nxdomain.example.com"), resolver=resolver
        )
    assert refusal_reason(excinfo) == FetchRefusedReason.DNS_EMPTY


def test_a_resolver_failure_is_a_refusal_not_a_crash() -> None:
    with pytest.raises(FetchRefusedError) as excinfo:
        validate_url(
            "https://unknown.example.com/feed", policy("unknown.example.com"), resolver=resolver
        )
    assert refusal_reason(excinfo) == FetchRefusedReason.DNS_FAILED


# --------------------------------------------------------------------------- #
# URL shape                                                                   #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://user:pass@jobs.example.com/feed", FetchRefusedReason.USERINFO_IN_URL),
        ("https://jobs.example.com:8443/feed", FetchRefusedReason.NON_DEFAULT_PORT),
        ("https://jobs.example.com:22/feed", FetchRefusedReason.NON_DEFAULT_PORT),
        ("   ", FetchRefusedReason.MALFORMED_URL),
        ("https:///feed", FetchRefusedReason.MALFORMED_URL),
        ("https://jobs.example.com/" + "a" * 2000, FetchRefusedReason.MALFORMED_URL),
    ],
)
def test_a_malformed_or_surprising_url_is_refused(url: str, reason: str) -> None:
    with pytest.raises(FetchRefusedError) as excinfo:
        validate_url(url, policy("jobs.example.com"), resolver=resolver)
    assert refusal_reason(excinfo) == reason


def test_an_explicit_https_port_is_accepted() -> None:
    target = validate_url(
        "https://jobs.example.com:443/feed", policy("jobs.example.com"), resolver=resolver
    )
    assert target.port == 443


# --------------------------------------------------------------------------- #
# Redirects                                                                   #
# --------------------------------------------------------------------------- #
def test_a_redirect_off_the_allowlist_is_refused() -> None:
    guarded = guard(
        "jobs.example.com",
        responses=[
            FetchResponse(
                url="https://jobs.example.com/feed",
                status_code=302,
                headers={"Location": "https://evil-attacker.example.net/feed"},
            )
        ],
    )
    with pytest.raises(FetchRefusedError) as excinfo:
        guarded.fetch("https://jobs.example.com/feed")
    assert refusal_reason(excinfo) == FetchRefusedReason.HOST_NOT_ALLOWLISTED


def test_a_redirect_to_a_private_address_is_refused() -> None:
    """The metadata address is refused even by a host the source is allowed to ask."""
    guarded = guard(
        "jobs.example.com",
        "169.254.169.254",
        responses=[
            FetchResponse(
                url="https://jobs.example.com/feed",
                status_code=307,
                headers={"Location": "https://169.254.169.254/latest/meta-data/"},
            )
        ],
    )
    with pytest.raises(FetchRefusedError) as excinfo:
        guarded.fetch("https://jobs.example.com/feed")
    assert refusal_reason(excinfo) == FetchRefusedReason.METADATA_ENDPOINT


def test_a_redirect_down_to_http_is_refused() -> None:
    guarded = guard(
        "jobs.example.com",
        responses=[
            FetchResponse(
                url="https://jobs.example.com/feed",
                status_code=301,
                headers={"Location": "http://jobs.example.com/feed"},
            )
        ],
    )
    with pytest.raises(FetchRefusedError) as excinfo:
        guarded.fetch("https://jobs.example.com/feed")
    assert refusal_reason(excinfo) == FetchRefusedReason.SCHEME_NOT_ALLOWED


def test_a_relative_redirect_stays_on_the_approved_host_and_is_followed() -> None:
    transport = ScriptedTransport(
        [
            FetchResponse(
                url="https://jobs.example.com/feed",
                status_code=302,
                headers={"Location": "/v2/feed.json"},
            ),
            FetchResponse(
                url="https://jobs.example.com/v2/feed.json",
                status_code=200,
                body=b'{"ok": true}',
            ),
        ]
    )
    guarded = FetchGuard(policy("jobs.example.com"), resolver=resolver, transport=transport)
    result = guarded.fetch("https://jobs.example.com/feed")
    assert result.url == "https://jobs.example.com/v2/feed.json"
    assert result.hops == 1
    assert result.json() == {"ok": True}


def test_a_redirect_without_a_location_is_refused() -> None:
    guarded = guard(
        "jobs.example.com",
        responses=[FetchResponse(url="https://jobs.example.com/feed", status_code=302)],
    )
    with pytest.raises(FetchRefusedError) as excinfo:
        guarded.fetch("https://jobs.example.com/feed")
    assert refusal_reason(excinfo) == FetchRefusedReason.REDIRECT_MALFORMED


def test_a_redirect_loop_is_refused() -> None:
    transport = ScriptedTransport(
        [
            FetchResponse(
                url="https://jobs.example.com/a",
                status_code=302,
                headers={"Location": "https://jobs.example.com/b"},
            ),
            FetchResponse(
                url="https://jobs.example.com/b",
                status_code=302,
                headers={"Location": "https://jobs.example.com/a"},
            ),
        ]
    )
    guarded = FetchGuard(policy("jobs.example.com"), resolver=resolver, transport=transport)
    with pytest.raises(FetchRefusedError) as excinfo:
        guarded.fetch("https://jobs.example.com/a")
    assert refusal_reason(excinfo) == FetchRefusedReason.REDIRECT_LOOP


def test_too_many_redirects_is_refused() -> None:
    transport = ScriptedTransport(
        [
            FetchResponse(
                url=f"https://jobs.example.com/hop{index}",
                status_code=302,
                headers={"Location": f"https://jobs.example.com/hop{index + 1}"},
            )
            for index in range(8)
        ]
    )
    guarded = FetchGuard(
        policy("jobs.example.com", max_redirects=2), resolver=resolver, transport=transport
    )
    with pytest.raises(FetchRefusedError) as excinfo:
        guarded.fetch("https://jobs.example.com/hop0")
    assert refusal_reason(excinfo) == FetchRefusedReason.TOO_MANY_REDIRECTS


# --------------------------------------------------------------------------- #
# Size and time limits                                                        #
# --------------------------------------------------------------------------- #
def test_an_oversized_declared_length_is_refused_before_the_body_is_read() -> None:
    guarded = guard(
        "jobs.example.com",
        responses=[
            FetchResponse(
                url="https://jobs.example.com/feed",
                status_code=200,
                body=b"{}",
                declared_length=DEFAULT_MAX_RESPONSE_BYTES + 1,
            )
        ],
    )
    with pytest.raises(FetchRefusedError) as excinfo:
        guarded.fetch("https://jobs.example.com/feed")
    assert refusal_reason(excinfo) == FetchRefusedReason.RESPONSE_TOO_LARGE


def test_an_oversized_body_is_refused_even_when_the_length_lies() -> None:
    guarded = guard(
        "jobs.example.com",
        responses=[
            FetchResponse(
                url="https://jobs.example.com/feed",
                status_code=200,
                body=b"x" * 2048,
                declared_length=10,
            )
        ],
        max_response_bytes=1024,
    )
    with pytest.raises(FetchRefusedError) as excinfo:
        guarded.fetch("https://jobs.example.com/feed")
    assert refusal_reason(excinfo) == FetchRefusedReason.RESPONSE_TOO_LARGE


def test_a_caller_cannot_widen_the_byte_cap() -> None:
    transport = ScriptedTransport(
        [FetchResponse(url="https://jobs.example.com/feed", status_code=200, body=b"{}")]
    )
    guarded = FetchGuard(
        policy("jobs.example.com", max_response_bytes=4096),
        resolver=resolver,
        transport=transport,
    )
    guarded.fetch("https://jobs.example.com/feed", max_bytes=64 * 1024 * 1024)
    assert transport.requests[0].max_bytes == 4096


def test_a_caller_cannot_widen_the_timeout() -> None:
    transport = ScriptedTransport(
        [FetchResponse(url="https://jobs.example.com/feed", status_code=200, body=b"{}")]
    )
    guarded = FetchGuard(
        policy("jobs.example.com", timeout_seconds=5.0),
        resolver=resolver,
        transport=transport,
    )
    guarded.fetch("https://jobs.example.com/feed", timeout_seconds=900)
    assert transport.requests[0].timeout_seconds == 5.0


@pytest.mark.parametrize("requested", [None, 0, -1])
def test_a_missing_or_non_positive_timeout_means_the_policy_default(
    requested: float | None,
) -> None:
    transport = ScriptedTransport(
        [FetchResponse(url="https://jobs.example.com/feed", status_code=200, body=b"{}")]
    )
    guarded = FetchGuard(
        policy("jobs.example.com", timeout_seconds=7.5), resolver=resolver, transport=transport
    )
    guarded.fetch("https://jobs.example.com/feed", timeout_seconds=requested)
    assert transport.requests[0].timeout_seconds == 7.5


def test_the_policy_caps_are_hard_ceilings() -> None:
    from app.db.models.job import JobSource as Source

    generous = FetchPolicy.from_source(
        Source(code="x", name="x", base_url="https://jobs.example.com"),
        max_response_bytes=10**9,
        timeout_seconds=10**6,
    )
    assert generous.max_response_bytes == HARD_MAX_RESPONSE_BYTES
    assert generous.timeout_seconds == HARD_MAX_TIMEOUT_SECONDS
    modest = FetchPolicy.from_source(
        Source(code="x", name="x", base_url="https://jobs.example.com"),
        max_response_bytes=1024,
        timeout_seconds=1.0,
    )
    assert modest.max_response_bytes == 1024
    assert modest.timeout_seconds == 1.0
    assert FetchPolicy.from_source(Source(code="x", name="x")).allowed_hosts == frozenset()


# --------------------------------------------------------------------------- #
# The guard cannot be bypassed by hand                                         #
# --------------------------------------------------------------------------- #
def test_an_approved_target_cannot_be_fabricated() -> None:
    """A connector cannot mint an approval; only the guard issues one."""
    with pytest.raises(PermissionError):
        ApprovedTarget(
            object(), "https://evil-attacker.example.net/feed", "https", "evil.example.net", 443
        )


def test_localhost_is_refused_twice_over(db_session: Session) -> None:
    """Off the allowlist, and on it but resolving inward."""
    with pytest.raises(FetchRefusedError) as off_list:
        validate_url("https://localhost/feed", policy("jobs.example.com"), resolver=resolver)
    assert refusal_reason(off_list) == FetchRefusedReason.HOST_NOT_ALLOWLISTED
    with pytest.raises(FetchRefusedError) as on_list:
        validate_url("https://localhost/feed", policy("localhost"), resolver=resolver)
    assert refusal_reason(on_list) == FetchRefusedReason.LOOPBACK


def test_a_transport_only_accepts_an_approved_request() -> None:
    request = FetchRequest.approved(
        "https://jobs.example.com/feed", policy("jobs.example.com"), resolver=resolver
    )
    assert request.target.host == "jobs.example.com"
    assert request.approve_next("https://cdn.jobs.example.com/feed.json").target.host == (
        "cdn.jobs.example.com"
    )


def test_a_guard_without_a_transport_refuses_rather_than_opening_a_socket() -> None:
    guarded = FetchGuard(policy("jobs.example.com"), resolver=resolver)
    with pytest.raises(FetchRefusedError) as excinfo:
        guarded.fetch("https://jobs.example.com/feed")
    assert excinfo.value.detail == "no_transport_configured"


def test_no_route_exposes_the_guard() -> None:
    """No endpoint accepts a URL and fetches it. Structural, not aspirational."""
    import pathlib

    forbidden = ("safe_fetch", "FetchPolicy", "FetchGuard", "validate_url", "FetchRequest")
    routes = pathlib.Path("app/api/routes")
    offenders = [
        path.name
        for path in sorted(routes.glob("*.py"))
        if any(token in path.read_text() for token in forbidden)
    ]
    assert offenders == [], f"an API route references the ingestion guard: {offenders}"


# --------------------------------------------------------------------------- #
# Registry gate: terms, robots, disablement                                   #
# --------------------------------------------------------------------------- #
def make_source(
    session: Session,
    **kwargs: object,
) -> JobSource:
    defaults: dict[str, object] = {
        "code": f"src-{uuid.uuid4().hex[:8]}",
        "name": "Coastal Jobs Board",
        "source_type": JobSourceType.AGGREGATED_PUBLIC.value,
        "base_url": "https://jobs.example.com",
        "terms_status": JobSourceTermsStatus.APPROVED.value,
        "robots_status": JobSourceRobotsStatus.PERMITTED.value,
        "respect_robots": True,
        "is_active": True,
        "rate_limit_per_minute": 10,
    }
    defaults.update(kwargs)
    source = JobSource(**defaults)  # type: ignore[arg-type]
    session.add(source)
    session.flush()
    return source


def test_an_unreviewed_source_is_refused_by_the_registry(db_session: Session) -> None:
    """Terms default to UNKNOWN, so forgetting to review fails closed."""
    source = make_source(db_session, terms_status=JobSourceTermsStatus.UNKNOWN.value)
    registry = JobSourceRegistry(db_session)
    with pytest.raises(SourceNotPermittedError) as excinfo:
        registry.require_permitted(source)
    assert excinfo.value.reason.startswith(RefusalReason.TERMS_NOT_APPROVED)
    assert source not in registry.enabled()
    assert registry.refusals()[source.id].reason == excinfo.value.reason


@pytest.mark.parametrize(
    "status",
    [
        JobSourceTermsStatus.UNDER_REVIEW,
        JobSourceTermsStatus.REJECTED,
        JobSourceTermsStatus.PROHIBITED,
    ],
)
def test_every_terms_status_other_than_approved_is_refused(
    db_session: Session, status: JobSourceTermsStatus
) -> None:
    source = make_source(db_session, terms_status=status.value)
    with pytest.raises(SourceNotPermittedError) as excinfo:
        JobSourceRegistry(db_session).require_permitted(source)
    assert excinfo.value.reason.startswith(RefusalReason.TERMS_NOT_APPROVED)


@pytest.mark.parametrize(
    "status",
    [
        JobSourceRobotsStatus.UNKNOWN,
        JobSourceRobotsStatus.RESTRICTED,
        JobSourceRobotsStatus.DISALLOWED,
    ],
)
def test_robots_must_permit_automated_fetching_while_they_are_respected(
    db_session: Session, status: JobSourceRobotsStatus
) -> None:
    source = make_source(db_session, robots_status=status.value)
    with pytest.raises(SourceNotPermittedError) as excinfo:
        JobSourceRegistry(db_session).require_permitted(source)
    assert excinfo.value.reason.startswith(RefusalReason.ROBOTS_NOT_PERMITTED)


def test_the_robots_flag_cannot_launder_an_unreviewed_source(db_session: Session) -> None:
    """``respect_robots=False`` is an operator decision about automation only."""
    source = make_source(
        db_session,
        terms_status=JobSourceTermsStatus.UNDER_REVIEW.value,
        robots_status=JobSourceRobotsStatus.DISALLOWED.value,
        respect_robots=False,
    )
    with pytest.raises(SourceNotPermittedError) as excinfo:
        JobSourceRegistry(db_session).require_permitted(source)
    assert excinfo.value.reason.startswith(RefusalReason.TERMS_NOT_APPROVED)


def test_an_operator_may_record_that_robots_do_not_apply(db_session: Session) -> None:
    source = make_source(
        db_session,
        robots_status=JobSourceRobotsStatus.DISALLOWED.value,
        respect_robots=False,
    )
    registry = JobSourceRegistry(db_session)
    registry.require_permitted(source)
    assert source in registry.enabled()


def test_a_source_can_be_disabled_without_a_deploy(db_session: Session) -> None:
    source = make_source(db_session)
    registry = JobSourceRegistry(db_session)
    assert source in registry.enabled()
    source.is_active = False
    db_session.flush()
    assert source not in registry.enabled()
    assert registry.refusals()[source.id].is_disabled
    with pytest.raises(SourceNotPermittedError) as excinfo:
        registry.require_permitted(source)
    assert excinfo.value.reason == RefusalReason.INACTIVE


def test_the_pipeline_refuses_a_disabled_source_before_it_fetches(
    db_session: Session,
) -> None:
    source = make_source(db_session, is_active=False)
    transport = ScriptedTransport(
        [FetchResponse(url=source.base_url or "", status_code=200, body=b"[]")]
    )
    connector = MappingConnector(
        guard=FetchGuard(FetchPolicy.from_source(source), resolver=resolver, transport=transport),
        code=source.code,
        field_map=FieldMap(source={"id": "external_id", "title": "title"}),
    )
    from app.services.job_sources.pipeline import IngestionPipeline

    pipeline = IngestionPipeline(db_session, guard=connector.guard)
    with pytest.raises(SourceNotPermittedError):
        pipeline.run(connector, source, now=utcnow())
    assert transport.requests == []


# --------------------------------------------------------------------------- #
# The remaining corners of the guard                                           #
# --------------------------------------------------------------------------- #
def test_a_refusal_serialises_with_its_reason() -> None:
    error = FetchRefusedError(FetchRefusedReason.HOST_NOT_ALLOWLISTED, detail="evil.example.net")
    payload = error.as_dict()
    assert payload["reason"] == "host_not_allowlisted"
    assert payload["code"] == error.code
    # The message carries the reason; the detail stays separate and structural.
    assert "host_not_allowlisted" in str(error)
    assert error.detail == "evil.example.net"


def test_an_address_with_an_ipv6_scope_id_is_still_judged() -> None:
    """A scope id is presentation; ``fe80`` underneath it is still link-local."""
    assert classify_address("fe80::1%eth0") == FetchRefusedReason.LINK_LOCAL
    assert classify_address("::1%lo0") == FetchRefusedReason.LOOPBACK


def test_something_that_is_not_an_address_at_all_is_not_routable() -> None:
    assert classify_address("not-an-address") == FetchRefusedReason.DNS_FAILED


def test_a_port_that_is_not_a_port_is_refused_rather_than_crashing() -> None:
    with pytest.raises(FetchRefusedError) as excinfo:
        validate_url(
            "https://jobs.example.com:notaport/feed", policy("jobs.example.com"), resolver=resolver
        )
    assert refusal_reason(excinfo) == FetchRefusedReason.NON_DEFAULT_PORT
    assert excinfo.value.detail == "bad_port"


def test_approving_without_a_transport_refuses() -> None:
    guarded = FetchGuard(policy("jobs.example.com"), resolver=resolver)
    request = FetchRequest.approved(
        "https://jobs.example.com/feed", guarded.policy, resolver=resolver
    )
    with pytest.raises(FetchRefusedError) as excinfo:
        guarded.execute(request)
    assert excinfo.value.detail == "no_transport_configured"


def test_a_protocol_relative_redirect_stays_on_the_approved_scheme() -> None:
    transport = ScriptedTransport(
        [
            FetchResponse(
                url="https://jobs.example.com/feed",
                status_code=302,
                headers={"Location": "//cdn.jobs.example.com/feed.json"},
            ),
            FetchResponse(
                url="https://cdn.jobs.example.com/feed.json", status_code=200, body=b"{}"
            ),
        ]
    )
    guarded = FetchGuard(policy("jobs.example.com"), resolver=resolver, transport=transport)
    result = guarded.fetch("https://jobs.example.com/feed")
    assert result.url == "https://cdn.jobs.example.com/feed.json"


def test_a_response_carries_its_declared_media_type() -> None:
    response = FetchResponse(
        url="https://jobs.example.com/feed",
        status_code=200,
        headers={"Content-Type": "APPLICATION/JSON"},
    )
    assert response.content_type == "APPLICATION/JSON"
    assert response.size_bytes == 0
    assert FetchResponse(url="x", status_code=204).header("content-type") is None


def test_no_stage_of_the_pipeline_reaches_dns(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The strongest form of "these tests are offline": DNS itself is made fatal.

    Every stage of a real poll runs here - guard, connector, dedupe, change
    detection, store - with ``getaddrinfo`` replaced by an assertion. If any of
    them ever fell back to the system resolver, this test would fail rather than
    quietly depend on whatever the internet answered.
    """
    import socket

    from app.services.job_sources.base import FieldMap, MappingConnector
    from app.services.job_sources.pipeline import IngestionPipeline

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("the ingestion suite must never resolve a hostname")

    monkeypatch.setattr(socket, "getaddrinfo", explode)

    source = JobSource(
        id=uuid.uuid4(),
        code="offline-source",
        name="Offline Source",
        source_type=JobSourceType.AGGREGATED_PUBLIC.value,
        base_url="https://jobs.example.com",
        terms_status=JobSourceTermsStatus.APPROVED.value,
        robots_status=JobSourceRobotsStatus.PERMITTED.value,
        # Column defaults are applied on INSERT, so an unflushed row has to say so:
        # an unset ``is_active`` reads as inactive, which is the fail-closed answer.
        is_active=True,
    )
    transport = ScriptedTransport(
        [
            FetchResponse(
                url="https://jobs.example.com/feed.json",
                status_code=200,
                body=b'{"results": []}',
                headers={"Content-Type": "application/json"},
            )
        ]
    )
    connector = MappingConnector(
        guard=FetchGuard(FetchPolicy.from_source(source), resolver=resolver, transport=transport),
        code=source.code,
        records_key="results",
        field_map=FieldMap(source={"id": "external_id"}, required=("external_id",)),
    )
    pipeline = IngestionPipeline(db_session, guard=connector.guard)
    result = pipeline.run(connector, source, now=utcnow())

    assert result.counts.parsed == 0
    assert transport.requests[0].target.resolved == (PUBLIC_IP,)
