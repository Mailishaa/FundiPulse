"""The SSRF guard: the only door any connector may fetch through.

Every outbound read in this package goes through :func:`safe_fetch`. There is no
"fetch this URL" helper anywhere else, and there is deliberately no endpoint that
accepts a URL from a client, so no user-supplied string can reach this module.

The guard is **deny by default**. A request is approved only when every one of
these holds, and any single failure refuses the whole fetch:

* the scheme is ``https`` (never ``http``, never ``file:``/``data:``/``ftp:``);
* the host is on the allowlist derived from the owning ``JobSource.base_url`` -
  the host itself or a subdomain of it, matched on a dot boundary so that
  ``notexample.com`` never satisfies ``example.com``;
* the URL carries no embedded credentials and no non-default port;
* **every** address the host resolves to is globally routable. All of them, not
  the first: a name that resolves to one public and one private address is the
  classic DNS-rebinding payload, so a single "good" answer proves nothing.

Refused categories include loopback, private, link-local (which is where the
cloud metadata service lives), CGNAT, multicast, reserved and unspecified
addresses; IPv4-mapped IPv6 forms are unwrapped and judged as the IPv4 address
they really are; and the well-known metadata endpoints are refused by name so
the refusal reason is unambiguous.

Redirects are re-validated hop by hop and refused outright when they leave the
allowlist. The byte cap and the timeout are properties of the *policy*, not of the
caller: a connector asking for a larger limit than the policy allows is silently
clamped, so no future connector can widen the guard by asking nicely.
"""

from __future__ import annotations

import abc
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
import ipaddress
import socket
from typing import Final
from urllib.parse import urlsplit, urlunsplit

from app.core.exceptions import AppError, ErrorCode
from app.core.logging import get_logger
from app.db.models.job import JobSource

logger = get_logger(__name__)

#: The only scheme this codebase will fetch. Plain HTTP would allow an on-path
#: attacker to rewrite a feed, and ``file:``/``data:`` are not the network at all.
ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"https"})

#: Cloud instance-metadata endpoints, refused by name as well as by category so
#: the reason is legible in a log rather than "link-local".
METADATA_ADDRESSES: Final[frozenset[str]] = frozenset(
    {
        "169.254.169.254",  # AWS / GCP / Azure / OpenStack / DigitalOcean
        "169.254.170.2",  # AWS ECS task metadata
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle Cloud
        "fd00:ec2::254",  # AWS IMDS over IPv6
    }
)

#: Longest URL accepted. ``jobs.source_url`` is ``VARCHAR(1024)``; a listing URL
#: longer than that cannot be stored, so fetching it would waste a request.
MAX_URL_LENGTH: Final[int] = 1024

#: Default and hard ceiling on a response body. An aggregator feed that answers
#: with 400 MiB is either broken or hostile, and either way is not a feed.
DEFAULT_MAX_RESPONSE_BYTES: Final[int] = 2 * 1024 * 1024
HARD_MAX_RESPONSE_BYTES: Final[int] = 8 * 1024 * 1024

#: Default and hard ceiling on a single request's timeout.
DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0
HARD_MAX_TIMEOUT_SECONDS: Final[float] = 30.0

#: Redirect hops followed before giving up. Zero is the right default for an
#: allowlisted source: a redirect is unusual, and every hop is re-validated.
DEFAULT_MAX_REDIRECTS: Final[int] = 3

#: Guards against a redirect loop between two allowlisted URLs.
MAX_REDIRECT_CHAIN: Final[int] = 6


class FetchRefusedReason:
    """Stable refusal reasons. Logged and asserted on; never shown to a client."""

    SCHEME_NOT_ALLOWED = "scheme_not_allowed"
    MALFORMED_URL = "malformed_url"
    USERINFO_IN_URL = "userinfo_in_url"
    NON_DEFAULT_PORT = "non_default_port"
    HOST_NOT_ALLOWLISTED = "host_not_allowlisted"
    NO_ALLOWLIST_CONFIGURED = "no_allowlist_configured"
    ADDRESS_NOT_ROUTABLE = "address_not_routable"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    PRIVATE = "private"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    UNSPECIFIED = "unspecified"
    METADATA_ENDPOINT = "metadata_endpoint"
    DNS_EMPTY = "dns_empty"
    DNS_FAILED = "dns_failed"
    REDIRECT_OFF_ALLOWLIST = "redirect_off_allowlist"
    REDIRECT_MALFORMED = "redirect_malformed"
    REDIRECT_LOOP = "redirect_loop"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    RESPONSE_TOO_LARGE = "response_too_large"
    TIMEOUT_INVALID = "timeout_invalid"


class FetchRefusedError(AppError):
    """The guard refused to issue a request.

    An :class:`AppError` so a caller on a request path would surface as a mapped
    response, but ingestion runs on a schedule where this is an operational
    event, not a user error.
    """

    code = ErrorCode.FORBIDDEN
    status_code = 403
    public_message = "The requested source is not permitted to be fetched."

    def __init__(self, reason: str, *, detail: str | None = None) -> None:
        super().__init__(f"fetch refused ({reason})")
        self.reason = reason
        #: Structural context only - a hostname or a port. Never response content.
        self.detail = detail

    def as_dict(self) -> dict[str, object]:
        return {"code": self.code, "message": self.message, "reason": self.reason}


#: Resolves a hostname to the addresses a connection could reach. Injected in
#: every test, which is why the suite never touches DNS.
AddressResolver = Callable[[str, int], Iterable[str]]


def system_resolver(host: str, port: int = 443) -> tuple[str, ...]:
    """Resolve *host* through the system resolver.

    The single place in this package that can touch DNS, and it is only reachable
    after the URL has already been checked against the allowlist and the scheme.
    """
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return tuple(dict.fromkeys(str(info[4][0]) for info in infos))


class AddressNotRoutableError(Exception):
    """An address failed the routability rule. Carries the reason for the log."""

    def __init__(self, reason: str, address: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.address = address


def classify_address(address: str) -> str:
    """Return a :class:`FetchRefusedReason` member if *address* is not routable.

    ``None`` means the address is globally routable. ``is_global`` is the primary
    rule because it is the negation of every "you must not fetch this" category
    at once; the explicit checks exist so the refusal reason names the actual
    problem instead of a catch-all.
    """
    literal = coerce_address(address)
    if literal is None:
        return FetchRefusedReason.DNS_FAILED
    if str(literal) in METADATA_ADDRESSES:
        return FetchRefusedReason.METADATA_ENDPOINT
    # An IPv4-mapped IPv6 address is the same host in a costume; judging it as
    # IPv6 would let ``::ffff:10.0.0.1`` through any "is this IPv6 private?"
    # reasoning, so it is unwrapped and judged as the address it really is.
    mapped = getattr(literal, "ipv4_mapped", None)
    if mapped is not None:
        return classify_address(str(mapped))
    if literal.is_unspecified:
        return FetchRefusedReason.UNSPECIFIED
    if literal.is_loopback:
        return FetchRefusedReason.LOOPBACK
    if literal.is_link_local:
        return FetchRefusedReason.LINK_LOCAL
    if literal.is_multicast:
        return FetchRefusedReason.MULTICAST
    if literal.is_reserved:
        return FetchRefusedReason.RESERVED
    if literal.is_private:
        return FetchRefusedReason.PRIVATE
    if not literal.is_global:
        return FetchRefusedReason.ADDRESS_NOT_ROUTABLE
    return ""


def coerce_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP literal, stripping an IPv6 scope id first."""
    candidate = value.strip()
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def assert_routable(addresses: Iterable[str]) -> tuple[str, ...]:
    """Raise :class:`AddressNotRoutableError` unless *every* address is routable."""
    resolved = tuple(dict.fromkeys(str(address).strip() for address in addresses))
    if not resolved:
        raise AddressNotRoutableError(FetchRefusedReason.DNS_EMPTY, "")
    for address in resolved:
        reason = classify_address(address)
        if reason:
            raise AddressNotRoutableError(reason, address)
    return resolved


def host_is_allowed(host: str, allowed_hosts: frozenset[str]) -> bool:
    """Whether *host* is on the allowlist, on a label boundary.

    ``example.com`` allows ``example.com`` and ``feeds.example.com``. It does
    not allow ``notexample.com``: a plain ``endswith`` would, and that single
    missing dot is the whole difference between an allowlist and no allowlist.
    """
    normalised = host.strip().rstrip(".").lower()
    if not normalised:
        return False
    return any(
        normalised == entry or normalised.endswith(f".{entry}")
        for entry in (candidate.rstrip(".").lower() for candidate in allowed_hosts)
    )


@dataclass(frozen=True, slots=True)
class FetchPolicy:
    """Everything a connector is *not* allowed to decide for itself.

    Built from the owning :class:`~app.db.models.job.JobSource`, so the allowlist
    is operator-controlled data rather than something a connector ships.
    """

    allowed_hosts: frozenset[str] = frozenset()
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    source_code: str = ""
    user_agent: str = "FundiPulse-JobAggregator/1.0"
    accepted_content_types: frozenset[str] = frozenset({"application/json"})

    @classmethod
    def from_source(
        cls,
        source: JobSource,
        *,
        max_response_bytes: int | None = None,
        timeout_seconds: float | None = None,
        max_redirects: int | None = None,
    ) -> FetchPolicy:
        """Derive a policy from a source's registered ``code`` and ``base_url``.

        A source with no usable ``base_url`` yields an empty allowlist, and an
        empty allowlist refuses everything - which is the correct outcome, since
        a target we cannot validate is a target we must not fetch.
        """
        return cls(
            allowed_hosts=allowed_hosts_from_base_url(source.base_url),
            # Clamped from above only. An operator may tighten a source below the
            # defaults; nothing may loosen it past the hard ceiling.
            max_response_bytes=int(
                min(
                    float(max_response_bytes or DEFAULT_MAX_RESPONSE_BYTES),
                    float(HARD_MAX_RESPONSE_BYTES),
                )
            ),
            timeout_seconds=min(
                float(timeout_seconds or DEFAULT_TIMEOUT_SECONDS), HARD_MAX_TIMEOUT_SECONDS
            ),
            max_redirects=max_redirects if max_redirects is not None else DEFAULT_MAX_REDIRECTS,
            source_code=source.code,
        )

    def clamp_timeout(self, requested: float | None) -> float:
        """The timeout that will actually be used.

        ``None`` and non-positive values mean "unset", not "unlimited": a caller
        that forgets the argument gets the policy default, and a caller that asks
        for more gets clamped rather than obeyed.
        """
        if requested is None or requested <= 0:
            return self.timeout_seconds
        return cap(float(requested), 0.1, self.timeout_seconds)

    def clamp_max_bytes(self, requested: int | None) -> int:
        """The byte ceiling that will actually be enforced."""
        if requested is None or requested <= 0:
            return self.max_response_bytes
        return min(int(requested), self.max_response_bytes)


def cap(value: float, low: float, high: float) -> float:
    """Clamp *value* into ``[low, high]``."""
    return max(low, min(float(value), high))


def allowed_hosts_from_base_url(base_url: str | None) -> frozenset[str]:
    """The host allowlist implied by a source's registered ``base_url``."""
    if not base_url:
        return frozenset()
    parts = urlsplit(base_url.strip())
    if parts.scheme not in ALLOWED_SCHEMES or not parts.hostname:
        return frozenset()
    return frozenset({parts.hostname.rstrip(".").lower()})


#: Guards the only constructor of :class:`ApprovedTarget`. Module-private on
#: purpose: a value that cannot be named from another module cannot be forged.
_APPROVAL_TOKEN: Final[object] = object()


@dataclass(frozen=True, slots=True, init=False)
class ApprovedTarget:
    """A URL that passed every rule. Only :func:`validate_url` creates one.

    Holding one is the proof of approval, which is why it is a separate type from
    a bare string: nothing downstream has to re-derive whether a URL was checked,
    and no caller can fabricate one. The constructor takes a token that exists
    only in this module, so a :class:`FetchRequest` cannot be built around a URL
    that never passed the guard.
    """

    url: str
    scheme: str
    host: str
    port: int
    resolved: tuple[str, ...] = ()

    def __init__(
        self,
        token: object,
        url: str,
        scheme: str,
        host: str,
        port: int,
        resolved: tuple[str, ...] = (),
    ) -> None:
        if token is not _APPROVAL_TOKEN:
            raise PermissionError(
                "ApprovedTarget is issued only by app.services.job_sources.safety.validate_url"
            )
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "resolved", tuple(resolved))


def validate_url(
    url: str,
    policy: FetchPolicy,
    *,
    resolver: AddressResolver | None = None,
) -> ApprovedTarget:
    """Approve *url* against *policy*, or raise :class:`FetchRefusedError`.

    Order matters: the allowlist is checked before DNS, so a host nobody is
    permitted to fetch is never even resolved.
    """
    if not url.strip():
        raise FetchRefusedError(FetchRefusedReason.MALFORMED_URL, detail="empty")
    candidate = url.strip()
    if len(candidate) > MAX_URL_LENGTH:
        raise FetchRefusedError(FetchRefusedReason.MALFORMED_URL, detail="too_long")

    try:
        parts = urlsplit(candidate)
    except ValueError as exc:  # pragma: no cover - urlsplit rarely raises
        raise FetchRefusedError(FetchRefusedReason.MALFORMED_URL, detail="unparsable") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise FetchRefusedError(FetchRefusedReason.SCHEME_NOT_ALLOWED, detail=scheme or "none")
    if parts.username or parts.password:
        raise FetchRefusedError(FetchRefusedReason.USERINFO_IN_URL, detail="userinfo")
    try:
        host = (parts.hostname or "").strip().rstrip(".").lower()
        port = parts.port
    except ValueError as exc:
        raise FetchRefusedError(FetchRefusedReason.NON_DEFAULT_PORT, detail="bad_port") from exc
    if not host:
        raise FetchRefusedError(FetchRefusedReason.MALFORMED_URL, detail="no_host")
    if port not in (None, 443):
        raise FetchRefusedError(FetchRefusedReason.NON_DEFAULT_PORT, detail=str(port))

    if not policy.allowed_hosts:
        raise FetchRefusedError(FetchRefusedReason.NO_ALLOWLIST_CONFIGURED, detail=host)
    if not host_is_allowed(host, policy.allowed_hosts):
        raise FetchRefusedError(FetchRefusedReason.HOST_NOT_ALLOWLISTED, detail=host)

    literal = coerce_address(host)
    addresses: tuple[str, ...]
    if literal is not None:
        # The host is an address, so there is no DNS step to trust.
        addresses = (str(literal),)
    else:
        resolve = resolver or system_resolver
        try:
            addresses = tuple(resolve(host, port or 443))
        except AddressNotRoutableError:
            raise
        except (OSError, ValueError) as exc:
            logger.warning(
                "JOB_SOURCE_DNS_FAILED",
                extra={"source_code": policy.source_code, "host": host},
            )
            raise FetchRefusedError(FetchRefusedReason.DNS_FAILED, detail=host) from exc

    try:
        routable = assert_routable(addresses)
    except AddressNotRoutableError as exc:
        logger.warning(
            "JOB_SOURCE_ADDRESS_REFUSED",
            extra={
                "source_code": policy.source_code,
                "host": host,
                "reason": exc.reason,
                "address": exc.address,
            },
        )
        raise FetchRefusedError(exc.reason, detail=exc.address) from exc

    return ApprovedTarget(
        _APPROVAL_TOKEN,
        urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, "")),
        scheme,
        host,
        port or 443,
        routable,
    )


@dataclass(frozen=True, slots=True)
class FetchRequest:
    """An approved fetch, with the limits already clamped.

    The constructor takes an approval rather than a URL, so a connector cannot
    hand a raw string to a transport even by mistake.
    """

    target: ApprovedTarget
    policy: FetchPolicy
    timeout_seconds: float
    max_bytes: int
    #: Carried so a redirect hop is resolved by the same resolver as the original,
    #: rather than falling back to the system one behind the caller's back.
    resolver: AddressResolver = field(default=system_resolver, repr=False, compare=False)

    @classmethod
    def approved(
        cls,
        url: str,
        policy: FetchPolicy,
        *,
        resolver: AddressResolver | None = None,
        timeout_seconds: float | None = None,
        max_bytes: int | None = None,
    ) -> FetchRequest:
        target = validate_url(url, policy, resolver=resolver)
        return cls(
            target=target,
            policy=policy,
            timeout_seconds=policy.clamp_timeout(timeout_seconds),
            max_bytes=policy.clamp_max_bytes(max_bytes),
            resolver=resolver or system_resolver,
        )

    def approve_next(self, location: str) -> FetchRequest:
        """Approve a redirect hop under the same policy, resolver and limits."""
        target = validate_url(location, self.policy, resolver=self.resolver)
        return FetchRequest(
            target=target,
            policy=self.policy,
            timeout_seconds=self.timeout_seconds,
            max_bytes=self.max_bytes,
            resolver=self.resolver,
        )


@dataclass(frozen=True, slots=True)
class FetchResponse:
    """One HTTP response. ``body`` is bytes, never a decoded string.

    Nothing here is logged: a response body is third-party content that may carry
    personal data, so only counts and identifiers are ever recorded.
    """

    url: str
    status_code: int
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    declared_length: int | None = None
    truncated: bool = False

    @property
    def content_type(self) -> str | None:
        """The declared media type, lower-cased. A connector may require JSON."""
        return self.header("content-type")

    @property
    def size_bytes(self) -> int:
        return len(self.body)

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None


class Transport(abc.ABC):
    """Performs an already-approved fetch.

    Abstract so the pipeline cannot be handed a transport at runtime by anything
    but application wiring, and so a test fake is a deliberate, visible subclass.
    """

    @abc.abstractmethod
    def fetch(self, request: FetchRequest) -> FetchResponse:
        """Issue *request*, honouring ``timeout_seconds`` and ``max_bytes``."""


@dataclass(frozen=True, slots=True)
class SafeFetchResult:
    """A completed, guarded fetch."""

    url: str
    body: bytes
    status_code: int
    hops: int
    size_bytes: int
    content_type: str | None = None

    def json(self) -> object:
        """Parse the body as JSON. The only way a payload enters the pipeline."""
        import json

        return json.loads(self.body)


class FetchGuard:
    """Issues guarded fetches for one source.

    Holds the resolver rather than reaching for the global one, so a test injects
    a table of addresses instead of reaching DNS.
    """

    def __init__(
        self,
        policy: FetchPolicy,
        *,
        resolver: AddressResolver | None = None,
        transport: Transport | None = None,
    ) -> None:
        self._policy = policy
        self._resolver = resolver or system_resolver
        self._transport = transport

    @property
    def policy(self) -> FetchPolicy:
        return self._policy

    def approve(
        self,
        url: str,
        *,
        timeout_seconds: float | None = None,
        max_bytes: int | None = None,
    ) -> FetchRequest:
        """Approve *url* without fetching it."""
        return FetchRequest.approved(
            url,
            self._policy,
            resolver=self._resolver,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
        )

    def fetch(
        self,
        url: str,
        *,
        timeout_seconds: float | None = None,
        max_bytes: int | None = None,
    ) -> SafeFetchResult:
        """Fetch *url* through the guard, following only approved redirects."""
        transport = self._transport
        if transport is None:
            raise FetchRefusedError(FetchRefusedReason.DNS_FAILED, detail="no_transport_configured")
        return self.execute(
            self.approve(url, timeout_seconds=timeout_seconds, max_bytes=max_bytes),
            transport=transport,
        )

    def execute(
        self, request: FetchRequest, *, transport: Transport | None = None
    ) -> SafeFetchResult:
        """Run the approved request, re-validating every redirect hop."""
        active = transport or self._transport
        if active is None:
            raise FetchRefusedError(FetchRefusedReason.DNS_FAILED, detail="no_transport_configured")
        current = request
        visited: list[str] = [current.target.url]
        hops = 0
        while True:
            response = active.fetch(current)
            self._enforce_size(current, response)
            location = self._redirect_location(current, response)
            if location is None:
                logger.info(
                    "JOB_SOURCE_FETCHED",
                    extra={
                        "source_code": current.policy.source_code,
                        "url": current.target.url,
                        "status_code": response.status_code,
                        "size_bytes": response.size_bytes,
                        "hops": hops,
                    },
                )
                return SafeFetchResult(
                    url=current.target.url,
                    body=response.body,
                    status_code=response.status_code,
                    hops=hops,
                    size_bytes=response.size_bytes,
                    content_type=response.content_type,
                )
            if hops >= current.policy.max_redirects:
                raise FetchRefusedError(FetchRefusedReason.TOO_MANY_REDIRECTS)
            hops += 1
            if len(visited) >= MAX_REDIRECT_CHAIN or location in visited:
                raise FetchRefusedError(FetchRefusedReason.REDIRECT_LOOP, detail=str(hops))
            visited.append(location)
            # Re-approval is the point: a hop that leaves the allowlist, drops to
            # http, or resolves inward never reaches the transport.
            nxt = current.approve_next(location)
            if not host_is_allowed(nxt.target.host, current.policy.allowed_hosts):
                # Unreachable while ``approve_next`` validates: kept so that a future
                # relaxation of approval cannot quietly open this door. That is a
                # deliberate second lock, not redundant logic.
                raise FetchRefusedError(
                    FetchRefusedReason.REDIRECT_OFF_ALLOWLIST, detail=nxt.target.host
                )
            current = nxt

    def _enforce_size(self, request: FetchRequest, response: FetchResponse) -> None:
        if (
            response.declared_length is not None and response.declared_length > request.max_bytes
        ) or response.size_bytes > request.max_bytes:
            logger.warning(
                "JOB_SOURCE_RESPONSE_TOO_LARGE",
                extra={
                    "source_code": request.policy.source_code,
                    "url": request.target.url,
                    "size_bytes": response.size_bytes,
                    "max_bytes": request.max_bytes,
                },
            )
            raise FetchRefusedError(
                FetchRefusedReason.RESPONSE_TOO_LARGE,
                detail=f"{response.size_bytes}>{request.max_bytes}",
            )

    def _redirect_location(self, request: FetchRequest, response: FetchResponse) -> str | None:
        """The next hop, or ``None`` when this response is the last one."""
        if response.status_code not in {301, 302, 303, 307, 308}:
            return None
        location = response.header("location")
        if not location:
            raise FetchRefusedError(FetchRefusedReason.REDIRECT_MALFORMED, detail="no_location")
        parts = urlsplit(location.strip())
        if parts.scheme and parts.scheme.lower() not in ALLOWED_SCHEMES:
            # A Location that names a scheme we do not fetch is refused outright.
            # Treating it as a path would quietly re-point the request at a URL
            # nobody approved.
            raise FetchRefusedError(
                FetchRefusedReason.SCHEME_NOT_ALLOWED, detail=parts.scheme.lower()
            )
        base = urlsplit(request.target.url)
        if parts.netloc:
            scheme = parts.scheme.lower() if parts.scheme else base.scheme
            return urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, ""))
        # A relative Location stays on the already-approved origin, so it is made
        # absolute and then re-approved like any other hop.
        return urlunsplit((base.scheme, base.netloc, parts.path or "/", parts.query, ""))


__all__ = [
    "ALLOWED_SCHEMES",
    "DEFAULT_MAX_REDIRECTS",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "HARD_MAX_RESPONSE_BYTES",
    "HARD_MAX_TIMEOUT_SECONDS",
    "METADATA_ADDRESSES",
    "AddressNotRoutableError",
    "AddressResolver",
    "ApprovedTarget",
    "FetchGuard",
    "FetchPolicy",
    "FetchRefusedError",
    "FetchRefusedReason",
    "FetchRequest",
    "FetchResponse",
    "SafeFetchResult",
    "Transport",
    "allowed_hosts_from_base_url",
    "assert_routable",
    "cap",
    "classify_address",
    "coerce_address",
    "host_is_allowed",
    "system_resolver",
    "validate_url",
]
