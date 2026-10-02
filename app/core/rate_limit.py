"""Fixed-window rate limiting."""

from __future__ import annotations

import abc
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import threading
import time
from types import MappingProxyType
from typing import Any
import uuid

from app.core.config import Settings, get_settings
from app.core.exceptions import RateLimitExceededError, ServiceUnavailableError
from app.utils.net import coerce_ip_address

#: Bump when the identity key layout changes, so old counters are orphaned
#: rather than silently reinterpreted.
KEY_NAMESPACE = "fundipulse:ratelimit"

DEFAULT_RULE_NAME = "default"

#: In-memory store ceiling. Well above any legitimate population; saturating it is
#: already a degraded state, so evicting the least-recently-touched keys beats
#: exhausting the heap.
MAX_ENTRIES = 50_000

RATE_LIMIT_RULE_NAMES: tuple[str, ...] = (
    "login",
    "register",
    "password_reset",
    "password_change",
    "verification_request",
    "file_upload",
    "job_apply",
    "search",
)


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    name: str
    limit: int
    window_seconds: int

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError("limit must be >= 1")
        if self.window_seconds < 1:
            raise ValueError("window_seconds must be >= 1 second")


def build_rules(settings: Settings | None = None) -> dict[str, RateLimitRule]:
    """Map the existing ``Settings`` limit fields onto named rules."""
    settings = settings or get_settings()
    minute = 60
    hour = 3600
    day = 86400
    return {
        "login": RateLimitRule("login", settings.rate_limit_login_per_5_min, 5 * minute),
        "register": RateLimitRule("register", settings.rate_limit_register_per_hour, hour),
        "password_reset": RateLimitRule(
            "password_reset", settings.rate_limit_password_reset_per_hour, hour
        ),
        "password_change": RateLimitRule(
            "password_change", settings.rate_limit_password_change_per_hour, hour
        ),
        "verification_request": RateLimitRule(
            "verification_request", settings.rate_limit_verification_request_per_day, day
        ),
        "file_upload": RateLimitRule("file_upload", settings.rate_limit_file_upload_per_hour, hour),
        "job_apply": RateLimitRule("job_apply", settings.rate_limit_job_apply_per_day, day),
        "search": RateLimitRule("search", settings.rate_limit_search_per_minute, minute),
    }


RATE_LIMIT_RULES = MappingProxyType(build_rules())


def default_rule(settings: Settings | None = None) -> RateLimitRule:
    """The allowance for anything not named above. Not part of ``build_rules``."""
    settings = settings or get_settings()
    return RateLimitRule(DEFAULT_RULE_NAME, settings.rate_limit_default_per_minute, 60)


def rate_limit_rule(name: str, settings: Settings | None = None) -> RateLimitRule:
    """Look a rule up by name, falling back to the default."""
    return build_rules(settings).get(name) or default_rule(settings)


# --------------------------------------------------------------------------- #
# Identity                                                                    #
# --------------------------------------------------------------------------- #
#: Used when neither a user nor an address can be derived. Shared deliberately:
#: raising would turn a diagnostic gap into an outage, and one bucket is still a
#: ceiling. The cost is that unrelated anonymous callers exhaust each other's
#: allowance.
SHARED_SUBJECT = "shared"


def _user_subject(user_id: uuid.UUID | str | None) -> str | None:
    """Accept only a real UUID."""
    if user_id is None:
        return None
    try:
        return f"user:{uuid.UUID(str(user_id))}"
    except (ValueError, AttributeError, TypeError):
        return None


def _ip_subject(client_ip: str | None) -> str | None:
    """Normalise with ``ipaddress`` so IPv6 forms and whitespace collapse."""
    validated = coerce_ip_address(client_ip) if client_ip else None
    return f"ip:{validated}" if validated else None


def resolve_identity(
    rule_name: str,
    *,
    user_id: uuid.UUID | str | None = None,
    client_ip: str | None = None,
) -> str:
    """Build the counter key."""
    subject = _user_subject(user_id) or _ip_subject(client_ip) or SHARED_SUBJECT
    return f"{rule_name}|{subject}"


def _window_index(now: float, window_seconds: int) -> int:
    """Epoch-align the window so every client sees the same reset edge."""
    return int(now // window_seconds)


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    reset_after_seconds: int

    @property
    def retry_after_seconds(self) -> int:
        """Seconds until the window resets. ``0`` while the request is allowed."""
        if self.allowed:
            return 0
        return max(1, self.reset_after_seconds)

    def standard_headers(self) -> dict[str, str]:
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(self.reset_after_seconds),
        }
        if not self.allowed:
            headers["Retry-After"] = str(self.retry_after_seconds)
        return headers


# --------------------------------------------------------------------------- #
# Stores                                                                      #
# --------------------------------------------------------------------------- #
class RateLimitStore(abc.ABC):
    """Counter backend. ``increment`` returns ``(count, reset_after_seconds)``."""

    @abc.abstractmethod
    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        """Count this hit and report when the window ends."""

    @abc.abstractmethod
    def reset(self) -> None:
        """Clear all counters. For tests and operational flushes."""


@dataclass(slots=True)
class _Counter:
    window_index: int
    count: int
    window_seconds: int
    seq: int = 0


class InMemoryRateLimitStore(RateLimitStore):
    """Thread-safe, single-process. Not shared across workers."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        max_entries: int = MAX_ENTRIES,
        prune_every: int = 100,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        if prune_every < 1:
            raise ValueError("prune_every must be >= 1")
        self._clock = clock
        self._max_entries = max_entries
        self._prune_every = prune_every
        self._since_prune = 0
        self._seq = 0
        self._lock = threading.Lock()
        self._counters: dict[str, _Counter] = {}

    @property
    def entry_count(self) -> int:
        with self._lock:
            return len(self._counters)

    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        if window_seconds < 1:
            raise ValueError("window_seconds must be >= 1 second")
        now = self._clock()
        index = _window_index(now, window_seconds)
        with self._lock:
            # Prune on a cadence: scanning every key on every request is O(n).
            self._since_prune += 1
            if self._since_prune >= self._prune_every or len(self._counters) > self._max_entries:
                self._prune(now)
                self._since_prune = 0
                self._evict_if_full()
            counter = self._counters.get(key)
            if counter is None or counter.window_index != index:
                counter = _Counter(window_index=index, count=0, window_seconds=window_seconds)
                self._counters[key] = counter
            counter.count += 1
            self._seq += 1
            counter.seq = self._seq
            self._evict_if_full()
            reset_after = int((index + 1) * window_seconds - now)
            return counter.count, max(1, reset_after)

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()

    def _prune(self, now: float) -> None:
        """Drop counters whose window has passed. Call with the lock held."""
        stale = [
            key
            for key, counter in self._counters.items()
            if _window_index(now, counter.window_seconds) > counter.window_index
        ]
        for key in stale:
            del self._counters[key]

    def _evict_if_full(self) -> None:
        if len(self._counters) <= self._max_entries:
            return
        # Saturation is already degraded; evicting the coldest keys beats OOM.
        ordered = sorted(self._counters.items(), key=lambda kv: kv[1].seq)
        for key, _ in ordered[: len(self._counters) - self._max_entries]:
            del self._counters[key]


_REDIS_LUA = """
local t = redis.call('TIME')
local now = t[1] + t[2] / 1000000
local window = tonumber(ARGV[1])
local index = math.floor(now / window)
local ttl = index * window + window - now

local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], math.ceil(ttl * 1000))
end
return {count, math.ceil(ttl)}
"""


class RedisRateLimitStore(RateLimitStore):
    """Shared counters for multi-instance deployments."""

    def __init__(
        self,
        *,
        redis_url: str | None = None,
        client: Any | None = None,
        settings: Settings | None = None,
        key_prefix: str | None = None,
    ) -> None:
        self._key_prefix = key_prefix or KEY_NAMESPACE
        self._client = client if client is not None else self._connect(redis_url, settings)
        self._script: Any | None = None

    def _connect(self, redis_url: str | None, settings: Settings | None) -> Any:
        import importlib

        settings = settings or get_settings()
        url = redis_url or settings.redis_url.get_secret_value()
        if not url:
            raise ServiceUnavailableError("RATE_LIMIT_BACKEND=redis requires REDIS_URL to be set.")
        try:
            redis = importlib.import_module("redis")
        except ImportError as exc:
            raise ServiceUnavailableError(
                "RATE_LIMIT_BACKEND=redis requires the 'redis' package, which is not "
                "installed. Install it or set RATE_LIMIT_BACKEND=memory."
            ) from exc
        return redis.Redis.from_url(url, decode_responses=True)

    @property
    def key_prefix(self) -> str:
        return self._key_prefix

    def _key(self, identity: str) -> str:
        return f"{self._key_prefix}:{identity}"

    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        if window_seconds < 1:
            raise ValueError("window_seconds must be >= 1 second")
        try:
            count, reset_after = self._invoke(key, window_seconds)
            return int(count), max(1, int(reset_after))
        except ServiceUnavailableError:
            raise
        except Exception as exc:
            # Fail closed: a silent allow when Redis is unreachable would remove
            # the only control in front of credential stuffing.
            raise ServiceUnavailableError(
                "The rate limit store is temporarily unavailable."
            ) from exc

    def _invoke(self, key: str, window_seconds: int) -> Any:
        """Prefer a registered script; fall back to EVAL for plain drivers."""
        full_key = self._key(key)
        register = getattr(self._client, "register_script", None)
        if register is not None and self._script is None:
            self._script = register(_REDIS_LUA)
        if self._script is not None:
            return self._script([], [full_key, str(window_seconds)])
        return self._client.eval(_REDIS_LUA, 1, full_key, str(window_seconds))

    def reset(self) -> None:
        """Flush this namespace in batches. SCAN rather than KEYS, which blocks."""
        pending: list[str] = []
        for key in self._client.scan_iter(match=f"{self._key_prefix}:*", count=500):
            pending.append(key)
            if len(pending) >= 500:
                self._client.delete(*pending)
                pending = []
        if pending:
            self._client.delete(*pending)


def build_store(settings: Settings | None = None, **kwargs: Any) -> RateLimitStore:
    """Select a store from configuration."""
    settings = settings or get_settings()
    if settings.rate_limit_backend == "redis":
        return RedisRateLimitStore(settings=settings, **kwargs)
    return InMemoryRateLimitStore(**kwargs)


# --------------------------------------------------------------------------- #
# Limiter                                                                     #
# --------------------------------------------------------------------------- #
class RateLimiter:
    def __init__(
        self,
        settings: Settings | None = None,
        store: RateLimitStore | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._store = store if store is not None else build_store(self._settings)

    @property
    def store(self) -> RateLimitStore:
        return self._store

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def rules(self) -> Mapping[str, RateLimitRule]:
        return MappingProxyType(build_rules(self._settings))

    @property
    def default_rule(self) -> RateLimitRule:
        return default_rule(self._settings)

    def rule_for(self, name: str) -> RateLimitRule:
        return rate_limit_rule(name, self._settings)

    def check(self, rule: RateLimitRule, identity: str) -> RateLimitDecision:
        """Count the hit and report, without raising."""
        if not self._settings.rate_limit_enabled:
            # No window is opened, so there is nothing to wait for.
            return RateLimitDecision(
                allowed=True, limit=rule.limit, remaining=rule.limit, reset_after_seconds=0
            )
        count, reset_after = self._store.increment(identity, rule.window_seconds)
        return RateLimitDecision(
            allowed=count <= rule.limit,
            limit=rule.limit,
            remaining=max(0, rule.limit - count),
            reset_after_seconds=reset_after,
        )

    def enforce(self, rule: RateLimitRule, identity: str) -> RateLimitDecision:
        """Like ``check``, but raises when the limit is exhausted."""
        decision = self.check(rule, identity)
        if not decision.allowed:
            raise RateLimitExceededError(
                retry_after_seconds=decision.retry_after_seconds,
                headers=decision.standard_headers(),
            )
        return decision


@lru_cache(maxsize=1)
def get_rate_limiter() -> RateLimiter:
    return RateLimiter()


def reset_rate_limiter() -> None:
    """Clear the cached limiter. For tests and settings reloads."""
    get_rate_limiter.cache_clear()


def fingerprint(identity: str) -> str:
    """Stable short digest of a key, for logs that must not carry an address."""
    return hashlib.blake2b(identity.encode(), digest_size=8).hexdigest()
