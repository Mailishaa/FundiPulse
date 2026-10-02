"""Unit tests for the rate limiting core.

Pure unit tests: no database, no HTTP client, no sleeping. Time is supplied by an
injected fake clock and advanced by hand, so every assertion here is exact and
the suite is deterministic - the same numbers at 3am under CI load as on a
laptop.

The Redis backend is exercised through injected fake clients, because ``redis``
is deliberately an optional dependency and is not installed. The *import*
failure path is asserted for real: that is the current situation, and it must
keep working.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import FrozenInstanceError
import importlib.util
import sys
import threading
import time
import uuid

import pytest

from app.core.config import Settings
from app.core.exceptions import RateLimitExceededError, ServiceUnavailableError
from app.core.rate_limit import (
    DEFAULT_RULE_NAME,
    RATE_LIMIT_RULE_NAMES,
    RATE_LIMIT_RULES,
    InMemoryRateLimitStore,
    RateLimitDecision,
    RateLimiter,
    RateLimitRule,
    RateLimitStore,
    RedisRateLimitStore,
    build_rules,
    build_store,
    default_rule,
    get_rate_limiter,
    rate_limit_rule,
    reset_rate_limiter,
    resolve_identity,
)

pytestmark = pytest.mark.unit

#: A float that is exactly representable in binary and divisible by the 300s
#: login window, so ``reset_after_seconds`` lands on whole numbers and can be
#: asserted exactly rather than with a tolerance.
WINDOW_START = 1_700_000_100.0


class FakeClock:
    """A monotonic clock the test drives by hand.

    Injected rather than monkeypatched so the store cannot reach the real clock
    even by accident.
    """

    def __init__(self, start: float = WINDOW_START) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def store(clock: FakeClock) -> InMemoryRateLimitStore:
    # prune_every=1 so the pruning and cap paths are the ones under test rather
    # than a path that only runs once every thousand writes.
    return InMemoryRateLimitStore(clock=clock, prune_every=1)


@pytest.fixture
def settings() -> Settings:
    """Small, explicit limits so no test needs more than a handful of calls."""
    return Settings(
        app_env="test",
        rate_limit_enabled=True,
        rate_limit_login_per_5_min=3,
        rate_limit_register_per_hour=2,
        rate_limit_search_per_minute=4,
        rate_limit_default_per_minute=7,
    )


@pytest.fixture
def limiter(
    settings: Settings,
    store: InMemoryRateLimitStore,
) -> RateLimiter:
    return RateLimiter(settings=settings, store=store)


def _identity(rule: str = "login", ip: str = "203.0.113.9") -> str:
    return resolve_identity(rule, client_ip=ip)


# --------------------------------------------------------------------------- #
# Rules                                                                        #
# --------------------------------------------------------------------------- #
class TestRules:
    def test_named_rules_come_from_settings(self, settings: Settings) -> None:
        rules = build_rules(settings)

        assert rules["login"].limit == 3
        assert rules["login"].window_seconds == 300
        assert rules["register"].limit == 2
        assert rules["register"].window_seconds == 3600
        assert rules["search"].window_seconds == 60
        assert rules["job_apply"].window_seconds == 86400
        assert rules["verification_request"].window_seconds == 86400

    def test_every_documented_rule_name_is_built(self, settings: Settings) -> None:
        assert set(RATE_LIMIT_RULE_NAMES) == set(build_rules(settings))
        assert set(RATE_LIMIT_RULES) == set(build_rules(settings))
        assert DEFAULT_RULE_NAME not in build_rules(settings)

    def test_default_rule_uses_the_configured_per_minute_budget(self, settings: Settings) -> None:
        rule = default_rule(settings)

        assert rule.name == DEFAULT_RULE_NAME
        assert rule.limit == 7
        assert rule.window_seconds == 60

    def test_unknown_rule_name_falls_back_to_the_default(self, settings: Settings) -> None:
        """A misspelled limit must still produce a limit, never an unbounded route."""
        rule = rate_limit_rule("definitely_not_a_rule", settings)

        assert rule == default_rule(settings)
        assert rule.limit == 7

    def test_module_level_mapping_is_live_not_a_snapshot(self) -> None:
        """`RATE_LIMIT_RULES` must not freeze settings at import time."""
        assert "login" in RATE_LIMIT_RULES
        assert set(RATE_LIMIT_RULES) == set(RATE_LIMIT_RULES)  # iterates consistently
        assert len(RATE_LIMIT_RULES) == 8
        assert RATE_LIMIT_RULES["login"].window_seconds == 300

    def test_a_rule_with_a_nonsense_limit_is_rejected_at_construction(self) -> None:
        # Loud failure at wiring time beats a 429 for every user in production.
        with pytest.raises(ValueError, match=">= 1"):
            RateLimitRule(name="login", limit=0, window_seconds=60)
        with pytest.raises(ValueError, match=">= 1 second"):
            RateLimitRule(name="login", limit=5, window_seconds=0)

    def test_rules_are_frozen(self, settings: Settings) -> None:
        rule = build_rules(settings)["login"]
        with pytest.raises(FrozenInstanceError):
            rule.limit = 999  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Identity                                                                     #
# --------------------------------------------------------------------------- #
class TestIdentity:
    def test_an_authenticated_user_id_beats_the_client_address(self) -> None:
        """Two workers behind one office NAT must not share a login bucket."""
        worker = uuid.uuid4()

        key = resolve_identity("login", user_id=worker, client_ip="41.223.16.4")

        assert key == f"login|user:{worker}"
        assert "41.223.16.4" not in key

    def test_anonymous_callers_are_keyed_on_the_validated_address(self) -> None:
        assert resolve_identity("login", client_ip="197.0.2.44") == "login|ip:197.0.2.44"

    def test_the_same_address_from_different_callers_shares_a_bucket(self) -> None:
        # Documented consequence of IP keying: a shared egress is one bucket.
        assert resolve_identity("login", client_ip="197.0.2.44") == resolve_identity(
            "login", client_ip="197.0.2.44"
        )

    def test_ipv6_is_normalised_before_it_becomes_a_key(self) -> None:
        assert resolve_identity("login", client_ip="2001:0DB8:0000::1") == ("login|ip:2001:db8::1")

    def test_the_rule_name_is_part_of_the_key(self) -> None:
        """Otherwise one endpoint's burst would starve another."""
        assert resolve_identity("login", client_ip="197.0.2.44") != resolve_identity(
            "register", client_ip="197.0.2.44"
        )

    def test_a_raw_forwarded_for_chain_is_never_used_as_a_key(self) -> None:
        """The header is client-controlled, so keying on it means no limit at all."""
        raw_chain = "197.0.2.44, 10.0.0.1, spoofed-garbage"

        assert resolve_identity("login", client_ip=raw_chain) == "login|shared"

    def test_a_hostname_is_not_a_valid_identity(self) -> None:
        assert resolve_identity("login", client_ip="testserver.local") == "login|shared"

    def test_an_unparseable_user_id_falls_through_instead_of_escaping_the_limit(self) -> None:
        """An unvalidated subject would let a caller mint unlimited buckets."""
        assert resolve_identity("login", user_id="not-a-uuid") == "login|shared"
        assert resolve_identity("login", user_id="not-a-uuid", client_ip="197.0.2.44") == (
            "login|ip:197.0.2.44"
        )

    def test_an_unidentifiable_caller_gets_the_shared_bucket(self) -> None:
        """Never raises: the endpoint has to stay reachable for everyone else."""
        assert resolve_identity("login") == "login|shared"
        assert resolve_identity("login", client_ip="") == "login|shared"
        assert resolve_identity("login", client_ip=None) == "login|shared"

    def test_the_shared_bucket_is_per_rule_not_global(self) -> None:
        assert resolve_identity("login") != resolve_identity("register")


# --------------------------------------------------------------------------- #
# Checking                                                                     #
# --------------------------------------------------------------------------- #
class TestCheck:
    def test_requests_under_the_limit_are_allowed_and_remaining_decrements(
        self, limiter: RateLimiter
    ) -> None:
        rule = limiter.rule_for("login")
        identity = _identity()

        first = limiter.check(rule, identity)
        second = limiter.check(rule, identity)
        third = limiter.check(rule, identity)

        assert first.allowed is True and first.remaining == 2
        assert second.allowed is True and second.remaining == 1
        # The request that exactly fills the allowance is still allowed.
        assert third.allowed is True and third.remaining == 0

    def test_the_request_over_the_limit_is_blocked(
        self, limiter: RateLimiter, clock: FakeClock
    ) -> None:
        rule = limiter.rule_for("login")
        identity = _identity()

        for _ in range(rule.limit):
            assert limiter.check(rule, identity).allowed is True

        blocked = limiter.check(rule, identity)

        assert blocked.allowed is False
        assert blocked.remaining == 0
        assert blocked.limit == rule.limit
        # The clock sits exactly on the window edge, so the whole window remains.
        assert blocked.reset_after_seconds == rule.window_seconds
        assert blocked.retry_after_seconds == rule.window_seconds

    def test_a_blocked_request_still_counts_so_retrying_cannot_reset_the_window(
        self, limiter: RateLimiter
    ) -> None:
        rule = limiter.rule_for("login")
        identity = _identity()

        for _ in range(rule.limit):
            assert limiter.check(rule, identity).allowed is True

        for _ in range(4):
            assert limiter.check(rule, identity).allowed is False

        still_blocked = limiter.check(rule, identity)

        # Still inside the same window: hammering the endpoint did not restart
        # the counter, and the window has not been pushed forward.
        assert still_blocked.allowed is False
        assert still_blocked.reset_after_seconds == rule.window_seconds

    def test_the_window_resets_once_the_clock_passes_it(
        self, limiter: RateLimiter, clock: FakeClock
    ) -> None:
        rule = limiter.rule_for("login")
        identity = _identity()

        for _ in range(rule.limit):
            limiter.check(rule, identity)
        assert limiter.check(rule, identity).allowed is False

        clock.advance(rule.window_seconds + 1)

        after_reset = limiter.check(rule, identity)

        assert after_reset.allowed is True
        assert after_reset.remaining == rule.limit - 1
        # One second past the old boundary, so the new window has 299s left.
        assert after_reset.reset_after_seconds == rule.window_seconds - 1

    def test_retry_after_shrinks_as_the_window_drains(
        self, limiter: RateLimiter, clock: FakeClock
    ) -> None:
        rule = limiter.rule_for("login")
        identity = _identity()

        for _ in range(rule.limit):
            limiter.check(rule, identity)
        first_block = limiter.check(rule, identity)

        clock.advance(120)
        later_block = limiter.check(rule, identity)

        assert later_block.retry_after_seconds < first_block.retry_after_seconds
        assert 0 < later_block.retry_after_seconds <= rule.window_seconds

    def test_disabling_rate_limits_allows_everything_without_touching_the_store(
        self, settings: Settings, store: InMemoryRateLimitStore
    ) -> None:
        disabled = RateLimiter(
            settings=settings.model_copy(update={"rate_limit_enabled": False}), store=store
        )
        rule = disabled.rule_for("login")
        identity = _identity()

        for _ in range(rule.limit * 3):
            decision = disabled.check(rule, identity)
            assert decision.allowed is True
            assert decision.remaining == rule.limit
            assert decision.reset_after_seconds == 0
            assert decision.retry_after_seconds == 0

        assert store.entry_count == 0

    def test_rules_have_independent_buckets(self, limiter: RateLimiter) -> None:
        """Exhausting login must not consume the register allowance."""
        login = limiter.rule_for("login")
        register = limiter.rule_for("register")
        identity = resolve_identity("register", client_ip="197.0.2.44")

        for _ in range(login.limit):
            login_decision = limiter.check(login, _identity())
            assert login_decision.allowed is True
        assert limiter.check(login, _identity()).allowed is False

        # A different rule, a different key, a fresh counter.
        register_decision = limiter.check(register, identity)

        assert register_decision.allowed is True
        assert register_decision.remaining == register.limit - 1

    def test_identities_have_independent_buckets(self, limiter: RateLimiter) -> None:
        rule = limiter.rule_for("login")
        alice = resolve_identity("login", user_id=uuid.UUID(int=1))
        bob = resolve_identity("login", user_id=uuid.UUID(int=2))

        for _ in range(rule.limit):
            limiter.check(rule, alice)
        assert limiter.check(rule, alice).allowed is False

        bob_decision = limiter.check(rule, bob)

        assert bob_decision.allowed is True
        assert bob_decision.remaining == rule.limit - 1

    def test_unidentifiable_callers_share_one_bucket(self, limiter: RateLimiter) -> None:
        """The documented abuse implication, asserted so it cannot change silently."""
        rule = limiter.rule_for("login")
        anonymous_a = resolve_identity("login")
        anonymous_b = resolve_identity("login", client_ip="not-an-address")

        for _ in range(rule.limit):
            assert limiter.check(rule, anonymous_a).allowed is True

        # An unrelated unidentified caller is blocked by the first one's usage.
        assert limiter.check(rule, anonymous_b).allowed is False

    def test_an_unscoped_identity_is_still_scoped_to_its_rule(self, limiter: RateLimiter) -> None:
        """Defence in depth: `check` must not trust a bare subject."""
        login = limiter.rule_for("login")
        register = limiter.rule_for("register")

        for _ in range(login.limit):
            limiter.check(login, "user:shared-subject")
        assert limiter.check(login, "user:shared-subject").allowed is False

        assert limiter.check(register, "user:shared-subject").allowed is True

    def test_enforce_raises_the_standard_429_with_retry_headers(self, limiter: RateLimiter) -> None:
        rule = limiter.rule_for("login")
        identity = _identity()

        for _ in range(rule.limit):
            assert limiter.enforce(rule, identity).allowed is True

        with pytest.raises(RateLimitExceededError) as caught:
            limiter.enforce(rule, identity)

        error = caught.value
        assert error.status_code == 429
        assert error.headers["Retry-After"] == str(rule.window_seconds)
        assert error.headers["X-RateLimit-Remaining"] == "0"
        assert error.headers["X-RateLimit-Limit"] == str(rule.limit)
        assert error.headers["X-RateLimit-Reset"] == str(rule.window_seconds)

    def test_enforce_returns_the_decision_when_allowed(self, limiter: RateLimiter) -> None:
        rule = limiter.rule_for("login")

        assert limiter.enforce(rule, _identity()).allowed is True


# --------------------------------------------------------------------------- #
# Headers                                                                      #
# --------------------------------------------------------------------------- #
class TestHeaders:
    def test_standard_headers_are_always_present(self, limiter: RateLimiter) -> None:
        rule = limiter.rule_for("search")

        headers = limiter.check(rule, _identity("search")).standard_headers()

        assert headers == {
            "X-RateLimit-Limit": "4",
            "X-RateLimit-Remaining": "3",
            "X-RateLimit-Reset": "60",
        }

    def test_retry_after_appears_only_when_blocked(self, limiter: RateLimiter) -> None:
        rule = limiter.rule_for("search")
        identity = _identity("search")

        for _ in range(rule.limit):
            assert "Retry-After" not in limiter.check(rule, identity).standard_headers()

        blocked = limiter.check(rule, identity).standard_headers()

        assert blocked["Retry-After"] == "60"
        assert blocked["X-RateLimit-Remaining"] == "0"

    def test_retry_after_is_absent_on_an_allowed_decision(self) -> None:
        """No store or clock involved: the header rule is a property of the decision."""
        allowed = RateLimitDecision(allowed=True, limit=10, remaining=9, reset_after_seconds=30)

        assert allowed.retry_after_seconds == 0
        assert "Retry-After" not in allowed.standard_headers()

    def test_headers_are_plain_strings(self, limiter: RateLimiter) -> None:
        """Headers travel into a Starlette response; every value must be a str."""
        headers = limiter.check(limiter.rule_for("search"), _identity("search")).standard_headers()

        assert all(isinstance(value, str) for value in headers.values())


# --------------------------------------------------------------------------- #
# In-memory store                                                              #
# --------------------------------------------------------------------------- #
class TestInMemoryStore:
    def test_counts_per_key_independently(self, store: InMemoryRateLimitStore) -> None:
        assert store.increment("a", 60) == (1, 60)
        assert store.increment("a", 60) == (2, 60)
        assert store.increment("b", 60) == (1, 60)

    def test_reset_after_is_never_less_than_one_second(self, store: InMemoryRateLimitStore) -> None:
        count, reset_after = store.increment("a", 60)

        assert count == 1
        # The clock is 100s into a 300s-aligned bucket, and ceil keeps a client
        # from being told to retry fractionally early.
        assert reset_after == 60

    def test_reset_after_counts_down_with_the_window(
        self, store: InMemoryRateLimitStore, clock: FakeClock
    ) -> None:
        clock.advance(240)

        _count, reset_after = store.increment("a", 300)

        assert reset_after == 60

    def test_a_new_window_starts_a_fresh_count(
        self, store: InMemoryRateLimitStore, clock: FakeClock
    ) -> None:
        store.increment("a", 60)
        store.increment("a", 60)

        clock.advance(61)

        # One second into the following window: a fresh counter, 59s to go.
        assert store.increment("a", 60) == (1, 59)

    def test_a_non_positive_window_is_rejected(self, store: InMemoryRateLimitStore) -> None:
        with pytest.raises(ValueError, match="window_seconds must be >= 1"):
            store.increment("a", 0)

    def test_reset_clears_every_counter(self, store: InMemoryRateLimitStore) -> None:
        store.increment("a", 60)
        store.increment("b", 60)

        store.reset()

        assert store.entry_count == 0
        assert store.increment("a", 60) == (1, 60)

    def test_expired_entries_are_pruned(
        self, store: InMemoryRateLimitStore, clock: FakeClock
    ) -> None:
        for index in range(5):
            store.increment(f"key-{index}", 60)

        assert store.entry_count == 5

        clock.advance(120)
        store.increment("fresh", 60)

        assert store.entry_count == 1

    def test_live_entries_are_not_pruned_early(
        self, store: InMemoryRateLimitStore, clock: FakeClock
    ) -> None:
        """Pruning must never reset a counter that is still inside its window."""
        store.increment("a", 60)
        clock.advance(30)
        for _ in range(10):
            store.increment("b", 60)

        assert store.increment("a", 60) == (2, 30)

    def test_the_size_cap_is_enforced_even_when_nothing_has_expired(self, clock: FakeClock) -> None:
        capped = InMemoryRateLimitStore(clock=clock, max_entries=10, prune_every=100_000)

        for index in range(50):
            capped.increment(f"key-{index}", 3600)

        assert capped.entry_count <= 10

    def test_the_size_cap_evicts_the_least_recently_touched_keys(self, clock: FakeClock) -> None:
        capped = InMemoryRateLimitStore(clock=clock, max_entries=3, prune_every=1)

        capped.increment("oldest", 3600)
        capped.increment("middle", 3600)
        capped.increment("newest", 3600)
        capped.increment("oldest", 3600)  # "oldest" is now the most recent
        capped.increment("overflow", 3600)  # evicts "middle"

        # "middle" was evicted, so its counter starts over; "oldest" kept its
        # count because reinserting on every hit moved it to the end.
        assert capped.increment("middle", 3600) == (1, 2700)
        assert capped.increment("oldest", 3600) == (3, 2700)

    def test_a_nonsense_cap_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="max_entries must be >= 1"):
            InMemoryRateLimitStore(max_entries=0)
        with pytest.raises(ValueError, match="prune_every must be >= 1"):
            InMemoryRateLimitStore(prune_every=0)

    def test_concurrent_increments_do_not_lose_counts(self) -> None:
        """Read-modify-write must happen under the lock, or limits leak."""
        threads_count = 16
        per_thread = 200
        start = threading.Barrier(threads_count)
        contended = InMemoryRateLimitStore(prune_every=10_000)
        results: list[int] = []
        results_lock = threading.Lock()

        def worker() -> None:
            start.wait()
            last = 0
            for _ in range(per_thread):
                last, _reset = contended.increment("contended", 3600)
            with results_lock:
                results.append(last)

        threads = [threading.Thread(target=worker) for _ in range(threads_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == threads_count
        assert max(results) == threads_count * per_thread
        assert contended.entry_count == 1

    def test_the_default_clock_is_monotonic(self) -> None:
        """A wall-clock jump must not be able to shorten or extend a window."""
        assert InMemoryRateLimitStore().increment("a", 60)[1] > 0
        assert time.get_clock_info("monotonic").monotonic is True


# --------------------------------------------------------------------------- #
# Redis store                                                                  #
# --------------------------------------------------------------------------- #
class FakeRedisScript:
    """Stand-in for a driver registered script.

    Records the call and returns a canned ``[count, ttl]`` so the store's
    response mapping is tested without a Redis server or the ``redis`` package.
    """

    def __init__(self, response: list[int]) -> None:
        self.response = response
        self.calls: list[tuple[list[str], list[str]]] = []

    def __call__(self, keys: list[str], args: list[str]) -> list[int]:
        self.calls.append((keys, args))
        return self.response


class FakeRedisClient:
    """A driver exposing only ``eval`` (no ``register_script``)."""

    def __init__(self, response: list[int] | None = None, error: Exception | None = None) -> None:
        self.response = response or [1, 60]
        self.error = error
        self.eval_calls: list[tuple[str, int, tuple[str, ...]]] = []
        self.deleted: list[str] = []
        self.keys: dict[str, str] = {}

    def eval(self, script: str, numkeys: int, *args: str) -> list[int]:
        self.eval_calls.append((script, numkeys, args))
        if self.error is not None:
            raise self.error
        return self.response

    def scan_iter(self, match: str, count: int) -> Iterator[str]:
        prefix = match.rstrip("*")
        for key in sorted(self.keys):
            if key.startswith(prefix):
                yield key

    def delete(self, *keys: str) -> int:
        for key in keys:
            self.deleted.append(key)
            self.keys.pop(key, None)
        return len(keys)


class TestRedisStore:
    def test_a_missing_redis_package_is_a_503_not_an_import_error(self) -> None:
        """`redis` is optional and is genuinely absent here: the failure must be
        typed, actionable, and must not escape as an ImportError."""
        if importlib.util.find_spec("redis") is not None:
            pytest.skip("redis is installed here, so the import cannot fail")

        with pytest.raises(ServiceUnavailableError) as caught:
            RedisRateLimitStore(redis_url="redis://localhost:6379/0")

        error = caught.value
        assert error.status_code == 503
        assert "redis" in str(error).lower()
        assert error.code == "SERVICE_UNAVAILABLE"

    def test_the_store_constructs_when_the_package_is_available(self) -> None:
        """Complements the test above so it cannot pass vacuously somewhere that
        does have `redis` installed."""
        if importlib.util.find_spec("redis") is not None:
            store = RedisRateLimitStore(redis_url="redis://localhost:6379/0")
            assert store.key_prefix.startswith("fundipulse")
        else:
            with pytest.raises(ServiceUnavailableError):
                RedisRateLimitStore(redis_url="redis://localhost:6379/0")

    def test_a_missing_url_is_rejected_before_touching_the_driver(self) -> None:
        with pytest.raises(ServiceUnavailableError, match="REDIS_URL"):
            RedisRateLimitStore(redis_url="")

    def test_importing_the_module_does_not_import_redis(self) -> None:
        """The module must stay importable for the in-memory deployment."""
        if importlib.util.find_spec("redis") is not None:
            pytest.skip("redis is installed; the optional-import path is moot")

        assert "redis" not in sys.modules

    def test_an_injected_client_skips_the_import(self) -> None:
        store = RedisRateLimitStore(client=FakeRedisClient(response=[3, 42]))

        assert store.key_prefix.startswith("fundipulse")
        assert store.increment("login|ip:1.2.3.4", 60) == (3, 42)

    def test_the_counter_key_is_namespaced(self) -> None:
        client = FakeRedisClient()
        store = RedisRateLimitStore(client=client, key_prefix="test:rl")

        store.increment("login|user:abc", 300)

        _script, _numkeys, args = client.eval_calls[0]
        assert args == ("test:rl:login|user:abc", "300")

    def test_the_script_result_is_mapped_to_count_and_ttl(self) -> None:
        client = FakeRedisClient(response=[7, 118])
        store = RedisRateLimitStore(client=client)

        assert store.increment("login|ip:1.2.3.4", 300) == (7, 118)

    def test_a_registered_script_is_used_when_the_driver_supports_one(self) -> None:
        script = FakeRedisScript([5, 200])
        client = FakeRedisClient()
        client.register_script = lambda source: script  # type: ignore[attr-defined]

        store = RedisRateLimitStore(client=client)

        assert store.increment("login|ip:1.2.3.4", 300) == (5, 200)
        # EVALSHA through the driver, with the counter key and the window as the
        # only two arguments the script needs.
        assert script.calls == [([], ["fundipulse:ratelimit:login|ip:1.2.3.4", "300"])]
        assert client.eval_calls == []

    def test_a_driver_failure_becomes_a_503_rather_than_a_500(self) -> None:
        """Failing closed: 'allow' because the cache is unreachable would remove
        the only control in front of credential stuffing."""
        client = FakeRedisClient(error=ConnectionError("redis is down"))
        store = RedisRateLimitStore(client=client)

        with pytest.raises(ServiceUnavailableError, match="temporarily unavailable"):
            store.increment("login|ip:1.2.3.4", 60)

    def test_reset_scans_and_deletes_in_batches(self) -> None:
        client = FakeRedisClient()
        client.keys = {"fundipulse:ratelimit:login|a": "1", "fundipulse:ratelimit:b": "1"}
        store = RedisRateLimitStore(client=client)

        store.reset()

        assert sorted(client.deleted) == [
            "fundipulse:ratelimit:b",
            "fundipulse:ratelimit:login|a",
        ]
        assert client.keys == {}

    def test_a_non_positive_window_is_rejected(self) -> None:
        store = RedisRateLimitStore(client=FakeRedisClient())

        with pytest.raises(ValueError, match="window_seconds must be >= 1"):
            store.increment("login|ip:1.2.3.4", 0)


# --------------------------------------------------------------------------- #
# Construction                                                                 #
# --------------------------------------------------------------------------- #
class TestConstruction:
    def test_the_memory_backend_is_built_by_default(self, settings: Settings) -> None:
        assert isinstance(build_store(settings), InMemoryRateLimitStore)

    def test_an_unreachable_redis_is_not_silently_downgraded(self) -> None:
        """Falling back to per-process counters would multiply the effective
        limit by the worker count while looking healthy."""
        with pytest.raises(ServiceUnavailableError):
            build_store(
                Settings(
                    app_env="test",
                    rate_limit_backend="redis",
                    redis_url="redis://localhost:6379/0",
                )
            )

    def test_the_factory_is_cached_and_resettable(self) -> None:
        try:
            first = get_rate_limiter()
            assert get_rate_limiter() is first

            reset_rate_limiter()

            assert get_rate_limiter() is not first
        finally:
            reset_rate_limiter()

    def test_the_limiter_exposes_its_rules(self, settings: Settings) -> None:
        limiter = RateLimiter(settings=settings, store=InMemoryRateLimitStore())

        assert limiter.settings is settings
        assert set(limiter.rules) == set(build_rules(settings))
        assert limiter.rule_for("login").limit == 3
        assert limiter.rule_for("nope") == default_rule(settings)
        assert limiter.default_rule.name == DEFAULT_RULE_NAME

    def test_a_limiter_built_without_a_store_gets_one(self, settings: Settings) -> None:
        assert isinstance(RateLimiter(settings=settings).store, RateLimitStore)
