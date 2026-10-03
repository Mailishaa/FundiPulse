"""Rate limiting is bound to real endpoints, not just built.

`app/core/rate_limit.py` had 62 unit tests before any route declared a limit, which
proved the mechanism worked and proved nothing about the API. These tests call the
endpoints.

The suite runs with ``RATE_LIMIT_ENABLED=false`` (see ``tests/conftest.py``) so
ordinary tests are not throttled. Each test here therefore flips the cached limiter
explicitly, and restores it afterwards - a test that left it enabled would make the
rest of the suite order-dependent.
"""

from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.core.rate_limit import reset_rate_limiter

pytestmark = [pytest.mark.api, pytest.mark.integration]


@pytest.fixture
def limited(monkeypatch):
    """Enable the limiter with a tight window for the duration of one test."""
    monkeypatch.setattr(get_settings(), "rate_limit_enabled", True)
    reset_rate_limiter()
    yield
    reset_rate_limiter()


def test_login_is_rate_limited_per_address(limited, client, make_user) -> None:
    """Credential stuffing must hit a ceiling, not just lock one account."""
    account = make_user()
    limit = get_settings().rate_limit_login_per_5_min

    codes = [
        client.post(
            "/auth/login", json={"email": account.email, "password": "Wrong-Password-1"}
        ).status_code
        for _ in range(limit + 2)
    ]

    assert 429 in codes, f"login was never rate limited: {codes}"


def test_the_429_carries_the_standard_headers(limited, client, make_user) -> None:
    account = make_user()
    limit = get_settings().rate_limit_login_per_5_min

    response = None
    for _ in range(limit + 2):
        response = client.post(
            "/auth/login", json={"email": account.email, "password": "Wrong-Password-1"}
        )
        if response.status_code == 429:
            break

    assert response is not None and response.status_code == 429
    assert response.json()["error"]["code"] == "RATE_LIMITED"
    assert response.headers["X-RateLimit-Limit"] == str(limit)
    assert response.headers["X-RateLimit-Remaining"] == "0"
    assert int(response.headers["Retry-After"]) >= 1


def test_allowed_requests_also_carry_the_headers(limited, client, make_user) -> None:
    """A client must be able to see its remaining allowance before it is refused."""
    account = make_user()
    response = client.post(
        "/auth/login",
        json={"email": account.email, "password": "Correct-Horse-9-Battery"},
    )
    assert response.status_code == 200
    assert response.headers["X-RateLimit-Limit"]
    assert int(response.headers["X-RateLimit-Remaining"]) >= 0


def test_a_different_address_does_not_share_a_bucket(limited, client, make_user) -> None:
    """Two people behind one NAT would be throttled together otherwise."""
    from app.core.rate_limit import resolve_identity

    first = resolve_identity("login", client_ip="197.0.2.10")
    second = resolve_identity("login", client_ip="198.51.100.20")
    assert first != second


def test_an_authenticated_identity_is_keyed_on_the_user(limited) -> None:
    """A shared office egress must not let one worker exhaust another's allowance."""
    from app.core.rate_limit import resolve_identity

    keyed = resolve_identity(
        "login", user_id="6f1b7f0c-2f0f-4a1d-9b6a-2c9b6c1f0a11", client_ip="197.0.2.10"
    )
    assert "197.0.2.10" not in keyed


def test_a_route_with_no_limit_is_not_throttled(client, make_user) -> None:
    """Unlimited by accident would be indistinguishable from unlimited by design.

    `GET /trades` is public reference data with no limit declared, so it must keep
    answering well past the login allowance.
    """
    limit = get_settings().rate_limit_login_per_5_min
    codes = [client.get("/trades").status_code for _ in range(limit * 2)]
    assert set(codes) == {200}


def test_worker_search_is_rate_limited(limited, client, db_session, make_user) -> None:
    from app.core.constants import ProfileVisibility
    from app.db.models.worker import WorkerProfile

    owner = make_user()
    db_session.add(
        WorkerProfile(
            user_id=owner.id, display_name="Visible", visibility=ProfileVisibility.PUBLIC.value
        )
    )
    db_session.flush()

    settings = get_settings()
    codes = [
        client.get("/workers").status_code for _ in range(settings.rate_limit_search_per_minute + 5)
    ]
    assert 429 in codes, f"search was never rate limited: {codes[:5]}..."
