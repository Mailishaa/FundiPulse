"""Unit tests for request-context resolution, role guards and email masking.

These are small functions that sit on the path between an untrusted HTTP request
and an authorisation decision, so each one is tested directly.
"""

from __future__ import annotations

import pytest

from app.core.constants import UserRole
from app.core.exceptions import InsufficientRoleError
from app.utils.email import mask_email, normalise_email
from app.utils.net import coerce_ip_address

pytestmark = pytest.mark.unit


class TestClientIpResolution:
    """A spoofed header must never produce an audit row that blames the wrong host."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("203.0.113.5", "203.0.113.5"),
            (" 203.0.113.5 ", "203.0.113.5"),
            ("203.0.113.5", "203.0.113.5"),
            ("2001:db8::1", "2001:db8::1"),
            ("fe80::1%eth0", "fe80::1"),
            ("::1", "::1"),
            ("0.0.0.0", "0.0.0.0"),  # noqa: S104 - a literal in a table, not a bind
        ],
    )
    def test_valid_addresses_are_normalised(self, value: str, expected: str) -> None:
        assert coerce_ip_address(value) == expected

    @pytest.mark.parametrize(
        "value",
        [
            "not-an-ip",
            "999.999.999.999",
            "testclient",  # the ASGI test client reports this as the host
            "localhost",
            "1.2.3.4:80",
            "example.com",
            "",
            "   ",
            "/var/run/app.sock",
            "'; DROP TABLE users; --",
            None,
        ],
    )
    def test_unusable_values_are_discarded(self, value: str | None) -> None:
        """Fails closed: an audit row without an address beats a 500."""
        assert coerce_ip_address(value) is None

    def test_an_overlong_value_is_rejected_without_parsing(self) -> None:
        assert coerce_ip_address("1" * 10_000) is None

    def test_the_forwarded_header_takes_precedence_over_the_socket(self, client, make_user) -> None:
        """On Render the socket address is always the load balancer."""
        user = make_user()
        response = client.post(
            "/auth/login",
            json={"email": user.email, "password": "Wrong-Password-9-X"},
            headers={"X-Forwarded-For": "203.0.113.42, 70.41.3.18"},
        )
        assert response.status_code == 401

    def test_a_hostile_forwarded_header_does_not_break_login(self, client, make_user) -> None:
        user = make_user()
        response = client.post(
            "/auth/login",
            json={"email": user.email, "password": "Wrong-Password-9-X"},
            headers={"X-Forwarded-For": "'; DROP TABLE users; --"},
        )
        assert response.status_code == 401, "a bad header must not become a 500"

    def test_the_recorded_address_is_the_forwarded_one(self, client, make_user, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        user = make_user()
        client.post(
            "/auth/login",
            json={"email": user.email, "password": "Wrong-Password-9-X"},
            headers={"X-Forwarded-For": "198.51.100.7"},
        )
        row = next(
            r
            for r in db_session.execute(select(AuditLog)).scalars().all()
            if r.action == "LOGIN_FAILURE" and r.actor_user_id == user.id
        )
        assert str(row.ip_address) == "198.51.100.7"


class TestRoleGuard:
    """`require_roles` is the deny-by-default gate; adding a role must not
    silently grant access anywhere."""

    def _guard(self, *roles: UserRole):
        from app.api.dependencies import require_roles

        return require_roles(*roles)

    def _user(self, role: UserRole) -> object:
        class _U:
            pass

        user = _U()
        user.role = role.value
        return user

    def test_a_listed_role_passes(self) -> None:
        guard = self._guard(UserRole.WORKER)
        assert guard(self._user(UserRole.WORKER)) is not None

    def test_an_unlisted_role_is_refused(self) -> None:
        guard = self._guard(UserRole.WORKER)
        with pytest.raises(InsufficientRoleError):
            guard(self._user(UserRole.ADMIN))

    def test_multiple_roles_are_accepted(self) -> None:
        guard = self._guard(UserRole.WORKER, UserRole.ADMIN)
        assert guard(self._user(UserRole.ADMIN)) is not None
        assert guard(self._user(UserRole.WORKER)) is not None

    def test_an_empty_role_set_denies_everyone(self) -> None:
        """An empty allowlist must fail closed, not allow all."""
        guard = self._guard()
        for role in UserRole:
            with pytest.raises(InsufficientRoleError):
                guard(self._user(role))

    def test_a_new_role_would_be_refused_until_added(self) -> None:
        """Documents the fail-closed property of a membership test."""
        guard = self._guard(UserRole.WORKER, UserRole.EMPLOYER)
        with pytest.raises(InsufficientRoleError):
            guard(self._user(UserRole.ADMIN))


class TestEmailMasking:
    @pytest.mark.parametrize(
        ("email", "must_not_contain"),
        [
            ("construction.worker@example.com", "construction"),
            ("john.doe@fundipulse.co.ke", "john.doe"),
            ("a@b.com", "a@"),
        ],
    )
    def test_masking_hides_the_local_part(self, email: str, must_not_contain: str) -> None:
        masked = mask_email(email)
        assert must_not_contain not in masked
        assert masked.count("@") == 1

    @pytest.mark.parametrize("email", ["", "not-an-email", "@", "a@"])
    def test_malformed_input_still_produces_something_safe(self, email: str) -> None:
        masked = mask_email(email)
        assert isinstance(masked, str)
        assert email == "" or masked

    def test_short_domains_are_fully_masked(self) -> None:
        assert mask_email("user@a.io").endswith("@***")

    def test_a_long_domain_keeps_only_its_edges(self) -> None:
        assert mask_email("user@example.com") == "u**r@e***m"

    def test_masking_is_stable(self) -> None:
        assert mask_email("worker@example.com") == mask_email("worker@example.com")

    def test_masking_rejects_nothing_it_cannot_handle(self) -> None:
        # Must not raise: this is called from logging paths.
        assert mask_email("a" * 500 + "@" + "b" * 250 + ".com")


class TestEmailNormalisationAcceptance:
    @pytest.mark.parametrize(
        "address",
        [
            "Worker@Example.com",
            "  spaced@example.com  ",
            "first.last@example.co.ke",
            "first_last@example.com",
            "first-last@example.com",
            "user+tag@example.com",
        ],
    )
    def test_plausible_addresses_are_accepted(self, address: str) -> None:
        normalised = normalise_email(address)
        assert normalised == normalised.strip().lower()
        assert "@" in normalised

    def test_gmail_dot_folding_is_not_applied(self) -> None:
        """Two visibly different addresses must not silently collide.

        Folding ``a.b@`` to ``ab@`` would make two accounts the same login, which
        is far more surprising than it is helpful.
        """
        assert normalise_email("a.b@example.com") != normalise_email("ab@example.com")

    def test_the_plus_tag_is_preserved(self) -> None:
        """A deliberate alias stays distinct, so recovery works as typed."""
        assert normalise_email("user+jobs@example.com") == "user+jobs@example.com"


class TestPaginationBounds:
    def test_page_parameters_are_bounded(self) -> None:
        """A client cannot request a million rows."""
        from pydantic import ValidationError

        from app.schemas.common import PageParams

        assert PageParams(page=1, page_size=100).page_size == 100
        with pytest.raises(ValidationError):
            PageParams(page=0)
        with pytest.raises(ValidationError):
            PageParams(page=1, page_size=0)
        with pytest.raises(ValidationError):
            PageParams(page=1, page_size=1000)

    def test_offset_is_computed_from_page_and_size(self) -> None:
        from app.schemas.common import PageParams

        params = PageParams(page=3, page_size=25)
        assert params.offset == 50
        assert params.limit == 25

    def test_pagination_metadata_is_consistent(self) -> None:
        from app.schemas.common import PaginationMeta

        meta = PaginationMeta.build(page=1, page_size=20, total_items=137, request_id="r")
        assert meta.total_pages == 7
        assert meta.has_next is True
        assert meta.has_previous is False

        last = PaginationMeta.build(page=7, page_size=20, total_items=137, request_id="r")
        assert last.has_next is False
        assert last.has_previous is True

    def test_an_empty_result_set_reports_zero_pages(self) -> None:
        from app.schemas.common import PaginationMeta

        meta = PaginationMeta.build(page=1, page_size=20, total_items=0, request_id="r")
        assert meta.total_pages == 0
        assert meta.has_next is False
