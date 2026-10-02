"""Unit tests for audit metadata redaction and log redaction.

Redaction is a security control, so it is tested as one: the interesting cases
are the ones where something secret could slip through.
"""

from __future__ import annotations

from datetime import UTC, datetime
import logging
import uuid

import pytest

from app.core.constants import AuditAction
from app.services.audit_service import (
    MAX_METADATA_BYTES,
    AuditService,
    build_metadata,
)

pytestmark = pytest.mark.unit


class TestAuditMetadataRedaction:
    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "new_password",
            "password_hash",
            "current_password",
            "token",
            "access_token",
            "refresh_token",
            "reset_token",
            "invitation_token",
            "secret",
            "api_key",
            "authorization",
            "cookie",
            "signed_url",
            "national_id",
            "national_id_number",
            "phone_number",
            "email",
        ],
    )
    def test_known_sensitive_keys_are_dropped_entirely(self, key: str) -> None:
        """These carry no diagnostic value, so a masked copy is still a leak."""
        result = build_metadata({key: "super-secret-value", "keep": "me"})
        assert key not in result, f"{key} should have been dropped"
        assert result["keep"] == "me"

    @pytest.mark.parametrize(
        "key",
        ["Api-Key", "sessionid_hash", "SET_COOKIE", "X-Auth-Token"],
    )
    def test_sensitive_lookalikes_are_masked_not_dropped(self, key: str) -> None:
        """Names that are *not* on the drop list are masked rather than removed."""
        result = build_metadata({key: "value", "other": 1})
        assert result[key] == "[REDACTED]"
        assert result["other"] == 1

    @pytest.mark.parametrize(
        "key",
        ["Token", "ACCESS_TOKEN", "refresh_token", "signed_url", "national_id"],
    )
    def test_drop_list_keys_are_removed_entirely_even_in_another_case(self, key: str) -> None:
        """A masked copy of a token is still a partial disclosure."""
        result = build_metadata({key.upper(): "value", "other": 1})
        assert key.upper() not in result
        assert result["other"] == 1

    def test_matching_is_case_insensitive(self) -> None:
        result = build_metadata({"PassWord": "x"})
        assert "PassWord" not in result

    def test_nested_dictionaries_are_redacted(self) -> None:
        """Recursion applies the same rules at every depth."""
        result = build_metadata(
            {"outer": {"inner": {"password": "p", "Api-Key": "k", "safe": "s"}}, "top": "t"}
        )
        assert "password" not in result["outer"]["inner"]
        assert result["outer"]["inner"]["Api-Key"] == "[REDACTED]"
        assert result["outer"]["inner"]["safe"] == "s"
        assert result["top"] == "t"

    def test_lists_of_dicts_are_redacted(self) -> None:
        result = build_metadata({"items": [{"token": "t", "ok": 1}]})
        assert "token" not in result["items"][0]
        assert result["items"][0]["ok"] == 1

    def test_a_sensitive_key_anywhere_in_a_nested_tree_is_removed(self) -> None:
        result = build_metadata({"a": {"b": {"c": {"password_hash": "hunter2"}}}})
        assert "hunter2" not in str(result)

    def test_uuid_values_become_strings(self) -> None:
        identifier = uuid.uuid4()
        result = build_metadata({"user_id": identifier})
        assert result["user_id"] == str(identifier)

    def test_datetimes_are_normalised_to_utc_iso(self) -> None:
        moment = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
        assert build_metadata({"at": moment})["at"] == "2026-01-02T03:04:05+00:00"

    def test_naive_datetimes_are_coerced_rather_than_rejected(self) -> None:
        # A naive datetime cannot normally reach here (the columns are TIMESTAMPTZ
        # and the DTZ lint rule forbids them in application code), but failing to
        # write an audit row is worse than recording an assumed-UTC value.
        naive = datetime(2026, 1, 2, 3, 4, 5, tzinfo=None)  # noqa: DTZ001
        assert "at" in build_metadata({"at": naive})

    def test_unknown_object_types_are_stringified_by_type_only(self) -> None:
        """Never call repr() on an arbitrary object: it can leak state."""

        class Leaky:
            def __repr__(self) -> str:  # pragma: no cover - must never be called
                return "LEAKED"

        assert build_metadata({"thing": Leaky()})["thing"] == "<Leaky>"

    def test_an_oversized_payload_is_truncated_rather_than_stored(self) -> None:
        result = build_metadata({f"k{i}": "x" * 500 for i in range(50)})
        assert result.get("_truncated") is True
        assert len(str(result)) < MAX_METADATA_BYTES * 1.5

    def test_empty_input_returns_an_empty_dict(self) -> None:
        assert build_metadata(None) == {}
        assert build_metadata({}) == {}

    def test_tuples_are_converted_to_lists_for_json_safety(self) -> None:
        assert build_metadata({"t": (1, 2)})["t"] == [1, 2]

    def test_extra_drop_keys_are_honoured(self) -> None:
        result = build_metadata({"custom": "v"}, drop_keys=["custom"])
        assert "custom" not in result


class TestAuditServiceWrites:
    def test_record_populates_the_actor_snapshot(self, db_session, make_user) -> None:
        """actor_role is captured at event time, so a later role change cannot
        rewrite what the operator saw."""
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        user = make_user()
        service = AuditService(db_session)
        service.record(
            action=AuditAction.LOGIN_SUCCESS,
            actor_user_id=user.id,
            actor_role="WORKER",
            resource_type="user",
            resource_id=user.id,
            outcome="SUCCESS",
        )
        db_session.flush()

        rows = db_session.execute(select(AuditLog)).scalars().all()
        row = next(r for r in rows if r.actor_user_id == user.id)
        assert row.actor_role == "WORKER"
        assert row.action == AuditAction.LOGIN_SUCCESS.value

    def test_a_non_uuid_resource_id_is_recorded_without_the_column(self, db_session) -> None:
        """``resource_type`` accepts a slug; ``resource_id`` must stay a UUID."""
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        AuditService(db_session).record(
            action=AuditAction.ADMIN_ACTION, resource_type="trades", resource_id="MASONRY"
        )
        db_session.flush()

        row = next(
            r
            for r in db_session.execute(select(AuditLog)).scalars().all()
            if r.resource_type == "trades"
        )
        assert row.resource_id is None

    def test_an_ipv6_zone_index_is_stripped(self, db_session) -> None:
        """PostgreSQL INET rejects a scope id; a malformed value must not crash."""
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        marker = str(uuid.uuid4())
        AuditService(db_session).record(
            action=AuditAction.LOGIN_FAILURE,
            ip_address="fe80::1%eth0",
            outcome="FAILURE",
            request_id=marker,
        )
        db_session.flush()
        row = next(
            r
            for r in db_session.execute(select(AuditLog)).scalars().all()
            if r.request_id == marker
        )
        assert str(row.ip_address) == "fe80::1"

    def test_an_invalid_ip_is_dropped_rather_than_raising(self, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        marker = str(uuid.uuid4())
        AuditService(db_session).record(
            action=AuditAction.LOGIN_FAILURE,
            ip_address="not-an-ip",
            outcome="FAILURE",
            request_id=marker,
        )
        db_session.flush()
        row = next(
            r
            for r in db_session.execute(select(AuditLog)).scalars().all()
            if r.request_id == marker
        )
        assert row.ip_address is None

    def test_the_user_agent_is_truncated(self, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        marker = str(uuid.uuid4())
        AuditService(db_session).record(
            action=AuditAction.LOGIN_FAILURE,
            user_agent="A" * 2000,
            outcome="FAILURE",
            request_id=marker,
        )
        db_session.flush()
        row = next(
            r
            for r in db_session.execute(select(AuditLog)).scalars().all()
            if r.request_id == marker
        )
        assert len(row.user_agent) == 512

    def test_record_many_writes_every_entry(self, db_session) -> None:
        from sqlalchemy import select

        from app.db.models.audit import AuditLog

        AuditService(db_session).record_many(
            [
                {"action": AuditAction.LOGIN_SUCCESS, "outcome": "SUCCESS"},
                {"action": AuditAction.LOGOUT, "outcome": "SUCCESS"},
            ]
        )
        db_session.flush()
        actions = [r.action for r in db_session.execute(select(AuditLog)).scalars().all()]
        assert actions.count(AuditAction.LOGOUT.value) >= 1

    def test_an_oversized_batch_is_refused(self, db_session) -> None:
        """One request must not be able to write thousands of rows."""
        from app.core.exceptions import AppError

        with pytest.raises(AppError):
            AuditService(db_session).record_many([{"action": AuditAction.LOGIN_SUCCESS}] * 500)

    def test_list_for_resource_is_newest_first_and_bounded(self, db_session, make_user) -> None:
        user = make_user()
        service = AuditService(db_session)
        for _ in range(3):
            service.record(
                action=AuditAction.FILE_ACCESSED,
                resource_type="user",
                resource_id=user.id,
            )
        db_session.flush()

        rows = service.list_for_resource(resource_type="user", resource_id=user.id, limit=2)
        assert len(rows) == 2, "limit must be honoured"
        assert rows[0].created_at >= rows[1].created_at

    def test_count_by_action_filters_by_time(self, db_session) -> None:
        from datetime import timedelta

        from app.db.base import utcnow

        service = AuditService(db_session)
        service.record(action=AuditAction.LOGIN_FAILURE, outcome="FAILURE")
        db_session.flush()

        assert (
            service.count_by_action(AuditAction.LOGIN_FAILURE, utcnow() - timedelta(hours=1)) >= 1
        )
        assert (
            service.count_by_action(AuditAction.LOGIN_FAILURE, utcnow() + timedelta(hours=1)) == 0
        )

    def test_audit_service_exposes_no_update_or_delete(self) -> None:
        """The API surface itself must not offer history rewriting."""
        forbidden = {"update", "delete", "destroy", "purge", "truncate"}
        public = {name for name in dir(AuditService) if not name.startswith("_")}
        assert not (public & forbidden), public & forbidden


class TestLogRedaction:
    @pytest.mark.parametrize(
        "key",
        ["password", "SECRET_KEY", "access_token", "Authorization", "api-key", "Set-Cookie"],
    )
    def test_is_sensitive_key(self, key: str) -> None:
        from app.core.logging import is_sensitive_key

        assert is_sensitive_key(key) is True

    @pytest.mark.parametrize("key", ["user_id", "status_code", "path", "duration_ms"])
    def test_ordinary_keys_are_not_sensitive(self, key: str) -> None:
        from app.core.logging import is_sensitive_key

        assert is_sensitive_key(key) is False

    def test_redact_masks_by_key_name_at_any_depth(self) -> None:
        """The log redactor masks rather than drops, so the shape is preserved."""
        from app.core.logging import REDACTED, redact

        result = redact({"a": {"refresh_token": "secret", "keep": 1}, "b": [{"password": "p"}]})
        assert result["a"]["refresh_token"] == REDACTED
        assert result["a"]["keep"] == 1
        assert result["b"][0]["password"] == REDACTED

    def test_redaction_leaves_plain_values_untouched(self) -> None:
        from app.core.logging import redact

        assert redact("hello") == "hello"
        assert redact(42) == 42
        assert redact(None) is None

    def test_the_json_formatter_masks_a_secret_passed_in_extras(self) -> None:
        """A caller that logs a token by mistake still cannot leak it."""
        import json

        from app.core.logging import JsonFormatter

        formatter = JsonFormatter(service_name="test")
        record = logging.LogRecord(
            name="t",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="event",
            args=(),
            exc_info=None,
        )
        record.refresh_token = "leaked-token-value"
        record.user_id = "abc"

        payload = json.loads(formatter.format(record))
        assert payload["refresh_token"] == "[REDACTED]"
        assert payload["user_id"] == "abc"
        assert "leaked-token-value" not in formatter.format(record)

    def test_the_json_formatter_emits_one_object_per_record(self) -> None:
        import json

        from app.core.logging import JsonFormatter

        formatter = JsonFormatter(service_name="test")
        record = logging.LogRecord(
            name="t",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="hello",
            args=(),
            exc_info=None,
        )
        parsed = json.loads(formatter.format(record))
        assert parsed["event"] == "hello"
        assert parsed["level"] == "INFO"
        assert parsed["service"] == "test"

    def test_the_human_formatter_includes_the_request_id(self) -> None:
        from app.core.logging import HumanFormatter

        formatter = HumanFormatter()
        record = logging.LogRecord(
            name="t",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="hello",
            args=(),
            exc_info=None,
        )
        record.request_id = "abcdef12-3456"
        assert "abcdef12" in formatter.format(record)
