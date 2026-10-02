"""Audit trail writer.

The audit log is the durable, tamper-evident record of security-relevant events.
It is deliberately separate from operational logs:

* **Logs** answer "is the service working, is someone attacking it".
* **Audit rows** answer "who did what, when, to which record" and must survive
  an incident response.

This service is the *only* writer. Centralising it means redaction, timestamp
handling and the actor snapshot cannot be forgotten at an individual call site.

Redaction is applied here rather than trusted to callers: metadata passes
through :func:`build_metadata`, which drops any key that looks like a secret. A
future endpoint that forgets to be careful still cannot write a credential to an
audit row.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
import uuid

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.constants import AuditAction
from app.core.exceptions import AppError
from app.core.logging import REDACTED, is_sensitive_key, request_id_var
from app.db.base import utcnow
from app.db.models.audit import AuditLog

#: Metadata keys that are dropped entirely rather than masked. A masked token is
#: still a partial disclosure; these carry no diagnostic value.
_DROP_ENTIRELY: frozenset[str] = frozenset(
    {
        "password",
        "password_hash",
        "new_password",
        "old_password",
        "current_password",
        "confirm_password",
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
        "presigned_url",
        "national_id",
        "national_id_number",
        "phone_number",
        "email",
    }
)

#: Hard cap so a metadata payload can never bloat the table.
MAX_METADATA_BYTES = 4096

#: Hard cap on how many entries a single call may write, so a loop cannot turn
#: one request into thousands of rows.
MAX_ENTRIES_PER_CALL = 50


def build_metadata(
    metadata: dict[str, Any] | None,
    *,
    drop_keys: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Produce audit metadata that is safe to persist.

    Three passes:

    1. drop the always-unsafe keys,
    2. mask anything whose name merely looks secret,
    3. truncate to a size cap, and serialise-check that the result is JSON-safe.
    """
    if not metadata:
        return {}

    result: dict[str, Any] = {}
    for key, value in metadata.items():
        key_str = str(key)
        lowered = key_str.lower()

        if lowered in _DROP_ENTIRELY or (drop_keys and lowered in drop_keys):
            continue
        if is_sensitive_key(lowered):
            result[key_str] = REDACTED
            continue

        if isinstance(value, dict):
            result[key_str] = build_metadata(value, drop_keys=drop_keys)
        elif isinstance(value, list | tuple):
            # Must recurse into dict elements: a secret inside a list of dicts is
            # still a secret, and without this branch the list is stored verbatim.
            # Scalar elements pass through untouched.
            result[key_str] = [
                build_metadata(item, drop_keys=drop_keys) if isinstance(item, dict) else item
                for item in value
            ]
        elif isinstance(value, uuid.UUID):
            result[key_str] = str(value)
        elif isinstance(value, datetime):
            result[key_str] = value.astimezone(UTC).isoformat()
        elif isinstance(value, str | int | float | bool | type(None)):
            result[key_str] = value
        else:
            # Unknown type: stringify rather than risk repr() leaking state, and
            # never store the raw object.
            result[key_str] = f"<{type(value).__name__}>"

    encoded = _approximate_size(result)
    if encoded > MAX_METADATA_BYTES:
        truncated: dict[str, Any] = {}
        for key, value in result.items():
            candidate = {**truncated, key: value}
            if _approximate_size(candidate) > MAX_METADATA_BYTES:
                truncated["_truncated"] = True
                break
            truncated = candidate
        return truncated
    return result


def _approximate_size(payload: dict[str, Any]) -> int:
    """Cheap size estimate that avoids importing json for the common path."""
    total = 0
    for key, value in payload.items():
        total += len(str(key)) + 2
        if isinstance(value, dict):
            total += _approximate_size(value)
        elif isinstance(value, str):
            total += len(value)
        else:
            total += 8
    return total


class AuditService:
    """Writes append-only audit rows.

    Two write paths, because "the action failed" and "the action succeeded"
    need opposite transaction handling:

    :meth:`record`
        Writes inside the caller's transaction, so an effect and its audit row
        commit together or not at all. Use this for successful actions.

    :meth:`record_durable`
        Writes in its **own** transaction, which therefore survives the caller's
        rollback. Use this for failed or denied actions.

    Why the split matters: when a service records ``LOGIN_FAILURE`` and then
    raises, the request transaction is rolled back - taking the audit row with
    it. A security trail that silently discards every failed login, every refused
    self-verification and every token-reuse detection is worse than no trail,
    because it looks complete while recording only successes. That is exactly the
    gap an attacker would exploit.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def record_durable(
        self,
        *,
        action: AuditAction,
        actor_user_id: uuid.UUID | None = None,
        actor_role: str | None = None,
        resource_type: str | None = None,
        resource_id: uuid.UUID | str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
        outcome: str | None = None,
        request_id: str | None = None,
        created_at: datetime | None = None,
    ) -> None:
        """Append an audit row that survives the caller's rollback.

        Used for anything that accompanies a raised exception. A security trail
        that silently discarded every failed login, refused self-verification and
        detected token reuse would look complete while recording only successes,
        which is precisely the gap an attacker would rely on.

        Implementation: commit on the caller's own session rather than opening a
        second connection. A second connection is the obvious implementation and
        the wrong one - it cannot see rows that this transaction has not yet
        committed, so the audit insert would fail its own foreign key on exactly
        the interesting cases.

        Committing the caller's pending work alongside the audit row is safe here
        because every call site is a *failure* path whose pending changes are
        themselves worth persisting: an incremented failed-login counter, a
        revoked token family, a consumed single-use token. Nothing that should be
        rolled back is pending at these points.
        """
        row = self.record(
            action=action,
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata,
            outcome=outcome,
            request_id=request_id,
            created_at=created_at,
        )
        try:
            self._session.commit()
        except Exception:  # noqa: BLE001 - never mask the original failure
            from app.core.logging import get_logger

            get_logger(__name__).error(
                "Failed to commit durable audit row",
                extra={
                    "error_category": "audit_write_failure",
                    "audit_action": action.value,
                    "audit_resource_id": str(row.id),
                },
                exc_info=True,
            )

    def record(
        self,
        *,
        action: AuditAction,
        actor_user_id: uuid.UUID | None = None,
        actor_role: str | None = None,
        resource_type: str | None = None,
        resource_id: uuid.UUID | str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
        outcome: str | None = None,
        request_id: str | None = None,
        created_at: datetime | None = None,
    ) -> AuditLog:
        """Append one audit row.

        ``created_at`` is written explicitly rather than defaulted, because the
        database trigger forbids later edits and the value must be the true event
        time.
        """
        if isinstance(resource_id, uuid.UUID):
            resource_uuid: uuid.UUID | None = resource_id
        elif isinstance(resource_id, str) and _looks_like_uuid(resource_id):
            resource_uuid = uuid.UUID(resource_id)
        else:
            resource_uuid = None

        row = AuditLog(
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            action=action.value,
            resource_type=resource_type,
            resource_id=resource_uuid,
            request_id=request_id or request_id_var.get(),
            ip_address=_validate_ip(ip_address),
            user_agent=(user_agent or "")[:512] or None,
            metadata_=build_metadata(metadata),
            outcome=outcome,
            created_at=created_at or utcnow(),
        )
        self._session.add(row)
        return row

    def record_many(self, entries: Sequence[dict[str, Any]]) -> list[AuditLog]:
        """Append several rows, capped to keep one request bounded."""
        if len(entries) > MAX_ENTRIES_PER_CALL:
            raise AppError(
                f"Audit batch of {len(entries)} exceeds the {MAX_ENTRIES_PER_CALL} entry limit.",
                code="AUDIT_BATCH_TOO_LARGE",
            )
        rows = []
        for entry in entries:
            payload = dict(entry)
            payload["action"] = AuditAction(payload["action"])
            rows.append(self.record(**payload))
        return rows

    # -- read side ------------------------------------------------------- #

    def list_for_resource(
        self,
        *,
        resource_type: str,
        resource_id: uuid.UUID,
        limit: int = 100,
    ) -> list[AuditLog]:
        """Read the audit history of one resource.

        Read-only and deliberately limited. There is no update or delete method
        anywhere on this class, and the database refuses both regardless.
        """
        statement: Select[tuple[AuditLog]] = (
            select(AuditLog)
            .where(
                AuditLog.resource_type == resource_type,
                AuditLog.resource_id == resource_id,
            )
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
        )
        return list(self._session.execute(statement).scalars())

    def count_by_action(self, action: AuditAction, since: datetime) -> int:
        """Aggregate used by admin reporting and monitoring queries."""
        statement = (
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action == action.value,
                AuditLog.created_at >= since,
            )
        )
        return int(self._session.execute(statement).scalar_one())


def _looks_like_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _validate_ip(value: str | None) -> str | None:
    """Normalise an address, discarding anything the ``INET`` column would reject.

    Validation has to happen here rather than relying on the column: an invalid
    address would raise at flush time, turning a spoofed header into a 500 exactly
    where a security event was being written down.
    """
    from app.utils.net import coerce_ip_address

    return coerce_ip_address(value)
