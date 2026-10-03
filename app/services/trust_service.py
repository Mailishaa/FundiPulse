"""Credentials and referee nominations.

Two rules this module exists to enforce:

1. **A nomination never becomes a verification.** Nothing here writes to
   ``verification_requests`` or ``verifications``, and nothing here sets
   ``WorkerReference.status``. A worker nominates a person who *can* vouch for
   them; the referee is the only party who can confirm or decline. The model
   default is therefore the only writer of ``status``.
2. **Uploading a certificate never certifies it.** There is no code path that
   marks a credential as issuer-confirmed, because there is no such column to set:
   ``verification_status`` lives on ``verifications``, which this service never
   touches.

Every method takes the caller's already-loaded passport, so ownership is decided
against a row rather than a client-supplied id. Another worker's credential id
matches nothing and the caller receives a 404, never a 403 that would confirm the
row exists.
"""

from __future__ import annotations

from datetime import date
from typing import Any
import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.constants import AuditAction
from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models.user import User
from app.db.models.worker import Credential, WorkerProfile, WorkerReference
from app.schemas.trust import (
    DEFAULT_ISSUING_COUNTRY,
    CredentialCreateRequest,
    CredentialUpdateRequest,
    WorkerReferenceCreateRequest,
    WorkerReferenceUpdateRequest,
)
from app.services.audit_service import AuditService
from app.utils.dates import utc_today

logger = get_logger(__name__)

#: Columns that are NOT NULL. An explicit ``null`` for one of these is a client
#: error, not a value to store, so it is a 422 rather than a 500 from the database.
_REQUIRED_CREDENTIAL_FIELDS: frozenset[str] = frozenset({"title", "credential_type"})
_REQUIRED_REFERENCE_FIELDS: frozenset[str] = frozenset(
    {"full_name", "email", "relationship_type", "status"}
)


class DuplicateReferenceError(ConflictError):
    """The same referee is already nominated on this passport."""

    public_message = "That email address is already nominated as a reference."


class TrustService:
    """Owner-scoped credential and nomination management."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._audit = AuditService(session)

    # -- credentials ------------------------------------------------------ #

    def create_credential(
        self, *, actor: User, profile: WorkerProfile, payload: CredentialCreateRequest
    ) -> Credential:
        """Record the claim that the worker holds a credential. Stops there."""
        self._reject_impossible_dates(payload.issue_date, payload.expiry_date)
        credential = Credential(
            worker_profile_id=profile.id,
            title=payload.title.strip(),
            credential_type=payload.credential_type.value,
            issuer=_clean(payload.issuer),
            issuing_country_code=payload.issuing_country_code or DEFAULT_ISSUING_COUNTRY,
            credential_number=_clean(payload.credential_number),
            issue_date=payload.issue_date,
            expiry_date=payload.expiry_date,
            description=_clean(payload.description),
        )
        self._session.add(credential)
        self._session.flush()
        self._record(
            actor=actor,
            resource_type="credential",
            resource_id=credential.id,
            operation="create_credential",
            credential_type=credential.credential_type,
            # The claim is recorded, not attested. Said here so an audit reader
            # cannot mistake a stored certificate for a checked one.
            verified=False,
        )
        logger.info("Credential claimed", extra={"credential_id": str(credential.id)})
        return credential

    def list_credentials(
        self, *, profile: WorkerProfile, limit: int = 20, offset: int = 0
    ) -> tuple[list[Credential], int]:
        conditions = [
            Credential.worker_profile_id == profile.id,
            Credential.deleted_at.is_(None),
        ]
        total = int(
            self._session.execute(
                select(func.count()).select_from(Credential).where(*conditions)
            ).scalar_one()
        )
        statement = (
            select(Credential)
            .where(*conditions)
            # id last so paging cannot skip or repeat a row.
            .order_by(Credential.created_at.desc(), Credential.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    def get_credential(self, *, profile: WorkerProfile, credential_id: uuid.UUID) -> Credential:
        """Scoped by passport as well as id, so another worker's id matches nothing."""
        credential = self._session.execute(
            select(Credential).where(
                Credential.id == credential_id,
                Credential.worker_profile_id == profile.id,
                Credential.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if credential is None:
            raise NotFoundError("The requested credential was not found.")
        return credential

    def update_credential(
        self,
        *,
        profile: WorkerProfile,
        credential_id: uuid.UUID,
        payload: CredentialUpdateRequest,
    ) -> Credential:
        """Revalidates the resulting date range, since a patch can half-change it."""
        credential = self.get_credential(profile=profile, credential_id=credential_id)
        data = payload.model_dump(exclude_unset=True)

        for field in ("title", "issuer", "credential_number", "description"):
            if field in data:
                _assign_required(credential, field, data[field], _REQUIRED_CREDENTIAL_FIELDS)
        for field in ("issuing_country_code", "issue_date", "expiry_date"):
            if field in data:
                setattr(credential, field, data[field])
        if "credential_type" in data:
            chosen = data["credential_type"]
            if chosen is None:
                raise ValidationError("credential_type cannot be set to null.")
            credential.credential_type = chosen.value
        self._reject_impossible_dates(credential.issue_date, credential.expiry_date)
        self._session.flush()
        return credential

    def delete_credential(
        self, *, actor: User, profile: WorkerProfile, credential_id: uuid.UUID
    ) -> None:
        """Soft delete: a verification may already target this credential."""
        credential = self.get_credential(profile=profile, credential_id=credential_id)
        credential.deleted_at = utcnow()
        self._session.flush()
        self._record(
            actor=actor,
            resource_type="credential",
            resource_id=credential.id,
            operation="delete_credential",
        )

    # -- references -------------------------------------------------------- #

    def create_reference(
        self, *, actor: User, profile: WorkerProfile, payload: WorkerReferenceCreateRequest
    ) -> WorkerReference:
        """Nominate a referee.

        ``status`` is left at the model default. The worker may nominate and may
        withdraw; only the referee responding, or an administrator, may confirm.
        """
        reference = WorkerReference(
            worker_profile_id=profile.id,
            full_name=payload.full_name.strip(),
            email=payload.email,
            relationship_type=payload.relationship_type.value,
            organization_name=_clean(payload.organization_name),
            job_title=_clean(payload.job_title),
            phone_number=payload.phone_number,
            is_visible_to_employers=payload.is_visible_to_employers,
        )
        self._session.add(reference)
        try:
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise DuplicateReferenceError() from exc
        self._record(
            actor=actor,
            resource_type="worker_reference",
            resource_id=reference.id,
            operation="create_worker_reference",
            relationship_type=reference.relationship_type,
            nomination_status=reference.status,
            # A nomination is not an attestation. Recorded so the audit trail
            # cannot be read as evidence that anyone has confirmed the worker.
            is_verification=False,
        )
        logger.info("Reference nominated", extra={"reference_id": str(reference.id)})
        return reference

    def list_references(
        self, *, profile: WorkerProfile, limit: int = 20, offset: int = 0
    ) -> tuple[list[WorkerReference], int]:
        conditions = [
            WorkerReference.worker_profile_id == profile.id,
            WorkerReference.deleted_at.is_(None),
        ]
        total = int(
            self._session.execute(
                select(func.count()).select_from(WorkerReference).where(*conditions)
            ).scalar_one()
        )
        statement = (
            select(WorkerReference)
            .where(*conditions)
            .order_by(WorkerReference.created_at.desc(), WorkerReference.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    def get_reference(self, *, profile: WorkerProfile, reference_id: uuid.UUID) -> WorkerReference:
        reference = self._session.execute(
            select(WorkerReference).where(
                WorkerReference.id == reference_id,
                WorkerReference.worker_profile_id == profile.id,
                WorkerReference.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if reference is None:
            raise NotFoundError("The requested reference was not found.")
        return reference

    def update_reference(
        self,
        *,
        profile: WorkerProfile,
        reference_id: uuid.UUID,
        payload: WorkerReferenceUpdateRequest,
    ) -> WorkerReference:
        """Edits the nomination only.

        ``status``, ``response_statement`` and ``responded_by_user_id`` are not
        reachable from any request schema, so a worker cannot confirm their own
        referee however they phrase the request.
        """
        reference = self.get_reference(profile=profile, reference_id=reference_id)
        data = payload.model_dump(exclude_unset=True)
        for field in ("full_name", "email", "relationship_type"):
            if field in data:
                _assign_required(reference, field, data[field], _REQUIRED_REFERENCE_FIELDS)
        for field in ("organization_name", "job_title", "phone_number", "is_visible_to_employers"):
            if field in data:
                setattr(reference, field, data[field])
        self._session.flush()
        return reference

    def delete_reference(
        self, *, actor: User, profile: WorkerProfile, reference_id: uuid.UUID
    ) -> None:
        """Soft delete, so a verification already targeting the nomination resolves."""
        reference = self.get_reference(profile=profile, reference_id=reference_id)
        reference.deleted_at = utcnow()
        self._session.flush()
        self._record(
            actor=actor,
            resource_type="worker_reference",
            resource_id=reference.id,
            operation="delete_worker_reference",
        )

    # -- helpers ----------------------------------------------------------- #

    @staticmethod
    def _reject_impossible_dates(issue_date: date | None, expiry_date: date | None) -> None:
        """A credential cannot have been issued in the future or expire before it."""
        if issue_date is not None and issue_date > utc_today():
            raise ValidationError("issue_date cannot be in the future.")
        if expiry_date is None:
            return
        if expiry_date > utc_today():
            raise ValidationError("expiry_date cannot be in the future.")
        if issue_date is not None and expiry_date < issue_date:
            raise ValidationError("expiry_date cannot be earlier than issue_date.")

    def _record(
        self,
        *,
        actor: User,
        resource_type: str,
        resource_id: uuid.UUID,
        operation: str,
        **metadata: Any,
    ) -> None:
        """One audit row per created or removed record.

        ``ADMIN_ACTION`` is the existing domain-action bucket: ``audit_logs.action``
        is CHECK-constrained, so a credential-specific action needs a new
        ``AuditAction`` member and a migration alongside it. The ``operation`` key
        carries the specific fact until that exists.
        """
        self._audit.record(
            action=AuditAction.ADMIN_ACTION,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome="SUCCESS",
            metadata={"operation": operation, **metadata},
        )


def _clean(value: str | None) -> str | None:
    """Strip optional free text, turning a whitespace-only value into NULL."""
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _assign_required(
    model: Credential | WorkerReference, field: str, value: Any, required: frozenset[str]
) -> None:
    """Write one patched field, refusing an explicit null on a NOT NULL column."""
    if value is None and field in required:
        raise ValidationError(f"{field} cannot be set to null.")
    setattr(model, field, value)


__all__ = ["DuplicateReferenceError", "TrustService"]
