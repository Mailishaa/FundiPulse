"""Verification workflow: a worker asks a third party to confirm one claim.

Every rule in the verification domain lives here, not in the route:

1. **A worker can never verify their own claim.** Two independent refusals guard
   it: :meth:`VerificationService.create_request` refuses a request that nominates
   the requester as the verifier, and :meth:`VerificationService.respond` refuses
   any answer from the account that owns the claim. Both refusals are audited, and
   the ``verifications`` table carries a CHECK constraint so the rule survives a
   future code path that forgets one of them.
2. **A verifier sees only what was addressed to them.** Every read and every
   answer is scoped to "raised by me or addressed to me" - by the nominated email,
   or by an active membership of the organization the request names. A request
   addressed to somebody else matches nothing, which is a 404 rather than a 403 so
   it does not confirm that the request exists.
3. **A request is answered once.** ``PENDING`` is the only answerable status, and
   the row is locked while it is answered, so a second response cannot overwrite
   the first.
4. **A verification is a record of an assertion, not a judgement.** It names the
   verifier, the relationship, the moment and their own words. There is no score,
   no tier, and no status written back onto the claim: the claim stays as the
   worker wrote it and the indicator on a claim is derived by reading this table.

Notifications are appended to the ``notification_events`` outbox and nothing more.
No message is sent here; delivery is a separate concern.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
import uuid

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql.elements import ColumnElement

from app.core.constants import (
    VERIFICATION_REQUEST_EXPIRE_DAYS,
    AuditAction,
    MembershipStatus,
    NotificationEventType,
    VerificationRequestStatus,
    VerificationStatus,
    VerificationTargetType,
)
from app.core.exceptions import (
    ConflictError,
    InvalidStateTransitionError,
    NotFoundError,
    SelfVerificationBlockedError,
    ValidationError,
)
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models.moderation import NotificationEvent
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.user import User
from app.db.models.verification import Verification, VerificationRequest
from app.db.models.worker import Credential, Project, WorkerProfile, WorkExperience
from app.schemas.verifications import (
    VerificationRequestCreate,
    VerificationRespondRequest,
)
from app.services.audit_service import AuditService
from app.services.worker_service import WorkerProfileService
from app.utils.email import mask_email, normalise_email

logger = get_logger(__name__)

#: The claim types this workflow can put to a third party. ``SKILL`` and
#: ``REFERENCE`` exist in the enum because other workflows use them; neither is a
#: third-party claim this endpoint can resolve, and accepting one would create a
#: request whose target nothing here could check.
SUPPORTED_TARGET_TYPES: frozenset[VerificationTargetType] = frozenset(
    {
        VerificationTargetType.EXPERIENCE,
        VerificationTargetType.PROJECT,
        VerificationTargetType.CREDENTIAL,
    }
)

#: Claim tables keyed by target type. All three are soft-deleted and all three are
#: owned by exactly one passport, which is what makes ownership checkable.
_CLAIM_MODELS: dict[VerificationTargetType, type[Any]] = {
    VerificationTargetType.EXPERIENCE: WorkExperience,
    VerificationTargetType.PROJECT: Project,
    VerificationTargetType.CREDENTIAL: Credential,
}

#: Eager loads every read needs, so serialising a page is not an N+1.
_LOADS = (
    selectinload(VerificationRequest.worker_profile),
    selectinload(VerificationRequest.verification),
)

#: Last-resort verifier name. Never a full address: this string is shown to the
#: worker and to employers.
_FALLBACK_VERIFIER_NAME = "Account holder"


class VerificationService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._audit = AuditService(session)
        self._profiles = WorkerProfileService(session)

    # -- create ----------------------------------------------------------- #

    def create_request(
        self, *, actor: User, payload: VerificationRequestCreate
    ) -> VerificationRequest:
        """Raise one request to confirm one claim the caller owns."""
        profile = self._profiles.get_for_user(actor)
        claim = self._load_claim(
            target_type=payload.target_type, target_id=payload.target_id, profile=profile
        )
        verifier_email = normalise_email(payload.verifier_email)
        verifier = self._find_user(verifier_email)
        self._assert_not_self_nominated(
            actor=actor,
            profile=profile,
            target_type=payload.target_type,
            claim=claim,
            verifier_email=verifier_email,
            verifier=verifier,
        )

        requested_at = utcnow()
        request = VerificationRequest(
            worker_profile_id=profile.id,
            requested_by_user_id=actor.id,
            target_type=payload.target_type.value,
            target_id=claim.id,
            target_label=_claim_label(claim),
            target_snapshot=_claim_snapshot(claim),
            verifier_email=verifier_email,
            verifier_full_name=_clean(payload.verifier_full_name),
            verifier_organization_id=self._verifier_organization_id(verifier),
            verifier_relationship=_clean(payload.verifier_relationship),
            message=_clean(payload.message),
            status=VerificationRequestStatus.PENDING.value,
            requested_at=requested_at,
            expires_at=requested_at + timedelta(days=VERIFICATION_REQUEST_EXPIRE_DAYS),
        )
        self._session.add(request)
        try:
            self._session.flush()
        except IntegrityError as exc:
            # The partial unique index permits one PENDING request per target, so
            # this is the race-safe form of "is one already waiting for an answer?".
            self._session.rollback()
            raise ConflictError(
                "A verification request for that claim is already awaiting a response.",
                code="VERIFICATION_REQUEST_ALREADY_PENDING",
            ) from exc

        self._audit.record(
            action=AuditAction.VERIFICATION_REQUESTED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="verification_request",
            resource_id=request.id,
            outcome="REQUESTED",
            metadata={
                "target_type": request.target_type,
                "target_id": str(request.target_id),
                # Masked: an audit row is not the place for a contact address.
                "verifier_email": mask_email(verifier_email),
                "verifier_organization_id": str(request.verifier_organization_id or ""),
            },
        )
        self._append_event(
            event_type=NotificationEventType.VERIFICATION_REQUESTED,
            request=request,
            recipient_user_id=None if verifier is None else verifier.id,
            recipient_email=verifier_email,
            payload={
                "verification_request_id": str(request.id),
                "target_type": request.target_type,
                "target_label": request.target_label,
                "relationship": request.verifier_relationship,
            },
        )
        logger.info(
            "Verification requested",
            extra={
                "verification_request_id": str(request.id),
                "target_type": request.target_type,
            },
        )
        return self._reload(request)

    # -- read ------------------------------------------------------------- #

    def list_requests(
        self,
        *,
        actor: User,
        status: VerificationRequestStatus | None = None,
        target_type: VerificationTargetType | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[VerificationRequest], int]:
        """Both directions at once: raised by the caller, or addressed to them."""
        conditions = self._scope(actor)
        if status is not None:
            conditions.append(VerificationRequest.status == status.value)
        if target_type is not None:
            conditions.append(VerificationRequest.target_type == target_type.value)

        total = int(
            self._session.execute(
                select(func.count()).select_from(VerificationRequest).where(*conditions)
            ).scalar_one()
        )
        statement = (
            select(VerificationRequest)
            .where(*conditions)
            .options(*_LOADS)
            # id last so paging cannot skip or repeat a row.
            .order_by(VerificationRequest.requested_at.desc(), VerificationRequest.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    def get_request(self, *, actor: User, request_id: uuid.UUID) -> VerificationRequest:
        return self._load_scoped(actor=actor, request_id=request_id)

    def verification_for_target(
        self, *, target_type: str, target_id: uuid.UUID
    ) -> Verification | None:
        """The standing attestation for a claim, or ``None``.

        This is how a claim's verification indicator is derived: by reading the
        ``verifications`` row, never by storing a status on the claim. Only a
        ``VERIFIED`` row is returned, so a declined or withdrawn attestation reads
        as "no current attestation" rather than as a verdict on the claim.
        """
        return self._session.execute(
            select(Verification)
            .where(
                Verification.target_type == target_type,
                Verification.target_id == target_id,
                Verification.status == VerificationStatus.VERIFIED.value,
            )
            .order_by(Verification.verified_at.desc(), Verification.id)
            .limit(1)
        ).scalar_one_or_none()

    # -- respond ---------------------------------------------------------- #

    def respond(
        self, *, actor: User, request_id: uuid.UUID, payload: VerificationRespondRequest
    ) -> VerificationRequest:
        """Answer a request addressed to the caller. Single-use."""
        request = self._load_scoped(actor=actor, request_id=request_id, lock=True)
        self._assert_responder_is_not_the_worker(actor=actor, request=request)
        self._assert_answerable(request)
        accepted = payload.confirm
        responded_at = utcnow()
        notes = _clean(payload.notes)

        request.status = (
            VerificationRequestStatus.VERIFIED if accepted else VerificationRequestStatus.REJECTED
        ).value
        request.responded_at = responded_at
        request.responded_by_user_id = actor.id
        request.response_notes = notes

        record = Verification(
            verification_request_id=request.id,
            worker_profile_id=request.worker_profile_id,
            requested_by_user_id=request.requested_by_user_id,
            target_type=request.target_type,
            target_id=request.target_id,
            status=(VerificationStatus.VERIFIED if accepted else VerificationStatus.REJECTED).value,
            verified_by_user_id=actor.id,
            verifier_display_name=self._verifier_display_name(request=request, actor=actor),
            verifier_organization_id=request.verifier_organization_id,
            verifier_relationship=request.verifier_relationship,
            verified_at=responded_at,
            # No expiry: an answer stands until somebody withdraws it. The
            # request's deadline bounds the invitation, not the attestation.
            expires_at=None,
            response_statement=notes,
        )
        self._session.add(record)
        self._session.flush()

        self._append_event(
            event_type=NotificationEventType.VERIFICATION_COMPLETED,
            request=request,
            recipient_user_id=request.requested_by_user_id,
            recipient_email=None,
            payload={
                "verification_request_id": str(request.id),
                "verification_id": str(record.id),
                "target_type": request.target_type,
                "status": record.status,
            },
        )
        metadata = {
            "target_type": request.target_type,
            "target_id": str(request.target_id),
            "verification_id": str(record.id),
            "responder_email": mask_email(actor.email),
            "verifier_relationship": request.verifier_relationship,
        }
        if accepted:
            self._audit.record(
                action=AuditAction.VERIFICATION_COMPLETED,
                actor_user_id=actor.id,
                actor_role=actor.role,
                resource_type="verification_request",
                resource_id=request.id,
                outcome="SUCCESS",
                metadata=metadata,
            )
        else:
            # A declined confirmation is a failure event: it is the record an
            # investigator needs after somebody complains that a claim was put to a
            # named person and turned down. Written durably so it outlives a
            # rollback of whatever happens to the request afterwards.
            self._audit.record_durable(
                action=AuditAction.VERIFICATION_REJECTED,
                actor_user_id=actor.id,
                actor_role=actor.role,
                resource_type="verification_request",
                resource_id=request.id,
                outcome="FAILURE",
                metadata=metadata,
            )
        return self._reload(request)

    # -- cancel ----------------------------------------------------------- #

    def cancel(self, *, actor: User, request_id: uuid.UUID) -> VerificationRequest:
        """Withdraw a request. Only the worker who raised it may do so."""
        request = self._load_owned(actor=actor, request_id=request_id)
        self._assert_answerable(request)
        request.status = VerificationRequestStatus.CANCELLED.value
        request.responded_at = utcnow()
        self._session.flush()
        self._audit.record(
            action=AuditAction.VERIFICATION_CANCELLED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="verification_request",
            resource_id=request.id,
            outcome="SUCCESS",
            metadata={
                "target_type": request.target_type,
                "target_id": str(request.target_id),
            },
        )
        return self._reload(request)

    # -- authorisation ---------------------------------------------------- #

    def _scope(self, actor: User) -> list[ColumnElement[bool]]:
        """``raised by me OR addressed to me``. Every read starts from here."""
        clauses: list[ColumnElement[bool]] = [
            VerificationRequest.requested_by_user_id == actor.id,
            VerificationRequest.verifier_email == actor.email,
        ]
        organization_ids = self._active_organization_ids(actor)
        if organization_ids:
            clauses.append(VerificationRequest.verifier_organization_id.in_(organization_ids))
        return [or_(*clauses)]

    def _load_scoped(
        self, *, actor: User, request_id: uuid.UUID, lock: bool = False
    ) -> VerificationRequest:
        statement = (
            select(VerificationRequest)
            .where(VerificationRequest.id == request_id, *self._scope(actor))
            .options(*_LOADS)
        )
        if lock:
            # Two verifiers racing on one request would otherwise both read PENDING
            # and both write, and the second would silently overwrite the first.
            statement = statement.with_for_update()
        request = self._session.execute(statement).scalar_one_or_none()
        if request is None:
            raise NotFoundError("No verification request was found for you.")
        return request

    def _load_owned(self, *, actor: User, request_id: uuid.UUID) -> VerificationRequest:
        """Requester-only scope: a verifier cannot withdraw somebody's request.

        Always locked, because this is only reached on the withdrawal path and
        withdrawing while a verifier answers would race exactly like answering twice.
        """
        statement = (
            select(VerificationRequest)
            .where(
                VerificationRequest.id == request_id,
                VerificationRequest.requested_by_user_id == actor.id,
            )
            .options(*_LOADS)
            .with_for_update()
        )
        request = self._session.execute(statement).scalar_one_or_none()
        if request is None:
            raise NotFoundError("No verification request was found for you.")
        return request

    def _active_organization_ids(self, user: User) -> list[uuid.UUID]:
        """Organizations whose active membership currently confers verifier standing."""
        return list(
            self._session.execute(
                select(OrganizationMembership.organization_id)
                .join(Organization, Organization.id == OrganizationMembership.organization_id)
                .where(
                    OrganizationMembership.user_id == user.id,
                    OrganizationMembership.status == MembershipStatus.ACTIVE.value,
                    Organization.deleted_at.is_(None),
                )
            ).scalars()
        )

    def _assert_not_self_nominated(
        self,
        *,
        actor: User,
        profile: WorkerProfile,
        target_type: VerificationTargetType,
        claim: Any,
        verifier_email: str,
        verifier: User | None,
    ) -> None:
        """Refuse to raise a request the caller would then be allowed to answer."""
        is_self = verifier_email == actor.email or (
            verifier is not None and verifier.id == actor.id
        )
        if not is_self:
            return
        self._audit.record_durable(
            action=AuditAction.VERIFICATION_REJECTED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="worker_profile",
            resource_id=profile.id,
            outcome="DENIED",
            metadata={
                "reason": "self_verification_blocked",
                "stage": "request",
                "target_type": target_type.value,
                "target_id": str(claim.id),
            },
        )
        raise SelfVerificationBlockedError()

    def _assert_responder_is_not_the_worker(
        self, *, actor: User, request: VerificationRequest
    ) -> None:
        """Refuse to answer a request about the caller's own claim.

        The second half of invariant 1, and the half that closes it: a request may
        have been raised entirely legitimately by a colleague, but the account that
        owns the claim can never be the account that answers it.
        """
        profile = self._profiles.get_by_id(request.worker_profile_id)
        if profile.user_id != actor.id and request.requested_by_user_id != actor.id:
            return
        self._audit.record_durable(
            action=AuditAction.VERIFICATION_REJECTED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="verification_request",
            resource_id=request.id,
            outcome="DENIED",
            metadata={
                "reason": "self_verification_blocked",
                "stage": "respond",
                "target_type": request.target_type,
                "target_id": str(request.target_id),
            },
        )
        raise SelfVerificationBlockedError()

    def _assert_answerable(self, request: VerificationRequest) -> None:
        """Only a live ``PENDING`` request may be answered or withdrawn."""
        if request.status != VerificationRequestStatus.PENDING.value:
            raise InvalidStateTransitionError(
                "This verification request has already been answered or withdrawn."
            )
        if request.expires_at <= utcnow():
            raise InvalidStateTransitionError("This verification request has passed its deadline.")

    # -- helpers ---------------------------------------------------------- #

    def _load_claim(
        self, *, target_type: VerificationTargetType, target_id: uuid.UUID, profile: WorkerProfile
    ) -> Any:
        """Load the claim, scoped to the requesting worker's own passport.

        Scoping by the parent passport rather than checking ownership afterwards is
        what makes this a non-disclosure: another worker's record and an id that
        does not exist produce the same empty result and the same 404.
        """
        model = _CLAIM_MODELS.get(target_type)
        if model is None:
            raise ValidationError(
                "That kind of claim cannot be put to a third party here. Supported: "
                + ", ".join(sorted(item.value for item in SUPPORTED_TARGET_TYPES))
                + "."
            )
        claim = self._session.execute(
            select(model).where(
                model.id == target_id,
                model.worker_profile_id == profile.id,
                model.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if claim is None:
            raise NotFoundError("That claim was not found on your Work Passport.")
        return claim

    def _find_user(self, email: str) -> User | None:
        """The nominated verifier's account, if they have one.

        Never required: a verifier who has not registered is still a legitimate
        third party, they simply cannot answer through the API yet.
        """
        user = self._session.execute(
            select(User).where(User.email == email, User.deleted_at.is_(None))
        ).scalar_one_or_none()
        return user if isinstance(user, User) else None

    def _verifier_organization_id(self, verifier: User | None) -> uuid.UUID | None:
        """Record the nominee's company, derived server-side.

        Never read from the request body: a client-supplied organization id would be
        a way to grant somebody else standing to answer. Resolving it here makes the
        stored value a fact about the nominee rather than an assertion by a caller.
        """
        if verifier is None:
            return None
        organization_ids = self._active_organization_ids(verifier)
        return organization_ids[0] if organization_ids else None

    def _verifier_display_name(self, *, request: VerificationRequest, actor: User) -> str:
        """How the verifier is named on the record: the name the worker supplied,
        else the account's local part."""
        if request.verifier_full_name:
            return request.verifier_full_name
        return actor.email.split("@", 1)[0] or _FALLBACK_VERIFIER_NAME

    def _append_event(
        self,
        *,
        event_type: NotificationEventType,
        request: VerificationRequest,
        recipient_user_id: uuid.UUID | None,
        recipient_email: str | None,
        payload: dict[str, Any],
    ) -> None:
        """Outbox only. Nothing is sent; a delivery worker reads this table."""
        self._session.add(
            NotificationEvent(
                event_type=event_type.value,
                user_id=recipient_user_id,
                recipient_email=recipient_email,
                worker_profile_id=request.worker_profile_id,
                payload=payload,
                created_at=utcnow(),
            )
        )

    def _reload(self, request: VerificationRequest) -> VerificationRequest:
        """Re-read so a caller never sees the in-memory object we just mutated.

        ``populate_existing`` matters: the row is already in the session's identity
        map, so without it SQLAlchemy would hand back the same instance with the
        relationships it loaded before the response existed - which is how a freshly
        created verification record ends up serialised as ``null``.
        """
        refreshed: VerificationRequest = self._session.execute(
            select(VerificationRequest)
            .where(VerificationRequest.id == request.id)
            .options(*_LOADS)
            .execution_options(populate_existing=True)
        ).scalar_one()
        return refreshed


def _clean(value: str | None) -> str | None:
    """Trim, mapping an empty string to NULL so ``''`` and ``None`` stay the same."""
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def _claim_label(claim: Any) -> str:
    """A short, human label for the claim, in the worker's own words."""
    if isinstance(claim, WorkExperience):
        return f"{claim.role_title} at {claim.employer_name}"[:255]
    if isinstance(claim, Project):
        return claim.name[:255]
    if isinstance(claim, Credential):
        return claim.title[:255]
    return "Claim"  # pragma: no cover - unreachable while _CLAIM_MODELS is fixed


def _claim_snapshot(claim: Any) -> dict[str, Any]:
    """Freeze the claim as written, so a later edit cannot rewrite the question.

    Only fields the worker typed. Dates become ISO strings because the snapshot is
    JSON, and the answer to "what were you shown?" must not depend on how the
    database happens to render a date.
    """
    if isinstance(claim, WorkExperience):
        return {
            "employer_name": claim.employer_name,
            "project_name": claim.project_name,
            "role_title": claim.role_title,
            "location": claim.location,
            "start_date": claim.start_date.isoformat(),
            "end_date": claim.end_date.isoformat() if claim.end_date else None,
            "is_current": claim.is_current,
            "description": claim.description,
        }
    if isinstance(claim, Project):
        return {
            "name": claim.name,
            "role_title": claim.role_title,
            "project_type": claim.project_type,
            "location": claim.location,
            "start_date": claim.start_date.isoformat() if claim.start_date else None,
            "end_date": claim.end_date.isoformat() if claim.end_date else None,
            "description": claim.description,
        }
    if isinstance(claim, Credential):
        return {
            "title": claim.title,
            "issuer": claim.issuer,
            "credential_number": claim.credential_number,
            "issue_date": claim.issue_date.isoformat() if claim.issue_date else None,
            "expiry_date": claim.expiry_date.isoformat() if claim.expiry_date else None,
            "description": claim.description,
        }
    return {}  # pragma: no cover - unreachable while _CLAIM_MODELS is fixed
