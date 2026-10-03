"""Employer-to-worker contact requests.

The privacy rule this service exists to enforce: **a worker's phone number and
email are never disclosed as a side effect of being searchable.** An employer who
finds a worker in search sees professional information only, and to reach them
they must file a request the worker can see and answer.

Who may ask is decided by organization membership, resolved through the same
authorisation helper the organizations domain uses, so a caller without a
membership in the named organization cannot file against it at all. Note the
asymmetry that falls out of this: the *worker* needs no organization membership,
because being the passport owner is the authorisation.

``contact_preference`` on the passport is consulted for nothing but whether a
request is worth filing — it is a routing hint and never releases an address.
Disclosure happens exactly once, when the worker accepts, and is recorded as
``contact_details_shared`` so a later status correction cannot rewrite history.
"""

from __future__ import annotations

from typing import Any
import uuid

from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.constants import (
    AuditAction,
    ContactRequestStatus,
    NotificationEventType,
    OrganizationRole,
)
from app.core.exceptions import (
    ConflictError,
    ForbiddenError,
    InvalidStateTransitionError,
    NotFoundError,
)
from app.db.base import utcnow
from app.db.models.contact import ContactRequest
from app.db.models.job import Job
from app.db.models.worker import WorkerProfile
from app.schemas.contact import ContactRequestCreateRequest
from app.services.audit_service import AuditService
from app.services.notification_service import NotificationService
from app.services.organization_service import OrganizationService

#: Roles permitted to reach out to a worker. A plain MEMBER has no recruiting remit.
RECRUITING_ROLES = frozenset(
    {OrganizationRole.OWNER, OrganizationRole.ADMIN, OrganizationRole.RECRUITER}
)

#: How long a request stays answerable before the sweep expires it.
REQUEST_TTL_DAYS = 30


class ContactRequestNotFoundError(NotFoundError):
    public_message = "The requested contact request was not found."


class DuplicateContactRequestError(ConflictError):
    public_message = "You already have a request pending with this worker."


class ContactRequestNotAnswerableError(InvalidStateTransitionError):
    """A request that is no longer PENDING.

    409 rather than 422: the request is well-formed, it is simply impossible in the
    current state. A client can distinguish "you sent something invalid" from "this
    was already answered".
    """

    public_message = "This contact request can no longer be answered."


class WorkerNotContactableError(ForbiddenError):
    public_message = "This worker is not accepting contact requests."


class ContactRequestService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._audit = AuditService(session)
        self._notifications = NotificationService(session)
        self._organizations = OrganizationService(session)

    # -- create ------------------------------------------------------------ #

    def create(
        self,
        *,
        actor: Any,
        worker_profile_id: uuid.UUID,
        payload: ContactRequestCreateRequest,
    ) -> ContactRequest:
        """File a request. The requester is the caller; nothing here is settable by them."""
        self._organizations._authorize(
            actor=actor,
            organization_id=payload.organization_id,
            required_roles=RECRUITING_ROLES,
            operation="request_worker_contact",
        )

        worker = self._load_worker(worker_profile_id)
        if worker.visibility == "PRIVATE" and worker.user_id != actor.id:
            raise ContactRequestNotFoundError()
        if worker.contact_preference == "NONE":
            # Said plainly rather than silently accepted: the request would sit
            # unanswered forever, and the employer deserves to know why.
            raise WorkerNotContactableError(
                "This worker has not listed a way to be contacted.",
                code="WORKER_NOT_CONTACTABLE",
            )

        job = self._load_job(payload.job_id, payload.organization_id)

        request = ContactRequest(
            worker_profile_id=worker.id,
            requester_user_id=actor.id,
            organization_id=payload.organization_id,
            job_id=job.id if job is not None else None,
            status=ContactRequestStatus.PENDING.value,
            message=(payload.message or "").strip() or None,
            contact_details_shared=False,
        )
        self._session.add(request)
        try:
            self._session.flush()
        except IntegrityError as exc:
            # The partial unique index is the guarantee, not a pre-check: two
            # concurrent requests from the same employer race past any read-then-write.
            self._session.rollback()
            raise DuplicateContactRequestError() from exc

        self._notifications.enqueue(
            recipient_user_id=worker.user_id,
            event_type=NotificationEventType.EMPLOYER_CONTACT_REQUEST,
            title="An employer would like to contact you",
            body=(
                "Someone at an organization is interested in working with you. "
                "Review the request and decide whether to share your details."
            ),
            related_resource_id=request.id,
            related_resource_type="contact_request",
        )
        self._audit.record(
            action=AuditAction.ADMIN_ACTION,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="contact_request",
            resource_id=request.id,
            outcome="SUCCESS",
            metadata={
                "operation": "create_contact_request",
                "organization_id": str(payload.organization_id),
                "worker_profile_id": str(worker.id),
            },
        )
        return request

    # -- read -------------------------------------------------------------- #

    def list_for_worker(
        self, *, worker: WorkerProfile, limit: int, offset: int
    ) -> tuple[list[ContactRequest], int]:
        return self._page(
            self._base().where(ContactRequest.worker_profile_id == worker.id),
            limit=limit,
            offset=offset,
        )

    def list_for_requester(
        self, *, requester_user_id: uuid.UUID, limit: int, offset: int
    ) -> tuple[list[ContactRequest], int]:
        """What this account has asked. Not what its organization has asked."""
        return self._page(
            self._base().where(ContactRequest.requester_user_id == requester_user_id),
            limit=limit,
            offset=offset,
        )

    def get_for_worker(self, *, worker: WorkerProfile, request_id: uuid.UUID) -> ContactRequest:
        """Scoped by the passport as well as the id, so a foreign id matches nothing."""
        row = self._session.execute(
            self._base()
            .where(
                ContactRequest.id == request_id,
                ContactRequest.worker_profile_id == worker.id,
            )
            .limit(1)
        ).scalar_one_or_none()
        if row is None:
            raise ContactRequestNotFoundError()
        return row

    def get_for_requester(self, *, actor: Any, request_id: uuid.UUID) -> ContactRequest:
        """The asking side. Requires an active membership in the asking organization."""
        row = self._session.execute(
            self._base().where(ContactRequest.id == request_id).limit(1)
        ).scalar_one_or_none()
        if row is None:
            raise ContactRequestNotFoundError()
        self._organizations._authorize(
            actor=actor,
            organization_id=row.organization_id,
            required_roles=RECRUITING_ROLES,
            operation="read_contact_request",
        )
        return row

    # -- transitions ------------------------------------------------------- #

    def accept(
        self,
        *,
        worker: WorkerProfile,
        request_id: uuid.UUID,
        response_note: str | None,
    ) -> ContactRequest:
        """Release the worker's details to the requesting organization. Once only."""
        return self._answer(
            worker=worker,
            request_id=request_id,
            status=ContactRequestStatus.ACCEPTED,
            response_note=response_note,
            shared=True,
        )

    def reject(
        self, *, worker: WorkerProfile, request_id: uuid.UUID, response_note: str | None
    ) -> ContactRequest:
        return self._answer(
            worker=worker,
            request_id=request_id,
            status=ContactRequestStatus.REJECTED,
            response_note=response_note,
            shared=False,
        )

    def cancel(self, *, actor: Any, request_id: uuid.UUID) -> ContactRequest:
        """The asker withdraws. Only the asking side may do this."""
        row = self._session.execute(
            self._base().where(ContactRequest.id == request_id).limit(1)
        ).scalar_one_or_none()
        if row is None or row.requester_user_id != actor.id:
            raise ContactRequestNotFoundError()
        return self._answer(
            worker=self._worker_of(row),
            request_id=request_id,
            status=ContactRequestStatus.CANCELLED,
            response_note=None,
            shared=row.contact_details_shared,
        )

    def _answer(
        self,
        *,
        worker: WorkerProfile,
        request_id: uuid.UUID,
        status: ContactRequestStatus,
        response_note: str | None,
        shared: bool,
    ) -> ContactRequest:
        row = self.get_for_worker(worker=worker, request_id=request_id)
        if row.status != ContactRequestStatus.PENDING.value:
            raise ContactRequestNotAnswerableError(
                f"A {row.status.lower()} contact request cannot be answered.",
                code="CONTACT_REQUEST_NOT_PENDING",
            )

        row.status = status.value
        row.responded_at = utcnow()
        row.response_note = (response_note or "").strip() or None
        # Deliberately monotonic: `shared` is a fact about what already happened,
        # so a cancellation after an acceptance cannot un-disclose anything.
        row.contact_details_shared = row.contact_details_shared or shared
        self._session.flush()

        if row.requester_user_id is not None:
            self._notifications.enqueue(
                recipient_user_id=row.requester_user_id,
                event_type=NotificationEventType.EMPLOYER_CONTACT_REQUEST,
                title=(
                    "A worker accepted your contact request"
                    if status is ContactRequestStatus.ACCEPTED
                    else "A contact request was closed"
                ),
                body=(
                    "Their contact details are now available to your organization."
                    if status is ContactRequestStatus.ACCEPTED
                    else "The worker is not proceeding with contact at this time."
                ),
                related_resource_id=row.id,
                related_resource_type="contact_request",
            )
        self._audit.record(
            action=AuditAction.ADMIN_ACTION,
            actor_user_id=worker.user_id,
            actor_role="WORKER",
            resource_type="contact_request",
            resource_id=row.id,
            outcome="SUCCESS",
            metadata={"operation": f"contact_request_{status.value.lower()}"},
        )
        return row

    # -- helpers ----------------------------------------------------------- #

    def _base(self) -> Select[tuple[ContactRequest]]:
        return (
            select(ContactRequest)
            .where(ContactRequest.deleted_at.is_(None))
            .options(
                selectinload(ContactRequest.worker),
                selectinload(ContactRequest.organization),
                selectinload(ContactRequest.job),
            )
        )

    def _page(
        self, statement: Select[tuple[ContactRequest]], *, limit: int, offset: int
    ) -> tuple[list[ContactRequest], int]:
        total = int(
            self._session.execute(
                select(func.count()).select_from(statement.subquery())
            ).scalar_one()
        )
        rows = (
            self._session.execute(
                statement.order_by(ContactRequest.created_at.desc(), ContactRequest.id)
                .limit(limit)
                .offset(offset)
            )
            .unique()
            .scalars()
            .all()
        )
        return list(rows), total

    def _load_worker(self, worker_profile_id: uuid.UUID) -> WorkerProfile:
        row = self._session.execute(
            select(WorkerProfile).where(
                WorkerProfile.id == worker_profile_id,
                WorkerProfile.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if row is None:
            raise ContactRequestNotFoundError()
        return row

    def _worker_of(self, request: ContactRequest) -> WorkerProfile:
        return self._load_worker(request.worker_profile_id)

    def _load_job(self, job_id: uuid.UUID | None, organization_id: uuid.UUID) -> Job | None:
        """The job must belong to the organization the request is filed under.

        Otherwise an employer could attach its request to another organization's
        vacancy and give a worker a reason to believe that company is hiring.
        """
        if job_id is None:
            return None
        row = self._session.execute(
            select(Job).where(
                Job.id == job_id,
                Job.organization_id == organization_id,
                Job.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if row is None:
            raise ContactRequestNotFoundError()
        return row
