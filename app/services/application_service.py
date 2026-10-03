"""Job applications: one worker's application to one job, through its lifecycle.

Four rules shape this module, and each of them is a security property rather than
a convenience.

**The worker is the authenticated caller.** There is no ``worker_id`` in any
request schema, so every worker-facing read and write is scoped by the passport
belonging to the token that made the request. Substituting another worker's
application id matches nothing, which is a 404 rather than a 403.

**The unique constraint is the guarantee.** ``uq_job_applications_job_worker``
means one application per worker per job, and a read-then-write pre-check cannot
enforce that: two concurrent submits both read "no application yet" and both
insert. The service therefore has no duplicate pre-check at all. It inserts and
lets the database refuse the loser, translating the ``IntegrityError`` into a 409.
The one lookup it does make is for a repeated ``idempotency_key``, which answers a
different question - "did my own request already succeed?" - and on a constraint
violation it asks again, because the winner may have committed in between.

**Only the employer decides.** ``SHORTLISTED`` and ``HIRED`` are an employer's
call about a person, so a worker can never reach them: their only write is
``withdraw``. The lifecycle is declared once in :data:`EMPLOYER_TRANSITIONS` and
:data:`WORKER_TRANSITIONS`, chosen by the caller's platform role, and anything not
listed is an :class:`InvalidStateTransitionError`. ``WITHDRAWN`` and ``HIRED`` are
terminal.

**Authorization is membership, scoped into the query.** The employer listing is
scoped by the job's ``organization_id`` *and* by an active membership in it. The
status change has no organization in the path, so its lookup is scoped by the
caller's memberships instead: an employer who does not manage the application's
organization receives the same 404 as somebody who invented the id, so
Organization A cannot even confirm that Organization B's application exists.

Applications are never deleted. A worker changes their mind, the row records it,
and the employer's decision history survives.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Select, false, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql.elements import ColumnElement

from app.core.constants import (
    EXTERNAL_JOB_SOURCE_TYPES,
    ApplicationStatus,
    AuditAction,
    JobSourceType,
    JobStatus,
    MembershipStatus,
    NotificationEventType,
    OrganizationRole,
    UserRole,
)
from app.core.exceptions import (
    ConflictError,
    IdempotencyKeyReusedError,
    InvalidStateTransitionError,
    NotFoundError,
)
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models.job import Job, JobApplication
from app.db.models.organization import OrganizationMembership
from app.db.models.user import User
from app.db.models.worker import WorkerProfile, WorkerTrade
from app.schemas.applications import (
    ApplicationCreateRequest,
    ApplicationStatusChangeRequest,
)
from app.services.audit_service import AuditService
from app.services.auth_service import RequestContext
from app.services.job_service import (
    JobManagementForbiddenError,
    JobNotFoundError,
    JobService,
    effective_status,
)
from app.services.notification_service import NotificationService
from app.services.worker_service import WorkerProfileService

logger = get_logger(__name__)

#: The employer side of the lifecycle, declared once. Anything not listed is refused.
#:
#: ``VIEWED`` is reachable only from ``SUBMITTED``: it records that an employer has
#: read the application, so re-marking a viewed application viewed is a no-op that
#: would be indistinguishable from a real transition.
#:
#: ``REJECTED -> SHORTLISTED`` is legal because an employer who rejected in error
#: may change their mind; the audit trail keeps both decisions, so nothing is
#: rewritten. Self-transitions (``SHORTLISTED -> SHORTLISTED`` and friends) are
#: not, for the same reason they are not legal on jobs.
#:
#: ``HIRED`` and ``WITHDRAWN`` have no successors: the outcome is recorded.
EMPLOYER_TRANSITIONS: dict[ApplicationStatus, frozenset[ApplicationStatus]] = {
    ApplicationStatus.SUBMITTED: frozenset(
        {
            ApplicationStatus.VIEWED,
            ApplicationStatus.SHORTLISTED,
            ApplicationStatus.REJECTED,
            ApplicationStatus.HIRED,
        }
    ),
    ApplicationStatus.VIEWED: frozenset(
        {ApplicationStatus.SHORTLISTED, ApplicationStatus.REJECTED, ApplicationStatus.HIRED}
    ),
    ApplicationStatus.SHORTLISTED: frozenset({ApplicationStatus.REJECTED, ApplicationStatus.HIRED}),
    ApplicationStatus.REJECTED: frozenset({ApplicationStatus.SHORTLISTED, ApplicationStatus.HIRED}),
    ApplicationStatus.HIRED: frozenset(),
    ApplicationStatus.WITHDRAWN: frozenset(),
}

#: The worker's side of the lifecycle: withdrawal and nothing else.
#:
#: ``HIRED`` is absent deliberately - a worker cannot withdraw from a job they have
#: been hired for, and the hire is the outcome of the whole process.
WORKER_TRANSITIONS: dict[ApplicationStatus, frozenset[ApplicationStatus]] = {
    ApplicationStatus.SUBMITTED: frozenset({ApplicationStatus.WITHDRAWN}),
    ApplicationStatus.VIEWED: frozenset({ApplicationStatus.WITHDRAWN}),
    ApplicationStatus.SHORTLISTED: frozenset({ApplicationStatus.WITHDRAWN}),
    ApplicationStatus.REJECTED: frozenset({ApplicationStatus.WITHDRAWN}),
    ApplicationStatus.HIRED: frozenset(),
    ApplicationStatus.WITHDRAWN: frozenset(),
}

#: Why a refused job says no. A draft is absent here on purpose: a worker must not
#: learn that an unpublished listing exists, so a draft is a 404 like any other
#: unknown id rather than a status-specific refusal.
JOB_REFUSAL_REASONS: dict[JobStatus, str] = {
    JobStatus.CLOSED: "This job has closed and is no longer accepting applications.",
    JobStatus.CANCELLED: "This job was cancelled by the employer.",
    JobStatus.EXPIRED: "This job has passed its closing date.",
}


class ApplicationNotFoundError(NotFoundError):
    """No application the caller is allowed to know about."""

    public_message = "No such application was found."


class DuplicateApplicationError(ConflictError):
    """The worker already applied to this job."""

    code = "DUPLICATE_APPLICATION"
    public_message = "You have already applied to this job."


class JobNotAcceptingApplicationsError(ConflictError):
    """The job exists and is visible, but is not taking applications."""

    code = "JOB_NOT_ACCEPTING_APPLICATIONS"
    public_message = "This job is not accepting applications."


class ApplicationService:
    """Reads and lifecycle writes for job applications."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._audit = AuditService(session)
        self._jobs = JobService(session)
        self._notifications = NotificationService(session)
        self._profiles = WorkerProfileService(session)

    # -- worker writes ----------------------------------------------------- #

    def apply(
        self,
        *,
        actor: User,
        job_id: uuid.UUID,
        payload: ApplicationCreateRequest,
        context: RequestContext | None = None,
    ) -> tuple[JobApplication, bool]:
        """Submit an application to the job in the path.

        The worker is taken from ``actor``'s own Work Passport and the job from the
        path; neither can be supplied by the client. The status is fixed at
        ``SUBMITTED`` here, so there is no way to arrive already shortlisted.

        Returns the application and whether it was *replayed* - the row an earlier
        request with the same ``idempotency_key`` already created. A replay is the
        answer to a retry, not a new resource, so the route reports it as 200.
        """
        profile = self._own_profile(actor)
        job = self._job_open_to_applications(job_id)
        replay = self._idempotent_replay(profile=profile, job=job, payload=payload)
        if replay is not None:
            return replay, True

        application = JobApplication(
            job_id=job.id,
            worker_profile_id=profile.id,
            cover_note=payload.cover_note,
            status=ApplicationStatus.SUBMITTED.value,
            submitted_at=utcnow(),
            idempotency_key=payload.idempotency_key,
            source_ip=context.ip_address if context else None,
        )
        try:
            # A savepoint, not a bare rollback: the constraint violation must not
            # discard whatever else the request had pending, and the caller still
            # needs a usable transaction to write the refusal into. The object is
            # added *inside* the savepoint for the same reason - ``begin_nested()``
            # flushes whatever is already pending before it emits ``SAVEPOINT``, so
            # an object added beforehand would fail outside the protection.
            with self._session.begin_nested():
                self._session.add(application)
                self._session.flush()
        except IntegrityError as exc:
            # Ask again whether this request already succeeded. The lookup above ran
            # before the competing commit landed, and the constraint name is not a
            # reliable discriminator: a duplicate carries both indexes, so the
            # driver may name either one. The caller's own key settles it.
            replay = self._idempotent_replay(profile=profile, job=job, payload=payload)
            if replay is not None:
                return replay, True
            self._audit.record_durable(
                action=AuditAction.APPLICATION_SUBMITTED,
                actor_user_id=actor.id,
                actor_role=actor.role,
                resource_type="job_application",
                ip_address=context.ip_address if context else None,
                user_agent=context.user_agent if context else None,
                request_id=context.request_id if context else None,
                outcome="DENIED",
                metadata={
                    "operation": "submit_application",
                    "job_id": str(job.id),
                    "constraint": _violated_constraint(exc),
                },
            )
            raise DuplicateApplicationError() from exc

        _adjust_counter(job, 1)
        self._session.flush()
        self._audit.record(
            action=AuditAction.APPLICATION_SUBMITTED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="job_application",
            resource_id=application.id,
            ip_address=context.ip_address if context else None,
            user_agent=context.user_agent if context else None,
            request_id=context.request_id if context else None,
            outcome="SUCCESS",
            metadata={
                "operation": "submit_application",
                "job_id": str(job.id),
                "organization_id": str(job.organization_id or ""),
                "status": ApplicationStatus.SUBMITTED.value,
            },
        )
        logger.info(
            "Job application submitted",
            extra={"application_id": str(application.id), "job_id": str(job.id)},
        )
        return self._reload(application), False

    def withdraw(
        self, *, actor: User, application_id: uuid.UUID, context: RequestContext | None = None
    ) -> JobApplication:
        """``-> WITHDRAWN``. The row stays, and stays readable.

        Withdrawal is not a delete: an employer who shortlisted somebody and then
        heard nothing should be able to see that the candidate withdrew rather than
        discovering the application has vanished.
        """
        profile = self._own_profile(actor)
        application = self._own_application(profile=profile, application_id=application_id)
        current = application.status_enum
        target = ApplicationStatus.WITHDRAWN
        if target not in WORKER_TRANSITIONS.get(current, frozenset()):
            self._refuse(
                action=AuditAction.APPLICATION_WITHDRAWN,
                actor=actor,
                application=application,
                context=context,
                metadata={"operation": "withdraw_application", "previous_status": current.value},
                message=_transition_refusal(current, target, employer=False),
            )

        self._stamp(application=application, target=target, actor=actor, note=None)
        self._session.flush()
        self._notify_withdrawal(application)
        self._audit.record(
            action=AuditAction.APPLICATION_WITHDRAWN,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="job_application",
            resource_id=application.id,
            ip_address=context.ip_address if context else None,
            user_agent=context.user_agent if context else None,
            request_id=context.request_id if context else None,
            outcome="SUCCESS",
            metadata={
                "operation": "withdraw_application",
                "job_id": str(application.job_id),
                "previous_status": current.value,
            },
        )
        logger.info(
            "Job application withdrawn",
            extra={"application_id": str(application.id), "job_id": str(application.job_id)},
        )
        return self._reload(application)

    # -- employer writes --------------------------------------------------- #

    def change_status(
        self,
        *,
        actor: User,
        application_id: uuid.UUID,
        payload: ApplicationStatusChangeRequest,
        context: RequestContext | None = None,
    ) -> JobApplication:
        """Move an application through the lifecycle.

        The same method serves both actors so the state machine cannot be bypassed by
        calling it the "wrong" way round. An employer is scoped by membership, and a
        ``WORKER`` actor is scoped to their own application *and* to
        :data:`WORKER_TRANSITIONS`, which contains only ``WITHDRAWN``. A worker
        asking for ``SHORTLISTED`` is therefore an ``InvalidStateTransitionError`,
        decided by the lifecycle rather than by trusting the caller's role.
        """
        employer_actor = actor.role in _EMPLOYER_ROLES
        if employer_actor:
            application = self._managed_application(
                actor=actor,
                application_id=application_id,
                action=AuditAction.APPLICATION_STATUS_CHANGED,
                operation="change_application_status",
                context=context,
            )
        else:
            application = self._own_application(
                profile=self._own_profile(actor), application_id=application_id
            )
        current = application.status_enum
        target = payload.status
        permitted = (EMPLOYER_TRANSITIONS if employer_actor else WORKER_TRANSITIONS).get(
            current, frozenset()
        )
        if target not in permitted:
            self._refuse(
                action=AuditAction.APPLICATION_STATUS_CHANGED,
                actor=actor,
                application=application,
                context=context,
                metadata={
                    "operation": "change_application_status",
                    "previous_status": current.value,
                    "requested_status": target.value,
                },
                message=_transition_refusal(current, target, employer=employer_actor),
            )

        self._stamp(application=application, target=target, actor=actor, note=payload.decision_note)
        self._session.flush()

        self._notifications.enqueue(
            recipient_user_id=application.worker_profile.user_id,
            event_type=NotificationEventType.APPLICATION_STATUS_CHANGED,
            title=f"Your application for {application.job.title} is now {target.value}",
            body=(
                f"The employer moved your application for {application.job.title} "
                f"from {current.value} to {target.value}."
            ),
            related_resource_id=application.id,
            related_resource_type="job_application",
            payload={
                "job_id": str(application.job_id),
                "previous_status": current.value,
                "new_status": target.value,
            },
        )
        self._audit.record(
            action=AuditAction.APPLICATION_STATUS_CHANGED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="job_application",
            resource_id=application.id,
            ip_address=context.ip_address if context else None,
            user_agent=context.user_agent if context else None,
            request_id=context.request_id if context else None,
            outcome="SUCCESS",
            metadata={
                "operation": "change_application_status",
                "job_id": str(application.job_id),
                "previous_status": current.value,
                "new_status": target.value,
            },
        )
        logger.info(
            "Job application status changed",
            extra={
                "application_id": str(application.id),
                "previous_status": current.value,
                "new_status": target.value,
            },
        )
        return self._reload(application)

    # -- reads -------------------------------------------------------------- #

    def get_own(self, *, actor: User, application_id: uuid.UUID) -> JobApplication:
        """Read one of the caller's own applications, withdrawn ones included."""
        return self._own_application(
            profile=self._own_profile(actor), application_id=application_id
        )

    def list_own(
        self,
        *,
        actor: User,
        status: ApplicationStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[JobApplication], int]:
        """The caller's applications, newest first. Nobody else's is in scope."""
        profile = self._own_profile(actor)
        conditions = [JobApplication.worker_profile_id == profile.id]
        if status is not None:
            conditions.append(JobApplication.status == status.value)
        total = self._count_own(conditions)
        rows = self._session.execute(
            self._base_query()
            .where(*conditions)
            .order_by(JobApplication.created_at.desc(), JobApplication.id)
            .limit(limit)
            .offset(offset)
        ).scalars()
        return list(rows), total

    def list_for_job(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        status: ApplicationStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[JobApplication], int]:
        """The applicants to one of this organization's jobs.

        Both gates are required and they answer different questions. The membership
        check asks "may this caller see a candidate pipeline at all", and it is asked
        first because the organization is in the path - naming another organization's
        id already told the caller it exists. The job lookup is then scoped by that
        same organization, so an employer who substitutes another employer's job id
        matches nothing. As on the jobs domain, the membership refusal is the 403
        itself rather than an audit row: nothing was changed and nothing was read.
        """
        if not self._jobs.is_manager(actor=actor, organization_id=organization_id):
            raise JobManagementForbiddenError()

        job_id_present = self._session.execute(
            select(Job.id).where(
                Job.id == job_id,
                Job.organization_id == organization_id,
                Job.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if job_id_present is None:
            raise JobNotFoundError()

        conditions = [JobApplication.job_id == job_id]
        if status is not None:
            conditions.append(JobApplication.status == status.value)
        total = int(
            self._session.execute(
                select(func.count()).select_from(JobApplication).where(*conditions)
            ).scalar_one()
        )
        rows = self._session.execute(
            self._base_query()
            .where(*conditions)
            .order_by(JobApplication.created_at.desc(), JobApplication.id)
            .limit(limit)
            .offset(offset)
        ).scalars()
        return list(rows), total

    # -- internals ---------------------------------------------------------- #

    def _stamp(
        self,
        *,
        application: JobApplication,
        target: ApplicationStatus,
        actor: User,
        note: str | None,
    ) -> None:
        """Write a legal transition onto the row, and keep the counter honest.

        One place stamps, so withdrawal and an employer decision cannot drift apart
        in what they record. ``VIEWED`` deliberately clears the decision fields: it
        is an acknowledgement that the application was read, and leaving a stale
        "decided by" from an earlier state would misattribute the current status. A
        withdrawal keeps whatever decision came before it, because that history is
        the whole point of not deleting the row - which is also why a note is only
        written when one was supplied, so a withdrawal cannot erase it.
        """
        moment = utcnow()
        application.status = target.value
        application.updated_status_at = moment
        if note is not None:
            application.decision_note = note
        if target is ApplicationStatus.WITHDRAWN:
            application.withdrawn_at = moment
            # No longer an application the employer is waiting on.
            _adjust_counter(application.job, -1)
        elif target in _DECISION_STATUSES:
            application.decided_at = moment
            application.decided_by_user_id = actor.id
        else:
            application.decided_at = None
            application.decided_by_user_id = None

    def _base_query(self) -> Select[tuple[JobApplication]]:
        """One eager-load shape for every read, so nothing N+1s."""
        return select(JobApplication).options(
            selectinload(JobApplication.job).selectinload(Job.organization),
            selectinload(JobApplication.worker_profile)
            .selectinload(WorkerProfile.trades)
            .selectinload(WorkerTrade.trade),
        )

    def _reload(self, application: JobApplication) -> JobApplication:
        self._session.expire(application, ["job", "worker_profile"])
        return self._session.execute(
            self._base_query().where(JobApplication.id == application.id)
        ).scalar_one()

    def _own_profile(self, actor: User) -> WorkerProfile:
        """The caller's passport, or 404. Never one named by the client."""
        return self._profiles.get_for_user(actor)

    def _own_application(
        self, *, profile: WorkerProfile, application_id: uuid.UUID
    ) -> JobApplication:
        """Scope by the parent, so another worker's id simply matches nothing."""
        application = self._session.execute(
            self._base_query().where(
                JobApplication.id == application_id,
                JobApplication.worker_profile_id == profile.id,
            )
        ).scalar_one_or_none()
        if application is None:
            raise ApplicationNotFoundError()
        return application

    def _managed_application(
        self,
        *,
        actor: User,
        application_id: uuid.UUID,
        action: AuditAction,
        operation: str,
        context: RequestContext | None,
    ) -> JobApplication:
        """Load an application the caller may manage, or 404.

        There is no organization in this path, so authorisation cannot be a separate
        question asked after the row is found: a 403 here would tell a caller with
        no membership that the id they guessed is real. Scoping the lookup by the
        caller's job-managing memberships makes "not yours" and "does not exist" the
        same answer.
        """
        managed = self._jobs.managed_organization_ids(actor)
        statement = self._base_query().where(JobApplication.id == application_id)
        statement = (
            statement.join(Job).where(Job.organization_id.in_(managed), Job.deleted_at.is_(None))
            if managed
            else statement.where(false())
        )
        application = self._session.execute(statement).scalar_one_or_none()
        if application is None:
            self._audit.record_durable(
                action=action,
                actor_user_id=actor.id,
                actor_role=actor.role,
                resource_type="job_application",
                resource_id=application_id,
                ip_address=context.ip_address if context else None,
                user_agent=context.user_agent if context else None,
                request_id=context.request_id if context else None,
                outcome="DENIED",
                metadata={"operation": operation},
            )
            raise ApplicationNotFoundError()
        return application

    def _job_open_to_applications(self, job_id: uuid.UUID) -> Job:
        """Load a job a worker may apply to, or refuse.

        A ``DRAFT`` answers 404 rather than a status-specific refusal: an
        unpublished listing is not something a worker is entitled to know exists,
        and a different status code would let one be enumerated.
        """
        job = self._session.execute(
            select(Job)
            .options(selectinload(Job.organization))
            .where(Job.id == job_id, Job.deleted_at.is_(None))
        ).scalar_one_or_none()
        if job is None or job.status == JobStatus.DRAFT.value:
            raise JobNotFoundError()
        if job.is_aggregated or JobSourceType(job.source_type) in EXTERNAL_JOB_SOURCE_TYPES:
            raise JobNotAcceptingApplicationsError(
                "This listing came from another site. Apply there instead."
            )
        status = effective_status(job)
        if status is not JobStatus.OPEN:
            raise JobNotAcceptingApplicationsError(
                JOB_REFUSAL_REASONS.get(status, JobNotAcceptingApplicationsError.public_message)
            )
        return job

    def _idempotent_replay(
        self, *, profile: WorkerProfile, job: Job, payload: ApplicationCreateRequest
    ) -> JobApplication | None:
        """The row a retried ``idempotency_key`` already created, if any.

        This is a retry aid, not the duplicate-application rule: it answers "did my
        own request already succeed?", which is a different question from "has this
        worker already applied?", and the latter is left entirely to the database
        constraint.
        """
        if payload.idempotency_key is None:
            return None
        existing = self._session.execute(
            self._base_query().where(
                JobApplication.worker_profile_id == profile.id,
                JobApplication.idempotency_key == payload.idempotency_key,
            )
        ).scalar_one_or_none()
        if existing is None:
            return None
        if existing.job_id != job.id:
            raise IdempotencyKeyReusedError()
        return existing

    def _notify_withdrawal(self, application: JobApplication) -> None:
        """Tell the employer side. Factual wording, no ranking of workers."""
        job = application.job
        for recipient in self._employer_recipients(job):
            self._notifications.enqueue(
                recipient_user_id=recipient,
                event_type=NotificationEventType.APPLICATION_WITHDRAWN,
                title=f"An application was withdrawn: {job.title}",
                body=f"A worker withdrew their application to {job.title}.",
                related_resource_id=application.id,
                related_resource_type="job_application",
                payload={"job_id": str(job.id), "status": ApplicationStatus.WITHDRAWN.value},
            )

    def _employer_recipients(self, job: Job) -> list[uuid.UUID]:
        """Accounts to tell that an application was withdrawn.

        The employer who posted the job is the addressee. A row with no
        ``created_by_user_id`` - ingested, or written before that column existed -
        falls back to the organization's active OWNERs, because somebody has to be
        able to hear that a candidate withdrew.
        """
        if job.created_by_user_id is not None:
            return [job.created_by_user_id]
        if job.organization_id is None:
            return []
        owners = self._session.execute(
            select(OrganizationMembership.user_id).where(
                OrganizationMembership.organization_id == job.organization_id,
                OrganizationMembership.status == MembershipStatus.ACTIVE.value,
                OrganizationMembership.role == OrganizationRole.OWNER.value,
            )
        ).scalars()
        return list(owners)

    def _count_own(self, conditions: list[ColumnElement[bool]]) -> int:
        return int(
            self._session.execute(
                select(func.count()).select_from(JobApplication).where(*conditions)
            ).scalar_one()
        )

    def _refuse(
        self,
        *,
        action: AuditAction,
        actor: User,
        application: JobApplication,
        context: RequestContext | None,
        metadata: dict[str, object],
        message: str,
    ) -> None:
        """Write the refusal durably, then raise. Never returns."""
        self._audit.record_durable(
            action=action,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="job_application",
            resource_id=application.id,
            ip_address=context.ip_address if context else None,
            user_agent=context.user_agent if context else None,
            request_id=context.request_id if context else None,
            outcome="DENIED",
            metadata=metadata,
        )
        raise InvalidStateTransitionError(message)


#: Statuses that constitute a decision about the candidate, and so record who made
#: it. ``VIEWED`` is not one of them.
_DECISION_STATUSES: frozenset[ApplicationStatus] = frozenset(
    {ApplicationStatus.SHORTLISTED, ApplicationStatus.REJECTED, ApplicationStatus.HIRED}
)

#: Platform roles that may drive an application's employer lifecycle. A caller in
#: any other role is held to :data:`WORKER_TRANSITIONS`.
_EMPLOYER_ROLES: frozenset[str] = frozenset({UserRole.EMPLOYER.value, UserRole.ADMIN.value})


def _adjust_counter(job: Job, delta: int) -> None:
    """Keep ``jobs.application_count`` equal to the live application count.

    A factual counter, not a score: it counts applications the employer is still
    waiting on. It rises when a worker applies and falls when they withdraw, and no
    employer decision moves it - shortlisting, rejecting and hiring all leave the
    application on the job. No client-supplied value can reach it, because no
    request schema has the field.
    """
    job.application_count = max(0, job.application_count + delta)


def _violated_constraint(exc: IntegrityError) -> str | None:
    """The constraint name from the driver diagnostic, if the driver offers one."""
    diag = getattr(getattr(exc, "orig", None), "diag", None)
    name = getattr(diag, "constraint_name", None)
    return str(name) if name else None


def _transition_refusal(
    current: ApplicationStatus, target: ApplicationStatus, *, employer: bool
) -> str:
    """Why a refused transition says no, naming the actual obstruction."""
    if not employer and target is not ApplicationStatus.WITHDRAWN:
        return (
            f"{target.value} is an employer's decision about a candidate. A worker may "
            "only withdraw an application."
        )
    if current is ApplicationStatus.WITHDRAWN:
        return "This application was withdrawn and can no longer change."
    if current is ApplicationStatus.HIRED:
        return "This application resulted in a hire and can no longer change."
    return f"This application cannot move from {current.value} to {target.value}."


__all__ = [
    "EMPLOYER_TRANSITIONS",
    "WORKER_TRANSITIONS",
    "ApplicationNotFoundError",
    "ApplicationService",
    "DuplicateApplicationError",
    "JobNotAcceptingApplicationsError",
]
