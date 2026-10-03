"""Moderation reports: raising them, scoping who may read them, and closing them.

Three invariants live here, and nowhere else in the code may relax them.

**1. A report belongs to the reporter.**
:meth:`ReportService.list_own` and :meth:`ReportService.get_own` scope every
query by ``reporter_user_id == caller.id``. Substituting another account's id
into the path therefore matches nothing and yields ``404`` - not ``403``, because
a ``403`` would confirm the report exists to someone who should not know.
Administrators read reports through a different service method entirely, reached
from a different router.

**2. Filing a report is not an existence oracle.**
``subject_id`` is a UUID shared by four heterogeneous tables, so the service must
load the row before it accepts the report - and that check would otherwise turn
``POST /reports`` into a way to ask "does this private passport id exist?". The
rule is therefore one *indistinguishable* answer: a subject the reporter is not
entitled to see, and a subject that does not exist, produce the same ``404`` with
the same code and the same message. Only a subject the reporter could already have
read through its own endpoint is reportable.

**3. A reporter never reports their own content.**
Refused per subject type: a worker's own passport, an organization they are a
member of, a job they posted, and a verification they personally attested. The one
deliberate exception is a verification *of the reporter's own claim*: a forged
attestation attributed to them is abuse worth reporting, and refusing it would
make forgery unreportable.

Reports are never deleted. Not by the reporter (there is no delete route at all),
and not by an administrator, who closes one by resolving, dismissing or escalating
it. Preserving the row is what makes a moderation decision reviewable afterwards.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any
import uuid

from sqlalchemy import Select, and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.core.constants import (
    AuditAction,
    NotificationEventType,
    ProfileVisibility,
    ReportStatus,
    ReportSubjectType,
    UserRole,
)
from app.core.exceptions import (
    ConflictError,
    ForbiddenError,
    InsufficientRoleError,
    InvalidStateTransitionError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models.job import Job
from app.db.models.moderation import NotificationEvent, Report
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.user import User
from app.db.models.verification import Verification
from app.db.models.worker import WorkerProfile
from app.schemas.reports import (
    TERMINAL_DECISIONS,
    ReportCreateRequest,
    ReportDecision,
    ReportDecisionRequest,
)
from app.services.audit_service import AuditService
from app.services.auth_service import RequestContext

logger = get_logger(__name__)

#: Subject types a report may be filed against.
#:
#: ``ORGANIZATION`` is the product's "employer": one account is never assumed to
#: equal one company, so an employer is an organization and its members are found
#: through memberships. ``USER`` is deliberately absent: an account is not content,
#: and account-level abuse is handled by suspending the account
#: (``PATCH /users/{id}/status``), which is separately audited.
REPORTABLE_SUBJECT_TYPES: frozenset[ReportSubjectType] = frozenset(
    {
        ReportSubjectType.WORKER_PROFILE,
        ReportSubjectType.ORGANIZATION,
        ReportSubjectType.JOB,
        ReportSubjectType.VERIFICATION,
    }
)

#: The status each administrator decision lands on.
_STATUS_BY_DECISION: dict[ReportDecision, ReportStatus] = {
    ReportDecision.REVIEW: ReportStatus.IN_REVIEW,
    ReportDecision.RESOLVE: ReportStatus.RESOLVED,
    ReportDecision.DISMISS: ReportStatus.DISMISSED,
    ReportDecision.ESCALATE: ReportStatus.ACTIONED,
}

#: Decisions that may be taken from each status. Absent keys are terminal statuses:
#: a closed report is immutable, so re-opening one cannot erase the record of how
#: it was previously closed.
_ALLOWED_DECISIONS: dict[ReportStatus, frozenset[ReportDecision]] = {
    ReportStatus.OPEN: frozenset(ReportDecision),
    ReportStatus.IN_REVIEW: frozenset(
        {
            ReportDecision.RESOLVE,
            ReportDecision.DISMISS,
            ReportDecision.ESCALATE,
        }
    ),
    ReportStatus.RESOLVED: frozenset(),
    ReportStatus.DISMISSED: frozenset(),
    ReportStatus.ACTIONED: frozenset(),
}

#: Minimum length of the note attached to a closing decision.
MIN_DECISION_NOTE_LENGTH = 5

_SUBJECT_RESOURCE_TYPE = "report"


# --------------------------------------------------------------------------- #
# Errors                                                                      #
# --------------------------------------------------------------------------- #
class ReportSubjectNotFoundError(NotFoundError):
    """The subject is missing, or the reporter may not know that it exists.

    The message is inherited verbatim from :class:`~app.core.exceptions.NotFoundError`
    on purpose. A report must not be usable to discover which passport ids, jobs
    or verifications exist, so this is byte-for-byte the response to a subject that
    genuinely does not exist and to one the reporter is not entitled to see.
    """


class UnreportableSubjectTypeError(ValidationError):
    """The subject type is a valid enum member but not something reportable."""

    public_message = "That kind of record cannot be reported."


class SelfReportBlockedError(ForbiddenError):
    """A reporter tried to report their own content."""

    code = "SELF_REPORT_BLOCKED"
    public_message = "You cannot report your own content."


class DuplicateReportError(ConflictError):
    """One report per reporter per subject, already filed."""

    code = "DUPLICATE_REPORT"
    public_message = "You have already reported this."


# --------------------------------------------------------------------------- #
# Service                                                                     #
# --------------------------------------------------------------------------- #
class ReportService:
    """Raise, read and adjudicate moderation reports."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._audit = AuditService(session)
        # Dispatch by subject type rather than a chain of comparisons: a new
        # reportable type is then one entry here, and an unreviewed one cannot fall
        # through to a permissive default.
        self._subject_checks: dict[ReportSubjectType, Callable[[User, uuid.UUID], None]] = {
            ReportSubjectType.WORKER_PROFILE: self._check_worker_profile,
            ReportSubjectType.ORGANIZATION: self._check_organization,
            ReportSubjectType.JOB: self._check_job,
            ReportSubjectType.VERIFICATION: self._check_verification,
        }

    # -- writing ---------------------------------------------------------- #

    def file_report(
        self,
        *,
        reporter: User,
        payload: ReportCreateRequest,
        context: RequestContext | None = None,
    ) -> Report:
        """Raise a report. **Any authenticated user.**

        Order matters. The subject is validated first, so a report can never be
        filed against an id that does not exist, and can never be filed against
        something the reporter is not allowed to know about. Only then is the row
        written.
        """
        ctx = context or RequestContext()
        self._assert_subject_reportable(
            reporter=reporter, subject_type=payload.subject_type, subject_id=payload.subject_id
        )

        report = Report(
            reporter_user_id=reporter.id,
            subject_type=payload.subject_type.value,
            subject_id=payload.subject_id,
            reason=payload.reason.value,
            details=payload.details,
            status=ReportStatus.OPEN.value,
        )
        self._session.add(report)
        try:
            self._session.flush()
        except IntegrityError as exc:
            # The unique constraint is the guarantee (ADR 0009), not this
            # application-level path: two concurrent identical reports race past
            # any pre-check and the database refuses the second one. Rolling back
            # is the caller's business - `get_db` does it for the request - and
            # doing it here would discard the caller's unrelated pending work.
            raise DuplicateReportError() from exc

        self._enqueue_outbox_event(report=report, reporter=reporter)
        self._audit.record(
            action=AuditAction.CONTENT_REPORTED,
            actor_user_id=reporter.id,
            actor_role=reporter.role,
            resource_type=_SUBJECT_RESOURCE_TYPE,
            resource_id=report.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            # Deliberately minimal. The report body is free text and is exactly the
            # kind of personal data an audit row must not accumulate; the subject
            # id is already on the report, and the reporter is already the actor.
            metadata={
                "operation": "report_filed",
                "subject_type": payload.subject_type.value,
                "reason": payload.reason.value,
                "has_details": bool((payload.details or "").strip()),
            },
        )
        logger.info(
            "Report filed",
            extra={
                "report_id": str(report.id),
                "subject_type": payload.subject_type.value,
                "subject_id": str(payload.subject_id),
            },
        )
        return report

    # -- reads ------------------------------------------------------------ #

    def list_own(
        self,
        *,
        reporter: User,
        status: ReportStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[Sequence[Report], int]:
        """The caller's own reports, newest first. **Every role, including admin.**

        The scope is the caller's own rows for *everyone*. Widening it for
        administrators on this route would make "a report is readable only by its
        reporter" untrue of the URL a client reaches by accident; administrators
        read the moderation queue through ``list_all`` instead, where the
        authorisation boundary is visible in the path.
        """
        conditions: list[ColumnElement[bool]] = [Report.reporter_user_id == reporter.id]
        if status is not None:
            conditions.append(Report.status == status.value)
        return self._page(conditions, limit=limit, offset=offset)

    def get_own(self, *, reporter: User, report_id: uuid.UUID) -> Report:
        """One of the caller's own reports, or ``404``.

        The reporter scope is part of the query rather than a check afterwards, so
        another account's report id simply matches nothing.
        """
        report = self._session.execute(
            select(Report).where(
                Report.id == report_id,
                Report.reporter_user_id == reporter.id,
            )
        ).scalar_one_or_none()
        if report is None:
            raise NotFoundError("The requested report was not found.")
        return report

    def list_all(
        self,
        *,
        actor: User,
        status: ReportStatus | None = None,
        subject_type: ReportSubjectType | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[Sequence[Report], int]:
        """The moderation queue. **Administrator only.**

        Filters are typed parameters, never a generic filter expression: there is
        no ``?filter=`` escape hatch, because that is how an unvalidated field name
        reaches a ``WHERE`` clause.
        """
        self._require_admin(actor)
        conditions: list[ColumnElement[bool]] = []
        if status is not None:
            conditions.append(Report.status == status.value)
        if subject_type is not None:
            conditions.append(Report.subject_type == subject_type.value)
        return self._page(conditions, limit=limit, offset=offset)

    # -- adjudication ------------------------------------------------------ #

    def decide(
        self,
        *,
        actor: User,
        report_id: uuid.UUID,
        payload: ReportDecisionRequest,
        context: RequestContext | None = None,
    ) -> Report:
        """Record an administrator's decision on a report. **Administrator only.**

        A client names an *intent* (:class:`~app.schemas.reports.ReportDecision`),
        not a status. The status is derived here, from a transition table, so a
        caller cannot reach a state the machine never intended to allow.
        """
        ctx = context or RequestContext()
        self._require_admin(actor)

        report = self._session.execute(
            select(Report).where(Report.id == report_id).with_for_update()
        ).scalar_one_or_none()
        if report is None:
            raise NotFoundError("The requested report was not found.")

        current = ReportStatus(report.status)
        allowed = _ALLOWED_DECISIONS[current]
        if payload.decision not in allowed:
            raise InvalidStateTransitionError(
                f"A {current.value} report cannot be {payload.decision.value.lower()}ed."
            )

        note = (payload.note or "").strip() or None
        if payload.decision in TERMINAL_DECISIONS and (
            note is None or len(note) < MIN_DECISION_NOTE_LENGTH
        ):
            raise ValidationError("A note of at least 5 characters is required to close a report.")

        previous = current
        target = _STATUS_BY_DECISION[payload.decision]
        report.status = target.value
        report.resolved_by_user_id = actor.id
        report.resolution_note = note
        if payload.decision in TERMINAL_DECISIONS:
            # Only a closing decision stamps a resolution time; being picked up for
            # review is not a resolution.
            report.resolved_at = utcnow()
        self._session.flush()

        self._audit.record(
            action=_AUDIT_ACTION_BY_DECISION[payload.decision],
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type=_SUBJECT_RESOURCE_TYPE,
            resource_id=report.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
            outcome="SUCCESS",
            # The note itself stays on the report row, which is the durable record
            # of the decision. Putting free text in audit metadata as well would
            # duplicate it into a second table that outlives the report's own
            # retention decisions.
            metadata={
                "operation": f"report_{payload.decision.value.lower()}",
                "previous_status": previous.value,
                "new_status": target.value,
                "subject_type": report.subject_type,
                "reason": report.reason,
                "has_note": note is not None,
            },
        )
        logger.info(
            "Report adjudicated",
            extra={
                "report_id": str(report.id),
                "decision": payload.decision.value,
                "new_status": target.value,
            },
        )
        return report

    # -- subject rules ------------------------------------------------------ #

    def _assert_subject_reportable(
        self, *, reporter: User, subject_type: ReportSubjectType, subject_id: uuid.UUID
    ) -> None:
        """Confirm the subject exists, is visible to ``reporter``, and is not theirs."""
        check = self._subject_checks.get(subject_type)
        if check is None:
            raise UnreportableSubjectTypeError()
        check(reporter, subject_id)

    def _check_worker_profile(self, reporter: User, subject_id: uuid.UUID) -> None:
        profile = self._session.execute(
            select(WorkerProfile).where(
                WorkerProfile.id == subject_id,
                WorkerProfile.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if profile is None:
            raise ReportSubjectNotFoundError()
        if profile.user_id == reporter.id:
            raise SelfReportBlockedError()
        # A private passport is invisible to everyone but its owner and
        # administrators, so filing a report against one must answer exactly what
        # reporting a non-existent id answers. Reporting is not a way to become
        # able to see it.
        if profile.visibility == ProfileVisibility.PRIVATE.value and not _is_admin(reporter):
            raise ReportSubjectNotFoundError()

    def _check_organization(self, reporter: User, subject_id: uuid.UUID) -> None:
        row = self._session.execute(
            select(Organization, OrganizationMembership.user_id)
            .outerjoin(OrganizationMembership, _membership_of(Organization.id, reporter.id))
            .where(Organization.id == subject_id, Organization.deleted_at.is_(None))
        ).one_or_none()
        if row is None:
            raise ReportSubjectNotFoundError()
        _, membership_user_id = row
        if membership_user_id is not None:
            raise SelfReportBlockedError()

    def _check_job(self, reporter: User, subject_id: uuid.UUID) -> None:
        row = self._session.execute(
            select(Job, OrganizationMembership.user_id)
            .outerjoin(OrganizationMembership, _membership_of(Job.organization_id, reporter.id))
            .where(Job.id == subject_id, Job.deleted_at.is_(None))
        ).one_or_none()
        if row is None:
            raise ReportSubjectNotFoundError()
        job, membership_user_id = row
        # A draft listing has never been seen by anyone, so it is not reportable -
        # for the same reason a private passport is not: it would be an existence
        # oracle for unpublished content.
        if job.published_at is None:
            raise ReportSubjectNotFoundError()
        # Either the reporter posted the listing, or they belong to the employer
        # that owns it. Both are their own content.
        if job.created_by_user_id == reporter.id or membership_user_id is not None:
            raise SelfReportBlockedError()

    def _check_verification(self, reporter: User, subject_id: uuid.UUID) -> None:
        row = self._session.execute(
            select(Verification, WorkerProfile.user_id)
            .join(WorkerProfile, WorkerProfile.id == Verification.worker_profile_id)
            .where(Verification.id == subject_id)
        ).one_or_none()
        if row is None:
            raise ReportSubjectNotFoundError()
        verification, passport_owner_id = row
        # A verification is evidence about a named third party, not public content.
        # Only the parties who already know about it - the worker whose claim it
        # covers, whoever asked for it, and the person who attested it - may report
        # it; for anyone else the answer must be the same as for an id that does not
        # exist.
        participants = {
            verification.requested_by_user_id,
            passport_owner_id,
            verification.verified_by_user_id,
        }
        if not _is_admin(reporter) and reporter.id not in participants:
            raise ReportSubjectNotFoundError()
        if verification.verified_by_user_id == reporter.id:
            # A worker reporting a verification of their *own* claim is allowed
            # above and refused here only if they personally attested it.
            raise SelfReportBlockedError()

    # -- helpers ------------------------------------------------------------ #

    def _page(
        self, conditions: list[ColumnElement[bool]], *, limit: int, offset: int
    ) -> tuple[Sequence[Report], int]:
        total = int(
            self._session.execute(
                select(func.count()).select_from(Report).where(*conditions)
            ).scalar_one()
        )
        statement: Select[tuple[Report]] = (
            select(Report)
            .where(*conditions)
            # Newest first, id last so paging cannot skip or repeat a row.
            .order_by(Report.created_at.desc(), Report.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    def _require_admin(self, actor: User) -> None:
        """Re-assert the role in the service, not only in the route dependency."""
        if not _is_admin(actor):
            raise InsufficientRoleError("This action requires administrator privileges.")

    def _enqueue_outbox_event(self, *, report: Report, reporter: User) -> None:
        """Append a ``CONTENT_REPORTED`` event for a future delivery worker.

        The outbox, not a message: nothing is sent here and no endpoint dispenses
        with SMS or WhatsApp. The recipient is the *reporter* - "we received your
        report" - never the reported subject, because telling someone they have
        been reported turns the feature into a way to harass them. The payload
        carries the report id, the subject type and the reason, and nothing else:
        no free text, no contact details, no document data.
        """
        self._session.add(
            NotificationEvent(
                event_type=NotificationEventType.CONTENT_REPORTED.value,
                user_id=reporter.id,
                payload={
                    "report_id": str(report.id),
                    "subject_type": report.subject_type,
                    "reason": report.reason,
                },
                created_at=utcnow(),
            )
        )
        self._session.flush()


#: Audit action recorded for each decision. ``REPORT_RESOLVED`` is the existing
#: canonical action for a report that was upheld; reviewing, dismissing and
#: escalating have no dedicated member yet, so they record ``ADMIN_ACTION`` with
#: the decision named in ``metadata["operation"]``. Widening
#: :class:`~app.core.constants.AuditAction` with ``REPORT_REVIEWED``,
#: ``REPORT_DISMISSED`` and ``REPORT_ESCALATED`` would make those three greppable
#: by action alone; it needs a migration, because ``audit_logs.action`` is
#: CHECK-constrained.
_AUDIT_ACTION_BY_DECISION: dict[ReportDecision, AuditAction] = {
    ReportDecision.REVIEW: AuditAction.ADMIN_ACTION,
    ReportDecision.RESOLVE: AuditAction.REPORT_RESOLVED,
    ReportDecision.DISMISS: AuditAction.ADMIN_ACTION,
    ReportDecision.ESCALATE: AuditAction.ADMIN_ACTION,
}


def _is_admin(actor: User) -> bool:
    return actor.role == UserRole.ADMIN.value


def _membership_of(organization_id: Any, user_id: uuid.UUID) -> ColumnElement[bool]:
    """Join condition matching a membership of ``user_id`` in that organization.

    Used as an **outer** join so the subject row survives whether or not the
    reporter belongs to it; the null membership column is the "not a member"
    answer, which keeps the self-report check to one query and one comparison.
    """
    return and_(
        OrganizationMembership.organization_id == organization_id,
        OrganizationMembership.user_id == user_id,
    )
