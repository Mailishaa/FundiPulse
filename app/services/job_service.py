"""Job listings: employer postings, external listings, and the lifecycle between them.

Three rules shape this module.

**Provenance is decided server-side, never by a client.** A job created through
``/organizations/{id}/jobs`` is a platform job: the organization comes from the
path, the status starts at ``DRAFT``, and ``source_type`` is fixed by the
service. A client cannot name a different source, because the request schema has
no field for it. External listings arrive through ingestion, are never written by
this service, and are only ever *rendered* - with their origin attached and with
no organization.

**Authorisation is membership, scoped into the query.** Every employer-facing
query filters on ``organization_id`` from the path *and* on an active membership
whose role may manage jobs. Organization A cannot read, edit, publish or close
Organization B's listing, and substituting another organization's id matches
nothing.

**Status is deterministic.** ``DRAFT -> OPEN -> CLOSED``, with ``CANCELLED`` and the
derived ``EXPIRED`` as the other outcomes. Only transitions in
:data:`ALLOWED_TRANSITIONS` are legal; anything else is an
:class:`InvalidStateTransitionError` rather than a silent no-op, so a client that
double-taps a button is told the truth instead of handed a stale 200.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
import uuid

from sqlalchemy import Select, and_, delete, func, not_, or_, select
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql.elements import ColumnElement

from app.core.constants import (
    DEFAULT_JOB_CLOSING_DAYS,
    JOB_MANAGING_ORG_ROLES,
    AuditAction,
    EmploymentType,
    ExperienceLevel,
    JobSourceType,
    JobStatus,
    MembershipStatus,
)
from app.core.exceptions import (
    ForbiddenError,
    InvalidStateTransitionError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.models.catalogue import County, Skill
from app.db.models.job import Job, JobSkill
from app.db.models.organization import OrganizationMembership
from app.db.models.user import User
from app.schemas.jobs import JobCreateRequest, JobSkillAssignment, JobUpdateRequest
from app.services.audit_service import AuditService
from app.services.auth_service import RequestContext
from app.services.worker_service import CatalogueEntryNotFoundError, CatalogueService

logger = get_logger(__name__)

#: The lifecycle, declared once. Anything not listed is refused.
#:
#: ``EXPIRED`` is reachable only from ``OPEN`` and only by the deterministic
#: deadline rule in :func:`effective_status`; no route targets it. ``CLOSED`` and
#: ``CANCELLED`` have no successors: a listing that ended has ended, and reopening
#: it would rewrite history a candidate may have applied against.
ALLOWED_TRANSITIONS: dict[JobStatus, frozenset[JobStatus]] = {
    JobStatus.DRAFT: frozenset({JobStatus.OPEN, JobStatus.CANCELLED}),
    JobStatus.OPEN: frozenset({JobStatus.CLOSED, JobStatus.CANCELLED, JobStatus.EXPIRED}),
    JobStatus.CLOSED: frozenset(),
    JobStatus.CANCELLED: frozenset(),
    JobStatus.EXPIRED: frozenset(),
}

#: Why a refused transition says no. A message that says only "not allowed" forces
#: the client to guess; these name the actual obstruction.
REFUSAL_REASONS: dict[JobStatus, str] = {
    JobStatus.DRAFT: "This job is a draft and has never been published.",
    JobStatus.OPEN: "This job is already open.",
    JobStatus.CLOSED: "This job has been closed. Create a new listing instead.",
    JobStatus.CANCELLED: "This job was cancelled. Create a new listing instead.",
    JobStatus.EXPIRED: "This job has expired. Create a new listing instead.",
}


class JobNotFoundError(NotFoundError):
    """No job the caller is allowed to know about."""

    public_message = "No such job was found."


class JobManagementForbiddenError(ForbiddenError):
    """Authenticated, but no job-managing membership in this organization."""

    code = "JOB_MANAGEMENT_FORBIDDEN"
    public_message = "You may not manage this organization's jobs."


class JobStatusFilterForbiddenError(ForbiddenError):
    """A discovery filter for a status the caller is not entitled to see."""

    code = "JOB_STATUS_FILTER_FORBIDDEN"
    public_message = "You may only list open jobs unless you manage the employer."


def effective_status(job: Job, *, now: datetime | None = None) -> JobStatus:
    """The status a client should be told about.

    A job still stored as ``OPEN`` whose closing date has passed is reported as
    ``EXPIRED``. The rule is evaluated server-side on every read, so a listing can
    never be presented as open past its deadline because a sweep has not run yet -
    the sweep only makes the stored row agree with what is already served.
    """
    moment = now or utcnow()
    if (
        job.status == JobStatus.OPEN.value
        and job.closing_at is not None
        and job.closing_at <= moment
    ):
        return JobStatus.EXPIRED
    return JobStatus(job.status)


def lapsed_expression(now: datetime) -> ColumnElement[bool]:
    """SQL form of "stored ``OPEN`` but past its closing date"."""
    return and_(
        Job.status == JobStatus.OPEN.value,
        Job.closing_at.is_not(None),
        Job.closing_at <= now,
    )


class JobService:
    """Reads and employer-driven writes for job listings."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._audit = AuditService(session)
        self._catalogue = CatalogueService(session)

    # -- authorisation ---------------------------------------------------- #

    def managed_organization_ids(self, actor: User | None) -> list[uuid.UUID]:
        """Organizations whose jobs ``actor`` may create and manage.

        Membership, not platform role: an ADMIN account with no membership in an
        organization has no claim on its listings. The alternative - deciding from
        ``user.role`` - would make "who owns this job" answerable from a field that
        says nothing about the relationship.
        """
        if actor is None:
            return []
        roles = [role.value for role in JOB_MANAGING_ORG_ROLES]
        rows = self._session.execute(
            select(OrganizationMembership.organization_id).where(
                OrganizationMembership.user_id == actor.id,
                OrganizationMembership.status == MembershipStatus.ACTIVE.value,
                OrganizationMembership.role.in_(roles),
            )
        ).scalars()
        return list(rows)

    def is_manager(self, *, actor: User | None, organization_id: uuid.UUID | None) -> bool:
        """Membership is the only claim on a job. ``None`` owns nothing."""
        if actor is None or organization_id is None:
            return False
        return organization_id in self.managed_organization_ids(actor)

    def _require_manager(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        action: AuditAction,
        operation: str,
        context: RequestContext | None,
    ) -> None:
        if self.is_manager(actor=actor, organization_id=organization_id):
            return
        # Durable: the refusal must survive the rollback the raised error causes,
        # or a cross-tenant attempt disappears from the record.
        self._audit.record_durable(
            action=action,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="job",
            ip_address=context.ip_address if context else None,
            user_agent=context.user_agent if context else None,
            request_id=context.request_id if context else None,
            outcome="DENIED",
            metadata={"operation": operation, "organization_id": str(organization_id)},
        )
        raise JobManagementForbiddenError()

    def _managed_job(self, *, organization_id: uuid.UUID, job_id: uuid.UUID) -> Job:
        """Load a job scoped by its organization.

        Scoping by both parent and id is what makes a substituted identifier match
        nothing instead of reaching another tenant's row. The failure is a 404, not
        a 403, because a 403 would confirm the job exists.
        """
        job = self._session.execute(
            self._base_query().where(
                Job.id == job_id,
                Job.organization_id == organization_id,
                Job.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if job is None:
            raise JobNotFoundError()
        return job

    # -- employer writes -------------------------------------------------- #

    def create(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        payload: JobCreateRequest,
        context: RequestContext | None = None,
    ) -> Job:
        """Create a ``DRAFT`` platform job owned by the organization in the path."""
        self._require_manager(
            actor=actor,
            organization_id=organization_id,
            action=AuditAction.JOB_CREATED,
            operation="create_job",
            context=context,
        )
        trade = (
            self._catalogue.get_trade_by_code(payload.trade_code) if payload.trade_code else None
        )
        county = self._one_county(payload.county_code)
        resolved = self._resolve_skills(payload.skills)

        job = Job(
            title=payload.title.strip(),
            description=payload.description.strip(),
            trade_id=trade.id if trade is not None else None,
            county_id=county.id if county is not None else None,
            # From the path, never from the body.
            organization_id=organization_id,
            location=payload.location,
            employment_type=payload.employment_type.value,
            experience_level=payload.experience_level.value,
            experience_required_years=payload.experience_required_years,
            salary_min=payload.salary_min,
            salary_max=payload.salary_max,
            salary_currency=payload.salary_currency,
            salary_period=payload.salary_period,
            # Server-controlled. The request schema has no field for either of
            # these, so a client cannot influence provenance or status here.
            status=JobStatus.DRAFT.value,
            source_type=JobSourceType.PLATFORM.value,
            created_by_user_id=actor.id,
            is_aggregated=False,
            # A deterministic close date, so expiry never depends on the client
            # remembering to send one.
            closing_at=payload.closing_at or utcnow() + timedelta(days=DEFAULT_JOB_CLOSING_DAYS),
        )
        self._session.add(job)
        self._session.flush()
        self._replace_skills(job, resolved)

        self._audit.record(
            action=AuditAction.JOB_CREATED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="job",
            resource_id=job.id,
            ip_address=context.ip_address if context else None,
            user_agent=context.user_agent if context else None,
            request_id=context.request_id if context else None,
            outcome="SUCCESS",
            metadata={
                "organization_id": str(organization_id),
                "source_type": job.source_type,
            },
        )
        logger.info(
            "Job created",
            extra={"job_id": str(job.id), "organization_id": str(organization_id)},
        )
        return self._reload(job)

    def update(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        payload: JobUpdateRequest,
        context: RequestContext | None = None,
    ) -> Job:
        """Partial update of an editable listing."""
        self._require_manager(
            actor=actor,
            organization_id=organization_id,
            action=AuditAction.JOB_UPDATED,
            operation="update_job",
            context=context,
        )
        job = self._managed_job(organization_id=organization_id, job_id=job_id)
        data = payload.model_dump(exclude_unset=True)

        if "trade_code" in data:
            code = data.pop("trade_code")
            trade = self._catalogue.get_trade_by_code(code) if code else None
            job.trade_id = trade.id if trade is not None else None
        if "county_code" in data:
            code = data.pop("county_code")
            county = self._one_county(code)
            job.county_id = county.id if county is not None else None
        for field in (
            "title",
            "description",
            "location",
            "experience_required_years",
            "salary_min",
            "salary_max",
            "salary_currency",
            "salary_period",
            "closing_at",
        ):
            if field in data:
                value = data[field]
                setattr(job, field, value.strip() if isinstance(value, str) else value)
        for field in ("employment_type", "experience_level"):
            if field in data:
                value = data[field]
                setattr(job, field, value.value if hasattr(value, "value") else str(value))

        # Resolved before any delete so an unknown code aborts the whole write
        # rather than leaving the employer with a half-replaced requirement.
        replaced_skills = "skills" in data
        resolved = self._resolve_skills(payload.skills) if replaced_skills else []
        if replaced_skills:
            self._replace_skills(job, resolved)

        self._audit.record(
            action=AuditAction.JOB_UPDATED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="job",
            resource_id=job.id,
            ip_address=context.ip_address if context else None,
            user_agent=context.user_agent if context else None,
            request_id=context.request_id if context else None,
            outcome="SUCCESS",
            metadata={
                "organization_id": str(organization_id),
                "fields": sorted(data),
                "skills_replaced": replaced_skills,
            },
        )
        return self._reload(job)

    def publish(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        context: RequestContext | None = None,
    ) -> Job:
        """``DRAFT -> OPEN``. Nothing else may enter ``OPEN``."""
        return self._transition(
            actor=actor,
            organization_id=organization_id,
            job_id=job_id,
            target=JobStatus.OPEN,
            operation="publish_job",
            context=context,
            before_apply=_stamp_published_at,
        )

    def close(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        context: RequestContext | None = None,
    ) -> Job:
        """``OPEN -> CLOSED``.

        Closing an already-closed job is a refusal that says so, not a no-op: a 200
        that quietly changes nothing is indistinguishable from a real transition, so
        a client could never tell that its state assumption was wrong.
        """
        return self._transition(
            actor=actor,
            organization_id=organization_id,
            job_id=job_id,
            target=JobStatus.CLOSED,
            operation="close_job",
            context=context,
            before_apply=_stamp_closed_at,
        )

    def cancel(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        context: RequestContext | None = None,
    ) -> Job:
        """``DRAFT -> CANCELLED`` or ``OPEN -> CANCELLED``.

        A draft that will never be published is cancelled rather than abandoned, so
        the employer can record why. A closed job cannot be cancelled: the closed
        record is the evidence of what happened, and overwriting it loses that.
        """
        return self._transition(
            actor=actor,
            organization_id=organization_id,
            job_id=job_id,
            target=JobStatus.CANCELLED,
            operation="cancel_job",
            context=context,
        )

    # -- reads ------------------------------------------------------------ #

    def list_for_organization(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        status: JobStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[Job], int]:
        """Every listing this organization owns, drafts included.

        Refuses a caller without a job-managing membership: the drafts in this list
        are not public information.
        """
        if not self.is_manager(actor=actor, organization_id=organization_id):
            raise JobManagementForbiddenError()

        now = utcnow()
        conditions: list[ColumnElement[bool]] = [
            Job.organization_id == organization_id,
            Job.deleted_at.is_(None),
        ]
        if status is not None:
            conditions.append(self._status_condition(status, managed=[organization_id], now=now))

        total = int(
            self._session.execute(
                select(func.count()).select_from(Job).where(*conditions)
            ).scalar_one()
        )
        statement = (
            self._base_query()
            .where(*conditions)
            .order_by(Job.created_at.desc(), Job.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    def discover(
        self,
        *,
        viewer: User | None = None,
        trade_code: str | None = None,
        skill_codes: list[str] | None = None,
        county_code: str | None = None,
        location: str | None = None,
        employment_type: EmploymentType | None = None,
        experience_level: ExperienceLevel | None = None,
        source_type: JobSourceType | None = None,
        status: JobStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[Job], int]:
        """Public job search.

        Visibility is the important part. A caller who manages no organization sees
        ``OPEN`` listings only. A caller who manages one also sees that
        organization's own drafts, closed and cancelled listings - and nothing
        belonging to any other employer. A non-``OPEN`` ``status`` filter is
        refused outright rather than quietly downgraded to an empty page, so a
        client never concludes an employer has no listings when it simply may not
        look.
        """
        now = utcnow()
        managed = self.managed_organization_ids(viewer)
        conditions: list[ColumnElement[bool]] = [Job.deleted_at.is_(None)]

        if status is None:
            conditions.append(not_(lapsed_expression(now)))
            conditions.append(_visibility_condition(managed))
        else:
            conditions.append(self._status_condition(status, managed=managed, now=now))

        if trade_code is not None:
            conditions.append(Job.trade_id == self._catalogue.get_trade_by_code(trade_code).id)
        county = self._one_county(county_code)
        if county is not None:
            conditions.append(Job.county_id == county.id)
        if location:
            conditions.append(Job.location.ilike(_like_pattern(location), escape="\\"))
        if employment_type is not None:
            conditions.append(Job.employment_type == employment_type.value)
        if experience_level is not None:
            conditions.append(Job.experience_level == experience_level.value)
        if source_type is not None:
            conditions.append(Job.source_type == source_type.value)
        if skill_codes:
            conditions.append(Job.id.in_(self._skill_job_ids(skill_codes)))

        total = int(
            self._session.execute(
                select(func.count()).select_from(Job).where(*conditions)
            ).scalar_one()
        )
        statement = (
            self._base_query()
            .where(*conditions)
            .order_by(Job.published_at.desc().nulls_last(), Job.created_at.desc(), Job.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(statement).scalars()), total

    def get_visible(self, *, job_id: uuid.UUID, viewer: User | None = None) -> Job:
        """Read one listing, or 404.

        A ``DRAFT`` is returned only to a job-managing member of the organization
        that owns it. Everyone else - anonymous, a worker, a member of a different
        organization - gets the same 404, so a draft cannot be enumerated by
        watching for a different status code.
        """
        job = self._session.execute(
            self._base_query().where(Job.id == job_id, Job.deleted_at.is_(None))
        ).scalar_one_or_none()
        if job is None:
            raise JobNotFoundError()
        if job.status == JobStatus.DRAFT.value and not self.is_manager(
            actor=viewer, organization_id=job.organization_id
        ):
            raise JobNotFoundError()
        return job

    def load_counties(self, jobs: list[Job]) -> dict[uuid.UUID, County]:
        """Resolve every referenced county in one query rather than one per row."""
        ids = {job.county_id for job in jobs if job.county_id is not None}
        if not ids:
            return {}
        rows = self._session.execute(select(County).where(County.id.in_(ids))).scalars()
        return {county.id: county for county in rows}

    # -- internals --------------------------------------------------------- #

    def _base_query(self) -> Select[tuple[Job]]:
        """One eager-load shape for every read, so nothing N+1s on skills."""
        return select(Job).options(
            selectinload(Job.skills).selectinload(JobSkill.skill),
            selectinload(Job.organization),
            selectinload(Job.source),
            selectinload(Job.trade),
        )

    def _reload(self, job: Job) -> Job:
        """Re-read with the eager loads the response schema needs."""
        self._session.expire(job, ["skills", "organization", "source", "trade"])
        return self._session.execute(self._base_query().where(Job.id == job.id)).scalar_one()

    def _status_condition(
        self,
        status: JobStatus,
        *,
        managed: list[uuid.UUID] | None = None,
        now: datetime | None = None,
    ) -> ColumnElement[bool]:
        """Match ``status`` as the caller is told it, not as it is stored.

        ``OPEN`` is public and excludes listings past their closing date. Every other
        status is scoped to the organizations the caller manages, and refused
        outright when they manage none - a worker filtering for ``CLOSED`` learns
        nothing rather than being handed another employer's pipeline. ``EXPIRED``
        additionally matches a listing still stored as ``OPEN``, so the answer does
        not depend on whether a sweep has run.
        """
        moment = now or utcnow()
        lapsed = lapsed_expression(moment)
        if status is JobStatus.OPEN:
            return and_(Job.status == status.value, not_(lapsed))
        owners = managed or []
        if not owners:
            raise JobStatusFilterForbiddenError()
        matches: ColumnElement[bool] = Job.status == status.value
        if status is JobStatus.EXPIRED:
            matches = or_(matches, lapsed)
        return and_(Job.organization_id.in_(owners), matches)

    def _transition(
        self,
        *,
        actor: User,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        target: JobStatus,
        operation: str,
        context: RequestContext | None,
        before_apply: Callable[[Job], None] | None = None,
    ) -> Job:
        self._require_manager(
            actor=actor,
            organization_id=organization_id,
            action=AuditAction.JOB_STATUS_CHANGED,
            operation=operation,
            context=context,
        )
        job = self._managed_job(organization_id=organization_id, job_id=job_id)
        current = JobStatus(job.status)
        if target not in ALLOWED_TRANSITIONS.get(current, frozenset()):
            self._audit.record_durable(
                action=AuditAction.JOB_STATUS_CHANGED,
                actor_user_id=actor.id,
                actor_role=actor.role,
                resource_type="job",
                resource_id=job.id,
                ip_address=context.ip_address if context else None,
                user_agent=context.user_agent if context else None,
                request_id=context.request_id if context else None,
                outcome="DENIED",
                metadata={
                    "operation": operation,
                    "previous_status": current.value,
                    "requested_status": target.value,
                },
            )
            raise InvalidStateTransitionError(REFUSAL_REASONS[current])

        if before_apply is not None:
            before_apply(job)
        job.status = target.value
        self._session.flush()
        self._audit.record(
            action=AuditAction.JOB_STATUS_CHANGED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type="job",
            resource_id=job.id,
            ip_address=context.ip_address if context else None,
            user_agent=context.user_agent if context else None,
            request_id=context.request_id if context else None,
            outcome="SUCCESS",
            metadata={
                "operation": operation,
                "previous_status": current.value,
                "new_status": target.value,
                "organization_id": str(organization_id),
            },
        )
        logger.info(
            "Job status changed",
            extra={
                "job_id": str(job.id),
                "previous_status": current.value,
                "new_status": target.value,
            },
        )
        return self._reload(job)

    def _one_county(self, code: str | None) -> County | None:
        if not code:
            return None
        county = self._catalogue.get_counties_by_codes([code]).get(code.upper())
        if county is None:
            raise CatalogueEntryNotFoundError(f"Unknown county code: {code}")
        return county

    def _resolve_skills(self, skills: list[JobSkillAssignment]) -> list[Skill]:
        """Resolve every skill code, naming the unknown ones."""
        if not skills:
            return []
        codes = [assignment.skill_code for assignment in skills]
        resolved = self._catalogue.get_skills_by_codes(codes)
        missing = sorted({code.upper() for code in codes if code.upper() not in resolved})
        if missing:
            raise CatalogueEntryNotFoundError("Unknown skill code(s): " + ", ".join(missing))
        return [resolved[assignment.skill_code.upper()] for assignment in skills]

    def _skill_job_ids(self, skill_codes: list[str]) -> Select[tuple[uuid.UUID]]:
        """Jobs requiring *any* of the given skills."""
        resolved = self._catalogue.get_skills_by_codes(skill_codes)
        missing = sorted({code.upper() for code in skill_codes if code.upper() not in resolved})
        if missing:
            raise CatalogueEntryNotFoundError("Unknown skill code(s): " + ", ".join(missing))
        return select(JobSkill.job_id).where(
            JobSkill.skill_id.in_([skill.id for skill in resolved.values()])
        )

    def _replace_skills(self, job: Job, resolved: list[Skill]) -> None:
        """Delete then insert, inside the caller's transaction.

        Replacing the list rather than merging it is what makes the update atomic.
        A skill that is kept and re-added - the overwhelmingly common case - would
        collide with ``uq_job_skills_job_skill`` on the way in while the old rows
        were still present, so an employer fixing one requirement would be told
        their job is invalid when it is not. The delete is flushed before the
        inserts so the two statements cannot interleave.
        """
        self._session.execute(delete(JobSkill).where(JobSkill.job_id == job.id))
        self._session.flush()
        for skill in resolved:
            self._session.add(JobSkill(job_id=job.id, skill_id=skill.id, is_required=True))
        self._session.flush()
        self._session.expire(job, ["skills"])


def _visibility_condition(managed: list[uuid.UUID]) -> ColumnElement[bool]:
    """Open listings for everyone, plus the caller's own organizations."""
    if managed:
        return or_(Job.status == JobStatus.OPEN.value, Job.organization_id.in_(managed))
    return Job.status == JobStatus.OPEN.value


def _stamp_published_at(job: Job) -> None:
    """Publication guards, then the timestamp.

    The closing date is re-checked here rather than trusted from creation: a draft
    can sit for weeks, and publishing it would open a listing that is already past
    its own deadline.
    """
    if job.closing_at is not None and job.closing_at <= utcnow():
        raise ValidationError(
            "This job's closing date has already passed. Set a future closing_at "
            "before publishing it.",
            code="JOB_CLOSING_DATE_PASSED",
        )
    job.published_at = utcnow()


def _stamp_closed_at(job: Job) -> None:
    job.closed_at = utcnow()


def _like_pattern(value: str) -> str:
    """Escape LIKE wildcards so a search for ``100%`` is not a prefix match."""
    escaped = value.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


__all__ = [
    "ALLOWED_TRANSITIONS",
    "JobManagementForbiddenError",
    "JobNotFoundError",
    "JobService",
    "JobStatusFilterForbiddenError",
    "effective_status",
]
