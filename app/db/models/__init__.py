"""ORM model package.

Every model is imported here so that ``Base.metadata`` is complete and Alembic's
autogenerate sees the whole schema. Order is irrelevant for correctness but is
grouped by domain for readability.
"""

from __future__ import annotations

from app.db.base import Base, install_enum_checks
from app.db.models.audit import AuditLog
from app.db.models.catalogue import County, Skill, Trade
from app.db.models.file import FileObject
from app.db.models.job import Job, JobApplication, JobSkill, JobSource, JobSourceEvent
from app.db.models.mixins import SoftDeleteMixin, VersionMixin
from app.db.models.moderation import NotificationEvent, Report
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.user import RefreshSession, SecurityToken, User
from app.db.models.verification import Verification, VerificationRequest
from app.db.models.worker import (
    Credential,
    EvidenceItem,
    Project,
    WorkerPreferredCounty,
    WorkerProfile,
    WorkerReference,
    WorkerSkill,
    WorkerTrade,
    WorkExperience,
)

# Derive a CHECK constraint for every enum-typed column now that the metadata is
# complete. Doing it here (rather than in each model) means a new enum column
# is constrained by construction rather than by remembering to add it.
install_enum_checks(Base.metadata)

__all__ = [
    "AuditLog",
    "County",
    "Credential",
    "EvidenceItem",
    "FileObject",
    "Job",
    "JobApplication",
    "JobSkill",
    "JobSource",
    "JobSourceEvent",
    "NotificationEvent",
    "Organization",
    "OrganizationMembership",
    "Project",
    "RefreshSession",
    "Report",
    "SecurityToken",
    "Skill",
    "SoftDeleteMixin",
    "Trade",
    "User",
    "Verification",
    "VerificationRequest",
    "VersionMixin",
    "WorkExperience",
    "WorkerPreferredCounty",
    "WorkerProfile",
    "WorkerReference",
    "WorkerSkill",
    "WorkerTrade",
]
