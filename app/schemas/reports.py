"""Report schemas: what a reporter may say, and what an administrator may decide.

Three things are structural rather than conventional here.

**No moderation field is settable by a reporter.** :class:`ReportCreateRequest`
carries ``subject_type``, ``subject_id``, ``reason`` and ``details``. It does not
carry ``status``, ``resolution_note``, ``resolved_by_user_id`` or an outcome, and
because :class:`~app.schemas.common.RequestSchema` forbids extras, a client that
sends any of them gets a ``422`` instead of quietly deciding the outcome of its
own report. The reporter's authority stops at *raising* a report.

**No reporter identity is settable at all.** A report belongs to the authenticated
caller, so there is no ``reporter_user_id`` field; accepting one would be an IDOR.

**No admin response schema can carry the reporter's contact details.**
:class:`AdminReportResponse` has no email, phone, name or display-name field, so
the guarantee is in the type rather than in a reviewer's memory. The reporter is
identified by :attr:`AdminReportResponse.reporter_ref`, a stable pseudonym, which
is enough to spot one account being reported repeatedly and not enough to reach
the reporter's account.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
import uuid

from pydantic import Field, model_validator

from app.core.constants import (
    MAX_NOTES_LENGTH,
    MAX_SHORT_TEXT,
    ReportReason,
    ReportStatus,
    ReportSubjectType,
)
from app.schemas.common import RequestSchema, TimestampMixinSchema


class ReportDecision(StrEnum):
    """What an administrator is asking for, as an intent rather than a status.

    The wire contract is a *decision*, never a ``status``: sending
    ``{"status": "RESOLVED"}`` would let a client pick any state of the machine,
    including the ones this API never intends a client to name. The service maps a
    decision onto exactly one :class:`~app.core.constants.ReportStatus` and
    refuses any transition that is not allowed from the report's current state.

    It lives here rather than in :mod:`app.core.constants` because it is a command
    and is never persisted: the stored vocabulary is ``ReportStatus``, which *is*
    database-CHECK-constrained. Adding a member here needs no migration, which is
    exactly right for something with no column behind it.
    """

    #: Take ownership of the report; it is being looked into.
    REVIEW = "REVIEW"
    #: The report was justified and the subject was dealt with.
    RESOLVE = "RESOLVE"
    #: The report was not justified; the subject stands.
    DISMISS = "DISMISS"
    #: A separate action was taken against the subject (e.g. an account suspended).
    ESCALATE = "ESCALATE"


#: Decisions that close a report. Each one must carry a note.
TERMINAL_DECISIONS: frozenset[ReportDecision] = frozenset(
    {ReportDecision.RESOLVE, ReportDecision.DISMISS, ReportDecision.ESCALATE}
)


# --------------------------------------------------------------------------- #
# Requests                                                                    #
# --------------------------------------------------------------------------- #
class ReportCreateRequest(RequestSchema):
    """Raise a report against a work passport, an employer, a job or a verification.

    ``subject_id`` is a UUID across four heterogeneous tables, so it is validated
    for *shape* here and for *meaning* in the service: the service confirms the row
    exists and that the reporter is entitled to see it. Nothing else in this
    schema can put a state on a report.
    """

    subject_type: ReportSubjectType = Field(
        description=(
            "Which kind of record is being reported. Not every enum member is "
            "reportable; an unlisted type is refused with 422."
        )
    )
    subject_id: uuid.UUID = Field(description="The id of the reported record.")
    reason: ReportReason = Field(description="Why the subject is being reported.")
    details: str | None = Field(
        default=None,
        max_length=MAX_NOTES_LENGTH,
        description=(
            "Optional free text. Mandatory when the reason is OTHER, because an "
            "'other' report with no explanation is not actionable."
        ),
    )

    @model_validator(mode="after")
    def _other_requires_details(self) -> ReportCreateRequest:
        """An OTHER report must say what the problem is."""
        if self.reason is ReportReason.OTHER and not (self.details or "").strip():
            raise ValueError("A report with reason OTHER must include details.")
        if self.details is not None and not self.details.strip():
            raise ValueError("details must not be blank.")
        return self


class ReportDecisionRequest(RequestSchema):
    """An administrator's decision on a report.

    Forbids extras, so ``status``, ``resolution_note``, ``resolved_by_user_id`` and
    ``outcome`` are all refused rather than applied. The decision vocabulary is
    narrower than :class:`~app.core.constants.ReportStatus` on purpose.
    """

    decision: ReportDecision = Field(description="REVIEW, RESOLVE, DISMISS or ESCALATE.")
    note: str | None = Field(
        default=None,
        max_length=MAX_SHORT_TEXT,
        description=(
            "Why the subject was (or was not) actioned. Mandatory - at least five "
            "characters - for RESOLVE, DISMISS and ESCALATE: 'why was this dismissed' "
            "must be answerable months later. Optional for REVIEW."
        ),
    )


# --------------------------------------------------------------------------- #
# Responses                                                                   #
# --------------------------------------------------------------------------- #
class ReportResponse(TimestampMixinSchema):
    """A report as its own reporter sees it.

    Deliberately omits ``resolution_note``. The note is the reviewer's internal
    record about the subject, and a reporter is an adversarial party by
    definition: there is no guarantee it was written for them to read.
    """

    id: uuid.UUID
    subject_type: ReportSubjectType
    subject_id: uuid.UUID
    reason: ReportReason
    details: str | None
    status: ReportStatus
    resolved_at: datetime | None = None


class AdminReportResponse(ReportResponse):
    """A report as a reviewer sees it.

    Adds the reviewer's own fields and a pseudonymous ``reporter_ref``.

    There is **no** field here for the reporter's email address, phone number,
    name or display name - not because the route filters them, but because the
    type cannot represent them. A reviewer needs the subject and the reason; the
    reporter's contact details are not part of that job and are not in the
    schema.
    """

    reporter_ref: str = Field(
        description=(
            "Stable pseudonym for the reporting account, derived from its id. "
            "Enough to recognise repeat reports from one account; not an account "
            "identifier and not a contact detail."
        )
    )
    resolution_note: str | None = None
    resolved_by_user_id: uuid.UUID | None = None


__all__ = [
    "TERMINAL_DECISIONS",
    "AdminReportResponse",
    "ReportCreateRequest",
    "ReportDecision",
    "ReportDecisionRequest",
    "ReportResponse",
]
