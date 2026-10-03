"""File service: the only place a file byte is allowed to become a stored object.

Three invariants live here, and everything else in the domain depends on them:

1. **The client never names a path.** ``object_key`` comes from
   :func:`~app.utils.fileinspect.generate_object_key`; the uploaded filename is
   recorded as sanitised *metadata* and is escaped again before it is allowed
   near a response header. Path traversal is therefore not "checked for" - it is
   unrepresentable.
2. **The bytes decide what the file is.** :func:`~app.utils.fileinspect.inspect_upload`
   sniffs the payload; the client's ``Content-Type`` is only ever cross-checked
   against that answer. A ``.jpg`` whose bytes are a script is refused.
3. **Nothing is downloadable until it is known good.** A new upload is
   ``PENDING`` and quarantined, so ``is_downloadable`` is false and no signed URL
   can be minted for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, BinaryIO, Final, Protocol
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.constants import (
    AuditAction,
    EvidenceVisibility,
    FilePurpose,
    ProfileVisibility,
    ScanStatus,
)
from app.core.exceptions import (
    AppError,
    FileInfectedError,
    FileNotScannedError,
    FileTooLargeError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.storage import Storage, StoredObject, get_storage, validate_object_key
from app.db.base import utcnow
from app.db.models.file import FileObject
from app.db.models.user import User
from app.db.models.worker import Credential, EvidenceItem, Project, WorkerProfile, WorkExperience
from app.schemas.files import FileUploadRequest
from app.services.audit_service import AuditService
from app.services.auth_service import RequestContext
from app.utils.dates import utc_today
from app.utils.fileinspect import (
    HARD_MAX_UPLOAD_BYTES,
    UploadInspection,
    content_disposition_value,
    generate_object_key,
    inspect_upload,
)

logger = get_logger(__name__)

#: ``audit_logs.resource_type`` for this domain.
RESOURCE_TYPE: Final[str] = "file"

#: Bytes pulled from the stream per iteration. Bounded so an oversized upload
#: costs one chunk of memory, not its whole length.
READ_CHUNK_BYTES: Final[int] = 64 * 1024

#: Purposes a caller may upload under from this endpoint. ``ORGANIZATION_LOGO``
#: and ``REPORT_ATTACHMENT`` belong to domains that own their own rules, and a
#: worker's document must not be filed under them.
UPLOADABLE_PURPOSES: Final[frozenset[FilePurpose]] = frozenset(
    {
        FilePurpose.WORK_EVIDENCE,
        FilePurpose.CREDENTIAL_DOCUMENT,
        FilePurpose.REFERENCE_DOCUMENT,
    }
)

#: Evidence visibility, narrowest first.
_EVIDENCE_RANK: Final[dict[EvidenceVisibility, int]] = {
    EvidenceVisibility.PRIVATE: 0,
    EvidenceVisibility.EMPLOYERS: 1,
    EvidenceVisibility.PUBLIC: 2,
}

#: The most permissive evidence visibility each passport visibility may carry,
#: keyed by the stored string. A ``PRIVATE`` passport cannot expose evidence even
#: if the client asks for ``PUBLIC``, so this is a lookup rather than a comparison
#: the caller could influence. An unrecognised value is absent from the table and
#: therefore falls through to ``PRIVATE``.
_PASSPORT_EVIDENCE_CEILING: Final[dict[str, EvidenceVisibility]] = {
    ProfileVisibility.PRIVATE.value: EvidenceVisibility.PRIVATE,
    ProfileVisibility.DISCOVERABLE.value: EvidenceVisibility.EMPLOYERS,
    ProfileVisibility.PUBLIC.value: EvidenceVisibility.PUBLIC,
}


class FileRecordNotFoundError(NotFoundError):
    """Reported for both "no such file" and "not yours".

    A 403 here would confirm the file exists, which is itself a disclosure.
    """

    public_message = "That file was not found."


class PassportNotFoundError(NotFoundError):
    public_message = "No Work Passport was found for this account."


class UnsupportedUploadPurposeError(ValidationError):
    public_message = "That file purpose is not accepted here."


# --------------------------------------------------------------------------- #
# Malware scanning: the seam, deliberately unimplemented                        #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class ScanPolicy:
    """What the upload path may assert about a freshly stored object."""

    scanning_enabled: bool
    scan_status: ScanStatus
    is_quarantined: bool


def resolve_scan_policy(settings: Settings) -> ScanPolicy:
    """Decide the scan state of a new upload.

    Both values of ``MALWARE_SCANNING_ENABLED`` produce ``PENDING`` and
    quarantine, and that is the point: nothing in this codebase scans anything.
    With the flag off an object is not clean because it was checked, it is not
    clean because it was not checked. Turning the flag on cannot retroactively
    expose unscanned content, and turning it off cannot silently mark anything
    clean. The flag is recorded in the audit row so an operator can tell the two
    postures apart later.
    """
    return ScanPolicy(
        scanning_enabled=settings.malware_scanning_enabled,
        scan_status=ScanStatus.PENDING,
        is_quarantined=True,
    )


class MalwareScanner(Protocol):
    """The interface a real scanner implements.

    Nothing implements this yet, and nothing calls it. It exists so that adding
    ClamAV or a managed scanner is a matter of writing one adapter and calling
    :meth:`FileService.apply_scan_result`, rather than a redesign of the upload
    path.
    """

    name: str

    def scan(self, *, object_key: str, data: bytes) -> ScanStatus:
        """Return the scan verdict for one stored object."""


# --------------------------------------------------------------------------- #
# Bounded reading                                                             #
# --------------------------------------------------------------------------- #
def read_upload_stream(stream: BinaryIO, *, declared_size: int | None, max_bytes: int) -> bytes:
    """Read an upload, buffering at most ``max_bytes + 1`` bytes.

    ``declared_size`` is the parser's claim about the length, and a client
    controls it. It is used only to refuse early; how much is actually read is
    decided by the loop, which stops as soon as the stream has produced one byte
    more than the ceiling. A request whose ``Content-Length`` understates its
    body is therefore caught by the bytes rather than trusted by the header, and
    an unbounded stream can never be buffered whole.
    """
    if declared_size is not None and declared_size > max_bytes:
        raise FileTooLargeError(
            f"That file is too large. The maximum accepted size is {max_bytes} bytes."
        )
    buffer = bytearray()
    while True:
        chunk = stream.read(min(READ_CHUNK_BYTES, max_bytes + 1 - len(buffer)))
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > max_bytes:
            raise FileTooLargeError(
                f"That file is too large. The maximum accepted size is {max_bytes} bytes."
            )
    return bytes(buffer)


# --------------------------------------------------------------------------- #
# Value objects                                                               #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class EvidenceAttachment:
    """A validated evidence target, resolved before any byte is stored."""

    profile: WorkerProfile
    project_id: uuid.UUID | None
    work_experience_id: uuid.UUID | None
    credential_id: uuid.UUID | None
    visibility: EvidenceVisibility
    title: str | None
    description: str | None
    captured_at: date | None


@dataclass(frozen=True, slots=True)
class UploadedFile:
    """What an upload produced."""

    file: FileObject
    evidence: EvidenceItem | None


@dataclass(frozen=True, slots=True)
class DownloadGrant:
    """A signed, single-object, expiring read grant."""

    file_id: uuid.UUID
    download_url: str
    expires_in_seconds: int
    expires_at: datetime
    download_filename: str


# --------------------------------------------------------------------------- #
# Service                                                                     #
# --------------------------------------------------------------------------- #
class FileService:
    """Upload, inspect, authorise and sign. No HTTP in, no HTTP out."""

    def __init__(
        self,
        session: Session,
        *,
        storage: Storage | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._session = session
        self._storage = storage if storage is not None else get_storage()
        self._settings = settings if settings is not None else get_settings()
        self._audit = AuditService(session)

    # -- read ------------------------------------------------------------- #

    def get_metadata(self, *, actor: User, file_id: uuid.UUID, ctx: RequestContext) -> FileObject:
        """Return one file's metadata, or 404 for anything the caller does not own."""
        try:
            return self._load_owned(actor=actor, file_id=file_id)
        except FileRecordNotFoundError:
            self._audit_denial(
                actor=actor,
                ctx=ctx,
                operation="read_metadata",
                reason="not_found_or_not_owner",
                file_id=file_id,
            )
            raise

    # -- write ------------------------------------------------------------ #

    def upload(
        self, *, actor: User, payload: FileUploadRequest, ctx: RequestContext
    ) -> UploadedFile:
        """Sniff, store and record one upload.

        Order: validate the request and any evidence target, read a bounded
        stream, sniff the bytes, generate the key, store, then write both rows in
        one transaction. Nothing is stored before the target is known good, so a
        refused attachment cannot leave an orphan object behind.
        """
        try:
            self._assert_purpose(payload.purpose)
            attachment = (
                self._resolve_evidence_target(actor=actor, payload=payload)
                if payload.attach_as_evidence
                else None
            )
            data, inspection = self._inspect(payload)
        except AppError as exc:
            self._audit_denial(
                actor=actor, ctx=ctx, operation="upload", reason=exc.code, exception=exc
            )
            raise

        object_key = generate_object_key(
            purpose=payload.purpose.value,
            content_type=inspection.content_type,
            owner_id=actor.id,
        )
        stored = self._storage.put_object(
            object_key=object_key,
            data=data,
            content_type=inspection.content_type,
            # No filename, no digest, no content: object metadata is sent to
            # third parties and is not covered by our redaction rules.
            metadata={"purpose": payload.purpose.value},
        )
        self._assert_digest_matches(inspection=inspection, stored=stored)

        policy = resolve_scan_policy(self._settings)
        record = FileObject(
            owner_user_id=actor.id,
            purpose=payload.purpose.value,
            object_key=object_key,
            bucket=stored.bucket,
            original_filename=inspection.safe_filename,
            content_type=inspection.content_type,
            size_bytes=inspection.size_bytes,
            sha256=stored.sha256,
            scan_status=policy.scan_status.value,
            is_quarantined=policy.is_quarantined,
            # Byte content validated by sniffing. Distinct from ``scanned_at``,
            # which records a malware verdict and is set by nothing yet.
            verified_at=utcnow(),
        )
        self._session.add(record)
        self._session.flush()

        evidence = self._write_evidence(record=record, attachment=attachment)
        self._audit.record(
            action=AuditAction.FILE_UPLOADED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type=RESOURCE_TYPE,
            resource_id=record.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            outcome="SUCCESS",
            metadata={
                "purpose": payload.purpose.value,
                "content_type": inspection.content_type,
                "size_bytes": inspection.size_bytes,
                "scan_status": record.scan_status,
                "malware_scanning_enabled": policy.scanning_enabled,
                "evidence_attached": evidence is not None,
            },
        )
        return UploadedFile(file=record, evidence=evidence)

    def apply_scan_result(
        self,
        *,
        file_id: uuid.UUID,
        status: ScanStatus,
        engine: str,
        ctx: RequestContext,
    ) -> FileObject:
        """Record a scanner's verdict. The entry point for a future scanner.

        Not exposed over HTTP, and deliberately carrying no caller identity: it is
        a system-to-system call, so whoever wires up a scanner must place it
        behind an authenticated queue consumer rather than behind a route. Any
        verdict other than ``CLEAN`` leaves the object quarantined, so a scanner
        that misreports fails closed.
        """
        record = self._session.execute(
            select(FileObject).where(FileObject.id == file_id)
        ).scalar_one_or_none()
        if record is None:
            raise FileRecordNotFoundError()
        record.scan_status = status.value
        record.scan_engine = engine[:64] or None
        record.scanned_at = utcnow()
        record.is_quarantined = not status.is_downloadable
        self._session.flush()
        self._audit.record(
            action=AuditAction.ADMIN_ACTION,
            resource_type=RESOURCE_TYPE,
            resource_id=record.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            outcome="SUCCESS",
            metadata={
                "operation": "file_scan_result",
                "scan_status": status.value,
                "scan_engine": record.scan_engine,
            },
        )
        return record

    # -- download --------------------------------------------------------- #

    def issue_download_url(
        self, *, actor: User, file_id: uuid.UUID, ctx: RequestContext
    ) -> DownloadGrant:
        """Sign a short-lived URL for one object, after authorising the caller.

        **The order below is the security control. Do not reorder it.**

        1. Load the row scoped to ``actor``. Substituting another user's id
           matches nothing, so the answer is 404 rather than 403 - and a 403
           would confirm the file exists.
        2. ``validate_object_key`` before anything reaches the storage backend, so
           a key that somehow became unsafe is refused before a socket opens.
           ``Storage`` validates again, but relying only on a callee would make
           this method's correctness somebody else's problem.
        3. ``is_downloadable``. **This is the only thing standing between a
           quarantined or unscanned object and a URL**: ``create_download_url``
           will cheerfully sign any key it is handed, with no knowledge of scan
           state. Signing above this check would hand out infected files.
        4. Sign, with a server-set lifetime and an already-escaped
           ``Content-Disposition`` value.

        No TTL is accepted from the caller. A client that could ask for a
        ten-year expiry would turn this endpoint into a permanent public link.
        """
        try:
            record = self._load_owned(actor=actor, file_id=file_id)
        except FileRecordNotFoundError:
            self._audit_denial(
                actor=actor,
                ctx=ctx,
                operation="download_url",
                reason="not_found_or_not_owner",
                file_id=file_id,
            )
            raise

        object_key = validate_object_key(record.object_key)

        try:
            self._assert_downloadable(record)
        except AppError as exc:
            self._audit_denial(
                actor=actor,
                ctx=ctx,
                operation="download_url",
                reason=exc.code,
                file_id=record.id,
                exception=exc,
            )
            raise

        ttl = self._settings.signed_url_ttl_seconds
        # ``content_disposition_value`` returns a complete, quoted, RFC 6266
        # value. The raw filename is never passed: a stored name must not be able
        # to add a header, a parameter, or a filename of its own choosing.
        download_filename = content_disposition_value(record.original_filename)
        url = self._storage.create_download_url(
            object_key=object_key,
            expires_in=ttl,
            download_filename=download_filename,
            # Pinned to the sniffed type so a browser cannot re-sniff the response
            # and decide for itself what the bytes are.
            content_type=record.content_type,
        )

        record.access_count += 1
        record.last_accessed_at = utcnow()
        self._session.flush()
        self._audit.record(
            action=AuditAction.FILE_DOWNLOAD_URL_ISSUED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type=RESOURCE_TYPE,
            resource_id=record.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            outcome="SUCCESS",
            metadata={
                "purpose": record.purpose,
                "content_type": record.content_type,
                "expires_in_seconds": ttl,
                "access_count": record.access_count,
            },
        )
        return DownloadGrant(
            file_id=record.id,
            download_url=url,
            expires_in_seconds=ttl,
            expires_at=utcnow() + timedelta(seconds=ttl),
            download_filename=record.original_filename or record.extension.lstrip("."),
        )

    # -- internals -------------------------------------------------------- #

    def _inspect(self, payload: FileUploadRequest) -> tuple[bytes, UploadInspection]:
        """Read the stream within bounds and sniff what arrived.

        Only ``payload.file.file`` and ``payload.file.size`` are touched: the
        service treats the upload as an anonymous byte stream, so it holds no
        framework types and the sniffing rules can be exercised directly.
        """
        ceiling = min(self._settings.max_upload_size_bytes, HARD_MAX_UPLOAD_BYTES)
        data = read_upload_stream(
            payload.file.file,
            declared_size=payload.file.size,
            max_bytes=ceiling,
        )
        inspection = inspect_upload(
            data,
            declared_content_type=payload.file.content_type,
            declared_filename=payload.file.filename,
            max_bytes=ceiling,
        )
        return data, inspection

    def _assert_purpose(self, purpose: FilePurpose) -> None:
        if purpose not in UPLOADABLE_PURPOSES:
            raise UnsupportedUploadPurposeError()

    def _load_owned(self, *, actor: User, file_id: uuid.UUID) -> FileObject:
        """Load one live file belonging to ``actor``, or raise 404.

        Ownership is expressed in the query rather than decided afterwards, so
        there is nothing left for a later check to be bypassed on.
        """
        record = self._session.execute(
            select(FileObject).where(
                FileObject.id == file_id,
                FileObject.owner_user_id == actor.id,
                FileObject.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if record is None:
            raise FileRecordNotFoundError()
        return record

    def _assert_downloadable(self, record: FileObject) -> None:
        """Refuse anything not known clean. One property, one place."""
        if record.is_downloadable:
            return
        if record.scan_status == ScanStatus.INFECTED.value:
            raise FileInfectedError()
        raise FileNotScannedError("This file is not available until its malware scan completes.")

    def _assert_digest_matches(self, *, inspection: UploadInspection, stored: StoredObject) -> None:
        """Fail closed if what was stored is not what was inspected.

        The row records the backend's digest, so a mismatch means the integrity
        chain is broken. The object is removed rather than tracked.
        """
        if stored.sha256 == inspection.sha256:
            return
        try:
            self._storage.delete_object(object_key=stored.object_key)
        except AppError:
            logger.exception("Failed to remove an object whose digest did not match")
        raise ValidationError("The file could not be verified after upload.")

    def _resolve_evidence_target(
        self, *, actor: User, payload: FileUploadRequest
    ) -> EvidenceAttachment:
        """Authorise and validate the evidence binding before any byte is stored."""
        profile = self._session.execute(
            select(WorkerProfile).where(
                WorkerProfile.user_id == actor.id,
                WorkerProfile.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if profile is None:
            raise PassportNotFoundError()

        if payload.captured_at is not None and payload.captured_at > utc_today():
            raise ValidationError("That capture date cannot be in the future.")

        title = payload.title.strip() if payload.title else ""
        description = payload.description.strip() if payload.description else ""
        return EvidenceAttachment(
            profile=profile,
            project_id=self._scoped_child_id(Project, payload.project_id, profile.id),
            work_experience_id=self._scoped_child_id(
                WorkExperience, payload.work_experience_id, profile.id
            ),
            credential_id=self._scoped_child_id(Credential, payload.credential_id, profile.id),
            visibility=clamp_evidence_visibility(
                payload.visibility, passport_visibility=profile.visibility
            ),
            title=title or None,
            description=description or None,
            captured_at=payload.captured_at,
        )

    def _scoped_child_id(
        self, model: Any, child_id: uuid.UUID | None, profile_id: uuid.UUID
    ) -> uuid.UUID | None:
        """Return ``child_id`` only when it sits under ``profile_id``.

        Scoping the query by the parent means a foreign id simply matches nothing:
        there is no loaded row for an ownership check to be bypassed on.
        """
        if child_id is None:
            return None
        found = self._session.execute(
            select(model.id).where(
                model.id == child_id,
                model.worker_profile_id == profile_id,
                model.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if found is None:
            raise NotFoundError("One of the referenced records was not found.")
        return child_id

    def _write_evidence(
        self, *, record: FileObject, attachment: EvidenceAttachment | None
    ) -> EvidenceItem | None:
        if attachment is None:
            return None
        evidence = EvidenceItem(
            worker_profile_id=attachment.profile.id,
            file_id=record.id,
            project_id=attachment.project_id,
            work_experience_id=attachment.work_experience_id,
            credential_id=attachment.credential_id,
            title=attachment.title or record.original_filename,
            description=attachment.description,
            visibility=attachment.visibility.value,
            captured_at=attachment.captured_at,
        )
        self._session.add(evidence)
        self._session.flush()
        return evidence

    def _audit_denial(
        self,
        *,
        actor: User,
        ctx: RequestContext,
        operation: str,
        reason: str,
        file_id: uuid.UUID | None = None,
        exception: AppError | None = None,
    ) -> None:
        """Write a refusal that survives the rollback of the refused effect.

        ``record_durable`` rather than ``record``: the request is about to raise,
        which rolls the transaction back, and an audit trail that keeps only
        successes is not a trail.
        """
        self._audit.record_durable(
            action=AuditAction.FILE_ACCESS_DENIED,
            actor_user_id=actor.id,
            actor_role=actor.role,
            resource_type=RESOURCE_TYPE,
            resource_id=file_id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            outcome="DENIED",
            metadata={
                "operation": operation,
                "reason": reason,
                # Never the filename, the object key or a byte of the payload.
                "error_message": exception.message if exception else None,
            },
        )


def clamp_evidence_visibility(
    requested: EvidenceVisibility, *, passport_visibility: str
) -> EvidenceVisibility:
    """Return ``requested``, narrowed to what the passport itself allows.

    An unrecognised passport visibility is treated as ``PRIVATE``: failing open on
    a value this code does not know would silently widen a worker's evidence.
    """
    ceiling = _PASSPORT_EVIDENCE_CEILING.get(passport_visibility, EvidenceVisibility.PRIVATE)
    return requested if _EVIDENCE_RANK[requested] <= _EVIDENCE_RANK[ceiling] else ceiling


__all__ = [
    "DownloadGrant",
    "EvidenceAttachment",
    "FileRecordNotFoundError",
    "FileService",
    "MalwareScanner",
    "ScanPolicy",
    "UploadedFile",
    "clamp_evidence_visibility",
    "read_upload_stream",
    "resolve_scan_policy",
]
