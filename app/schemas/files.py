"""Pydantic contracts for uploaded files and evidence.

Two decisions are worth stating here because they are what make the rest of the
domain safe, and both are enforced by *absence of a field* rather than by a
runtime check:

* **No response schema has an ``object_key`` field.** The storage key is the one
  value that, if leaked, hands an attacker a direct path to the bytes. It stays
  server-side; a schema that cannot represent it cannot leak it.
* **No request schema has an ``owner_user_id`` field.** The owner is always the
  authenticated caller, so accepting one would be an IDOR.
"""

from __future__ import annotations

from datetime import date
from typing import Annotated
import uuid

from fastapi import UploadFile
from pydantic import Field

from app.core.constants import EvidenceVisibility, FilePurpose, ScanStatus
from app.schemas.common import RequestSchema, ResponseSchema, TimestampMixinSchema

#: Longest accepted evidence title. Matches ``evidence_items.title``.
MAX_EVIDENCE_TITLE_LENGTH = 255

#: Evidence description cap. ``description`` is a ``TEXT`` column, but an
#: unbounded body field on an upload endpoint is an abuse surface.
MAX_EVIDENCE_DESCRIPTION_LENGTH = 2000

NonEmptyTitle = Annotated[str, Field(min_length=1, max_length=MAX_EVIDENCE_TITLE_LENGTH)]
BoundedDescription = Annotated[str, Field(max_length=MAX_EVIDENCE_DESCRIPTION_LENGTH)]


class FileUploadRequest(RequestSchema):
    """The multipart body of ``POST /files/upload``.

    Declared as a form model so ``extra="forbid"`` applies to form fields too: a
    client sending ``owner_user_id`` or ``is_quarantined`` gets a 422 instead of
    having the field quietly ignored.
    """

    file: UploadFile = Field(description="The bytes to store. Sniffed, never trusted.")
    purpose: FilePurpose = Field(
        default=FilePurpose.WORK_EVIDENCE,
        description="Why the file exists. Determines the object-key namespace.",
    )
    attach_as_evidence: bool = Field(
        default=False,
        description="Also bind the file to the caller's Work Passport as an evidence item.",
    )
    visibility: EvidenceVisibility = Field(
        default=EvidenceVisibility.PRIVATE,
        description=(
            "Requested evidence visibility. Narrowed server-side to at most the "
            "passport's own visibility, so this can only ever make a file more private."
        ),
    )
    project_id: uuid.UUID | None = Field(
        default=None, description="Attach to this project. Must belong to the caller."
    )
    work_experience_id: uuid.UUID | None = Field(
        default=None, description="Attach to this work experience. Must belong to the caller."
    )
    credential_id: uuid.UUID | None = Field(
        default=None, description="Attach to this credential. Must belong to the caller."
    )
    title: NonEmptyTitle | None = Field(
        default=None, description="Evidence label. Defaults to the sanitised upload filename."
    )
    description: BoundedDescription | None = None
    captured_at: date | None = Field(
        default=None, description="When the photo or document was produced, if known."
    )


class FileResponse(TimestampMixinSchema):
    """Metadata for one stored object.

    Deliberately omits ``object_key``, ``bucket`` and ``sha256``'s storage
    location: this schema is what an authorised caller sees, and a key in it
    would be a key in every log, cache and analytics pipeline downstream.
    """

    id: uuid.UUID
    purpose: FilePurpose
    original_filename: str | None = Field(
        default=None,
        description="Sanitised display name. Never a path, never echoed into a header verbatim.",
    )
    content_type: str = Field(description="Agreed by byte-level sniffing, not by the client.")
    size_bytes: int
    sha256: str = Field(description="Integrity digest of the stored bytes.")
    scan_status: ScanStatus
    is_quarantined: bool
    is_downloadable: bool = Field(
        description="False while quarantined or unscanned. No URL is issued unless this is true."
    )


class FileDownloadResponse(ResponseSchema):
    """A short-lived, single-object grant.

    The URL is not a permanent public link: it is scoped to one object, carries a
    server-set expiry, and is only minted after an authorisation check.
    """

    file_id: uuid.UUID
    download_url: str
    expires_in_seconds: int
    expires_at: str
    download_filename: str = Field(
        description="Sanitised name the client should save the object as."
    )


class EvidenceItemResponse(TimestampMixinSchema):
    """The binding between a stored object and what it evidences."""

    id: uuid.UUID
    file_id: uuid.UUID
    worker_profile_id: uuid.UUID
    project_id: uuid.UUID | None = None
    work_experience_id: uuid.UUID | None = None
    credential_id: uuid.UUID | None = None
    title: str | None = None
    description: str | None = None
    visibility: EvidenceVisibility
    captured_at: date | None = None


class FileUploadResponse(ResponseSchema):
    """Result of an upload: the stored metadata and any evidence binding."""

    file: FileResponse
    evidence: EvidenceItemResponse | None = Field(
        default=None, description="Null unless the upload asked to be attached as evidence."
    )


__all__ = [
    "EvidenceItemResponse",
    "FileDownloadResponse",
    "FileResponse",
    "FileUploadRequest",
    "FileUploadResponse",
]
