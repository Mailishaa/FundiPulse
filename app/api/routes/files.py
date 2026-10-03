"""File endpoints: upload, metadata, and an authorised short-lived download URL.

Three endpoints and one rule: **there is no permanent public URL.** Bytes live in
private object storage and leave only through a URL this API signs after an
ownership check, a scan-state check and a key-safety check, all inside
:meth:`~app.services.file_service.FileService.issue_download_url`. The route does
not decide any of that - it parses, delegates and serialises.
"""

from __future__ import annotations

from typing import Annotated, Any
import uuid

from fastapi import APIRouter, Depends, Form, Path, status
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser, DbSession, FileUploadRateLimit, get_request_context
from app.db.models.file import FileObject
from app.schemas.common import ErrorResponse, Meta, ResponseEnvelope
from app.schemas.files import (
    EvidenceItemResponse,
    FileDownloadResponse,
    FileResponse,
    FileUploadRequest,
    FileUploadResponse,
)
from app.services.auth_service import RequestContext
from app.services.file_service import DownloadGrant, FileService

router = APIRouter(prefix="/files", tags=["Files"])

Ctx = Annotated[RequestContext, Depends(get_request_context)]
FileId = Annotated[uuid.UUID, Path(description="Identifier of one stored object.")]

#: Shared OpenAPI additions. Typed loosely because OpenAPI keys mix ints and strs.
AUTH_ERRORS: dict[int | str, Any] = {
    401: {"model": ErrorResponse, "description": "Authentication required."}
}

#: Reported identically for a file that does not exist and one owned by someone
#: else, so a 404 never becomes an existence oracle.
NOT_FOUND: dict[int | str, Any] = {
    404: {
        "model": ErrorResponse,
        "description": "No such file on this account. A file belonging to another "
        "user is reported the same way.",
    }
}

NOT_DOWNLOADABLE: dict[int | str, Any] = {
    409: {
        "model": ErrorResponse,
        "description": "The file is quarantined, infected or unscanned. It is not "
        "released, so no URL is issued.",
    }
}


def _service(session: Session) -> FileService:
    return FileService(session)


def _file_response(record: FileObject) -> FileResponse:
    """Map the model to the response schema.

    Reads only attributes; the schema has no ``object_key`` field, so the storage
    location cannot be serialised even by accident.
    """
    return FileResponse.model_validate(record)


@router.post(
    "/upload",
    response_model=ResponseEnvelope[FileUploadResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Upload a file",
    description=(
        "The bytes are sniffed server-side: the stored `content_type` is decided by "
        "the file's magic number, and a filename whose extension contradicts it is "
        "refused. The object key is generated, so the uploaded filename is recorded "
        "as display metadata only and never becomes a path.\n\n"
        "The new record is `PENDING` and quarantined, which means it is **not** "
        "downloadable until a malware scan clears it. Nothing here claims the file "
        "was scanned."
    ),
    responses={
        201: {"description": "Stored, with metadata returned."},
        404: {
            "model": ErrorResponse,
            "description": "Evidence attachment was requested but the caller has no "
            "Work Passport, or a referenced record is not theirs.",
        },
        413: {
            "model": ErrorResponse,
            "description": "Larger than the configured maximum upload size.",
        },
        415: {
            "model": ErrorResponse,
            "description": "Unsupported type, executable "
            "content, or bytes that contradict the declared type or extension.",
        },
        422: {"model": ErrorResponse, "description": "Validation failed."},
        **AUTH_ERRORS,
    },
)
def upload_file(
    _limit: FileUploadRateLimit,
    payload: Annotated[FileUploadRequest, Form()],
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[FileUploadResponse]:
    result = _service(session).upload(actor=current_user, payload=payload, ctx=ctx)
    return ResponseEnvelope(
        data=FileUploadResponse(
            file=_file_response(result.file),
            evidence=(
                EvidenceItemResponse.model_validate(result.evidence)
                if result.evidence is not None
                else None
            ),
        ),
        meta=Meta(request_id=ctx.request_id),
    )


@router.get(
    "/{file_id}",
    response_model=ResponseEnvelope[FileResponse],
    summary="Read a file's metadata",
    description=(
        "Owner-only. Returns no object key and no bucket: the storage location is "
        "never exposed, because a leaked key is a leaked file."
    ),
    responses={
        200: {"description": "The metadata."},
        **NOT_FOUND,
        **AUTH_ERRORS,
    },
)
def read_file_metadata(
    file_id: FileId,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[FileResponse]:
    record = _service(session).get_metadata(actor=current_user, file_id=file_id, ctx=ctx)
    return ResponseEnvelope(data=_file_response(record), meta=Meta(request_id=ctx.request_id))


@router.get(
    "/{file_id}/download",
    response_model=ResponseEnvelope[FileDownloadResponse],
    summary="Get a short-lived download URL",
    description=(
        "Authorises the caller, checks the object is released for download, and only "
        "then signs. The URL is bound to this one object, carries a server-set "
        "expiry, and forces a download rather than inline rendering. A quarantined "
        "or unscanned file gets `409`, never a URL."
    ),
    responses={
        200: {"description": "A signed, expiring URL."},
        **NOT_FOUND,
        **NOT_DOWNLOADABLE,
        **AUTH_ERRORS,
    },
)
def create_file_download(
    file_id: FileId,
    session: DbSession,
    current_user: CurrentUser,
    ctx: Ctx,
) -> ResponseEnvelope[FileDownloadResponse]:
    grant: DownloadGrant = _service(session).issue_download_url(
        actor=current_user, file_id=file_id, ctx=ctx
    )
    return ResponseEnvelope(
        data=FileDownloadResponse(
            file_id=grant.file_id,
            download_url=grant.download_url,
            expires_in_seconds=grant.expires_in_seconds,
            expires_at=grant.expires_at.isoformat(),
            download_filename=grant.download_filename,
        ),
        meta=Meta(request_id=ctx.request_id),
    )


__all__ = ["router"]
